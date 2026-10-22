#!/usr/bin/env python3
"""Read-only per-account AWS logging inventory. Run in AWS CloudShell."""
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


FIELDS = ["account_id", "region", "service", "resource_type", "resource_id",
          "name", "destination_type", "destination", "status", "details"]


def pages(client, operation, key, **kwargs):
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        yield from page.get(key, [])


def main():
    session = boto3.Session()
    retry = Config(retries={"max_attempts": 10, "mode": "adaptive"})
    _raw_client = session.client

    def client(service, **kwargs):
        return _raw_client(service, config=retry, **kwargs)

    account = client("sts").get_caller_identity()["Account"]
    home_region = session.region_name or "us-east-1"
    rows, errors = [], []

    def add(region, service, kind, resource, name="", dtype="", destination="", status="", **details):
        rows.append({"account_id": account, "region": region, "service": service,
                     "resource_type": kind, "resource_id": str(resource), "name": name,
                     "destination_type": dtype, "destination": str(destination or ""),
                     "status": str(status), "details": json.dumps(details, default=str, sort_keys=True)})

    def collect(region, service, action, fn):
        try:
            fn()
        except (ClientError, BotoCoreError, ValueError, KeyError) as exc:
            errors.append({"region": region, "service": service, "operation": action, "error": str(exc)})
            print(f"  WARNING {region} {service}/{action}: {exc}", file=sys.stderr)

    ec2 = client("ec2", region_name=home_region)
    regions = []
    try:
        regions = sorted(r["RegionName"] for r in ec2.describe_regions(AllRegions=True)["Regions"]
                         if r.get("OptInStatus") in ("opt-in-not-required", "opted-in"))
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(f"Cannot enumerate enabled Regions: {exc}") from exc
    print(f"Account {account}: scanning {len(regions)} enabled Regions")

    # S3 bucket names are global, but notifications are read from the bucket's own Region.
    def s3_inventory():
        s3 = client("s3", region_name=home_region)
        for bucket in pages(s3, "list_buckets", "Buckets") if s3.can_paginate("list_buckets") else s3.list_buckets()["Buckets"]:
            name = bucket["Name"]
            try:
                loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
                region = "us-east-1" if loc is None else "eu-west-1" if loc == "EU" else loc
                add(region, "s3", "bucket", name, name=name)
                s3r = client("s3", region_name=region)
                notification = s3r.get_bucket_notification_configuration(Bucket=name)
                for kind, dtype in (("QueueConfigurations", "sqs"), ("TopicConfigurations", "sns"),
                                    ("LambdaFunctionConfigurations", "lambda")):
                    for n in notification.get(kind, []):
                        add(region, "s3", "event_notification", n.get("Id", name), name=name,
                            dtype=dtype, destination=n.get("QueueArn") or n.get("TopicArn") or n.get("LambdaFunctionArn"),
                            events=n.get("Events", []), filter=n.get("Filter", {}))
                if notification.get("EventBridgeConfiguration") is not None:
                    add(region, "s3", "eventbridge_notification", name, name=name,
                        dtype="eventbridge", destination=f"EventBridge default bus ({region})", status="enabled")
            except (ClientError, BotoCoreError) as exc:
                errors.append({"region": "unknown", "service": "s3", "operation": f"bucket {name}", "error": str(exc)})
    collect("global", "s3", "buckets/notifications", s3_inventory)

    for region in regions:
        print(f"  {region}")
        def cloudtrail():
            ct = client("cloudtrail", region_name=region)
            # Home-region trails only, avoiding shadow-trail duplicates.
            for t in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
                arn = t["TrailARN"]
                state = ct.get_trail_status(Name=arn)
                selectors = ct.get_event_selectors(TrailName=arn)
                add(region, "cloudtrail", "trail", arn, name=t["Name"], dtype="s3",
                    destination=t.get("S3BucketName", ""), status="logging" if state.get("IsLogging") else "stopped",
                    prefix=t.get("S3KeyPrefix", ""), organization=t.get("IsOrganizationTrail"),
                    multi_region=t.get("IsMultiRegionTrail"), cloudwatch_log_group=t.get("CloudWatchLogsLogGroupArn"),
                    sns_topic=t.get("SnsTopicARN"), selectors=selectors.get("EventSelectors", []),
                    advanced_selectors=selectors.get("AdvancedEventSelectors", []),
                    latest_delivery=state.get("LatestDeliveryTime"), latest_delivery_error=state.get("LatestDeliveryError"))
        collect(region, "cloudtrail", "trails", cloudtrail)

        def flowlogs():
            ec = client("ec2", region_name=region)
            for f in pages(ec, "describe_flow_logs", "FlowLogs"):
                add(region, "ec2", "vpc_flow_log", f["FlowLogId"], name=f.get("ResourceId", ""),
                    dtype=f.get("LogDestinationType", ""),
                    destination=f.get("LogDestination") or f.get("LogGroupName", ""),
                    status=f.get("FlowLogStatus", ""), traffic_type=f.get("TrafficType"),
                    deliver_logs_status=f.get("DeliverLogsStatus"), deliver_logs_error=f.get("DeliverLogsErrorMessage"))
        collect(region, "ec2", "flow_logs", flowlogs)

        def config():
            c = client("config", region_name=region)
            statuses = {s["name"]: s for s in c.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]}
            for r in c.describe_configuration_recorders()["ConfigurationRecorders"]:
                st = statuses.get(r["name"], {})
                add(region, "config", "recorder", r["name"], name=r["name"],
                    status="recording" if st.get("recording") else "not_recording",
                    role_arn=r.get("roleARN"), recording_group=r.get("recordingGroup"),
                    last_status=st.get("lastStatus"), last_error=st.get("lastErrorMessage"))
            for d in c.describe_delivery_channels()["DeliveryChannels"]:
                add(region, "config", "delivery_channel", d["name"], name=d["name"], dtype="s3",
                    destination=d.get("s3BucketName", ""), prefix=d.get("s3KeyPrefix"),
                    sns_topic=d.get("snsTopicARN"))
        collect(region, "config", "recorders/delivery", config)

        def logs():
            cw = client("logs", region_name=region)
            for group in pages(cw, "describe_log_groups", "logGroups"):
                name = group["logGroupName"]
                add(region, "logs", "log_group", group.get("arn", name), name=name,
                    status="present", retention_days=group.get("retentionInDays"),
                    stored_bytes=group.get("storedBytes"), kms_key=group.get("kmsKeyId"))
                try:
                    for sub in pages(cw, "describe_subscription_filters", "subscriptionFilters", logGroupName=name):
                        add(region, "logs", "subscription_filter", sub["filterName"], name=name,
                            dtype="subscription", destination=sub.get("destinationArn", ""),
                            filter_pattern=sub.get("filterPattern", ""), role_arn=sub.get("roleArn"))
                except (ClientError, BotoCoreError) as exc:
                    errors.append({"region": region, "service": "logs", "operation": f"subscriptions {name}", "error": str(exc)})
        collect(region, "logs", "groups/subscriptions", logs)

        def sqs():
            q = client("sqs", region_name=region)
            token = None
            while True:
                kw = {"MaxResults": 1000, **({"NextToken": token} if token else {})}
                resp = q.list_queues(**kw)
                for url in resp.get("QueueUrls", []):
                    attrs = q.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn", "Policy", "ApproximateNumberOfMessages"])["Attributes"]
                    add(region, "sqs", "queue", attrs.get("QueueArn", url), name=url.rsplit("/", 1)[-1],
                        status="present", messages=attrs.get("ApproximateNumberOfMessages"),
                        policy=attrs.get("Policy", ""))
                token = resp.get("NextToken")
                if not token:
                    break
        collect(region, "sqs", "queues", sqs)

        def sns():
            sn = client("sns", region_name=region)
            for topic in pages(sn, "list_topics", "Topics"):
                arn = topic["TopicArn"]
                attrs = sn.get_topic_attributes(TopicArn=arn)["Attributes"]
                add(region, "sns", "topic", arn, name=arn.rsplit(":", 1)[-1],
                    status="present", policy=attrs.get("Policy", ""))
                for sub in pages(sn, "list_subscriptions_by_topic", "Subscriptions", TopicArn=arn):
                    add(region, "sns", "subscription", sub.get("SubscriptionArn", "PendingConfirmation"),
                        name=arn, dtype=sub.get("Protocol", ""), destination=sub.get("Endpoint", ""),
                        status="present")
        collect(region, "sns", "topics/subscriptions", sns)

    rows.sort(key=lambda x: (x["region"], x["service"], x["resource_type"], x["resource_id"]))
    out = Path.cwd()
    stamp = datetime.now(timezone.utc).isoformat()
    report = {"generated_at_utc": stamp, "account_id": account, "regions_scanned": regions,
              "resources": rows, "errors": errors}
    json_path = out / f"logging-{account}.json"
    csv_path = out / f"logging-{account}.csv"
    json_path.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Saved {len(rows)} records to {csv_path.name} and {json_path.name}; {len(errors)} warning(s).")
    if errors:
        print("Review the errors array in JSON: incomplete discovery must not be treated as no resources.")


if __name__ == "__main__":
    try:
        main()
    except (BotoCoreError, ClientError, RuntimeError) as exc:
        print(f"Discovery failed: {exc}", file=sys.stderr)
        sys.exit(1)
