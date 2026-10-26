#!/usr/bin/env python3
"""Read-only validation of logging dependencies from Script B's per-account JSON.

Run once per account in CloudShell. Cross-account references are recorded for
validation in their owning account; they are never called missing locally.
"""
import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

ARN = re.compile(r"^arn:([^:]+):([^:]+):([^:]*):([^:]*):(.+)$")


def parse_arn(value):
    match = ARN.match(str(value or ""))
    if not match:
        return None
    partition, service, region, account, resource = match.groups()
    return dict(partition=partition, service=service, region=region,
                account=account, resource=resource)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", help="Script B JSON; defaults to logging-<account>.json")
    args = parser.parse_args()
    session = boto3.Session()
    retry = Config(retries={"max_attempts": 10, "mode": "adaptive"})
    account = session.client("sts", config=retry).get_caller_identity()["Account"]
    source = Path(args.input or f"logging-{account}.json")
    report = json.loads(source.read_text(encoding="utf-8"))
    if str(report["account_id"]) != account:
        raise ValueError("Input JSON belongs to a different AWS account")
    if not isinstance(report.get("resources"), list):
        raise ValueError("Input is not a Script B inventory")
    resources = report["resources"]
    clients, checks = {}, []

    def client(service, region):
        key = service, region
        if key not in clients:
            clients[key] = session.client(service, region_name=region, config=retry)
        return clients[key]

    def check(source_type, source_id, target, relation, region, action):
        """Run action only for same-account references; preserve uncertain results."""
        arn = parse_arn(target)
        row = dict(source_type=source_type, source_id=source_id,
                   relation=relation, destination=str(target or ""),
                   region=region, state="", details="")
        if arn and arn["account"] and arn["account"] != account:
            row["state"] = "CROSS_ACCOUNT"
            row["details"] = "Validate in destination-owning account"
        elif arn and arn["region"] and arn["region"] != region:
            row["state"] = "UNVERIFIED"
            row["details"] = "Reference Region differs from source Region"
        else:
            try:
                details = action()
                row["state"] = "VALID"
                row["details"] = str(details or "Resource found")
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation",
                            "AuthorizationError", "AuthorizationErrorException", "403"):
                    row["state"] = "ACCESS_DENIED"
                elif code in ("NotFound", "NotFoundException", "ResourceNotFoundException",
                              "ResourceNotFound", "NoSuchBucket", "NonExistentQueue",
                              "AWS.SimpleQueueService.NonExistentQueue", "NotFoundFault", "404"):
                    row["state"] = "MISSING"
                else:
                    row["state"] = "UNVERIFIED"
                row["details"] = f"{code}: {exc.response.get('Error', {}).get('Message', '')}"
            except (BotoCoreError, ValueError, KeyError) as exc:
                row["state"] = "UNVERIFIED"
                row["details"] = str(exc)
        checks.append(row)

    def bucket_exists(bucket, region):
        client("s3", region).head_bucket(Bucket=bucket)
        return "Bucket accessible"

    def sns_exists(arn, region):
        client("sns", region).get_topic_attributes(TopicArn=arn)
        return "Topic accessible"

    def sqs_exists(arn, region):
        name = parse_arn(arn)["resource"]
        url = client("sqs", region).get_queue_url(QueueName=name)["QueueUrl"]
        attrs = client("sqs", region).get_queue_attributes(
            QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]
        if attrs.get("QueueArn") != arn:
            raise ValueError("Resolved queue ARN differs from configured ARN")
        return "Queue accessible"

    def lambda_exists(arn, region):
        client("lambda", region).get_function_configuration(FunctionName=arn)
        return "Function accessible"

    def log_group_exists(name, region):
        logs = client("logs", region)
        groups = logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
        if not any(g["logGroupName"] == name for g in groups):
            raise ValueError("Log group not found (or not visible)")
        return "Log group visible"

    def logs_destination_exists(arn, region):
        name = parse_arn(arn)["resource"].split(":", 1)[-1]
        ds = client("logs", region).describe_destinations(DestinationNamePrefix=name)["destinations"]
        found = next((d for d in ds if d["destinationName"] == name), None)
        if not found:
            raise ValueError("Destination not found (or not visible)")
        return "Target: " + found.get("targetArn", "")

    def stream_exists(arn, region):
        data = client("kinesis", region).describe_stream_summary(StreamARN=arn)["StreamDescriptionSummary"]
        return "Stream status: " + data["StreamStatus"]

    def firehose_exists(arn, region):
        name = parse_arn(arn)["resource"].split("/", 1)[-1]
        data = client("firehose", region).describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        return "Stream status: " + data["DeliveryStreamStatus"]

    def verify_target(source_type, source_id, target, relation, region):
        parsed = parse_arn(target)
        if not parsed:
            checks.append(dict(source_type=source_type, source_id=source_id, relation=relation,
                               destination=str(target or ""), region=region,
                               state="UNVERIFIED", details="Not an ARN; requires manual resolution"))
            return
        actions = {"sns": sns_exists, "sqs": sqs_exists, "lambda": lambda_exists,
                   "kinesis": stream_exists, "firehose": firehose_exists}
        if parsed["service"] == "logs" and parsed["resource"].startswith("destination:"):
            action = logs_destination_exists
        elif parsed["service"] == "logs" and parsed["resource"].startswith("log-group:"):
            # Log group ARN has trailing :* in some AWS responses.
            name = parsed["resource"][len("log-group:"):].removesuffix(":*")
            action = lambda _, r: log_group_exists(name, r)
        else:
            action = actions.get(parsed["service"])
        if action is None:
            checks.append(dict(source_type=source_type, source_id=source_id, relation=relation,
                               destination=target, region=region, state="UNVERIFIED",
                               details="Destination service not supported by this validator"))
        else:
            check(source_type, source_id, target, relation, region,
                  lambda: action(target, parsed["region"] or region))

    def details(item):
        try:
            return json.loads(item.get("details") or "{}")
        except (ValueError, TypeError):
            return {}

    # Script B discovered resources and references.
    for item in resources:
        kind, region, rid = item["resource_type"], item["region"], item["resource_id"]
        target = item.get("destination", "")
        extra = details(item)
        if kind == "event_notification" and item.get("destination_type") in ("sns", "sqs", "lambda"):
            verify_target(kind, f"{item.get('name', '')}/{rid}", target, "s3_notification", region)
        elif kind == "subscription_filter":
            verify_target(kind, f"{item.get('name', '')}/{rid}", target, "cloudwatch_subscription", region)
        elif kind == "vpc_flow_log":
            dtype = item.get("destination_type")
            if dtype == "s3" and target:
                parsed = parse_arn(target)
                bucket = parsed["resource"].split("/", 1)[0] if parsed else target
                check(kind, rid, target, "vpc_to_s3", region,
                      lambda: bucket_exists(bucket, region))
            elif dtype == "cloud-watch-logs" and target:
                parsed = parse_arn(target)
                name = parsed["resource"][len("log-group:"):].removesuffix(":*") if parsed and parsed["resource"].startswith("log-group:") else target
                check(kind, rid, target, "vpc_to_cloudwatch", region,
                      lambda: log_group_exists(name, region))
        elif kind in ("trail", "delivery_channel") and target and item.get("destination_type") == "s3":
            check(kind, rid, target, "logging_to_s3", region,
                  lambda: bucket_exists(target, region))
        if kind in ("trail", "delivery_channel") and extra.get("sns_topic"):
            verify_target(kind, rid, extra["sns_topic"], "notification_topic", region)

    # New: resolve cross-account CloudWatch destination -> Kinesis stream in owning account.
    for region in report.get("regions_scanned", []):
        try:
            logs = client("logs", region)
            token = None
            while True:
                kwargs = {"nextToken": token} if token else {}
                response = logs.describe_destinations(**kwargs)
                for d in response.get("destinations", []):
                    verify_target("logs_destination", d["destinationName"], d.get("targetArn", ""),
                                  "destination_to_target", region)
                token = response.get("nextToken")
                if not token:
                    break
        except (ClientError, BotoCoreError) as exc:
            checks.append(dict(source_type="logs_destination", source_id="*", relation="enumeration",
                               destination="", region=region, state="UNVERIFIED", details=str(exc)))

        # New: Firehose delivery stream source, transformation function and S3 target.
        try:
            firehose = client("firehose", region)
            token = None
            while True:
                kwargs = {"ExclusiveStartDeliveryStreamName": token} if token else {}
                response = firehose.list_delivery_streams(**kwargs)
                for name in response.get("DeliveryStreamNames", []):
                    try:
                        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
                        src = desc.get("Source", {}).get("KinesisStreamSourceDescription", {}).get("KinesisStreamARN")
                        if src:
                            verify_target("firehose", name, src, "firehose_source", region)
                        for destination in desc.get("Destinations", []):
                            s3 = (destination.get("ExtendedS3DestinationDescription")
                                  or destination.get("S3DestinationDescription") or {})
                            if s3.get("BucketARN"):
                                parsed = parse_arn(s3["BucketARN"])
                                bucket = parsed["resource"] if parsed else s3["BucketARN"]
                                check("firehose", name, s3["BucketARN"], "firehose_to_s3", region,
                                      lambda b=bucket: bucket_exists(b, region))
                            processors = (s3.get("ProcessingConfiguration") or {}).get("Processors", [])
                            for processor in processors:
                                if processor.get("Type") == "Lambda":
                                    for param in processor.get("Parameters", []):
                                        if param.get("ParameterName") == "LambdaArn":
                                            verify_target("firehose", name, param["ParameterValue"],
                                                          "firehose_transform", region)
                    except (ClientError, BotoCoreError) as exc:
                        checks.append(dict(source_type="firehose", source_id=name,
                                           relation="describe", destination="", region=region,
                                           state="UNVERIFIED", details=str(exc)))
                if not response.get("HasMoreDeliveryStreams"):
                    break
                token = response["DeliveryStreamNames"][-1]
        except (ClientError, BotoCoreError) as exc:
            checks.append(dict(source_type="firehose", source_id="*", relation="enumeration",
                               destination="", region=region, state="UNVERIFIED", details=str(exc)))

    output = {"generated_at_utc": datetime.now(timezone.utc).isoformat(),
              "account_id": account, "source_inventory": source.name,
              "checks": checks,
              "limitations": [
                  "Cross-account dependencies require validation in the destination account.",
                  "VALID means resource exists/is accessible, not successful log delivery.",
                  "UNVERIFIED may mean missing, insufficient visibility, or unsupported lookup.",
                  "No Splunk indexing or downstream consumer activity is tested.",
                  "S3 bucket head checks do not prove write permissions or object delivery."
              ]}
    dest = Path(f"dependencies-{account}.json")
    dest.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    counts = Counter(c["state"] for c in checks)
    print(f"Account {account}: {len(checks)} dependency checks")
    print("States:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print(f"Saved {dest}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, ClientError, BotoCoreError) as exc:
        print(f"Validation failed: {exc}", file=sys.stderr)
        sys.exit(1)
