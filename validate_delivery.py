#!/usr/bin/env python3
"""Read-only point-in-time and historical delivery checks using Script B inventory."""
import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

METRICS = {
    "queue": ("AWS/SQS", "QueueName", ["NumberOfMessagesSent", "NumberOfMessagesReceived",
                                      "NumberOfMessagesDeleted", "ApproximateAgeOfOldestMessage"]),
    "topic": ("AWS/SNS", "TopicName", ["NumberOfMessagesPublished", "NumberOfNotificationsDelivered",
                                     "NumberOfNotificationsFailed"]),
    "log_group": ("AWS/Logs", "LogGroupName", ["IncomingLogEvents", "IncomingBytes"]),
}
SUM_METRICS = {"NumberOfMessagesSent", "NumberOfMessagesReceived", "NumberOfMessagesDeleted",
               "NumberOfMessagesPublished", "NumberOfNotificationsDelivered",
               "NumberOfNotificationsFailed", "IncomingLogEvents", "IncomingBytes"}

def metric(cw, namespace, dimension, name, start, end, period):
    statistic = "Sum" if name in SUM_METRICS else "Maximum"
    response = cw.get_metric_statistics(
        Namespace=namespace, MetricName=name,
        Dimensions=[{"Name": dimension[0], "Value": dimension[1]}],
        StartTime=start, EndTime=end, Period=period, Statistics=[statistic])
    points = response.get("Datapoints", [])
    return {"metric": name, "statistic": statistic, "datapoints": len(points),
            "value": (sum(p[statistic] for p in points) if statistic == "Sum"
                      else max(p[statistic] for p in points)) if points else None,
            "last_datapoint_utc": max(p["Timestamp"] for p in points).isoformat() if points else None}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=7, help="Lookback window: 1-14 days (default 7)")
    parser.add_argument("--input", help="Script B JSON path (default logging-<current account>.json)")
    args = parser.parse_args()
    if not 1 <= args.days <= 14:
        parser.error("--days must be between 1 and 14")
    session = boto3.Session()
    retry = Config(retries={"max_attempts": 10, "mode": "adaptive"})
    account = session.client("sts", config=retry).get_caller_identity()["Account"]
    path = Path(args.input or f"logging-{account}.json")
    inventory = json.loads(path.read_text(encoding="utf-8"))
    if str(inventory["account_id"]) != account:
        raise ValueError("Inventory account does not match current AWS identity")
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)
    period = 3600 if args.days <= 7 else 86400
    checks, errors = [], []
    clients = {}

    def client(service, region):
        key = (service, region)
        if key not in clients:
            clients[key] = session.client(service, region_name=region, config=retry)
        return clients[key]

    def record(item, check, state, **evidence):
        checks.append({"region": item["region"], "service": item["service"],
                       "resource_type": item["resource_type"], "resource_id": item["resource_id"],
                       "check": check, "state": state, "evidence": evidence})

    def attempt(item, check, action):
        try:
            action()
        except (ClientError, BotoCoreError, ValueError, KeyError) as exc:
            errors.append({"region": item["region"], "resource_id": item["resource_id"],
                           "check": check, "error": str(exc)})
            record(item, check, "unverified", reason="API error; see errors")

    # Explicitly scoped to resources discovered by Script B.
    for item in inventory["resources"]:
        region = item["region"]
        kind = item["resource_type"]
        rid = item["resource_id"]
        if kind == "trail":
            def check_trail():
                status = client("cloudtrail", region).get_trail_status(Name=rid)
                record(item, "trail_delivery", "reported_logging" if status.get("IsLogging") else "stopped",
                       is_logging=status.get("IsLogging"),
                       latest_delivery_time=status.get("LatestDeliveryTime"),
                       latest_delivery_error=status.get("LatestDeliveryError"),
                       latest_notification_time=status.get("LatestNotificationTime"),
                       latest_notification_error=status.get("LatestNotificationError"))
            attempt(item, "trail_delivery", check_trail)
        elif kind == "vpc_flow_log":
            def check_flow():
                response = client("ec2", region).describe_flow_logs(FlowLogIds=[rid])
                flows = response.get("FlowLogs", [])
                if not flows:
                    record(item, "flow_delivery", "missing")
                else:
                    flow = flows[0]
                    record(item, "flow_delivery", "reported_active" if flow.get("FlowLogStatus") == "ACTIVE" else "not_active",
                           flow_log_status=flow.get("FlowLogStatus"),
                           delivery_status=flow.get("DeliverLogsStatus"),
                           delivery_error=flow.get("DeliverLogsErrorMessage"))
            attempt(item, "flow_delivery", check_flow)
        elif kind == "recorder":
            def check_recorder():
                result = client("config", region).describe_configuration_recorder_status(
                    ConfigurationRecorderNames=[rid]).get("ConfigurationRecordersStatus", [])
                if not result:
                    record(item, "recorder_status", "missing")
                else:
                    s = result[0]
                    record(item, "recorder_status", "recording" if s.get("recording") else "not_recording",
                           last_status=s.get("lastStatus"), last_error=s.get("lastErrorMessage"),
                           last_successful_recording=s.get("lastSuccessfulRecordingTime"),
                           last_status_change=s.get("lastStatusChangeTime"))
            attempt(item, "recorder_status", check_recorder)
        elif kind == "delivery_channel":
            def check_channel():
                result = client("config", region).describe_delivery_channel_status(
                    DeliveryChannelNames=[rid]).get("DeliveryChannelsStatus", [])
                if not result:
                    record(item, "config_delivery", "missing")
                else:
                    s = result[0]
                    record(item, "config_delivery", "reported", 
                           config_history=s.get("configHistoryDeliveryInfo"),
                           config_snapshot=s.get("configSnapshotDeliveryInfo"),
                           config_stream=s.get("configStreamDeliveryInfo"))
            attempt(item, "config_delivery", check_channel)
        elif kind in METRICS:
            namespace, dim_name, names = METRICS[kind]
            # Metrics are only collected for inventoried queues/topics/log groups.
            name = item["name"]
            def check_metrics():
                cw = client("cloudwatch", region)
                result = [metric(cw, namespace, (dim_name, name), m, start, end, period) for m in names]
                record(item, "cloudwatch_metrics", "observed" if any(
                    m["datapoints"] and m["value"] is not None for m in result) else "no_datapoints",
                       metrics=result)
            attempt(item, "cloudwatch_metrics", check_metrics)

    output = {"generated_at_utc": end.isoformat(), "account_id": account,
              "source_inventory": path.name, "window_start_utc": start.isoformat(),
              "window_end_utc": end.isoformat(), "days": args.days,
              "checks": checks, "errors": errors,
              "limitations": [
                  "Metrics are historical aggregates; activity does not prove SIEM indexing.",
                  "No S3 objects or SQS message bodies were read.",
                  "No datapoints is not equivalent to zero activity.",
                  "S3 notifications, SQS/SNS resource existence and Splunk ingestion require separate validation.",
                  "CloudWatch log group metrics can be sparse or unavailable depending on service behavior."
              ]}
    dest = Path(f"delivery-{account}.json")
    dest.write_text(json.dumps(output, indent=2, default=str) + "\n", encoding="utf-8")
    counts = defaultdict(int)
    for c in checks:
        counts[c["state"]] += 1
    print(f"Account {account}: {len(checks)} checks, {len(errors)} API errors, {args.days}-day lookback")
    print("States:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print(f"Saved {dest}")

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, BotoCoreError, ClientError) as exc:
        print(f"Delivery validation failed: {exc}", file=sys.stderr)
        sys.exit(1)
