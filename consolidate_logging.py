#!/usr/bin/env python3
"""Offline consolidation of Script A and B JSON files; no AWS calls."""
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ["account_id", "account_name", "ou_path", "region", "service",
          "resource_type", "resource_id", "name", "destination_type",
          "destination", "status", "details"]
ARN = re.compile(r"^arn:[^:]+:(sqs|sns):([^:]+):(\d{12}):(.+)$")

def load(path):
    with path.open(encoding="utf-8") as f:
        return json.load(f)

def md_table(headers, rows):
    def safe(value):
        return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")
    return "\n".join(["| " + " | ".join(map(safe, headers)) + " |",
                       "| " + " | ".join("---" for _ in headers) + " |"] +
                      ["| " + " | ".join(map(safe, row)) + " |" for row in rows])

def main():
    base = Path.cwd()
    org = load(base / "organization.json")
    accounts = {str(a["account_id"]): a for a in org["accounts"]}
    files = sorted(base.glob("logging-*.json"))
    if not files:
        raise ValueError("No logging-*.json files found")
    reports = {}
    for path in files:
        report = load(path)
        aid = str(report["account_id"])
        if aid in reports:
            raise ValueError(f"Duplicate account report: {aid}")
        if path.name != f"logging-{aid}.json":
            raise ValueError(f"Filename/account mismatch: {path.name}")
        if not isinstance(report.get("resources"), list) or not isinstance(report.get("errors"), list):
            raise ValueError(f"Malformed report: {path.name}")
        reports[aid] = report
    missing = sorted(set(accounts) - set(reports))
    unknown = sorted(set(reports) - set(accounts))
    if missing or unknown:
        raise ValueError(f"Account mismatch. Missing reports: {missing}; unknown accounts: {unknown}")

    resources = []
    errors = []
    for aid, report in sorted(reports.items()):
        for item in report["resources"]:
            if str(item.get("account_id")) != aid:
                raise ValueError(f"Resource account mismatch in logging-{aid}.json")
            row = {k: item.get(k, "") for k in FIELDS}
            row["account_name"] = accounts[aid]["account_name"]
            row["ou_path"] = accounts[aid]["ou_path"]
            resources.append(row)
        for err in report["errors"]:
            errors.append((aid, accounts[aid]["account_name"], err))
    resources.sort(key=lambda r: (r["account_name"], r["region"], r["service"], r["resource_type"], r["resource_id"]))
    with (base / "logging-map.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(resources)

    counts = Counter(r["resource_type"] for r in resources)
    inventory = defaultdict(set)
    for r in resources:
        if r["resource_type"] in ("queue", "topic"):
            inventory[(r["resource_type"], r["resource_id"])].add(r["account_id"])
    references = []
    for r in resources:
        if r["destination_type"] in ("sqs", "sns"):
            references.append((r, r["destination_type"], r["destination"]))
        try:
            details = json.loads(r["details"] or "{}")
        except (ValueError, TypeError):
            details = {}
        for key in ("sns_topic",):
            if details.get(key):
                references.append((r, "sns", details[key]))

    links = []
    for source, kind, target in references:
        parsed = ARN.match(target)
        if not parsed or parsed.group(1) != kind:
            state = "Unverified (nonstandard reference)"
        else:
            _, region, owner, _ = parsed.groups()
            if owner not in reports:
                state = "Unverified (account not scanned)"
            elif region not in reports[owner].get("regions_scanned", []):
                state = "Unverified (Region not scanned)"
            elif any(e.get("region") == region and e.get("service") == kind
                     for e in reports[owner]["errors"]):
                state = "Unverified (discovery error)"
            elif (("queue" if kind == "sqs" else "topic"), target) in inventory:
                state = "Present in inventory"
            else:
                state = "Potentially missing (not in inventory)"
        links.append((source["account_name"], source["region"], source["resource_type"],
                      source["name"] or source["resource_id"], kind.upper(), target, state))

    with (base / "destination-checks.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["source_account", "source_region", "source_type", "source_name",
                    "destination_type", "destination", "assessment"])
        w.writerows(links)

    count_rows = [(kind, count) for kind, count in sorted(counts.items())]
    per_account = []
    for aid, report in sorted(reports.items(), key=lambda x: accounts[x[0]]["account_name"]):
        per_account.append((accounts[aid]["account_name"], accounts[aid]["ou_path"],
                            len(report["regions_scanned"]), len(report["resources"]), len(report["errors"])))
    trail_count = len({r["resource_id"] for r in resources if r["resource_type"] == "trail"})
    summary = [
        "# AWS Logging Configuration Discovery",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Scope and limitations",
        f"- Accounts inventoried: **{len(reports)} of {len(accounts)}**",
        f"- Resource records: **{len(resources)}**",
        f"- Distinct CloudTrail trail ARNs: **{trail_count}**",
        f"- Discovery warnings/errors: **{len(errors)}**",
        "- This report describes configuration, not proof of log delivery or SIEM ingestion.",
        "- SQS/SNS destination assessments are inventory comparisons, not live health checks.",
        "",
        "## Account coverage",
        md_table(["Account", "OU", "Regions scanned", "Records", "Errors"], per_account),
        "",
        "## Resource inventory",
        md_table(["Resource type", "Records"], count_rows),
        "",
        "## Forwarding references",
        f"- SQS/SNS references examined: **{len(links)}**",
        f"- Potentially missing: **{sum(s == 'Potentially missing (not in inventory)' for *_, s in links)}**",
        f"- Unverified: **{sum(s.startswith('Unverified') for *_, s in links)}**",
        "- See `destination-checks.csv` for individual references.",
        "",
        "## Interpretation",
        "A destination appearing in the inventory does not establish that events are delivered or consumed.",
        "A destination absent from the inventory is a potential issue, not definitive proof of deletion.",
        "Cross-account permissions, API errors, and unscanned Regions can prevent verification.",
        "",
    ]
    (base / "summary.md").write_text("\n".join(summary), encoding="utf-8")

    findings = ["# AWS Logging Discovery — Follow-up Items", "",
                "These are investigation candidates, not confirmed incidents.", "",
                "## Potentially missing SQS/SNS destinations"]
    suspect = [x for x in links if x[-1] == "Potentially missing (not in inventory)"]
    findings.append(md_table(["Account", "Region", "Source", "Source name", "Type", "Destination", "Assessment"], suspect)
                    if suspect else "None identified by inventory comparison.")
    findings += ["", "## Discovery errors", ""]
    if errors:
        findings.append(md_table(["Account", "Region", "Service", "Operation", "Error"],
            [(name, e.get("region", ""), e.get("service", ""), e.get("operation", ""), e.get("error", ""))
             for _, name, e in errors]))
    else:
        findings.append("No API discovery errors recorded.")
    findings += ["", "## Other checks to perform", "",
                 "- Confirm actual delivery and SIEM ingestion using destination metrics and consumer configuration.",
                 "- Review S3 EventBridge rules and external polling separately; Script B does not inventory them.",
                 "- Investigate failed VPC Flow Log delivery and stopped trails before declaring coverage.",
                 ""]
    (base / "findings.md").write_text("\n".join(findings), encoding="utf-8")
    print(f"Processed {len(reports)} accounts, {len(resources)} resources, {len(errors)} errors.")
    print(f"Checked {len(links)} SQS/SNS references; {len(suspect)} potentially missing.")
    print("Created summary.md, findings.md, logging-map.csv, destination-checks.csv")

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"Consolidation failed: {exc}", file=sys.stderr)
        sys.exit(1)
