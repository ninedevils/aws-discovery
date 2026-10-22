#!/usr/bin/env python3
"""Read-only AWS Organizations OU and account inventory for CloudShell."""
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


def pages(client, operation, result_key, **kwargs):
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        yield from page[result_key]


def main():
    session = boto3.Session()
    sts = session.client("sts")
    org = session.client(
        "organizations",
        region_name="us-east-1",  # Organizations is global, served from us-east-1
        config=Config(retries={"max_attempts": 10, "mode": "adaptive"}),
    )
    caller_account = sts.get_caller_identity()["Account"]
    organization = org.describe_organization()["Organization"]
    management_account = organization["MasterAccountId"]
    if caller_account != management_account:
        raise RuntimeError(
            f"Run from the management account ({management_account}), not {caller_account}."
        )

    records = []
    ous = []

    def walk(parent_id, parent_path):
        for account in pages(org, "list_accounts_for_parent", "Accounts", ParentId=parent_id):
            records.append({
                "ou_path": parent_path,
                "account_name": account["Name"],
                "account_id": account["Id"],
                "state": account.get("State", account.get("Status", "UNKNOWN")),
                "email": account.get("Email", ""),
            })
        for ou in pages(org, "list_organizational_units_for_parent", "OrganizationalUnits", ParentId=parent_id):
            path = f"{parent_path}/{ou['Name']}"
            ous.append({"id": ou["Id"], "name": ou["Name"], "path": path, "parent_id": parent_id})
            walk(ou["Id"], path)

    roots = list(pages(org, "list_roots", "Roots"))
    for root in roots:
        walk(root["Id"], "Root")

    records.sort(key=lambda r: (r["ou_path"], r["account_name"], r["account_id"]))
    ous.sort(key=lambda o: o["path"])
    output = Path.cwd()
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "organization_id": organization["Id"],
        "management_account_id": management_account,
        "roots": [{"id": r["Id"], "name": r["Name"]} for r in roots],
        "organizational_units": ous,
        "accounts": records,
    }
    (output / "organization.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with (output / "organization.csv").open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["ou_path", "account_name", "account_id", "state", "email"])
        writer.writeheader()
        writer.writerows(records)
    print(f"Discovered {len(roots)} root(s), {len(ous)} OU(s), {len(records)} account(s).")
    print("Saved organization.csv and organization.json in", output)


if __name__ == "__main__":
    try:
        main()
    except (BotoCoreError, ClientError, RuntimeError) as error:
        print(f"Discovery failed: {error}", file=sys.stderr)
        sys.exit(1)
