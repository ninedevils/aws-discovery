#!/usr/bin/env python3
"""Offline summary of Script D delivery evidence. No AWS API calls."""
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def load(path):
    with path.open(encoding='utf-8') as f:
        return json.load(f)


def markdown_table(headers, rows):
    def cell(value):
        return str(value if value is not None else '').replace('|', '\\|').replace('\n', ' ')
    return '\n'.join(['| ' + ' | '.join(map(cell, headers)) + ' |',
                      '| ' + ' | '.join('---' for _ in headers) + ' |'] +
                     ['| ' + ' | '.join(map(cell, row)) + ' |' for row in rows])


def main():
    base = Path.cwd()
    org = load(base / 'organization.json')
    accounts = {str(a['account_id']): a['account_name'] for a in org['accounts']}
    reports = {}
    for path in sorted(base.glob('delivery-*.json')):
        report = load(path)
        aid = str(report['account_id'])
        if path.name != f'delivery-{aid}.json' or aid in reports:
            raise ValueError(f'Duplicate or mismatched account report: {path.name}')
        if not isinstance(report.get('checks'), list) or not isinstance(report.get('errors'), list):
            raise ValueError(f'Invalid report structure: {path.name}')
        reports[aid] = report
    missing = sorted(set(accounts) - set(reports))
    extra = sorted(set(reports) - set(accounts))
    if missing or extra:
        raise ValueError(f'Account mismatch: missing={missing}, unexpected={extra}')
    rows, evidence_rows, findings = [], [], []
    present = sorted({c['state'] for report in reports.values() for c in report['checks']})
    for aid, report in sorted(reports.items(), key=lambda x: accounts[x[0]]):
        counts = Counter(c['state'] for c in report['checks'])
        rows.append([accounts[aid], len(report['checks']), len(report['errors']),
                     *(counts[s] for s in present)])
        for check in report['checks']:
            ev = check.get('evidence') or {}
            evidence_rows.append([accounts[aid], check.get('region', ''),
                                  check.get('resource_type', ''), check.get('resource_id', ''),
                                  check.get('check', ''), check.get('state', ''),
                                  json.dumps(ev, sort_keys=True, default=str)])
            state = check.get('state')
            if state in ('stopped', 'not_recording', 'not_active', 'missing'):
                findings.append([accounts[aid], check.get('region', ''),
                                 check.get('resource_type', ''), check.get('resource_id', ''),
                                 state, 'Verify expected logging state'])
            if any(ev.get(k) for k in ('latest_delivery_error', 'delivery_error', 'last_error')):
                findings.append([accounts[aid], check.get('region', ''),
                                 check.get('resource_type', ''), check.get('resource_id', ''),
                                 'reported_error', 'Inspect AWS delivery error'])
        for err in report['errors']:
            findings.append([accounts[aid], err.get('region', ''), '',
                             err.get('resource_id', ''), 'api_error', err.get('check', '')])
    with (base / 'delivery-evidence.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['account', 'region', 'resource_type', 'resource_id', 'check', 'state', 'evidence_json'])
        writer.writerows(evidence_rows)
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    totals = Counter(c['state'] for report in reports.values() for c in report['checks'])
    health = ['# AWS Logging Delivery Evidence', '', f'Generated: {now}', '',
              f'**Accounts:** {len(reports)} / {len(accounts)}  ',
              f'**Checks:** {len(evidence_rows)}  ',
              f'**API errors:** {sum(len(r["errors"]) for r in reports.values())}', '',
              '## Account summary', '',
              markdown_table(['Account', 'Checks', 'API errors', *present], rows), '',
              '## Check states', '', markdown_table(['State', 'Count'], sorted(totals.items())), '',
              '## Interpretation', '',
              '- No datapoints is not evidence of a failure; quiet resources may produce no metrics.',
              '- Observed metrics do not establish successful Splunk indexing.',
              '- Service status is a point-in-time observation, not proof of uninterrupted delivery.',
              '- No S3 object freshness or Splunk-side ingestion verification is performed.',
              '- Detailed evidence is available in `delivery-evidence.csv`.', '']
    (base / 'delivery-health.md').write_text('\n'.join(health), encoding='utf-8')
    finding_text = ['# Delivery Follow-up Findings', '', f'Generated: {now}', '',
                    'Potential issues requiring verification; not confirmed incidents.', '']
    if findings:
        finding_text.append(markdown_table(['Account', 'Region', 'Resource type', 'Resource ID',
                                            'Observation', 'Next action'], findings))
    else:
        finding_text.append('No stopped/missing statuses, explicit delivery errors or API errors identified.')
    finding_text.extend(['', 'Metric gaps are not automatically classified as incidents.', ''])
    (base / 'delivery-findings.md').write_text('\n'.join(finding_text), encoding='utf-8')
    print(f'Analysed {len(reports)} accounts, {len(evidence_rows)} checks, '
          f'{sum(len(r["errors"]) for r in reports.values())} API errors.')
    print(f'Flagged {len(findings)} follow-up observations.')
    print('Created delivery-health.md, delivery-findings.md, delivery-evidence.csv')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'Analysis failed: {exc}', file=sys.stderr)
        sys.exit(1)
