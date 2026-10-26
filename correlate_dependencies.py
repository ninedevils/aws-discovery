#!/usr/bin/env python3
"""Offline correlation of Script F outputs. No AWS calls or dependencies."""
import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

FIELDS = ('account_id account_name source_type source_id relation destination '
          'destination_account region original_state correlated_state details evidence').split()
ARN = re.compile(r'^arn:[^:]+:([^:]+):([^:]*):([^:]*):(.+)$')


def arn(value):
    m = ARN.match(str(value or ''))
    return dict(zip(('service', 'region', 'account', 'resource'), m.groups())) if m else None


def account_names(doc):
    names = {}
    def visit(obj):
        if isinstance(obj, dict):
            aid = obj.get('Id', obj.get('id', obj.get('account_id')))
            name = obj.get('Name', obj.get('name', obj.get('account_name')))
            if re.fullmatch(r'\d{12}', str(aid)) and isinstance(name, str):
                names[str(aid)] = name
            for value in obj.values():
                visit(value)
        elif isinstance(obj, list):
            for value in obj:
                visit(value)
    visit(doc)
    return names


def table(headers, rows):
    def safe(value):
        return str(value or '').replace('|', '\\|').replace('\n', ' ')
    return '\n'.join(['| ' + ' | '.join(headers) + ' |',
                      '| ' + ' | '.join('---' for _ in headers) + ' |'] +
                     ['| ' + ' | '.join(safe(x) for x in row) + ' |' for row in rows])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-dir', default='.')
    parser.add_argument('--organization', default='organization.json')
    args = parser.parse_args()
    paths = sorted(Path(args.input_dir).glob('dependencies-*.json'))
    if not paths:
        parser.error('No dependencies-*.json files found')
    org = Path(args.organization)
    names = account_names(json.loads(org.read_text())) if org.exists() else {}
    if not org.exists():
        print('WARNING: organization.json absent; using account IDs')
    rows, accounts = [], set()
    for path in paths:
        data = json.loads(path.read_text())
        aid = str(data['account_id'])
        if aid in accounts:
            parser.error(f'Duplicate account {aid}: {path}')
        accounts.add(aid)
        for item in data['checks']:
            destination = str(item.get('destination') or '')
            parts = arn(destination)
            rows.append(dict(account_id=aid, account_name=names.get(aid, aid),
                             source_type=str(item.get('source_type') or ''),
                             source_id=str(item.get('source_id') or ''),
                             relation=str(item.get('relation') or ''),
                             destination=destination,
                             destination_account=parts['account'] if parts else '',
                             region=str(item.get('region') or ''),
                             original_state=str(item.get('state') or 'UNVERIFIED'),
                             correlated_state='', details=str(item.get('details') or ''),
                             evidence=''))
    # An exact ARN checked as VALID in its own account is corroborating evidence.
    # No fuzzy matching: names alone cannot prove a cross-account destination exists.
    valid_arns = {r['destination'] for r in rows if r['original_state'] == 'VALID'
                  and r['destination_account'] == r['account_id']}
    for r in rows:
        if r['original_state'] != 'CROSS_ACCOUNT':
            r['correlated_state'] = r['original_state']
            r['evidence'] = 'Script F direct check'
        elif r['destination_account'] not in accounts:
            r['correlated_state'] = 'CROSS_ACCOUNT_OUTSIDE_SCOPE'
            r['evidence'] = 'Target account absent from supplied files'
        elif r['destination'] in valid_arns:
            r['correlated_state'] = 'CROSS_ACCOUNT_CORROBORATED'
            r['evidence'] = 'Exact destination ARN checked VALID in owning account'
        else:
            r['correlated_state'] = 'CROSS_ACCOUNT_UNRESOLVED'
            r['evidence'] = 'No exact-ARN VALID check in owning account'
    rows.sort(key=lambda r: (r['account_name'], r['source_type'], r['source_id'], r['destination']))
    with open('dependency-map.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    orig = Counter(r['original_state'] for r in rows)
    corr = Counter(r['correlated_state'] for r in rows)
    groups = defaultdict(list)
    for r in rows:
        groups[r['account_id']].append(r)
    stamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    summary = [
        '# Logging dependency correlation — summary', '', f'Generated: {stamp}', '',
        f'**{len(accounts)} accounts | {len(rows)} checks**', '',
        '## Original Script F results', '', table(['State', 'Checks'], sorted(orig.items())), '',
        '## Correlated results', '', table(['State', 'Checks'], sorted(corr.items())), '',
        '## Account breakdown', '',
        table(['Account', 'Checks', 'VALID', 'MISSING', 'ACCESS_DENIED', 'CROSS_ACCOUNT', 'UNVERIFIED'],
              [(names.get(a, a), len(items), *(sum(r['original_state'] == state for r in items)
                  for state in ('VALID', 'MISSING', 'ACCESS_DENIED', 'CROSS_ACCOUNT', 'UNVERIFIED')))
               for a, items in sorted(groups.items(), key=lambda x: names.get(x[0], x[0]))]), '',
        '## Interpretation', '',
        '- VALID means resource was accessible, not that logs were delivered.',
        '- MISSING is a Script F missing-resource response; inspect its AWS error.',
        '- ACCESS_DENIED is a permissions limitation, not proof of failure.',
        '- CROSS_ACCOUNT_CORROBORATED means exact ARN matched a VALID check in owning account.',
        '- CROSS_ACCOUNT_UNRESOLVED means insufficient evidence, **not a broken dependency**.',
        '- CROSS_ACCOUNT_OUTSIDE_SCOPE means owning account is not among supplied JSON files.',
        '- Correlation makes no AWS calls and cannot verify Splunk ingestion, delivery permissions, or log freshness.',
        '- Script F is not a full resource inventory; many cross-account checks may remain unresolved.', ''
    ]
    Path('dependency-summary.md').write_text('\n'.join(summary), encoding='utf-8')
    findings = ['# Logging dependency correlation — findings', '', f'Generated: {stamp}', '']
    for title, state in [('Missing destinations', 'MISSING'), ('Access denied', 'ACCESS_DENIED')]:
        findings += ['## ' + title, '']
        selected = [r for r in rows if r['correlated_state'] == state]
        findings += [table(['Account', 'Source', 'Relation', 'Destination', 'Detail'],
                           [(r['account_name'], r['source_type'], r['relation'], r['destination'], r['details'])
                            for r in selected]) if selected else 'None reported.', '']
    findings += ['## Cross-account follow-up', '',
                 table(['State', 'Checks'], [(state, corr[state]) for state in
                       ('CROSS_ACCOUNT_CORROBORATED', 'CROSS_ACCOUNT_UNRESOLVED',
                        'CROSS_ACCOUNT_OUTSIDE_SCOPE')]), '',
                 'See `dependency-map.csv` for all individual dependencies. Unresolved does not mean missing.', '']
    Path('dependency-findings.md').write_text('\n'.join(findings), encoding='utf-8')
    print(f'Accounts: {len(accounts)} | Checks: {len(rows)}')
    print('Original:', ', '.join(f'{k}={v}' for k, v in sorted(orig.items())))
    print('Correlated:', ', '.join(f'{k}={v}' for k, v in sorted(corr.items())))
    print('Created: dependency-summary.md, dependency-findings.md, dependency-map.csv')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f'Correlation failed: {exc}', file=sys.stderr)
        sys.exit(1)
