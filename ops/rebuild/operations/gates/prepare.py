#!/usr/bin/env python3
"""Offline proposals only. Never contacts Telegram, starts capture, or applies policy."""
import argparse
import hashlib
import json
import os
from pathlib import Path


def save(root, name, value):
    path = root / name
    with path.open('x') as handle:
        path.chmod(0o600)
        json.dump(value, handle, indent=2, ensure_ascii=False)


def select_peers(results, reconciliation):
    manifest = json.loads((reconciliation / 'manifest-reconciliation.json').read_text())
    peers = []
    for path in sorted(results.glob('seed-*.json')):
        item = json.loads(path.read_text())
        matches = [row for row in manifest if any(m['account'] == item['account'] and m['native_id'] == str(next(iter(item['result']['Peer'].values()))) for m in row['current_alias_matches'])]
        conflicts = [row['preserved'] for row in matches if row['preserved'].get('conflicts')]
        peer = item['result']['Peer']
        field = next(k for k in ('ChannelID', 'ChatID', 'UserID') if k in peer)
        peers.append({'account_id': str(item['account']), 'peer_type': {'ChannelID': 'channel', 'ChatID': 'chat', 'UserID': 'user'}[field],
                      'native_id': str(peer[field]), 'current_alias': item['alias'], 'checked_at': item['checked_at'],
                      'evidence': str(path), 'historic_identity_verified': False, 'historic_account_scope': None,
                      'preserved_matches': [row['preserved'] for row in matches], 'conflicts': conflicts,
                      'approval': 'pending', 'active': False, 'proposed_selection': False})
    eligible = [p for p in peers if not p['conflicts']]
    if len(peers) != 5 or not eligible:
        raise ValueError('Expected five peers and a conflict-free candidate; explicit review needed')
    eligible[0]['proposed_selection'] = True
    return peers


def prepare(inventory, output):
    if output.is_symlink() or output.resolve().is_relative_to(Path(__file__).resolve().parents[4]) or output.stat().st_mode & 0o077:
        raise ValueError('Output must be private 0700 outside repository, without symlink')
    peers = select_peers(inventory / 'results', inventory / 'reconciliation')
    reconciliation = inventory / 'reconciliation'
    save(output, 'pilot-permissions.proposal.json', {
        'schema': 'noctis-pilot-proposal-v1', 'approval': 'pending', 'executable': False,
        'peers': peers, 'disabled_peers': 4, 'active_peers': 0,
        'all_preserved_conflicts': [x['preserved'] for x in json.loads((reconciliation / 'manifest-reconciliation.json').read_text()) if x['preserved'].get('conflicts')],
        'restrictions': json.loads((reconciliation / 'restrictions-preserved.json').read_text()),
        'historical_identity': 'unverified; alias reassignment possible; no historical relabeling',
        'evidence_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(reconciliation.glob('*.json'))},
        'access_hash_copied': False})
    save(output, 'pilot-runbook.json', {
        'schema': 'noctis-pilot-runbook-v1', 'approval': 'pending', 'state': 'BLOCKED',
        'blockers': ['final binary freeze/hash and local QA evidence pending', 'explicit pilot approval pending',
            'operator owner-preflight and verified session/source/epoch identities pending'],
        'capture_budget_implementation': 'SQL006 and guarded SDK establishment implemented; verify exact candidate evidence before use',
        'binary': None, 'binary_sha256': None,
        'destination_proposal': {'database': 'noctis_v2_pilot_20261018', 'host': 'isolated local PostgreSQL16 network none; create only after approval',
            'migration_owner_role': 'noctis_pilot_owner', 'runtime_login_role': 'noctis_pilot_telegram', 'runtime_role': 'telegram',
            'database_secret_file': str(output / 'pilot-database.secret'), 'credential_file': str(inventory / 'credentials.json'),
            'session_file': str(output / 'session/pilot.session'), 'session_source': str(inventory / 'session/collector.session'), 'created': False},
        'limits_proposed': {'total_wall_seconds': 600, 'runs': 2, 'seconds_per_run': 300, 'bootstrap_runs_max': 1, 'bootstrap_messages_max': 100,
            'application_and_control_admissions_total_both_runs_and_bootstrap': 256,
            'admission_unit': 'one control establishment including SDK initialization/retries plus public application API calls; not every internal SDK RPC or physical packet',
            'observations_total': 1000, 'content_bytes_total': 67108864,
            'byte_unit': 'persisted payload per new observation; not network ingress', 'ai_cost': 0, 'delivery': 'off'},
        'owner_preflight': ['record owner identity/time', 'verify original controllers stopped and no other authorization consumer',
            'verify session custody and exclusive consumer lock held until confirmed exit', 'verify final binary hash, policy and cumulative counters',
            'verify own DB role privileges and zero AI/delivery', 'approve exactly one proposed peer; preserve all restrictions'],
        'epochs': {'live': 'same persisted epoch and cursor across two runs', 'bootstrap': 'independent epoch; at most one bounded bootstrap; never reset on restart'},
        'shutdown': ['SIGTERM', 'wait for confirmed process exit', 'verify receipt closed=true, committed cursor, gap/coverage status and released lock', 'lease expiry alone is insufficient'],
        'restart_requires': ['first run confirmed exit', 'closed=true', 'no other consumer', 'same epochs and persisted cumulative budgets'],
        'stop_criteria': ['FLOOD_WAIT', 'revocation', 'any cumulative limit reached', 'shutdown uncertain', 'identity or policy conflict', 'unexpected paid inference or delivery'],
        'automatic_retry': False,
        'receipt_criteria': ['binary/hash and approved policy', 'both runs exact start/end', 'application/control admissions, observations and persisted payload/metadata cumulative counts', 'bootstrap separate proof',
            'epochs/cursors preserved', 'closed=true on both runs', 'coverage and gap dispositions', 'no duplicate downstream effects', 'AI=0 and delivery=off'],
        'g4_status': 'pending; no new content implies pending, never automatic widening'})


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.inventory, args.output)
