#!/usr/bin/env python3
"""Offline reconciliation of preserved legacy inventory with private read-only RPC evidence.

Never emits a source-import manifest or changes authorization/collection policy.
Alias-only matches identify today's alias; they cannot establish historic identity.
"""
import argparse
import hashlib
import json
from pathlib import Path

def alias(value):
    return str(value).removeprefix('https://t.me/').removeprefix('t.me/').removeprefix('@').lower()

def reconcile(legacy, results, output):
    if output.exists() or output.parent.stat().st_mode & 0o077:
        raise ValueError('New output under private parent required')
    output.mkdir(mode=0o700)
    seeds = {}
    for path in sorted(results.glob('seed-*.json')):
        item = json.loads(path.read_text())
        if not item.get('result'):
            continue
        raw = item['result']['Peer']
        types = {'ChannelID': 'channel', 'ChatID': 'chat', 'UserID': 'user'}
        field = next(key for key in types if key in raw)
        seeds[alias(item['alias'])] = {'type': types[field], 'native_id': str(raw[field]), 'account': item['account'], 'checked_at': item['checked_at']}
    dialogs = json.loads((results / 'dialogs.json').read_text())
    numeric = {}
    for item in dialogs:
        numeric.setdefault(item['native_id'], []).append(item)
        if item['peer_type'] == 'channel':
            numeric.setdefault('-100' + item['native_id'], []).append(item)
    sources = [json.loads(line) for line in (legacy / 'sources.jsonl').read_text().splitlines()]
    history = json.loads((legacy / 'historical-identities.json').read_text())
    manifest = json.loads((legacy / 'sources-manifest-legacy.json').read_text())
    if len(sources) != 1781 or len(history) != 1823:
        raise ValueError('Preserved inventory count mismatch')
    counters = {'sources': len(sources), 'historical_identities': len(history), 'resolved_configuration_aliases': len(seeds), 'dialogs': len(dialogs), 'alias_only_current_matches': 0, 'numeric_candidates': 0}
    def record(original):
        aliases = original.get('aliases') or [original.get('identifier', original.get('legacy_identifier', ''))]
        current = [seeds[alias(value)] for value in aliases if alias(value) in seeds]
        candidates = [candidate for value in aliases for candidate in numeric.get(str(value), [])]
        counters['alias_only_current_matches'] += bool(current)
        counters['numeric_candidates'] += bool(candidates)
        return {'preserved': original, 'current_alias_matches': current, 'numeric_dialog_candidates': candidates,
                'historic_identity_verified': False, 'historic_account_scope': None,
                'identity_warning': 'Alias may be reassigned; numeric candidate has unverified historical type/account scope',
                'authorization': 'preserved only; no new authorization', 'disposition': 'pending explicit per-source review; no activation'}
    def save(name, item):
        path = output / name
        with path.open('x') as target:
            path.chmod(0o600); json.dump(item, target, ensure_ascii=False, indent=2)
    save('sources-reconciliation.json', [record(item) for item in sources])
    save('history-reconciliation.json', [record(item) for item in history])
    save('manifest-reconciliation.json', [record(item) for item in manifest['sources']])
    save('restrictions-preserved.json', json.loads((legacy / 'legacy-restrictions.json').read_text()))
    counters['conflicts_preserved'] = sum(bool(item.get('conflicts')) for item in manifest['sources'])
    counters['input_sha256'] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in [legacy / 'sources.jsonl', legacy / 'historical-identities.json', legacy / 'sources-manifest-legacy.json', legacy / 'legacy-restrictions.json']}
    counters['policy_written'] = False
    counters['complete_historical_identity_resolution'] = False
    save('receipt.json', counters)
    return counters

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ['legacy', 'results', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    reconcile(**vars(parser.parse_args()))
    print('Private offline reconciliation complete; historic identity and policy review remain pending')
