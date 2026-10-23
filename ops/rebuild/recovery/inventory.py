"""Export config and recovered DB identities; never authorize or contact Telegram."""
import json
import hashlib
from pathlib import Path
import re
import yaml
from manifest import sql, identifier as quote

def write_source_manifest(root, filename, records):
    sources = []
    for record_ in records:
        seed = json.dumps([record_['origins'], record_['legacy_source_id'], record_['source_type'], record_['legacy_identifier']], ensure_ascii=False, separators=(',', ':'))
        status = record_['legacy_status']
        disposition = {'paused': 'paused', 'banned': 'rejected', 'rejected': 'rejected', 'dead': 'inaccessible'}.get(status, 'pending')
        aliases = list(record_['aliases'])
        if record_['legacy_identifier'] not in aliases:
            aliases.append(record_['legacy_identifier'])
        sources.append({'identity': 'inventory:' + hashlib.sha256(seed.encode()).hexdigest(), 'source_id': None, 'legacy_source_id': record_['legacy_source_id'], 'kind': 'telegram' if record_['source_type'].startswith('telegram') else record_['source_type'], 'account_id': None, 'peer_type': None, 'native_id': None, 'aliases': aliases, 'provenance': record_['origins'], 'legacy_status': status, 'authorization': record_['authorization'], 'resolution_status': record_['resolution_status'], 'disposition': disposition, 'policy_version': '', 'conflicts': record_['conflicts']})
    canonical = json.dumps(sources, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    manifest_ = {'version': 'sources-manifest-v1', 'manifest_id': 'sha256:' + hashlib.sha256(canonical.encode()).hexdigest(), 'sources': sources}
    (Path(root) / filename).write_text(json.dumps(manifest_, ensure_ascii=False, indent=2))

def configured_channels(root):
    channels = []
    for obj in json.loads((Path(root) / 'configmaps.json').read_text())['items']:
        if obj['metadata']['name'] == 'noctis-config':
            config = yaml.safe_load(obj['data']['config.yaml'])
            channels.extend(config['noctis']['sources']['telegram'].get('channels', []))
    return channels

def export_config(root):
    records = []
    for channel in configured_channels(root):
        identifier = channel.get('id') or channel.get('username') or channel.get('invite')
        if identifier is None:
            raise ValueError('Unknown configured channel shape')
        records.append({'inventory_version': 1, 'legacy_source_id': None, 'source_type': 'telegram_channel', 'legacy_identifier': str(identifier), 'native_peer_id': None, 'aliases': [str(identifier)], 'origins': ['config'], 'legacy_status': 'configured', 'authorization': 'previously_configured', 'resolution_status': 'pending_verification', 'desired_collection': 'pending_policy_review', 'conflicts': [], 'database_reconciliation': 'blocked_until_verified_restore'})
    with (Path(root) / 'config-channel-inventory.jsonl').open('w') as output:
        for record_ in records:
            output.write(json.dumps(record_, ensure_ascii=False) + '\n')
    write_source_manifest(root, 'sources-manifest-config.json', records)
    return len(records)

def export_inventory(root, container, database):
    root = Path(root)
    # JSON conversion keeps every current/future source column. IDs are textual
    # in the interchange file even when the legacy SQL type is numeric.
    sources = json.loads(sql(container, database, "SELECT coalesce(json_agg((to_jsonb(s) || jsonb_build_object('id',s.id::text,'discovered_from',s.discovered_from::text)) ORDER BY s.id),'[]') FROM sources s"))
    history = []
    tables = set(json.loads(sql(container, database, "SELECT coalesce(json_agg(tablename),'[]') FROM pg_tables WHERE schemaname='public'")))
    for table, type_expression, identity_column in (('raw_content', 'source_type', 'source_id'), ('findings', 'source', 'source_id'), ('ioc_sightings', "'legacy_unclassified'::text", 'source_id'), ('source_triage_log', "'legacy_unclassified'::text", 'identifier')):
        if table not in tables:
            continue
        rows = json.loads(sql(container, database, 'SELECT coalesce(json_agg(row_to_json(s) ORDER BY source_type,source_id),\'[]\') FROM (SELECT ' + type_expression + ' AS source_type,' + quote(identity_column) + '::text AS source_id,count(*) AS observations FROM ' + quote(table) + ' GROUP BY 1,2) s'))
        history.extend(dict(row, origin='legacy_' + table) for row in rows)
    restrictions = {}
    for table in ('source_triage_log', 'discovered_blacklist'):
        if table in tables:
            restrictions[table] = json.loads(sql(container, database, 'SELECT coalesce(json_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),\'[]\') FROM ' + quote(table) + ' t'))
    (root / 'legacy-restrictions.json').write_text(json.dumps(restrictions, ensure_ascii=False, indent=2))
    with (root / 'sources.jsonl').open('w') as output:
        for source in sources:
            output.write(json.dumps(source, ensure_ascii=False) + '\n')
    (root / 'historical-identities.json').write_text(json.dumps(history, ensure_ascii=False, indent=2))
    records = []
    def record(origin, source_type, identifier, status, legacy_id=None):
        identifier = str(identifier)
        numeric = bool(re.fullmatch(r'-?[0-9]+', identifier))
        # A numeric legacy ID does not prove MTProto-vs-Bot-API representation,
        # account scope or peer kind. Preserve it without inventing native identity.
        records.append({'inventory_version': 1, 'legacy_source_id': legacy_id, 'source_type': source_type, 'legacy_identifier': identifier, 'native_peer_id': None, 'peer_type': None, 'account_scope': None, 'aliases': [] if numeric else [identifier], 'origins': [origin], 'legacy_status': status, 'authorization': 'previously_configured' if origin == 'config' else 'preserved_legacy_status', 'resolution_status': 'legacy_unresolved', 'desired_collection': 'pending_policy_review', 'conflicts': []})
    for channel in configured_channels(root):
        identifier = channel.get('id') or channel.get('username') or channel.get('invite')
        assert identifier is not None, 'Unknown configured channel shape'
        record('config', 'telegram_channel', identifier, 'configured')
    for source in sources:
        record('legacy_sources', source['type'], source['identifier'], source['status'], source['id'])
    for source in history:
        record(source['origin'], source['source_type'], source['source_id'], 'historical_only')
    groups = {}
    for record_ in records:
        groups.setdefault((record_['source_type'], record_['legacy_identifier']), []).append(record_)
    for group in groups.values():
        if len({r['legacy_status'] for r in group}) > 1:
            for record_ in group:
                record_['conflicts'].append('different_status_or_provenance_requires_review')
    with (root / 'channel-inventory.jsonl').open('w') as output:
        for record_ in records:
            output.write(json.dumps(record_, ensure_ascii=False) + '\n')
    write_source_manifest(root, 'sources-manifest-legacy.json', records)
    return {'sources': len(sources), 'configured': sum(r['origins'] == ['config'] for r in records), 'historical_identities': len(history), 'inventory_records': len(records), 'unresolved': sum(r['resolution_status'] == 'legacy_unresolved' for r in records), 'conflicts': sum(bool(r['conflicts']) for r in records)}
