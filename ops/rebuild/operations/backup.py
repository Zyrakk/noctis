#!/usr/bin/env python3
"""V2 consistent logical backup and isolated restore. No infrastructure discovery.

Uses the P0 snapshot/manifest/age interfaces unchanged. Connections use a named
Docker container's local Unix socket; passwords never enter arguments or logs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'recovery'))
from manifest import compare, manifest, sql, stream
from recover import snapshot
from protect import protect_artifacts

if not __debug__:
    raise RuntimeError('Safety checks require Python without optimization')

IMAGE = 'postgres:16-bookworm'
MEMBERS = {'database.dump', 'manifest.json', 'representative.json', 'recovery-report.json'}
LEGACY_CONFIG_REQUIRED = {
    'api': {'ai-master.json', 'admin.secret', 'database.secret', 'tls.crt', 'tls.key'},
    'worker': {'ai-master.json', 'database.secret'},
    'collector': {'database.secret'},
    'telegram': {'database.secret', 'collector.session', 'telegram-credentials.json'},
}
CONFIG_DATABASES = {mode: 'database-' + mode + '.secret' for mode in LEGACY_CONFIG_REQUIRED}
CONFIG_REQUIRED = {mode: (files - {'database.secret'}) | {CONFIG_DATABASES[mode]}
                   for mode, files in LEGACY_CONFIG_REQUIRED.items()}
V3_CONFIG_REQUIRED = {mode: set(files) for mode, files in CONFIG_REQUIRED.items()}
CONFIG_REQUIRED['telegram'].add('capture-policy.json')
CONFIG_FILES = set.union(*CONFIG_REQUIRED.values()) | {'runtime-config.json', 'database.secret'}

def configuration_required(modes):
    if not modes or set(modes) - CONFIG_REQUIRED.keys():
        raise ValueError('Explicit known configuration modes required')
    return set.union(*(CONFIG_REQUIRED[mode] for mode in modes))

def validate_configuration(root, names):
    if 'ai-master.json' in names:
        master = json.loads((root / 'ai-master.json').read_text())
        if not master.get('key_id') or len(bytes.fromhex(master.get('key', ''))) != 32:
            raise ValueError('Invalid recovered master key')
    if 'telegram-credentials.json' in names:
        credentials = json.loads((root / 'telegram-credentials.json').read_text())
        if (not credentials.get('account') or not isinstance(credentials.get('api_id'), int)
                or credentials['api_id'] <= 0 or not credentials.get('api_hash')):
            raise ValueError('Invalid Telegram credentials')
    if 'collector.session' in names and not (root / 'collector.session').stat().st_size:
        raise ValueError('Empty Telegram session')
    if 'capture-policy.json' in names:
        if (root / 'capture-policy.json').stat().st_mode & 0o777 != 0o600:
            raise ValueError('Capture policy requires exact mode0600')
        policy = json.loads((root / 'capture-policy.json').read_text())
        if (not isinstance(policy, dict) or type(policy.get('version')) is not int
                or policy['version'] not in (1, 2) or not policy.get('budget_id')):
            raise ValueError('Invalid capture policy envelope; validate semantics with capture-policy-validate')
        if policy['version'] == 2 and (any(not isinstance(policy.get(field), str) or not policy[field]
                for field in ('account', 'auth_generation', 'period_anchor', 'expires_at', 'actor', 'reason'))
                or type(policy.get('revision')) is not int or policy['revision'] < 1):
            raise ValueError('Invalid production consent envelope; validate semantics with capture-policy-validate')
        if 'telegram-credentials.json' in names and policy.get('account') != credentials['account']:
            raise ValueError('Capture policy account differs from Telegram credentials')

def configuration_hashes(root, names):
    return {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sorted(names)}

def private_file(path):
    path = Path(path)
    if path.absolute() != path.resolve() or path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError('Private regular file with permissions0600 required')
    return path

def new_root(path):
    path = Path(path).absolute()
    parent = path.parent
    if path != path.resolve() or parent.is_symlink() or not parent.is_dir() or parent.stat().st_mode & 0o077:
        raise ValueError('Private existing parent directory required')
    path.mkdir(mode=0o700, exist_ok=False)
    return path

class Transport:
    def __init__(self, container, user='noctis', expected_id=None):
        if not re.fullmatch(r'[a-zA-Z0-9_.-]+', container + user):
            raise ValueError('Invalid container/user')
        self.container, self.user = container, user
        self.info = json.loads(subprocess.check_output(['docker', 'inspect', container]))[0]
        self.identity = self.info['Id']
        if expected_id is not None and expected_id != self.identity:
            raise ValueError('Container identity mismatch')
        if not self.info['State']['Running']:
            raise ValueError('Source must already be running; tool never starts preserved containers')

    def command(self, *args):
        args = list(args)
        for index, value in enumerate(args[:-1]):
            if value == '-U':
                args[index + 1] = self.user
        return ['docker', 'exec', '-i', '-e', 'PGHOST=/var/run/postgresql', self.identity, *args]

def representatives(transport, database, token=None):
    tables = ['intelligence_cases', 'case_revisions', 'claim_versions', 'evidence_spans', 'observations',
              'checkpoints', 'telegram_history_cursors', 'telegram_accounts', 'jobs', 'ai_jobs', 'outbox', 'ai_attempts']
    result = {}
    for table in tables:
        exists = sql(transport, database, "SELECT to_regclass('noctis_v2." + table + "') IS NOT NULL", token).strip() == b't'
        if exists:
            rows = sql(transport, database, 'SELECT row_to_json(t)::text FROM noctis_v2.' + table + ' t ORDER BY row_to_json(t)::text COLLATE "C" LIMIT 20', token)
            result[table] = {'sample_sha256': hashlib.sha256(rows).hexdigest()}
    # Referential semantic query covers actual case->observation citation membership.
    rows = sql(transport, database, 'SELECT c.id::text,c.revision,count(r.*) FROM noctis_v2.intelligence_cases c LEFT JOIN noctis_v2.case_revisions r ON r.case_id=c.id GROUP BY c.id,c.revision ORDER BY c.id', token)
    result['case_revision_join'] = {'sha256': hashlib.sha256(rows).hexdigest()}
    return result

def describe_encryption(root, description):
    """Keep P0's verified age interface, replace its legacy-specific note."""
    path = Path(root) / 'logical-encryption-report.json'
    report = json.loads(path.read_text())
    report['restore_data'] = description
    path.write_text(json.dumps(report, indent=2))

def backup_config(source_directory, destination, key, modes=('api',)):
    key = private_file(key)
    source = Path(source_directory).absolute()
    if source != source.resolve() or not source.is_dir() or source.stat().st_mode & 0o077:
        raise ValueError('Private source directory required')
    allowed = sorted(CONFIG_FILES)
    files = [private_file(source / name) for name in allowed if (source / name).exists()]
    required = configuration_required(modes)
    missing = required - {file.name for file in files}
    if missing:
        raise ValueError('Required configuration missing (including master key where applicable): ' + ', '.join(sorted(missing)))
    validate_configuration(source, {file.name for file in files})
    root = new_root(destination)
    for file in files:
        shutil.copyfile(file, root / file.name)
        (root / file.name).chmod(0o600)
    (root / 'recovery-report.json').write_text(json.dumps({'format': 'noctis-v2-config-v4', 'modes': sorted(set(modes)), 'database_files': {mode: CONFIG_DATABASES[mode] for mode in sorted(set(modes))}, 'capture_policy_files': {'telegram': 'capture-policy.json'} if 'telegram' in modes else {}, 'sha256': configuration_hashes(root, [file.name for file in files]), 'files': [file.name for file in files], 'contains_secrets': True}, indent=2))
    protect_artifacts(root, key)
    describe_encryption(root, 'Protected external configuration; no PostgreSQL container or session is started')
    return {'result': 'pass', 'configuration_encrypted': True, 'full_decrypt_verified': True, 'files': [file.name for file in files]}

def restore_config(archive, key, destination):
    private_file(archive); private_file(key)
    root = new_root(destination)
    plain = root / 'configuration.tar'
    with plain.open('xb') as target:
        plain.chmod(0o600)
        subprocess.run(['age', '-d', '-i', str(key), str(archive)], stdout=target, check=True, stderr=subprocess.DEVNULL)
    with tarfile.open(plain) as bundle:
        members = bundle.getmembers()
        names = {member.name for member in members}
        if len(names) != len(members) or 'recovery-report.json' not in names or not names <= CONFIG_FILES | {'recovery-report.json'}:
            raise ValueError('Invalid configuration archive membership')
        for member in members:
            if not member.isfile() or member.size > 64 * 1024**2:
                raise ValueError('Unsafe configuration member')
            with bundle.extractfile(member) as source, (root / member.name).open('xb') as target:
                (root / member.name).chmod(0o600)
                shutil.copyfileobj(source, target)
    report = json.loads((root / 'recovery-report.json').read_text())
    version = report.get('format')
    modes = ['api'] if version == 'noctis-v2-config-v1' else report.get('modes', [])
    legacy = version in {'noctis-v2-config-v1', 'noctis-v2-config-v2'}
    required = (set.union(*(LEGACY_CONFIG_REQUIRED[mode] for mode in modes))
                if legacy and modes and not set(modes) - LEGACY_CONFIG_REQUIRED.keys()
                else set.union(*(V3_CONFIG_REQUIRED[mode] for mode in modes))
                if version == 'noctis-v2-config-v3' and modes and not set(modes) - V3_CONFIG_REQUIRED.keys()
                else configuration_required(modes))
    if (version not in {'noctis-v2-config-v1', 'noctis-v2-config-v2', 'noctis-v2-config-v3', 'noctis-v2-config-v4'}
            or set(report['files']) != names - {'recovery-report.json'}
            or not required <= names
            or (not legacy and report.get('database_files') != {mode: CONFIG_DATABASES[mode] for mode in modes})):
        raise ValueError('Configuration manifest mismatch')
    if version == 'noctis-v2-config-v4' and (
            report.get('capture_policy_files') != ({'telegram': 'capture-policy.json'} if 'telegram' in modes else {})
            or report.get('sha256') != configuration_hashes(root, names - {'recovery-report.json'})):
        raise ValueError('Configuration policy mapping or checksum mismatch')
    validate_configuration(root, names)
    return {'result': 'pass', 'configuration_restored': True, 'files': sorted(names - {'recovery-report.json'}),
            'modes': modes, 'database_files': {mode: ('database.secret' if legacy else CONFIG_DATABASES[mode]) for mode in modes},
            'coverage': 'legacy-shared-dsn-only' if legacy else 'selected-mode-specific-dsns-without-required-capture-policy' if version == 'noctis-v2-config-v3' else 'selected-mode-specific-dsns-and-capture-policy',
            'capture_policy_files': report.get('capture_policy_files', {}),
            'capture_policy_semantics': 'requires offline capture-policy-validate and restored database binding verification' if 'telegram' in modes else 'not-selected'}

def backup(container, identity, user, database, destination, key):
    if not re.fullmatch(r'noctis_v2_[a-z0-9_]+', database):
        raise ValueError('Independent named v2 database required')
    key = private_file(key)
    source = Transport(container, user, identity)
    root = new_root(destination)
    started = time.monotonic()
    try:
        with snapshot(source, database) as token:
            with (root / 'database.dump.partial').open('xb') as handle:
                stream(source, ['pg_dump', '-U', 'noctis', '-d', database, '--format=custom', '--snapshot=' + token], handle.write)
            full = manifest(source, database, token)
            queries = representatives(source, database, token)
        if not full['tables'].get('public.noctis_v2_migrations') or not full['migrations']:
            raise ValueError('No v2 migration registry; refusing legacy backup')
        if full['sequences']:
            raise ValueError('Sequence state is not MVCC snapshot-isolated; require a separately reviewed paused export')
        if any('public.' + table in full['tables'] for table in ['sources', 'messages', 'schema_migrations', 'findings', 'raw_content']):
            raise ValueError('Legacy public tables detected; independent v2 DB required')
        (root / 'database.dump.partial').rename(root / 'database.dump')
        (root / 'manifest.json').write_text(json.dumps(full, indent=2))
        (root / 'representative.json').write_text(json.dumps(queries, indent=2))
        report = {'format': 'noctis-v2-logical-v1', 'source_database': database, 'source_container_id': source.identity,
                  'snapshot_shared': True, 'dump_sha256': hashlib.file_digest((root / 'database.dump').open('rb'), 'sha256').hexdigest(),
                  'rows': sum(t['rows'] for t in full['tables'].values()), 'tables': len(full['tables']),
                  'backup_seconds': time.monotonic() - started,
                  'server_version': sql(source, database, 'SHOW server_version').decode().strip(),
                  'pg_dump_version': subprocess.check_output(source.command('pg_dump', '--version'), text=True).strip(),
                  'external_secrets_required': ['AI master key/key_id', 'admin/TLS config', 'collector sessions', 'database service config']}
        (root / 'recovery-report.json').write_text(json.dumps(report, indent=2))
        protect_artifacts(root, key)
        describe_encryption(root, 'Verified logical dump in private staging; each owned restore container is removed after verification')
        return report
    except BaseException:
        (root / 'FAILED').write_text('Incomplete backup; never restore as verified')
        raise

def unpack(archive, key, root):
    private_file(archive); private_file(key)
    plain = root / 'backup.tar'
    with plain.open('xb') as target:
        subprocess.run(['age', '-d', '-i', str(key), str(archive)], stdout=target, check=True, stderr=subprocess.DEVNULL)
    with tarfile.open(plain) as bundle:
        entries = bundle.getmembers()
        if {m.name for m in entries} != MEMBERS or len(entries) != len(MEMBERS):
            raise ValueError('Incomplete/extra/duplicate archive membership')
        for member in entries:
            if not member.isfile() or member.size > 64 * 1024**3:
                raise ValueError('Unsafe archive member')
            with bundle.extractfile(member) as source, (root / member.name).open('xb') as target:
                import shutil
                shutil.copyfileobj(source, target)
    report = json.loads((root / 'recovery-report.json').read_text())
    if report['format'] != 'noctis-v2-logical-v1' or hashlib.file_digest((root / 'database.dump').open('rb'), 'sha256').hexdigest() != report['dump_sha256']:
        raise ValueError('Corrupt dump or unsupported format')
    return report

def owned_info(identity, owner):
    info = json.loads(subprocess.check_output(['docker', 'inspect', identity]))[0]
    if info['Id'] != identity or info['Config']['Labels'].get('noctis.restore.owner') != owner or info['HostConfig']['NetworkMode'] != 'none':
        raise ValueError('Restore ownership/isolation mismatch')
    return info

def restore(archive, key, destination, fail_after_restore=False):
    root = new_root(destination)
    identity = None
    owner = uuid.uuid4().hex
    started = time.monotonic()
    try:
        if shutil.disk_usage(root).free < max(Path(archive).stat().st_size * 4, 512 * 1024**2):
            raise ValueError('Insufficient local staging capacity; restore target also needs independently verified capacity')
        source = unpack(archive, key, root)
        database = 'noctis_v2_restore_' + owner[:12]
        name = 'noctis-v2-restore-' + owner[:12]
        identity = subprocess.check_output(['docker', 'create', '--name', name, '--label', 'noctis.restore.owner=' + owner,
            '--network', 'none', '--memory', '512m', '--cpus', '1', '-e', 'POSTGRES_USER=noctis', '-e', 'POSTGRES_DB=' + database,
            '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', IMAGE, '-c', 'listen_addresses='], text=True).strip()
        info = owned_info(identity, owner)
        subprocess.run(['docker', 'start', identity], check=True, stdout=subprocess.DEVNULL)
        target = Transport(identity)
        for _ in range(120):
            ready = subprocess.run(target.command('psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-U', 'noctis', '-d', database, '-c', 'SELECT 1'), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('Restore PostgreSQL timeout')
        if sql(target, database, "SELECT count(*) FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')").strip() != b'0':
            raise ValueError('Destination must be fresh and empty')
        if source['source_container_id'] == identity or source['source_database'] == database:
            raise ValueError('Refusing origin as restore destination')
        with (root / 'database.dump').open('rb') as handle:
            subprocess.run(target.command('pg_restore', '-U', 'noctis', '-d', database, '--exit-on-error', '--single-transaction', '--no-owner', '--no-privileges'), stdin=handle, check=True, stdout=subprocess.DEVNULL)
        if fail_after_restore:
            raise RuntimeError('Injected failure after restore before verification')
        actual = manifest(target, database)
        compare(json.loads((root / 'manifest.json').read_text()), actual)
        compare(json.loads((root / 'representative.json').read_text()), representatives(target, database))
        result = {'result': 'pass', 'schema_migrations_counts_digests_queries': 'exact', 'source_rows': source['rows'],
                  'tables': source['tables'], 'restore_seconds': time.monotonic() - started, 'network': 'none',
                  'memory_limit_bytes': 512 * 1024**2, 'cpu_limit': 1, 'database': database, 'owned_container_removed': False}
        result['postgres_image_id'] = info['Image']
    except BaseException:
        (root / 'FAILED').write_text('Restore incomplete or not verified')
        raise
    finally:
        if identity:
            owned_info(identity, owner)
            subprocess.run(['docker', 'rm', '-f', '-v', identity], check=True, stdout=subprocess.DEVNULL)
            if subprocess.run(['docker', 'inspect', identity], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                raise RuntimeError('Owned restore container cleanup failed')
    result['owned_container_removed'] = True
    (root / 'restore-report.json').write_text(json.dumps(result, indent=2))
    return result

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='action', required=True)
    export = sub.add_parser('backup')
    for flag in ['container', 'container-id', 'user', 'database', 'destination', 'key']:
        export.add_argument('--' + flag, required=True)
    load = sub.add_parser('restore')
    for flag in ['archive', 'key', 'destination']:
        load.add_argument('--' + flag, required=True)
    config = sub.add_parser('backup-config')
    for flag in ['source-directory', 'destination', 'key']:
        config.add_argument('--' + flag, required=True)
    config.add_argument('--mode', dest='modes', action='append', choices=sorted(CONFIG_REQUIRED), required=True)
    config_load = sub.add_parser('restore-config')
    for flag in ['archive', 'key', 'destination']:
        config_load.add_argument('--' + flag, required=True)
    args = vars(parser.parse_args()); action = args.pop('action')
    if action == 'backup':
        args['identity'] = args.pop('container_id')
        result = backup(**args)
    elif action == 'restore':
        result = restore(**args)
    elif action == 'backup-config':
        result = backup_config(**args)
    else:
        result = restore_config(**args)
    print(json.dumps(result))

if __name__ == '__main__':
    main()
