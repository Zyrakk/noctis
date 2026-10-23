#!/usr/bin/env python3
"""UID-guarded production snapshot, using the existing encrypted archive format."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

from preflight import verify, kube
from release import DB

path = Path(__file__).resolve().parents[1] / 'operations/backup.py'
spec = importlib.util.spec_from_file_location('operations_backup', path)
existing = importlib.util.module_from_spec(spec); spec.loader.exec_module(existing)


class Transport:
    def __init__(self, namespace_uid, pod_uid, image):
        verify(namespace_uid)
        if not re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}', image):
            raise ValueError('Expected immutable PostgreSQL image required')
        self.identity, self.image = pod_uid, image
        self.check()

    def check(self):
        pod = json.loads(kube('get', 'pod', 'noctis-v2-postgres-0', '-n', 'noctis-v2', '-o', 'json'))
        statuses = pod['status'].get('containerStatuses', [])
        if pod['metadata']['uid'] != self.identity or pod['spec']['containers'][0]['image'] != self.image or not statuses or not all(s.get('ready') for s in statuses):
            raise ValueError('Expected ready PostgreSQL pod UID and image required')

    def command(self, *args):
        self.check()
        # Password stays in the PostgreSQL container's environment, never argv/output.
        return ['kubectl', '--context=zcloud-cluster', '--request-timeout=30s', 'exec', '-i', '-n', 'noctis-v2', 'noctis-v2-postgres-0', '-c', 'postgres', '--', '/bin/sh', '-ec', 'export PGHOST=/var/run/postgresql PGPASSWORD="$POSTGRES_PASSWORD"; exec "$@"', 'production-backup', *args]


def backup(namespace_uid, pod_uid, image, destination, key):
    if not Path(destination).absolute().is_relative_to(Path('/home/zyrak/.local/share/noctis-rebuild')):
        raise ValueError('Protected existing rebuild staging root required')
    key = existing.private_file(key)
    source = Transport(namespace_uid, pod_uid, image)
    root = existing.new_root(destination)
    started = time.monotonic()
    try:
        with existing.snapshot(source, DB) as token:
            with (root / 'database.dump.partial').open('xb') as handle:
                existing.stream(source, ['pg_dump', '-U', 'noctis', '-d', DB, '--format=custom', '--snapshot=' + token], handle.write)
            full = existing.manifest(source, DB, token)
            queries = existing.representatives(source, DB, token)
        source.check()
        if not full['tables'].get('public.noctis_v2_migrations') or not full['migrations'] or full['sequences']:
            raise ValueError('Migrated independent v2 schema without non-MVCC sequences required')
        if any('public.' + table in full['tables'] for table in ('sources', 'messages', 'schema_migrations', 'findings', 'raw_content')):
            raise ValueError('Legacy tables prohibited')
        (root / 'database.dump.partial').rename(root / 'database.dump')
        (root / 'manifest.json').write_text(json.dumps(full, indent=2))
        (root / 'representative.json').write_text(json.dumps(queries, indent=2))
        report = {'format': 'noctis-v2-logical-v1', 'source_database': DB, 'source_container_id': source.identity, 'source_namespace_uid': namespace_uid, 'source_image': image, 'snapshot_shared': True, 'dump_sha256': hashlib.file_digest((root / 'database.dump').open('rb'), 'sha256').hexdigest(), 'rows': sum(t['rows'] for t in full['tables'].values()), 'tables': len(full['tables']), 'backup_seconds': time.monotonic() - started, 'server_version': existing.sql(source, DB, 'SHOW server_version').decode().strip(), 'pg_dump_version': subprocess.check_output(source.command('pg_dump', '--version'), text=True).strip(), 'external_secrets_required': ['AI master key/key_id', 'admin/TLS config', 'collector sessions', 'database service config']}
        source.check()
        (root / 'recovery-report.json').write_text(json.dumps(report, indent=2))
        existing.protect_artifacts(root, key)
        existing.describe_encryption(root, 'Production UID-scoped shared snapshot; restore only to owned isolated Docker fixture using operations/backup.py restore')
        return {'result': 'backed-up', 'tables': report['tables'], 'rows': report['rows'], 'snapshot_shared': True, 'secrets_printed': False}
    except BaseException:
        (root / 'FAILED').write_text('Incomplete backup; never restore as verified')
        raise


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('namespace-uid', 'pod-uid', 'image', 'destination', 'key'):
        parser.add_argument('--' + name, required=True)
    args = vars(parser.parse_args())
    print(json.dumps(backup(**args)))
