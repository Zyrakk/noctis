#!/usr/bin/env python3
"""Isolated PG16 recovery, consistent dump and independent restore comparison.

Requires preserve.py to have succeeded. Never accepts a production DSN.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import contextlib
import selectors
import uuid
from manifest import manifest, compare, sql
from inventory import export_inventory
from manifest import command as transport_command, KubeTransport, stream, representative

if not __debug__:
    raise RuntimeError("Safety checks require Python without optimization")

IMAGE = "postgres@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea"

def verify_architecture(source, target):
    if source != target:
        raise ValueError("Physical recovery blocked: source/image architecture mismatch")

def verify_transfer(expected, actual):
    if expected != actual:
        raise ValueError('Transferred member, size or SHA256 mismatch')

def validate_source_settings(settings):
    # PG renders '(disabled)' for archive_command with archive_mode=off.
    assert settings['archive_mode'] == settings['autovacuum'] == 'off'
    assert settings['archive_command'] in ('', '(disabled)')
    for key in ('listen_addresses','restore_command','primary_conninfo','shared_preload_libraries','session_preload_libraries','local_preload_libraries'):
        assert settings[key] == '', key
    assert settings['default_transaction_read_only'] == 'on' and settings['unix_socket_directories'] == '/tmp'
    assert all(settings[key] == '0' for key in ('max_worker_processes','max_wal_senders','max_logical_replication_workers'))

def command(*args, **kwargs):
    return subprocess.run(list(args), check=True, **kwargs)

@contextlib.contextmanager
def snapshot(container, database):
    process = subprocess.Popen(transport_command(container, 'psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-U', 'noctis', '-d', database), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        process.stdin.write(b'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT pg_export_snapshot();\n'); process.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(30):
                raise TimeoutError('Snapshot exporter did not respond')
        token = process.stdout.readline().decode().strip()
        if not token or any(c not in '0123456789ABCDEF-' for c in token):
            raise RuntimeError('Snapshot export failed')
        yield token
        if process.poll() is not None:
            raise RuntimeError('Snapshot exporter exited before consumer completion')
        process.stdin.write(b'COMMIT;\n'); process.stdin.close()
        if process.wait(timeout=30):
            raise RuntimeError('Snapshot transaction failed')
    finally:
        if process.poll() is None:
            process.kill(); process.wait()
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()

def logical_export(container, database, output):
    output = Path(output)
    output.mkdir(mode=0o700)
    temporary = output / 'database.dump.partial'
    with snapshot(container, database) as token:
        with temporary.open('xb') as handle:
            stream(container, ['pg_dump', '-U', 'noctis', '-d', database, '--format=custom', '--snapshot=' + token], handle.write)
        result = manifest(container, database, token)
        queries = representative(container, database, token)
        acl = sql(container, database, "SELECT json_build_object('roles',(SELECT json_agg(row_to_json(r)) FROM (SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls FROM pg_roles ORDER BY rolname) r),'relations',(SELECT json_agg(row_to_json(t)) FROM (SELECT n.nspname,c.relname,c.relacl FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') ORDER BY n.nspname,c.relname) t),'schemas',(SELECT json_agg(row_to_json(n)) FROM (SELECT nspname,nspacl FROM pg_namespace ORDER BY nspname) n),'database',(SELECT datacl FROM pg_database WHERE datname=current_database()),'default_acl',(SELECT json_agg(row_to_json(d)) FROM pg_default_acl d))", token)
    temporary.rename(output / 'database.dump')
    (output / 'manifest.json').write_text(json.dumps(result, indent=2))
    (output / 'roles-acl.json').write_bytes(acl)
    (output / 'representative-source.json').write_text(json.dumps(queries, indent=2))
    return result

def verify_preserved(root):
    from preserve import verify_copy, verify_metadata
    import tarfile
    root = Path(root)
    for name in ('database', 'session'):
        state = json.loads((root / (name + '.verified.json')).read_text())
        assert state['hashes_match'] and state['source_unchanged']
        expected = dict((path, digest) for digest, path in (line.split('  ', 1) for line in (root / (name + '.source.sha256')).read_text().splitlines()))
        actual = {}
        with tarfile.open(root / (name + '.tar')) as archive:
            members = archive.getmembers()
            verify_metadata((root / (name + '.metadata')).read_bytes(), members)
            for member in members:
                assert not member.name.startswith('/') and '..' not in Path(member.name).parts
                if member.isfile():
                    actual[member.name] = hashlib.file_digest(archive.extractfile(member), 'sha256').hexdigest()
        verify_copy(expected, actual)

def start_arm(auxiliary, pod, root):
    root = Path(root)
    origin = json.loads((root / 'architecture.json').read_text())
    verify_architecture(origin['source'], 'arm64')
    verify_preserved(root)
    with (root / 'database.tar').open('rb') as archive:
        auxiliary.exec(pod, 'tar', 'xof', '-', '-C', '/work', stdin=archive, check=True, timeout=600)
    # Actual transferred membership must match, not merely the expected subset.
    actual = auxiliary.exec(pod, 'sh', '-ec', 'cd /work; find ./pgdata -type f -exec sha256sum {} + | sort', check=True, stdout=subprocess.PIPE, timeout=300).stdout
    verify_transfer((root / 'database.source.sha256').read_bytes(), actual)
    import tarfile
    with tarfile.open(root / 'database.tar') as archive:
        expected_sizes = {m.name: m.size for m in archive.getmembers() if m.isfile()}
    sizes = auxiliary.exec(pod, 'sh', '-ec', "cd /work; find ./pgdata -type f -exec stat -c '%s %n' {} +", check=True, stdout=subprocess.PIPE, timeout=60).stdout.decode()
    actual_sizes = {name: int(size) for size, name in (line.split(' ', 1) for line in sizes.splitlines())}
    verify_transfer(expected_sizes, actual_sizes)
    (auxiliary.root / 'transfer-report.json').write_text(json.dumps({'members': len(actual_sizes), 'bytes': sum(actual_sizes.values()), 'hashes_match': True, 'sizes_match': True, 'membership_match': True, 'session_transferred': False, 'key_transferred': False}, indent=2))
    script = """set -eu
test "$(cat /work/pgdata/PG_VERSION)" = 16
test "$(uname -m)" = aarch64
test ! -e /work/pgdata/standby.signal
test ! -e /work/pgdata/recovery.signal
test -z "$(find /work/pgdata -type l)"
chmod 700 /work/pgdata
rm -f /work/pgdata/postmaster.pid
if test -f /work/pgdata/postgresql.auto.conf; then mv /work/pgdata/postgresql.auto.conf /work/original-postgresql.auto.conf; fi
printf 'local all all trust\\n' > /work/recovery-hba.conf
cat > /work/recovery.conf <<'EOF'
data_directory='/work/pgdata'
hba_file='/work/recovery-hba.conf'
ident_file='/work/pgdata/pg_ident.conf'
listen_addresses=''
unix_socket_directories='/tmp'
archive_mode=off
archive_command=''
restore_command=''
primary_conninfo=''
shared_preload_libraries=''
session_preload_libraries=''
local_preload_libraries=''
max_worker_processes=0
max_wal_senders=0
max_logical_replication_workers=0
autovacuum=off
default_transaction_read_only=on
logging_collector=off
EOF
pg_ctl -D /work/pgdata -l /work/postgres.log -o '-c config_file=/work/recovery.conf' -w start
"""
    auxiliary.exec(pod, 'sh', '-ec', script, check=True, stdout=subprocess.DEVNULL, timeout=90)
    transport = KubeTransport(pod)
    settings = json.loads(sql(transport, 'noctis', "SELECT json_object_agg(name,setting) FROM pg_settings WHERE name IN ('listen_addresses','archive_mode','archive_command','restore_command','primary_conninfo','shared_preload_libraries','session_preload_libraries','local_preload_libraries','max_worker_processes','max_wal_senders','max_logical_replication_workers','autovacuum','default_transaction_read_only','unix_socket_directories')"))
    (auxiliary.root / 'effective-settings.json').write_text(json.dumps(settings, indent=2))
    validate_source_settings(settings)
    auxiliary.exec(pod, 'sh', '-ec', "! awk '$4 == \"0A\" && $2 ~ /:1538$/ {found=1} END {exit !found}' /proc/net/tcp /proc/net/tcp6", check=True)
    return transport, settings

def restore_logical(root, source, databases):
    root = Path(root)
    name = 'noctis-private-restore-' + uuid.uuid4().hex[:10]
    data = root / 'restore-data'
    data.mkdir(mode=0o700)
    first = databases[0]
    encoding = first['encoding']
    locale = first['collate']
    args = ['docker', 'run', '-d', '--name', name, '--network', 'none', '--mount', f'type=bind,src={data},dst=/var/lib/postgresql/data', '-e', 'PGHOST=/tmp', '-e', 'POSTGRES_USER=noctis', '-e', 'POSTGRES_DB=restore_control', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', '-e', 'POSTGRES_INITDB_ARGS=--encoding=' + encoding + ' --locale=' + locale, IMAGE, '-c', 'listen_addresses=', '-c', 'unix_socket_directories=/tmp,/var/run/postgresql']
    created = False
    try:
        command(*args, stdout=subprocess.DEVNULL)
        created = True
        (root / 'restore-container.json').write_text(json.dumps({'name': name, 'network': 'none', 'image': IMAGE}))
        for _ in range(60):
            probe = subprocess.run(transport_command(name, 'psql', '-XqAt', '-U', 'noctis', '-d', 'restore_control', '-c', 'SELECT 1'), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Restore destination not ready')
        environment = {'server': json.loads(sql(name, 'restore_control', "SELECT json_build_object('version',version(),'encoding',current_setting('server_encoding'),'collation',datcollate,'ctype',datctype) FROM pg_database WHERE datname=current_database()")), 'pg_restore': subprocess.check_output(transport_command(name, 'pg_restore', '--version'), text=True).strip(), 'pg_dump': subprocess.check_output(transport_command(name, 'pg_dump', '--version'), text=True).strip()}
        (root / 'destination-environment.json').write_text(json.dumps(environment, indent=2))
        results = []
        for database in databases:
            db = database['name']
            target = 'recovered_' + hashlib.sha256(db.encode()).hexdigest()[:16]
            command(*transport_command(name, 'createdb', '-U', 'noctis', '-T', 'template0', '--encoding=' + database['encoding'], '--lc-collate=' + database['collate'], '--lc-ctype=' + database['ctype'], target))
            output = root / ('db-' + hashlib.sha256(db.encode()).hexdigest()[:16])
            exported = json.loads((output / 'manifest.json').read_text())
            with (output / 'database.dump').open('rb') as handle:
                command(*transport_command(name, 'pg_restore', '-U', 'noctis', '-d', target, '--exit-on-error', '--single-transaction', '--no-owner', '--no-privileges'), stdin=handle, timeout=900)
            restored = manifest(name, target)
            (output / 'restored-manifest.json').write_text(json.dumps(restored, indent=2))
            compare(exported, restored)
            queries = representative(name, target)
            (output / 'representative-restored.json').write_text(json.dumps(queries, indent=2))
            compare(json.loads((output / 'representative-source.json').read_text()), queries)
            if db == 'noctis':
                # Export runs against the independent AMD64 restore.
                inventory = export_inventory(root, name, target)
                (root / 'inventory-report.json').write_text(json.dumps(inventory, indent=2))
            results.append({'database': db, 'manifest_exact': True, 'tables': len(restored['tables']), 'rows': sum(t['rows'] for t in restored['tables'].values()), 'dump_sha256': hashlib.file_digest((output / 'database.dump').open('rb'), 'sha256').hexdigest()})
        return results
    finally:
        if created:
            command('docker', 'stop', '--time', '30', name, stdout=subprocess.DEVNULL)

def recover_arm(root):
    from kube_guard import Auxiliary
    root = Path(root).resolve()
    assert str(root).startswith('/home/zyrak/.local/share/noctis-rebuild/') and root.stat().st_mode & 0o077 == 0
    output = root / ('arm-logical-' + uuid.uuid4().hex[:10])
    output.mkdir(mode=0o700)
    # Config is private input for inventory reconciliation; session/key never sent.
    shutil.copyfile(root / 'configmaps.json', output / 'configmaps.json')
    auxiliary = Auxiliary(output)
    try:
        pod = auxiliary.gate()
        source, settings = start_arm(auxiliary, pod, root)
        (output / 'effective-settings.json').write_text(json.dumps(settings, indent=2))
        databases = json.loads(sql(source, 'noctis', "SELECT json_agg(row_to_json(d) ORDER BY name) FROM (SELECT datname AS name,pg_encoding_to_char(encoding) AS encoding,datcollate AS collate,datctype AS ctype,datallowconn AS allow_connect FROM pg_database WHERE NOT datistemplate) d"))
        (output / 'databases.json').write_text(json.dumps(databases, indent=2))
        assert all(d['allow_connect'] for d in databases), 'Non-template database cannot be inventoried'
        metadata = {'source': json.loads(sql(source, 'noctis', "SELECT json_build_object('version',version(),'encoding',current_setting('server_encoding'),'collation',datcollate,'ctype',datctype) FROM pg_database WHERE datname=current_database()")), 'pg_dump': subprocess.check_output(transport_command(source, 'pg_dump', '--version'), text=True).strip(), 'image': IMAGE, 'source_architecture': 'arm64', 'destination_architecture': 'amd64'}
        (output / 'environment.json').write_text(json.dumps(metadata, indent=2))
        for database in databases:
            path = output / ('db-' + hashlib.sha256(database['name'].encode()).hexdigest()[:16])
            logical_export(source, database['name'], path)
        results = restore_logical(output, source, databases)
        report = {'state': 'verified', 'databases': results, 'snapshot_shared': True, 'physical_architecture_guard_preserved': True, 'cleanup_verified': True}
    finally:
        auxiliary.cleanup()
    (output / 'recovery-report.json').write_text(json.dumps(report, indent=2))
    print('Verified ARM->logical->AMD64 restore; private evidence: ' + str(output))

def recover(root):
    root = Path(root).resolve()
    assert str(root).startswith("/home/zyrak/.local/share/noctis-rebuild/")
    assert root.stat().st_mode & 0o077 == 0
    for name in ("database", "session"):
        state = json.loads((root / (name + ".verified.json")).read_text())
        assert state["hashes_match"] and state["source_unchanged"]
    origin = json.loads((root / "architecture.json").read_text())
    image_architecture = subprocess.check_output(["docker", "image", "inspect", IMAGE, "--format", "{{.Architecture}}"], text=True).strip()
    verify_architecture(origin["source"], image_architecture)
    source = root / "database" / "pgdata"
    assert (source / "PG_VERSION").read_text().strip() == "16"
    assert not any((source / p).exists() for p in ("standby.signal", "recovery.signal")), "Recovery topology requires explicit review"
    work = root / "work"
    shutil.copytree(source, work)
    # Changes to ownership/PID/config are restricted to this disposable copy.
    (work / "postmaster.pid").unlink(missing_ok=True)
    (work / "recovery-hba.conf").write_text("local all all trust\n")
    (work / "recovery-hba.conf").chmod(0o644)
    (work / "recovery.conf.safe").write_text("data_directory='/data'\nhba_file='/data/recovery-hba.conf'\nident_file='/data/pg_ident.conf'\n")
    (work / "recovery.conf.safe").chmod(0o644)
    command("docker", "run", "--rm", "--network", "none", "--mount", f"type=bind,src={work},dst=/data", "--entrypoint", "chown", IMAGE, "-R", "70:70", "/data", stdout=subprocess.DEVNULL)
    containers = []
    snapshot_process = None
    try:
        name = "noctis-private-recovery-20261018"
        command("docker", "run", "-d", "--name", name, "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,mode=1777", "--user", "70:70", "--mount", f"type=bind,src={work},dst=/data", "--entrypoint", "postgres", IMAGE,
                "-D", "/data", "-c", "config_file=/data/recovery.conf.safe", "-c", "listen_addresses=", "-c", "unix_socket_directories=/tmp", "-c", "archive_mode=off", "-c", "archive_command=", "-c", "restore_command=", "-c", "primary_conninfo=", "-c", "shared_preload_libraries=", "-c", "session_preload_libraries=", "-c", "local_preload_libraries=", "-c", "max_worker_processes=0", "-c", "max_wal_senders=0", "-c", "max_logical_replication_workers=0", "-c", "default_transaction_read_only=on", stdout=subprocess.DEVNULL)
        containers.append(name)
        for attempt in range(60):
            if subprocess.run(["docker", "exec", name, "pg_isready", "-h", "/tmp", "-U", "noctis", "-d", "noctis"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("Recovery PostgreSQL did not become ready; inspect private container logs")
        snapshot_process = subprocess.Popen(["docker", "exec", "-i", "-e", "PGHOST=/tmp", name, "psql", "-XqAt", "-v", "ON_ERROR_STOP=1", "-U", "noctis", "-d", "noctis"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        snapshot_process.stdin.write(b"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT pg_export_snapshot();\n"); snapshot_process.stdin.flush()
        snapshot = snapshot_process.stdout.readline().decode().strip()
        assert snapshot and all(c in '0123456789ABCDEF-' for c in snapshot), "Snapshot export failed"
        with (root / "legacy.dump").open("xb") as output:
            command("docker", "exec", "-e", "PGHOST=/tmp", name, "pg_dump", "-U", "noctis", "-d", "noctis", "--format=custom", "--snapshot=" + snapshot, stdout=output)
        exported = manifest(name, "noctis", snapshot)
        (root / "legacy-manifest.json").write_text(json.dumps(exported, indent=2))
        (root / "roles-acl.json").write_bytes(sql(name, "noctis", "SELECT json_build_object('roles',(SELECT json_agg(row_to_json(r)) FROM (SELECT rolname,rolsuper,rolinherit,rolcreaterole,rolcreatedb,rolcanlogin,rolreplication,rolbypassrls FROM pg_roles) r),'acl',(SELECT json_agg(row_to_json(t)) FROM (SELECT n.nspname,c.relname,c.relacl FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema')) t))", snapshot))
        snapshot_process.stdin.write(b"COMMIT;\n"); snapshot_process.stdin.close()
        assert snapshot_process.wait() == 0
        snapshot_process = None
        restore = "noctis-private-restore-20261018"
        data = root / "restore"
        data.mkdir(mode=0o700)
        command("docker", "run", "-d", "--name", restore, "--network", "none", "--mount", f"type=bind,src={data},dst=/var/lib/postgresql/data", "-e", "POSTGRES_USER=noctis", "-e", "POSTGRES_DB=restore_check", "-e", "POSTGRES_HOST_AUTH_METHOD=trust", IMAGE, "-c", "listen_addresses=", "-c", "unix_socket_directories=/tmp", stdout=subprocess.DEVNULL)
        containers.append(restore)
        for attempt in range(60):
            probe = subprocess.run(["docker", "exec", "-e", "PGHOST=/tmp", restore, "psql", "-XqAt", "-U", "noctis", "-d", "restore_check", "-c", "SELECT 1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if probe.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError("Restore destination did not become ready")
        with (root / "legacy.dump").open("rb") as dump:
            command("docker", "exec", "-i", "-e", "PGHOST=/tmp", restore, "pg_restore", "-U", "noctis", "-d", "restore_check", "--exit-on-error", "--single-transaction", "--no-owner", "--no-privileges", stdin=dump)
        restored = manifest(restore, "restore_check")
        (root / "restored-manifest.json").write_text(json.dumps(restored, indent=2))
        compare(exported, restored)
        inventory = export_inventory(root, restore, "restore_check")
        result = {"state": "verified", "tables": len(exported["tables"]), "rows": sum(t["rows"] for t in exported["tables"].values()), "dump_sha256": hashlib.file_digest((root / "legacy.dump").open("rb"), "sha256").hexdigest(), "image": IMAGE, "network": "none", "snapshot_shared": True, "restore_flags": ["--exit-on-error", "--single-transaction", "--no-owner", "--no-privileges"]}
        (root / "recovery-report.json").write_text(json.dumps(result, indent=2))
        (root / "inventory-report.json").write_text(json.dumps(inventory, indent=2))
        print(json.dumps(result))
    finally:
        if snapshot_process is not None:
            snapshot_process.terminate()
            snapshot_process.wait()
        for container in reversed(containers):
            subprocess.run(["docker", "stop", "--time", "30", container], check=True, stdout=subprocess.DEVNULL)

if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("destination")
    parser.add_argument('--arm-kube', action='store_true')
    arguments = parser.parse_args()
    (recover_arm if arguments.arm_kube else recover)(arguments.destination)
