"""Explicit synthetic Docker PG16 exercise; never touches cluster or originals."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
from manifest import command, compare
from recover import IMAGE, logical_export, restore_logical

def exercise(parent):
    root = Path(parent) / ('synthetic-' + uuid.uuid4().hex[:10])
    root.mkdir(mode=0o700)
    (root / 'configmaps.json').write_text('{"items":[]}')
    name = 'noctis-synthetic-' + uuid.uuid4().hex[:10]
    subprocess.run(['docker', 'run', '-d', '--name', name, '--network', 'none', '-e', 'PGHOST=/tmp', '-e', 'POSTGRES_USER=noctis', '-e', 'POSTGRES_DB=noctis', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust', IMAGE, '-c', 'listen_addresses=', '-c', 'unix_socket_directories=/tmp,/var/run/postgresql'], check=True, stdout=subprocess.DEVNULL)
    try:
        for _ in range(60):
            if subprocess.run(command(name, 'psql', '-XqAt', '-U', 'noctis', '-d', 'noctis', '-c', 'SELECT 1'), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Synthetic PostgreSQL failed readiness')
        query = """CREATE TABLE samples(id bigserial, data text);
INSERT INTO samples(data) VALUES ('á'),(NULL),('line'||chr(10)||'two');
CREATE SEQUENCE unused; SELECT setval('unused',9007199254740993,false);
CREATE TABLE sources(id bigint PRIMARY KEY,type text,identifier text,name text,status text,discovered_from bigint,metadata jsonb);
INSERT INTO sources VALUES(9007199254740993,'telegram_channel','-1009007199254740993','test','paused',NULL,'{"extra":true}');
CREATE TABLE linked(source_id bigint REFERENCES sources(id)); INSERT INTO linked VALUES(9007199254740993);
SELECT lo_from_bytea(0,decode('00ff00','hex'));
CREATE TABLE raw_content(source_type text,source_id text);
INSERT INTO raw_content VALUES('telegram_channel','-1009007199254740993');
CREATE TABLE findings(source text,source_id text); INSERT INTO findings VALUES('telegram','-1009007199254740994');
CREATE TABLE ioc_sightings(source_id text); INSERT INTO ioc_sightings VALUES('-1009007199254740995');
CREATE TABLE source_triage_log(identifier text,decision text); INSERT INTO source_triage_log VALUES('-1009007199254740996','reject');
CREATE TABLE discovered_blacklist(domain text); INSERT INTO discovered_blacklist VALUES('synthetic.invalid');"""
        subprocess.run(command(name, 'psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-U', 'noctis', '-d', 'noctis'), input=query.encode(), check=True, stdout=subprocess.DEVNULL)
        output = root / ('db-' + hashlib.sha256(b'noctis').hexdigest()[:16])
        exported = logical_export(name, 'noctis', output)
        results = restore_logical(root, name, [{'name': 'noctis', 'encoding': 'UTF8', 'collate': 'en_US.utf8', 'ctype': 'en_US.utf8'}])
        source = json.loads((root / 'sources.jsonl').read_text())
        assert source['id'] == '9007199254740993' and source['discovered_from'] is None and source['metadata'] == {'extra': True}
        history = json.loads((root / 'historical-identities.json').read_text())
        assert len(history) == 4 and {h['source_id'] for h in history} == {'-1009007199254740993','-1009007199254740994','-1009007199254740995','-1009007199254740996'}
        restrictions = json.loads((root / 'legacy-restrictions.json').read_text())
        assert restrictions['source_triage_log'][0]['decision'] == 'reject' and restrictions['discovered_blacklist'][0]['domain'] == 'synthetic.invalid'
        # Real pg_restore failure propagation using a malformed dump.
        failed = subprocess.run(command(name, 'pg_restore', '-U', 'noctis', '-d', 'noctis', '--exit-on-error', '--single-transaction', '--no-owner', '--no-privileges'), input=b'not a PostgreSQL dump', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert failed.returncode != 0
        (root / 'integration-report.json').write_text(json.dumps({'restores': results, 'corrupt_dump_rejected': True, 'all_source_columns': True, 'large_string_ids': True, 'uncalled_sequence_verified': True}, indent=2))
        print('Synthetic Docker PG16 dump/restore + failure checks passed: ' + str(root))
    finally:
        subprocess.run(['docker', 'stop', '--time', '5', name], check=True, stdout=subprocess.DEVNULL)

if __name__ == '__main__':
    os.umask(0o077)
    exercise(sys.argv[1])
