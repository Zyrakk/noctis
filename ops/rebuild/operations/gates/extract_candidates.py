#!/usr/bin/env python3
"""Private, deterministic archive candidates; no labels/predictions/network services."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from prepare import save

SEED = 'noctis-human-candidates-v1'
COUNT = 400
IMAGE = 'postgres:16-bookworm'


def file_sha256(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def verify_dump(dump):
    if dump.is_symlink() or not dump.is_file() or dump.stat().st_mode & 0o077:
        raise ValueError('Protected regular preserved dump required')
    receipt = json.loads((dump.parent.parent / 'recovery-report.json').read_text())
    digest = file_sha256(dump)
    if not any(row.get('manifest_exact') is True and row.get('dump_sha256') == digest for row in receipt['databases']):
        raise ValueError('Dump hash does not match verified full restore receipt')
    return digest


def sql(container, statement, log):
    return subprocess.check_output(['docker', 'exec', container, 'psql', '-h', '/tmp', '-U', 'noctis', '-d', 'archive', '-At', '-v', 'ON_ERROR_STOP=1', '-c', statement], stderr=log)


def candidate_metadata(row, index):
    return {'id': f'candidate-{index:04d}', 'legacy_record_id': row['id'], 'source': row['source_type'],
            'source_id': row['source_id'], 'language': row['language'] or 'unknown',
            'language_provenance': 'archived detection, provisional; human verification pending',
            'at': row['posted_at'] or row['collected_at'], 'collected_at': row['collected_at'],
            'episode': None, 'episode_provisional': row['source_type'] + ':' + row['source_id'] + ':' + str(row['posted_at'] or row['collected_at'])[:10],
            'partition': None, 'task': None, 'relevant': None, 'adversarial': None,
            'legacy_content_hash': row['content_hash'], 'content_sha256': hashlib.sha256(row['content'].encode()).hexdigest(),
            'label_provenance': 'unlabeled; legacy classifications excluded; human adjudication pending', 'eligible_for_evaluator': False}


def extract(container, output, dump, log):
    counts = json.loads(sql(container, "SELECT json_build_object('total',count(*),'empty',count(*) FILTER(WHERE btrim(content)=''),'over_1MiB',count(*) FILTER(WHERE octet_length(content)>1048576),'eligible',count(*) FILTER(WHERE btrim(content)<>'' AND octet_length(content)<=1048576)) FROM raw_content", log))
    query = """WITH ranked AS (
      SELECT id,source_type,source_id,content,content_hash,language,collected_at,posted_at,
       row_number() OVER(PARTITION BY source_type,coalesce(nullif(language,''),'unknown')
                         ORDER BY md5(id::text || 'noctis-human-candidates-v1'),id) AS n
      FROM raw_content WHERE btrim(content)<>'' AND octet_length(content)<=1048576)
      SELECT row_to_json(t) FROM (SELECT id,source_type,source_id,content,content_hash,language,collected_at,posted_at
      FROM ranked ORDER BY n,md5(source_type || coalesce(language,'') || 'noctis-human-candidates-v1'),id LIMIT 400) t"""
    # Raw bytes never leave private files except local parsing in this process.
    raw = sql(container, query, log)
    rows = [json.loads(line) for line in raw.splitlines()]
    if len(rows) != COUNT:
        raise ValueError('Archive cannot supply expected candidate count')
    candidates = [candidate_metadata(row, i) for i, row in enumerate(rows, 1)]
    save(output, 'candidate-inputs.private.json', {'inputs': {c['id']: {'content': r['content']} for c, r in zip(candidates, rows)}})
    save(output, 'candidate-dataset.UNLABELED.json', {'metadata': {'version': 'archive-candidates-v1', 'synthetic': False,
        'input_fixture': 'candidate-inputs.private.json', 'label_provenance': 'UNLABELED, excluded from evaluator until independent human adjudication',
        'quality_measured': False, 'promotion_authorized': False}, 'examples': candidates})
    for name, fields in [('reviewer-a.csv', ['candidate_id','language','episode','partition','task','relevant','claims','evidence_spans','abstention','reason']),
                         ('reviewer-b.csv', ['candidate_id','language','episode','partition','task','relevant','claims','evidence_spans','abstention','reason']),
                         ('adjudication.csv', ['candidate_id','disagreement','decision','evidence_spans','adjudicator','decided_at']),
                         ('utility-review.csv', ['candidate_id','task_id','success_criterion','blind_arm','order','time_seconds','attention_seconds','omissions','false_alarms','verified_outcome','reviewer'])]:
        with (output / name).open('x', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=fields); writer.writeheader()
            for c in candidates:
                writer.writerow({'candidate_id': c['id']})
    receipt = {'schema': 'noctis-candidate-selection-v1', 'count': len(rows), 'seed': SEED,
        'selection': 'round-robin by archived source_type/language, then deterministic MD5 UUID ordering; no legacy labels used',
        'count_reason': '400 bounds two independent human reviews within requested 300-500; no claim of representativeness',
        'eligibility': 'nonempty trimmed content, at most 1MiB UTF8 per record', 'counts': counts,
        'dump': str(dump), 'dump_sha256': file_sha256(dump),
        'selection_sha256': hashlib.sha256(json.dumps([c['legacy_record_id'] for c in candidates]).encode()).hexdigest(),
        'episode_partition_human_review': 'pending; provisional source/day groups must be merged for cross-source copies and episodes',
        'g6': 'pending human adjudication and real predictions', 'g7': 'pending controlled utility review',
        'quality_measured': False, 'model_content_access': False, 'external_transmission': False}
    save(output, 'candidate-selection-receipt.json', receipt)
    return receipt


def main(dump, output):
    os.umask(0o077)
    if output.exists() or output.resolve().is_relative_to(Path(__file__).resolve().parents[4]) or output.parent.stat().st_mode & 0o077:
        raise ValueError('Verified logical dump and new private output required')
    verify_dump(dump)
    output.mkdir(mode=0o700)
    # Never pull implicitly: only an image already available locally is accepted.
    subprocess.run(['docker', 'image', 'inspect', IMAGE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    name = 'noctis-gates-' + uuid.uuid4().hex[:12]
    with (output / 'restore.log').open('xb') as log:
        try:
            subprocess.run(['docker','run','--pull=never','-d','--name',name,'--network','none','--memory','768m','--cpus','1',
                '-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_USER=noctis','-e','POSTGRES_DB=archive',IMAGE,
                '-c','listen_addresses=','-c','unix_socket_directories=/tmp,/var/run/postgresql'], stdout=log, stderr=log, check=True)
            for _ in range(120):
                if subprocess.run(['docker','exec',name,'psql','-h','/tmp','-U','noctis','-d','archive','-Atc','SELECT 1'],stdout=log,stderr=log).returncode == 0:
                    # Entry point can restart once after initialization; wait and recheck.
                    time.sleep(3)
                    if subprocess.run(['docker','exec',name,'psql','-h','/tmp','-U','noctis','-d','archive','-Atc','SELECT 1'],stdout=log,stderr=log).returncode == 0:
                        break
                time.sleep(.5)
            else:
                raise RuntimeError('Own isolated PostgreSQL did not become ready')
            with dump.open('rb') as source:
                subprocess.run(['docker','exec','-i',name,'pg_restore','-h','/tmp','-U','noctis','-d','archive','--no-owner','--no-privileges','--single-transaction','--exit-on-error'], stdin=source,stdout=log,stderr=log,check=True)
            extract(name, output, dump, log)
        finally:
            # Exact unique owned resource only; no shared/P0 container references.
            subprocess.run(['docker','rm','-f','-v',name],stdout=log,stderr=log,check=True)
    save(output, 'cleanup-receipt.json', {'own_container_and_volume_removed': True, 'originals_modified': False, 'network': 'none'})


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dump', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    main(args.dump, args.output)
