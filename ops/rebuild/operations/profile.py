#!/usr/bin/env python3
"""Measure an existing canonical synthetic-runner fixture, without a new pipeline."""
import argparse
import json
import os
from pathlib import Path
import statistics
import time
from backup import Transport, sql

def profile(container, identity, receipt_file, time_file, output):
    receipt = json.loads(Path(receipt_file).read_text())
    if receipt.get('result') != 'pass' or not receipt.get('processes_stopped_on_exit') or not receipt['database'].startswith('noctis_v2_e2e_'):
        raise ValueError('Successful canonical synthetic runner fixture required')
    source = Transport(container, 'postgres', identity)
    database = receipt['database']
    metrics = json.loads(sql(source, database, """SELECT json_build_object(
      'database_bytes',pg_database_size(current_database()),
      'observations',(SELECT count(*) FROM noctis_v2.observations),
      'payload_bytes',(SELECT coalesce(sum(octet_length(payload)),0) FROM noctis_v2.content_blobs),
      'cases',(SELECT count(*) FROM noctis_v2.intelligence_cases),
      'checkpoints',(SELECT count(*) FROM noctis_v2.checkpoints),
      'jobs_by_state',(SELECT json_object_agg(state,n) FROM (SELECT state,count(*) n FROM noctis_v2.jobs GROUP BY state) j),
      'ai_jobs_by_state',(SELECT json_object_agg(state,n) FROM (SELECT state,count(*) n FROM noctis_v2.ai_jobs GROUP BY state) a),
      'ai_attempts_by_state',(SELECT json_object_agg(state,n) FROM (SELECT state,count(*) n FROM noctis_v2.ai_attempts GROUP BY state) a),
      'ai_exposure_units',(SELECT coalesce(sum(exposure_units),0) FROM noctis_v2.ai_attempts),
      'oldest_pending_ai_job_age_seconds',(SELECT extract(epoch FROM clock_timestamp()-min(created_at)) FROM noctis_v2.ai_jobs WHERE state IN ('queued','retry_wait','budget_blocked','dependency_blocked')),
      'outbox_by_state',(SELECT json_object_agg(state,n) FROM (SELECT state,count(*) n FROM noctis_v2.outbox GROUP BY state) o))"""))
    # Server execution time excludes Docker/psql launch overhead. Sample all
    # current case revisions, same fixture used for the private product journey.
    samples = []
    for _ in range(20):
        plan = json.loads(sql(source, database, 'EXPLAIN (ANALYZE,FORMAT JSON) SELECT c.id,c.title,r.body FROM noctis_v2.intelligence_cases c JOIN noctis_v2.case_revisions r ON r.case_id=c.id AND r.revision=c.revision ORDER BY c.updated_at DESC LIMIT 50'))
        samples.append(plan[0]['Execution Time'])
    samples.sort()
    metrics.update({'case_query_server_ms': {'samples': len(samples), 'median': statistics.median(samples), 'p95': samples[18], 'max': max(samples)},
                    'runner_time_v': Path(time_file).read_text(),
                    'runner': 'canonical ops/rebuild/e2e ' + ' '.join('--' + mode for mode in ['browser', 'product', 'ai'] if receipt.get(mode)) + ' --keep (compiled binary, PG16, HTTPS)',
                    'oldest_mechanical_job_age': 'unknown: schema004 jobs has no created_at; no fabricated age',
                    'source_container_memory_limit_bytes': source.info['HostConfig']['Memory'],
                    'source_container_nano_cpus': source.info['HostConfig']['NanoCpus'],
                    'memory_scope': 'time-v peak RSS is aggregate launcher/Go/browser measurement, not isolated runtime RSS',
                    'limits': 'tiny synthetic fixture, no sustained arrivals, paid inference, Telegram or production I/O; no production sizing or RPO proof',
                    'failure_domain': 'backup/archive/key/source share this local host; encrypted key stored in a separate private directory; no offsite transfer'})
    Path(output).write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for argument in ['container', 'identity', 'receipt-file', 'time-file', 'output']:
        parser.add_argument('--' + argument, required=True)
    profile(**{k: v for k, v in vars(parser.parse_args()).items()})
