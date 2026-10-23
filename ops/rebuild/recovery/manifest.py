#!/usr/bin/env python3
"""Logical manifest, streaming deterministic row serializations from one snapshot."""
import hashlib
import json
import subprocess
import threading

SETTINGS = "SET timezone='UTC'; SET datestyle='ISO, YMD'; SET intervalstyle='postgres'; SET extra_float_digits=3; SET bytea_output='hex'; SET client_encoding='UTF8'; SET default_transaction_read_only=on; "

class KubeTransport:
    def __init__(self, pod):
        self.pod = pod

    def command(self, *args):
        return ['kubectl', 'exec', '-i', '-n', 'noctis', self.pod, '--', 'env', 'PGHOST=/tmp', *args]

def command(container, *args):
    if hasattr(container, 'command'):
        return container.command(*args)
    return ['docker', 'exec', '-i', '-e', 'PGHOST=/tmp', container, *args]

def stream(container, args, output, statement=None, timeout=900):
    process = subprocess.Popen(command(container, *args), stdin=subprocess.PIPE if statement else subprocess.DEVNULL, stdout=subprocess.PIPE)
    expired = threading.Event()
    def stop():
        expired.set()
        process.kill()
    timer = threading.Timer(timeout, stop)
    timer.start()
    try:
        if statement:
            process.stdin.write(statement.encode()); process.stdin.close()
        for block in iter(lambda: process.stdout.read(1024 * 1024), b''):
            output(block)
        code = process.wait()
        if expired.is_set():
            raise TimeoutError('Logical export exceeded deadline')
        if code:
            raise subprocess.CalledProcessError(code, process.args)
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill(); process.wait()
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()

if not __debug__:
    raise RuntimeError("Safety checks require Python without optimization")

def sql(container, database, statement, snapshot=None):
    statement = SETTINGS + statement
    if snapshot:
        statement = "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET TRANSACTION SNAPSHOT '" + snapshot.replace("'", "''") + "'; " + statement + "; COMMIT;"
    return subprocess.check_output(command(container, 'psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-U', 'noctis', '-d', database), input=statement.encode(), timeout=900)

def identifier(value):
    return '"' + value.replace('"', '""') + '"'

def representative(container, database, snapshot=None):
    tables = json.loads(sql(container, database, "SELECT coalesce(json_agg(row_to_json(t) ORDER BY schemaname,tablename),'[]') FROM pg_tables t WHERE schemaname NOT IN ('pg_catalog','information_schema')", snapshot))
    result = {'tables': {}}
    for table in tables:
        name = table['tablename']
        if name not in ('sources', 'raw_content', 'findings', 'ioc_sightings', 'source_triage_log', 'discovered_blacklist') and 'migration' not in name:
            continue
        qualified = identifier(table['schemaname']) + '.' + identifier(name)
        sample = sql(container, database, 'SELECT row_to_json(t)::text FROM ' + qualified + ' t ORDER BY row_to_json(t)::text COLLATE "C" LIMIT 20', snapshot)
        result['tables'][table['schemaname'] + '.' + name] = {'count': int(sql(container, database, 'SELECT count(*) FROM ' + qualified, snapshot)), 'sample_sha256': hashlib.sha256(sample).hexdigest()}
    relations = sql(container, database, "SELECT coalesce(json_agg(row_to_json(r) ORDER BY schema,relation,name),'[]') FROM (SELECT n.nspname AS schema,t.relname AS relation,c.conname AS name,c.contype AS type,pg_get_constraintdef(c.oid) AS definition,c.convalidated AS validated FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema')) r", snapshot)
    result['relations'] = {'sha256': hashlib.sha256(relations).hexdigest(), 'count': len(json.loads(relations))}
    return result

def manifest(container, database, snapshot=None):
    def query(statement):
        return sql(container, database, statement, snapshot).decode().strip()
    result = {"encoding": query("SHOW server_encoding"), "extensions": query("SELECT coalesce(json_agg(row_to_json(x) ORDER BY extname),'[]') FROM (SELECT extname,extversion FROM pg_extension) x")}
    result['serialization_settings'] = SETTINGS
    result['database_environment'] = json.loads(query("SELECT row_to_json(d) FROM (SELECT pg_encoding_to_char(encoding) AS encoding,datcollate,datctype,datlocprovider,daticulocale,datcollversion FROM pg_database WHERE datname=current_database()) d"))
    args = command(container, 'pg_dump', '-U', 'noctis', '-d', database, '--schema-only', '--no-owner', '--no-privileges')
    if snapshot:
        args.append("--snapshot=" + snapshot)
    schema = subprocess.check_output(args).decode()
    schema = "\n".join(line for line in schema.splitlines() if not line.startswith(("\\restrict ", "\\unrestrict ")))
    result["schema_sha256"] = hashlib.sha256(schema.encode()).hexdigest()
    tables = json.loads(query("SELECT coalesce(json_agg(row_to_json(t) ORDER BY schemaname,tablename),'[]') FROM pg_tables t WHERE schemaname NOT IN ('pg_catalog','information_schema')"))
    result["tables"] = {}
    for table in tables:
        schema, name = table["schemaname"], table["tablename"]
        qualified = identifier(schema) + "." + identifier(name)
        count = int(query("SELECT count(*) FROM " + qualified))
        digest = hashlib.sha256()
        statement = "COPY (SELECT row_to_json(t)::text FROM " + qualified + " t ORDER BY row_to_json(t)::text COLLATE \"C\") TO STDOUT"
        statement = SETTINGS + statement
        if snapshot:
            statement = "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET TRANSACTION SNAPSHOT '" + snapshot + "'; " + statement + "; COMMIT;"
        stream(container, ['psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-U', 'noctis', '-d', database], digest.update, statement)
        result["tables"][schema + "." + name] = {"rows": count, "sha256": digest.hexdigest()}
    result['sequences'] = []
    sequences = json.loads(query("SELECT coalesce(json_agg(row_to_json(s) ORDER BY schemaname,sequencename),'[]') FROM (SELECT schemaname,sequencename,data_type,start_value,min_value,max_value,increment_by,cycle,cache_size FROM pg_sequences WHERE schemaname NOT IN ('pg_catalog','information_schema')) s"))
    for sequence in sequences:
        qualified = identifier(sequence['schemaname']) + '.' + identifier(sequence['sequencename'])
        sequence['state'] = json.loads(query('SELECT row_to_json(s) FROM (SELECT last_value::text,is_called FROM ' + qualified + ') s'))
        result['sequences'].append(sequence)
    result["large_objects"] = query("SELECT count(*)::text || ':' || md5(coalesce(string_agg(oid::text,',' ORDER BY oid),'')) FROM pg_largeobject_metadata")
    pages = hashlib.sha256()
    statement = SETTINGS + "COPY (SELECT loid::text,pageno,encode(data,'hex') FROM pg_largeobject ORDER BY loid,pageno) TO STDOUT"
    if snapshot:
        statement = "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET TRANSACTION SNAPSHOT '" + snapshot + "'; " + statement + "; COMMIT;"
    stream(container, ['psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-U', 'noctis', '-d', database], pages.update, statement)
    result['large_object_pages'] = {'rows': int(query('SELECT count(*) FROM pg_largeobject')), 'sha256': pages.hexdigest()}
    result["migrations"] = [k for k in result["tables"] if "migration" in k]
    return result

def compare(left, right):
    if left != right:
        raise ValueError("Restored manifest does not match the exported snapshot")
