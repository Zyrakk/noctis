#!/usr/bin/env python3
"""Offline production release renderer. Never runs kubectl or prints private data."""
import argparse
import base64
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

NS = 'noctis-v2'
DB = 'noctis_v2_production'
HOST = 'noctis-v2-postgres.noctis-v2.svc.cluster.local'
ROOT = Path(__file__).resolve().parents[3]
MODES = ('api', 'worker', 'collector', 'telegram')
SECURITY = {'readOnlyRootFilesystem': True, 'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}
POD_SECURITY = {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532, 'fsGroup': 65532, 'seccompProfile': {'type': 'RuntimeDefault'}}
SQL_READY_COMMAND = ['/usr/bin/timeout', '--signal=TERM', '--kill-after=2s', '120s', '/bin/sh', '-ec', 'until psql -Xqw -v ON_ERROR_STOP=1 -c "SELECT 1" >/dev/null 2>&1; do sleep 2; done']


def private_directory(path, create=False):
    path = Path(path).absolute()
    if path.is_symlink():
        raise ValueError('Private directory cannot be a symlink')
    if path.resolve() != path:
        raise ValueError('Private directory ancestors cannot be symlinks')
    if create:
        path.mkdir(mode=0o700, parents=False, exist_ok=False)
    if not path.is_dir() or path.stat().st_uid != os.getuid() or stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise ValueError('Private directory must be owned by caller with mode 0700')
    return path


def write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(data if isinstance(data, str) else json.dumps(data, indent=2) + '\n')


def obj(kind, name, spec=None, **extra):
    api = {'Deployment': 'apps/v1', 'StatefulSet': 'apps/v1', 'Job': 'batch/v1', 'NetworkPolicy': 'networking.k8s.io/v1', 'Ingress': 'networking.k8s.io/v1', 'ServersTransport': 'traefik.io/v1alpha1'}.get(kind, 'v1')
    result = {'apiVersion': api, 'kind': kind, 'metadata': {'name': name, 'namespace': NS}, **extra}
    if spec is not None:
        result['spec'] = spec
    return result


def secret(name, data):
    return obj('Secret', name, type='Opaque', data={k: base64.b64encode(v.encode()).decode() for k, v in data.items()})


def provision(directory):
    root = private_directory(directory, create=True)
    passwords = {mode: secrets.token_hex(32) for mode in ('owner', *MODES)}
    items = []
    for mode, password in passwords.items():
        role = 'noctis' if mode == 'owner' else 'noctis_v2_' + mode
        dsn = f'postgres://{role}:{password}@{HOST}:5432/{DB}?sslmode=disable'
        write(root / ('database-' + mode + '.secret'), dsn + '\n')
        items.append(secret('noctis-v2-' + ('migration' if mode == 'owner' else mode) + '-database', {'database': dsn}))
    init = '\\set ON_ERROR_STOP on\n'
    init += f'REVOKE ALL ON DATABASE {DB} FROM PUBLIC;\nREVOKE CREATE ON SCHEMA public FROM PUBLIC;\n'
    init += 'CREATE ROLE noctis_v2_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;\n'
    for mode in MODES:
        init += f"CREATE ROLE noctis_v2_{mode} LOGIN PASSWORD '{passwords[mode]}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;\n"
        init += f'GRANT noctis_v2_runtime TO noctis_v2_{mode};\n'
    init += f'GRANT CONNECT ON DATABASE {DB} TO noctis_v2_runtime;\n'
    write(root / 'init.sql', init)
    items.append(secret('noctis-v2-postgres-bootstrap', {'password': passwords['owner'], 'init.sql': init}))
    admin = json.dumps({'username': 'admin', 'password': secrets.token_urlsafe(36)})
    master = json.dumps({'key_id': 'production-' + secrets.token_hex(8), 'key': secrets.token_hex(32)})
    write(root / 'admin.secret', admin)
    write(root / 'ai-master.json', master)
    items.extend([secret('noctis-v2-admin', {'admin': admin}), secret('noctis-v2-ai-master', {'master.json': master})])
    write(root / 'secrets.json', {'apiVersion': 'v1', 'kind': 'List', 'items': items})
    write(root / 'private-receipt.json', {'format': 'noctis-production-private-v1', 'database': DB, 'roles': list(MODES), 'fresh_master_key': True, 'telegram_session_copied': False})
    return {'result': 'prepared', 'secrets_printed': False, 'session_copied': False}


def hostnetwork_sources(config):
    sources = config.get('traefik_hostnetwork_sources', [])
    if not isinstance(sources, list):
        raise ValueError('Traefik hostNetwork sources must be a list of explicit host CIDRs')
    normalized = []
    for source in sources:
        if not isinstance(source, str) or '/' not in source or '%' in source:
            raise ValueError('Traefik hostNetwork source requires an IPv4 /32 or IPv6 /128')
        network = ipaddress.ip_network(source, strict=True)
        if network.prefixlen != network.max_prefixlen:
            raise ValueError('Traefik hostNetwork sources cannot authorize a subnet')
        normalized.append(str(network))
    if len(set(normalized)) != len(normalized):
        raise ValueError('Duplicate Traefik hostNetwork source')
    return normalized


def validate(config, infrastructure_only=False):
    required = {'image', 'busybox_image', 'postgres_image', 'tls_secret', 'storage_class', 'postgres_size', 'session_size', 'traefik_namespace', 'traefik_labels'}
    if infrastructure_only:
        required.remove('image')
    if set(config) - {'traefik_hostnetwork_sources'} != required:
        raise ValueError('Release input requires: ' + ', '.join(sorted(required)) + '; optional: traefik_hostnetwork_sources')
    hostnetwork_sources(config)
    for key in (('busybox_image', 'postgres_image') if infrastructure_only else ('image', 'busybox_image', 'postgres_image')):
        value = config[key]
        if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}', value) or len(set(value.rsplit(':', 1)[-1])) < 4:
            raise ValueError('Real immutable image digest required: ' + key)
    if not re.fullmatch(r'(?:docker.io/library/)?postgres:16(?:\.[0-9]+)?-bookworm@sha256:[a-f0-9]{64}', config['postgres_image']):
        raise ValueError('PostgreSQL 16 bookworm digest required')
    for key in ('tls_secret', 'storage_class', 'traefik_namespace'):
        if not isinstance(config[key], str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,62}', config[key]) or any(x in config[key] for x in ('placeholder', 'replace', 'example', 'changeme')):
            raise ValueError('Explicit Kubernetes resource name required: ' + key)
    for key in ('postgres_size', 'session_size'):
        if not re.fullmatch(r'[1-9][0-9]*(?:Gi|Mi)', config[key]):
            raise ValueError('Explicit positive PVC size required: ' + key)
    labels = config['traefik_labels']
    if not isinstance(labels, dict) or not labels or any(not isinstance(k, str) or not isinstance(v, str) or not k or not v for k, v in labels.items()):
        raise ValueError('Exact observed Traefik pod labels required')


def volume(name, secret_name):
    return {'name': name, 'secret': {'secretName': secret_name, 'defaultMode': 0o440}}


def mount(name, path, readonly=True):
    return {'name': name, 'mountPath': path, 'readOnly': readonly}


def pod(containers, volumes, init=None):
    result = {'automountServiceAccountToken': False, 'enableServiceLinks': False, 'nodeSelector': {'kubernetes.io/hostname': 'oracle1', 'kubernetes.io/arch': 'arm64'}, 'securityContext': copy.deepcopy(POD_SECURITY), 'terminationGracePeriodSeconds': 60, 'containers': containers, 'volumes': volumes}
    if init:
        result['initContainers'] = init
    return result


def container(name, image, args=None):
    result = {'name': name, 'image': image, 'securityContext': copy.deepcopy(SECURITY), 'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}, 'limits': {'cpu': '1', 'memory': '512Mi'}}}
    if args is not None:
        result['args'] = args
    return result


def template(name, spec):
    return {'metadata': {'labels': {'app': name, 'noctis-release': 'production'}}, 'spec': spec}


def job(name, spec):
    spec['restartPolicy'] = 'Never'
    return obj('Job', name, {'suspend': True, 'backoffLimit': 0, 'activeDeadlineSeconds': 600, 'template': template(name, spec)})


def owner_environment():
    return [{'name': 'PGHOST', 'value': HOST}, {'name': 'PGUSER', 'value': 'noctis'}, {'name': 'PGDATABASE', 'value': DB}, {'name': 'PGSSLMODE', 'value': 'disable'}, {'name': 'PGCONNECT_TIMEOUT', 'value': '2'}, {'name': 'PGPASSWORD', 'valueFrom': {'secretKeyRef': {'name': 'noctis-v2-postgres-bootstrap', 'key': 'password'}}}]


def sql_ready(config):
    ready = container('database-sql-ready', config['postgres_image'])
    ready['command'] = list(SQL_READY_COMMAND)
    ready['env'] = owner_environment()
    return ready


def render(config, infrastructure_only=False):
    validate(config, infrastructure_only)
    image = config.get('image')
    infra = [{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NS, 'labels': {'noctis-release': 'production'}}}]
    for name, size in (('noctis-v2-postgres-data', 'postgres_size'), ('noctis-v2-telegram-private-session', 'session_size')):
        infra.append(obj('PersistentVolumeClaim', name, {'accessModes': ['ReadWriteOnce'], 'storageClassName': config['storage_class'], 'resources': {'requests': {'storage': config[size]}}}))
    pg = container('postgres', config['postgres_image'])
    pg.update({'env': [{'name': 'POSTGRES_USER', 'value': 'noctis'}, {'name': 'POSTGRES_DB', 'value': DB}, {'name': 'PGDATA', 'value': '/var/lib/postgresql/data/pgdata'}, {'name': 'POSTGRES_INITDB_ARGS', 'value': '--auth-host=scram-sha-256 --auth-local=scram-sha-256'}, {'name': 'POSTGRES_PASSWORD', 'valueFrom': {'secretKeyRef': {'name': 'noctis-v2-postgres-bootstrap', 'key': 'password'}}}], 'ports': [{'name': 'postgres', 'containerPort': 5432}], 'volumeMounts': [mount('data', '/var/lib/postgresql/data', False), mount('bootstrap', '/docker-entrypoint-initdb.d'), mount('socket', '/var/run/postgresql', False), mount('tmp', '/tmp', False)], 'readinessProbe': {'exec': {'command': ['pg_isready', '-U', 'noctis', '-d', DB]}, 'periodSeconds': 5}, 'startupProbe': {'exec': {'command': ['pg_isready', '-U', 'noctis', '-d', DB]}, 'failureThreshold': 60, 'periodSeconds': 5}})
    pg['resources'] = {'requests': {'cpu': '250m', 'memory': '512Mi'}, 'limits': {'cpu': '2', 'memory': '2Gi'}}
    pg['env'].append({'name': 'POD_IP', 'valueFrom': {'fieldRef': {'fieldPath': 'status.podIP'}}})
    pod_ip_probe = {'exec': {'command': ['/bin/sh', '-ec', f'test -n "$POD_IP"; exec pg_isready -h "$POD_IP" -U noctis -d {DB}']}, 'periodSeconds': 5}
    pg['readinessProbe'] = copy.deepcopy(pod_ip_probe)
    pg['startupProbe'] = {**copy.deepcopy(pod_ip_probe), 'failureThreshold': 60}
    pgpod = pod([pg], [{'name': 'data', 'persistentVolumeClaim': {'claimName': 'noctis-v2-postgres-data'}}, {'name': 'bootstrap', 'secret': {'secretName': 'noctis-v2-postgres-bootstrap', 'defaultMode': 0o440, 'items': [{'key': 'init.sql', 'path': '00-runtime.sql'}]}}, {'name': 'socket', 'emptyDir': {}}, {'name': 'tmp', 'emptyDir': {}}])
    infra += [obj('Service', 'noctis-v2-postgres', {'clusterIP': 'None', 'selector': {'app': 'noctis-v2-postgres'}, 'ports': [{'name': 'postgres', 'port': 5432, 'targetPort': 5432}]}), obj('StatefulSet', 'noctis-v2-postgres', {'replicas': 1, 'serviceName': 'noctis-v2-postgres', 'selector': {'matchLabels': {'app': 'noctis-v2-postgres'}}, 'template': template('noctis-v2-postgres', pgpod)})]
    clients = ['noctis-v2-' + m for m in MODES] + ['noctis-v2-migrate', 'noctis-v2-grants']
    infra.append(obj('NetworkPolicy', 'noctis-v2-postgres-only', {'podSelector': {'matchLabels': {'app': 'noctis-v2-postgres'}}, 'policyTypes': ['Ingress', 'Egress'], 'ingress': [{'from': [{'podSelector': {'matchExpressions': [{'key': 'app', 'operator': 'In', 'values': clients}]}}], 'ports': [{'protocol': 'TCP', 'port': 5432}]}], 'egress': []}))
    if infrastructure_only:
        return {'01-infrastructure.json': infra}
    migrate = container('migrate', image, ['v2', '--database-secret-file', '/run/db/database', 'migrate'])
    migrate['volumeMounts'] = [mount('db', '/run/db')]
    migrations = [job('noctis-v2-migrate', pod([migrate], [volume('db', 'noctis-v2-migration-database')], [sql_ready(config)]))]
    grants_sql = f"""\\set ON_ERROR_STOP on
DO $$ BEGIN
 IF current_database() <> '{DB}' THEN RAISE EXCEPTION 'wrong database'; END IF;
 IF to_regclass('public.noctis_v2_migrations') IS NULL THEN RAISE EXCEPTION 'migrate first'; END IF;
END $$;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA noctis_v2 TO noctis_v2_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA noctis_v2 TO noctis_v2_runtime;
GRANT SELECT ON public.noctis_v2_migrations TO noctis_v2_runtime;
"""
    grant = container('grants', config['postgres_image'], ['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-f', '/grants/grants.sql'])
    grant['env'] = owner_environment()
    grant['volumeMounts'] = [mount('grants', '/grants')]
    grants = [obj('ConfigMap', 'noctis-v2-runtime-grants', data={'grants.sql': grants_sql}), job('noctis-v2-grants', pod([grant], [{'name': 'grants', 'configMap': {'name': 'noctis-v2-runtime-grants'}}], [sql_ready(config)]))]
    apps = []
    for mode in MODES:
        name = 'noctis-v2-' + mode
        args = ['v2', '--database-secret-file', '/run/db/database', 'serve', '--mode', mode]
        c = container(mode, image, args)
        c['volumeMounts'] = [mount('db', '/run/db')]
        volumes = [volume('db', name + '-database')]
        init = []
        if mode in ('api', 'worker'):
            args += ['--ai-master-key-file', '/run/ai/owned/master.json']
            volumes += [volume('master-source', 'noctis-v2-ai-master'), {'name': 'ai', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '1Mi'}}]
            key = container('private-master-key', config['busybox_image'])
            key['command'] = ['/bin/sh', '-ec', 'umask 077; mkdir -p /private/owned; chmod 700 /private/owned; cp /source/master.json /private/owned/master.json; chmod 600 /private/owned/master.json; test "$(stat -c %u /private/owned/master.json)" = 65532']
            key['volumeMounts'] = [mount('master-source', '/source'), mount('ai', '/private', False)]
            init.append(key)
            c['volumeMounts'].append(mount('ai', '/run/ai'))
        if mode == 'worker':
            args += ['--automatic-inference=false']
        if mode == 'api':
            args += ['--listen', '0.0.0.0:8081', '--origin', 'https://noctis.zyrak.cloud', '--admin-secret-file', '/run/auth/admin', '--tls-cert-file', '/run/tls/tls.crt', '--tls-key-file', '/run/tls/tls.key']
            volumes += [volume('auth', 'noctis-v2-admin'), volume('tls', config['tls_secret'])]
            c['volumeMounts'] += [mount('auth', '/run/auth'), mount('tls', '/run/tls')]
            c['ports'] = [{'name': 'https', 'containerPort': 8081}]
            c['livenessProbe'] = {'httpGet': {'path': '/livez', 'port': 'https', 'scheme': 'HTTPS'}, 'initialDelaySeconds': 10}
            c['readinessProbe'] = {'httpGet': {'path': '/readyz', 'port': 'https', 'scheme': 'HTTPS'}, 'periodSeconds': 5}
        if mode == 'telegram':
            # Reuse the reviewed fail-closed permission checks and command contract.
            import yaml
            existing = yaml.safe_load((ROOT / 'deploy/v2/telegram.yaml').read_text())
            original = existing['spec']['template']['spec']
            tg_init = copy.deepcopy(original['initContainers'][0])
            tg_init['image'] = config['busybox_image']
            tg_init['command'][-1] = tg_init['command'][-1].replace('chmod 700 /private;', 'mkdir -p /private/owned; chmod 700 /private/owned;').replace('/private/credentials.json', '/private/owned/credentials.json').replace('/private/capture-policy.json', '/private/owned/capture-policy.json')
            init = [tg_init]
            c['args'] = [a.replace('/run/telegram/credentials.json', '/run/telegram/owned/credentials.json').replace('/run/telegram/capture-policy.json', '/run/telegram/owned/capture-policy.json') for a in original['containers'][0]['args']]
            c['volumeMounts'] = original['containers'][0]['volumeMounts']
            next(m for m in c['volumeMounts'] if m['name'] == 'session')['subPath'] = 'session'
            next(m for m in tg_init['volumeMounts'] if m['name'] == 'session')['subPath'] = 'session'
            volumes = original['volumes']
        spec = pod([c], volumes, init)
        apps.append(obj('Deployment', name, {'replicas': 1 if mode == 'api' else 0, 'strategy': {'type': 'Recreate'}, 'selector': {'matchLabels': {'app': name}}, 'template': template(name, spec)}))
    apps.append(obj('Service', 'noctis-v2-api', {'type': 'ClusterIP', 'selector': {'app': 'noctis-v2-api'}, 'ports': [{'name': 'https', 'port': 8443, 'targetPort': 'https'}]}))
    apps[-1]['metadata']['annotations'] = {'traefik.ingress.kubernetes.io/service.serversscheme': 'https', 'traefik.ingress.kubernetes.io/service.serverstransport': 'noctis-v2-noctis-v2-api@kubernetescrd'}
    traefik_peers = [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': config['traefik_namespace']}}, 'podSelector': {'matchLabels': config['traefik_labels']}}]
    traefik_peers += [{'ipBlock': {'cidr': source}} for source in hostnetwork_sources(config)]
    apps.append(obj('NetworkPolicy', 'noctis-v2-api-only', {'podSelector': {'matchLabels': {'app': 'noctis-v2-api'}}, 'policyTypes': ['Ingress'], 'ingress': [{'from': traefik_peers, 'ports': [{'port': 8081, 'protocol': 'TCP'}]}]}))
    ingress = [obj('ServersTransport', 'noctis-v2-api', {'serverName': 'noctis.zyrak.cloud', 'insecureSkipVerify': False}), obj('Ingress', 'noctis-v2', {'ingressClassName': 'traefik', 'tls': [{'hosts': ['noctis.zyrak.cloud'], 'secretName': config['tls_secret']}], 'rules': [{'host': 'noctis.zyrak.cloud', 'http': {'paths': [{'path': '/', 'pathType': 'Prefix', 'backend': {'service': {'name': 'noctis-v2-api', 'port': {'name': 'https'}}}}]}}]})]
    ingress[-1]['metadata']['annotations'] = {'traefik.ingress.kubernetes.io/router.entrypoints': 'websecure', 'traefik.ingress.kubernetes.io/router.tls': 'true'}
    session = container('provision-session', config['busybox_image'])
    session['command'] = ['/bin/sh', '-ec', 'umask 077; test ! -e /volume/session; mkdir -m 700 /volume/session; test "$(stat -c %u /volume/session)" = 65532; cp /source/collector.session /volume/session/collector.session; chmod 600 /volume/session/collector.session; test -s /volume/session/collector.session; test "$(stat -c %u /volume/session/collector.session)" = 65532']
    session['volumeMounts'] = [mount('session', '/volume', False), mount('session-source', '/source')]
    session_job = job('noctis-v2-session-provision', pod([session], [{'name': 'session', 'persistentVolumeClaim': {'claimName': 'noctis-v2-telegram-private-session'}}, volume('session-source', 'noctis-v2-session-provision')]))
    return {'01-infrastructure.json': infra, '02-migrate.json': migrations, '03-grants.json': grants, '04-applications.json': apps, '05-cutover.json': ingress, '06-session-provision.json': [session_job]}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('private-config'); p.add_argument('--directory', required=True)
    p = sub.add_parser('render'); p.add_argument('--input', required=True); p.add_argument('--directory', required=True)
    p = sub.add_parser('render-infrastructure'); p.add_argument('--input', required=True); p.add_argument('--directory', required=True)
    args = parser.parse_args()
    if args.command == 'private-config':
        result = provision(args.directory)
    else:
        infrastructure_only = args.command == 'render-infrastructure'
        bundles = render(json.loads(Path(args.input).read_text()), infrastructure_only)
        root = private_directory(args.directory, create=True)
        for name, items in bundles.items():
            write(root / name, {'apiVersion': 'v1', 'kind': 'List', 'items': items})
        result = {'result': 'rendered', 'namespace': NS, 'files': sorted(bundles), 'applied': False, 'api_replicas': 0 if infrastructure_only else 1, 'other_replicas': 0, 'automatic_inference': False, 'alert_sender': False}
        write(root / 'render-receipt.json', {**result, 'sha256': {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in bundles}})
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError):
        sys.exit('Release preparation rejected; check private file permissions and explicit release inputs (no secret values logged).')
