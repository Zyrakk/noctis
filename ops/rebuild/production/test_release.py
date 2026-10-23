import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest

import release


def configuration():
    digest = hashlib.sha256(b'unit fixture; never applied').hexdigest()
    return {'image': 'ghcr.io/zyrakk/noctis@sha256:' + digest, 'busybox_image': 'busybox@sha256:' + digest, 'postgres_image': 'postgres:16-bookworm@sha256:' + digest, 'tls_secret': 'noctis-v2-tls', 'storage_class': 'verified-rwo-class', 'postgres_size': '20Gi', 'session_size': '1Gi', 'traefik_namespace': 'kube-system', 'traefik_labels': {'app.kubernetes.io/name': 'traefik'}}


class ReleaseTests(unittest.TestCase):
    def test_hostnetwork_sources_only_extend_api_tcp_ingress(self):
        cfg = configuration()
        original = release.render(cfg)
        cfg['traefik_hostnetwork_sources'] = []
        self.assertEqual(release.render(cfg), original)
        cfg['traefik_hostnetwork_sources'] = ['10.42.3.0/32', '10.42.1.1/32', '2001:0db8::1/128']
        rendered = release.render(cfg)
        for filename, items in original.items():
            for before, after in zip(items, rendered[filename]):
                if before['kind'] != 'NetworkPolicy' or before['metadata']['name'] != 'noctis-v2-api-only':
                    self.assertEqual(after, before)
                    continue
                expected = copy.deepcopy(before)
                expected['spec']['ingress'][0]['from'] += [{'ipBlock': {'cidr': source}} for source in ['10.42.3.0/32', '10.42.1.1/32', '2001:db8::1/128']]
                self.assertEqual(after, expected)
                self.assertEqual(after['spec']['ingress'][0]['ports'], [{'port': 8081, 'protocol': 'TCP'}])

    def test_hostnetwork_sources_reject_broad_malformed_and_duplicate_entries(self):
        for sources in (None, '10.42.3.0/32', {}, [None], [1], ['10.42.3.0'], ['0.0.0.0/0'], ['10.42.3.0/24'], ['10.42.3.1/24'], ['::/0'], ['2001:db8::/64'], ['256.1.1.1/32'], ['10.42.3.0/128'], ['fe80::1%eth0/128'], ['10.42.3.0/32', '10.42.3.0/32'], ['2001:db8::1/128', '2001:0db8::1/128']):
            cfg = configuration(); cfg['traefik_hostnetwork_sources'] = sources
            with self.subTest(sources=sources), self.assertRaises(ValueError):
                release.render(cfg)

    def test_sql_gate_waits_before_ddl_and_fails_closed_on_timeout(self):
        cfg = configuration()
        bundles = release.render(cfg)
        for filename in ('02-migrate.json', '03-grants.json'):
            rendered = next(item for item in bundles[filename] if item['kind'] == 'Job')
            spec = rendered['spec']['template']['spec']
            self.assertEqual(rendered['spec']['template']['metadata']['labels']['app'], rendered['metadata']['name'])
            self.assertEqual(rendered['spec']['backoffLimit'], 0)
            self.assertEqual(spec['restartPolicy'], 'Never')
            self.assertEqual(len(spec['initContainers']), 1)
            gate = spec['initContainers'][0]
            self.assertEqual(gate['image'], cfg['postgres_image'])
            self.assertEqual(gate['command'], release.SQL_READY_COMMAND)
            self.assertEqual(next(e for e in gate['env'] if e['name'] == 'PGPASSWORD')['valueFrom'], {'secretKeyRef': {'name': 'noctis-v2-postgres-bootstrap', 'key': 'password'}})
            self.assertEqual(next(e for e in gate['env'] if e['name'] == 'PGUSER')['value'], 'noctis')
            self.assertNotIn('database', json.dumps(gate.get('volumeMounts', [])))
            self.assertNotIn('migrate', gate['command'][-1])
            self.assertIn('SELECT 1', gate['command'][-1])
        with tempfile.TemporaryDirectory() as base:
            root = Path(base)
            fake = root / 'psql'
            fake.write_text('#!/bin/sh\nexit 1\n'); fake.chmod(0o700)
            command = list(release.SQL_READY_COMMAND)
            command[3] = '0.1s'  # Same timeout/SQL process; shorten only the test deadline.
            env = dict(os.environ, PATH=str(root) + ':' + os.environ['PATH'])
            failed = subprocess.run(command, env=env, timeout=3, capture_output=True)
            self.assertEqual(failed.returncode, 124)
            fake.write_text('#!/bin/sh\nexit 0\n')
            passed = subprocess.run(command, env=env, timeout=3, capture_output=True)
            self.assertEqual(passed.returncode, 0)

    def test_infrastructure_stage_does_not_require_or_emit_an_application_image(self):
        cfg = configuration(); del cfg['image']
        with self.assertRaises(ValueError):
            release.render(cfg)
        bundles = release.render(cfg, infrastructure_only=True)
        self.assertEqual(set(bundles), {'01-infrastructure.json'})
        self.assertFalse(any(item['kind'] in ('Deployment', 'Job', 'Ingress')
                             for item in bundles['01-infrastructure.json']))

    def test_rejects_incomplete_mutable_sentinel_and_port_override(self):
        for key, value in [('image', ''), ('image', 'ghcr.io/zyrakk/noctis:latest'), ('image', 'repo@sha256:' + '0' * 64), ('postgres_image', 'postgres:17-bookworm@sha256:' + hashlib.sha256(b'17').hexdigest()), ('storage_class', 'replace-me'), ('session_size', '0Gi'), ('traefik_labels', {}), ('api_port', 80)]:
            cfg = configuration(); cfg[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                release.render(cfg)
        cfg = configuration(); del cfg['image']
        with self.assertRaises(ValueError):
            release.render(cfg)

    def test_release_separates_cutover_migrations_and_stopped_capture(self):
        cfg = configuration()
        bundles = release.render(cfg)
        items = [item for group in bundles.values() for item in group]
        apps = [i for i in items if i['kind'] == 'Deployment']
        self.assertEqual({i['metadata']['name']: i['spec']['replicas'] for i in apps}, {'noctis-v2-api': 1, 'noctis-v2-worker': 0, 'noctis-v2-collector': 0, 'noctis-v2-telegram': 0})
        self.assertTrue(all(i['metadata'].get('namespace', 'noctis-v2') == 'noctis-v2' for i in items))
        self.assertTrue(all(i['spec']['suspend'] and i['spec']['backoffLimit'] == 0 for i in items if i['kind'] == 'Job'))
        worker = next(i for i in apps if i['metadata']['name'].endswith('worker'))['spec']['template']['spec']['containers'][0]
        self.assertIn('--automatic-inference=false', worker['args'])
        self.assertNotIn('--delivery-endpoint', worker['args'])
        self.assertFalse(any(i['kind'] == 'Ingress' for name, group in bundles.items() if name != '05-cutover.json' for i in group))
        claims = [i for i in items if i['kind'] == 'PersistentVolumeClaim']
        self.assertEqual(len(claims), 2)
        self.assertTrue(all(i['spec']['accessModes'] == ['ReadWriteOnce'] for i in claims))
        for app in apps:
            spec = app['spec']['template']['spec']
            self.assertEqual(spec['securityContext']['runAsUser'], 65532)
            self.assertFalse(spec['automountServiceAccountToken'])
            for c in spec['containers']:
                self.assertTrue(c['securityContext']['readOnlyRootFilesystem'])
        text = json.dumps(bundles)
        self.assertNotIn('noctis-postgres-data', text)
        self.assertNotIn('noctis-data', text)
        self.assertNotIn('ClusterRole', text)

    def test_fresh_configuration_has_four_distinct_logins_and_no_session(self):
        with tempfile.TemporaryDirectory() as base:
            root = Path(base) / 'private'
            result = release.provision(root)
            self.assertFalse(result['secrets_printed'])
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            dsns = [(root / ('database-' + mode + '.secret')).read_text() for mode in release.MODES]
            self.assertEqual(len(set(dsns)), 4)
            for mode, dsn in zip(release.MODES, dsns):
                self.assertIn('postgres://noctis_v2_' + mode + ':', dsn)
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in root.iterdir()))
            self.assertFalse((root / 'collector.session').exists())
            sql = (root / 'init.sql').read_text()
            self.assertEqual(sql.count(' LOGIN PASSWORD '), 4)
            self.assertIn('REVOKE ALL ON DATABASE', sql)
            with self.assertRaises(FileExistsError):
                release.provision(root)


if __name__ == '__main__':
    unittest.main()
