import subprocess
import sys
import unittest
import tarfile
import tempfile
import json
from pathlib import Path
from inventory import write_source_manifest
from manifest import compare
from preserve import verify_copy, verify_metadata
from recover import command, verify_architecture, validate_source_settings, verify_transfer
from kube_guard import pod_spec, validate_pod, verify_uid
from unittest.mock import patch
from recover import snapshot

class FailureGates(unittest.TestCase):
    def test_remote_corrupt_absent_extra_size_rejected(self):
        expected = {'./PG_VERSION': {'size': 3, 'sha256': 'expected'}}
        for actual in ({}, {'./PG_VERSION': {'size': 3, 'sha256': 'corrupt'}}, dict(expected, extra={'size': 0, 'sha256': 'extra'}), {'./PG_VERSION': {'size': 4, 'sha256': 'expected'}}):
            with self.assertRaises(ValueError):
                verify_transfer(expected, actual)
    def test_archive_disabled_sentinel_requires_archive_off(self):
        settings = dict.fromkeys(('listen_addresses','restore_command','primary_conninfo','shared_preload_libraries','session_preload_libraries','local_preload_libraries'), '')
        settings.update(archive_mode='off', archive_command='(disabled)', autovacuum='off', default_transaction_read_only='on', unix_socket_directories='/tmp', max_worker_processes='0', max_wal_senders='0', max_logical_replication_workers='0')
        validate_source_settings(settings)
        with self.assertRaises(AssertionError):
            validate_source_settings(dict(settings, archive_mode='on'))
        with self.assertRaises(AssertionError):
            validate_source_settings(dict(settings, archive_mode='always'))
        with self.assertRaises(AssertionError):
            validate_source_settings(dict(settings, archive_command='touch /tmp/external-effect'))
    def test_changed_uid_rejected(self):
        with self.assertRaises(ValueError):
            verify_uid({'metadata': {'uid': 'replacement'}}, 'expected')
    def test_pvc_and_wrong_config_rejected(self):
        pod = pod_spec('test', 'run')
        pod['spec']['volumes'].append({'name': 'private', 'persistentVolumeClaim': {'claimName': 'noctis-postgres-data'}})
        with self.assertRaises(AssertionError):
            validate_pod(pod, 'run')
        pod = pod_spec('test', 'run')
        pod['spec']['containers'][0]['securityContext']['allowPrivilegeEscalation'] = True
        with self.assertRaises(AssertionError):
            validate_pod(pod, 'run')
        with self.assertRaises(AssertionError):
            validate_pod(pod_spec('test', 'run'), 'wrong-run')

    def test_snapshot_exporter_failure(self):
        class FailedTransport:
            def command(self, *args):
                return [sys.executable, '-c', 'import sys; sys.stdin.readline(); print("bad-snapshot",flush=True); raise SystemExit(17)']
        with self.assertRaises(RuntimeError):
            with snapshot(FailedTransport(), 'synthetic'):
                self.fail('Invalid snapshot must not reach consumers')

    def test_same_rows_sequence_called_difference_rejected(self):
        with self.assertRaises(ValueError):
            compare({'tables': {}, 'sequences': [{'last_value':'9007199254740993','is_called':False}]}, {'tables': {}, 'sequences': [{'last_value':'9007199254740993','is_called':True}]})

    def test_wrong_architecture_rejected(self):
        with self.assertRaises(ValueError):
            verify_architecture('arm64', 'amd64')

    def test_archive_metadata_mismatch_rejected(self):
        member = tarfile.TarInfo('./file')
        member.mode, member.uid, member.gid, member.size, member.mtime = 0o600, 70, 70, 4, 100
        with self.assertRaises(ValueError):
            verify_metadata(b'600 999 999 4 100 ./file\n', [member])

    def test_manifest_preserves_large_legacy_identity_without_authorizing(self):
        record = {'origins': ['legacy_sources'], 'legacy_source_id': '9007199254740993', 'source_type': 'telegram_channel', 'legacy_identifier': '-1009007199254740993', 'legacy_status': 'paused', 'aliases': [], 'authorization': 'preserved_legacy_status', 'resolution_status': 'legacy_unresolved', 'conflicts': []}
        with tempfile.TemporaryDirectory() as directory:
            write_source_manifest(directory, 'manifest.json', [record])
            result = json.loads((Path(directory) / 'manifest.json').read_text())
        self.assertEqual(result['version'], 'sources-manifest-v1')
        source = result['sources'][0]
        self.assertEqual(source['legacy_source_id'], '9007199254740993')
        self.assertIn('-1009007199254740993', source['aliases'])
        self.assertEqual(source['disposition'], 'paused')
        self.assertIsNone(source['native_id'])
        self.assertIsNone(source['source_id'])
        self.assertEqual(source['policy_version'], '')

    def test_incomplete_copy_rejected(self):
        with self.assertRaises(ValueError):
            verify_copy({'./PG_VERSION': 'version', './base/file': 'data'}, {'./PG_VERSION': 'version'})

    def test_corrupt_copy_rejected(self):
        with self.assertRaises(ValueError):
            verify_copy({'./base/file': 'original'}, {'./base/file': 'corrupt'})

    def test_restore_failure_propagates(self):
        with self.assertRaises(subprocess.CalledProcessError):
            command(sys.executable, '-c', 'raise SystemExit(17)')

    def test_same_counts_different_digest_rejected(self):
        with self.assertRaises(ValueError):
            compare({'tables': {'t': {'rows': 2, 'sha256': 'a'}}}, {'tables': {'t': {'rows': 2, 'sha256': 'b'}}})

    def test_schema_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            compare({'schema_sha256': 'a'}, {'schema_sha256': 'b'})

    def test_matching_manifest_accepted(self):
        compare({'tables': {'t': {'rows': 2, 'sha256': 'a'}}}, {'tables': {'t': {'rows': 2, 'sha256': 'a'}}})

if __name__ == '__main__':
    unittest.main()
