import io
import contextlib
import json
import os
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

import backup
import ci_checks
import hashlib

class SafetyTests(unittest.TestCase):
    def test_existing_destination_and_symlink_parent_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            existing = root / 'existing'; existing.mkdir()
            with self.assertRaises(FileExistsError):
                backup.new_root(existing)
            link = root / 'link'; link.symlink_to(existing)
            with self.assertRaises(ValueError):
                backup.new_root(link / 'new')

    def test_foreign_resource_or_connected_network_refused(self):
        good = {'Id': 'owned', 'Config': {'Labels': {'noctis.restore.owner': 'task'}}, 'HostConfig': {'NetworkMode': 'none'}}
        for mutation in [('Id', 'other'), ('HostConfig', {'NetworkMode': 'bridge'}), ('Config', {'Labels': {'noctis.restore.owner': 'foreign'}})]:
            item = dict(good); item[mutation[0]] = mutation[1]
            with patch('subprocess.check_output', return_value=json.dumps([item]).encode()):
                with self.assertRaises(ValueError):
                    backup.owned_info('owned', 'task')

    def test_key_group_readable_refused(self):
        with tempfile.TemporaryDirectory() as name:
            key = Path(name) / 'key'; key.write_text('synthetic'); key.chmod(0o640)
            with self.assertRaises(ValueError):
                backup.private_file(key)

    def test_configuration_without_master_refused_before_encryption(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'source'; source.mkdir(mode=0o700)
            key = root / 'key'; key.write_text('synthetic'); key.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'master key'):
                backup.backup_config(source, root / 'backup', key)

    def test_required_configuration_by_mode_and_telegram_missing_rejected(self):
        self.assertEqual(backup.configuration_required(['collector']), {'database-collector.secret'})
        self.assertEqual(backup.configuration_required(['telegram']), {'database-telegram.secret', 'collector.session', 'telegram-credentials.json', 'capture-policy.json'})
        self.assertIn('tls.key', backup.configuration_required(['api', 'worker', 'telegram']))
        with self.assertRaises(ValueError):
            backup.configuration_required(['unknown'])
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'source'; source.mkdir(mode=0o700)
            for filename in ['database-telegram.secret', 'collector.session']:
                path = source / filename; path.write_text('synthetic'); path.chmod(0o600)
            key = root / 'key'; key.write_text('synthetic'); key.chmod(0o600)
            with patch('backup.protect_artifacts') as protect:
                with self.assertRaisesRegex(ValueError, 'telegram-credentials.json'):
                    backup.backup_config(source, root / 'backup', key, ['telegram'])
                protect.assert_not_called()
            self.assertFalse((root / 'backup').exists())

    def test_each_mode_database_missing_refused_before_encryption(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'source'; source.mkdir(mode=0o700)
            key = root / 'key'; key.write_text('synthetic'); key.chmod(0o600)
            for filename in backup.configuration_required(list(backup.CONFIG_REQUIRED)):
                path = source / filename; path.write_text('synthetic'); path.chmod(0o600)
            for mode, filename in backup.CONFIG_DATABASES.items():
                path = source / filename; path.unlink()
                with self.subTest(mode=mode), patch('backup.protect_artifacts') as protect:
                    with self.assertRaisesRegex(ValueError, filename):
                        backup.backup_config(source, root / 'backup', key, list(backup.CONFIG_REQUIRED))
                    protect.assert_not_called()
                self.assertFalse((root / 'backup').exists())
                path.write_text('synthetic'); path.chmod(0o600)

    def test_legacy_restore_reports_shared_dsn_scope_and_v3_mapping_is_verified(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'source'; source.mkdir(mode=0o700)
            archive = root / 'archive'; archive.write_bytes(b'encrypted-synthetic'); archive.chmod(0o600)
            key = root / 'key'; key.write_text('synthetic'); key.chmod(0o600)
            values = {'database.secret': 'synthetic-dsn', 'ai-master.json': json.dumps({'key_id': 'synthetic', 'key': '11'*32}),
                      'admin.secret': 'synthetic', 'tls.crt': 'synthetic', 'tls.key': 'synthetic'}
            for version in ['noctis-v2-config-v1', 'noctis-v2-config-v2', 'noctis-v2-config-v3']:
                report = {'format': version, 'modes': ['api'], 'files': list(values), 'database_files': {'api': 'database.secret'}}
                plain = io.BytesIO()
                with tarfile.open(fileobj=plain, mode='w') as tar:
                    for filename, data in dict(values, **{'recovery-report.json': json.dumps(report)}).items():
                        data = data.encode(); member = tarfile.TarInfo(filename); member.size = len(data)
                        tar.addfile(member, io.BytesIO(data))
                def decrypt(*args, **kwargs):
                    kwargs['stdout'].write(plain.getvalue())
                with patch('backup.subprocess.run', side_effect=decrypt):
                    if version.endswith('v3'):
                        with self.assertRaisesRegex(ValueError, 'manifest mismatch'):
                            backup.restore_config(archive, key, root / version)
                    else:
                        result = backup.restore_config(archive, key, root / version)
                        self.assertEqual(result['coverage'], 'legacy-shared-dsn-only')
                        self.assertEqual(result['database_files'], {'api': 'database.secret'})

    def test_policy_missing_or_public_refused_before_encryption(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); source = root / 'source'; source.mkdir(mode=0o700)
            key = root / 'key'; key.write_text('synthetic'); key.chmod(0o600)
            for filename in backup.configuration_required(['telegram']) - {'capture-policy.json'}:
                path = source / filename; path.write_text('synthetic'); path.chmod(0o600)
            with patch('backup.protect_artifacts') as protect:
                with self.assertRaisesRegex(ValueError, 'capture-policy.json'):
                    backup.backup_config(source, root / 'backup', key, ['telegram'])
                policy = source / 'capture-policy.json'; policy.write_text('{}'); policy.chmod(0o640)
                with self.assertRaisesRegex(ValueError, '0600'):
                    backup.backup_config(source, root / 'backup', key, ['telegram'])
                protect.assert_not_called()
            self.assertFalse((root / 'backup').exists())

    def test_v4_policy_manifest_mapping_and_digest_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            archive = root / 'archive'; archive.write_bytes(b'synthetic'); archive.chmod(0o600)
            key = root / 'key'; key.write_text('synthetic'); key.chmod(0o600)
            values = {'database-telegram.secret': 'synthetic-dsn', 'collector.session': 'synthetic-session',
                      'telegram-credentials.json': json.dumps({'account': 'synthetic', 'api_id': 1, 'api_hash': 'fake'}),
                      'capture-policy.json': json.dumps({'version': 1, 'budget_id': 'synthetic', 'account': 'synthetic'})}
            for scenario in ['valid', 'valid-v2', 'invalid-v2', 'unknown-version', 'digest', 'mapping', 'missing-policy', 'account', 'v3']:
                files = dict(values)
                if scenario in ['valid-v2', 'invalid-v2', 'unknown-version']:
                    policy = {'version': 2, 'budget_id': 'production-synthetic', 'account': 'synthetic',
                              'auth_generation': 'synthetic-generation', 'revision': 1,
                              'period_anchor': '2026-10-20T00:00:00Z', 'expires_at': '2026-10-27T00:00:00Z',
                              'actor': 'test', 'reason': 'restore same consent without renewal'}
                    if scenario == 'invalid-v2': del policy['auth_generation']
                    if scenario == 'unknown-version': policy['version'] = 3
                    files['capture-policy.json'] = json.dumps(policy)
                report = {'format': 'noctis-v2-config-v4', 'modes': ['telegram'], 'files': list(files),
                          'database_files': {'telegram': 'database-telegram.secret'}, 'capture_policy_files': {'telegram': 'capture-policy.json'},
                          'sha256': {k: hashlib.sha256(v.encode()).hexdigest() for k, v in files.items()}}
                if scenario == 'digest': files['capture-policy.json'] += ' '
                if scenario == 'mapping': report['capture_policy_files'] = {}
                if scenario in ['missing-policy', 'v3']:
                    del files['capture-policy.json']; report['files'].remove('capture-policy.json')
                if scenario == 'v3': report['format'] = 'noctis-v2-config-v3'
                if scenario == 'account':
                    files['capture-policy.json'] = json.dumps({'version': 1, 'budget_id': 'synthetic', 'account': 'other'})
                    report['sha256']['capture-policy.json'] = hashlib.sha256(files['capture-policy.json'].encode()).hexdigest()
                plain = io.BytesIO()
                with tarfile.open(fileobj=plain, mode='w') as tar:
                    for filename, data in dict(files, **{'recovery-report.json': json.dumps(report)}).items():
                        data = data.encode(); member = tarfile.TarInfo(filename); member.size = len(data)
                        tar.addfile(member, io.BytesIO(data))
                def decrypt(*args, **kwargs): kwargs['stdout'].write(plain.getvalue())
                with self.subTest(scenario=scenario), patch('backup.subprocess.run', side_effect=decrypt):
                    if scenario in ['valid', 'valid-v2', 'v3']:
                        result = backup.restore_config(archive, key, root / scenario)
                        self.assertIn('without-required-capture-policy' if scenario == 'v3' else 'and-capture-policy', result['coverage'])
                        if scenario == 'valid-v2':
                            self.assertEqual((root / scenario / 'capture-policy.json').read_text(), files['capture-policy.json'])
                    else:
                        with self.assertRaises(ValueError): backup.restore_config(archive, key, root / scenario)

class CIRequiredCoverageTests(unittest.TestCase):
    def test_missing_postgres_configuration_fails(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'PostgreSQL'):
                ci_checks.main()

    def test_missing_fault_configuration_fails(self):
        with patch.dict(os.environ, {'NOCTIS_V2_TEST_DATABASE_URL': 'postgres://postgres@127.0.0.1/noctis_v2_test'}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'fault image'):
                ci_checks.main()

    def run_events(self, events):
        process = type('Process', (), {'stdout': io.StringIO(''.join(json.dumps(x) + '\n' for x in events)), 'wait': lambda _: 0})()
        with tempfile.TemporaryDirectory() as name, patch.dict(os.environ, {
                'NOCTIS_V2_TEST_DATABASE_URL': 'postgres://postgres@127.0.0.1/noctis_v2_test',
                'NOCTIS_V2_FAULT_DOCKER_IMAGE': 'postgres:16-bookworm',
                'NOCTIS_V2_CHECK_RECEIPT': str(Path(name) / 'receipt.jsonl')}, clear=True), \
                patch('subprocess.run'), patch('subprocess.Popen', return_value=process), contextlib.redirect_stdout(io.StringIO()):
            ci_checks.main()

    def test_zero_exit_with_mandatory_missing_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'mandatory_missing'):
            self.run_events([])

    def test_unexpected_skip_fails_even_with_mandatory_passes(self):
        events = [{'Action': 'pass', 'Test': test} for test in ci_checks.MANDATORY]
        with self.assertRaisesRegex(RuntimeError, 'unexpected_skips'):
            self.run_events(events + [{'Action': 'skip', 'Test': 'TestMigrationsPostgres'}])

    def test_only_child_helper_skip_allowed(self):
        events = [{'Action': 'pass', 'Test': test} for test in ci_checks.MANDATORY]
        self.run_events(events + [{'Action': 'skip', 'Test': 'TestDomainProcessChild'}])

    def test_package_without_test_files_is_not_test_skip(self):
        events = [{'Action': 'pass', 'Test': test} for test in ci_checks.MANDATORY]
        self.run_events(events + [{'Action': 'skip', 'Package': 'example/no-tests', 'Output': '[no test files]'}])

if __name__ == '__main__':
    unittest.main()
