"""Synthetic restore publication tests; no services, providers or real secrets."""
from concurrent.futures import ThreadPoolExecutor
import contextlib
import ctypes
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

import backup


def fixture(version=4):
    files = {'database.secret' if version < 3 else 'database-api.secret': b'synthetic-private-dsn',
             'ai-master.json': json.dumps({'key_id': 'synthetic-private-id', 'key': '12' * 32}).encode(),
             'admin.secret': b'synthetic-private-admin', 'tls.crt': b'synthetic-private-cert',
             'tls.key': b'synthetic-private-key'}
    report = {'format': 'noctis-v2-config-v' + str(version), 'modes': ['api'], 'files': list(files),
              'database_files': {'api': 'database.secret' if version < 3 else 'database-api.secret'},
              'capture_policy_files': {}, 'sha256': {k: hashlib.sha256(v).hexdigest() for k, v in files.items()}}
    return files, report


def bundle(files, report):
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode='w') as archive:
        for filename, data in dict(files, **{'recovery-report.json': json.dumps(report).encode()}).items():
            member = tarfile.TarInfo(filename)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return plain.getvalue()


class ConfigurationPublicationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.archive = self.root / 'archive.age'
        self.key = self.root / 'key'
        for path in [self.archive, self.key]:
            path.write_bytes(b'synthetic-placeholder')
            path.chmod(0o600)
        self.destination = self.root / 'restored'

    def restore(self, plain):
        def decrypt(*args, **kwargs):
            kwargs['stdout'].write(plain)
        with patch('backup.subprocess.run', side_effect=decrypt):
            return backup.restore_config(self.archive, self.key, self.destination)

    def assert_private(self, directory):
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        for path in directory.iterdir():
            self.assertFalse(path.is_symlink())
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def assert_incomplete(self, count=1):
        self.assertFalse(self.destination.exists())
        attempts = list(self.root.glob('.restored.restore-config-*.incomplete'))
        self.assertEqual(len(attempts), count)
        for attempt in attempts:
            self.assert_private(attempt)
        return attempts

    def test_all_formats_preserve_bytes_and_sanitized_receipt(self):
        for version in range(1, 5):
            with self.subTest(version=version):
                self.destination = self.root / ('restored-v' + str(version))
                files, report = fixture(version)
                # Historical reports can contain unvalidated extension metadata.
                if version < 4:
                    report['capture_policy_files'] = {'untrusted': 'synthetic-private-extension'}
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured):
                    result = self.restore(bundle(files, report))
                    print(json.dumps(result))
                self.assert_private(self.destination)
                for filename, data in files.items():
                    self.assertEqual((self.destination / filename).read_bytes(), data)
                self.assertEqual((self.destination / 'recovery-report.json').read_bytes(), json.dumps(report).encode())
                receipt_text = (self.destination / 'restore-receipt.json').read_text()
                receipt = json.loads(receipt_text)
                self.assertEqual(receipt['archive_format'], report['format'])
                self.assertEqual(receipt['coverage'], result['coverage'])
                self.assertEqual(receipt['checks']['sha256'], 'pass' if version == 4 else 'not-available-in-format')
                self.assertFalse(receipt['services_authorized'])
                self.assertNotIn('synthetic-private', receipt_text + captured.getvalue())
                self.assertNotIn('12' * 32, receipt_text + captured.getvalue())
                self.assertEqual(list(self.root.glob('*.incomplete')), [])

    def test_decryption_failure_retains_private_incomplete_attempt(self):
        with patch('backup.subprocess.run', side_effect=subprocess.CalledProcessError(1, ['age'])):
            with self.assertRaises(subprocess.CalledProcessError):
                backup.restore_config(self.archive, self.key, self.destination)
        self.assert_incomplete()

    def test_invalid_archives_never_publish(self):
        scenarios = ['truncated', 'traversal', 'symlink', 'duplicate', 'json', 'hash', 'mapping', 'modes', 'required-file', 'account']
        for attempt_number, scenario in enumerate(scenarios, 1):
            with self.subTest(scenario=scenario):
                files, report = fixture()
                if scenario == 'traversal':
                    files['../escaped'] = b'unsafe'
                if scenario == 'hash':
                    files['admin.secret'] += b'tampered'
                if scenario == 'mapping':
                    report['database_files'] = {'api': 'database-worker.secret'}
                if scenario == 'modes':
                    report['modes'] = {'api': 'synthetic-private-extension'}
                if scenario == 'required-file':
                    del files['admin.secret']
                    report['files'].remove('admin.secret')
                if scenario == 'account':
                    files['telegram-credentials.json'] = json.dumps({'account': 'one', 'api_id': 1, 'api_hash': 'synthetic-private-api'}).encode()
                    files['capture-policy.json'] = json.dumps({'version': 1, 'budget_id': 'synthetic-private-budget', 'account': 'other'}).encode()
                    report['files'] = list(files)
                    report['sha256'] = {k: hashlib.sha256(v).hexdigest() for k, v in files.items()}
                plain = bundle(files, report)
                if scenario == 'truncated':
                    plain = plain[:520]
                if scenario in {'symlink', 'duplicate', 'json'}:
                    buffer = io.BytesIO(plain)
                    with tarfile.open(fileobj=buffer, mode='a') as archive:
                        member = tarfile.TarInfo('database-api.secret' if scenario == 'duplicate' else 'collector.session')
                        if scenario == 'symlink':
                            member.type = tarfile.SYMTYPE
                            member.linkname = '../escaped'
                        archive.addfile(member)
                    plain = buffer.getvalue()
                    if scenario == 'json':
                        plain = plain.replace(b'"format":', b'!format!:')
                with self.assertRaises((ValueError, tarfile.TarError)):
                    self.restore(plain)
                self.assert_incomplete(count=attempt_number)
                self.assertFalse((self.root / 'escaped').exists())

    def test_sigkill_before_and_after_commit(self):
        files, report = fixture()
        plain = bundle(files, report)
        real_publish = backup.publish_configuration
        for phase in ['decryption', 'extraction', 'before-publication', 'after-publication']:
            with self.subTest(phase=phase):
                self.destination = self.root / 'restored'
                def terminate(*args, **kwargs):
                    if phase == 'decryption':
                        kwargs['stdout'].write(plain[:512])
                        kwargs['stdout'].flush()
                    elif phase == 'extraction':
                        args[1].write(args[0].read(1))
                        args[1].flush()
                    if phase == 'after-publication':
                        real_publish(*args, **kwargs)
                    os.kill(os.getpid(), signal.SIGKILL)
                child = os.fork()
                if child == 0:
                    try:
                        target = {'decryption': 'backup.subprocess.run', 'extraction': 'backup.shutil.copyfileobj',
                                  'before-publication': 'backup.publish_configuration', 'after-publication': 'backup.publish_configuration'}[phase]
                        if phase == 'decryption':
                            with patch(target, side_effect=terminate):
                                backup.restore_config(self.archive, self.key, self.destination)
                        else:
                            with patch(target, side_effect=terminate):
                                self.restore(plain)
                    finally:
                        os._exit(70)
                _, status = os.waitpid(child, 0)
                self.assertTrue(os.WIFSIGNALED(status))
                self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                if phase == 'after-publication':
                    self.assert_private(self.destination)
                    self.assertTrue((self.destination / 'restore-receipt.json').is_file())
                    for filename, data in files.items():
                        self.assertEqual((self.destination / filename).read_bytes(), data)
                    self.assertFalse((self.destination / 'FAILED').exists())
                else:
                    self.assert_incomplete(count=['decryption', 'extraction', 'before-publication'].index(phase) + 1)

    def test_existing_and_racing_destinations_are_never_replaced(self):
        plain = bundle(*fixture())
        real_publish = backup.publish_configuration
        for when in ['existing', 'racing']:
            for kind in ['file', 'empty-directory', 'nonempty-directory', 'symlink']:
                with self.subTest(when=when, kind=kind):
                    self.destination = self.root / (when + '-' + kind)
                    def create_destination():
                        if kind == 'file':
                            self.destination.write_bytes(b'preserved')
                        elif kind == 'symlink':
                            self.destination.symlink_to(self.archive)
                        else:
                            self.destination.mkdir()
                            if kind == 'nonempty-directory':
                                (self.destination / 'preserved').write_bytes(b'preserved')
                        return self.destination.lstat().st_ino
                    def race(staging, destination):
                        inode.append(create_destination())
                        real_publish(staging, destination)
                    inode = [create_destination()] if when == 'existing' else []
                    with patch('backup.publish_configuration', side_effect=race) as publish:
                        with self.assertRaises((FileExistsError, ValueError)):
                            self.restore(plain)
                        if when == 'existing':
                            publish.assert_not_called()
                    self.assertEqual(self.destination.lstat().st_ino, inode[0])
                    if kind == 'file':
                        self.assertEqual(self.destination.read_bytes(), b'preserved')
                    elif kind == 'symlink':
                        self.assertEqual(self.destination.readlink(), self.archive)
                    else:
                        self.assertEqual(sorted(path.name for path in self.destination.iterdir()), ['preserved'] if kind == 'nonempty-directory' else [])

    def test_concurrent_restores_have_one_winner(self):
        plain = bundle(*fixture())
        barrier = threading.Barrier(2)
        real_publish = backup.publish_configuration
        def publish(staging, destination):
            barrier.wait(timeout=10)
            real_publish(staging, destination)
        def restore():
            try:
                backup.restore_config(self.archive, self.key, self.destination)
                return 'published'
            except FileExistsError:
                return 'preserved'
        def decrypt(*args, **kwargs):
            kwargs['stdout'].write(plain)
        with patch('backup.subprocess.run', side_effect=decrypt), patch('backup.publish_configuration', side_effect=publish):
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _: restore(), range(2)))
        self.assertEqual(sorted(results), ['preserved', 'published'])
        self.assert_private(self.destination)
        self.assertTrue((self.destination / 'restore-receipt.json').exists())
        attempts = list(self.root.glob('*.incomplete'))
        self.assertEqual(len(attempts), 1)
        self.assert_private(attempts[0])

    def test_unsupported_atomic_rename_has_no_fallback(self):
        for code in [errno.ENOSYS, errno.EINVAL, errno.ENOTSUP]:
            with self.subTest(errno=code), patch('backup.ctypes.CDLL') as library:
                def unsupported(*args):
                    ctypes.set_errno(code)
                    return -1
                library.return_value.renameat2.side_effect = unsupported
                with self.assertRaisesRegex(RuntimeError, 'atomic configuration publication'):
                    self.restore(bundle(*fixture()))
        self.assert_incomplete(count=3)

    def test_symlink_parent_is_rejected_before_decryption(self):
        link = self.root / 'link'
        link.symlink_to(self.root, target_is_directory=True)
        with patch('backup.subprocess.run') as decrypt:
            with self.assertRaises(ValueError):
                backup.restore_config(self.archive, self.key, link / 'restored')
            decrypt.assert_not_called()


if __name__ == '__main__':
    unittest.main()
