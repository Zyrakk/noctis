import contextlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import image_checks


COMMIT = 'a' * 40
VERSION = 'candidate-20'
REGISTRY = 'ghcr.io/test/app'


class DockerAndHarness:
    """Exercise the actual orchestration without Docker, databases or providers."""
    def __init__(self):
        self.calls = []
        self.images = {}
        self.exports = {arch: b'\x7fELF\x02\x01' + b'\0' * 12 + struct.pack('<H', machine)
                        for arch, machine in image_checks.ARCHITECTURES.items()}
        self.on_harness = None

    def run(self, args, **kwargs):
        self.calls.append(args)
        if args[:3] == ['docker', 'buildx', 'build']:
            arch = args[args.index('--platform') + 1].split('/')[1]
            tag = args[args.index('-t') + 1]
            digest = 'sha256:' + ('1' if arch == 'amd64' else '2') * 64
            self.images[tag] = {'Id': digest, 'Architecture': arch,
                                'Config': {'User': 'nonroot:nonroot', 'Cmd': ['v2', 'serve']},
                                'RepoDigests': [REGISTRY + '@' + digest]}
        elif args[:2] == ['docker', 'cp']:
            arch = args[2].split(':')[0]
            Path(args[3]).write_bytes(self.exports[arch])
        elif args[:2] == ['docker', 'save']:
            Path(args[3]).write_bytes(args[-1].encode())
        elif args[:2] == ['docker', 'tag']:
            self.images[args[3]] = next(info for info in self.images.values() if info['Id'] == args[2])
        elif args[:3] == ['go', 'run', './ops/rebuild/e2e']:
            receipt = {'result': 'pass', 'binary': 'noctis-amd64', 'browser': True,
                       'product': True, 'ai': True, 'dataset': 'SYNTHETIC',
                       'restricted_runtime_login': True, 'processes_stopped_on_exit': True,
                       'temporary_database_removed': True}
            destination = Path(kwargs['env']['NOCTIS_V2_E2E_RECEIPT'])
            destination.write_text(json.dumps(receipt))
            if self.on_harness:
                self.on_harness(destination)
        elif args[:2] == ['docker', 'run'] and args[-1] in self.images:
            return subprocess.CompletedProcess(args, 1, b'database secret file is required')
        elif args[:2] not in (['docker', 'run'], ['docker', 'rm'], ['docker', 'load'], ['docker', 'push']) and args[:4] != ['docker', 'buildx', 'imagetools', 'create']:
            raise AssertionError('Unexpected subprocess: ' + repr(args))
        return subprocess.CompletedProcess(args, 0)

    def check_output(self, args, **kwargs):
        self.calls.append(args)
        if args == ['git', 'rev-parse', 'HEAD']:
            return COMMIT + '\n'
        if args[:3] == ['docker', 'image', 'inspect']:
            return json.dumps([self.images[args[3]]]).encode()
        if args[:2] == ['docker', 'create']:
            return args[args.index('--platform') + 1].split('/')[1] + '\n'
        if args[:2] == ['docker', 'run']:
            return 'noctis version ' + VERSION + '\n'
        if args[:3] == ['docker', 'buildx', 'imagetools']:
            manifests = [{'platform': {'os': 'linux', 'architecture': arch},
                          'digest': 'sha256:' + digit * 64}
                         for arch, digit in [('amd64', '1'), ('arm64', '2')]]
            if args[3] == 'create' or args[4] == REGISTRY + ':latest':
                return json.dumps({'digest': 'sha256:' + '3' * 64, 'manifests': manifests}).encode()
            return json.dumps({'digest': args[4].split('@')[1]}).encode()
        raise AssertionError('Unexpected subprocess: ' + repr(args))


class ImageArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / 'candidate'
        self.fake = DockerAndHarness()
        for target, replacement in [('run', self.fake.run), ('check_output', self.fake.check_output)]:
            mock = patch('image_checks.subprocess.' + target, side_effect=replacement)
            mock.start()
            self.addCleanup(mock.stop)
        environment = patch.dict(os.environ, {'NOCTIS_IMAGE_TAGS': REGISTRY + ':latest'})
        environment.start()
        self.addCleanup(environment.stop)

    def build(self):
        with contextlib.redirect_stdout(io.StringIO()):
            image_checks.check(self.output, VERSION, COMMIT)
        self.fake.calls.clear()

    def read(self, name):
        return json.loads((self.output / name).read_text())

    def edit(self, name, change):
        value = self.read(name)
        change(value)
        (self.output / name).write_text(json.dumps(value))

    def assert_not_published(self):
        self.assertFalse(any(args[:2] == ['docker', 'push'] or (
            args[:4] == ['docker', 'buildx', 'imagetools', 'create'] and '--dry-run' not in args)
            for args in self.fake.calls), self.fake.calls)

    def reject_publication(self, expected=ValueError):
        with self.assertRaises(expected):
            image_checks.publish(self.output, REGISTRY, COMMIT, VERSION)
        self.assert_not_published()

    def test_candidate_runs_exact_extracted_binary_and_promotes_without_rebuild(self):
        with contextlib.redirect_stdout(io.StringIO()):
            image_checks.check(self.output, VERSION, COMMIT)
        harness = [args for args in self.fake.calls if args[:2] == ['go', 'run']]
        self.assertEqual(harness, [['go', 'run', './ops/rebuild/e2e', '--binary',
                                   str(self.output / 'noctis-amd64'), '--browser', '--product', '--ai']])
        e2e = self.read('e2e/candidate-receipt.json')
        self.assertEqual(e2e['candidate'], image_checks.identity(self.read('receipt.json')))
        self.assertEqual(e2e['harness_sha256'], image_checks.checksum(self.output / 'e2e/harness-receipt.json'))
        self.fake.calls.clear()
        image_checks.publish(self.output, REGISTRY, COMMIT, VERSION)
        first_push = next(i for i, args in enumerate(self.fake.calls) if args[:2] == ['docker', 'push'])
        prior = self.fake.calls[:first_push]
        self.assertEqual(sum(args[:2] == ['docker', 'load'] for args in prior), 2)
        self.assertEqual(sum(args[:2] == ['docker', 'cp'] for args in prior), 2)
        self.assertFalse(any(args[:3] == ['docker', 'buildx', 'build'] or args[:1] == ['go'] for args in self.fake.calls))
        self.assertEqual(self.read('publication-receipt.json')['published_tags'], [REGISTRY + ':latest'])
        self.assertTrue((self.output / 'publication-progress.json').exists())

    def test_missing_or_legacy_receipts_never_publish(self):
        self.build()
        for name in ['receipt.json', 'e2e/candidate-receipt.json', 'e2e/harness-receipt.json']:
            with self.subTest(name=name):
                path = self.output / name
                raw = path.read_bytes()
                path.unlink()
                self.reject_publication(FileNotFoundError)
                path.write_bytes(raw)
        self.edit('receipt.json', lambda value: value.pop('schema'))
        self.reject_publication()

    def test_failed_stale_or_mismatched_binding_never_publishes(self):
        self.build()
        path = self.output / 'e2e/candidate-receipt.json'
        raw = path.read_bytes()
        changes = [lambda value: value.update(result='fail'),
                   lambda value: value['candidate'].update(candidate_id='previous-run'),
                   lambda value: value['candidate'].update(commit='b' * 40),
                   lambda value: value['candidate'].update(version='previous-version'),
                   lambda value: value.update(harness_sha256='0' * 64),
                   lambda value: value['candidate']['images']['arm64'].update(id='sha256:wrong')]
        for change in changes:
            with self.subTest(change=change):
                path.write_bytes(raw)
                self.edit('e2e/candidate-receipt.json', change)
                self.reject_publication()

    def test_expected_identity_is_independent_of_receipts(self):
        self.build()
        for commit, version in [('b' * 40, VERSION), (COMMIT, 'unexpected'), ('', VERSION)]:
            with self.subTest(commit=commit, version=version):
                with self.assertRaises(ValueError):
                    image_checks.publish(self.output, REGISTRY, commit, version)
                self.assert_not_published()

    def test_incomplete_or_non_synthetic_harness_never_publishes(self):
        self.build()
        path = self.output / 'e2e/harness-receipt.json'
        raw = path.read_bytes()
        for field in ['browser', 'product', 'ai', 'dataset', 'result', 'restricted_runtime_login',
                      'processes_stopped_on_exit', 'temporary_database_removed', 'binary']:
            with self.subTest(field=field):
                path.write_bytes(raw)
                self.edit('e2e/harness-receipt.json', lambda value: value.pop(field))
                self.edit('e2e/candidate-receipt.json', lambda value: value.update(harness_sha256=image_checks.checksum(path)))
                self.reject_publication()
        path.write_bytes(raw)
        self.edit('e2e/harness-receipt.json', lambda value: value.update(real_ai_wire_enabled=False))
        self.edit('e2e/candidate-receipt.json', lambda value: value.update(harness_sha256=image_checks.checksum(path)))
        self.reject_publication()

    def test_either_corrupt_archive_prevents_all_loads_and_pushes(self):
        self.build()
        for arch in image_checks.ARCHITECTURES:
            with self.subTest(arch=arch):
                archive = self.output / (arch + '.tar')
                raw = archive.read_bytes()
                archive.write_bytes(b'corrupt')
                self.reject_publication()
                self.assertFalse(any(args[:2] == ['docker', 'load'] for args in self.fake.calls))
                archive.write_bytes(raw)

    def test_either_wrong_loaded_image_or_executable_prevents_all_pushes(self):
        self.build()
        for arch in image_checks.ARCHITECTURES:
            record = self.read('receipt.json')['images'][arch]
            info = self.fake.images[record['tag']]
            with self.subTest(arch=arch, fault='id'):
                original = info['Id']
                info['Id'] = 'sha256:wrong'
                self.reject_publication()
                info['Id'] = original
            with self.subTest(arch=arch, fault='binary'):
                original = self.fake.exports[arch]
                self.fake.exports[arch] += b'changed'
                self.reject_publication()
                self.fake.exports[arch] = original

    def test_changed_local_executable_prevents_publication(self):
        self.build()
        for arch in image_checks.ARCHITECTURES:
            with self.subTest(arch=arch):
                binary = self.output / ('noctis-' + arch)
                original = binary.read_bytes()
                binary.write_bytes(b'changed')
                self.reject_publication()
                binary.write_bytes(original)

    def test_transferred_archives_do_not_require_duplicate_executable_files(self):
        self.build()
        for arch in image_checks.ARCHITECTURES:
            (self.output / ('noctis-' + arch)).unlink()
        image_checks.preflight(self.output, COMMIT, VERSION)
        self.assertEqual(sum(args[:2] == ['docker', 'cp'] for args in self.fake.calls), 2)
        self.assert_not_published()

    def test_loaded_architecture_user_and_command_mismatch_prevents_publication(self):
        self.build()
        for arch in image_checks.ARCHITECTURES:
            tag = self.read('receipt.json')['images'][arch]['tag']
            original = json.dumps(self.fake.images[tag])
            for fault in ['architecture', 'user', 'cmd']:
                with self.subTest(arch=arch, fault=fault):
                    info = self.fake.images[tag]
                    if fault == 'architecture':
                        info['Architecture'] = 'wrong'
                    elif fault == 'user':
                        info['Config']['User'] = 'root'
                    else:
                        info['Config']['Cmd'] = ['serve']
                    self.reject_publication()
                    self.fake.images[tag] = json.loads(original)

    def test_source_commit_mismatch_fails_before_build(self):
        with self.assertRaisesRegex(ValueError, 'Source commit'):
            image_checks.check(self.output, VERSION, 'b' * 40)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.fake.calls, [['git', 'rev-parse', 'HEAD']])

    def test_failed_process_cannot_leave_success_receipt(self):
        def fail(destination):
            raise subprocess.CalledProcessError(1, ['go', 'run'])
        self.fake.on_harness = fail
        with self.assertRaises(subprocess.CalledProcessError):
            image_checks.check(self.output, VERSION, COMMIT)
        self.assertFalse((self.output / 'receipt.json').exists())
        self.assertFalse((self.output / 'e2e/candidate-receipt.json').exists())

    def test_zero_exit_without_harness_receipt_fails_closed(self):
        self.fake.on_harness = lambda destination: destination.unlink()
        with self.assertRaises(FileNotFoundError):
            image_checks.check(self.output, VERSION, COMMIT)
        self.assertFalse((self.output / 'e2e/candidate-receipt.json').exists())

    def test_zero_exit_with_incomplete_harness_receipt_fails_closed(self):
        self.fake.on_harness = lambda destination: destination.write_text('{"result":"pass"}')
        with self.assertRaises(ValueError):
            image_checks.check(self.output, VERSION, COMMIT)
        self.assertFalse((self.output / 'e2e/candidate-receipt.json').exists())

    def test_existing_evidence_cannot_be_reused(self):
        self.build()
        with self.assertRaises(FileExistsError):
            image_checks.run_candidate_e2e(self.output, self.read('receipt.json'))
        self.assertEqual(self.fake.calls, [])

    def test_files_must_remain_stable_during_harness(self):
        for filename in ['noctis-amd64', 'noctis-arm64', 'amd64.tar', 'arm64.tar']:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as name:
                output = Path(name) / 'candidate'
                self.fake.on_harness = lambda destination: (output / filename).write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'checksum'):
                    image_checks.check(output, VERSION, COMMIT)
                self.assertFalse((output / 'e2e/candidate-receipt.json').exists())


if __name__ == '__main__':
    unittest.main()
