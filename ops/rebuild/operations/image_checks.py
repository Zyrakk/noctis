#!/usr/bin/env python3
"""Cross-build on the host; execute AMD64 only. Never install QEMU/binfmt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import uuid

def checksum(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

ARCHITECTURES = {'amd64': 62, 'arm64': 183}

def identity(receipt):
    return {key: receipt[key] for key in ('candidate_id', 'commit', 'version')} | {
        'images': {arch: {key: receipt['images'][arch][key]
                         for key in ('id', 'archive_sha256', 'binary_sha256')}
                   for arch in ARCHITECTURES}}

def require_expected(commit, version):
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', commit) or not version:
        raise ValueError('Explicit expected commit SHA and version required')

def inspect_image(tag, arch, record=None):
    info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag]))[0]
    if (info['Architecture'] != arch or info['Config']['User'] != 'nonroot:nonroot'
            or info['Config']['Cmd'][:1] != ['v2']):
        raise ValueError('Architecture/nonroot/default v2 contract mismatch')
    if record and (info['Id'] != record['id'] or info['Config']['Cmd'] != record['cmd']):
        raise ValueError('Loaded image differs from tested image')
    return info

def extract_binary(tag, arch, binary):
    container = subprocess.check_output(['docker', 'create', '--platform', 'linux/' + arch,
                                         '--network', 'none', tag, '--version'], text=True).strip()
    try:
        subprocess.run(['docker', 'cp', container + ':/noctis', str(binary)], check=True, stdout=subprocess.DEVNULL)
        with binary.open('rb') as handle:
            header = handle.read(20)
        if (len(header) != 20 or header[:6] != b'\x7fELF\x02\x01'
                or struct.unpack('<H', header[18:20])[0] != ARCHITECTURES[arch]):
            raise ValueError('Exported ELF target mismatch')
        return checksum(binary)
    finally:
        subprocess.run(['docker', 'rm', container], check=True, stdout=subprocess.DEVNULL)

def validate_harness(receipt):
    if (receipt.get('result') != 'pass' or receipt.get('dataset') != 'SYNTHETIC'
            or receipt.get('binary') != 'noctis-amd64'
            or any(receipt.get(key) is not True for key in (
                'browser', 'product', 'ai', 'restricted_runtime_login',
                'processes_stopped_on_exit', 'temporary_database_removed'))
            or any(key.startswith('real_ai_') for key in receipt)):
        raise ValueError('Incomplete or non-synthetic harness receipt')

def validate_files(output, receipt, binaries=False):
    for arch, record in receipt['images'].items():
        if checksum(output / (arch + '.tar')) != record['archive_sha256']:
            raise ValueError('Tested image archive checksum mismatch: ' + arch)
        binary = output / ('noctis-' + arch)
        # CI transfers archives, not redundant executable copies. Local copies
        # must match when present; preflight always re-extracts both archives.
        if (binaries or binary.exists()) and checksum(binary) != record['binary_sha256']:
            raise ValueError('Tested executable checksum mismatch: ' + arch)

def run_candidate_e2e(output, receipt):
    # A fresh private destination prevents a previous successful harness run from
    # satisfying this invocation, including when the process exits without writing.
    evidence = output / 'e2e'
    evidence.mkdir(mode=0o700, exist_ok=False)
    harness = evidence / 'harness-receipt.json'
    validate_files(output, receipt, binaries=True)
    subprocess.run(['go', 'run', './ops/rebuild/e2e', '--binary', str((output / 'noctis-amd64').resolve()),
                    '--browser', '--product', '--ai'], check=True,
                   env=dict(os.environ, NOCTIS_V2_E2E_RECEIPT=str(harness.resolve())))
    validate_harness(json.loads(harness.read_text()))
    validate_files(output, receipt, binaries=True)
    for arch, record in receipt['images'].items():
        inspect_image(record['tag'], arch, record)
    result = {'schema': 1, 'result': 'pass', 'candidate': identity(receipt),
              'harness_sha256': checksum(harness)}
    with (evidence / 'candidate-receipt.json').open('x') as handle:
        json.dump(result, handle, indent=2)

def check(output, version, commit):
    require_expected(commit, version)
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() != commit:
        raise ValueError('Source commit differs from expected commit')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    receipt = {'schema': 2, 'candidate_id': uuid.uuid4().hex, 'commit': commit,
               'arm64_execution': False, 'network_smoke': 'none', 'version': version, 'images': {}}
    for arch, machine in ARCHITECTURES.items():
        tag = 'noctis-v2-check:' + arch + '-' + uuid.uuid4().hex[:10]
        with (output / (arch + '-build.log')).open('w') as log:
            subprocess.run(['docker', 'buildx', 'build', '--load', '--platform', 'linux/' + arch, '--build-arg', 'VERSION=' + version, '-t', tag, '.'], stdout=log, stderr=subprocess.STDOUT, check=True)
        info = inspect_image(tag, arch)
        binary_sha256 = extract_binary(tag, arch, output / ('noctis-' + arch))
        archive = output / (arch + '.tar')
        subprocess.run(['docker', 'save', '--output', str(archive), tag], check=True)
        record = {'id': info['Id'], 'tag': tag, 'archive_sha256': checksum(archive), 'architecture': arch, 'elf_machine': machine, 'binary_sha256': binary_sha256, 'user': info['Config']['User'], 'cmd': info['Config']['Cmd']}
        if arch == 'amd64':
            actual_version = subprocess.check_output(['docker', 'run', '--rm', '--network', 'none', tag, '--version'], text=True).strip()
            if actual_version != 'noctis version ' + version:
                raise RuntimeError('Built image version mismatch: ' + actual_version)
            record['version_output'] = actual_version
            for args in [['--version'], ['v2', 'serve', '--help']]:
                subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', tag, *args], check=True, stdout=subprocess.DEVNULL)
            missing = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--read-only', tag], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if missing.returncode == 0 or b'database secret file' not in missing.stdout:
                raise RuntimeError('Unconfigured default must fail closed on v2 secret reference')
            record['executed'] = True
            record['unconfigured_default_rejected'] = True
        else:
            record['executed'] = False
        receipt['images'][arch] = record
    run_candidate_e2e(output, receipt)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2))
    print('AMD64 offline smoke and synthetic browser/product/AI E2E PASS; ARM64 ELF export PASS (not executed); receipt=' + str(output / 'receipt.json'))

def preflight(output, commit, version):
    """Validate both archives, identities and E2E before any publication effect."""
    require_expected(commit, version)
    receipt = json.loads((output / 'receipt.json').read_text())
    if (receipt.get('schema') != 2 or receipt.get('commit') != commit
            or receipt.get('version') != version or not receipt.get('candidate_id')
            or set(receipt.get('images', {})) != set(ARCHITECTURES)):
        raise ValueError('Candidate receipt schema/commit/version mismatch')
    e2e = json.loads((output / 'e2e/candidate-receipt.json').read_text())
    harness = output / 'e2e/harness-receipt.json'
    if (e2e.get('schema') != 1 or e2e.get('result') != 'pass'
            or e2e.get('candidate') != identity(receipt)
            or e2e.get('harness_sha256') != checksum(harness)):
        raise ValueError('E2E receipt differs from candidate or harness')
    validate_harness(json.loads(harness.read_text()))
    for arch, machine in ARCHITECTURES.items():
        record = receipt['images'][arch]
        if (record['architecture'] != arch or record['elf_machine'] != machine
                or record['user'] != 'nonroot:nonroot' or record['cmd'][:1] != ['v2']
                or record['executed'] is not (arch == 'amd64')):
            raise ValueError('Candidate image contract mismatch')
    if (receipt['images']['amd64'].get('version_output') != 'noctis version ' + version
            or receipt['images']['amd64'].get('unconfigured_default_rejected') is not True):
        raise ValueError('Candidate version/smoke mismatch')
    validate_files(output, receipt)
    with tempfile.TemporaryDirectory(prefix='noctis-image-preflight-') as directory:
        for arch, record in receipt['images'].items():
            subprocess.run(['docker', 'load', '--input', str(output / (arch + '.tar'))], check=True, stdout=subprocess.DEVNULL)
            inspect_image(record['tag'], arch, record)
            digest = extract_binary(record['tag'], arch, Path(directory) / ('noctis-' + arch))
            if digest != record['binary_sha256']:
                raise ValueError('Loaded executable differs from tested executable: ' + arch)
    validate_files(output, receipt)
    return receipt

def publish(output, registry, commit, version):
    """Publish only the exact image archives tested by the prerequisite CI job."""
    tags = os.environ.get('NOCTIS_IMAGE_TAGS', '').splitlines()
    if not tags or any(not tag.startswith(registry + ':') for tag in tags):
        raise ValueError('Explicit registry-scoped publication tags required')
    receipt = preflight(output, commit, version)
    digests = []
    expected_runtime = set()
    for arch in ['amd64', 'arm64']:
        record = receipt['images'][arch]
        target = registry + ':tested-' + record['id'].removeprefix('sha256:')
        subprocess.run(['docker', 'tag', record['id'], target], check=True)
        subprocess.run(['docker', 'push', target], check=True)
        info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', target]))[0]
        digest = next(value for value in info['RepoDigests'] if value.startswith(registry + '@sha256:'))
        digests.append(digest)
        record['published_digest'] = digest
        remote = json.loads(subprocess.check_output(['docker', 'buildx', 'imagetools', 'inspect', digest, '--format', '{{json .Manifest}}']))
        if 'manifests' in remote:
            executable = [entry for entry in remote['manifests'] if entry.get('platform', {}).get('os') != 'unknown'
                          and entry.get('platform', {}).get('architecture') != 'unknown']
            if (len(executable) != 1 or executable[0]['platform'].get('os') != 'linux'
                    or executable[0]['platform'].get('architecture') != arch):
                raise ValueError('Published architecture index differs from tested image')
            runtime_digest = executable[0]['digest']
        else:
            runtime_digest = digest.split('@')[1]
        expected_runtime.add(('linux', arch, runtime_digest))
        record['published_runtime_digest'] = runtime_digest
        (output / 'publication-progress.json').write_text(json.dumps(receipt, indent=2))
    for tag in tags:
        # Containerd image stores may publish each tested archive as an OCI index
        # containing its executable manifest and provenance attestations.
        preview = json.loads(subprocess.check_output(['docker', 'buildx', 'imagetools', 'create', '--dry-run', *digests]))
        def executable_manifests(document):
            return {(entry['platform']['os'], entry['platform']['architecture'], entry['digest'])
                    for entry in document['manifests'] if entry.get('platform', {}).get('os') != 'unknown'
                    and entry.get('platform', {}).get('architecture') != 'unknown'}
        if executable_manifests(preview) != expected_runtime:
            raise ValueError('Publication preview differs from tested executable manifests')
        subprocess.run(['docker', 'buildx', 'imagetools', 'create', '--tag', tag, *digests], check=True)
        remote = json.loads(subprocess.check_output(['docker', 'buildx', 'imagetools', 'inspect', tag, '--format', '{{json .Manifest}}']))
        if executable_manifests(remote) != expected_runtime:
            raise ValueError('Published manifest differs from tested image digests')
        receipt.setdefault('published_manifest_digests', {})[tag] = remote['digest']
    receipt['published_tags'] = tags
    (output / 'publication-receipt.json').write_text(json.dumps(receipt, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', required=True, help='Expected embedded version, supplied independently of receipts')
    parser.add_argument('--commit', required=True, help='Expected source commit SHA, supplied independently of receipts')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--publish', help='Publish the existing tested archives to this registry/repository')
    mode.add_argument('--verify', action='store_true', help='Validate existing candidate without publishing or rebuilding')
    args = parser.parse_args()
    if args.publish:
        publish(args.output, args.publish, args.commit, args.version)
    elif args.verify:
        preflight(args.output, args.commit, args.version)
    else:
        check(args.output, args.version, args.commit)
