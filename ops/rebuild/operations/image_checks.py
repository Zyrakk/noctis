#!/usr/bin/env python3
"""Cross-build on the host; execute AMD64 only. Never install QEMU/binfmt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import uuid

def checksum(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

def check(output, version='dev'):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    receipt = {'arm64_execution': False, 'network_smoke': 'none', 'version': version, 'images': {}}
    for arch, machine in [('amd64', 62), ('arm64', 183)]:
        tag = 'noctis-v2-check:' + arch + '-' + uuid.uuid4().hex[:10]
        with (output / (arch + '-build.log')).open('w') as log:
            subprocess.run(['docker', 'buildx', 'build', '--load', '--platform', 'linux/' + arch, '--build-arg', 'VERSION=' + version, '-t', tag, '.'], stdout=log, stderr=subprocess.STDOUT, check=True)
        info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', tag]))[0]
        if info['Architecture'] != arch or info['Config']['User'] != 'nonroot:nonroot':
            raise RuntimeError('Architecture/nonroot contract mismatch')
        if info['Config']['Cmd'][:1] != ['v2']:
            raise RuntimeError('Default command must select v2')
        container = subprocess.check_output(['docker', 'create', '--platform', 'linux/' + arch, '--network', 'none', tag, '--version'], text=True).strip()
        try:
            binary = output / ('noctis-' + arch)
            subprocess.run(['docker', 'cp', container + ':/noctis', str(binary)], check=True, stdout=subprocess.DEVNULL)
            data = binary.read_bytes()
            if data[:6] != b'\x7fELF\x02\x01' or struct.unpack('<H', data[18:20])[0] != machine:
                raise RuntimeError('Exported ELF target mismatch')
        finally:
            subprocess.run(['docker', 'rm', container], check=True, stdout=subprocess.DEVNULL)
        archive = output / (arch + '.tar')
        subprocess.run(['docker', 'save', '--output', str(archive), tag], check=True)
        record = {'id': info['Id'], 'tag': tag, 'archive_sha256': checksum(archive), 'architecture': arch, 'elf_machine': machine, 'binary_sha256': hashlib.sha256(data).hexdigest(), 'user': info['Config']['User'], 'cmd': info['Config']['Cmd']}
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
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2))
    print('AMD64 offline smoke PASS; ARM64 ELF export PASS (not executed); receipt=' + str(output / 'receipt.json'))

def publish(output, registry):
    """Publish only the exact image archives tested by the prerequisite CI job."""
    receipt = json.loads((output / 'receipt.json').read_text())
    tags = os.environ.get('NOCTIS_IMAGE_TAGS', '').splitlines()
    if not tags or any(not tag.startswith(registry + ':') for tag in tags):
        raise ValueError('Explicit registry-scoped publication tags required')
    digests = []
    expected_runtime = set()
    for arch in ['amd64', 'arm64']:
        record = receipt['images'][arch]
        archive = output / (arch + '.tar')
        if checksum(archive) != record['archive_sha256']:
            raise ValueError('Tested image archive checksum mismatch')
        subprocess.run(['docker', 'load', '--input', str(archive)], check=True, stdout=subprocess.DEVNULL)
        info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', record['tag']]))[0]
        if info['Id'] != record['id'] or info['Architecture'] != arch:
            raise ValueError('Loaded image differs from tested image')
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
    parser.add_argument('--version', default='dev')
    parser.add_argument('--publish', help='Publish the existing tested archives to this registry/repository')
    args = parser.parse_args()
    if args.publish:
        publish(args.output, args.publish)
    else:
        check(args.output, args.version)
