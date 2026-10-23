#!/usr/bin/env python3
"""Create an age portable backup and verify full decryption without plaintext files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

if not __debug__:
    raise RuntimeError("Safety checks require Python without optimization")

def protect(root):
    root = Path(root).resolve()
    assert str(root).startswith('/home/zyrak/.local/share/noctis-rebuild/')
    assert root.stat().st_mode & 0o077 == 0
    keys = root.parent / (root.name + '-keys')
    keys.mkdir(mode=0o700)
    key = keys / 'backup.agekey'
    subprocess.run(['age-keygen', '-o', str(key)], check=True, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    recipient = subprocess.check_output(['age-keygen', '-y', str(key)], text=True).strip()
    files = sorted(p.name for p in root.iterdir() if p.is_file() and not p.name.endswith('.age'))
    archive = root / 'preserved.age'
    source = subprocess.Popen(['tar', '-C', str(root), '-cpf', '-', '--', *files], stdout=subprocess.PIPE)
    encrypted = subprocess.Popen(['age', '-r', recipient, '-o', str(archive)], stdin=subprocess.PIPE)
    expected = hashlib.sha256()
    try:
        for block in iter(lambda: source.stdout.read(1024 * 1024), b''):
            expected.update(block)
            encrypted.stdin.write(block)
        encrypted.stdin.close()
        assert source.wait() == 0, 'Archive creation failed'
        assert encrypted.wait() == 0, 'Encryption failed'
    finally:
        for process in (source, encrypted):
            if process.poll() is None:
                process.terminate(); process.wait()
    decrypt = subprocess.Popen(['age', '-d', '-i', str(key), str(archive)], stdout=subprocess.PIPE)
    actual = hashlib.sha256()
    for block in iter(lambda: decrypt.stdout.read(1024 * 1024), b''):
        actual.update(block)
    assert decrypt.wait() == 0, 'Decryption failed'
    assert actual.digest() == expected.digest(), 'Decrypted archive differs'
    result = {'tool': subprocess.check_output(['age', '--version'], text=True).strip(), 'archive_sha256': hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest(), 'plaintext_sha256': expected.hexdigest(), 'decryption_verified': True, 'files': files}
    (root / 'encryption-report.json').write_text(json.dumps(result, indent=2))
    print('Portable encrypted archive verified by full streamed decryption; key stored separately')

def protect_artifacts(root, key):
    root, key = Path(root).resolve(), Path(key).resolve()
    assert str(root).startswith('/home/zyrak/.local/share/noctis-rebuild/')
    assert root.stat().st_mode & 0o077 == 0 and key.stat().st_mode & 0o077 == 0
    archive = root / 'logical-recovery.age'
    temporary = root / 'logical-recovery.age.partial'
    assert not archive.exists() and not temporary.exists(), 'Refusing to overwrite encryption artifacts'
    files = sorted(str(p.relative_to(root)) for p in root.rglob('*') if p.is_file() and 'restore-data' not in p.relative_to(root).parts and not p.name.endswith(('.age', '.partial')))
    assert files and 'recovery-report.json' in files
    recipient = subprocess.check_output(['age-keygen', '-y', str(key)], text=True).strip()
    source = subprocess.Popen(['tar', '-C', str(root), '-cpf', '-', '--', *files], stdout=subprocess.PIPE)
    encrypted = subprocess.Popen(['age', '-r', recipient, '-o', str(temporary)], stdin=subprocess.PIPE)
    digest = hashlib.sha256()
    try:
        for block in iter(lambda: source.stdout.read(1024 * 1024), b''):
            digest.update(block); encrypted.stdin.write(block)
        encrypted.stdin.close()
        assert source.wait() == 0 and encrypted.wait() == 0, 'Encryption pipeline failed'
    finally:
        for process in (source, encrypted):
            if process.poll() is None:
                process.kill(); process.wait()
    actual = hashlib.sha256()
    decrypt = subprocess.Popen(['age', '-d', '-i', str(key), str(temporary)], stdout=subprocess.PIPE)
    for block in iter(lambda: decrypt.stdout.read(1024 * 1024), b''):
        actual.update(block)
    assert decrypt.wait() == 0 and digest.digest() == actual.digest(), 'Full decryption verification failed'
    temporary.rename(archive)
    result = {'files': files, 'decryption_verified': True, 'plaintext_sha256': digest.hexdigest(), 'archive_sha256': hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest(), 'restore_data': 'Private stopped copy retained; complete portable representation is the included verified logical dump'}
    (root / 'logical-encryption-report.json').write_text(json.dumps(result, indent=2))
    print('New logical artifacts encrypted and full decryption hash verified')

if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('destination')
    parser.add_argument('--reuse-key')
    arguments = parser.parse_args()
    if arguments.reuse_key:
        protect_artifacts(arguments.destination, arguments.reuse_key)
    else:
        protect(arguments.destination)
