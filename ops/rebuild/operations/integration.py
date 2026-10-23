#!/usr/bin/env python3
"""Failure acceptance against an existing synthetic v2 encrypted backup only."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time
import uuid
from backup import MEMBERS, private_file, restore, unpack

def exercise(archive, key, parent):
    os.umask(0o077)
    archive, key, parent = Path(archive), Path(key), Path(parent)
    root = parent / ('faults-' + uuid.uuid4().hex[:10])
    root.mkdir(mode=0o700)
    source = root / 'source'
    source.mkdir(mode=0o700)
    unpack(archive, key, source)
    results = {}
    def rejected(name, function):
        try:
            function()
        except (ValueError, RuntimeError, FileExistsError, subprocess.CalledProcessError):
            results[name] = 'rejected'
        else:
            raise RuntimeError('Unsafe operation accepted: ' + name)
    rejected('existing_destination', lambda: restore(archive, key, source))
    bad = root / 'corrupt.age'
    bad.write_bytes(archive.read_bytes()[:-25] + b'corrupt')
    rejected('corrupt_ciphertext', lambda: restore(bad, key, root / 'bad-cipher'))
    recipient = subprocess.check_output(['age-keygen', '-y', str(private_file(key))], text=True).strip()
    def altered(name, missing=False, broken_dump=False):
        path = root / (name + '.age')
        report = json.loads((source / 'recovery-report.json').read_text())
        if broken_dump:
            report['dump_sha256'] = hashlib.sha256(b'not a pg dump').hexdigest()
        plain = root / (name + '.tar')
        with tarfile.open(plain, 'w') as bundle:
            for member in sorted(MEMBERS):
                if missing and member == 'manifest.json':
                    continue
                data = (source / member).read_bytes()
                if member == 'database.dump' and broken_dump:
                    data = b'not a pg dump'
                if member == 'recovery-report.json':
                    data = json.dumps(report).encode()
                info = tarfile.TarInfo(member); info.size = len(data); info.mode = 0o600
                bundle.addfile(info, io.BytesIO(data))
        with plain.open('rb') as handle:
            subprocess.run(['age', '-r', recipient, '-o', str(path)], stdin=handle, check=True)
        return path
    incomplete = altered('incomplete', missing=True)
    rejected('incomplete_archive', lambda: restore(incomplete, key, root / 'missing'))
    broken = altered('malformed-dump', broken_dump=True)
    rejected('real_pg_restore_failure', lambda: restore(broken, key, root / 'broken-dump'))
    rejected('failure_mid_restore', lambda: restore(archive, key, root / 'mid-restore', fail_after_restore=True))
    # No restore container created by this exercise may survive failure paths.
    running = subprocess.check_output(['docker', 'ps', '-aq', '--filter', 'label=noctis.restore.owner'], text=True).strip()
    if running:
        raise RuntimeError('Owned restore resource leaked')
    results['restore_owned_containers_remaining'] = 0
    (root / 'fault-receipt.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--parent', required=True)
    args = parser.parse_args()
    exercise(args.archive, args.key, args.parent)
