#!/usr/bin/env python3
"""Copy both entire offline PVCs; reject links and verify every file hash.

Destination must be private and outside the repository. Original metadata is
preserved in the tar headers; extraction deliberately does not change ownership.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
from preflight import kube, verify

POD = "noctis-rebuild-preservation-20261018"

def verify_copy(expected, actual):
    if actual != expected:
        raise ValueError("Copy incomplete or content mismatch")

def verify_metadata(metadata, members):
    expected = {}
    for line in metadata.decode().splitlines():
        mode, uid, gid, size, mtime, name = line.split(' ', 5)
        expected[name.rstrip('/')] = (int(mode, 8), int(uid), int(gid), int(size), int(mtime))
    actual = {}
    for member in members:
        name = member.name.rstrip('/')
        if not (member.isdir() or member.isfile()):
            raise ValueError('Non-regular archive member requires explicit preservation review')
        actual[name] = (member.mode, member.uid, member.gid, member.size if member.isfile() else expected[name][3], int(member.mtime))
    if expected != actual:
        raise ValueError('Archive ownership, permissions, timestamps or membership differ')

def remote(script):
    return ["kubectl", "exec", "-n", "noctis", POD, "--", "sh", "-ec", script]

def preserve(destination):
    destination = Path(destination).resolve()
    assert str(destination).startswith("/home/zyrak/.local/share/noctis-rebuild/")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    assert destination.stat().st_mode & 0o077 == 0
    uid = json.loads(kube("get", "pod", POD, "-n", "noctis", "-o", "json"))["metadata"]["uid"]
    verify(uid)
    links = subprocess.check_output(remote("find /preserve -type l"), text=True)
    assert not links.strip(), "Symlinks require explicit external preservation"
    for name in ("database", "session"):
        verify(uid)
        base = f"/preserve/{name}"
        manifest_cmd = f"cd {base}; find . -type f -exec sha256sum {{}} + | sort"
        before = subprocess.check_output(remote(manifest_cmd))
        (destination / f"{name}.source.sha256").write_bytes(before)
        metadata = subprocess.check_output(remote(f"cd {base}; find . -exec stat -c '%a %u %g %s %Y %n' {{}} +"))
        (destination / f"{name}.metadata").write_bytes(metadata)
        archive = destination / f"{name}.tar"
        with archive.open("xb") as output:
            subprocess.run(remote(f"cd {base}; tar cpf - ."), stdout=output, check=True)
        after = subprocess.check_output(remote(manifest_cmd))
        assert before == after, "Source changed during preservation"
        target = destination / name
        target.mkdir(mode=0o700)
        with tarfile.open(archive) as tar:
            verify_metadata(metadata, tar.getmembers())
            tar.extractall(target, filter="data")
        actual = {}
        for path in target.rglob("*"):
            if path.is_file():
                with path.open("rb") as handle:
                    actual["./" + str(path.relative_to(target))] = hashlib.file_digest(handle, "sha256").hexdigest()
        expected = {}
        for line in before.decode().splitlines():
            digest, path = line.split("  ", 1)
            expected[path] = digest
        verify_copy(expected, actual)
        (destination / f"{name}.verified.json").write_text(json.dumps({"files": len(actual), "bytes": sum(p.stat().st_size for p in target.rglob("*") if p.is_file()), "source_unchanged": True, "hashes_match": True}))
    verify(uid)
    print("Both full PVC copies verified; source unchanged")

if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("destination")
    preserve(parser.parse_args().destination)
