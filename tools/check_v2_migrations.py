#!/usr/bin/env python3
"""Generate/check the canonical immutable v2 SQL checksum fixture."""
import argparse
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--write', action='store_true', help='explicitly regenerate after adding a migration')
args = parser.parse_args()
actual = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
          for p in sorted((root / 'migrations/v2').glob('*.sql'))}
fixture = root / 'testdata/contracts/v2-migration-checksums.json'
if args.write:
    fixture.write_text(json.dumps(actual, indent=2) + '\n')
elif not fixture.exists() or json.loads(fixture.read_text()) != actual:
    raise SystemExit('v2 migration checksum fixture differs; do not rewrite existing migrations')
else:
    print(f'{len(actual)} v2 migration checksums verified')
