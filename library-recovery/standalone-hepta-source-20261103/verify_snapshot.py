#!/usr/bin/env python3
"""Verify immutable original source-byte identities."""
import hashlib, json, sys
from pathlib import Path
here=Path(__file__).resolve().parent
m=json.loads((here/'MANIFEST.json').read_text())
errors=[]
for row in m['files']:
    f=here/'files'/row['name']
    try: b=f.read_bytes()
    except OSError as exc: errors.append(str(exc)); continue
    h=hashlib.sha1(b'blob '+str(len(b)).encode('ascii')+b'\x00'+b).hexdigest()
    if (len(b),hashlib.sha256(b).hexdigest(),h)!=(row['bytes'],row['sha256'],row['git_blob_sha']):
        errors.append(row['name'])
if errors:
    print('MISMATCH:',*errors);sys.exit(1)
print('PASS: %d source identities' % len(m['files']))
