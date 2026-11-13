"""Enter the exact already-frozen source request environment once."""
from pathlib import Path
import hashlib
import json
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
assert len(sys.argv) == 2 and len(sys.argv[1]) == 64
raw = (ROOT / 'REQUEST-r2.json').read_bytes()
assert hashlib.sha256(raw).hexdigest() == sys.argv[1]
q = json.loads(raw)
assert q['schema'] == 'hia.sqlite-btree-cell.source12-request.v1'
assert q['qualification_seconds'] == 180 and q['cleanup_seconds'] == 3
runtime = q['runtime']['executable']
assert runtime == '/usr/bin/python3.14'
os.chdir(ROOT)
os.execve(runtime, [runtime, '-I', '-S', '-B', str(ROOT / 'control/source12_r2.py'),
                   '--request', str(ROOT / 'REQUEST-r2.json'), '--sha256', sys.argv[1]],
          q['environment'])
