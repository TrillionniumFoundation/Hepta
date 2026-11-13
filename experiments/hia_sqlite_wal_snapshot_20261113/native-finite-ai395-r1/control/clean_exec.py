"""Exact environment handoff before the original owner; no inherited shell keys."""
from pathlib import Path
import hashlib,json,os,sys
root=Path(__file__).resolve().parents[1]
if len(sys.argv)!=3:raise SystemExit('exact request path and SHA required')
path=Path(sys.argv[1]);raw=path.read_bytes()
if path!=root/'REQUEST.json' or hashlib.sha256(raw).hexdigest()!=sys.argv[2]:raise SystemExit('request identity')
q=json.loads(raw)
argv=[q['runtime']['path'],'-I','-S','-B',str(root/'control/launch.py'),str(path),sys.argv[2]]
os.execve(argv[0],argv,q['environment'])
