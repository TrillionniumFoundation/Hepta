"""Start exactly one fixed development phase under the unchanged Linux owner."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
from hashlib import sha1,sha256

encoded=sys.stdin.buffer.read(1048577)
if len(encoded)>1048576:
    raise ValueError('request exceeds original tool stdin limit')
payload=json.loads(encoded)
request=payload['request']
phase=request['phase']
roots={'prepare':'/home/qian-qi/he26instructions-native-prepare-r1',
    'state':'/home/qian-qi/he26instructions-state-qualification-r1',
    'instructions':'/home/qian-qi/he26instructions-instruction-qualification-r1'}
if phase not in roots or request['root']!=roots[phase]:
    raise ValueError('fixed development root or phase differs')
root=Path(request['root'])
if request['original_source']!='/home/qian-qi/he26v67r2/s':
    raise ValueError('original source root differs')
binary=Path(sys.executable).resolve()
if sha256(binary.read_bytes()).hexdigest()!=request['python_binary_sha256']:
    raise ValueError('actual CPython binary differs')
files={}
for key,name in [('common','development_common.py'),('worker','worker.py')]:
    raw=payload[key].encode()
    identity=request[key]
    actual_blob=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    if len(raw)!=identity['bytes'] or sha256(raw).hexdigest()!=identity['sha256'] or actual_blob!=identity['git_blob']:
        raise ValueError('frozen controller bytes differ '+key)
    files[name]=raw
root.mkdir(mode=0o700)
for name,raw in files.items():
    (root/name).write_bytes(raw)
(root/'launch-payload.original.json').write_bytes(encoded)
(root/'request.json').write_text(json.dumps(request,indent=2,sort_keys=True)+'\n')
owner=Path(request['original_source'])/'tools/hia_selfhost_process_owner.py'
owner_raw=owner.read_bytes()
if sha256(owner_raw).hexdigest()!=request['owner_sha256']:
    raise ValueError('unchanged process owner differs')
spec=importlib.util.spec_from_file_location('_hia_original_process_owner',owner)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.path.insert(0,str(root))
from development_common import natural_owner,save
env={'PATH':'/usr/local/bin:/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
    'PYTHONDONTWRITEBYTECODE':'1','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null',
    'GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0'}
started=time.monotonic()
life=module.run_owned([sys.executable,'-B',str(root/'worker.py'),str(root)],
    cwd=root,env=env,stdout_path=root/'child.stdout',stderr_path=root/'child.stderr',
    receipt_path=root/'lifecycle.json',qualification_seconds=180)
natural=natural_owner(life)
okay=natural and life.get('status')=='OWNED_PROCESS_COMPLETED' and life.get('returncode')==0
expected=('EXPLICIT_DEVELOPMENT_IMAGES_BUILT_NOT_CALLER_QUALIFIED' if phase=='prepare'
    else 'EXPLICIT_DEVELOPMENT_12_PLUS_51_PASS')
inner_path=root/'report.json'
inner_raw=inner_path.read_bytes() if inner_path.is_file() else None
inner=json.loads(inner_raw) if inner_raw is not None else None
owner_stable=owner.read_bytes()==owner_raw
result={'schema':'hia.machine-instructions-owned-development.v1',
    'status':'PASS' if okay and inner and inner['status']==expected and owner_stable else 'HOLD',
    'scope':'EXPLICIT_DEVELOPMENT_ONLY','phase':phase,'lifecycle':life,
    'natural_owner_cleanup':natural,'natural_owner_success':okay,
    'inner_status':inner.get('status') if inner else None,
    'inner_report_sha256':sha256(inner_raw).hexdigest() if inner_raw is not None else None,
    'seconds':time.monotonic()-started,'owner_source_stable':owner_stable,
    'matching_current_cold':False,'whole_native_delivery':False,'default_activated':False,
    'original_compile_wall_seconds':20,'original_compile_CPU_seconds':10,
    'original_owner_wall_seconds':180,'original_caller_budgets_unchanged':True}
save(root,'control.json',result)
print(json.dumps({key:result[key] for key in ('status','scope','phase',
    'natural_owner_cleanup','natural_owner_success','inner_status','seconds')},sort_keys=True),flush=True)
raise SystemExit(0 if result['status']=='PASS' else 1)
