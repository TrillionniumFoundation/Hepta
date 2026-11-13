"""Freeze a new launcher request after the known pre-owner R1 schema rejection.
No product import, generation, VM, C or native execution occurs here.
"""
from pathlib import Path
import ast, hashlib, json, os, stat, sys
ROOT=Path(__file__).resolve().parent
OLD_SHA='79cef7743537967dc89a325bb365636acfd914c6b8b91daa7f16dedce8fe1294'
def identity(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(path):
    path=Path(path);a=path.lstat()
    assert path.resolve(strict=True)==path and stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=64<<20
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb') as f:
        assert identity(os.fstat(f.fileno()))==identity(a)
        raw=f.read()
        assert identity(os.fstat(f.fileno()))==identity(a)
    assert len(raw)==a.st_size and identity(path.lstat())==identity(a)
    return raw,dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),identity=identity(a))
def create(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    os.chmod(path,0o400)
    actual,pin=read(path);assert raw==actual;return pin
assert ROOT==Path('/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-source-r1')
raw,oldpin=read(ROOT/'REQUEST.json');assert oldpin['sha256']==OLD_SHA
old=json.loads(raw)
assert old['expected_vm_returns']==339 and len(old['expected_ids'])==12
assert old['qualification_seconds']==180 and old['cleanup_seconds']==3 and len(old['inputs'])==43
assert not os.path.lexists(old['output_root'])
for row in old['inputs']:
    body,pin=read(row['path']);assert pin=={k:row[k] for k in pin}
add=[]
for name in ('control/source12_r2.py','control/clean_exec_r2.py','freeze_source12_r2.py'):
    body,pin=read(ROOT/name);ast.parse(body);add.append(pin)
assert read(ROOT/'control/process_owner_impl.py')[1]['sha256']=='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
q=dict(old);q['inputs']=old['inputs']+add
q['output_root']=str(ROOT.parent/'sqlite-btree-cell-source12-actual-r2')
assert not os.path.lexists(q['output_root'])
q['prior_pre_owner_failure']={'request':oldpin,'h_job':'1a1d3f606e3-392-25b',
    'status':'KNOWN_TERMINAL_LAUNCHER_SCHEMA_ASSERTION_BEFORE_EXECVE',
    'owner_invoked':False,'generation_VM_C_native_executed':False,
    'original_43_inputs_preserved':True,
    'changes':'Only schema literal in clean shim and explicit REQUEST-r2/source12_r2 path bindings; implementation and twelve339 controls unchanged'}
pin=create(ROOT/'REQUEST-r2.json',q)
launch={'schema':'hia.sqlite-btree-cell.source12-launch.v1',
    'command':[q['runtime']['executable'],'-I','-S','-B',str(ROOT/'control/clean_exec_r2.py'),pin['sha256']],
    'cwd':str(ROOT),'environment':q['environment'],'request':pin,'additional_timeout':None,
    'automatic_retry':False,'status':'FROZEN_EXPLICIT_NEW_REQUEST_UNEXECUTED'}
lp=create(ROOT/'LAUNCH-r2.json',launch)
fp=create(ROOT/'STATIC-FREEZE-r2.json',{'schema':'hia.sqlite-btree-cell.source12-static-freeze.v2',
    'status':'STATIC_ONLY_UNEXECUTED','original_request':oldpin,'request':pin,'launch':lp,
    'old_inputs_unchanged':43,'additional_control_inputs':add,'all_inputs':46,
    'implementation_and_test_changes':0,'expected_methods':12,'expected_VM_returns':339,
    'Core_and_VM_caps_unchanged':True,'qualification_seconds':180,'cleanup_seconds':3})
print(json.dumps({'request':pin,'launch':lp,'freeze':fp,'all_inputs':46,'expected_methods':12,'expected_VM_returns':339}))
