"""Freeze the corrected B-tree cell live-state request without product execution."""
from pathlib import Path
import ast, hashlib, json, os, stat
ROOT=Path(__file__).resolve().parent
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
raw,oldpin=read(ROOT/'REQUEST-r2.json')
assert oldpin['sha256']=='ebdb6023995fe43b21fe0bf8bd36b6c3966a30a8e8d2a75371c6b4e9b3d696e5'
old=json.loads(raw)
assert old['expected_vm_returns']==339 and len(old['expected_ids'])==12
assert old['qualification_seconds']==180 and old['cleanup_seconds']==3 and len(old['inputs'])==46
for row in old['inputs']:
    body,pin=read(row['path']);assert pin=={k:row[k] for k in pin}
report_raw,report_pin=read(Path(old['output_root'])/'tests/REPORT.json')
final_raw,final_pin=read(Path(old['output_root'])/'FINAL.json')
assert report_pin['sha256']=='e21b3390d82e401e8bc9a9aef3ccc6d23d289f3ce243dc83a605ca93398073df'
assert final_pin['sha256']=='24f68181f4b238fd173ab0b4d3b82d2b9a57bfbc5de740fa83b7148cf273f6c0'
report=json.loads(report_raw);final=json.loads(final_raw)
assert final['status']=='HOLD' and final['closed'] is True and final['natural'] is False
assert report['status']=='HOLD' and report['tests_run']==12 and report['VM']['calls']==339
assert len(report['failures'])==1 and report['failures'][0]['id']==old['expected_ids'][0]
assert '17 not less than or equal to 16' in report['failures'][0]['detail']
assert report['errors']==[] and report['exception'] is None and report['secondary_errors']==[]
add=[]
for name in ('inputs/tools/generate_hia_sqlite_btree_cell_r3.py','control/source12_r3.py','control/clean_exec_r3.py','freeze_source12_r3.py'):
    body,pin=read(ROOT/name);ast.parse(body);add.append(pin)
q=dict(old);q['inputs']=old['inputs']+add
q['generator_path']=str(ROOT/'inputs/tools/generate_hia_sqlite_btree_cell_r3.py')
q['output_root']=str(ROOT.parent/'sqlite-btree-cell-source12-actual-r3')
assert not os.path.lexists(q['output_root'])
q['prior_Core_shape_failure']={'request':oldpin,'report':report_pin,'final':final_pin,
    'h_job':'1a1d3ff7808-392-263','status':'KNOWN_TERMINAL_HOLD_ORIGINAL_MAX16_BLOCK_ARGS_EXCEEDED',
    'original_tests_and_339_population_unchanged':True,'original_46_inputs_preserved':True,
    'change':'Defer the two pure overflow count/last scalar calculations until after word104 and before words112/120; original payload_offset and all output writes remain ordered; ten functions and all original Core/VM/owner caps retained'}
pin=create(ROOT/'REQUEST-r3.json',q)
launch={'schema':'hia.sqlite-btree-cell.source12-launch.v1',
    'command':[q['runtime']['executable'],'-I','-S','-B',str(ROOT/'control/clean_exec_r3.py'),pin['sha256']],
    'cwd':str(ROOT),'environment':q['environment'],'request':pin,'additional_timeout':None,
    'automatic_retry':False,'status':'FROZEN_EXPLICIT_NEW_REQUEST_UNEXECUTED'}
lp=create(ROOT/'LAUNCH-r3.json',launch)
fp=create(ROOT/'STATIC-FREEZE-r3.json',{'schema':'hia.sqlite-btree-cell.source12-static-freeze.v3',
    'status':'STATIC_ONLY_UNEXECUTED','original_request':oldpin,'request':pin,'launch':lp,
    'old_inputs_unchanged':46,'additional_inputs':add,'all_inputs':50,
    'test_changes':0,'expected_methods':12,'expected_VM_returns':339,
    'Core_and_VM_caps_unchanged':True,'qualification_seconds':180,'cleanup_seconds':3})
print(json.dumps({'request':pin,'launch':lp,'freeze':fp,'all_inputs':50,'expected_methods':12,'expected_VM_returns':339}))
