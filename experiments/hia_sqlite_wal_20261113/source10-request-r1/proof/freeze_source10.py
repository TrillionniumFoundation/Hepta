"""Freeze the first WAL source request without importing or executing product code."""
from pathlib import Path
import ast
import hashlib
import json
import os
import sys

ROOT=Path(__file__).resolve().parents[1]
SOURCE_ROOT=Path('/home/agent/hia-sqlite-source8-r2-recovery-20261113-e26e/source-base')
CATALOG=Path('/home/agent/hia-sqlite-varint-source-eight-actual-r2-20261113-e26e/SOURCE-BEFORE.json')
OWNER=Path('/home/agent/hia-v92-diagnostics-only-remote-r2-20261113-e26e/candidate/process_owner_impl.py')
OUT=Path('/home/agent/hia-sqlite-wal-source10-actual-r1-20261113-e26e')
def pin(path):
    raw=path.read_bytes();s=path.lstat()
    return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'identity':[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]}
def save(name,value):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    with (ROOT/name).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    os.chmod(ROOT/name,0o400);return pin(ROOT/name)
assert not os.path.lexists(OUT) and not (ROOT/'REQUEST.json').exists()
files=sorted(p for directory in ('inputs','control','reference') for p in (ROOT/directory).rglob('*') if p.is_file())
for p in files:
    if p.suffix=='.py':ast.parse(p.read_bytes())
    os.chmod(p,0o400)
catalog=json.loads(CATALOG.read_bytes());assert len(catalog)==1686
assert sum(v['bytes'] for v in catalog.values())==40890650
assert hashlib.sha256(CATALOG.read_bytes()).hexdigest()=='47883509715c4bd177ad238c3d544327249db595ee99bd265120894c41337209'
assert hashlib.sha256(OWNER.read_bytes()).hexdigest()=='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
tree=ast.parse((ROOT/'inputs/tests/test_hia_sqlite_wal_source.py').read_bytes())
names=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='EXPECTED_NAMES' for t in n.targets)))
cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='SQLiteWalSourceTests')
assert names==tuple(n.name for n in cls.body if isinstance(n,ast.FunctionDef) and n.name.startswith('test_'))
module='tests.hia_sqlite_wal_source_r1';ids=[module+'.SQLiteWalSourceTests.'+n for n in names]
counts=[0,46,56,16,54,32,8,26,0,0];assert len(ids)==10 and sum(counts)==238
runtime=Path(sys.executable).resolve();assert str(runtime)=='/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python3.12'
environment={'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PATH':'','PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0','PYTHONUNBUFFERED':'1'}
inputs=[pin(p) for p in [*files,CATALOG,OWNER,runtime]]
q={'schema':'hia.sqlite-wal.source10-request.v1','status':'FROZEN_UNEXECUTED','qualification_seconds':180,'cleanup_seconds':3,
   'output_root':str(OUT),'source_root':str(SOURCE_ROOT),'source_catalog':str(CATALOG),'source_commit':'0504beb11c0dae875d8590660c42488b7bc634fb',
   'source_tree':'596ab07e8813e4811a8dca51800cd51eb397aeb2','source_file_count':1686,'source_total_bytes':40890650,
   'owner_path':str(OWNER),'runtime':{'executable':str(runtime),'version':sys.version},'environment':environment,
   'test_module':module,'expected_ids':ids,'expected_vm_by_id':dict(zip(ids,counts)),'expected_vm_returns':238,
   'inputs':inputs,'actual_source10_runs':0,'native_C_SQL_or_network_allowed':False,
   'original_caps':{'assembly_bytes':1048576,'assembly_lines':16384,'functions':128,'total_blocks':1536,'blocks_per_function':256,'operations':8192,'maximum_ssa':2047,'arguments':16,'returns':3},
   'output_limits':{'files':64,'bytes':16777216},'minimum_free_bytes':268435456,'minimum_free_inodes':4096,
   'old_failures_or_UNKNOWN_reclassified':False,'scope':'New WAL byte kernel only; no full database, installed/default or current native qualification.'}
request_pin=save('REQUEST.json',q)
launch={'schema':'hia.sqlite-wal.source10-launch.v1','command':[str(runtime),'-I','-S','-B',str(ROOT/'control/source10.py'),'--request',str(ROOT/'REQUEST.json'),'--sha256',request_pin['sha256']],
        'cwd':str(ROOT),'environment':environment,'request':request_pin,'additional_timeout':None,'automatic_retry':False,'status':'UNEXECUTED'}
launch_pin=save('LAUNCH.json',launch)
save('STATIC-FREEZE.json',{'schema':'hia.sqlite-wal.source10-static-freeze.v1','request':request_pin,'launch':launch_pin,'inputs':inputs,'AST_only':True,'generator_VM_native_and_SQL_runs':0,
                            'complete_original_C_sources_and_original_functions_retained':True,'per_method_expected_VM_returns':counts})
print(json.dumps({'request':request_pin,'launch':launch_pin,'inputs':len(inputs),'source_files':1686,'expected_methods':10,'expected_VM_returns':238}))
