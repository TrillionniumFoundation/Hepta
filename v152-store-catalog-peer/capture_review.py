"""Capture reviewed data only. No project imports or implementation calls."""
import ast
import hashlib
import json
import os
from pathlib import Path
import stat

HERE=Path(__file__).absolute().parent
A=Path('/workspace/hia-store-catalog-root-author-r1-20261115-dda7')
B=Path('/workspace/hia-cli-as-dict-generation-r1-dda7/source')
PATHS=[A/name for name in ('catalog_root_policy.py.txt','generate_hia_store_catalog_root.py',
    'catalog_codec_oracle.py','CONTRACT.md','CONTROL-PLAN.json','STATIC-REVIEW.json','AUTHORITY.json')]
PATHS += [B/'tools/generate_hia_sha256.py', B/'hepta/hia_agent_store.py']
EXPECTED={str(PATHS[0]):'933bce644986f532686da429ac7ebff621330054',
    str(PATHS[1]):'709db0ecc4c27cf9dce1d687a9c0f430f0ce3f62',
    str(PATHS[7]):'92e64315b638e86b6f212ac4f915052213d88fa5',
    str(PATHS[8]):'f13e349e7d5f4a4655e59375f963280764cda4e0'}
def seven(x):return [x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns]
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
    'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def read(p):
    before=p.lstat();assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<1<<20
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        assert seven(os.fstat(fd))==seven(before)
        data=[];left=before.st_size+1
        while left:
            block=os.read(fd,min(left,65536))
            if not block:break
            data.append(block);left-=len(block)
        raw=b''.join(data)
        assert len(raw)==before.st_size and seven(os.fstat(fd))==seven(p.lstat())==seven(before)
    finally:os.close(fd)
    row={'path':str(p),'pin':pin(raw),'mode':stat.S_IMODE(before.st_mode),'seven_stats':seven(before)}
    if str(p) in EXPECTED:assert row['pin']['git_blob']==EXPECTED[str(p)]
    return raw,row
def write(name,value):
    raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    with (HERE/name).open('xb') as f:f.write(raw)
    os.chmod(HERE/name,0o644);assert (HERE/name).read_bytes()==raw
    return pin(raw)
def main():
    rows=[];payload={}
    for path in PATHS:
        raw,row=read(path);rows.append(row);payload[str(path)]=raw
    authority=json.loads(payload[str(A/'AUTHORITY.json')])
    for relative in ('tools/generate_hia_sha256.py','hepta/hia_agent_store.py'):
        row=next(x for x in rows if x['path']==str(B/relative))
        assert row['pin']==authority['read_sources'][relative]['pin']
        assert row['mode']==authority['read_sources'][relative]['posix_mode']
    nodes=ast.parse(payload[str(A/'catalog_codec_oracle.py')]).body
    tables=next(ast.literal_eval(n.value) for n in nodes if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name) and t.id=='TABLES' for t in n.targets))
    ddl=payload[str(B/'hepta/hia_agent_store.py')].decode()
    positions=[ddl.index('CREATE TABLE IF NOT EXISTS '+t+' (') for t in tables]
    assert len(tables)==10 and positions==sorted(positions)
    for row in rows:assert seven(Path(row['path']).lstat())==row['seven_stats']
    inputs=write('INPUT-PINS.json',{'schema':'hepta.hia.store-catalog-root.peer-inputs.v1',
        'files':rows,'table_order_matches_actual_ddl':tables,'scope':'Nine files only; not full product guards'})
    _,review=read(HERE/'REVIEW.md')
    result=write('RESULT.json',{'schema':'hepta.hia.store-catalog-root.static-peer-review.v1',
        'status':'NO_DETERMINATE_BLOCKER_FOUND_WITHIN_DECLARED_CODEC_ABI','inputs':inputs,'review':review,
        'source_files_read':len(rows),'bytes_read':sum(x['pin']['bytes'] for x in rows),
        'project_imports':0,'generator_calls':0,'Core_calls':0,'Native_calls':0,'VM_calls':0,
        'candidate_files_modified':0,'whole_native':False,'durability_verified':False,'row_semantics_verified':False})
    print(json.dumps({'result':result,'review':review['pin'],'inputs':inputs},sort_keys=True))
if __name__=='__main__':main()
