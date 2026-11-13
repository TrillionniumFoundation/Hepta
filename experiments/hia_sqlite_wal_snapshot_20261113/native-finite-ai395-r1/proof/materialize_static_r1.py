"""Static exact-source copying and stdlib fixture arithmetic only.
No project modules, HIA author, VM, compiler, oracle or original tests execute.
"""
from pathlib import Path
import ast,hashlib,json,os,shutil,stat,sys,time
P=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
R=P/'sqlite-wal-snapshot-native-r1'
W=P/'sqlite-wal-native-r2'
S=P/'sqlite-wal-snapshot-source-r1'
A=P/'sqlite-wal-snapshot-source12-actual-r1'
def pin(p):
    b=p.read_bytes();s=p.stat()
    return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),
            'mode':stat.S_IMODE(s.st_mode)}
def put(p,b):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb')as f:f.write(b);f.flush();os.fsync(f.fileno())
    os.chmod(p,0o600)
    if p.read_bytes()!=b:raise RuntimeError('new exact copy readback')
def clone(source,dest,expected=None):
    p=pin(source)
    if expected is not None:
        for k in ('bytes','sha256','git_blob'):
            if p[k]!=expected[k]:raise RuntimeError('fixed donor differs '+str(source))
    put(dest,source.read_bytes());q=pin(dest)
    if any(p[k]!=q[k] for k in ('bytes','sha256','git_blob')):raise RuntimeError('copy changed')
    copies.append({'source':p,'destination':q})
copies=[]
old=json.loads((W/'REQUEST.json').read_bytes())
for name in ('SOURCE-BASE.json','SYSTEM-INPUTS.json','control/common.py','control/process_owner_impl.py'):
    clone(W/name,R/name,old['inputs'][name])
for item in (W/'compiler-inputs').iterdir():
    clone(item,R/'compiler-inputs'/item.name,old['inputs']['compiler-inputs/'+item.name])
for n in ('B3-ORIGINALS-CUSTODY.json','COMPILER-ORIGIN.json'):
    clone(W/'reference'/n,R/'reference'/n,old['inputs']['reference/'+n])
for folder in ('inputs','reference'):
    for path in sorted((S/folder).rglob('*')):
        if path.is_file():clone(path,R/'candidate'/folder/path.relative_to(S/folder))
for n in ('REQUEST.json','STATIC-FREEZE.json'):
    clone(S/n,R/'reference/source12-request'/n)
for n in ('VM-RAW.json','REPORT.json','CORE.json','sqlite_wal_snapshot.hiaasm'):
    clone(A/'tests'/n,R/'reference/source12-actual'/n)
for n in ('FINAL.json','owner.json','owner.json.request.json','OWNER-WRAPPER.json'):
    clone(A/n,R/'reference/source12-actual'/n)
clone(P/'sqlite-wal-snapshot-source12-actual-publication-r1/CANONICAL-HANDOFF.json',R/'reference/source12-actual/CANONICAL-HANDOFF.json')
clone(P/'sqlite-wal-snapshot-source12-actual-audit-r2/READBACK.json',R/'reference/source12-actual/INDEPENDENT-READBACK.json')
for v in ('3.46.0','3.53.2'):
    clone(P/('root-wal-snapshot-oracle-sqlite-'+v+'-r1.c'),R/'candidate/native-oracles'/('sqlite-'+v)/'adapter.c')
    clone(P/'sqlite-btree-cell-native-r1/candidate/reference'/('sqlite-'+v)/'util.c.original',R/'candidate/reference'/('sqlite-'+v)/'util.c.original')
clone(P/'root-wal-snapshot-oracle-draft-r1.json',R/'NEW-C-ORACLES.json')
clone(P/'peer-reviews/wal-snapshot-C-oracles-static-r1.json',R/'peer-reviews/C-oracles-static.json')
for n in ('model.py','matrix.py'):
    ast.parse((R/'control'/n).read_bytes(),filename=n)
put(R/'MATERIALIZATION.json',(json.dumps({'schema':'hia.wal-snapshot.native-static-materialization.v1',
    'source12_actual_commit':'9f2aed8b240ebe70a3de8084f062fae04f93709d','copies':copies,
    'product_execution':False,'HIA_generation':False,'VM':False,'C':False,'native':False},
    sort_keys=True,indent=2)+'\n').encode())
sys.path.insert(0,str(R/'control'))
import matrix
manifest=matrix.manifest(R)
if manifest['populations']['original12']!=608:raise RuntimeError('original 608')
if len(manifest['drives'])!=len({x['index']for x in manifest['drives']}):raise RuntimeError('drive IDs')
if any(x['maximum_record_bytes']>1<<20 for x in manifest['streams'].values()):raise RuntimeError('original trace record bound')
if manifest['combined_trace_bytes']>256<<20:raise RuntimeError('original total trace bound')
put(R/'EXPECTED-MATRIX.json',(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode())
print(json.dumps({'schema':'hia.wal-snapshot.native-static-arithmetic.v1','status':'STATIC_ONLY',
    'expected':pin(R/'EXPECTED-MATRIX.json'),'counts':manifest['counts'],'streams':manifest['streams'],
    'combined_trace_bytes':manifest['combined_trace_bytes'],'C_calls_each':manifest['C_calls_each'],
    'copies':len(copies),'VM_C_native_original_test_executions':0},sort_keys=True))
