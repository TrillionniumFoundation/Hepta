"""Lossless immutable author-code custody; no project import or product execution."""
from pathlib import Path
import base64,hashlib,json,re,stat,zlib

ROOT=Path(__file__).resolve().parents[1]
OUT=Path(__file__).resolve().parent
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def encode(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b,m=None):
    p={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
    if m is not None:p.update(mode=m,git_mode='100755' if m&0o111 else '100644')
    return p
def read(p):
    s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    b=p.read_bytes();stamp=[getattr(s,k) for k in FIELDS]
    assert len(b)==s.st_size and stamp==[getattr(p.lstat(),k) for k in FIELDS]
    return b,stat.S_IMODE(s.st_mode),stamp
def write(p,b):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(b)
    p.chmod(0o644);assert p.read_bytes()==b

files=[];manifest=[];total=0
for p in sorted(ROOT.rglob('*')):
    if OUT==p or OUT in p.parents:continue
    if p.is_dir():assert not p.is_symlink();continue
    b,m,s=read(p);name=p.relative_to(ROOT).as_posix()
    text=b.decode('utf-8')
    for pattern in (r'(?i)[?&](?:sig|se|skoid|sktid)=',r'(?i)authorization\s*[:=]\s*(?:bearer|basic|token)\s+',r'(?i)set-cookie\s*[:=]'):
        assert re.search(pattern,text) is None,(name,'credential carrier')
    row={'path':name,'identity':pin(b,m)}
    manifest.append({**row,'local_seven_stats':s})
    files.append({**row,'data_base64':base64.b64encode(b).decode()});total+=len(b)
payload=encode({'schema':'hia.R9.complete-prefix-author-files.v1','files':files})
packed=zlib.compress(payload,9)
wrapper={'schema':'hia.R9.prefix-author-capsule.v1','encoding':'zlib+base64',
    'decoded':pin(payload),'compressed':pin(packed),'data':base64.b64encode(packed).decode()}
write(OUT/'AUTHOR-CAPSULE.json',encode(wrapper))
decoded=zlib.decompress(base64.b64decode(wrapper['data'],validate=True));assert decoded==payload
for row in json.loads(decoded)['files']:
    b=base64.b64decode(row['data_base64'],validate=True);now,m,s=read(ROOT/row['path'])
    assert now==b and pin(b,m)==row['identity']
write(OUT/'AUTHOR-MANIFEST.json',encode({'schema':'hia.R9.prefix-author-manifest.v1','files':manifest,
    'file_count':len(files),'logical_bytes':total,'source_or_runtime_payload_included':False,
    'all_author_files_lossless':True,'credential_carriers_detected':0,'products':0}))
plan=json.loads((ROOT/'PREFIX-PLAN.json').read_bytes())
write(OUT/'EXTERNAL-INPUTS.json',encode({'schema':'hia.R9.prefix-fixed-external-inputs.v1',
    'fresh_mapping':plan['fresh_mapping'],'candidate_generator':plan['candidate_generator'],
    'original70_size_author_capsule':plan['size_author_capsule'],'fixed_controls':plan['fixed_controls'],
    'runtime':plan['runtime'],'source':plan['source'],
    'product_payloads_not_repeated_in_author_capsule':True,'actual_future_asset_or_image_pins':None}))
write(OUT/'LOCAL-READBACK.json',encode({'schema':'hia.R9.prefix-author-local-readback.v1',
    'status':'PASS_LOSSLESS_AUTHOR_BYTES_ONLY','files':len(files),'logical_bytes':total,
    'capsule':pin((OUT/'AUTHOR-CAPSULE.json').read_bytes(),0o644),'decoded':pin(payload),'compressed':pin(packed),
    'all_files_full_bytes_modes_recovered':True,'author_preimages_unchanged':True,
    'product_executions':0,'new_execution_root_exists':Path(plan['execution_root']).exists()}))
selected=['HANDOFF.json','PREFIX-PLAN.json','PREFIX-LAUNCH.json','run_prefix.py','prefix_support.py',
    'bind_size_context.py','generation-candidate.py','size-runner.py','size-support.py',
    'candidate_size_source.py.txt','STATIC-INVERSES.json','CONTRACT.md','AUTHORING-RESULT.json']
rows=[]
for name in selected:
    b,m,_=read(ROOT/name);write(OUT/name,b);rows.append({'path':name,'identity':pin(b,m)})
for name in ('AUTHOR-CAPSULE.json','AUTHOR-MANIFEST.json','EXTERNAL-INPUTS.json','LOCAL-READBACK.json','build_publication.py'):
    b,m,_=read(OUT/name);rows.append({'path':name,'identity':pin(b,m)})
write(OUT/'PUBLICATION-INPUTS.json',encode({'schema':'hia.R9.prefix-publication-inputs.v1','files':rows,
    'repository':'TrillionniumFoundation/Hepta','refs':0,'CI':0,'products':0}))
print(json.dumps({'author_files':len(files),'author_bytes':total,'publication_leaves':len(rows),
    'capsule':pin((OUT/'AUTHOR-CAPSULE.json').read_bytes(),0o644),'products':0},sort_keys=True))
