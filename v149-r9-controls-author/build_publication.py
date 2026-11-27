"""Lossless immutable R9 author custody; no project or product execution."""
from pathlib import Path
import base64,hashlib,json,re,stat,zlib
ROOT=Path(__file__).resolve().parents[1]
OUT=Path(__file__).resolve().parent
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def encode(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b,m=None):
    d={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
    if m is not None:d.update(mode=m,git_mode='100755' if m&0o111 else '100644')
    return d
def read(p):
    s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
    before=[getattr(s,k) for k in FIELDS];b=p.read_bytes()
    assert len(b)==s.st_size and before==[getattr(p.lstat(),k) for k in FIELDS]
    return b,stat.S_IMODE(s.st_mode),before
def write(p,b,m=0o644):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(b)
    p.chmod(m);assert read(p)[:2]==(b,m)

files=[];manifest=[];total=0
for p in sorted(ROOT.rglob('*')):
    if p==OUT or OUT in p.parents:continue
    if p.is_dir():assert not p.is_symlink();continue
    b,m,s=read(p);name=p.relative_to(ROOT).as_posix();text=b.decode('utf-8')
    for pattern in (r'(?i)[?&](?:sig|se|skoid|sktid)=',r'(?i)authorization\s*[:=]\s*(?:bearer|basic|token)\s+',r'(?i)set-cookie\s*[:=]'):
        assert re.search(pattern,text) is None,(name,'credential carrier')
    row={'path':name,'identity':pin(b,m)}
    manifest.append({**row,'local_seven_stats':s});files.append({**row,'data_base64':base64.b64encode(b).decode()});total+=len(b)
payload=encode({'schema':'hia.R9.complete-controls-author-files.v1','files':files})
packed=zlib.compress(payload,9)
parts=[]
for index,start in enumerate(range(0,len(packed),360000)):
    chunk=packed[start:start+360000]
    wrapper={'schema':'hia.R9.controls-author-transport-part.v1','index':index,'offset':start,
        'encoding':'base64','decoded':pin(chunk),'data':base64.b64encode(chunk).decode()}
    path='parts/%03d.json'%index;raw=encode(wrapper);write(OUT/path,raw)
    parts.append({'path':path,'identity':pin(raw,0o644),'decoded':pin(chunk),'offset':start})
index={'schema':'hia.R9.controls-author-transport-index.v1','codec':'zlib','decoded':pin(payload),
    'compressed':pin(packed),'parts':parts,'files':len(files),'logical_bytes':total,
    'all_author_files_lossless':True,'complete_runtime_or_source_payload_included':False,
    'actual_R9_product_payloads_included':False,'credential_carriers_detected':0,'products':0}
write(OUT/'AUTHOR-CAPSULE-INDEX.json',encode(index))
joined=b''.join(base64.b64decode(json.loads(read(OUT/p['path'])[0])['data'],validate=True) for p in parts)
assert joined==packed
d=zlib.decompressobj();restored=d.decompress(joined)+d.flush()
assert d.eof and not d.unused_data and not d.unconsumed_tail and restored==payload
restored_rows=json.loads(restored)['files'];assert len(restored_rows)==len(files)
for row in restored_rows:
    b=base64.b64decode(row['data_base64'],validate=True);now,m,s=read(ROOT/row['path'])
    assert b==now and pin(b,m)==row['identity']
    assert s==next(x['local_seven_stats'] for x in manifest if x['path']==row['path'])
write(OUT/'AUTHOR-MANIFEST.json',encode({'schema':'hia.R9.controls-author-manifest.v1','files':manifest,
    'file_count':len(files),'logical_bytes':total,'full_current_bytes_modes_and_seven_stats_checked':True}))
plan=json.loads(read(ROOT/'EXECUTION-PLAN.json')[0])
write(OUT/'EXTERNAL-INPUTS.json',encode({'schema':'hia.R9.controls-external-inputs.v1',
    'original948_roles_fully_embedded_in_plan':True,'new14_actual_roles':plan['R9_explicit_successor']['actual_candidate_roles'],
    'source':plan['source'],'runtime':plan['runtime'],'original_ORACLE_plan_sha256':plan['requires_prior_original_oracle_restore'],
    'fixed_inputs_total':len(plan['fixed_inputs']),'complete_payloads_not_repeated_in_author_capsule':True,
    'original_R4_failure_retained':True,'R9_semantics_or_aggregate_executed':False}))
write(OUT/'LOCAL-READBACK.json',encode({'schema':'hia.R9.controls-author-local-readback.v1',
    'status':'PASS_LOSSLESS_AUTHOR_BYTES_ONLY','files':len(files),'logical_bytes':total,
    'index':pin(read(OUT/'AUTHOR-CAPSULE-INDEX.json')[0],0o644),'decoded':pin(payload),'compressed':pin(packed),
    'transport_parts':len(parts),'all_full_bytes_modes_and_current_seven_stats_match':True,
    'full_product_payload_readback_claimed':False,'product_output_absent':not Path(plan['output']).exists(),
    'project_imports':0,'products':0}))
selected=['HANDOFF.json','EXECUTION-PLAN.json','PRODUCT-LAUNCH.json','R9-EXACT-INVERSE.json','FINAL-STATIC-READBACK.json',
    'prepare_controls_author.py','verify_controls_author.py','CONTRACT-R9.md','R9-AUTHORING-RESULT.json',
    'r8_common.py','r8_private_reference.py']
rows=[]
for name in selected:
    b,m,_=read(ROOT/name);write(OUT/name,b,m);rows.append({'path':name,'identity':pin(b,m)})
for name in ['AUTHOR-CAPSULE-INDEX.json','AUTHOR-MANIFEST.json','EXTERNAL-INPUTS.json','LOCAL-READBACK.json','build_publication.py']+[x['path'] for x in parts]:
    b,m,_=read(OUT/name);rows.append({'path':name,'identity':pin(b,m)})
write(OUT/'PUBLICATION-INPUTS.json',encode({'schema':'hia.R9.controls-publication-inputs.v1',
    'repository':'TrillionniumFoundation/Hepta','files':rows,'refs':0,'CI':0,'products':0}))
print(json.dumps({'author_files':len(files),'author_bytes':total,'compressed_bytes':len(packed),'parts':len(parts),
    'publication_leaves':len(rows),'index':pin(read(OUT/'AUTHOR-CAPSULE-INDEX.json')[0],0o644),'products':0},sort_keys=True))
