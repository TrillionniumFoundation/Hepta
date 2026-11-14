"""Bounded immutable transport of every sealed generation original; no products."""
from pathlib import Path
import base64,hashlib,json,stat
R=Path(__file__).absolute().parent
def pin(b):
    return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def write(p,b):
    with p.open('xb') as f:f.write(b)
    assert p.read_bytes()==b
report=json.loads((R/'REPORT.json').read_bytes())
archive=(R/'COMPLETE-ORIGINALS.tar.gz').read_bytes()
assert report['status']=='PASS_COMPLETE_ORIGINAL_BYTES_AND_MODES' and pin(archive)==report['archive']
assert report['all_files']==140 and report['logical_bytes']==34477797
(R/'parts').mkdir(mode=0o700)
parts=[]
for i,offset in enumerate(range(0,len(archive),393216)):
    b=archive[offset:offset+393216]
    p=R/'parts'/('%03d.json'%i)
    wrapper={'schema':'hepta.complete-originals.archive-part.v1','index':i,'offset':offset,
        'archive':report['archive'],'decoded':pin(b),'encoding':'base64','data':base64.b64encode(b).decode()}
    raw=encoded(wrapper);write(p,raw)
    parts.append({'path':p.relative_to(R).as_posix(),'index':i,'offset':offset,'decoded':pin(b),**pin(raw)})
index={'schema':'hepta.op8-generation.complete-originals.transport.v1','archive':report['archive'],
    'manifest':report['manifest'],'parts':parts,'file_count':140,'logical_bytes':34477797,
    'generation_raw_files':103,'generation_raw_bytes':13102351,
    'source_payload_repeated':False,'all_generated_outputs_and_copy_records_included':True,
    'qualification':'GENERATION_ONLY_NOT_NEW_OP8_TEST_QUALIFICATION','products':0,'refs':0}
write(R/'TRANSPORT-INDEX.json',encoded(index))
names=['INPUT-PLAN.json','INTENT.json','MANIFEST.json','REPORT.json','TRANSPORT-INDEX.json',
    'seal_originals.py','BEFORE-SEALER.py','SEALER.diff','prepare_transport.py',
    'verify_git_readback.py','ACTUAL-SEALER-TOOL-RETURNS.json']+[p['path']for p in parts]
rows=[]
for i,n in enumerate(names):
    p=R/n;b=p.read_bytes();assert len(b)<=650000
    rows.append({'index':i,'path':str(p),'relative':n,**pin(b),'mode':'100644',
        'posix_mode':stat.S_IMODE(p.lstat().st_mode)})
for n in ['INTENTS','ACK','GET','VERIFIED']:(R/n).mkdir(mode=0o700)
write(R/'PUBLICATION-PLAN.json',encoded({'schema':'hepta.op8-generation.complete-originals.publication.v1',
    'files':rows,'products':0,'refs':0,'all_leaf_full_GET_required':True}))
print(json.dumps({'files':len(rows),'parts':len(parts),'archive':report['archive'],'originals':140}))
