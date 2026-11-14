"""Bounded UTF-8 transport of the complete actual R9 archive; zero products."""
from pathlib import Path
import base64,hashlib,json,stat,zlib
R=Path(__file__).resolve().parent
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def enc(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def write(n,b):
 p=R/n;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(b)
 p.chmod(0o644);assert p.read_bytes()==b
 return {'path':n,'identity':{**pin(b),'mode':0o644},'mode':0o644}
report=json.loads((R/'REPORT.json').read_bytes());archive=(R/'COMPLETE-ORIGINALS.tar.gz').read_bytes()
assert pin(archive)==report['archive'] and report['all_files']==2213 and report['logical_bytes']==1122457162
rows=[];parts=[]
for i,start in enumerate(range(0,len(archive),393216)):
 b=archive[start:start+393216]
 row=write('parts/%03d.json'%i,enc({'schema':'hepta.complete-originals.archive-part.v1','index':i,'offset':start,
     'decoded':pin(b),'archive':report['archive'],'encoding':'base64','data':base64.b64encode(b).decode()}))
 rows.append(row);parts.append({**row,'offset':start,'decoded':pin(b)})
for name in ('MANIFEST.json','INTENT.json'):
 b=(R/name).read_bytes();z=zlib.compress(b,9)
 rows.append(write(name[:-5]+'.zlib.json',enc({'schema':'hepta.complete-originals.exact-text-wrapper.v1',
     'original_name':name,'original':pin(b),'original_mode':stat.S_IMODE((R/name).stat().st_mode),
     'encoding':'zlib-base64','compressed':pin(z),'data':base64.b64encode(z).decode()})))
index={'schema':'hepta.r9.controls.complete-originals.transport-index.v1','archive':report['archive'],
 'manifest':report['manifest'],'parts':parts,'all_files':report['all_files'],'logical_bytes':report['logical_bytes'],
 'unique_objects':report['unique_objects'],'unique_bytes':report['unique_bytes'],'qualification':'FAIL',
 'complete_original_failure_and_success_raw':True,'original_input_payloads_are_separately_retained':True,
 'parts_required_order':list(range(len(parts))),'all_parts_POST_GET_required':True,'refs':0,'products':0,
 'R9_author_recipe':'0495153ef956e3e06eddc2f6bce978068d66ff85','terminal_semantic_reader_not_yet_executed':True}
rows.append(write('TRANSPORT-INDEX.json',enc(index)))
for name in ('REPORT.json','build_custody.py','prepare_publication.py','prepare_sealer.py','R4-SEALER-ORIGINAL.py',
             'SEALER.diff','CUSTODY-SCOPE.json','ACTUAL-SEALER-TOOL-RETURNS.json'):
 p=R/name;b=p.read_bytes();m=stat.S_IMODE(p.stat().st_mode)
 rows.append({'path':name,'identity':{**pin(b),'mode':m},'mode':m})
assert all(r['identity']['bytes']<=650000 for r in rows)
write('PUBLICATION-INPUTS.json',enc({'schema':'hia.R9.complete-raw-publication-inputs.v1','files':rows,'products':0,'refs':0}))
print(json.dumps({'parts':len(parts),'leaves':len(rows),'archive':report['archive'],'all_originals':report['all_files'],
    'logical_bytes':report['logical_bytes'],'max_leaf_bytes':max(r['identity']['bytes'] for r in rows),'products':0},sort_keys=True))
