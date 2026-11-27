"""Prepare bounded complete terminal-readback transport after the actual seal."""
from pathlib import Path
import base64,hashlib,json,stat,zlib
R=Path(__file__).resolve().parent
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def enc(x):return (json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def write(n,b):
    p=R/n;p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(b)
    p.chmod(0o644);assert p.read_bytes()==b
    return {'path':n,'local_path':str(p),'identity':{**pin(b),'mode':0o644}}
report=json.loads((R/'REPORT.json').read_bytes());archive=(R/'COMPLETE-ORIGINALS.tar.gz').read_bytes()
assert pin(archive)==report['archive'] and report['all_files']==33 and report['logical_bytes']==10674864
rows=json.loads((R/'INITIAL-PUBLICATION-INPUTS.json').read_bytes())['files'];assert len(rows)==10
parts=[]
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
index={'schema':'hepta.r9.terminal-readback.complete-originals.transport-index.v1','archive':report['archive'],
    'manifest':report['manifest'],'parts':parts,'all_files':33,'logical_bytes':10674864,
    'unique_objects':report['unique_objects'],'unique_bytes':report['unique_bytes'],
    'qualification':'FAIL','actual_terminal_readback':'PASS_READBACK_OF_ACTUAL_R9_VM_FUEL_FAILURE',
    'actual_terminal_reader_outputs_files':9,'actual_terminal_reader_outputs_bytes':10211986,
    'all_author_files_including_complete_R1':20,'all_Root_records':4,
    'all_parts_POST_GET_required':True,'parts_required_order':list(range(len(parts))),
    'complete_actual_product_raw_recipe':'90fa722cc35d3eec283193dcb4e7d72c59d9a36f',
    'author_recipe':'85d17475b000d5a0d4d32ad7dd846e62eb7cf267',
    'actual_buffer_payloads_not_duplicated_in_this_metadata_package':True,
    'additional_reader_executions':0,'refs':0,'products':0,'CI':0}
rows.append(write('TRANSPORT-INDEX.json',enc(index)))
for name in ('REPORT.json','prepare_publication.py','ACTUAL-SEALER-TOOL-RETURNS.json'):
    p=R/name;b=p.read_bytes();m=stat.S_IMODE(p.stat().st_mode)
    rows.append({'path':name,'local_path':str(p),'identity':{**pin(b),'mode':m}})
assert len({r['path'] for r in rows})==len(rows) and all(r['identity']['bytes']<=650000 for r in rows)
write('PUBLICATION-INPUTS.json',enc({'schema':'hia.R9.terminal-readback-publication-inputs.v1','files':rows,'products':0,'refs':0}))
print(json.dumps({'parts':len(parts),'leaves':len(rows),'archive':report['archive'],'all_originals':33,
    'logical_bytes':10674864,'max_leaf_bytes':max(r['identity']['bytes'] for r in rows),'products':0},sort_keys=True))
