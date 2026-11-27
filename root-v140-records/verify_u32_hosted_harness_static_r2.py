import ast,base64,copy,hashlib,json,stat,zlib
from pathlib import Path
R=Path('/workspace/scratch/dda74a4fae35'); P=R/'v134-u32-full-hosted-plan-r1'; H=P/'prepared-r2/harness'
def pin(b,mode=420):
 return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'mode':mode,'git_mode':'100755' if mode&73 else '100644'}
def read(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode);b=p.read_bytes();a=p.lstat();assert (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(a.st_dev,a.st_ino,a.st_mode,a.st_size,a.st_mtime_ns,a.st_ctime_ns);return b,pin(b,stat.S_IMODE(s.st_mode))
def load(p):return json.loads(read(p)[0])
author=load(P/'prepared-r2/AUTHORING-RESULT.json')
assert author['status']=='COMPLETE_AUTHORED_HARNESS_AND_TRANSPORT_STATIC_ONLY'
assert len(author['harness_files'])==22 and author['product_executions']==0
for name,expected in author['harness_files'].items():assert read(H/name)[1]==expected,name
assert {p.relative_to(H).as_posix() for p in H.rglob('*') if p.is_file()}==set(author['harness_files'])
assert read(H/'tools/materialize_hosted.py')[1]['git_blob']=='e31bc5cdf7cee29b5f95ddccbe45f8440270a011'
assert read(H/'tools/download_originals.py')[1]['git_blob']=='f1685f67721a7059d62288091242d67e98be0254'
assert read(H/'.github/workflows/qualification.yml')[1]['git_blob']=='96aeb56e55fd5ef83b218b393c3715937a510ea4'
for p in (H/'tools').glob('*.py'):ast.parse(read(p)[0])
for n,e in load(H/'inputs/HARNESS-INDEX.json')['files'].items():assert read(H/n)[1]==e
index=load(H/'inputs/MATERIAL-INDEX.json');parts=[]
assert len(index['parts'])==15
for row in index['parts']:
 raw,ident=read(H/'inputs'/row['path']);assert ident==row['identity']
 decoded=base64.b64decode(raw,validate=True);assert base64.b64encode(decoded)==raw and pin(decoded)==row['decoded_identity'];parts.append(decoded)
packed=b''.join(parts);assert pin(packed)==index['compressed_identity']
z=zlib.decompressobj();raw=z.decompress(packed,index['payload_identity']['bytes']+1)
assert z.eof and not z.unused_data and not z.unconsumed_tail and pin(raw)==index['payload_identity']
files={}
for row in json.loads(raw)['files']:
 assert row['path'] not in files
 b=row['text'].encode();assert pin(b,row['identity']['mode'])==row['identity'];files[row['path']]=(b,row['identity'])
assert len(files)==51 and sum(len(b) for b,p in files.values())==7688994
materials=load(P/'MATERIALS.json')
assert len(materials['files'])==44
for row in materials['files']:
 expected=read(Path(row['input_path']));assert expected[1]==row['identity'];assert files[row['logical_path']]==expected
extra={'plan/PLAN.md':P/'PLAN.md','plan/MATERIALS.json':P/'MATERIALS.json','plan/SOURCE-MATERIALIZATION.json':P/'SOURCE-MATERIALIZATION.json','plan/BASE-MANIFEST.json':Path(json.loads(files['plan/SOURCE-MATERIALIZATION.json'][0])['base_manifest']['path']),'plan/BINDING-CONTRACT.md':P/'BINDING-CONTRACT.md','plan/JSON-POINTER-ALLOWLIST.json':P/'JSON-POINTER-ALLOWLIST.json','plan/ACTUAL-BASE-READBACK.json':P/'base-readback-r1/REPORT.json'}
assert set(files)=={r['logical_path'] for r in materials['files']}|set(extra)
for n,p in extra.items():assert files[n]==read(p),n
spec=load(H/'inputs/EXECUTION-SPEC.json');assert len(spec['original_execution_python_files'])==10
for row in spec['original_execution_python_files']:
 b,i=files[row['logical_path']];assert i==row['identity'];ast.parse(b)
allow=json.loads(files['plan/JSON-POINTER-ALLOWLIST.json'][0]);counts={}
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode()
def at(v,ps):
 for p in ps:v=v[p]
 return v
for n,d in allow['documents'].items():
 b,i=read(Path(d['original_path']));assert i==d['original_identity'];v=json.loads(b);assert enc(v)==b
 mutations=[]
 for ordinal,row in enumerate(d['pointers']):
  assert at(v,row['parts'])==row['before']
  after={'ROOT_STATIC_SENTINEL':ordinal};at(v,row['parts'][:-1])[row['parts'][-1]]=after;mutations.append((row,after))
 for row,after in reversed(mutations):
  assert at(v,row['parts'])==after;at(v,row['parts'][:-1])[row['parts'][-1]]=row['before']
 assert enc(v)==b;counts[n]=len(mutations)
assert counts=={'full':120,'generation':6,'projection':12,'storage':17}
assert spec['checks']==5052 and spec['phase_count']==38 and spec['original_callable_bodies']==33
assert spec['original_budgets_exact']['qualification_seconds']==180 and spec['original_budgets_exact']['cleanup_seconds']==3
assert spec['original_storage_exact']['required_free_bytes']==3221225472
source=json.loads(files['plan/SOURCE-MATERIALIZATION.json'][0])
assert source['target_files']==3180 and source['target_tree']=='4c62be4ed66ff107fa6f88c6131313a354868bd9'
assert len(source['changes'])==22 and sum(r['after'] is not None for r in source['changes'])==20
for row in source['changes']:
 if row['after'] is not None:assert files['scope/candidate/source/'+row['path']][1]==row['after']
report={'schema':'hepta.root-u32-hosted-harness-static.v1','status':'PASS_STATIC_FULL_MATERIAL_READBACK','harness':author['harness_files'],'material_files':51,'material_bytes':7688994,'all_44_original_authorities_full_bytes_modes_equal':True,'seven_plan_proofs_full_bytes_modes_equal':True,'original_execution_Python_full_bytes':10,'JSON_pointer_counts':counts,'four_original_JSON_full_byte_inverse':True,'checks':5052,'phases':38,'retained_callable_bodies_original_pin_chain':33,'qualification_seconds':180,'cleanup_seconds':3,'free_floor':3221225472,'executed_harness_stages':[],'product_executions':0,'downloads':0,'CI_runs':0,'authorizes_execution':False,'whole_native':False}
out=R/'v95-audit-mount-r1/v140-progress/ROOT-U32-HOSTED-HARNESS-STATIC-READBACK.json'
with out.open('x') as f:f.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({'status':report['status'],'report':str(out),'identity':read(out)[1]}))
