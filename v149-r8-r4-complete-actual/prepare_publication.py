from pathlib import Path
import base64,hashlib,json,os,stat,zlib
R=Path(__file__).resolve().parent
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def enc(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def write(n,b):
 p=R/n;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(b)
 return {'path':n,'identity':{**pin(b),'mode':stat.S_IMODE(p.stat().st_mode)},'mode':stat.S_IMODE(p.stat().st_mode)}
report=json.loads((R/'REPORT.json').read_bytes());archive=(R/'COMPLETE-ORIGINALS.tar.gz').read_bytes()
assert pin(archive)==report['archive']
rows=[];parts=[]
for index,start in enumerate(range(0,len(archive),393216)):
 raw=archive[start:start+393216]
 item={'schema':'hepta.complete-originals.archive-part.v1','index':index,'offset':start,'decoded':pin(raw),
       'archive':report['archive'],'encoding':'base64','data':base64.b64encode(raw).decode()}
 row=write('parts/%03d.json'%index,enc(item));rows.append(row);parts.append({**row,'offset':start,'decoded':pin(raw)})
for name in ('MANIFEST.json','INTENT.json'):
 raw=(R/name).read_bytes();wire=zlib.compress(raw,9)
 rows.append(write(name[:-5]+'.zlib.json',enc({'schema':'hepta.complete-originals.exact-text-wrapper.v1',
  'original_name':name,'original':pin(raw),'original_mode':stat.S_IMODE((R/name).stat().st_mode),
  'encoding':'zlib-base64','compressed':pin(wire),'data':base64.b64encode(wire).decode()})))
reader=Path('/tmp/hia-u32-r8-r4-terminal-reader-r1-dda7')
files=[]
for p in sorted(reader.iterdir()):
 if p.is_file():
  raw=p.read_bytes();files.append({'path':p.name,'mode':stat.S_IMODE(p.stat().st_mode),'identity':pin(raw),
      'encoding':'base64','data':base64.b64encode(raw).decode()})
caps=enc({'schema':'hepta.r8.r4.terminal-reader.complete-author.v1','files':files,'products':0,'reader_executions':0})
z=zlib.compress(caps,9)
rows.append(write('TERMINAL-READER-AUTHOR.zlib.json',enc({'schema':'hepta.r8.r4.terminal-reader.author-transport.v1',
 'decoded':pin(caps),'file_count':len(files),'encoding':'zlib-base64','compressed':pin(z),'data':base64.b64encode(z).decode()})))
index={'schema':'hepta.r8.r4.complete-originals.transport-index.v1','archive':report['archive'],
 'manifest':report['manifest'],'parts':parts,'all_files':report['all_files'],'logical_bytes':report['logical_bytes'],
 'unique_objects':report['unique_objects'],'unique_bytes':report['unique_bytes'],'qualification':'FAIL',
 'complete_original_failure_and_success_raw':True,'source_input_payloads_are_separately_retained':True,
 'parts_required_order':list(range(len(parts))),'all_parts_POST_GET_required':True,'Git_ref_changes':0,'products':0}
rows.append(write('TRANSPORT-INDEX.json',enc(index)))
for name in ('REPORT.json','build_custody.py','prepare_publication.py'):
 raw=(R/name).read_bytes();rows.append({'path':name,'identity':{**pin(raw),'mode':stat.S_IMODE((R/name).stat().st_mode)},'mode':stat.S_IMODE((R/name).stat().st_mode)})
assert all(row['identity']['bytes']<=650000 for row in rows)
write('PUBLICATION-INPUTS.json',enc({'files':rows}))
print(json.dumps({'parts':len(parts),'leaves':len(rows),'archive':report['archive'],'all_originals':report['all_files'],
                  'logical_bytes':report['logical_bytes'],'max_leaf_bytes':max(r['identity']['bytes'] for r in rows)},sort_keys=True))
