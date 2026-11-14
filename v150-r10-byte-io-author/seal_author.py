from pathlib import Path
from hashlib import sha1,sha256
import base64,json,stat,zlib
R=Path('/tmp/hia-r10-byte-io-author-r1-dda7')
O=Path('/tmp/hia-r10-byte-io-custody-r1-dda7')

def identity(raw):
 return {'bytes':len(raw),'git_blob':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'sha256':sha256(raw).hexdigest()}

def save(name,value):
 raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
 with (O/name).open('xb') as s:s.write(raw)
 (O/name).chmod(0o644)
 return identity(raw)

manifest=json.loads((R/'AUTHOR-FILES.json').read_bytes())
files=[]
for row in manifest['rows']:
 p=Path(row['path']); before=p.lstat(); raw=p.read_bytes(); after=p.lstat()
 fields=tuple(row['stat'])
 assert all(getattr(before,k)==row['stat'][k]==getattr(after,k) for k in fields)
 assert identity(raw)==row['identity'] and stat.S_IMODE(before.st_mode)==row['mode']
 files.append({'path':row['logical_path'],'text':raw.decode(),'identity':row['identity'], 'mode':row['mode'],'stat':row['stat']})
for name in ('AUTHOR-FILES.json','HANDOFF.json'):
 p=R/name; before=p.lstat(); raw=p.read_bytes(); after=p.lstat()
 fields=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
 assert all(getattr(before,k)==getattr(after,k) for k in fields)
 files.append({'path':name,'text':raw.decode(),'identity':identity(raw),'mode':stat.S_IMODE(before.st_mode),'stat':{k:getattr(before,k) for k in fields}})
assert len(files)==22 and len(set(r['path'] for r in files))==22
payload={'schema':'hia.R10.byte-io.lossless-author-payload.v1','files':files,'product_executions':0}
raw=(json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n').encode()
compressed=zlib.compress(raw,9)
cap={'schema':'hia.R10.byte-io.lossless-author-capsule.v1','encoding':'base64(zlib(UTF-8 JSON))',
     'raw_json':identity(raw),'compressed':identity(compressed),'file_count':len(files),
     'logical_file_bytes':sum(r['identity']['bytes'] for r in files),'data':base64.b64encode(compressed).decode()}
cap_pin=save('SOURCE-CAPSULE.json',cap)
back=zlib.decompress(base64.b64decode(cap['data'],validate=True))
assert back==raw
restored=json.loads(back)
for row in restored['files']:
 current=(R/row['path']).read_bytes()
 assert row['text'].encode()==current and identity(current)==row['identity']
 assert stat.S_IMODE((R/row['path']).lstat().st_mode)==row['mode']
index={'schema':'hia.R10.byte-io.source-index.v1','author_root':str(R),'capsule':cap_pin,
       'file_count':len(files),'logical_file_bytes':cap['logical_file_bytes'],
       'rows':[{k:v for k,v in row.items() if k!='text'} for row in files],
       'full_decode_equal':True,'products_executed':0,'original_R9_failure_retained':True}
indexpin=save('SOURCE-INDEX.json',index)
selected=[('SOURCE-CAPSULE.json',O/'SOURCE-CAPSULE.json'),('SOURCE-INDEX.json',O/'SOURCE-INDEX.json'),
          ('HANDOFF.json',R/'HANDOFF.json'),('GENERATOR.py',R/'overlay/tools/generate_hia_file_render_checker_word64_bytes.py'),
          ('CONTRACT.md',R/'CONTRACT.md'),('CONTROL-PLAN.json',R/'CONTROL-PLAN.json'),
          ('STATIC-BOUNDARY-PROOF.json',R/'STATIC-BOUNDARY-PROOF.json'),('EXACT-INVERSE.json',R/'EXACT-INVERSE.json'),
          ('COST-BOUND.json',R/'COST-BOUND.json'),('SOURCE.diff',R/'SOURCE.diff')]
rows=[]
for mount,path in selected:
 raw=path.read_bytes(); rows.append({'mount':mount,'path':str(path),'identity':identity(raw),'mode':stat.S_IMODE(path.stat().st_mode)})
save('PUBLISH-PLAN.json',{'repository':'TrillionniumFoundation/Hepta','leaves':rows,'ref_changes':False,'products_executed':0})
print(json.dumps({'capsule':cap_pin,'index':indexpin,'files':len(files),'logical_bytes':cap['logical_file_bytes'],'leaves':len(rows),'product_executions':0},sort_keys=True))
