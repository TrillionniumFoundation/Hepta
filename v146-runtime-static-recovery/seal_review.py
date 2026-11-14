from pathlib import Path
import base64,hashlib,json,stat,zlib
R=Path('/tmp/hia-runtime-artifact-recovery-20261114-dda7')
NAMES=('INTENT.json','DOWNLOAD.json','ZIP-CENTRAL.json','ZIP-MEMBERS.json','RESTORATION.json','CURRENT-FILE-MAP.json','DATA-READBACK.json','download_data.py','extract_zip_static.py','restore_static.py','verify_data_readback.py','export_interpreter.original.py','AUTHORITIES.json','CONTRACT.md','zip-members/MANIFEST.json','zip-members/INTERPRETER-EXPORT.json')
def pin(b):return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def enc(x):return (json.dumps(x,sort_keys=True,indent=2)+'\n').encode()
files=[]
for name in NAMES:
 p=R/name;s=p.lstat();b=p.read_bytes()
 assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 fields=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
 assert all(getattr(p.lstat(),k)==getattr(s,k) for k in fields)
 files.append({'file':name,'mode':stat.S_IMODE(s.st_mode),'pin':pin(b),'content':b.decode('utf-8')})
raw=enc({'schema':'hepta.runtime-static-recovery.text-capsule.v1','files':files,'binary_payloads_included':False,'product_calls':0})
compressed=zlib.compress(raw,1)
(R/'REVIEW-CAPSULE.zlib').open('xb').write(compressed)
back=json.loads(zlib.decompress(compressed));assert back['files']==files
for row in back['files']:
 assert pin(row['content'].encode())==row['pin'] and (R/row['file']).read_bytes()==row['content'].encode()
parts=R/'parts';parts.mkdir(mode=0o700)
part_rows=[];width=128*1024;count=(len(compressed)+width-1)//width
for i,at in enumerate(range(0,len(compressed),width)):
 b=compressed[at:at+width];transport=enc({'schema':'hepta.immutable-zlib-part.v1','ordinal':i,'count':count,'offset':at,'decoded_pin':pin(b),'data':base64.b64encode(b).decode()})
 name=f'parts/PART-{i:03d}.json';(R/name).open('xb').write(transport);part_rows.append({'file':name,'pin':pin(transport)})
manifest={'schema':'hepta.runtime-static-recovery.capsule-manifest.v1','files':[ {k:x[k] for k in ('file','mode','pin')} for x in files],'logical_files':len(files),'logical_bytes':sum(x['pin']['bytes'] for x in files),'decoded_json_pin':pin(raw),'zlib_pin':pin(compressed),'parts':part_rows,'zip_and_runtime_payloads_duplicated':False,'product_calls':0}
(R/'CAPSULE-MANIFEST.json').open('xb').write(enc(manifest))
report={'schema':'hepta.runtime-static-recovery.local-capsule-readback.v1','status':'PASS_EXACT_TEXT_AND_MODE_INVERSE','logical_files':len(files),'logical_bytes':manifest['logical_bytes'],'decoded_json_pin':pin(raw),'zlib_pin':pin(compressed),'parts':len(part_rows),'binary_execution':False,'product_calls':0}
(R/'LOCAL-CAPSULE-READBACK.json').open('xb').write(enc(report))
print(json.dumps({'files':len(files),'logical_bytes':manifest['logical_bytes'],'compressed':pin(compressed),'parts':len(part_rows),'manifest':pin(enc(manifest))},sort_keys=True))
