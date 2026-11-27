import base64,hashlib,json,stat,zlib
from pathlib import Path
ROOT=Path('/workspace/scratch/dda74a4fae35')
BASE=ROOT/'v133-own-cache-retirement-r1'
OUT=ROOT/'v95-audit-mount-r1/v140-progress'
NAMES=['DELETIONS.jsonl','INTENT.json','RESULT.json','VERIFIED.json','retire_verified_caches.py','stderr.log','stdout.log']
def enc(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def stats(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode)
 return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')]
assert sorted(p.name for p in BASE.iterdir() if p.is_file())==sorted(NAMES)
records=[]
for name in NAMES:
 p=BASE/name;before=stats(p);raw=p.read_bytes();assert stats(p)==before
 records.append({'path':p.relative_to(ROOT).as_posix(),'posix_mode':stat.S_IMODE(before[2]),'pin':pin(raw),'base64':base64.b64encode(raw).decode(),'stat':before})
assert sum(r['pin']['bytes'] for r in records)==1803856 and len(records)==7
assert next(r for r in records if r['path'].endswith('/RESULT.json'))['pin']['git_blob']=='4b9897dc4896174a0e0dd6eacd95e6f202cb7559'
assert next(r for r in records if r['path'].endswith('/VERIFIED.json'))['pin']['git_blob']=='b4f5dcf2c153e2f4b43953108e4fd3486e9f583f'
payload=enc({'schema':'hepta.complete-original-records.v1','files':records})
capsule=enc({'schema':'hepta.zlib-complete-original-records.v1','encoding':'base64(zlib(utf8-json))','payload_pin':pin(payload),'file_count':7,'original_bytes':1803856,'data':base64.b64encode(zlib.compress(payload,9)).decode()})
actual_payload=zlib.decompress(base64.b64decode(json.loads(capsule)['data'],validate=True))
assert actual_payload==payload and pin(actual_payload)==pin(payload)
decoded=json.loads(actual_payload);assert decoded['files']==records
for row in decoded['files']:
 p=ROOT/row['path'];raw=base64.b64decode(row['base64'],validate=True)
 assert raw==p.read_bytes() and pin(raw)==row['pin'] and stats(p)==row['stat']
index=enc({'schema':'hepta.root-own-cache-retirement-custody.v1','status':'FULL_SEVEN_ORIGINAL_FILES_BYTES_MODES_ROUNDTRIP_PASS','capsule_pin':pin(capsule),'files':[{k:v for k,v in r.items() if k!='base64'} for r in records],'source_records_unchanged':True,'new_deletions':0,'new_product_execution':False,'whole_native':False,'production_legacy_retired':False})
result=[]
for name,raw in [('OWN-CACHE-RECORDS.zlib.json',capsule),('OWN-CACHE-RECORDS-INDEX.json',index)]:
 p=OUT/name
 with p.open('xb') as f:f.write(raw)
 result.append({'name':name,'local_path':str(p),**pin(raw)})
print(json.dumps(result))
