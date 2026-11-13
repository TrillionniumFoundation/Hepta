"""Create a lossless archive from an already-audited explicit file inventory.
No project imports, qualification, C build, VM, native entry, or SQL.
This packages either PASS or HOLD evidence without reclassifying it.
"""
from pathlib import Path
import base64, gzip, hashlib, io, json, os, stat, tarfile
ROOT=Path(__file__).resolve().parent
def identity(s):
 return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def digest(raw):
 return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob_sha1':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def read(path,maximum=128<<20):
 p=Path(path);assert p.is_absolute() and p.resolve(strict=True)==p
 old=p.lstat();assert stat.S_ISREG(old.st_mode) and old.st_nlink==1 and old.st_size<=maximum
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as stream:
  assert identity(os.fstat(stream.fileno()))==identity(old)
  raw=stream.read();assert identity(os.fstat(stream.fileno()))==identity(old)
 assert len(raw)==old.st_size and identity(p.lstat())==identity(old)
 return raw,{'path':str(p),**digest(raw),'identity':identity(old)}
def create(path,raw):
 path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('xb') as stream:
  assert stream.write(raw)==len(raw);stream.flush();os.fsync(stream.fileno())
 os.chmod(path,0o400);body,pin=read(path);assert body==raw;return pin
def wire(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def main():
 config_raw,config_pin=read(ROOT/'PACKAGE-INPUTS.json')
 config=json.loads(config_raw)
 assert config['schema']=='hia.sqlite-btree-cell.source12-package-inputs.v1'
 assert config['qualification_repeated'] is False
 assert config['qualification_owner_closed'] is True
 assert config['r1_owner_or_VM_started'] is False
 assert config['source12_actual_runs']==1
 payload={}
 for row in config['files']:
  name=row['name'];assert name not in payload and not name.startswith('/') and '..' not in Path(name).parts
  raw,pin=read(row['path'])
  for key in ('path','bytes','sha256','git_blob_sha1','identity'):assert pin[key]==row[key],(name,key)
  payload[name]=(raw,pin)
 assert len(payload)==config['original_count']
 buffer=io.BytesIO()
 with tarfile.open(fileobj=buffer,mode='w',format=tarfile.USTAR_FORMAT) as archive:
  for name,(raw,pin) in sorted(payload.items()):
   member=tarfile.TarInfo(name);member.size=len(raw);member.mode=stat.S_IMODE(pin['identity'][2])
   member.mtime=0;member.uid=member.gid=0;member.uname=member.gname=''
   archive.addfile(member,io.BytesIO(raw))
 tar=buffer.getvalue();packed=gzip.compress(tar,compresslevel=6,mtime=0)
 packed_pin=create(ROOT/'originals.tar.gz',packed)
 restored=gzip.decompress(packed);assert restored==tar
 with tarfile.open(fileobj=io.BytesIO(restored),mode='r:') as archive:
  members=archive.getmembers();assert [m.name for m in members]==sorted(payload)
  for member in members:
   raw,pin=payload[member.name]
   assert member.isfile() and archive.extractfile(member).read()==raw and member.mode==stat.S_IMODE(pin['identity'][2])
 parts=[]
 for n,offset in enumerate(range(0,len(packed),196608)):
  chunk=packed[offset:offset+196608];name='carriers/part-%03d.b64'%n
  pin=create(ROOT/name,base64.b64encode(chunk)+b'\n')
  parts.append({'path':name,'offset':offset,'decoded':digest(chunk),**{k:pin[k] for k in ('bytes','sha256','git_blob_sha1')}})
 assert b''.join(base64.b64decode(read(ROOT/p['path'])[0]) for p in parts)==packed
 mirrors=[]
 for name,(raw,pin) in sorted(payload.items()):
  if name.startswith('source/') or len(raw)>262144:continue
  try:raw.decode('utf-8')
  except UnicodeError:continue
  path='text/'+name;copy=create(ROOT/path,raw)
  mirrors.append({'path':path,**{k:copy[k] for k in ('bytes','sha256','git_blob_sha1')}})
 for name,(raw,pin) in payload.items():
  body,after=read(Path(pin['path']));assert body==raw and after==pin
 manifest={'schema':'hia.sqlite-btree-cell.source12-complete-archive.v1',
  'status':config['actual_status'],'qualification_repeated':False,
  'r1_preexec_failure_preserved':True,'r1_owner_or_VM_started':False,
  'source12_actual_runs':1,'C_native_SQL_runs':0,
  'original_count':len(payload),'original_bytes':sum(len(raw) for raw,pin in payload.values()),
  'originals':[{'name':name,'original_path':pin['path'],**{k:pin[k] for k in ('bytes','sha256','git_blob_sha1','identity')}} for name,(raw,pin) in sorted(payload.items())],
  'archive':{k:packed_pin[k] for k in ('bytes','sha256','git_blob_sha1')},'tar':digest(tar),
  'parts':parts,'text_mirrors':mirrors,'complete_roundtrip':True,
  'original_bytes_and_identities_unchanged_after':True,'package_inputs':config_pin,
  'qualification_scope':config['qualification_scope']}
 result=create(ROOT/'ARCHIVE-MANIFEST.json',wire(manifest))
 print(json.dumps({'manifest':result,'archive':packed_pin,'originals':len(payload),
                   'bytes':manifest['original_bytes'],'parts':len(parts),'text_mirrors':len(mirrors),'qualification_executed':False}))
if __name__=='__main__':main()
