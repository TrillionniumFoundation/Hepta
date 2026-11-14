import base64,hashlib,json,os,stat,zlib
from pathlib import Path
ROOT=Path('/workspace/scratch/dda74a4fae35/v141-inspect-storage-recovery-r1')
AUTHOR=Path('/tmp/hia-root-v141-dda7')
OUT=AUTHOR/'storage408-complete-r1'
EXTRA=['verify_storage408_terminal.py','ROOT-STORAGE408-TERMINAL.json','ROOT-STORAGE408-TERMINAL-EXEC.json','ROOT-STORAGE408-PROPOSAL-EXEC.json','AUTHORIZATION-STORAGE408-SOURCE18.json']
def enc(x):return (json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode()
def identity(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),git_blob=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest())
def stamp(s):return dict(device=s.st_dev,inode=s.st_ino,bytes=s.st_size,mode=stat.S_IMODE(s.st_mode),nlink=s.st_nlink,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns)
def read(p):
 before=p.lstat();assert stat.S_ISREG(before.st_mode)
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  assert stamp(os.fstat(fd))==stamp(before)
  with os.fdopen(fd,'rb',closefd=False) as f:b=f.read()
  assert stamp(os.fstat(fd))==stamp(before)==stamp(p.lstat())
 finally:os.close(fd)
 assert len(b)==before.st_size
 return b,stamp(before)
def write(p,b):
 with p.open('xb') as f:f.write(b)
OUT.mkdir(mode=0o700)
files=[];dirs=[];objects={};sources={}
for folder,children,names in os.walk(ROOT,followlinks=False):
 d=Path(folder);s=d.lstat();assert stat.S_ISDIR(s.st_mode)
 rel=d.relative_to(ROOT).as_posix()
 dirs.append(dict(path='original' if rel=='.' else 'original/'+rel,original_path=str(d),stat=stamp(s)))
 for name in children:assert stat.S_ISDIR((d/name).lstat().st_mode)
 for name in sorted(names):
  p=d/name;b,s=read(p);i=identity(b);key=i['sha256'];objects.setdefault(key,base64.b64encode(b).decode());sources[str(p)]=b
  files.append(dict(path='original/'+p.relative_to(ROOT).as_posix(),original_path=str(p),identity=i,stat=s,object=key))
for name in EXTRA:
 p=AUTHOR/name;b,s=read(p);i=identity(b);key=i['sha256'];objects.setdefault(key,base64.b64encode(b).decode());sources[str(p)]=b
 files.append(dict(path='root/'+name,original_path=str(p),identity=i,stat=s,object=key))
files.sort(key=lambda x:x['path']);dirs.sort(key=lambda x:x['path'])
payload=dict(schema='hepta.complete-authoring-and-actual-files.v1',scope='Exact 408-file archival retirement authoring and complete actual evidence plus named Root checks',files=files,directories=dirs,objects=objects,product_source_or_runtime_contents_included=False)
raw=enc(payload)
capsule=enc(dict(schema='hepta.complete-files-capsule.v1',codec='zlib9-base64',payload=identity(raw),files=len(files),directories=len(dirs),logical_bytes=sum(x['identity']['bytes'] for x in files),unique_objects=len(objects),data=base64.b64encode(zlib.compress(raw,9)).decode()))
write(OUT/'CAPSULE.json',capsule)
c=json.loads(capsule);packed=base64.b64decode(c['data'],validate=True);de=zlib.decompressobj();restored=de.decompress(packed)+de.flush()
assert de.eof and not de.unused_data and not de.unconsumed_tail and restored==raw and identity(restored)==c['payload']
decoded=json.loads(restored);assert enc(decoded)==raw
assert decoded['files']==files and decoded['directories']==dirs and decoded['objects']==objects
for row in files:
 b=base64.b64decode(objects[row['object']],validate=True);assert identity(b)==row['identity']
 actual,st=read(Path(row['original_path']));assert b==actual==sources[row['original_path']] and st==row['stat']
for row in dirs:assert stamp(Path(row['original_path']).lstat())==row['stat']
part_rows=[];extent=196608
for index,offset in enumerate(range(0,len(capsule),extent)):
 span=capsule[offset:offset+extent];name=f'part-{index:03d}.json'
 wrapped=enc(dict(schema='hepta.complete-capsule-byte-span.v1',index=index,offset=offset,span=identity(span),capsule=identity(capsule),base64=base64.b64encode(span).decode()))
 write(OUT/name,wrapped);part_rows.append(dict(name=name,identity=identity(wrapped),span=identity(span),offset=offset))
joined=b''.join(base64.b64decode(json.loads((OUT/r['name']).read_bytes())['base64'],validate=True) for r in part_rows)
assert joined==capsule
manifest=dict(schema='hepta.storage408-complete-custody-manifest.v1',capsule=identity(capsule),files=files,directories=dirs,logical_bytes=c['logical_bytes'],unique_objects=len(objects),parts=part_rows,all_actual_scope_nodes_included=True,source_runtime_archive_contents_not_duplicated=True)
write(OUT/'MANIFEST.json',enc(manifest))
readback=dict(schema='hepta.storage408-complete-custody-readback.v1',status='ALL_ORIGINAL_BYTES_MODES_SEVEN_STATS_AND_CAPSULE_PARTS_ROUNDTRIP_PASS',files=len(files),directories=len(dirs),logical_bytes=c['logical_bytes'],unique_objects=len(objects),capsule=identity(capsule),parts=len(part_rows),new_deletions=0,new_products=0)
write(OUT/'READBACK.json',enc(readback));write(OUT/'PARTS.json',enc(part_rows))
print(json.dumps(readback,sort_keys=True))
