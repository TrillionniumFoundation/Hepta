"""Preserve frozen source4 request text only; no project import or execution."""
from __future__ import annotations
import gzip,hashlib,io,json,os,stat,tarfile
from pathlib import Path
ROOT=Path('/home/qq/hia-rewrite-20261113-e26e-r1/pc-dispatch-r1')
names=['source_common.py','source_worker.py','source_launch.py','freeze_source_request.py',
       'SOURCE4-REQUEST.json','SOURCE4-LAUNCH.json','SOURCE4-PREEXEC.json','DEVELOPMENT-NATIVE-NEXT.json',
       'SOURCE-MATERIALIZATION.json','references/generate_hia_core_lowering.before.py',
       'authoring/materialize_source.py','authoring/archive_static_request.py',
       'publication/GIT-READBACK.json','source/tools/hia_selfhost_process_owner.py',
       'source/tests/test_hia_core_lowering_native.py','source/hepta/hia_core_lowering_abi.json',
       'source/examples/hia_bootstrap/core_lowering_pool.hiaasm']
names+=sorted(p.relative_to(ROOT).as_posix() for p in (ROOT/'canonical').rglob('*') if p.is_file())
def sha(b):return hashlib.sha256(b).hexdigest()
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
 s=p.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or p.resolve()!=p:raise RuntimeError('unsafe static input')
 b=p.read_bytes()
 if ident(s)!=ident(p.lstat()):raise RuntimeError('static input changed')
 return b
def write(p,b):
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 if read(p)!=b:raise RuntimeError('write readback')
os.umask(0o077)
if len(names)!=len(set(names)):raise RuntimeError('duplicate archive path')
rows=[];bodies={}
for name in sorted(names):
 b=read(ROOT/name);bodies[name]=b
 rows.append({'path':name,'bytes':len(b),'sha256':sha(b),'git_blob_sha1':hashlib.sha1(('blob '+str(len(b))+'\0').encode()+b).hexdigest()})
out=io.BytesIO()
with gzip.GzipFile(fileobj=out,mode='wb',mtime=0,compresslevel=6) as gz:
 with tarfile.open(fileobj=gz,mode='w',format=tarfile.PAX_FORMAT) as tf:
  for row in rows:
   info=tarfile.TarInfo(row['path']);info.size=row['bytes'];info.mode=0o600;info.mtime=0
   tf.addfile(info,io.BytesIO(bodies[row['path']]))
packed=out.getvalue();write(ROOT/'SOURCE4-STATIC-INPUTS.tar.gz',packed)
with tarfile.open(fileobj=io.BytesIO(packed),mode='r:gz') as tf:
 members=tf.getmembers()
 if [m.name for m in members]!=[r['path'] for r in rows]:raise RuntimeError('archive order')
 for m,row in zip(members,rows):
  if not m.isfile() or m.size!=row['bytes']:raise RuntimeError('archive type')
  b=tf.extractfile(m).read()
  if b!=bodies[row['path']] or sha(b)!=row['sha256']:raise RuntimeError('archive body')
for name,b in bodies.items():
 if read(ROOT/name)!=b:raise RuntimeError('original changed during archive')
report={'schema':'hia.pc-source4.static-request-archive.v1','status':'UNEXECUTED_STATIC_REQUEST_ALL_RAW_READBACK',
        'files':rows,'file_count':len(rows),'raw_bytes':sum(r['bytes'] for r in rows),
        'archive_path':str(ROOT/'SOURCE4-STATIC-INPUTS.tar.gz'),'archive_bytes':len(packed),'archive_sha256':sha(packed),
        'source_snapshot_1711_files_is_pinned_by_manifest_not_duplicated':True,
        'source4_generator_tests_native_executed':False}
raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
write(ROOT/'SOURCE4-STATIC-ARCHIVE.json',raw)
print(json.dumps({'files':len(rows),'raw_bytes':report['raw_bytes'],'archive_bytes':len(packed),'archive_sha256':sha(packed),
                  'manifest_bytes':len(raw),'manifest_sha256':sha(raw)},sort_keys=True))
