"""Preserve existing unexecuted draft bytes only; never import or execute project code."""
from pathlib import Path
import gzip,hashlib,io,json,os,stat,tarfile
BASE=Path('/home/qq/hia-rewrite-20261113-e26e-r1')
SRC=BASE/'cli-body-ports-r4h-ai395-r1'
OUT=BASE/'cli-body-ports-r4h-readonly-custody-r1'
def ident(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(p):
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  assert ident(os.fstat(fd))==ident(s)
  chunks=[]
  while True:
   b=os.read(fd,1<<20)
   if not b:break
   chunks.append(b)
  raw=b''.join(chunks)
  assert len(raw)==s.st_size and ident(os.fstat(fd))==ident(s)==ident(p.lstat())
 finally:os.close(fd)
 return raw,ident(s)
def pin(p):
 raw,i=read(p)
 return raw,{'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob_sha1':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'identity':i}
def wire(x):return (json.dumps(x,sort_keys=True,indent=2)+'\n').encode()
def create(p,b):
 fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 assert p.read_bytes()==b
receipt_raw,receipt_pin=pin(SRC/'authoring-history/resume-control-r1/WRITE-RECEIPT.json')
assert receipt_pin['bytes']==2006 and receipt_pin['sha256']=='bbbbec0b44e0b3d5c1984e4940eaa5f6b4717962e49c4a8caacb1d78349ed363'
receipt=json.loads(receipt_raw)
assert receipt['status']=='SOURCE_WRITTEN_UNEXECUTED' and len(receipt['files'])==7
assert all(receipt[k] is False for k in ('C_compile','native','source_generation'))
assert receipt['original17']==receipt['traces46']==0
selection=[]
for item in receipt['files']:
 rel=Path(item['path']);assert not rel.is_absolute() and '..' not in rel.parts
 selection.append(('source/'+item['path'],SRC/'source'/rel,item['sha256']))
 if item['old_sha256']:
  selection.append(('authoring-history/resume-control-r1/before/'+item['path'],SRC/'authoring-history/resume-control-r1/before'/rel,item['old_sha256']))
selection.extend([
 ('authoring-history/resume-control-r1/WRITE-RECEIPT.json',SRC/'authoring-history/resume-control-r1/WRITE-RECEIPT.json',receipt_pin['sha256']),
 ('BASELINE.json',SRC/'BASELINE.json','caa513eaa64d3261bfc3c9d85eaadf69fd1ada2802c0fd176e0dd09174a9a509'),
 ('reference/BASELINE-CREATE-SCHEMA-FAILURE.json',SRC/'reference/BASELINE-CREATE-SCHEMA-FAILURE.json','ff12b7cfbc40a6732c46eab41780c631907fd50e02caa7464313b3eee3512c2d'),
 ('reference/CPYTHON-LICENSE.original.txt',BASE/'cpython31214-r1/Python-3.12.14/LICENSE','3b2f81fe21d181c499c59a256c8e1968455d6689d269aa85373bfb6af41da3bf')])
assert len(selection)==17
assert not (SRC/'source/hepta/hia_cli_json_cpython312_for_iter.inc').exists()
assert all(not os.path.lexists(SRC/n) for n in ('REQUEST.json','LAUNCH.json','PREEXEC.json','actual','guardian'))
bodies={};rows=[]
for name,p,sha in selection:
 raw,r=pin(p);assert r['sha256']==sha
 assert name not in bodies
 bodies[name]=raw;rows.append({'archive_path':name,**r})
os.umask(0o077);OUT.mkdir(mode=0o700,exist_ok=False)
manifest={'schema':'hia.cli.resume-control-r4h.passive-snapshot.v1','status':'UNVALIDATED_SOURCE_DRAFT_SYSTEM_REVIEW_INTERRUPTED','source_root':str(SRC),'baseline_request_commit':'a66b7478ad1596384c5aa137aa0b652a79a16cae','baseline_actual_commit':'6b4f7761fb986678cff94a51f52b0efa5a7d7035','written_source_files':7,'before_source_files':6,'originals':rows,'original_files':len(rows),'original_bytes':sum(len(b) for b in bodies.values()),'source_generation':False,'C_compile':False,'native_execution':False,'original17':0,'traces46':0,'FOR_ITER_memory_draft_included':False,'source_modified_by_snapshot':False,'blocking_boundary':'The runtime-port subtask was interrupted by system content review. This is passive preservation of previously written bytes. No interrupted operation was retried.'}
m=wire(manifest);create(OUT/'MANIFEST.json',m)
with (OUT/'ORIGINALS.tar.gz').open('xb') as output:
 with gzip.GzipFile(fileobj=output,mode='wb',mtime=0,filename='',compresslevel=9) as zipped:
  with tarfile.open(fileobj=zipped,mode='w|',format=tarfile.PAX_FORMAT) as tar:
   for row in rows:
    b=bodies[row['archive_path']];t=tarfile.TarInfo(row['archive_path'])
    t.size=len(b);t.mode=stat.S_IMODE(row['identity'][2]);t.uid=row['identity'][3];t.gid=row['identity'][4];t.mtime=0
    tar.addfile(t,io.BytesIO(b))
   t=tarfile.TarInfo('SNAPSHOT-MANIFEST.json');t.size=len(m);t.mode=0o400;tar.addfile(t,io.BytesIO(m))
 output.flush();os.fsync(output.fileno())
seen=set()
with tarfile.open(OUT/'ORIGINALS.tar.gz','r:gz') as tar:
 for t in tar:
  assert t.name not in seen and t.isfile();seen.add(t.name)
  expected=m if t.name=='SNAPSHOT-MANIFEST.json' else bodies[t.name]
  assert tar.extractfile(t).read()==expected
assert seen==set(bodies)|{'SNAPSHOT-MANIFEST.json'}
for row in rows:
 _,after=pin(Path(row['path']))
 assert after=={k:v for k,v in row.items() if k!='archive_path'}
araw,ap=pin(OUT/'ORIGINALS.tar.gz')
summary={**{k:manifest[k] for k in ('status','original_files','original_bytes','written_source_files','before_source_files')},'archive':ap,'manifest':pin(OUT/'MANIFEST.json')[1],'full_inverse_verified':True,'source_generation':False,'C_compile':False,'native_execution':False,'unknown_mutations':[]}
create(OUT/'READBACK.json',wire(summary));print(json.dumps(summary,sort_keys=True))
