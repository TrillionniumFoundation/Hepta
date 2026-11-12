from pathlib import Path,PurePosixPath
import hashlib,json,zipfile,tarfile,resource,time,signal,traceback
BASE=Path('/workspace/scratch/9acdfa9f5639');OUT=BASE/'follow57-root-originals/physical56';OUT.mkdir(exist_ok=False)
Z=BASE/'native-checker-development/physical56-originals/original.zip';started=time.monotonic_ns()
resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0));signal.alarm(180)
def budget():assert time.monotonic_ns()-started<180000000000
def pin(p):
 n=p.stat().st_size;h=hashlib.sha256();g=hashlib.sha1(b'blob '+str(n).encode()+b'\0')
 with p.open('rb') as f:
  while b:=f.read(1<<20):h.update(b);g.update(b);budget()
 return {'bytes':n,'sha256':h.hexdigest(),'gitsha':g.hexdigest()}
outer=[];members=0;total=0;failure=None;before=None;ap=None;lp=None
try:
 before=pin(Z);assert before['bytes']==349266299 and before['sha256']=='1a87d8a956cfd165a0e3751064615cc23cd2a23cee09e5d056d582098e6d1229'
 prefix='hia-implementation-files-r1-recovery/';retain={'evidence.tar.xz','evidence-members.jsonl','custody.json','evidence-seal-process.json','summary.json'};seen=set()
 with zipfile.ZipFile(Z) as z:
  for m in z.infolist():
   assert not m.is_dir() and m.filename not in seen;seen.add(m.filename)
   p=PurePosixPath(m.filename);assert not p.is_absolute() and '..' not in p.parts
   local=OUT/m.filename[len(prefix):] if m.filename.startswith(prefix) and m.filename[len(prefix):] in retain else None
   writer=local.open('xb') if local else None;n=0;h=hashlib.sha256();g=hashlib.sha1(b'blob '+str(m.file_size).encode()+b'\0')
   try:
    with z.open(m) as f:
     while b:=f.read(1<<20):
      h.update(b);g.update(b);n+=len(b)
      if writer:writer.write(b)
      budget()
   finally:
    if writer:writer.close()
   assert n==m.file_size;outer.append({'path':m.filename,'bytes':n,'sha256':h.hexdigest(),'gitsha':g.hexdigest(),'mode':m.external_attr>>16,'zip_crc':m.CRC})
 assert len(outer)==1348 and sum(r['bytes'] for r in outer)==348728823
 (OUT/'outer-members.json').write_text(json.dumps(outer,indent=2)+'\n')
 custody=json.loads((OUT/'custody.json').read_bytes());ap=pin(OUT/'evidence.tar.xz');lp=pin(OUT/'evidence-members.jsonl')
 assert ap['bytes']==199377588 and ap['sha256']=='4a91beb491c2ae15c50fbace1467954ef6869fe277e04e255686cd15bd5ff13d' and ap['bytes']==custody['bytes'] and ap['sha256']==custody['sha256']
 assert lp['bytes']==85270025 and lp['sha256']=='f28fc1fea0bcf8cc33f67d6595708c8f824a4f0d60e7cd5f79c4fd96c80871e2' and lp['sha256']==custody['member_index_sha256']
 expected={}
 with (OUT/'evidence-members.jsonl').open('rb') as f:
  for line in f:
   r=json.loads(line);assert r['name'] not in expected;expected[r['name']]=r
 assert len(expected)==161887;observed=set()
 with tarfile.open(OUT/'evidence.tar.xz','r:xz') as t:
  for m in t:
   assert m.name in expected and m.name not in observed and m.isfile() and not m.issym() and not m.islnk(),m.name
   r=expected[m.name];assert m.mode==r['mode'] and m.size==r['bytes'],m.name
   p=PurePosixPath(m.name);assert not p.is_absolute() and '..' not in p.parts
   h=hashlib.sha256();n=0
   with t.extractfile(m) as f:
    while b:=f.read(1<<20):h.update(b);n+=len(b);budget()
   assert n==m.size and h.hexdigest()==r['sha256'],m.name
   observed.add(m.name);members+=1;total+=n;t.members.clear()
 assert observed==set(expected) and members==custody['members'] and total==custody['original_bytes']==1119637158
 assert pin(Z)==before and pin(OUT/'evidence.tar.xz')==ap and pin(OUT/'evidence-members.jsonl')==lp
except BaseException as exc:failure={'class':type(exc).__name__,'error':str(exc),'traceback':traceback.format_exc()}
u=resource.getrusage(resource.RUSAGE_SELF);cpu=u.ru_utime+u.ru_stime;wall=time.monotonic_ns()-started
if not failure and not(cpu<90 and wall<180000000000):failure={'class':'FinalBudget','CPU_seconds':cpu,'elapsed_ns':wall}
report={'schema':'hia-root-follow56-physical-full-original-readback-r1','status':'FAIL' if failure else 'PASS','failure':failure,'run':43276498118,'job':131386199051,'artifact':13971147766,'outer_archive':before,'outer_members':len(outer),'outer_raw_bytes':sum(r['bytes'] for r in outer),'inner_archive':ap,'member_index':lp,'inner_members':members,'inner_raw_bytes':total,'all_member_bytes_mode_SHA_checked':failure is None,'all_originals_after_checked':failure is None,'aggregate_CPU_seconds':cpu,'elapsed_ns':wall,'target_executions':0,'scope':'Full original evidence byte readback; actual fresh target execution remains the separately recorded Ubuntu job.'}
(OUT/'root-full-readback.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,sort_keys=True),flush=True)
if failure:raise SystemExit(1)
