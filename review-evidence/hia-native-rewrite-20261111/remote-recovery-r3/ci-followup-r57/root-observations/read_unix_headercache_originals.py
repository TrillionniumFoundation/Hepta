from pathlib import Path,PurePosixPath
import hashlib,json,lzma,resource,signal,tarfile,time,traceback
BASE=Path('/workspace/scratch/9acdfa9f5639');S=BASE/'runtime-development/header-cache-complete-r1';OUT=BASE/'follow57-root-originals/unix-headercache';OUT.mkdir(exist_ok=False)
A=S/'complete-header-cache-evidence-dict8-r2.tar.xz';I=S/'members.json';started=time.monotonic_ns();resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CORE,(0,0));signal.alarm(180)
def budget():assert time.monotonic_ns()-started<180000000000
def pin(p):
 b=p.read_bytes();return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'gitsha':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
ap=pin(A);ip=pin(I);assert ap=={'bytes':3927276,'sha256':'a15de74bcc4e5e58f8fdd56d7502e5b3a65b636cd23c7ca0747d6b6e9c4a60e4','gitsha':'50d67ece62f943617db1a3696865cbc773aeb8b3'}
assert ip=={'bytes':4145224,'sha256':'1532e7106f520f889862316da0e1dd035ffd952e32958bdfad21422cab288c3b','gitsha':'854a137d2164884f9dbfe3f35d2f662239c79c55'}
members=total=0;failure=None;stream_bytes=0;stream_sha=None
try:
 expected={r['path']:r for r in json.loads(I.read_bytes())};assert len(expected)==8848;seen=set()
 with tarfile.open(A,'r:xz') as t:
  for m in t:
   assert m.isfile() and not m.issym() and not m.islnk() and m.name not in seen and m.name in expected,m.name
   p=PurePosixPath(m.name);assert not p.is_absolute() and '..' not in p.parts
   r=expected[m.name];assert m.size==r['bytes'] and m.mode==r['mode'],m.name
   n=0;h=hashlib.sha256();g=hashlib.sha1(b'blob '+str(m.size).encode()+b'\0')
   with t.extractfile(m) as f:
    while b:=f.read(1<<20):n+=len(b);h.update(b);g.update(b);budget()
   assert n==r['bytes'] and h.hexdigest()==r['sha256'] and g.hexdigest()==r['gitsha'],m.name
   members+=1;total+=n;seen.add(m.name);t.members.clear()
 assert seen==set(expected) and members==8848 and total==444807153
 h=hashlib.sha256()
 with lzma.open(A,'rb') as f:
  while b:=f.read(1<<20):stream_bytes+=len(b);h.update(b);budget()
 stream_sha=h.hexdigest();assert stream_bytes==453724160 and stream_sha=='e779ddf82a9fbdc5535ae232abb16ece1f039299cd0334b5de2089075b0e71cb'
 assert pin(A)==ap and pin(I)==ip
except BaseException as exc:failure={'class':type(exc).__name__,'error':str(exc),'traceback':traceback.format_exc()}
u=resource.getrusage(resource.RUSAGE_SELF);cpu=u.ru_utime+u.ru_stime;wall=time.monotonic_ns()-started
if failure is None and not(cpu<90 and wall<180000000000):failure={'class':'FinalBudget','CPU_seconds':cpu,'elapsed_ns':wall}
result={'schema':'hia-root-Unix-headercache-complete-original-readback-r1','status':'FAIL' if failure else 'PASS','failure':failure,'archive':ap,'member_index':ip,'members':members,'raw_bytes':total,'complete_tar_stream_bytes':stream_bytes,'complete_tar_stream_sha256':stream_sha,'all_original_members_bytes_mode_SHA_Git_checked':failure is None,'archive_and_index_after_equal':failure is None,'root_transport_binding':'Archive reconstructed from10 full-GET Git base64 parts; index reconstructed from11 separate full-GET Git base64 parts. Local complete files independently matched whole bytes/SHA/Git before this member read. No direct binary or 4MiB index GET is claimed.','aggregate_CPU_seconds':cpu,'elapsed_ns':wall,'target_executions':0,'qualification':'Readback only; local target results remain distinct from fresh Ubuntu qualification.'}
(OUT/'root-full-readback.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,sort_keys=True),flush=True)
if failure:raise SystemExit(1)
