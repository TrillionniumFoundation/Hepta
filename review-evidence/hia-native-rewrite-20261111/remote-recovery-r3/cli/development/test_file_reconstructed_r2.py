"""New reconstruction actual-image differential; no lost-run qualification."""
from pathlib import Path
from hashlib import sha256
import ctypes as C, json, os, struct, sys, zlib, traceback, random, errno, stat, socket, resource
BASE=Path('/var/tmp/hia9acdfa-native-resume-a3c61136-20261111')
PROJECT=BASE/'cli-recovery/workspace/native-hia-cli-next'
sys.path.insert(0,str(BASE/'source'));sys.dont_write_bytecode=True
from hepta.hia_json_preflight_native import NativeHiaJsonImage
import hepta.hia_program_tools as reference
assert sys.version_info[:3]==(3,12,14)
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
MANIFEST=PROJECT/'development/file-reconstructed-compile-r2/cli-file.manifest.json'
OUT=PROJECT/'development/file-reconstructed-native-r2'
OUT.mkdir(exist_ok=False);(OUT/'cas').mkdir();(OUT/'fixtures').mkdir()
mraw=MANIFEST.read_bytes();m=json.loads(mraw);sp=Path(m['source']);ip=Path(m['image'])
sraw=sp.read_bytes();iraw=ip.read_bytes()
assert sha256(sraw).hexdigest()==m['source_sha256'] and sha256(iraw).hexdigest()==m['image_sha256']
pins={str(p):sha256(raw).hexdigest() for p,raw in [(MANIFEST,mraw),(sp,sraw),(ip,iraw),(Path(__file__),Path(__file__).read_bytes()),(Path(reference.__file__),Path(reference.__file__).read_bytes())]}
(OUT/'source-before.json').write_text(json.dumps(pins,sort_keys=True,indent=2)+'\n')
native=NativeHiaJsonImage(iraw,expected_sha256=m['image_sha256'])
MAG=lambda v:int.from_bytes(v,'little')
COMMAND=MAG(b'HIAFRB01');ACK=MAG(b'HIAFRA01');EVENT=MAG(b'HIACRE01')
BAD=0xfffffffd;GROW=0xfffffffe;MASK=(1<<64)-1;GUARD=b'F'*32
entries=0;cases=[];snapshots={};ledger=(OUT/'entries.jsonl').open('w');syscalls=(OUT/'syscalls.jsonl').open('w')
reference_read=reference.read_bounded
def disabled(*a,**kw):raise AssertionError('host read_bounded invoked during native execution')
def cas(raw):
 raw=bytes(raw);h=sha256(raw).hexdigest();p=OUT/'cas'/(h+'.zlib')
 if not p.exists():p.write_bytes(zlib.compress(raw,6))
 assert zlib.decompress(p.read_bytes())==raw
 return dict(sha256=h,bytes=len(raw),compression='zlib',path='cas/'+p.name)
def invoke(source,reply,work,label):
 global entries
 a=C.create_string_buffer(source+GUARD);b=C.create_string_buffer(reply+GUARD);w=C.create_string_buffer(bytes(work)+GUARD)
 record=dict(entry=entries+1,label=label,input=cas(source),reply=cas(reply),workspace_before=cas(work),state='ENTER')
 ledger.write(json.dumps(record,sort_keys=True)+'\n');ledger.flush();entries+=1
 old=reference.read_bounded;reference.read_bounded=disabled
 try:ret=int(native._entry(C.addressof(a),len(source),C.addressof(b),len(reply),C.addressof(w),len(work)))
 finally:reference.read_bounded=old
 assert a.raw[:len(source)]==source and b.raw[:len(reply)]==reply
 assert a.raw[len(source):len(source)+32]==b.raw[len(reply):len(reply)+32]==w.raw[len(work):len(work)+32]==GUARD
 after=w.raw[:len(work)]
 record.update(state='RETURN',ret=ret,workspace_after=cas(after),input_after=cas(a.raw[:len(source)]),reply_after=cas(b.raw[:len(reply)]))
 ledger.write(json.dumps(record,sort_keys=True)+'\n');ledger.flush()
 return ret,after
def packet(path,limit=64,lease=17,sequence=1):
 raw=path.encode('utf-8','surrogatepass')
 return struct.pack('<8Q',COMMAND,1,lease,sequence,limit,len(raw),64,64+len(raw))+raw
def answer(e,status=0,result=0,result2=0,error=0,payload=b''):
 return struct.pack('<12Q',ACK,e[2],e[3],e[1],status,result,result2,error,len(payload),96+len(payload),0,0)+payload
def outcome(e,w):
 error=e[9]
 if error==0:return dict(ok=True,payload=cas(w[e[12]:e[12]+e[13]]))
 classes={1:'HIAEditRejected',2:'HIAEditRejected',3:'HIAEditRejected',4:'ValueError',5:'UnicodeEncodeError',6:'TypeError'}
 result=dict(ok=False,exception=classes[error],text=w[e[10]:e[10]+e[11]].decode('utf-8'),cause=None)
 if e[15]:
  cause=OSError(e[15],os.strerror(e[15]));result['cause']=dict(exception=type(cause).__name__,errno=cause.errno)
 return result
def oracle(path,limit,hook=None):
 # Reference fdopen(int) construction can leave the int fd open on rejection.
 # Test isolation closes only descriptors newly created by this oracle call.
 old=reference.os.fstat;before=set()
 for name in os.listdir('/proc/self/fd'):
  try:old(int(name));before.add(name)
  except OSError:pass
 def observed(fd):
  info=old(fd)
  if hook:hook(fd,info)
  return info
 if hook:reference.os.fstat=observed
 try:
  try:result=dict(ok=True,payload=cas(reference_read(path,limit=limit)))
  except Exception as exc:
   result=dict(ok=False,exception=type(exc).__name__,text=str(exc),cause=None)
   if exc.__cause__ is not None:result['cause']=dict(exception=type(exc.__cause__).__name__,errno=getattr(exc.__cause__,'errno',None))
 finally:
  reference.os.fstat=old
  leaked=[]
  for name in set(os.listdir('/proc/self/fd'))-before:
   fd=int(name)
   try:old(fd)
   except OSError:continue
   leaked.append(fd);os.close(fd)
 return result,leaked
def run(path,limit,label,hook=None):
 source=packet(path,limit);reply=b'';w=bytes(1024);fd=None;opened_count=0;closed_count=0;stats=0;calls=0
 trace=[]
 try:
  while True:
   before=w;ret,w=invoke(source,reply,w,label);calls+=1;assert calls<200
   e=struct.unpack_from('<16Q',w,256);assert e[0]==EVENT
   if e[1]==1:
    assert ret==GROW and e[14]>len(w)
    if struct.unpack_from('<Q',w,16)[0]==7 and 'stat-grow' not in snapshots:snapshots['stat-grow']=(source,reply,w,e)
    w+=bytes(e[14]-len(w));continue
   assert ret==128,(label,ret,e)
   if e[1]==0:
    assert fd is None and opened_count==closed_count
    got=outcome(e,w);return got,dict(calls=calls,opens=opened_count,closes=closed_count,trace=trace,final=cas(w))
   action=e[1];assert action in (2,3,4,5) and e[4]==1
   key={2:'open',3:'stat',4:'read',5:'close'}[action]
   if key not in snapshots:snapshots[key]=(source,reply,w,e)
   if action==3 and struct.unpack_from('<Q',w,200)[0]==0 and 'stat-body' not in snapshots:snapshots['stat-body']=(source,reply,w,e)
   record=dict(label=label,action=action,sequence=e[3],request=e)
   try:
    if action==2:
     assert fd is None and w[e[5]+e[6]]==0
     rawpath=w[e[5]:e[5]+e[6]];record['path']=cas(rawpath)
     fd=os.open(rawpath,e[7]);opened_count+=1
     reply=answer(e,result=1)
    elif action==3:
     assert fd is not None;info=os.fstat(fd);stats+=1
     reply=answer(e,result=info.st_mode,result2=info.st_size&MASK)
     if stats==2 and hook:hook(fd,info)
    elif action==4:
     assert fd is not None;payload=os.read(fd,e[8]);reply=answer(e,result=len(payload),payload=payload)
    else:
     assert fd is not None;closing=fd;fd=None;closed_count+=1;os.close(closing);reply=answer(e)
   except OSError as exc:reply=answer(e,status=1,error=exc.errno)
   record['reply']=cas(reply);syscalls.write(json.dumps(record,sort_keys=True)+'\n');syscalls.flush();trace.append(record)
 finally:
  if fd is not None:os.close(fd)
def compare(path,limit,label,prepare=None,hook=None):
 if prepare:prepare()
 want,leaked=oracle(path,limit,hook)
 if prepare:prepare()
 got,stats=run(path,limit,label,hook)
 assert got==want,(label,got,want)
 cases.append(dict(label=label,scope='REAL_FILESYSTEM_ORACLE',path=cas(path.encode('utf-8','surrogatepass')),limit=limit,outcome=got,reference_constructor_unowned_fds_closed_for_test=leaked,actual=stats))

def boot(label,path='private',limit=8):
 s=packet(path,limit);r=b'';w=bytes(1024)
 while True:
  ret,w=invoke(s,r,w,label)
  e=struct.unpack_from('<16Q',w,256)
  if ret==GROW:
   assert e[1]==1 and e[14]>len(w);w+=bytes(e[14]-len(w));continue
  assert ret==128 and e[1]==2
  return s,r,w,e
def poison(label,source,reply,work):
 ret,w=invoke(source,reply,work,label);assert ret==BAD,(label,ret)
 ret,w=invoke(source,reply,w,label+'-replay');assert ret==BAD
 ret,w=invoke(packet('other',8,lease=18),b'',w,label+'-new-source');assert ret==BAD
 cases.append(dict(label=label,scope='PRIVATE_PROTOCOL_PERMANENT_REFUSAL'))
def scripted(label,overrides,expected,limit=8):
 s=packet('private',limit);r=b'';w=bytes(1024);counts={};ops=[]
 while True:
  ret,w=invoke(s,r,w,label);e=struct.unpack_from('<16Q',w,256)
  if ret==GROW:
   assert e[1]==1 and e[14]>len(w);w+=bytes(e[14]-len(w));continue
  assert ret==128,(label,ret,e)
  if e[1]==0:
   got=outcome(e,w);assert got==expected,(label,got,expected)
   cases.append(dict(label=label,scope='PRIVATE_PRIMITIVE_ACK_OUTCOME',outcome=got,actions=ops));return counts
  a=e[1];counts[a]=counts.get(a,0)+1;ops.append(a);assert len(ops)<40
  fields=overrides.get((a,counts[a]))
  if fields is None:
   fields={2:dict(result=1),3:dict(result=stat.S_IFREG|0o600,result2=0),4:dict(result=0,payload=b''),5:{}}[a]
  r=answer(e,**fields)
def err(kind,text,number=None):
 value=dict(ok=False,exception=kind,text=text,cause=None)
 if number:
  e=OSError(number,os.strerror(number));value['cause']=dict(exception=type(e).__name__,errno=number)
 return value
try:
 fixtures=OUT/'fixtures';empty=fixtures/'empty';empty.write_bytes(b'')
 normal=fixtures/'ordinary';normal.write_bytes(b'hello\x00world')
 for limit in (0,1,10,11,12,64,1048576,8388608):
  compare(str(empty),limit,'empty-'+str(limit))
  compare(str(normal),limit,'ordinary-'+str(limit))
 for path,label in [('', 'empty-path'),('.', 'dot-path'),('/', 'root-path'),('//', 'double-root'),('///', 'triple-root'),(str(fixtures/'absent'),'missing'),(str(normal)+'/x','not-directory'),('/dev/null','special-file')]:
  compare(path,64,label)
 directory=fixtures/'directory';directory.mkdir();fifo=fixtures/'fifo';os.mkfifo(fifo)
 link=fixtures/'link';link.symlink_to(normal);parentlink=fixtures/'parent-link';parentlink.symlink_to(directory,target_is_directory=True)
 inside=directory/'inside';inside.write_bytes(b'inside')
 hard=fixtures/'hard';os.link(normal,hard)
 for path,label in [(directory,'directory'),(fifo,'fifo'),(link,'final-symlink'),(parentlink/'inside','parent-symlink'),(hard,'hard-link')]:
  compare(str(path),64,label)
 for variant in [str(fixtures)+'/./ordinary',str(fixtures)+'//ordinary/',str(fixtures)+'/.//./ordinary/.',str(fixtures)+'/directory/../ordinary','//'+str(normal).lstrip('/'),'///'+str(normal).lstrip('/')]:
  compare(variant,64,'normalized-'+str(len(cases)))
 denied=fixtures/'no-permission';denied.write_bytes(b'x');denied.chmod(0)
 compare(str(denied),64,'actual-permissions');denied.chmod(0o600)
 for i,name in enumerate(['中','é','😀','a\nb','quote\"','back\\slash',os.fsdecode(b'bad-\xff-\x80')]):
  target=fixtures/name;target.write_bytes(bytes([i])*17);compare(str(target),17,'unicode-path-'+str(i))
 specials=['\x00','a\x00b','\ud800','\udfff','\udc7f','\udc80','\udcff','\ud800\udc80','\udc80\ud800','\udc80\ud800\udc81','a\udfff\ud800b','\x00\ud800','\ud800\x00','.././\ud800','//./\udc80\ud800']
 for i,path in enumerate(specials):compare(path,64,'surrogate-or-nul-'+str(i))
 compare(str(fixtures)+'/'+'x'*5000,64,'long-filename')
 rng=random.Random(0xC11F11E)
 for i in range(100):
  name='case-%03d'%i;path=fixtures/name;value=rng.randbytes(rng.randrange(0,300));path.write_bytes(value)
  limit=rng.choice([0,1,max(0,len(value)-1),len(value),len(value)+1,512])
  variant=str(path)
  if i%4==0:variant=str(fixtures)+'//./'+name+'/.'
  if i%4==1:variant='//'+variant.lstrip('/')
  compare(variant,limit,'random-'+str(i))
 growing_file=fixtures/'growing'
 def prepare_growth():growing_file.write_bytes(b'a')
 def add_after_stat(fd,info):growing_file.write_bytes(b'ab')
 compare(str(growing_file),1,'growth-after-stat',prepare_growth,add_after_stat)
 closed_file=fixtures/'externally-closed'
 closed_file.write_bytes(b'x')
 def close_after_stat(fd,info):os.close(fd)
 compare(str(closed_file),64,'closed-after-stat',hook=close_after_stat)
 large=fixtures/'eight-mib';large.write_bytes(b'z'*8388608);compare(str(large),8388608,'actual-eight-mib')
 large.write_bytes(b'z'*8388609);compare(str(large),8388608,'actual-eight-mib-plus-one')
 
 success=dict(ok=True,payload=cas(b''))
 generic=lambda n:err('HIAEditRejected','E_HIA_EDIT: cannot read ordinary input',n)
 script_cases=[
 ('open-eintr',{(2,1):dict(status=1,error=4)},success),
 ('initial-stat-eintr-ignored',{(3,1):dict(status=1,error=4)},success),
 ('initial-stat-other-ignored',{(3,1):dict(status=1,error=22)},success),
 ('body-stat-eintr',{(3,2):dict(status=1,error=4)},generic(4)),
 ('initial-dir-cleanup-error-preserves',{(3,1):dict(result=stat.S_IFDIR,result2=0),(5,1):dict(status=1,error=5)},generic(21)),
 ('initial-badfd-cleanup-error-preserves',{(3,1):dict(status=1,error=9),(5,1):dict(status=1,error=5)},generic(9)),
 ('body-nonregular-close-overrides',{(3,2):dict(result=stat.S_IFIFO,result2=0),(5,1):dict(status=1,error=5)},generic(5)),
 ('read-eintr',{(4,1):dict(status=1,error=4)},success),
 ('read-error-close-overrides',{(4,1):dict(status=1,error=5),(5,1):dict(status=1,error=9)},generic(9)),
 ('close-eintr-no-retry',{(5,1):dict(status=1,error=4)},generic(4)),
 ('would-block-no-data',{(4,1):dict(status=1,error=11)},err('TypeError',"object of type 'NoneType' has no len()")),
 ('would-block-partial',{(4,1):dict(result=2,payload=b'ab'),(4,2):dict(status=1,error=11)},dict(ok=True,payload=cas(b'ab'))),
 ('negative-stat-size',{(3,2):dict(result=stat.S_IFREG,result2=MASK)},success),
 ('late-byte-limit-close-overrides',{(4,1):dict(result=9,payload=b'123456789'),(5,1):dict(status=1,error=5)},generic(5)),
 ('late-byte-limit',{(4,1):dict(result=9,payload=b'123456789')},err('HIAEditRejected','E_HIA_EDIT: input exceeds byte limit'))
 ]
 for label,changes,expected in script_cases:
  count=scripted(label,changes,expected)
  if label=='close-eintr-no-retry':assert count[5]==1
  if label=='body-stat-eintr':assert count[3]==2
 s,r,w,e=boot('private-base')
 good=answer(e,result=1)
 for at,value in [(0,0),(8,18),(16,e[3]+1),(24,3),(32,2),(40,2),(48,1),(56,1),(64,1),(72,95),(80,1),(88,1)]:
  bad=bytearray(good);struct.pack_into('<Q',bad,at,value);poison('bad-open-ack-'+str(at),s,bytes(bad),w)
 for label,bad in [('truncated',good[:-1]),('extra',good+b'0'),('error-no-errno',answer(e,status=1)),('error-with-result',answer(e,status=1,result=1,error=5))]:
  poison('bad-'+label,s,bad,w)
 for at,value in [(16,5),(80,1),(88,3)]:
  bad=bytearray(w);struct.pack_into('<Q',bad,at,value);poison('bad-private-state-'+str(at),s,good,bytes(bad))
 badsrc=bytearray(s);struct.pack_into('<Q',badsrc,32,9);poison('changed-source-header',bytes(badsrc),good,w)
 ret,after=invoke(s,good,w,'replay-seed');assert ret==128
 poison('replayed-consumed-open',s,good,after)
 gs,gr,gw,ge=snapshots['stat-grow'];expanded=gw+bytes(ge[14]-len(gw))
 for at,value in [(16,1),(40,999),(64,len(expanded)+1),(176,0),(200,1)]:
  bad=bytearray(expanded);struct.pack_into('<Q',bad,at,value);poison('grow-state-'+str(at),gs,gr,bytes(bad))
 bad=bytearray(gr);struct.pack_into('<Q',bad,48,1);poison('grow-reply-changed-size',gs,bytes(bad),expanded)
 grow_error=answer(struct.unpack_from('<16Q',gw,256),status=1,error=5)
 grow_error=bytearray(grow_error);struct.pack_into('<Q',grow_error,24,3)
 poison('grow-reply-changed-to-error',gs,bytes(grow_error),expanded)
 for kind in ('stat','read','close'):
  ss,rr,ww,ee=snapshots[kind]
  bad=answer(ee,result=MASK)
  poison('bad-'+kind+'-result',ss,bad,ww)
 for label,source in [('empty-source',b''),('short-header',s[:63]),('bad-utf8',struct.pack('<8Q',COMMAND,1,17,1,8,1,64,65)+b'\xff')]:
  poison(label,source,b'',bytes(1024))
 result=dict(status='PASS',scope='NEW_RECONSTRUCTION_DEVELOPMENT_ONLY',cases=len(cases),real_filesystem_cases=sum(c['scope']=='REAL_FILESYSTEM_ORACLE' for c in cases),private_primitive_cases=sum(c['scope']=='PRIVATE_PRIMITIVE_ACK_OUTCOME' for c in cases),private_refusal_cases=sum(c['scope']=='PRIVATE_PROTOCOL_PERMANENT_REFUSAL' for c in cases),entries=entries,python=sys.version)
 (OUT/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result,sort_keys=True),flush=True)
except BaseException:
 failure=traceback.format_exc();(OUT/'failure.txt').write_text(failure)
 (OUT/'result.json').write_text(json.dumps(dict(status='FAIL',cases_completed=len(cases),entries=entries,failure=failure),sort_keys=True,indent=2)+'\n');raise
finally:
 ledger.close();syscalls.close();(OUT/'cases-completed.json').write_text(json.dumps(cases,sort_keys=True,indent=2)+'\n')
 after={p:sha256(Path(p).read_bytes()).hexdigest() for p in pins}
 (OUT/'source-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n');assert after==pins
