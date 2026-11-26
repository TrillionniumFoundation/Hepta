"""Native log framing compared with the unchanged original _run_logged oracle."""
from pathlib import Path
import argparse,copy,ctypes as C,hashlib,json,os,platform,random,struct,sys,traceback
from tools.qualify_hia_multiversion_components import Image
from tools.qualify_hia_result_value_platform import Bound,Engine,Values,sweep
from hepta import hia_program_llvm as original
from hepta.clang_capture import CaptureResult,CaptureFailure,CaptureRejected
MASK=(1<<64)-1
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def capture_frame(argv,timeout=10,stdout_limit=65536,stderr_limit=65536,stdin_limit=1000000):
 out=bytearray(128);out[:8]=b'HIACAP01'
 for at,value in((16,len(argv)),(40,timeout*1000000000),(48,stdout_limit),(56,stderr_limit),(64,stdin_limit)):struct.pack_into('<Q',out,at,value)
 return bytes(out)+b''.join(struct.pack('<Q',len(raw))+raw+b'\0'for raw in map(os.fsencode,argv))
def packet(op,*,frame=b'',cwd=b'',stdout=b'',stderr=b'',out_total=0,err_total=0,known=0,returncode=0,type_name=b'',message=b'',code=b'',capture_error=b'',flags=0):
 raw=bytearray(128);raw[:8]=b'HIALLGQ1'
 values=(op,len(frame),len(cwd),len(stdout),len(stderr),out_total,err_total,known,returncode&MASK,len(type_name),len(message),len(code),len(capture_error),flags,0)
 struct.pack_into('<15Q',raw,8,*values)
 return bytes(raw)+frame+cwd+stdout+stderr+type_name+message+code+capture_error
def text(value):return value.encode('utf-8','surrogatepass')
def result_packet(result):
 out=result.raw_stdout;err=result.raw_stderr;flags=(2 if out is not None else 0)|(4 if err is not None else 0)
 out=text(result.stdout)if out is None else out;err=text(result.stderr)if err is None else err
 return packet(1,stdout=out,stderr=err,out_total=len(out),err_total=len(err),known=1,returncode=result.returncode,flags=flags)
def error_packet(error):
 capture=getattr(error,'capture',None);code=getattr(error,'code',None);secondary=getattr(error,'capture_error',None)
 if code is not None and type(code)is not str:raise TypeError('non-text exception code requires direct strong Value edge, outside capture-text codec')
 kw=dict(type_name=text(type(error).__name__),message=text(str(error)),code=b''if code is None else text(code),
  capture_error=b''if secondary is None else text(secondary),flags=(1 if capture is not None else 0)|(8 if code is not None else 0)|(16 if secondary is not None else 0))
 if capture is not None:
  kw.update(stdout=capture.stdout,stderr=capture.stderr,out_total=capture.stdout_total_bytes,err_total=capture.stderr_total_bytes,
   known=int(capture.returncode is not None),returncode=capture.returncode or 0)
 return packet(2,**kw)
class Codec:
 def __init__(self,path):self.image=Image(path);self.calls=0
 def call(self,raw,capacity=1<<20,want=None):
  source=C.create_string_buffer(raw,max(1,len(raw)));out=C.create_string_buffer(b'\xa5'*(capacity+64),capacity+64)
  work=C.create_string_buffer(b'\xa5'*192,192)
  rc=self.image.entry(source,len(raw),out,capacity,work,128);self.calls+=1
  assert source.raw==(raw or b'\0')and out.raw[capacity:]==b'\xa5'*64 and work.raw[128:]==b'\xa5'*64
  if want is not None:
   assert rc==want,(rc,want,raw[:128].hex())
   assert out.raw==b'\xa5'*(capacity+64)
   return rc,b''
  assert rc<0xfffffffc and rc<=capacity,(rc,raw[:128].hex())
  assert out.raw[rc:]==b'\xa5'*(capacity+64-rc)
  return rc,out.raw[:rc]
 def value(self,raw):
  _,data=self.call(raw);return json.loads(data.decode('utf-8','surrogatepass')),data
def run(image,owner,out):
 assert platform.python_version()=='3.14.4';out.mkdir(parents=True,exist_ok=False)
 report=dict(passed=False,pure_codec_qualified=False,public_command_log_enclosing_qualified=False,whole_public_runtime_qualified=False)
 before=set(os.listdir('/proc/self/fd'));codec=Codec(image);groups=[];sample_frames=[];native_json=0
 old=original.run_bounded
 try:
  b=Bound(owner);assert b.call(0)['status']==0;v=Values(Engine(b))
  def check(argv,kwargs,result=None,error=None,live=False,check_native=False):
   nonlocal native_json
   sink=[];attempts=[];captured=[]
   def observation(*a,**kw):
    assert len(sink)==1 and sink[0]['status']=='attempted'
    attempts.append(copy.deepcopy(sink[0]))
    if live:
     try:r=old(*a,**kw)
     except BaseException as e:captured.append(e);raise
     captured.append(r);return r
    if error is not None:raise error
    return result
   original.run_bounded=observation
   try:
    try:returned=original._run_logged(argv,command_log=sink,**kwargs)
    except BaseException as e:
     if not live:assert e is error
     actual_error=e
    else:
     if not live:assert returned is result
     actual_error=None
   finally:original.run_bounded=old
   frame=capture_frame(argv,**{k:kwargs[k]for k in('timeout','stdout_limit','stderr_limit','stdin_limit')if k in kwargs})
   initial=packet(0,frame=frame,cwd=os.fsencode(kwargs.get('cwd')or os.getcwd()))
   row,raw=codec.value(initial);assert row==attempts[0]and list(row)==list(attempts[0]),(row,attempts[0])
   assert raw==json.dumps(attempts[0],ensure_ascii=False,separators=(',',':')).encode('utf-8','surrogatepass')
   final=error_packet(actual_error)if actual_error is not None else result_packet(returned)
   patch,pdata=codec.value(final);row.update(patch)
   assert row==sink[0]and list(row)==list(sink[0]),(row,sink[0])
   if check_native:
    for data,expected in((raw,attempts[0]),(pdata,patch)):
     cap=v.keep(v.raw(1,tail=data))
     actual=v.python_value(cap)
     assert actual==expected and list(actual)==list(expected),(actual,expected)
     v.drop(cap);native_json+=1
   for data in(initial,final):
    if len(sample_frames)<20:sample_frames.append(data)
   return actual_error,returned if actual_error is None else None
  base=dict(timeout=10,stdout_limit=65536,stderr_limit=65536,stdin_limit=1000000)
  for value in range(256):
   argv=[os.fsdecode(b'/tmp/compiler-'+bytes([value])),os.fsdecode(bytes([value])+b'x')]
   kwargs={**base,'cwd':os.fsdecode(b'/tmp/cwd-'+bytes([value]))}
   check(argv,kwargs,CaptureResult(0,'','',b'',b''),check_native=value in(0,34,92,127,128,237,255))
  groups.append(dict(case='all-filesystem-bytes-real-surrogateescape-and-attempt-row',cases=256))
  print('LLVM_LOG_CODEC_PASS filesystem',flush=True)
  texts=['','ascii','é\U0001f600','\ud800','\udcff','\ud800\udc00','a\r\nb\x00c','\b\t\n\f\r"\\']
  cases=0
  for a in texts:
   for c in texts:
    for mask in range(4):
     result=CaptureResult(-(1<<63)if cases==0 else (1<<63)-1 if cases==1 else -9,a,c,None if mask&1 else text(a),None if mask&2 else text(c))
     check(['/actual/clang','--version'],base,result,check_native=cases<8 or(a=='\ud800\udc00'and c==''));cases+=1
  groups.append(dict(case='completed-raw-bytes-and-exact-WTF8-fallback',cases=cases))
  print('LLVM_LOG_CODEC_PASS completed',flush=True)
  failures=0
  for capture in(None,CaptureFailure(('clang',),None,b'',b'',0,0),CaptureFailure(('clang',),-9,b'\0\xff',b'\r\n',1000,2000),
                 CaptureFailure(('clang',),0,bytes(range(256)),bytes(range(255,-1,-1)),256,256)):
   for code in(None,'','E_CAPTURE_OUTPUT','E_"\\\ud800\udc00'):
    for secondary in(None,'','actual secondary\n\udcff'):
     e=CaptureRejected(code,'reasoné\ud800\udc00\x00');e.capture=capture;e.capture_error=secondary
     check(['clang','-c'],base,error=e,check_native=failures<8);failures+=1
  for e in(ValueError('x'),KeyboardInterrupt('stop'),SystemExit('native message')):
   check(['clang'],base,error=e);failures+=1
  try:error_packet(SystemExit(7))
  except TypeError as rejection:assert 'direct strong Value edge'in str(rejection)
  else:raise AssertionError('non-text code cannot be silently stringified')
  groups.append(dict(case='failure-prefix-total-unknown-return-and-independent-capture-error',cases=failures))
  print('LLVM_LOG_CODEC_PASS failures',flush=True)
  rng=random.Random(620108)
  for i in range(250):
   argv=[os.fsdecode(rng.randbytes(rng.randrange(1,300)))for _ in range(rng.randrange(1,12))]
   cwd=os.fsdecode(rng.randbytes(rng.randrange(1,400)))
   stdout=rng.randbytes(rng.randrange(0,800));stderr=rng.randbytes(rng.randrange(0,800))
   check(argv,{**base,'cwd':cwd,'timeout':rng.choice((0,1,10,60,3600))},
    CaptureResult(rng.randrange(-2147483648,2147483648),'','',stdout,stderr))
  groups.append(dict(case='fixed-random-argv-cwd-and-real-byte-hex',cases=250))
  live_cases=[
   "import os;os.write(1,b'a\\r\\nb\\x00');os.write(2,'é'.encode());raise SystemExit(7)",
   "import os;os.write(1,b'\\xff')",
   "import os;os.write(2,b'x'*10000)",
  ]
  live=[]
  for i,code in enumerate(live_cases):
   e,r=check([sys.executable,'-c',code],{**base,'stdout_limit':64,'stderr_limit':64},live=True,check_native=True)
   live.append(dict(case=i,error_type=type(e).__name__ if e else None,error_code=getattr(e,'code',None),returncode=r.returncode if r else None))
  groups.append(dict(case='actual-subprocess-original-capture-not-synthetic-return',cases=live))
  print('LLVM_LOG_CODEC_PASS live-captures',flush=True)
  capacities=0
  for raw in sample_frames:
   n,data=codec.call(raw)
   for capacity in sorted({0,max(0,n-1),n,n+1}):
    if capacity<n:codec.call(raw,capacity,want=0xfffffffe)
    else:assert codec.call(raw,capacity)==(n,data)
    capacities+=1
  controls=[]
  good=packet(0,frame=capture_frame(['clang','--version']),cwd=b'/tmp')
  controls += [good[:n]for n in(0,1,8,127,len(good)-1)]
  controls += [good+b'\0']
  for at,value in((0,0),(8,3),(16,MASK),(24,MASK),(32,1),(64,2),(112,1),(120,1),(128,0),(136,1),(144,MASK),(152,1),(160,1),(168,10000000001),(200,1)):
   row=bytearray(good);struct.pack_into('<Q',row,at,value);controls.append(bytes(row))
  bad=bytearray(good);bad[-1]=255
  # Bad UTF-8 is legal filesystem input, while malformed retained text is not.
  controls.extend([
   packet(1,stdout=b'\xff',out_total=1,known=1,flags=4),
   packet(2,type_name=b'\xff',message=b'x'),
   packet(2,type_name=b'Error',code=b'x'),
   packet(2,type_name=b'Error',flags=1,stdout=b'xx',out_total=1),
   packet(1,known=0),packet(1,known=1,flags=1),
  ])
  for raw in controls:codec.call(raw,65536,want=0xfffffffd)
  groups.append(dict(case='exact-output-capacity-canaries-and-malformed-no-write',capacities=capacities,controls=len(controls)))
  for cap in list(v.held):v.drop(cap)
  sweep(v,b);b.close();assert set(os.listdir('/proc/self/fd'))==before
  report.update(passed=True,pure_codec_qualified=True,groups=groups,calls=codec.calls,native_value_json_imports=native_json,
   product=pin(image.read_bytes()),owner=pin(owner.read_bytes()),source=pin(Path(__file__).read_bytes()),
   original_run_logged_source=pin(Path(original.__file__).read_bytes()))
  print('LLVM_LOG_CODEC_ALL_PASS',codec.calls,native_json,flush=True)
 except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc());raise
 finally:
  original.run_bounded=old
  (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 return report
def main():
 p=argparse.ArgumentParser()
 for name in('image','owner','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();run(a.image,a.owner,a.output)
if __name__=='__main__':main()
