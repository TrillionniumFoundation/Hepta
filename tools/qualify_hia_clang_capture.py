"""Development-only driver for the actual native Linux capture component.

The caller here encodes already typed test values and decodes retained native
streams. It does not qualify the future public Value type/exception adapter.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,struct,sys,time,traceback,unittest,importlib,concurrent.futures,signal
ROOT=Path(__file__).resolve().parents[1]
class NativeCapture:
 def __init__(self,path):
  self.path=Path(path);self.library=C.CDLL(str(self.path));self.entry=self.library.hia_clang_capture
  self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32;self.rows=[]
 def frame(self,argv,*,cwd=None,input_text=None,timeout=30,stdout_limit=32000000,stderr_limit=1000000,stdin_limit=1000000,env=None):
  args=[os.fsencode(x)for x in argv];environment=[] if env is None else [(k+'='+v).encode('utf8')for k,v in env.items()]
  payload=b'' if input_text is None else input_text.encode('utf8');directory=b'' if cwd is None else os.fsencode(cwd)
  header=b'HIACAP01'+struct.pack('<15Q',0,len(args),len(environment),int(env is not None),int(timeout*1_000_000_000),stdout_limit,stderr_limit,stdin_limit,len(payload),len(directory),0,int(cwd is not None),0,0,0)
  return header+b''.join(struct.pack('<Q',len(x))+x+b'\0'for x in args+environment)+(directory+b'\0'if cwd is not None else b'')+payload
 def raw(self,argv,**kw):
  wire=self.frame(argv,**kw);source=C.create_string_buffer(wire);output=C.create_string_buffer(256)
  count=struct.unpack_from('<Q',wire,16)[0]+struct.unpack_from('<Q',wire,24)[0]+2
  work=C.create_string_buffer(max(65536,4096+8*count));before=time.monotonic()
  rc=self.entry(source,len(wire),output,len(output),work,len(work));assert rc==0,hex(rc)
  data=bytes(output);assert data[:8]==b'HIACAR01';v=struct.unpack('<32Q',data)
  result=dict(error=v[1],errno=v[2],return_known=v[3],returncode=C.c_int64(v[4]).value if v[3] else None,cleanup_error=v[5],cleanup_errno=v[6],stdout_total=v[7],stderr_total=v[8],pending=v[17],pid=v[18],group_attempted=v[19],exec_stage=v[24],evidence_error=v[25],evidence_errno=v[26])
  for name,pointer_at,length_at,cap_at in [('raw_stdout',9,10,20),('raw_stderr',11,12,21),('stdout',13,14,22),('stderr',15,16,23)]:
   assert v[length_at]<=v[cap_at] and (v[pointer_at]!=0 or v[length_at]==0),(name,v)
   result[name]=C.string_at(v[pointer_at],v[length_at])if v[pointer_at]else b''
  request=b'HIACAP01'+struct.pack('<15Q',1,*([0]*14));retire=C.create_string_buffer(request)
  rc=self.entry(retire,len(request),output,len(output),work,len(work));rv=struct.unpack('<32Q',bytes(output))
  result['retirement']=dict(returned=rc,error=rv[1],errno=rv[2],pending=rv[17],context_cleared=not any(bytes(work)[:4096]))
  assert rc==0 and rv[1]==0 and not any(bytes(work)[:4096]),result
  result['seconds']=time.monotonic()-before
  self.rows.append({k:(v.hex()if isinstance(v,bytes)else v)for k,v in result.items()})
  return result
 def run(self,argv,**kw):
  from hepta.clang_capture import CaptureResult,CaptureRejected,CaptureFailure
  r=self.raw(argv,**kw)
  if r['error']:
   names={1:'ARGV',2:'BUDGET',3:'ENV',4:'INPUT',5:'INPUT_SIZE',6:'OWNERSHIP',7:'EXEC',8:'OUTPUT_SIZE',9:'TIMEOUT',10:'ENCODING',11:'CLEANUP'}
   assert r['error']in names,r
   error=CaptureRejected('E_CAPTURE_'+names[r['error']],'Native component rejection; public message object is not under test')
   if r['pid'] and r['error']!=7:error.capture=CaptureFailure(tuple(argv),r['returncode'],r['raw_stdout'],r['raw_stderr'],r['stdout_total'],r['stderr_total'])
   if r['cleanup_error']:error.capture_error='E_CAPTURE_CLEANUP'
   raise error
  return CaptureResult(r['returncode'],r['stdout'].decode('utf8'),r['stderr'].decode('utf8'),r['raw_stdout'],r['raw_stderr'])
def additional(client,out):
 from hepta.clang_capture import run_bounded as oracle,CaptureRejected
 rows=[]
 def passed(name):rows.append(name);print('CAPTURE_ADDITIONAL_PASS',name,flush=True)
 script='import sys;sys.stdout.buffer.write(sys.stdin.buffer.read());sys.stderr.buffer.write(b"e\\r\\nf\\rg")'
 for value in ('','ascii','é 中 😀\r\nnext\r', 'x'*200000):
  a=client.run([sys.executable,'-c',script],input_text=value);b=oracle([sys.executable,'-c',script],input_text=value)
  assert a==b,(a,b)
 passed('raw-utf8-newline-and-growing-storage')
 for code in (0,7,127,128,255):
  command=[sys.executable,'-c','import os,sys;os.write(1,b"raw\\r\\n");os.write(2,b"err\\r");os._exit(int(sys.argv[1]))',str(code)]
  assert client.run(command,timeout=5)==oracle(command,timeout=5)
 passed('exact-five-real-exit-codes')
 command=[sys.executable,'-c','import os,signal;os.kill(os.getpid(),signal.SIGTERM)']
 assert client.run(command,timeout=3)==oracle(command,timeout=3)
 passed('actual-signal-returncode')
 old=os.environ.get('HIA_CAPTURE_COMPONENT')
 try:
  os.environ['HIA_CAPTURE_COMPONENT']='parent'
  script='import os,json;print(json.dumps([os.getenv("HIA_CAPTURE_COMPONENT"),os.getenv("LANG")]))'
  for environment in (None,{}, {'PATH':os.defpath,'LANG':'C','LC_ALL':'C'}, {'1-x. z':'value','🧪':'中文','PATH':os.defpath}):
   assert client.run([sys.executable,'-I','-c',script],env=environment)==oracle([sys.executable,'-I','-c',script],env=environment)
  assert os.environ['HIA_CAPTURE_COMPONENT']=='parent'
 finally:
  if old is None:os.environ.pop('HIA_CAPTURE_COMPONENT',None)
  else:os.environ['HIA_CAPTURE_COMPONENT']=old
 passed('actual-inheritance-and-exact-environment-domain')
 for environment in (None,{}, {'PATH':'/not-found:/usr/bin:/bin'}, {'PATH':''}):
  name='/usr/bin/printf'if environment is not None and environment.get('PATH')==''else'printf'
  assert client.run([name,'path=%s','ok'],env=environment)==oracle([name,'path=%s','ok'],env=environment)
 passed('path-search-default-explicit-empty')
 arguments=[sys.executable,'-c','import sys;print(len(sys.argv),sys.argv[-1])']+['v'+str(i)for i in range(300)]
 assert client.run(arguments)==oracle(arguments)
 environment={'K'+str(i):'v'+str(i)for i in range(255)}
 assert client.run([sys.executable,'-I','-c','import os;print(len(os.environ))'],env=environment)==oracle([sys.executable,'-I','-c','import os;print(len(os.environ))'],env=environment)
 passed('argv-above64-and-full256-environment-domain')
 directory=out/'cwd';directory.mkdir()
 assert client.run([sys.executable,'-c','import os;print(os.getcwd())'],cwd=directory)==oracle([sys.executable,'-c','import os;print(os.getcwd())'],cwd=directory)
 for command,cwd in [(['/hia-capture-component-missing'],None),(['printf','x'],out/'missing-cwd'),(['printf','x'],'')]:
  native=client.raw(command,cwd=cwd)
  try:oracle(command,cwd=cwd)
  except CaptureRejected as e:assert e.code=='E_CAPTURE_EXEC' and native['error']==7,(e,native)
  else:raise AssertionError('original unexpected success')
 passed('cwd-and-real-exec-failures')
 for stream in (1,2):
  for data,limit,error in [(b'\xff',100,10),(b'x'*8192,4096,8),(b'\xf0\x9f',100,10)]:
   command=[sys.executable,'-c','import os;os.write('+str(stream)+','+repr(data)+');os._exit(7)']
   kwargs={('stdout_limit'if stream==1 else'stderr_limit'):limit}
   actual=client.raw(command,**kwargs)
   try:oracle(command,**kwargs)
   except CaptureRejected as e:
    assert actual['error']==error and actual['returncode']==e.capture.returncode
    assert (actual['raw_stdout'],actual['raw_stderr'],actual['stdout_total'],actual['stderr_total'])==(e.capture.stdout,e.capture.stderr,e.capture.stdout_total_bytes,e.capture.stderr_total_bytes)
   else:raise AssertionError('missing original failure')
 passed('bounded-failure-prefix-totals-and-status')
 assert client.run(['/usr/bin/true'],stdout_limit=0,stderr_limit=0)==oracle(['/usr/bin/true'],stdout_limit=0,stderr_limit=0)
 passed('zero-stream-budgets')
 before=set(os.listdir('/proc/self/fd'))
 def job(i):
  actual=client.run(['/usr/bin/printf','%s','parallel-'+str(i)],timeout=3)
  assert actual.stdout=='parallel-'+str(i) and actual.returncode==0
 with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:list(pool.map(job,range(64)))
 assert set(os.listdir('/proc/self/fd'))==before
 passed('8-threads64-processes-and-descriptor-balance')
 return rows
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
 args.output.mkdir(mode=0o700);client=NativeCapture(args.library)
 report=dict(schema='hepta.hia.clang-capture-component-qualification.v1',passed=False,whole_capture_qualified=False,public_value_adapter_qualified=False,python_product_callbacks=False,product={'bytes':args.library.stat().st_size,'sha256':hashlib.sha256(args.library.read_bytes()).hexdigest()})
 try:
  mod=importlib.import_module('tests.test_clang_capture');mod.run_bounded=client.run
  names=('test_success_preserves_text_and_input','test_real_clang_c_preprocess','test_child_exit_failure_does_not_turn_into_success','test_real_exit_status_and_streams_are_preserved','test_stdout_limit','test_stderr_limit','test_wall_timeout','test_oversize_stdin_without_process_launch','test_bad_utf8_stdout_is_rejected','test_descendant_cancelled_even_when_parent_succeeds','test_descendant_cancelled_when_parent_fails','test_descendant_cancelled_on_wall_timeout','test_descendant_cancelled_on_output_limit')
  suite=unittest.TestSuite(mod.CaptureBudgets(name)for name in names)
  with (args.output/'original-real-process.log').open('w')as log:
   result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
  report['original_real_process']={'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':result.skipped,'names':list(names),'source_sha256':hashlib.sha256((ROOT/'tests/test_clang_capture.py').read_bytes()).hexdigest()}
  print('CAPTURE_ORIGINAL_REAL_PROCESS',json.dumps(report['original_real_process']),flush=True)
  assert result.wasSuccessful() and not result.skipped,(result.failures,result.errors)
  report['additional_groups']=additional(client,args.output)
  report['passed']=True
 except BaseException as e:report['error']=repr(e);report['traceback']=traceback.format_exc();raise
 finally:
  report['actual_calls']=client.rows;(args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
  print('CAPTURE_REPORT',report['passed'],len(client.rows),flush=True)
if __name__=='__main__':main()
