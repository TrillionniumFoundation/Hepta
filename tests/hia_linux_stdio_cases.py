"""Exact retained public direct/VM controls; fixture authority is supplied separately."""
from pathlib import Path
import hashlib,json,os,resource,signal,subprocess,time
from hepta.hia_program_runtime import execute_program,HIAProgramTrap
from hepta.hia_linux_stdio import PROFILE,READ,LinuxStdioSignal

def sha(raw):return hashlib.sha256(raw).hexdigest()


def dump(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def impose(mode):
 def before_exec():
  for kind,limit in [(resource.RLIMIT_CORE,0),(resource.RLIMIT_CPU,10),(resource.RLIMIT_AS,256<<20),(resource.RLIMIT_STACK,8<<20),(resource.RLIMIT_FSIZE,16<<20),(resource.RLIMIT_NOFILE,32)]:resource.setrlimit(kind,(limit,limit))
  if mode=='closed-stdin':os.close(0)
  if mode=='closed-stdout':os.close(1)
 return before_exec


def direct(folder,elf,data,mode,ignored):
 folder.mkdir();(folder/'stdin.bin').write_bytes(data);raw=elf.read_bytes();started=time.perf_counter();timed_out=False;pipe=None
 with (folder/'stdin.bin').open('rb') as inp,(folder/'stdout.bin').open('wb') as out,(folder/'stderr.bin').open('wb') as err:
  target=out
  if mode=='broken-pipe':
   rd,pipe=os.pipe();os.close(rd);target=pipe
  try:
   child=subprocess.Popen([str(elf.resolve())],stdin=inp,stdout=target,stderr=err,start_new_session=True,restore_signals=not ignored,preexec_fn=impose(mode))
   try:rc=child.wait(timeout=20)
   except subprocess.TimeoutExpired:timed_out=True;os.killpg(child.pid,signal.SIGKILL);rc=child.wait(timeout=3)
   consumed=inp.tell()
  finally:
   if pipe is not None:os.close(pipe)
 try:os.waitpid(child.pid,os.WNOHANG)
 except ChildProcessError:reaped=True
 else:reaped=False
 after=elf.read_bytes()
 result={'command':[str(elf.resolve())],'returncode':rc,'timed_out':timed_out,'reaped_ECHILD':reaped,'stdin_consumed':consumed,'stdout_hex':(folder/'stdout.bin').read_bytes().hex(),'stderr_hex':(folder/'stderr.bin').read_bytes().hex(),'image_sha256':sha(raw),'image_after_sha256':sha(after),'wall_seconds':time.perf_counter()-started,'limits':{'wall':20,'cleanup':3,'cpu':10,'address':256<<20,'stack':8<<20,'filesize':16<<20,'fds':32,'core':0},'runtime_payload_python_or_ctypes':False}
 dump(folder/'OBSERVATION.json',result);return result


def reference(program,data,mode,ignored):
 consumed=0;writes=[]
 def provider(request):
  nonlocal consumed
  if request.operation==READ:
   if mode=='closed-stdin':return -9,b''
   piece=data[consumed:consumed+request.count];consumed+=len(piece);return len(piece),piece
  if mode=='closed-stdout':return -9,b''
  if mode=='broken-pipe':
   if ignored:return -32,b''
   raise LinuxStdioSignal(int(signal.SIGPIPE))
  writes.append(request.write_bytes);return request.count,b''
 try:
  result=execute_program(program,'f0',(b'',bytes(1048576),bytes(1048576)),profile=PROFILE,linux_stdio_provider=provider,max_steps=1000000)
  expected=result['values'][0]&255
 except HIAProgramTrap as exc:result=exc.report;expected=-signal.SIGILL
 except LinuxStdioSignal as exc:result=exc.report;expected=-exc.number
 result.update(expected_stdout_hex=b''.join(writes).hex(),stdin_consumed=consumed,process_returncode=expected)
 return result


def case_definitions():
  data=bytes(range(256))*4096
  definitions=[('empty-input','bounded-copy',b'','ordinary',False,0,b''),('short-binary-input','bounded-copy',b'\x00\xffshort\n','ordinary',False,0,b'\x00\xffshort\n'),('zero-count-open','zero-transfer',b'unchanged','ordinary',False,0,b''),('zero-count-closed-read','zero-transfer',b'unchanged','closed-stdin',False,247,b''),('zero-count-closed-write','zero-transfer',b'unchanged','closed-stdout',False,247,b''),('full-signed-read-ebadf','read-ebadf-exact',b'untouched','closed-stdin',False,93,b''),('full-signed-write-ebadf','write-ebadf-exact',b'untouched','closed-stdout',False,93,b''),('SIGPIPE-default','bounded-copy',b'pipe payload','broken-pipe',False,-signal.SIGPIPE,b''),('SIGPIPE-inherited-ignore-EPIPE','bounded-copy',b'pipe payload','broken-pipe',True,224,b''),('exact-1MiB','bounded-copy',data,'ordinary',False,0,data),('over-1MiB-rejected-before-write','bounded-copy',data+b'!','ordinary',False,3,b''),('bounds-before-read','out-of-bounds',b'untouched','ordinary',False,-signal.SIGILL,b'')]
  return definitions

def case_checks(name,build,ref,actual,rc,stdout):
   checks={'return':actual['returncode']==ref['process_returncode']==rc,'stdout':actual['stdout_hex']==ref['expected_stdout_hex']==stdout.hex(),'consumed':actual['stdin_consumed']==ref['stdin_consumed'],'no_stderr':actual['stderr_hex']=='','no_timeout':not actual['timed_out'],'reaped':actual['reaped_ECHILD'],'immutable':actual['image_sha256']==actual['image_after_sha256']==build['executable_sha256']}
   if name=='zero-count-open':checks['two_zero_effects']=len(ref['effects'])==2 and all(row['count']==0 for row in ref['effects'])
   if name.startswith('full-signed'):checks['signed_i64_before_exit']=ref['values']==[93]
   if name=='bounds-before-read':checks['no_effect']=ref['effects']==[]
   return checks
