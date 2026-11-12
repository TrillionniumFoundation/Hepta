from pathlib import Path
from hashlib import sha256
import json,struct,subprocess,time,os,signal,resource,traceback
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'development/native-whole-r2';OUT.mkdir(exist_ok=False)
exe=ROOT/'development/native-build-r2/hia-build';input_path=ROOT/'development/gate-actual-r1/input.hiabuild'
raw=input_path.read_bytes();expected=sha256(raw[64:]).hexdigest();assert raw[16:48].hex()==expected
pins={exe:exe.read_bytes(),input_path:raw,Path(__file__):Path(__file__).read_bytes()};(OUT/'pins.json').write_text(json.dumps({str(p):dict(bytes=len(b),sha256=sha256(b).hexdigest()) for p,b in pins.items()},indent=2,sort_keys=True)+'\n')
request=dict(executable=str(exe),argv=[expected],stdin=dict(path=str(input_path),offset=64,bytes=len(raw)-64,sha256=expected),environment=dict(PATH='',HOME=str(OUT)),limits=dict(address_bytes=1<<30,cpu_seconds=120,wall_seconds=150),scope='ACTUAL_FIXED_ELF_DEVELOPMENT_NOT_NEW_COLD')
(OUT/'request.json').write_text(json.dumps(request,indent=2,sort_keys=True)+'\n')
def setup():
 resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30));resource.setrlimit(resource.RLIMIT_CPU,(120,120));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def timeout(signum,frame):raise TimeoutError('fixed native build wall bound')
result=dict(status='INCOMPLETE');start=time.monotonic_ns();proc=None
try:
 with input_path.open('rb') as src,(OUT/'package.raw').open('xb') as out,(OUT/'terminal.raw').open('xb') as err:
  src.seek(64);proc=subprocess.Popen([str(exe),expected],stdin=src,stdout=out,stderr=err,env=request['environment'],preexec_fn=setup,start_new_session=True)
  signal.signal(signal.SIGALRM,timeout);signal.alarm(150);pid,status,usage=os.wait4(proc.pid,0);signal.alarm(0);proc.returncode=os.waitstatus_to_exitcode(status)
 result.update(returncode=proc.returncode,wait4=dict(status=status,user_seconds=usage.ru_utime,system_seconds=usage.ru_stime,maxrss_kib=usage.ru_maxrss))
 terminal=(OUT/'terminal.raw').read_bytes();package=(OUT/'package.raw').read_bytes();result.update(terminal_hex=terminal.hex(),output_bytes=len(package),output_sha256=sha256(package).hexdigest())
 assert proc.returncode==0,(proc.returncode,terminal.hex())
 event=struct.unpack('<16Q',terminal);assert event[0]==int.from_bytes(b'HIABBE01','little') and event[1]==0 and event[4]==len(package)
 assert terminal[96:128]==sha256(package).digest()
 magic,count,reserved=struct.unpack_from('<3Q',package);assert magic==int.from_bytes(b'HIAREL01','little') and count==6 and reserved==0
 at=24;files={}
 for i in range(count):
  n,mode,size=struct.unpack_from('<3Q',package,at);at+=24;name=package[at:at+n].decode();at+=n;payload=package[at:at+size];at+=size;assert len(payload)==size and name not in files
  files[name]=(mode,payload)
 assert at==len(package);assert set(files)=={'hia','hia-release','hia-build','compiler.bin','source-kit.hiabuild','build.json'}
 assert files['source-kit.hiabuild'][1]==raw[64:] and files['hia-build'][1]==pins[exe]
 compiler_size=struct.unpack_from('<Q',raw,96)[0];assert files['compiler.bin'][1]==raw[128:128+compiler_size]
 report=json.loads(files['build.json'][1]);assert report['kit_sha256']==expected and report['builder_sha256']==sha256(pins[exe]).hexdigest() and report['compiler_sha256']==sha256(files['compiler.bin'][1]).hexdigest()
 assert report['new_builder_matching_source_cold_qualified'] is False and report['whole_native_delivery_qualified'] is False
 result.update(status='PASS',event=list(event),files={name:dict(mode=mode,bytes=len(b),sha256=sha256(b).hexdigest()) for name,(mode,b) in files.items()},native_receipt=report)
except BaseException as e:
 result.update(status='FAIL',error_class=type(e).__name__,error=str(e));traceback.print_exc()
 if proc and proc.returncode is None:
  os.killpg(proc.pid,signal.SIGKILL);pid,status,usage=os.wait4(proc.pid,0);proc.returncode=os.waitstatus_to_exitcode(status);result['termination_returncode']=proc.returncode
 raise
finally:
 signal.alarm(0);result['all_pins_unchanged']=all(p.read_bytes()==b for p,b in pins.items());result['elapsed_ns']=time.monotonic_ns()-start;(OUT/'summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,sort_keys=True),flush=True);assert result['all_pins_unchanged']
