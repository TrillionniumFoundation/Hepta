"""Actual native MV snapshot vs frozen original runtime/retirement methods."""
from pathlib import Path
import contextlib,copy,ctypes,fcntl,hashlib,json,mmap,os,random,struct,sys,threading,time
from collections import OrderedDict,deque
from types import SimpleNamespace
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125')
S=Path(__file__).resolve().parents[1];Q=Path(os.environ.get('HIA_MV_SNAPSHOT_QA_ROOT',str(T/'multiversion-runtime-snapshot-qa')))
sys.path.insert(0,str(S));os.environ.setdefault('Z3_LIBRARY_PATH',str(T/'qa-z3-4.15.4'))
if hasattr(sys,'set_int_max_str_digits'):sys.set_int_max_str_digits(0)
from hepta import hia_native_retirement as original
from hepta import hia_retirement_state_native as native_original
from hepta import hia_multiversion as runtime_original
U=(1<<64)-1
qword=lambda x:struct.pack('<Q',x)
sha=lambda b:hashlib.sha256(b).hexdigest()
jbytes=lambda o:json.dumps(o,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode()
text=lambda x:x.encode('utf-8','surrogatepass')
decimal=lambda x:str(x).encode()
def frame(kind,fields,flags=0):
 fields=[bytes(x) for x in fields];head=32+16*len(fields);at=head;table=[]
 for field in fields:table.append(qword(at)+qword(len(field)));at+=len(field)
 return struct.pack('<4Q',kind,flags,len(fields),at)+b''.join(table)+b''.join(fields)
def packet(record):
 return b'HIAMVSP1'+record[:8]+qword(len(record))+bytes(40)+record
def array(rows):return frame(9,rows)
def jsonlist(rows):return frame(10,[jbytes(x)for x in rows])
def statewords(values=None):
 v=[0]*576;v[0]=int.from_bytes(b'HIARSTA1','little')
 for i,x in (values or {}).items():v[i]=x
 return v
def statebytes(v):return struct.pack('<576Q',*v)
def error(exc):
 d=original._error(exc)
 return frame(7,[text(d['type']),b''if d['errno']is None else decimal(d['errno']),text(str(exc))]),d
def oserror(code,path=None):
 message=os.strerror(code)if -(1<<31)<=code<(1<<31)else 'Unknown error '+str(code)
 e=OSError(code,message)if path is None else OSError(code,message,os.fsdecode(path))
 return frame(12,[decimal(code),b''if path is None else path],int(path is not None)),original._error(e)
class FakeState:
 def __init__(self,words,flags,fenced=None):self._words=tuple(words[:64]);self._flags=flags;self._fenced=fenced
 def query(self):return self._words,self._flags
 def scope(self):return contextlib.nullcontext()
 def diagnostic(self,report):return native_original.RetirementState.diagnostic(self,report)
class Item:
 def __init__(self,wire,expected,oracle=None):self.wire=wire;self.expected=expected;self.oracle=oracle

def pin(path=b'/private/artifact',directory=False,bound=False,held=False,attempted=False,released=False,close_attempted=False,close_status=0,close_finished=False,acq=None,close=None,native=False,fenced=None,quarantine=None,slot=(0,None),words=None,extra_flags=0):
 v=statewords()if words is None else list(words)
 v[3]=int(directory);v[4]=int(attempted);v[5]=int(held);v[6]=57 if held else 0;v[7]=int(bound);v[8:10]=[13,123456]
 v[10]=int(released);v[11]=int(close_attempted);v[12]=close_status;v[41]=72301;v[42]=72519;v[43]=int(close_finished)
 acqwire,acqobj=acq if acq else (b'',None);closewire,closeobj=close if close else(b'',None)
 close_result={'status':native_original.STATUS[close_status]}
 if close_attempted:close_result['attempted_ns']=v[41]
 if not native and closeobj is not None:close_result['error']=closeobj
 if close_finished:close_result['finished_ns']=v[42]
 if native and closeobj is not None:close_result['error']=closeobj
 ref=original._ReferencePathIdentityPin(Path(os.fsdecode(path)),directory=directory,fd=57 if held else None,inode=(v[8],v[9])if bound else None,acquisition_attempted=attempted,acquisition_error=acqobj,bound=bound,path_released=released,close_attempted=close_attempted,close_result=close_result)
 flags=int(ref.release_succeeded)|(2 if bound and held and not close_attempted else 0)|extra_flags
 policywire,policyobj=fenced if fenced else(b'',None)
 if native:
  st=FakeState(v,flags,policyobj);ref=native_original.NativePathIdentityPin.__new__(native_original.NativePathIdentityPin)
  st.path=Path(os.fsdecode(path));ref._state=st;ref._acquisition_error=acqobj;ref._close_error=closeobj;ref._returned_open=quarantine;ref._open_result=slot
  expected=ref.snapshot()
 else:expected=ref.snapshot()
 if fenced:
  stage,returned=slot;slotobj={'stage':stage,'kernel_result':returned if stage==2 else None,'outcome':'not_entered'if stage==0 else'returned'if stage==2 else'unknown','close_retry_permitted':False}
 else:slotobj=None
 wire=frame(3,[path,statebytes(v),acqwire,closewire,policywire,b''if quarantine is None else jbytes(quarantine),b''if slotobj is None else jbytes(slotobj)],flags|(16 if native else 0))
 return Item(wire,expected,ref)

def observation(path=b'/private',now=123456789,status=2,inode=(13,42),err=None,native=False):
 errorwire,errorobj=err if err else(b'',None)
 out={'path':os.fsdecode(path),'observed_ns':now}
 if inode is not None:out['actual_inode']=list(inode)
 if native and errorobj is not None:out['error']=errorobj
 out['status']=native_original.OBSERVATION[status]
 if not native and errorobj is not None:out['error']=errorobj
 return Item(frame(5,[path,decimal(now),b''if inode is None else struct.pack('<2Q',*inode),errorwire],status|(16 if native else 0)),out)

def directory(path=b'/private',now=123456790,status=0,before=None,after=None,pinitem=None,err=None,native=False):
 if status==0:return Item(frame(6,[b'']*6,16 if native else 0),{'status':'not_attempted'})
 before=before or observation(path);after=after or observation(path,status=1,inode=None)
 errorwire,errorobj=err if err else(b'',None)
 out={'path':os.fsdecode(path),'attempted_ns':now,'before':before.expected}
 if native and errorobj is not None:out['error']=errorobj
 out['status']={1:'already_absent',3:'refused_unowned_or_unobservable',4:'removed',5:'error'}[status]
 if not native and errorobj is not None:out['error']=errorobj
 out['after']=after.expected;out['identity_pin']=None if pinitem is None else pinitem.expected
 return Item(frame(6,[path,decimal(now),before.wire,after.wire,b''if pinitem is None else pinitem.wire,errorwire],status|(16 if native else 0)),out)

def task(generation=1,cause='retired',path=b'/private/artifact',pinitem=None,attempted=True,library_status=3,fd_status=3,finished=True,disk_attempts=1,disk_status=4,liberr=None,fderr=None,diskerr=None,before=None,native=False,fenced=None,quarantine=None):
 pi=pinitem or pin(path,bound=True,held=False,attempted=True,released=True,close_attempted=True,close_status=3,close_finished=True,native=native)
 v=statewords({22:int(attempted),23:library_status,24:fd_status,28:min(disk_attempts,U),29:disk_status,31:min(generation,U),38:123001,39:123999,40:int(finished),44:124111,16:1,17:13,18:123456})
 nativeobj={}
 if attempted:
  nativeobj={'attempted_ns':v[38],'library':{'status':native_original.STATUS[library_status]},'fd':{'status':native_original.STATUS[fd_status]}}
  if finished:nativeobj['finished_ns']=v[39]
  if liberr:nativeobj['library']['error']=liberr[1]
  if fderr:nativeobj['fd']['error']=fderr[1]
 diskobj={}
 if disk_attempts:
  diskobj['attempted_ns']=v[44]
  if before:diskobj['before']=before.expected
 if native_original.DISK[disk_status]is not None:diskobj['status']=native_original.DISK[disk_status]
 if diskerr:diskobj['error']=diskerr[1]
 ref=original._ReferenceNativeRetirement(generation,cause,Path(os.fsdecode(path)),(13,123456),None,{},None,identity_pin=pi.oracle,native_attempted=attempted,native=nativeobj,disk=diskobj,disk_attempts=disk_attempts)
 flags=(4 if ref.native_succeeded else 0)|(8 if ref.complete else 0)
 expected=ref.snapshot()
 if native:
  # Use the original native decoder with captured query words/flags, including
  # the original conditional field insertion order.
  assert generation<=U and disk_attempts<=U
  nr=native_original.NativeRetirement.__new__(native_original.NativeRetirement);nr._state=FakeState(v,flags,fenced[1]if fenced else None)
  nr._cause=cause;nr._artifact=Path(os.fsdecode(path));nr._library=None;nr._functions={};nr._identity_pin=pi.oracle;nr._pin=pi.oracle
  nr._unattached_custody=None;nr._creation_fields=None;nr._library_error=liberr[1]if liberr else None;nr._fd_error=fderr[1]if fderr else None
  nr._disk_before=before.expected if before else None;nr._disk_error=diskerr[1]if diskerr else None
  expected=nr.snapshot();ref=nr
 # The private policy diagnostic is carried by the same pin/state producer.
 if fenced:
  assert native
  # Rebind the exact captured policy error in the supplied pin record.
  assert pi.expected.get('native_policy_error')==fenced[1]
 if quarantine is not None:expected['quarantined_foreign_resources']=quarantine
 fields=[decimal(generation),text(cause),path,statebytes(v),pi.wire,decimal(disk_attempts),liberr[0]if liberr else b'',fderr[0]if fderr else b'',before.wire if before else b'',diskerr[0]if diskerr else b'',jbytes(quarantine)if quarantine is not None else b'',struct.pack('<2Q',13,123456)]
 return Item(frame(4,fields,flags|(16 if native else 0)),expected,ref)

class Native:
 def __init__(self,path):
  self.raw=Path(path).read_bytes();self.map=mmap.mmap(-1,len(self.raw),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);self.map.write(self.raw)
  self.function=ctypes.CFUNCTYPE(ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)(ctypes.addressof(ctypes.c_char.from_buffer(self.map)))
 def run(self,data,outcap=65536,workcap=1048576,offset=0,poison=0xA9):
  sb=ctypes.create_string_buffer(len(data)+128+offset);ob=ctypes.create_string_buffer(outcap+128+offset);wb=ctypes.create_string_buffer(workcap+128+offset)
  ctypes.memset(sb,0xD3,len(sb));ctypes.memset(ob,poison,len(ob));ctypes.memset(wb,0xB7,len(wb))
  sp=ctypes.addressof(sb)+64+offset;op=ctypes.addressof(ob)+64+offset;wp=ctypes.addressof(wb)+64+offset
  ctypes.memmove(sp,data,len(data));start=time.monotonic_ns()
  status=self.function(sp,len(data),op,outcap,wp,workcap);elapsed=time.monotonic_ns()-start
  assert sb.raw[:64+offset]==bytes([0xD3])*(64+offset) and sb.raw[64+offset+len(data):]==bytes([0xD3])*64
  assert sb.raw[64+offset:64+offset+len(data)]==data
  assert ob.raw[:64+offset]==bytes([poison])*(64+offset) and ob.raw[64+offset+outcap:]==bytes([poison])*64
  assert wb.raw[:64+offset]==bytes([0xB7])*(64+offset) and wb.raw[64+offset+workcap:]==bytes([0xB7])*64
  out=ob.raw[64+offset:64+offset+outcap];work=wb.raw[64+offset:64+offset+workcap]
  if status>=U-2:assert out==bytes([poison])*outcap
  return status,out,work,elapsed
def main():
 native=Native(Q/'native-v4/snapshot.flat');rows=[]
 def check(label,item,offset=0):
  raw=packet(item.wire);expected=jbytes(item.expected);status,out,w,elapsed=native.run(raw,max(256,len(expected)+32),offset=offset)
  if status!=len(expected)or out[:status]!=expected:
   d=Q/'first-failure';d.mkdir(exist_ok=True);(d/'input.bin').write_bytes(raw);(d/'expected.json').write_bytes(expected);(d/'output.bin').write_bytes(out);(d/'work.bin').write_bytes(w)
   raise AssertionError((label,status,len(expected),struct.unpack('<8Q',w[:64]),out[:min(len(expected)+20,1000)],expected[:1000]))
  rows.append({'case':label,'bytes':len(expected),'sha256':sha(expected),'elapsed_ns':elapsed});return raw,expected
 err=error(ValueError('actual value\nwith \ud800 and 🙂'));ose=oserror(13,b"/private/a'b\xff")
 for native_order in [False,True]:
  for status in range(4):
   check('pin-'+str(native_order)+'-'+str(status),pin(bound=True,held=True,attempted=True,close_attempted=True,close_status=status,close_finished=True,acq=err,close=ose,native=native_order),status)
  for status in range(7):
   check('observe-'+str(native_order)+'-'+str(status),observation(status=status,err=ose if status==6 else None,native=native_order))
  for status in [0,1,3,4,5]:
   check('directory-'+str(native_order)+'-'+str(status),directory(status=status,err=ose if status==5 else None,pinitem=pin(directory=True,native=native_order),native=native_order))
  for status in range(7):
   check('task-'+str(native_order)+'-'+str(status),task(disk_status=status,before=observation(native=native_order),diskerr=ose if status==5 else None,liberr=err,fderr=ose,native=native_order))
 for code in list(range(134))+[255,4095,-1,-4095,1<<63,10**100]:
  wi,ex=oserror(code,b"/a'b/\xff/\t/"+"🙂".encode())
  check('errno-'+str(code),Item(wi,ex))
 for count in [0,1,1023,1024,1025,10001]:
  wi,ex=error(RuntimeError(('🙂\udfff\n'*(count//3+1))[:count]));check('error-truncate-'+str(count),Item(wi,ex))
 (Q/'smoke-report.json').write_text(json.dumps({'status':'PASS','cases':len(rows),'rows':rows,'flat_sha256':sha(native.raw)},indent=2)+'\n')
 print('SNAPSHOT_SMOKE_PASS',len(rows),flush=True)
if __name__=='__main__':main()
