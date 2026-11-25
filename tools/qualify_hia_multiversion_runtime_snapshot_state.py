from pathlib import Path
import importlib.util,sys,ctypes,json,struct,tempfile,os,copy,hashlib
from types import SimpleNamespace
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');Q=T/'multiversion-runtime-snapshot-qa'
from tools import qualify_hia_multiversion_runtime_snapshot as h
Q=h.Q;T=h.T
D=Q/'actual-state-v3';D.mkdir();fmt=h.Native(Q/'native-v4/snapshot.flat');state=h.Native(Q/'actual-retirement-state.flat')
image=SimpleNamespace(_entry=state.function,_open_primitive=h.native_original.RetirementOpenPrimitive());image.owner=lambda path,directory:h.native_original.RetirementState(image,path,directory);rows=[]
def ew(error):
 if error is None:return b''
 return h.frame(7,[h.text(error['type']),b''if error['errno']is None else h.decimal(error['errno']),h.text(error['message'])])
def pw(pin):
 words,flags=pin._state.query();raw=struct.pack('<64Q',*words)+pin._state._buffer.raw[512:]
 policy=pin._state._fenced;returned=b'';slot=b''
 if policy is not None:
  if pin._returned_open is not None:returned=h.jbytes(pin._returned_open)
  stage,value=pin._open_result;slot=h.jbytes({'stage':stage,'kernel_result':value if stage==2 else None,'outcome':'not_entered'if stage==0 else'returned'if stage==2 else'unknown','close_retry_permitted':False})
 return h.frame(3,[os.fsencode(pin.path),raw,ew(pin._acquisition_error),ew(pin._close_error),ew(policy),returned,slot],flags|16)
def ow(o):
 return h.frame(5,[os.fsencode(o['path']),h.decimal(o['observed_ns']),struct.pack('<2Q',*o['actual_inode'])if 'actual_inode'in o else b'',ew(o.get('error'))],h.native_original.OBSERVATION.index(o['status'])|16)
def dw(d):
 return h.frame(6,[os.fsencode(d['path']),h.decimal(d['attempted_ns']),ow(d['before']),ow(d['after']),pw(active_dir)if d['identity_pin']is not None else b'',ew(d.get('error'))],{'already_absent':1,'refused_unowned_or_unobservable':3,'removed':4,'error':5}[d['status']]|16)
def tw(task):
 words,flags=task._state.query();raw=struct.pack('<64Q',*words)+task._state._buffer.raw[512:];quarantine=b''
 if task._unattached_custody is not None or task._state._fenced is not None:
  quarantine=h.jbytes({'library_held':task.library is not None,'native_descriptor':task.fd,'native_task_attachment_confirmed':task._unattached_custody is None})
 return h.frame(4,[h.decimal(task.generation),h.text(task.cause),os.fsencode(task.artifact),raw,pw(task._pin),h.decimal(task.disk_attempts),ew(task._library_error),ew(task._fd_error),ow(task._disk_before)if task._disk_before is not None else b'',ew(task._disk_error),quarantine,struct.pack('<2Q',*task.inode)if task.inode is not None else b''],flags|16)
def check(label,wire,expected):
 raw=h.packet(wire);ex=h.jbytes(expected);r,out,w,elapsed=fmt.run(raw,len(ex),65536)
 if r!=len(ex)or out!=ex:
  (D/'failed.input').write_bytes(raw);(D/'failed.expected.json').write_bytes(ex);(D/'failed.actual').write_bytes(out);raise AssertionError((label,r,len(ex),out,ex))
 (D/(label+'.capture')).write_bytes(raw)
 rows.append({'case':label,'capture_sha256':h.sha(raw),'output_sha256':h.sha(ex),'elapsed_ns':elapsed})
with tempfile.TemporaryDirectory(prefix='hia-snapshot-actual-')as tmp:
 root=Path(tmp)
 # Actual fixed state owner and real open/fstat/lstat/unlink/close observations.
 path=root/"a'Ω🙂";path.write_bytes(b'owned');st=path.stat();pin=h.native_original.NativePathIdentityPin(path,False,image)
 check('pin-new',pw(pin),pin.snapshot());pin.acquire((st.st_dev,st.st_ino));check('pin-open',pw(pin),pin.snapshot())
 ob=pin.observe();check('observation-owned',ow(ob),ob);path.unlink();ob=pin.observe();check('observation-absent',ow(ob),ob)
 pin.release_absent_path();check('pin-closed',pw(pin),pin.snapshot())
 # Actual acquisition failure including pathname text.
 missing=root/'missing';pin=h.native_original.NativePathIdentityPin(missing,False,image)
 try:pin.acquire((0,0))
 except FileNotFoundError:pass
 else:raise AssertionError('expected actual missing open')
 check('pin-actual-open-error',pw(pin),pin.snapshot())
 # A real directory error, then retryable removal and held identity close.
 path=root/'dir';path.mkdir();(path/'child').write_bytes(b'x');st=path.stat();active_dir=h.native_original.NativePathIdentityPin(path,True,image);active_dir.acquire((st.st_dev,st.st_ino));wrapper=SimpleNamespace(_backend=active_dir,snapshot=active_dir.snapshot)
 result=h.native_original.remove_directory(path,(st.st_dev,st.st_ino),wrapper,image)
 assert result['status']=='error'and result['error']['errno']!=0;check('directory-actual-not-empty',dw(result),result)
 (path/'child').unlink();result=h.native_original.remove_directory(path,(st.st_dev,st.st_ino),wrapper,image);assert result['status']=='removed';check('directory-actual-removed',dw(result),result)
 # One real native task with no library, an actual native fd, and owned path.
 path=root/'task';path.write_bytes(b'elf fixture');st=path.stat();pin=h.native_original.NativePathIdentityPin(path,False,image);pin.acquire((st.st_dev,st.st_ino));wrapper=SimpleNamespace(_backend=pin,snapshot=pin.snapshot,release_succeeded=pin.release_succeeded)
 fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC)
 task=h.native_original.NativeRetirement(17,'actual retired',path,(st.st_dev,st.st_ino),None,{},fd,wrapper)
 check('task-before-attempt',tw(task),task.snapshot());task.attempt();check('task-after-attempt',tw(task),task.snapshot());assert not path.exists()
 # A real state fence uses the previously attested header, never corrupted
 # bytes from the retained memory as renewed resource authority.
 path=root/'fenced';path.write_bytes(b'x');st=path.stat();pin=h.native_original.NativePathIdentityPin(path,False,image);pin.acquire((st.st_dev,st.st_ino));ownedfd=pin.fd
 before=pin._state._words;ctypes.memset(pin._state._buffer,0,8);expected=pin.snapshot();assert pin._state._fenced is not None and pin._state._flags==0 and pin._state._words==before
 check('fenced-last-attested',pw(pin),expected);os.close(ownedfd)
(D/'report.json').write_text(json.dumps({'status':'PASS','cases':len(rows),'native_formatter_sha256':h.sha(fmt.raw),'actual_state_sha256':h.sha(state.raw),'rows':rows},indent=2)+'\n');print('ACTUAL_STATE_PASS',len(rows),flush=True)
