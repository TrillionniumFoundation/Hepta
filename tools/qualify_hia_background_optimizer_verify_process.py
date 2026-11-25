from pathlib import Path
import ctypes as C,fcntl,json,os,sys,struct,time
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');P=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z/native-multiversion-proof-source');D=T/'verify-process-unlimited-v1';D.mkdir(exist_ok=False);sys.path.insert(0,str(P))
from tools.qualify_hia_multiversion_prepare_process import Process,sealed,NONE
p=Process(T/'verify-process-native-v5/component.so');fd=sealed((T/'verify-process-regression-v6/child-fixture').read_bytes());rows=[]
def call(role,body,*,deadline=0,magic=b'HIAMVPS2',bad=False,cancel=None):
 b=struct.pack('<8s15Q',magic,role,fd,deadline,len(body),67108864,67108864,0,C.addressof(cancel) if cancel is not None else 0,*([0]*7))+body;s=C.create_string_buffer(b);o=C.create_string_buffer(b'J'*128);w=C.create_string_buffer(20<<20);start=time.monotonic_ns();r=p.f(s,len(b),o,128,w,len(w));elapsed=time.monotonic_ns()-start
 if bad:
  assert r==0xfffffffd and o.raw[:128]==b'J'*128;return {'role':role,'rejected':True}
 h=struct.unpack_from('<8s15Q',o.raw);assert r==h[1] and h[0]==b'HIAMVPO1';got=[]
 if r==0:
  assert h[12:15]==(1,7,15)
  for f,n in zip(h[6:8],h[8:10]):
   assert fcntl.fcntl(f,fcntl.F_GET_SEALS)==15;got.append(os.pread(f,n,0));os.close(f)
 else:assert h[6:8]==(NONE,NONE)
 if h[2]:
  try:os.waitpid(h[2],os.WNOHANG)
  except ChildProcessError:pass
  else:raise AssertionError('unreaped')
 return {'role':role,'status':r,'wait':h[3],'wall_ns':elapsed,'stdout':got[0].hex()if got else '', 'stderr':got[1].hex()if got else ''}
for role in(1,4):
 body=struct.pack('<4Q',2,150,11,0);baseline=set(os.listdir('/proc/self/fd'));x=call(role,body);assert x['status']==0 and os.waitstatus_to_exitcode(x['wait'])==11 and x['wall_ns']>=140000000;assert set(os.listdir('/proc/self/fd'))==baseline;rows.append(x)
 timed=call(role,body,magic=b'HIAMVPS1',deadline=time.monotonic_ns()+10000000);assert timed['status']==1;rows.append(timed)
 for end in(1,time.monotonic_ns()+10**9):rows.append(call(role,body,deadline=end,bad=True))
for role in(0,2,3,5):rows.append(call(role,struct.pack('<4Q',0,0,0,0),bad=True))
rows.append(call(1,struct.pack('<4Q',0,0,0,0),magic=b'HIAMVPS1',bad=True))
cancel=C.c_uint64(1);x=call(1,struct.pack('<4Q',0,0,0,0),cancel=cancel);assert x['status']==2;rows.append(x)
os.close(fd);(D/'report.json').write_text(json.dumps({'passed':True,'count':len(rows),'cases':rows},indent=2)+'\n');print('VERIFY_PROCESS_UNLIMITED_PASS',len(rows),flush=True)
