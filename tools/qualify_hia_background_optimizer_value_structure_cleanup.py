from pathlib import Path
from hashlib import sha256
import ctypes as C,importlib.util,json,os,sys,struct,resource,copy,random,math,time
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125')
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');W=A/'native-multiversion-proof-source'
D=T/'verify-value-structure-cleanup-v1';D.mkdir(exist_ok=False);sys.path.insert(0,str(W));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
spec=importlib.util.spec_from_file_location('values_client',T/'qualify-result-value-core-smoke-v1.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
from hepta.hia_program import _structure,_bounded_detached_snapshot,HIAProgramRejected
from tools.generate_hia_background_optimizer_value_structure import ERRORS,C as K
policy=m.load(T/'verify-value-structure-v5/value-structure.flat','8ac533174506bb5dea7206fae1b0031d32d4d86e6c31c94d6ba241d7bf48e944')
value_entry=m.load(T/'result-value-native-v4/result-value.flat','6d769f3369ceaebed9602a784166548ed2cf48fed608a80a572b1a9c73cc3a7c')
threshold=(W/'examples/hia_bootstrap/background_optimizer_integer_threshold.hiadat').read_bytes()
assert len(threshold)==10100891 and sha256(threshold).hexdigest()=='735f15939ea8fbf91283013a1719773d01018683e1fdb417c3f18ce22f2f1706'
frame=C.create_string_buffer(128+len(threshold));C.memmove(C.addressof(frame)+128,threshold,len(threshold))
lib=m.lib;lib.munmap.argtypes=(C.c_void_p,C.c_size_t);lib.munmap.restype=C.c_int
extent=96<<20;out=lib.mmap(None,extent,3,0x22,-1,0);assert out not in(None,C.c_void_p(-1).value)
def read(off,n=8):return C.string_at(out+off,n)
def get(off):return struct.unpack('<Q',read(off))[0]
def put(off,value):C.memmove(out+off,struct.pack('<Q',value),8)

rows=[]
def drive(v,mode,root,fail_at=None,mutate=None,retry=False):
 h=bytearray(128);h[:8]=b'HIABTC02' if retry else b'HIABTC01';struct.pack_into('<Q',h,8,2 if retry else mode);struct.pack_into('<3Q',h,16,*((0,0,0) if retry else root));struct.pack_into('<QQ',h,40,4300,len(threshold));C.memmove(frame,bytes(h),128)
 ctx=C.create_string_buffer(128);struct.pack_into('<8s3Q',ctx,0,b'HIABVC01',C.cast(value_entry,C.c_void_p).value,C.addressof(v.ctx),256)
 if not retry:C.memset(out,0,4096)
 calls=0;failures=0;dropcalls=0;mutated=False
 while True:
  rc=policy(frame,len(frame),out,extent,ctx,128)
  if rc==0:break
  if rc==10:continue
  assert rc==4,(rc,get(K['PHASE']))
  args=[get(16+i*8) for i in range(6)];mask=get(8)
  for i in (0,2,4):args[i]+=[0,C.addressof(ctx),C.addressof(frame),out][mask>>(i*2)&3]
  op=struct.unpack('<Q',C.string_at(args[0]+8,8))[0]
  if mutate and not mutated and op==23:
   mutate();mutated=True
  bad=op==6 and dropcalls==fail_at
  if op==6:dropcalls+=1
  old=C.string_at(v.ctx,8)
  if bad:C.memset(v.ctx,0,8)
  try:
   rc=value_entry(*args);calls+=1
   if bad:
    failures+=1;assert struct.unpack('<Q',C.string_at(args[2]+8,8))[0]!=0
  finally:
   if bad:C.memmove(v.ctx,old,8)
  put(K['FEEDBACK'],rc)
 head=struct.unpack('<8s15Q',read(0,128))
 return head,calls,dropcalls,failures
for mode in (0,1):
 v=m.Values(entry=value_entry);root=v.empty(list)
 for i in range(4):v.call(16,root,v.scalar(i))
 head,calls,drops,failures=drive(v,mode,root,fail_at=1)
 assert head[1]==3 and head[13]==1 and failures==1,(mode,head)
 head2,calls2,drops2,failures2=drive(v,mode,root,retry=True)
 assert head2[1]==0 and head2[13]==0 and drops2==1,(mode,head2,drops2)
 cap=tuple(head2[3:6]);assert cap[0];v.held.append(cap)
 v.finish()
 rows.append({'group':'ordinary-owned-row','mode':mode,'passed':True,'initial_calls':calls,'retry_calls':calls2,'only_failed_ref_retried':drops2})
 print('TYPED_CLEANUP_ROW_PASS',mode,calls,calls2,flush=True)
v=m.Values(entry=value_entry);root=v.take(v.call(1,tail=b'['+b'null,'*262142+b'null]'))
leaf=v.scalar(None)
head,calls,drops,failures=drive(v,0,root,fail_at=0,mutate=lambda:v.call(16,root,leaf))
assert head[1]==3 and head[2]==2 and head[13]==1 and get(K['OVERFLOW_N'])==262144,(head,get(K['OVERFLOW_N']))
assert get(K['RP']+8192+40)!=0 and get(K['RP']+8192+64+40)==0
head2,calls2,drops2,failures2=drive(v,0,root,retry=True)
assert head2[1]==1 and head2[2]==2 and head2[13]==0 and drops2==1 and get(K['OVERFLOW_N'])==0,(head2,drops2)
v.finish()
rows.append({'group':'actual-concurrent-growth-overflow','passed':True,'captured_refs':262144,'initial_calls':calls,'retry_calls':calls2,'only_failed_ref_retried':drops2})
assert lib.munmap(out,extent)==0
report={'passed':True,'count':len(rows),'fault':'Temporary actual value-context lifecycle invalidation for one native drop; restored before cleanup retry. No mocked provider return.','cases':rows}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print('TYPED_CLEANUP_ALL_PASS',len(rows),flush=True)
