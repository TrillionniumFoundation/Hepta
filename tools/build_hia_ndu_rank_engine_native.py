from pathlib import Path
from hashlib import sha256
import ctypes as C,fcntl,json,os,resource,struct,sys
T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');L=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');P=L/'native-multiversion-proof-source';D=T/'ndu-rank-engine-native-v2';D.mkdir(exist_ok=False);sys.path.insert(0,str(P));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
from tools.generate_hia_ndu_rank_engine_packer import ROLES,reference_object,reference_flat
lib=C.CDLL(None);lib.mmap.argtypes=(C.c_void_p,C.c_size_t,C.c_int,C.c_int,C.c_int,C.c_long);lib.mmap.restype=C.c_void_p;lib.munmap.argtypes=(C.c_void_p,C.c_size_t);lib.munmap.restype=C.c_int
FUNC=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))
def read(path,pin):
 raw=path.read_bytes();assert sha256(raw).hexdigest()==pin,(str(path),sha256(raw).hexdigest(),pin);return raw
def function(raw):
 fd=os.memfd_create('rank-engine-native-pack',os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);at=lib.mmap(None,len(raw),5,2,fd,0);os.close(fd);assert at not in(None,C.c_void_p(-1).value);return FUNC(at)
paths={
'main':(T/'ndu-rank-main-v5/ndu_rank_main.flat','b67c6de037c6aa041fa60225f778f1e5f1cbb344ee319b74ec336d997b7b2d34'),
'tasks':(T/'ndu-rank-tasks-v4/ndu_rank_tasks.flat','0a4364fc8f886bd1e862c3cac24c7d9e5028dec670773c0cec8d3d4ac76fb88b'),
'r1':(T/'ndu-rank-json-v4/ndu_rank_json.flat','2e6537acb01c8c2e93c7f7bbcac4f9d0a9fe2e10836d6f56d479c9506f434144'),
'r2':(T/'ndu-rank-canonical-unchanged-v2/ndu_rank_canonical.flat','2b9b658fd0c5211d020b60238472119f136075b3e89f638f84ed0ad7835f4fa0'),
'r3':(T/'ndu-rank-main-v2/ndu_rank_snapshot.flat','c6ab6ba1f7c89117ac687665b2c0489f27ca54740dc900bcd2501f41b99fbf64'),
'r4':(L/'native-background-structure-v3/background_optimizer_structure.flat','501694a31b52ec095f31a6e650e1ca15f7c0999c1cee62c6afcbe077a838afde'),
'r5':(L/'native-background-freeze-v2/background_optimizer_freeze.flat','f32bf4a811481a3baa007919710549a8e231caa3cb44c6afcb180f4c124d210d'),
'r6':(T/'ndu-rank-admission-staged-v2/ndu_rank_admission.flat','18c70f0fb94c80d386b3f5eabb6accef4989c78cb4f4f76b93b27126f2aab2e1'),
'r7':(T/'ndu-rank-binary64-v1/agent_binary64.flat','9184c68f231af5e42a0b2a419700d0601390fbbe4942387777d80e55f012559a'),
'r8':(T/'ndu-rank-binary64-v1/agent_binary64_format.flat','ab4877e353a65a3834cf318bd02ad3ccacb16c2709aebbb669af7ed3b8a6eb2c'),
'r9':(T/'ndu-rank-cost-v1/ndu_rank_cost.flat','f6c4aa1ac0f0de5e0971456d615407d8d67954b6be58fc609e5cdbe7f441d29b'),
'r10':(T/'ndu-rank-clock-budget-v1/ndu_rank_clock_budget.flat','f3dfec793b05805db93a2b4b0e794201b13e495dba40a74909f2bf2117b4902e'),
'r11':(T/'ndu-rank-canonical-unchanged-v2/ndu_rank_unchanged.flat','381902ad4e92287af2491e17ac92b7baca1ac036adeaa8af01d0ef694fb9869a'),
'r12':(T/'ndu-rank-binding-v1/ndu_rank_binding.flat','d8b8b223bbace19a922d15eb6b150c1e27a0f6453161e8e2de7ee90a33702cbd'),
'r13':(T/'ndu-rank-selection-v1/ndu_rank_selection.flat','e4c7125ccc6295fe7fea4188f096a5a65735923e9a8f4f70c7c482bde451271e'),
'r14':(T/'ndu-rank-owner-support-v1/ndu_rank_report.flat','908e9b52943be2e477b045042147751e2e44e9ab9148c1ac40e6ceaba040d720'),
'r15':(T/'ndu-evaluator-qa/owner-main-v1/sha.flat','214aea20ce10da438d1a96e98b0a25ed1151776e1fd577047c336d57cd54ae19'),
'r16':(T/'ndu-rank-owner-support-v1/ndu_rank_process.flat','531319d3fed0853e80d44fe53804a78f75ea2553888d5d3cce36eddf05f1bf88'),
'r17':(T/'ndu-evaluator-qa/native-owner-pack-v6/effects.flat','14abdc26508e5adbdb8dbd301d305599689eb9228d7e65efdb701b2c2f177b0a'),
'r19':(T/'ndu-evaluator-qa/owner-error-v3/flat.bin','0b423516af64a25a3a682f101fba8c92fd0fbd5c724fa3681b5399f69a8d3c2e'),
'r20':(L/'native-background-json-capture-v4/background_optimizer_json_capture.flat','62f62e547a346c631697a4c0ced3385afb78d6a6472a11ecad2e8c57da0faf1f')}
flats=[read(*paths[k])for k in ROLES]
pk=read(T/'ndu-rank-engine-packer-v2/ndu_rank_engine_packer.flat','78a2b66835ecc37c8eb13cdc6db4fabdcc8383e62c59f335801bc3d3517e3a13');pack=function(pk)
def packet(items,mode=0):return b'HIANEP02'+struct.pack('<Q',21)+struct.pack('<21Q',*[len(x)for x in items])+struct.pack('<Q',mode)+b''.join(items)
def call(raw,cap,wn=512):
 s=C.create_string_buffer(raw);o=C.create_string_buffer(b'Q'*(cap+32),cap+32);w=C.create_string_buffer(wn);rc=pack(s,len(raw),C.addressof(o)+16,cap,w,wn);assert o.raw[:16]+o.raw[-16:]==b'Q'*32;return rc,o.raw[16:-16]
rows=[]
for mode,label,expected in [(0,'object',reference_object(flats)),(1,'flat',reference_flat(flats))]:
 raw=packet(flats,mode);rc,actual=call(raw,len(expected));assert rc==len(expected)and actual==expected,(label,rc,len(expected))
 (D/('rank-engine.'+('o'if mode==0 else'flat'))).write_bytes(actual)
 rc,again=call(raw,len(expected));assert again==actual and rc==len(actual)
 rows.append({'case':'native-'+label+'-twice','passed':True,'bytes':len(actual),'sha256':sha256(actual).hexdigest()})
 for cap in(0,1,len(expected)-1):
  rc,out=call(raw,cap);assert rc==0xfffffffe and out==b'Q'*cap;rows.append({'case':label+'-short-'+str(cap),'passed':True})
 for wn in(0,511):
  rc,out=call(raw,128,wn);assert rc==0xfffffffe and out==b'Q'*128;rows.append({'case':label+'-work-'+str(wn),'passed':True})
raw=packet(flats,1)
for label,data in [('empty',b''),('truncated-header',raw[:191]),('short-body',raw[:-1]),('trailing-body',raw+b'x')]:
 rc,out=call(data,1024);assert rc==0xffffffff and out==b'Q'*1024;rows.append({'case':label,'passed':True})
for off,val in[(0,0),(8,20),(8,22),(184,2)]+[(16+i*8,0)for i in range(21)]+[(16+i*8,4194305)for i in range(21)]:
 data=bytearray(raw);struct.pack_into('<Q',data,off,val);rc,out=call(bytes(data),512);assert rc==0xffffffff and out==b'Q'*512,(off,val,rc);rows.append({'case':'invalid-'+str(off)+'-'+str(val),'passed':True})
# Preserved total .text domain is checked before touching output.
big=[b'x'*4194304 if i<4 else b'y'for i in range(21)]
rc,out=call(packet(big,1),64);assert rc==0xffffffff and out==b'Q'*64;rows.append({'case':'preserved-16MiB-total-text-limit','passed':True})
engine=function((D/'rank-engine.flat').read_bytes());s=C.create_string_buffer(65536);o=C.create_string_buffer(b'V'*65536);w=C.create_string_buffer(65536)
cases=[
 ('short-control',C.addressof(s),128,C.addressof(o),65535,0,0),
 ('null-control',C.addressof(s),128,0,65536,0,0),
 ('null-input',0,128,C.addressof(o),65536,0,0),
 ('input-wrap',(1<<64)-64,128,C.addressof(o),65536,0,0),
 ('control-wrap',C.addressof(s),128,C.addressof(o),(1<<64)-1,0,0),
 ('input-control-alias',C.addressof(o),128,C.addressof(o),65536,0,0),
 ('null-work-nonzero',C.addressof(s),128,C.addressof(o),65536,0,65536),
 ('work-zero-extent',C.addressof(s),128,C.addressof(o),65536,C.addressof(w),0),
 ('work-wrap',C.addressof(s),128,C.addressof(o),65536,(1<<64)-32,128),
 ('work-control-alias',C.addressof(s),128,C.addressof(o),65536,C.addressof(o),65536),
 ('work-input-alias',C.addressof(s),128,C.addressof(o),65536,C.addressof(s),65536)]
for label,*args in cases:
 rc=engine(*args);assert rc==0xfffffffd and o.raw[:65536]==b'V'*65536,(label,rc);rows.append({'case':label,'passed':True})
report={'schema':'hepta.hia.ndu-rank-engine.native-pack.v1','passed':True,'count':len(rows),'qualified_as_final_owner':False,'owner_dependency':'v6 selected owner pending final source-custody qualification','input_roles':[{'role':k,'path':str(paths[k][0]),'sha256':paths[k][1],'bytes':len(raw)}for k,raw in zip(ROLES,flats)],'packer_sha256':sha256(pk).hexdigest(),'cases':rows}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('RANK_ENGINE_NATIVE_PACK_PASS',len(rows),len((D/'rank-engine.flat').read_bytes()),sha256((D/'rank-engine.flat').read_bytes()).hexdigest(),flush=True)
