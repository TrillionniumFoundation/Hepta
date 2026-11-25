from pathlib import Path
from hashlib import sha256
import ctypes as C,struct,json,sys,importlib.util,resource
A=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/native-release-closeout-20261124T0740Z');T=Path('/home/qian-qi/.local/state/hia-native-final-custody-20261125');W=A/'native-background-source';B=A/'native-background-submission-v8';D=A/'native-background-submission-final-v1/pack';D.mkdir();sys.path.insert(0,str(W));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
from tools.generate_hia_background_optimizer_submission_packer import reference_object,BRIDGE,HOLES,RELOCATIONS
sp=importlib.util.spec_from_file_location('v',T/'qualify-result-value-core-smoke-v1.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
flat=(B/'background_optimizer_submission_packer.flat').read_bytes();f=m.load(B/'background_optimizer_submission_packer.flat',sha256(flat).hexdigest());policy=(B/'background_optimizer_submission.flat').read_bytes()
rows=[]
def call(raw,on,wn=128,want=None,expected=None):
 s=C.create_string_buffer(raw or b'\0');o=C.create_string_buffer(b'\xa3'*max(on,1),max(on,1));w=C.create_string_buffer(b'\xa4'*max(128,wn),max(128,wn));old=s.raw
 rc=f(s,len(raw),o,on,w,wn);assert s.raw==old
 if want is not None:assert rc==want and o.raw==b'\xa3'*len(o),(rc,want,len(raw),on,wn)
 else:assert rc==len(expected)and o.raw[:rc]==expected,(rc,len(expected),on,wn)
 rows.append({'input_bytes':len(raw),'output_extent':on,'work_extent':wn,'return':rc,'passed':True})
for body in(b'\xc3',b'\x90'*15,b'\x90'*16,policy,b'\x90'*(4<<20)):
 exp=reference_object([body]);raw=struct.pack('<8sQQ',b'HIABSMP1',1,len(body))+body;call(raw,len(exp),expected=exp)
raw=struct.pack('<8sQQ',b'HIABSMP1',1,len(policy))+policy;exp=reference_object([policy])
for n in(0,1,127,len(exp)-1):call(raw,n,want=0xfffffffe)
for wn in(0,1,127):call(raw,len(exp),wn,want=0xfffffffe)
bad=[raw[:n]for n in(0,1,7,8,15,16,23)]+[raw[:-1],raw+b'x']
for at,val in[(0,0),(8,0),(8,2),(16,0),(16,len(policy)-1),(16,len(policy)+1),(16,(4<<20)+1),(16,(1<<64)-1)]:
 r=bytearray(raw);struct.pack_into('<Q',r,at,val);bad.append(bytes(r))
for x in bad:call(x,len(exp),want=0xffffffff)
assert (B/'submission.o').read_bytes()==exp
report={'passed':True,'whole_background_closed':False,'count':len(rows),'native_packer_sha256':sha256(flat).hexdigest(),'native_policy_sha256':sha256(policy).hexdigest(),'mechanical_template_sha256':sha256(BRIDGE).hexdigest(),'policy_fixup':HOLES,'native_import_relocations':RELOCATIONS,'cases':rows}
(D/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('BG_SUBMISSION_NATIVE_PACK_PASS',len(rows),flush=True)
