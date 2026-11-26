"""Actual artifact capture followed by fresh fixed native LLVM admission."""
from pathlib import Path
import argparse,ast,copy,ctypes as C,hashlib,json,mmap,os,struct
from tools.qualify_hia_multiversion_prepare_intake import abi_bytes
from hepta.hia_program import verify_program,execute_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_multiversion import ScalarABI,_read_artifact
from hepta.elf_shared_abi import inspect_owned_shared_elf
BAD=0xfffffffd;WORK=336<<20;NONE=(1<<64)-1
def pin(data):return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def word(data,at):return struct.unpack_from('<Q',data,at)[0]
def pointer(data):return C.addressof(C.c_char.from_buffer(data))
def invoke(entry,raw,out,work):
 source=C.create_string_buffer(raw);C.memset(out,165,len(out))
 rc=int(entry(source,len(raw),out,len(out),pointer(work),WORK))&0xffffffff
 assert source.raw==raw+b'\0'
 return rc,bytes(out)
def fixture(script):
 tree=ast.parse(script.read_text())
 for node in tree.body:
  if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='program'for t in node.targets):
   return ast.literal_eval(node.value)
 raise AssertionError('actual producer source program is absent')
def wire(path,abi,receipt,facts,core):
 h=bytearray(256);p=os.fsencode(path)
 struct.pack_into('<8s3Q',h,0,b'HIAMVI04',len(p),len(abi),len(receipt))
 for at,key in [(32,'core_sha256'),(64,'input_sha256'),(128,'artifact_sha256')]:
  h[at:at+32]=bytes.fromhex(facts[key])
 struct.pack_into('<Q',h,160,len(core))
 return bytes(h)+p+abi+receipt+core
def original_accepts(path,receipt,facts,abi):
 try:
  raw,inode=_read_artifact(path)
  if receipt.get('core_sha256')!=facts['core_sha256']:return False
  if receipt.get('input_sha256')!=facts['input_sha256']:return False
  if receipt.get('llvm_ir_sha256')!=facts['llvm_ir_sha256']:return False
  if receipt.get('artifact_sha256')!=hashlib.sha256(raw).hexdigest():return False
  if receipt.get('artifact_bytes')!=len(raw):return False
  if receipt.get('target')!='x86_64-unknown-linux-gnu' or receipt.get('kind')!='shared':return False
  inspect_owned_shared_elf(raw,tuple(sig.function for sig in abi))
  return True
 except (OSError,ValueError,TypeError,RuntimeError):return False
class Suite:
 def __init__(self,component,out,artifact,receipt,program):
  self.lib=C.CDLL(str(component));self.entry=self.lib.hia_generation_lease_owner_clang_fresh_image
  self.retire=self.lib.hia_generation_lease_owner_clang_fresh_image_retire
  for f in (self.entry,self.retire):f.argtypes=[C.c_void_p,C.c_uint64]*3;f.restype=C.c_uint32
  self.output=out;self.artifact=artifact.read_bytes();self.receipt=receipt
  self.verified=verify_program(program);self.ir=emit_program_llvm(self.verified)
  self.signatures=(ScalarABI('calculate',('u64',),'u64'),)
  self.abi=abi_bytes(self.verified,self.signatures)
  assert self.receipt['core_sha256']==self.verified.sha256
  assert self.receipt['input_sha256']==self.verified.input_sha256
  assert self.receipt['llvm_ir_sha256']==self.ir.sha256
  assert self.receipt['artifact_sha256']==hashlib.sha256(self.artifact).hexdigest()
  self.rows=[]
 def run(self,label,mutate=None,fact_mutate=None,data_mutate=None,mode='ordinary',wanted=None,core_override=None):
  path=self.output/(label+'.so')
  data=self.artifact if data_mutate is None else data_mutate(self.artifact)
  if mode=='ordinary':path.write_bytes(data)
  elif mode=='symlink':path.symlink_to(self.output/'outside-unchanged.so')
  rec=copy.deepcopy(self.receipt);facts=copy.deepcopy(self.receipt)
  core=self.verified.canonical_bytes if core_override is None else core_override
  if core_override is not None:
   rec['core_sha256']=facts['core_sha256']=hashlib.sha256(core).hexdigest()
   rec['input_sha256']=facts['input_sha256']=hashlib.sha256(core).hexdigest()
  if data_mutate is not None:
   rec['artifact_sha256']=facts['artifact_sha256']=hashlib.sha256(data).hexdigest();rec['artifact_bytes']=len(data)
  if mutate is not None:mutate(rec)
  if fact_mutate is not None:fact_mutate(facts)
  expected=original_accepts(path,rec,facts,self.signatures) if wanted is None else wanted
  # Native artifact facts also bind the producer's actual observed artifact.
  if facts['artifact_sha256']!=rec['artifact_sha256']:expected=False
  encoded=json.dumps(rec,sort_keys=True,separators=(',',':')).encode()
  if mode=='missing-invalid-json':encoded=b'{'
  raw=wire(path,self.abi,encoded,facts,core);output=C.create_string_buffer(512);ret=C.create_string_buffer(768)
  with mmap.mmap(-1,WORK,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS)as work:
   before=set(os.listdir('/proc/self/fd'));rc,head=invoke(self.entry,raw,output,work)
   assert head[:8]==b'HIAMVIR1'and rc==word(head,8),(label,rc,head[:128].hex())
   assert (rc==0)==expected,(label,rc,expected,head[:128].hex())
   if word(head,200)==1:
    fresh=emit_program_llvm(verify_program(core));actual_ir=bytes(work[320<<20:(320<<20)+word(head,192)])
    assert actual_ir==fresh.text.encode('ascii') and head[160:192]==bytes.fromhex(fresh.sha256)
    assert word(head,192)==len(actual_ir)
   if rc==0:
    assert word(head,200)==1 and head[160:192]==bytes.fromhex(self.ir.sha256)
    assert head[64:96]==hashlib.sha256(data).digest()and word(head,48)==len(data)
    assert word(head,56)==1 and word(head,112)==1 and word(head,128)==0
    fn=C.CFUNCTYPE(C.c_uint64,C.c_uint64)(word(head,256))
    results=[fn(35),fn(NONE)];assert results==[42,6]
    for value,result in zip((35,NONE),results):
     assert execute_program(self.verified,'calculate',[value],max_steps=4224)['result']==result
    del fn
   if mode=='missing-invalid-json':assert rc!=12,'receipt parsed before actual missing artifact'
   if mode.startswith('missing') or mode=='symlink':
    assert word(head,200)==0 and work[192<<20:(192<<20)+128]==bytes(128),'LLVM ran before artifact capture'
   retired=[]
   for op in (1,1,2):
    rrc,rhead=invoke(self.retire,struct.pack('<8sQQ',b'HIAMVRT1',op,0),ret,work)
    assert rrc==0 and rhead[:8]==b'HIAMVTR1',(label,op,rrc,rhead[:128].hex())
    if mode=='symlink':
     from tools.qualify_hia_multiversion_retirement import native_summary,original_summary
     from hepta.hia_native_retirement import _ReferencePathIdentityPin,_ReferenceNativeRetirement
     if op==1 and len(retired)==0:
      reference_pin=_ReferencePathIdentityPin(path)
      try:reference_pin.acquire(None)
      except (OSError,ValueError):pass
      reference=_ReferenceNativeRetirement(0,'qualification',path,None,None,{},None,reference_pin)
     if op==1:reference.attempt()
     assert native_summary(ret)==original_summary(reference),(label,native_summary(ret),original_summary(reference))
     assert native_summary(ret)['disk']=='refused_unowned' and not native_summary(ret)['complete']
    else:
     assert word(rhead,24)&8,(label,op,'retirement incomplete',rhead[:128].hex())
    retired.append(pin(rhead))
   assert set(os.listdir('/proc/self/fd'))==before,(label,'descriptor ownership')
   assert word(work,40)==NONE and word(work,48)==NONE and word(work,56)==0
  # A wrong/unacquired path remains a fixture object; native resources are already retired.
  if path.is_symlink():path.unlink()
  if path.exists():path.unlink()
  row=dict(case=label,accepted=rc==0,status=rc,original_accepts=expected,
           response=pin(head),actual_native_retirement=retired,fd_balance=True,
           actual_fresh_llvm=word(head,200)==1,fresh_llvm_bytes=word(head,192),fresh_llvm_sha256=head[160:192].hex())
  self.rows.append(row);print('CLANG_IMAGE_CASE',label,rc,flush=True)
 def guards(self):
  path=self.output/'guard-unopened.so';path.write_bytes(self.artifact)
  raw=wire(path,self.abi,json.dumps(self.receipt).encode(),self.receipt,self.verified.canonical_bytes)
  controls=[('short',raw[:255]),('magic',b'BADMAGIC'+raw[8:]),('trailing',raw+b'0')]
  for at in list(range(96,128,8))+list(range(168,256,8)):
   frame=bytearray(raw);struct.pack_into('<Q',frame,at,1);controls.append(('reserved-'+str(at),bytes(frame)))
  for at,value,label in [(24,1048577,'receipt-limit'),(160,0,'empty-core'),(160,8388609,'core-limit')]:
   frame=bytearray(raw);struct.pack_into('<Q',frame,at,value);controls.append((label,bytes(frame)))
  frame=bytearray(raw);frame[256]=0;controls.append(('path-nul',bytes(frame)))
  before=set(os.listdir('/proc/self/fd'))
  for label,packet in controls:
   with mmap.mmap(-1,WORK,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS)as work:
    output=C.create_string_buffer(512);rc,head=invoke(self.entry,packet,output,work)
    assert rc==BAD and head==b'\xa5'*512,(label,rc,head[:128].hex())
   assert set(os.listdir('/proc/self/fd'))==before,label
  path.unlink()
  return dict(passed=True,cases=len(controls),actual_no_output_write=True)
 def qualify(self):
  outside=self.output/'outside-unchanged.so';outside.write_bytes(self.artifact)
  self.run('actual-clang-mapping-and-vm')
  for field,value in [('core_sha256','00'*32),('input_sha256','00'*32),('llvm_ir_sha256','00'*32),
                      ('artifact_sha256','00'*32),('artifact_bytes',len(self.artifact)+1),
                      ('target','aarch64-unknown-linux-gnu'),('kind','object')]:
   self.run('receipt-'+field,lambda r,k=field,v=value:r.__setitem__(k,v))
  for field in ('core_sha256','input_sha256','artifact_sha256'):
   self.run('actual-binding-'+field,fact_mutate=lambda r,k=field:r.__setitem__(k,'00'*32),wanted=False)
  changed=json.loads(self.verified.canonical_bytes)
  changed['functions'][0]['blocks'][0]['ops'][0]['attrs']['value']=8
  altered=verify_program(changed).canonical_bytes
  assert emit_program_llvm(verify_program(altered)).sha256!=self.ir.sha256
  self.run('fresh-actual-core-differs-from-producer',core_override=altered,wanted=False)
  self.run('fresh-invalid-core-after-capture',core_override=b'{',wanted=False)
  self.run('missing-before-fresh-invalid-core',core_override=b'{',mode='missing-invalid-json',wanted=False)
  self.run('actual-malformed-elf',data_mutate=lambda data:b'BAD!'+data[4:])
  self.run('missing-before-invalid-receipt',mode='missing-invalid-json',wanted=False)
  self.run('symlink-not-followed',mode='symlink',wanted=False)
  assert outside.read_bytes()==self.artifact;outside.unlink()
  return self.guards()
def main():
 p=argparse.ArgumentParser();p.add_argument('--component',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--artifact',type=Path,required=True);p.add_argument('--receipt',type=Path,required=True);p.add_argument('--producer-fixture',type=Path,required=True)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 report=json.loads(a.receipt.read_bytes());assert report['passed'] and report['actual_retirement_ack']
 suite=Suite(a.component,a.output,a.artifact,report['receipt'],fixture(a.producer_fixture));guards=suite.qualify()
 result=dict(schema='hia.generation-lease-owner.clang-fresh-image.v1',passed=True,
             product=pin(a.component.read_bytes()),actual_clang_artifact=pin(a.artifact.read_bytes()),
             producer_report=pin(a.receipt.read_bytes()),groups=suite.rows,guards=guards,
             source=pin(Path(__file__).read_bytes()),actual_native_loaded_function=True,
             actual_artifact_before_fresh_llvm=True,actual_fixed_native_fresh_llvm=True,caller_llvm_digest_not_accepted=True,actual_independent_vm_comparison=True,
             actual_native_same_holder_retirement=True,whole_public_runtime_qualified=False,
             public_runtime_constructor_qualified=False)
 (a.output/'report.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(dict(passed=True,groups=len(suite.rows)+1,guard_cases=guards['cases'])),flush=True)
if __name__=='__main__':main()
