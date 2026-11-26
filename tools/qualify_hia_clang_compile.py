"""Actual native Clang producer qualification; Python is an oracle and driver.

This file covers the private byte-input producer. The public Value coercion,
exception and supplied-IR-record adapters are qualified separately.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,importlib,json,mmap,os,shutil,struct,threading,traceback,unittest
from tools.qualify_hia_clang_capture_faults import isolated
from tools import qualify_hia_clang_stable_file as faults
from tools import generate_hia_clang_compile_packer as spec
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm,HIAProgramLLVMRejected
WORK=512<<20;OUT=(1<<20)+512;NONE=(1<<64)-1
TARGETS=('x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu','riscv64-unknown-linux-gnu')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def small(version=9,count=1):
 fs=[]
 for i in range(count):
  name='calculate'if count==1 else 'function_'+str(count-i).zfill(3)
  fs.append(dict(name=name,params=[dict(name='x',type='u64')],returns=['u64'],effects=[],entry='b0',blocks=[dict(id='b0',params=[dict(name='x',type='u64')],ops=[dict(op='const',args=[],out=[dict(name='seven',type='u64')],attrs=dict(value=7)),dict(op='int.add.wrap',args=['x','seven'],out=[dict(name='r',type='u64')],attrs={})],term=dict(op='ret',values=['r']))]))
 return dict(schema='hepta.hia.program.v'+str(version),module='actual_native_clang_qualification',functions=fs,exports=[f['name']for f in fs])
def guarded(version):
 # A complete disjoint scalar entry guard, as recognized by the unchanged
 # hia_entry_layout.entry_plan oracle; both branches are exercised below.
 def param(name):return dict(name=name,type='usize')
 def arm(name,amount):
  x=name+'_x';k=name+'_k';r=name+'_r'
  return dict(id=name,params=[param(x)],ops=[dict(op='const',args=[],out=[param(k)],attrs=dict(value=amount)),dict(op='int.add.wrap',args=[x,k],out=[param(r)],attrs={})],term=dict(op='ret',values=[r]))
 entry=dict(id='entry',params=[param('x')],ops=[dict(op='const',args=[],out=[param('bound')],attrs=dict(value=31)),dict(op='compare.le',args=['x','bound'],out=[dict(name='eligible',type='bool')],attrs={})],term=dict(op='branch',cond='eligible',then=dict(target='fast',args=['x']),**{'else':dict(target='slow',args=['x'])}))
 fn=dict(name='calculate',params=[param('x')],returns=['usize'],effects=[],entry='entry',blocks=[entry,arm('fast',7),arm('slow',11)])
 return dict(schema='hepta.hia.program.v'+str(version),module='actual_native_clang_guarded_qualification',functions=[fn],exports=['calculate'])
class Client:
 def __init__(self,path):
  self.path=Path(path);self.lib=C.CDLL(str(self.path));self.entry=self.lib.hia_clang_compile
  self.entry.argtypes=[C.c_void_p,C.c_uint64]*3;self.entry.restype=C.c_uint32;self.rows=[]
 def frame(self,raw,destination,tool='/usr/bin/clang-20',target=0,kind=0,layout=0,abi=b''):
  tool=os.fsencode(tool);dest=os.fsencode(destination)
  return b'HIACLB01'+struct.pack('<31Q',0,target,kind,layout,len(raw),len(tool),len(dest),len(abi),*([0]*23))+raw+tool+dest+abi
 def raw(self,raw,destination,**kw):
  s=Session(self);before=set(os.listdir('/proc/self/fd'))
  try:
   v=s.run(self.frame(raw,destination,**kw));record=dict(header=list(v),receipt=s.receipt,stdout=s.stdout.hex(),stderr=s.stderr.hex())
   self.rows.append(record)
   rv=s.retire();assert rv[43]==1 and rv[44]==1 and rv[45]==0,rv
   assert before==set(os.listdir('/proc/self/fd')),(before,set(os.listdir('/proc/self/fd')))
   record['real_retirement_ack']=True
   return record
  finally:s.close_mapping()
 def compile(self,ir,*,program,output,clang='clang',kind='shared',command_log=None):
  # The original real-process tests supply already constructed typed fixtures.
  # This driver does not implement or claim the public origin/type contract.
  assert command_log is None
  result=self.raw(program.canonical_bytes,Path(os.path.abspath(output)),tool=clang,target=TARGETS.index(ir.target),kind={'shared':0,'object':1}[kind],layout={'canonical':0,'guarded-outline-v1':1}[ir.layout])
  v=result['header']
  if v[1]:
   messages={3:'cross-target builds produce relocatable objects',4:'actual Clang 20+ is required',5:'a new output path in an existing directory is required'}
   raise HIAProgramLLVMRejected(messages.get(v[1],'actual native producer rejected: '+str(v[1:6])))
  receipt=result['receipt']
  assert receipt['core_sha256']==program.sha256 and receipt['llvm_ir_sha256']==ir.sha256
  assert receipt['exports']==list(ir.exports)and receipt['profile']==ir.profile and receipt['target']==ir.target and receipt['entry_layout']==ir.layout
  data=Path(output).read_bytes();assert receipt['artifact_bytes']==len(data)and receipt['artifact_sha256']==hashlib.sha256(data).hexdigest()
  assert receipt['input_sha256']==hashlib.sha256(program.canonical_bytes).hexdigest()
  return receipt
class Session:
 def __init__(self,client):
  self.client=client;self.work=mmap.mmap(-1,WORK);self.wp=C.addressof(C.c_char.from_buffer(self.work));self.output=C.create_string_buffer(OUT);self.header=None;self.receipt=None
 def run(self,wire):
  self.source=C.create_string_buffer(wire);rc=self.client.entry(self.source,len(wire),self.output,OUT,self.wp,WORK);assert rc==0,hex(rc)
  data=bytes(self.output);assert data[:8]==b'HIACLR01';v=struct.unpack('<64Q',data[:512]);self.header=v
  self.receipt=json.loads(data[512:512+v[10]])if v[10]else None
  self.stdout=b''if v[11]==NONE else os.pread(v[11],v[14],0)
  self.stderr=b''if v[12]==NONE else os.pread(v[12],v[15],0)
  return v
 def retire(self):
  wire=b'HIACLB01'+struct.pack('<31Q',1,*([0]*30));src=C.create_string_buffer(wire);o=C.create_string_buffer(512)
  rc=self.client.entry(src,len(wire),o,512,self.wp,WORK);assert rc==0,hex(rc)
  v=struct.unpack('<64Q',bytes(o));assert bytes(o)[:8]==b'HIACLR01'
  if v[44]:assert not any(C.string_at(self.wp,4096))
  return v
 def close_mapping(self):self.work.close()
def original_real_process(client,root):
 mod=importlib.import_module('tests.test_hia_program_llvm');saved=mod.compile_program_llvm;mod.compile_program_llvm=client.compile
 omitted={'test_rehashed_wrong_llvm_is_rejected_before_native_tool_runs','test_aarch64_requires_object_and_target_origin_before_compilation'}
 names=[n for n in unittest.defaultTestLoader.getTestCaseNames(mod.StandaloneHIANativeTests)if n not in omitted]
 assert len(names)==12
 try:
  suite=unittest.TestSuite(mod.StandaloneHIANativeTests(n)for n in names)
  with (root/'original-real-process.log').open('w')as log:result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
 finally:mod.compile_program_llvm=saved
 assert result.wasSuccessful()and result.testsRun==12 and not result.skipped,(result.failures,result.errors)
 return dict(tests=12,names=names,source=pin(Path(mod.__file__).read_bytes()),public_origin_tests_deferred=sorted(omitted),assertions_and_domains_unchanged=True)
def matrix(client,root):
 rows=[]
 for version in range(1,10):
  for target,kind,layout in [(0,0,0),(0,1,0),(1,1,0),(2,1,0),(0,0,1)]:
   program=verify_program(guarded(version)if layout else small(version))
   ir=emit_program_llvm(program,target=TARGETS[target],layout='guarded-outline-v1'if layout else'canonical')
   path=root/('v'+str(version)+'-'+str(target)+'-'+str(kind)+'-'+str(layout)+('.so'if kind==0 else'.o'))
   receipt=client.compile(ir,program=program,output=path,clang='/usr/bin/clang-20',kind='shared'if kind==0 else'object')
   if kind==0:
    lib=C.CDLL(str(path));fn=lib.calculate;fn.argtypes=[C.c_uint64];fn.restype=C.c_uint64
    vectors=[(0,7),(1,8),(31,38),(32,43),(35,46),(NONE,10)]if layout else[(35,42),(NONE,6)]
    from hepta.hia_program_runtime import execute_program
    for argument,expected in vectors:assert fn(argument)==expected==execute_program(program,'calculate',[argument])['values'][0]
   else:
    data=path.read_bytes();assert int.from_bytes(data[18:20],'little')==(62,183,243)[target]
    if target==2:assert int.from_bytes(data[48:52],'little')==5
   rows.append(dict(version=version,target=target,kind=kind,layout=layout,artifact_sha256=receipt['artifact_sha256']))
 return dict(actual_builds=len(rows),rows=rows)
def exports(client,root):
 program=verify_program(small(9,128));rows=[]
 for target in range(3):
  ir=emit_program_llvm(program,target=TARGETS[target]);out=root/('exports128-'+str(target)+'.o')
  receipt=client.compile(ir,program=program,output=out,clang='/usr/bin/clang-20',kind='object')
  assert len(receipt['exports'])==128 and receipt['exports']==sorted(receipt['exports'])
  assert receipt['binary_inventory']['defined']==receipt['exports'];rows.append(target)
 return dict(actual_128_export_targets=rows,no_sixteen_export_restriction=True)
def refusals(client,root):
 raw=verify_program(small()).canonical_bytes;existing=root/'existing';existing.write_bytes(b'keep')
 dangling=root/'dangling';dangling.symlink_to('absent');badparent=root/'file';badparent.write_bytes(b'keep')
 cases=[('missing-compiler',root/'missing.so',dict(tool='/hia-native-clang-absent'),4),('existing',existing,{},5),('dangling',dangling,{},5),('missing-parent',root/'no-parent/a.so',{},5),('file-parent',badparent/'a.so',{},5),('arm-shared',root/'arm.so',dict(target=1),3),('rv-shared',root/'rv.so',dict(target=2),3),('arm-outline',root/'arm.o',dict(target=1,kind=1,layout=1),2)]
 rows=[]
 for name,path,kw,error in cases:
  v=client.raw(raw,path,**kw)['header'];assert v[1]==error,(name,v);rows.append(name)
 assert existing.read_bytes()==b'keep'and dangling.is_symlink()and badparent.read_bytes()==b'keep'
 result=client.raw(b'{"schema":"not-HIA"}',root/'bad-core.so');assert result['header'][1]==1
 assert not(root/'bad-core.so').exists()
 return dict(cases=rows+['invalid-core'],original_namespace_preserved=True)
def native_exports(client,root):
 program=verify_program(small());raw=program.canonical_bytes;exports=[]
 for name in ['hia_program_llvm','hia_program_llvm_metadata']:
  entry=getattr(client.lib,name);entry.argtypes=[C.c_void_p,C.c_uint64]*3;entry.restype=C.c_uint32;exports.append(name)
 work=mmap.mmap(-1,128<<20);wp=C.addressof(C.c_char.from_buffer(work));out=mmap.mmap(-1,16<<20);op=C.addressof(C.c_char.from_buffer(out))
 try:
  wire=b'HIALLV01'+struct.pack('<7Q',0,0,len(raw),0,0,0,0)+raw;src=C.create_string_buffer(wire)
  n=client.lib.hia_program_llvm(src,len(wire),op,16<<20,wp,128<<20);assert n<16<<20
  expected=emit_program_llvm(program).text.encode();assert C.string_at(op,n)==expected
  mwire=b'HIALLM01'+bytes(24);ms=C.create_string_buffer(mwire);mo=C.create_string_buffer(65536)
  n=client.lib.hia_program_llvm_metadata(ms,len(mwire),mo,len(mo),wp,128<<20);assert n>=64 and bytes(mo)[:8]==b'HIALLR01'
  assert struct.unpack_from('<Q',mo,32)[0]==1
 finally:out.close();work.close()
 return dict(actual_exports=exports,same_fixed_llvm_body=True,exact_original_ir=True)
def reuse_and_guards(client,root):
 s=Session(client);raw=verify_program(small()).canonical_bytes;before=set(os.listdir('/proc/self/fd'));values=[]
 try:
  for i in range(3):
   v=s.run(client.frame(raw,root/('reuse-'+str(i)+'.so')));assert v[1]==0,v
   if i==0:
    wire=b'HIACLB01'+struct.pack('<31Q',1,*([0]*30));src=C.create_string_buffer(wire);o=C.create_string_buffer(b'\xa5'*512,512)
    copied=mmap.mmap(-1,WORK);cp=C.addressof(C.c_char.from_buffer(copied));C.memmove(cp,s.wp,4096)
    rc=client.entry(src,len(wire),o,512,cp,WORK);assert rc==0xfffffffd and bytes(o)==b'\xa5'*512;copied.close()
    pid=os.fork()
    if pid==0:
     rc=client.entry(src,len(wire),o,512,s.wp,WORK);os._exit(0 if rc==0xfffffffd and bytes(o)==b'\xa5'*512 else 1)
    _,status=os.waitpid(pid,0);assert os.WIFEXITED(status)and os.WEXITSTATUS(status)==0
   rv=s.retire();assert rv[43]==1 and rv[44]==1 and rv[45]==0;values.append(v[1])
   assert set(os.listdir('/proc/self/fd'))==before
 finally:s.close_mapping()
 return dict(actual_reuse_calls=len(values),copied_context_refused=True,forked_context_refused=True,caller_mapping_shared=True,private_capture_contexts=True,fd_balanced=True)
def wire_guards(client,root):
 raw=verify_program(small()).canonical_bytes;wire=client.frame(raw,root/'guard.so');s=Session(client);out=C.create_string_buffer(b'\xa5'*OUT,OUT)
 cases=[wire[:255],wire[:-1],wire+b'x']
 for at,value in [(0,0),(8,2),(16,3),(24,2),(32,2),(40,0),(48,1<<63),(56,0),(64,1),(72,1),(248,1)]:
  bad=bytearray(wire);struct.pack_into('<Q',bad,at,value);cases.append(bytes(bad))
 try:
  for bad in cases:
   src=C.create_string_buffer(bad);rc=client.entry(src,len(bad),out,OUT,s.wp,WORK);assert rc==0xfffffffd and bytes(out)==b'\xa5'*OUT,(hex(rc),bad[:80].hex())
 finally:s.close_mapping()
 assert not(root/'guard.so').exists()
 return dict(actual_no_write_controls=len(cases))
def filtered(client,root,nr,match=None):
 raw=verify_program(small()).canonical_bytes;s=Session(client);before=set(os.listdir('/proc/self/fd'));answers=[];go=threading.Event();done=threading.Event()
 def retry():
  go.wait()
  try:answers.append(s.retire())
  except BaseException as e:answers.append(repr(e))
  finally:done.set()
 thread=threading.Thread(target=retry);thread.start();original=faults.spec;faults.spec=spec
 try:
  faults.native_seccomp(client,[(nr,13,match)]);v=s.run(client.frame(raw,root/('kernel-'+str(nr)+'.so')));assert v[1]!=0 and v[2]==13,v
  if nr in (11,436):
   first=s.retire();assert first[43]==1 and first[44]==0 and first[45]==1,first
  go.set();assert done.wait(10);thread.join()
  assert len(answers)==1 and isinstance(answers[0],tuple)and answers[0][43]==1 and answers[0][44]==1 and answers[0][45]==0,answers
  assert set(os.listdir('/proc/self/fd'))==before
 finally:
  faults.spec=original
  if not done.is_set():go.set();thread.join(10)
  s.close_mapping()
 return dict(actual_syscall=nr,actual_errno=13,actual_unfiltered_thread_retirement=True,fd_balanced=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(mode=0o700)
 client=Client(a.library);rows=[];report=dict(schema='hia.native-clang-private-producer.qualification.v1',passed=False,private_byte_producer_qualified=False,public_value_frontend_qualified=False,whole_public_runtime_qualified=False,product=pin(a.library.read_bytes()),groups=rows,actual_calls=client.rows)
 def save():(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 def group(name,fn):
  result=fn();rows.append(dict(name=name,passed=True,result=result));save();print('CLANG_NATIVE_GROUP_PASS',name,flush=True)
 try:
  group('original-real-process-and-native-allocator',lambda:original_real_process(client,a.output))
  group('core1-through9-three-targets-both-x86-layouts',lambda:matrix(client,a.output))
  group('actual128export-inventory-three-targets',lambda:exports(client,a.output))
  group('actual-failures-and-output-preservation',lambda:refusals(client,a.output))
  group('same-component-llvm-exports',lambda:native_exports(client,a.output))
  group('reused-context-shared-mapping-and-owner-guards',lambda:reuse_and_guards(client,a.output))
  group('wire-no-write-controls',lambda:wire_guards(client,a.output))
  for nr,match in [(9,(1,393216)),(318,None),(258,None),(86,None),(11,None),(436,None)]:
   rows.append(isolated('kernel-'+str(nr),lambda nr=nr,match=match:filtered(client,a.output,nr,match)));save();print('CLANG_NATIVE_KERNEL_PASS',nr,flush=True)
  report['passed']=True;report['private_byte_producer_qualified']=True
 except BaseException as e:report['failure']=repr(e);report['traceback']=traceback.format_exc();raise
 finally:save()
 print('CLANG_NATIVE_PRIVATE_PRODUCER_PASS',len(rows),len(client.rows),flush=True)
if __name__=='__main__':main()
