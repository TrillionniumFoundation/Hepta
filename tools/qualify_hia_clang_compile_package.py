"""Native package, relocatability and publication identity controls.

Python only assembles QA requests, copies isolated fixtures and observes actual
native calls; it supplies no implementation identity or native policy result.
"""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,mmap,os,queue,select,shutil,struct,threading,traceback
from tools.qualify_hia_clang_compile import Client,Session,small,pin
from tools.qualify_hia_clang_capture_faults import isolated
from tools import generate_hia_clang_compile_packer as spec
from tools import qualify_hia_native_seccomp_notify as notify
from hepta.hia_program import verify_program
from hepta.hia_program_llvm import emit_program_llvm
def parts(build):
 names={name:'clang_compile_'+name+'.flat'for name in spec.ROLES[:11]}
 names.update(hash='native_scalar_proof_hash.flat',admission='core_admission.flat',canonical='json_canonical.flat',llvm_meta='program_llvm_metadata.flat',object='clang_object_inventory.flat',shared='safe_core_elf_inventory.flat',catalog='catalog.bin')
 for role in ['llvm','which','path','file','capture','identity','rmtree']:names[role]=role+'.component'
 return [(build/names[name]).read_bytes()for name in spec.ROLES]
def packer(build):
 body=parts(build);flat=(build/'clang_compile_packer.flat').read_bytes()
 code=mmap.mmap(-1,len(flat),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);code.write(flat)
 entry=C.CFUNCTYPE(C.c_uint32,*([C.c_void_p,C.c_uint64]*3))(C.addressof(C.c_char.from_buffer(code)))
 work=C.create_string_buffer(2048);controls=[]
 def frame(body,mode=0):return b'HIACLPP2'+struct.pack('<27Q',25,*map(len,body),mode)+b''.join(body)
 def run(raw,capacity):
  src=C.create_string_buffer(raw);out=C.create_string_buffer(b'\xa5'*capacity,capacity)
  rc=entry(src,len(raw),out,capacity,work,len(work));return rc,bytes(out)
 try:
  wire=frame(body)
  for mode,name in [(0,'clang-compile.o'),(1,'clang-compile.flat')]:
   expected=(build/name).read_bytes();rc,data=run(frame(body,mode),len(expected));assert rc==len(expected)and data==expected,(mode,rc)
  bad=[('short',wire[:223]),('truncated',wire[:-1]),('trailing',wire+b'x')]
  for name,at,value in [('magic',0,0),('count',8,24),('mode',216,2)]+[(role+'-'+kind,16+8*i,value)for i,role in enumerate(spec.ROLES)for kind,value in [('zero',0),('oversize',4194305)]]:
   candidate=bytearray(wire);struct.pack_into('<Q',candidate,at,value);bad.append((name,bytes(candidate)))
  for name,raw in bad:
   rc,data=run(raw,512);assert rc==0xffffffff and data==b'\xa5'*512,(name,hex(rc));controls.append(name)
  huge=frame([bytes(4194304)for _ in spec.ROLES]);rc,data=run(huge,512);assert rc==0xffffffff and data==b'\xa5'*512;controls.append('original16MiBtext-bound')
  for mode,name in [(0,'clang-compile.o'),(1,'clang-compile.flat')]:
   n=(build/name).stat().st_size-1;rc,data=run(frame(body,mode),n);assert rc==0xfffffffe and data==b'\xa5'*n;controls.append('short-output-'+str(mode))
 finally:code.close()
 return dict(native_pack_modes=2,controls=controls,original_role_limit=4194304,original_text_limit=16777216,atomic_rejections=True)
def relocated(package,root):
 clone=Path(os.fsdecode(os.fsencode(root)+b'/relocated-\xff-package'));clone.mkdir()
 shutil.copytree(package/'source',clone/'source');(clone/'build').mkdir();shutil.copy2(package/'build/clang-compile.so',clone/'build/native-compiler.so')
 outside=root/'unrelated-working-directory';outside.mkdir();saved=Path.cwd()
 program=verify_program(small());ir=emit_program_llvm(program);before=set(os.listdir('/proc/self/fd'))
 try:
  os.chdir(outside);client=Client(clone/'build/native-compiler.so')
  receipt=client.compile(ir,program=program,output=root/'relocated.so',clang='clang')
 finally:os.chdir(saved)
 assert set(os.listdir('/proc/self/fd'))==before
 assert receipt['toolchain']['path']==str(Path(shutil.which('clang')).resolve())
 assert receipt['toolchain']['sha256']==hashlib.sha256(Path(receipt['toolchain']['path']).read_bytes()).hexdigest()
 assert not any(p.name.startswith('.hia-native-')for p in root.iterdir())
 return dict(package=str(clone),default_clang_resolved_and_executed=True,source_discovery_from_actual_image=True,unrelated_cwd=True,raw_filesystem_surrogate=True,receipt=receipt,fd_balanced=True)
def concurrent(package,root):
 client=Client(package/'build/clang-compile.so');raw=verify_program(small()).canonical_bytes;before=set(os.listdir('/proc/self/fd'));barrier=threading.Barrier(4);rows=[];errors=[]
 def worker(index):
  s=Session(client)
  try:
   barrier.wait()
   v=s.run(client.frame(raw,root/('concurrent-'+str(index)+'.so')));assert v[1]==0,v
   rows.append(dict(index=index,artifact=s.receipt['artifact_sha256']))
   rv=s.retire();assert rv[43]==1 and rv[44]==1 and rv[45]==0,rv
  except BaseException as e:errors.append(repr(e))
  finally:s.close_mapping()
 threads=[threading.Thread(target=worker,args=(i,))for i in range(4)]
 for thread in threads:thread.start()
 for thread in threads:thread.join(180)
 assert not errors and all(not t.is_alive()for t in threads),(errors,rows)
 assert len(rows)==4 and len({r['artifact']for r in rows})==1,rows
 assert set(os.listdir('/proc/self/fd'))==before
 return dict(actual_parallel_contexts=4,rows=rows,fd_balanced=True)
def stale_source(package,root):
 clone=root/'staleness-package';shutil.copytree(package/'source',clone/'source');(clone/'build').mkdir();shutil.copy2(package/'build/clang-compile.so',clone/'build/compiler.so')
 source=clone/'source/examples/hia_bootstrap/clang_compile_owner.hepta';original=source.read_bytes();source.chmod(0o600)
 client=Client(clone/'build/compiler.so');s=Session(client);raw=verify_program(small()).canonical_bytes;output=root/'stale.so'
 ready=queue.Queue();stop=threading.Event();errors=[];notices=[];before=set(os.listdir('/proc/self/fd'))
 def observer():
  listener=ready.get()
  try:
   while not stop.is_set():
    if not select.select([listener],[],[],.1)[0]:continue
    note=notify.receive(listener)
    if not notices:source.write_bytes(original+b'\n')
    notices.append(dict(nr=note.data.nr,ip=note.data.ip))
    notify.continue_syscall(listener,note)
  except BaseException as e:errors.append(repr(e))
 thread=threading.Thread(target=observer);thread.start();entry=C.cast(client.entry,C.c_void_p).value
 listener=notify.install(entry,entry+len(spec.BRIDGE),86);ready.put(listener)
 try:
  v=s.run(client.frame(raw,output));assert v[1]==10 and v[16]==1 and v[17]==0,(v,notices,errors)
  rv=s.retire();assert rv[43]==1 and rv[44]==1 and rv[45]==0,rv
 finally:
  stop.set();thread.join(5);os.close(listener);s.close_mapping()
 assert not thread.is_alive()and not errors and len(notices)==1,(errors,notices)
 assert not output.exists()and source.read_bytes()==original+b'\n'
 assert not any(p.name.startswith('.hia-native-')for p in root.iterdir())
 assert set(os.listdir('/proc/self/fd'))==before
 return dict(actual_link_kernel_notification=notices,implementation_change_detected=True,only_owned_published_link_withdrawn=True,fd_balanced=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(mode=0o700);rows=[]
 report=dict(schema='hia.native-clang-package-qualification.v1',passed=False,product=pin((a.package/'build/clang-compile.so').read_bytes()),groups=rows,public_value_frontend_qualified=False,whole_public_runtime_qualified=False)
 def save():(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 try:
  rows.append(dict(name='native-packer-original-domain',passed=True,result=packer(a.package/'build')));save();print('CLANG_PACKAGE_PASS packer',flush=True)
  for name,fn in [('actual-image-relative-relocation',relocated),('parallel-real-compilation',concurrent),('post-publication-source-change',stale_source)]:
   directory=a.output/name;directory.mkdir()
   rows.append(isolated(name,lambda fn=fn,directory=directory:fn(a.package,directory)));save();print('CLANG_PACKAGE_PASS',name,flush=True)
  report['passed']=True
 except BaseException as e:report['failure']=repr(e);report['traceback']=traceback.format_exc();raise
 finally:save()
 print('CLANG_PACKAGE_QUALIFICATION_PASS',len(rows),flush=True)
if __name__=='__main__':main()
