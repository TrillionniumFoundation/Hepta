"""External native Worker CLI fixtures; complete Worker installation is a separate gate."""
FIXTURE_OWNER = r'''.intel_syntax noprefix
.text
.global _start
_start:
    mov eax,5
    xor edi,edi
    lea rsi,[rip+status]
    syscall
    test rax,rax
    jne bad
    mov r13,[rip+status+48]
    cmp r13,288
    jb bad
    cmp r13,2097152
    ja bad
    mov eax,72
    xor edi,edi
    mov esi,1034
    syscall
    cmp eax,15
    jne bad
    xor r15d,r15d
reading:
    mov eax,0
    xor edi,edi
    lea rsi,[rip+payload]
    add rsi,r15
    mov rdx,r13
    sub rdx,r15
    syscall
    test rax,rax
    jle bad
    add r15,rax
    cmp r15,r13
    jb reading
    movabs rax,0x31304e4957414948
    cmp [rip+payload],rax
    jne bad
    mov eax,110
    syscall
    cmp rax,[rip+payload+8]
    jne bad
    lea r12,[rip+payload]
    mov rax,[r12+104]
    add rax,[r12+112]
    add rax,288
    mov rcx,[r12+rax+24]
    cmp rcx,1
    ja bad
    add rcx,11
    mov [rip+fd_count],rcx
    lea rsi,[rip+payload]
    mov rdx,r13
    call write_all
    lea r14,[rip+evidence]
    movabs rax,0x3130445645414948
    mov [r14],rax
    xor ebx,ebx
descriptors:
    lea r12,[rip+payload]
    cmp ebx,10
    jb header_descriptor
    mov rax,[r12+104]
    add rax,[r12+112]
    add rax,288
    cmp ebx,10
    je package_descriptor
    add rax,[r12+rax+16]
    mov r12,[r12+rax+72]
    jmp descriptor_ready
package_descriptor:
    mov r12,[r12+rax+8]
    jmp descriptor_ready
header_descriptor:
    mov r12,[r12+24+rbx*8]
descriptor_ready:
    imul r15,rbx,160
    lea r15,[r14+r15+8]
    mov eax,5
    mov rdi,r12
    mov rsi,r15
    syscall
    test rax,rax
    jne bad
    mov eax,72
    mov rdi,r12
    mov esi,1034
    syscall
    mov [r15+144],rax
    mov eax,72
    mov rdi,r12
    mov esi,1
    syscall
    mov [r15+152],rax
    test rax,rax
    jne bad
    inc ebx
    cmp rbx,[rip+fd_count]
    jb descriptors
    mov QWORD PTR [r14+1928],15
    xor ebx,ebx
open_fds:
    mov eax,72
    mov edi,ebx
    mov esi,1
    syscall
    test rax,rax
    js next_fd
    bts QWORD PTR [r14+1936],rbx
next_fd:
    inc ebx
    cmp ebx,256
    jb open_fds
    mov rsi,r14
    mov edx,1968
    call write_all
    mov eax,60
    xor edi,edi
    syscall
write_all:
    mov eax,1
    mov edi,1
    syscall
    test rax,rax
    jle bad
    add rsi,rax
    sub rdx,rax
    jne write_all
    ret
bad:
    mov eax,60
    mov edi,65
    syscall
    ud2
.bss
.balign 16
status: .skip 144
payload: .skip 2097152
evidence: .skip 1968

.bss
.balign 8
fd_count: .skip 8
'''
from pathlib import Path
from hashlib import sha256
import json,subprocess,struct,os,fcntl,shutil,time,traceback
import argparse
parser=argparse.ArgumentParser(description='Qualify native Worker CLI custody with an external mechanical owner fixture.')
for name in ('unbound','binder','runner','seed','capture','compiler','output'):
 parser.add_argument('--'+name,type=Path,required=True)
parser.add_argument('--case',action='append')
parser.add_argument('--trace',action='store_true')
args=parser.parse_args()

D=args.output.resolve();D.mkdir(mode=0o700)
unbound=args.unbound.read_bytes();binder=args.binder.resolve()
layout={'prefix_bytes': 976, 'pins': 824, 'metadata': 952, 'holes': {'policy_hole': 428, 'sha_hole': 797}};pin_at=layout['pins']
stub=D/'fixture-owner.S';stub.write_text(FIXTURE_OWNER);obj=D/'owner.o';owner=D/'owner'
subprocess.run(['/usr/bin/as','--64',str(stub),'-o',str(obj)],check=True,capture_output=True)
subprocess.run(['/usr/bin/ld','-static','-nostdlib','-z','noexecstack','-o',str(owner),str(obj)],check=True,capture_output=True)
assets={'hia-worker-install-owner':owner,'hia-subprocess':args.runner,'hia-source-build':args.seed,'hia-source-capture':args.capture}
raws={k:p.read_bytes() for k,p in assets.items()};pins=b''.join(sha256(x).digest() for x in raws.values())
bind_request=b'HIAENBD1'+pins+unbound
r=subprocess.run([str(binder),'build'],input=bind_request,capture_output=True,env={'PATH':''},timeout=30)
assert r.returncode==0 and r.stderr==b'' and len(r.stdout)==len(unbound),(r.returncode,r.stderr,len(r.stdout))
bound=r.stdout
assert bound[:pin_at]==unbound[:pin_at] and bound[pin_at:pin_at+128]==pins and bound[pin_at+128:]==unbound[pin_at+128:]
results=[];record={'scope':'Native Worker CLI custody and binder component fixtures. The mechanical native test owner returns its HIAWIN01 request and descriptor evidence; it does not install a Worker. Full Worker installation qualification is separate.','unbound_sha256':sha256(unbound).hexdigest(),'bound_sha256':sha256(bound).hexdigest(),'binder_sha256':sha256(binder.read_bytes()).hexdigest(),'cases':results}
def save():(D/'results.json').write_text(json.dumps(record,indent=2)+'\n')
def outcome(name,ok,**details):
 item={'case':name,'passed':bool(ok),**details};results.append(item);save();print(json.dumps(item),flush=True)
 if not ok:raise AssertionError(item)
outcome('binding-exact-patch',True)
mutations={
 'binding-wrong-magic':lambda x:b'BADENBD1'+x[8:],
 'binding-zero-owner-pin':lambda x:x[:8]+bytes(32)+x[40:],
 'binding-dirty-pins':lambda x:x[:136+pin_at]+b'x'+x[137+pin_at:],
 'binding-wrong-prefix':lambda x:x[:136+64]+bytes([x[136+64]^1])+x[136+65:],
 'binding-wrong-call':lambda x:x[:136+layout['holes']['policy_hole']]+bytes([x[136+layout['holes']['policy_hole']]^1])+x[137+layout['holes']['policy_hole']:],
 'binding-trailing-data':lambda x:x+b'x',
}
for name,change in mutations.items():
 r=subprocess.run([str(binder),'build'],input=change(bind_request),capture_output=True,env={'PATH':''},timeout=30)
 outcome(name,r.returncode!=0 and r.stdout==b'',rc=r.returncode)
compiler=args.compiler.resolve()
sample_package=D/'package.hiapack';sample_package.write_bytes(bytes(range(251))*713);sample_package.chmod(0o400)
sample_package_pin=sha256(sample_package.read_bytes()).hexdigest()
sample_config=D/'runtime.json';sample_config.write_text(json.dumps({'hia_worker':{'host':'rog'},'hosts':{'rog':{}},'unrelated':{'kept':['yes',1,True,None]}}));sample_config.chmod(0o600)
def install(target,modify=None,raw_entry=bound):
 target.mkdir(mode=0o700)
 for name,raw in raws.items():
  if modify and modify[0]==name:raw=modify[1](raw)
  p=target/name;p.write_bytes(raw);p.chmod(0o500)
 entry=target/'hia-worker-install';entry.write_bytes(raw_entry);entry.chmod(0o500);return entry
base=D/'install';entry=install(base)
r=subprocess.run([str(entry),'--help'],capture_output=True,env={'PATH':''},timeout=10)
outcome('help',r.returncode==0 and r.stdout.startswith(b'usage: hia-worker-install ') and r.stderr==b'',rc=r.returncode)
valid=['fresh','reordered','default-source','sealed-exec','inherited-fd','package-relative','roots-one','roots-unicode','roots-duplicate','roots-maximum','maximum-argv','roots-alias','runtime-config','runtime-config-symlink','runtime-config-large','maximum-argv-config','roots-relative','roots-empty','roots-posix-normalization']
negative=['unbound','wrong-owner-pin','wrong-runner-pin','wrong-seed-pin','wrong-capture-pin','existing-output','unsafe-source-path','invalid-cold-json','compiler-symlink','source-symlink','unknown-option','duplicate-option','invalid-timeout','package-symlink','empty-package','oversized-package','package-directory','wrong-package-pin','short-package-pin','uppercase-package-pin','missing-package','missing-package-pin','duplicate-package','too-many-roots','invalid-root-utf8','runtime-config-empty','runtime-config-directory','duplicate-runtime-config']
if args.case:
 selected=set(args.case)
 if not selected.issubset(set(valid+negative)):raise SystemExit('unknown CLI fixture case')
 valid=[name for name in valid if name in selected]
 negative=[name for name in negative if name in selected]
for case_name in valid+negative:
 case=D/case_name;case.mkdir(mode=0o700)
 source=case/'source';source.mkdir(mode=0o700);(source/'docs').mkdir()
 (source/'a.hepta').write_bytes(b'current source\n');(source/'docs/b.json').write_bytes(b'{"current":true}\n')
 source_map={rel:sha256((source/rel).read_bytes()).hexdigest() for rel in ['a.hepta','docs/b.json']}
 if case_name=='reordered':source_map=dict(reversed(list(source_map.items())))
 if case_name=='unsafe-source-path':source_map['../escape']='0'*64
 cold=case/'cold.json';cold.write_text(json.dumps({'source_manifest':source_map,'ignored':{'x':[1,True,None]}}))
 if case_name=='invalid-cold-json':cold.write_bytes(b'not-json')
 out=case/'out';actual_entry=entry;actual_compiler=compiler;actual_source=source;extra=[]
 actual_package=sample_package;package_pin=sample_package_pin;roots=[];actual_config=None
 if case_name=='package-relative':
  actual_package=case/'package-relative.hiapack';actual_package.write_bytes(sample_package.read_bytes())
  actual_package=Path('../package-relative.hiapack')
 if case_name=='package-symlink':
  actual_package=case/'package-link';actual_package.symlink_to(sample_package)
 if case_name=='empty-package':actual_package=case/'empty';actual_package.write_bytes(b'')
 if case_name=='oversized-package':
  actual_package=case/'oversized'
  with actual_package.open('wb') as stream:stream.truncate((512<<20)+1)
 if case_name=='package-directory':actual_package=source
 if case_name=='wrong-package-pin':package_pin='0'*64
 if case_name=='short-package-pin':package_pin=sample_package_pin[:-1]
 if case_name=='uppercase-package-pin':package_pin=sample_package_pin.upper()
 if case_name=='roots-one':roots=['/worker/one']
 if case_name=='roots-unicode':roots=['/worker/é/汉字/🦉']
 if case_name=='roots-duplicate':roots=['/worker/repeated','/worker/repeated']
 if case_name=='roots-maximum':roots=['/r'+str(i).zfill(2)+'/'+'a'*(4095-5) for i in range(32)]
 if case_name=='maximum-argv':roots=['/worker/'+str(i) for i in range(32)]
 if case_name=='roots-relative':roots=['relative/root','.','../parent']
 if case_name=='roots-empty':roots=['']
 if case_name=='roots-posix-normalization':roots=['/a//./b/','//a/./b','///a//b','relative/./../kept//','////','./.']
 if case_name=='too-many-roots':roots=['/worker/'+str(i) for i in range(33)]
 if case_name=='invalid-root-utf8':roots=[b'/\xc0\xaf']
 if case_name=='roots-alias':roots=['/worker/readonly-alias']
 if case_name in ('runtime-config','runtime-config-symlink','runtime-config-large','maximum-argv-config','runtime-config-empty','runtime-config-directory','duplicate-runtime-config'):actual_config=sample_config
 if case_name=='runtime-config-symlink':
  actual_config=case/'runtime-link';actual_config.symlink_to(sample_config)
 if case_name=='runtime-config-large':
  actual_config=case/'large-runtime.json'
  with actual_config.open('wb') as stream:
   stream.write(b'{"padding":"');stream.write(b'x'*((64<<20)+32769));stream.write(b'","hia_worker":{"host":"rog"},"hosts":{"rog":{}}}')
 if case_name=='runtime-config-empty':actual_config=case/'empty-config';actual_config.write_bytes(b'')
 if case_name=='runtime-config-directory':actual_config=source
 if case_name=='maximum-argv-config':roots=['/worker/'+str(i) for i in range(32)]
 if case_name=='unbound':actual_entry=install(case/'install',raw_entry=unbound)
 roles={'wrong-owner-pin':'hia-worker-install-owner','wrong-runner-pin':'hia-subprocess','wrong-seed-pin':'hia-source-build','wrong-capture-pin':'hia-source-capture'}
 if case_name in roles:actual_entry=install(case/'install',modify=(roles[case_name],lambda raw:raw[:-1]+bytes([raw[-1]^1])))
 if case_name=='existing-output':out.mkdir();(out/'keep').write_text('unchanged')
 if case_name=='compiler-symlink':
  actual_compiler=case/'compiler-link';actual_compiler.symlink_to(compiler)
 if case_name=='source-symlink':
  actual_source=case/'source-link';actual_source.symlink_to(source,target_is_directory=True)
 cmd=[str(actual_entry),'--output',str(out),'--compiler',str(actual_compiler),'--cold-report',str(cold)]
 if case_name!='missing-package':cmd+=['--package',str(actual_package)]
 if case_name!='missing-package-pin':cmd+=['--package-sha256',package_pin]
 if case_name=='duplicate-package':cmd+=['--package',str(actual_package)]
 for root in roots:cmd+=['--readonly-artifact-root' if case_name=='roots-alias' else '--artifact-root',root]
 if actual_config is not None:cmd+=['--runtime-config',str(actual_config)]
 if case_name=='duplicate-runtime-config':cmd+=['--runtime-config',str(actual_config)]
 if case_name in ('maximum-argv','maximum-argv-config'):cmd+=['--timeout-seconds','604800']
 if case_name!='default-source':cmd+=['--source',str(actual_source)]
 if case_name=='unknown-option':cmd+=['--unknown','x']
 if case_name=='duplicate-option':cmd+=['--source',str(source)]
 if case_name=='invalid-timeout':cmd+=['--timeout-seconds','0']
 if case_name=='reordered':
  pairs=[cmd[i:i+2] for i in range(1,len(cmd),2)];cmd=[cmd[0],*[item for pair in reversed(pairs) for item in pair]]
 kwargs={}
 inherited=[]
 if case_name=='sealed-exec':
  fd=os.memfd_create('entry-fixture-sealed',os.MFD_ALLOW_SEALING);os.write(fd,bound);os.fchmod(fd,0o500);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
  inherited.append(fd);kwargs['executable']=f'/proc/self/fd/{fd}'
 if case_name=='inherited-fd':
  fd=os.open(cold,os.O_RDONLY);inherited.append(fd)
 if case_name=='fresh' and args.trace:cmd=['/usr/bin/strace','-f','-qq','-yy','-s','120','-o',str(case/'trace.log'),'-e','trace=process,fcntl,openat2,memfd_create,close_range',*cmd]
 start=time.monotonic();r=subprocess.run(cmd,cwd=source,capture_output=True,env={'PATH':''},pass_fds=tuple(inherited),timeout=30,**kwargs)
 for fd in inherited:os.close(fd)
 (case/'stdout.bin').write_bytes(r.stdout);(case/'stderr').write_bytes(r.stderr)
 if case_name not in valid:
  ok=r.returncode!=0 and r.stdout==b'' and (not out.exists() or case_name=='existing-output')
  if case_name=='existing-output':ok=ok and (out/'keep').read_text()=='unchanged'
  outcome(case_name,ok,rc=r.returncode,seconds=time.monotonic()-start);continue
 try:
  raw=r.stdout;header=struct.unpack_from('<8s15Q',raw);name_len,inv_len=header[13],header[14]
  tail=288+name_len+inv_len;name=raw[288:288+name_len];inventory=raw[288+name_len:tail]
  options,pkgfd,roots_size,reserved=struct.unpack_from('<8s3Q',raw,tail)
  size=tail+64+roots_size+(48 if actual_config is not None else 0)
  assert r.returncode==0 and r.stderr==b'' and len(raw)==size+1968 and header[0]==b'HIAWIN01'
  assert name==b'out' and header[15]==0 and header[1]>=2 and header[2]>time.monotonic_ns()
  assert options==b'HIAWOP01' and reserved==int(actual_config is not None) and raw[tail+32:tail+64].hex()==sample_package_pin
  root_frame=raw[tail+64:tail+64+roots_size];root_count=struct.unpack_from('<Q',root_frame)[0];cursor=8;observed_roots=[]
  for _ in range(root_count):
   n=struct.unpack_from('<Q',root_frame,cursor)[0];cursor+=8;observed_roots.append(root_frame[cursor:cursor+n].decode('utf-8'));cursor+=n
  assert cursor==len(root_frame) and observed_roots==[str(Path(root)) for root in roots] and root_count<=32
  fds=[*header[3:13],pkgfd]
  if actual_config is not None:
   config_tail=tail+64+roots_size;config_magic,config_fd=struct.unpack_from('<8sQ',raw,config_tail)
   assert config_magic==b'HIAWCF01' and raw[config_tail+16:config_tail+48]==sha256(actual_config.read_bytes()).digest()
   fds.append(config_fd)
  assert len(set(fds))==11+int(actual_config is not None) and min(fds)>=3
  assert raw[128:288]==b''.join(sha256(x).digest() for x in [raws['hia-subprocess'],raws['hia-source-build'],raws['hia-source-capture'],compiler.read_bytes(),cold.read_bytes()])
  magic,count=struct.unpack_from('<8sQ',inventory);assert magic==b'HIASPI01' and count==2
  cursor=16;observed={}
  for i in range(count):
   n=struct.unpack_from('<Q',inventory,cursor)[0];pin=inventory[cursor+8:cursor+40].hex();key=inventory[cursor+40:cursor+40+n].decode();observed[key]=pin;cursor+=40+n
  assert cursor==len(inventory) and list(observed)==sorted(observed) and observed==source_map
  evidence=raw[size:];assert evidence[:8]==b'HIAEVD01' and struct.unpack_from('<Q',evidence,1928)[0]==15
  for i in range(len(fds)):
   st=evidence[8+i*160:8+(i+1)*160];mode,uid=struct.unpack_from('<II',st,24);seals,flags=struct.unpack_from('<QQ',st,144)
   assert flags==0
   if 3<=i<=7 or i>=10:assert mode&0xf000==0x8000 and seals==15 and mode&0o777==(0o500 if i<=5 else 0o400)
   else:assert mode&0xf000==0x4000
   if i in (1,2,9):assert mode&0o777==0o700 and uid==os.getuid()
   if i==10:assert struct.unpack_from('<Q',st,48)[0]==sample_package.stat().st_size
   if i==11:assert struct.unpack_from('<Q',st,48)[0]==actual_config.stat().st_size
  for i,path in [(0,source),(8,case),(9,out)]:
   st=evidence[8+i*160:];actual=os.stat(path);assert struct.unpack_from('<QQ',st)==(actual.st_dev,actual.st_ino)
  bitmap=int.from_bytes(evidence[1936:1968],'little');assert {i for i in range(256) if bitmap>>i&1}==set([0,1,2,*fds])
  outcome(case_name,True,rc=r.returncode,request_bytes=size,files=count,seconds=time.monotonic()-start)
 except BaseException:
  outcome(case_name,False,rc=r.returncode,stdout_bytes=len(r.stdout),stderr=r.stderr.decode(errors='replace'),error=traceback.format_exc())

# These test owners are controlled mechanical Linux fixtures, not release
# implementations. They exercise the public CLI's response to terminal failures.
if not args.case:
 import signal,ctypes
 fault_modes=('reject','replacement','nonempty','signal','parent-death')
 marker='    lea rsi,[rip+payload]\n    mov rdx,r13\n    call write_all\n'
 exit_bad='    mov eax,60\n    mov edi,65\n    syscall\n'
 for mode in fault_modes:
  case=D/('owner-'+mode);case.mkdir(mode=0o700)
  assembly=''
  if mode=='replacement':
   assembly='''    lea r12,[rip+payload]
    mov r12,[r12+88]
    mov eax,264
    mov rdi,r12
    lea rsi,[rip+fault_out]
    mov rdx,r12
    lea r10,[rip+fault_moved]
    syscall
    test rax,rax
    jne bad
    mov eax,258
    mov rdi,r12
    lea rsi,[rip+fault_out]
    mov edx,448
    syscall
    test rax,rax
    jne bad
'''+exit_bad
  elif mode=='nonempty':
   assembly='''    lea r12,[rip+payload]
    mov rdi,[r12+96]
    mov eax,257
    lea rsi,[rip+fault_keep]
    mov edx,131266
    mov r10d,384
    syscall
    test rax,rax
    js bad
    mov rdi,rax
    mov eax,3
    syscall
'''+exit_bad
  elif mode=='signal':
   assembly='''    mov eax,39
    syscall
    mov rdi,rax
    mov eax,62
    mov esi,15
    syscall
    jmp bad
'''
  elif mode=='parent-death':
   assembly='''    mov eax,39
    syscall
    mov [rip+status],rax
    lea r12,[rip+payload]
    mov rdi,[r12+88]
    mov eax,257
    lea rsi,[rip+fault_started]
    mov edx,131266
    mov r10d,384
    syscall
    test rax,rax
    js bad
    mov r12,rax
    mov eax,1
    mov rdi,r12
    lea rsi,[rip+status]
    mov edx,8
    syscall
    cmp rax,8
    jne bad
    mov eax,3
    mov rdi,r12
    syscall
fault_wait:
    mov eax,34
    syscall
    jmp fault_wait
'''
  else:assembly=exit_bad
  native_source=FIXTURE_OWNER.replace(marker,assembly,1)+'''\n.section .rodata
fault_out: .asciz "out"
fault_moved: .asciz "moved"
fault_keep: .asciz "keep"
fault_started: .asciz "started"
'''
  asm=case/'owner.S';obj=case/'owner.o';exe=case/'owner';asm.write_text(native_source)
  subprocess.run(['/usr/bin/as','--64',str(asm),'-o',str(obj)],check=True,capture_output=True)
  subprocess.run(['/usr/bin/ld','-static','-nostdlib','-z','noexecstack','-o',str(exe),str(obj)],check=True,capture_output=True)
  owner_raw=exe.read_bytes();fault_pins=sha256(owner_raw).digest()+pins[32:]
  bind=subprocess.run([str(binder),'build'],input=b'HIAENBD1'+fault_pins+unbound,capture_output=True,env={'PATH':''},timeout=30)
  assert bind.returncode==0 and len(bind.stdout)==len(unbound)
  inst=case/'install';actual_entry=install(inst,modify=('hia-worker-install-owner',lambda old:owner_raw),raw_entry=bind.stdout)
  source=case/'source';source.mkdir(mode=0o700);(source/'source.hepta').write_bytes(b'current')
  cold=case/'cold.json';cold.write_text(json.dumps({'source_manifest':{'source.hepta':sha256(b'current').hexdigest()}}))
  out=case/'out';cmd=[str(actual_entry),'--output',str(out),'--compiler',str(compiler),'--cold-report',str(cold),'--source',str(source),'--package',str(sample_package),'--package-sha256',sample_package_pin]
  if mode in ('nonempty','parent-death'):cmd+=['--runtime-config',str(sample_config)]
  if mode!='parent-death':
   r=subprocess.run(cmd,capture_output=True,env={'PATH':''},timeout=30)
   if mode=='replacement':ok=r.returncode==65 and out.is_dir() and (case/'moved').is_dir()
   elif mode=='nonempty':ok=r.returncode==74 and (out/'keep').is_file()
   else:ok=r.returncode==(143 if mode=='signal' else 65) and not out.exists()
   outcome('owner-'+mode,ok and r.stdout==b'' and r.stderr==b'',rc=r.returncode,output_exists=out.exists())
  else:
   libc=ctypes.CDLL(None,use_errno=True);old_subreaper=ctypes.c_int()
   assert libc.prctl(37,ctypes.byref(old_subreaper),0,0,0)==0
   assert libc.prctl(36,1,0,0,0)==0
   child_pid=None;reaped=False;p=None
   try:
    p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''})
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
     started=case/'started'
     if started.exists() and started.stat().st_size==8:
      child_pid=struct.unpack('<Q',started.read_bytes())[0];break
     if p.poll() is not None:break
     time.sleep(0.01)
    assert child_pid and child_pid!=p.pid
    p.terminate();stdout,stderr=p.communicate(timeout=5)
    deadline=time.monotonic()+3;status=None
    while time.monotonic()<deadline:
     got,status=os.waitpid(child_pid,os.WNOHANG)
     if got==child_pid:reaped=True;break
     time.sleep(0.01)
    ok=p.returncode==-signal.SIGTERM and reaped and os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGTERM and stdout==b'' and stderr==b''
    outcome('owner-parent-death',ok,frontend_rc=p.returncode,owned_child_reaped=reaped,child_wait_status=status)
   finally:
    if p is not None and p.poll() is None:p.kill();p.wait()
    if child_pid and not reaped:
     try:os.kill(child_pid,signal.SIGKILL)
     except ProcessLookupError:pass
     try:os.waitpid(child_pid,0)
     except ChildProcessError:pass
    libc.prctl(36,old_subreaper.value,0,0,0)

record['passed']=True;record['case_count']=len(results);save();(D/'run.rc').write_text('0\n');print('ENTRY_COMPONENT_PASSED',len(results),flush=True)
