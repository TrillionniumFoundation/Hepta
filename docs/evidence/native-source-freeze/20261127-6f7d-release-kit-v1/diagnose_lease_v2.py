from pathlib import Path
from hashlib import sha256
import ctypes,mmap,os,fcntl,struct,subprocess,json,time,sys,traceback
R=Path('/home/qian-qi/hia-native-cold-edge-6f7d-20261127-2ac5');S=Path('/home/qian-qi/hia-release-kit-extent-fix-20261127-2ac5/source');D=R/'release-lease-native-diagnostic-v2';D.mkdir(mode=0o700)
sys.path.insert(0,str(S))
from tools.generate_hia_release_owner import template
report={'schema':'hepta.hia.release-lease-native-diagnostic.v1','scope':'external mechanical checkpoint harness; original HIA owner and DAG machine bytes; component diagnostic only','source_base':'6f7dfb2defd8852d2fe58e02ff8c5cf78c5e7807','whole_release_claimed':False,'matching_cold_claimed':False}
def pin(b):return {'bytes':len(b),'sha256':sha256(b).hexdigest()}
def save():(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
fds=[]
def seal(name,b,mode=0o400):
 f=os.memfd_create(name,os.MFD_ALLOW_SEALING);fds.append(f);os.write(f,b);os.fchmod(f,mode);fcntl.fcntl(f,fcntl.F_ADD_SEALS,15);return f
try:
 stagebase=R/'chain/.hia-build-bed45864da51a4a38448d27369efeb15/stage'
 original=(stagebase/'hia-release-owner').read_bytes();prefix,holes=template();labels=['policy_hole','stage_hole','sha_hole']
 starts=[holes[n]+4+struct.unpack_from('<i',original,holes[n])[0] for n in labels];assert starts==sorted(starts) and starts[0]==len(prefix)
 parts=[original[a:b] for a,b in zip(starts,starts[1:]+[len(original)])]
 report['original_owner']=pin(original);report['native_parts']={n:pin(b) for n,b in zip(labels,parts)}
 w=bytearray(4194304);o=bytearray(128)
 def put(a,v):struct.pack_into('<Q',w,a,v)
 for name in ['stage','work','published']:(D/name).mkdir(mode=0o700)
 dirs=[os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW) for p in [S,D/'stage',D/'work',D,D/'published']];fds.extend(dirs)
 cold=(R/'chain/cold/final-cold.json').read_bytes();sources=json.loads(cold)['source_manifest'];changed='examples/hia_bootstrap/release_stage_generation_lease.hiastd';report['source_variant']={changed:{'original':sources[changed],'actual':sha256((S/changed).read_bytes()).hexdigest()}};sources[changed]=report['source_variant'][changed]['actual']
 imagepaths=[stagebase/'hia-subprocess',stagebase/'hia-source-build',stagebase/'hia-source-capture',R/'chain/cold/qualification/base/B3.flat']
 rawcaps=[p.read_bytes() for p in imagepaths]+[cold];caps=[seal('original-cap-'+str(i),b,0o500 if i<3 else 0o400) for i,b in enumerate(rawcaps)]
 inv=bytearray(struct.pack('<8sQ',b'HIASPI01',len(sources)))
 for n,d in sorted(sources.items()):
  e=n.encode();inv+=struct.pack('<Q',len(e))+bytes.fromhex(d)+e
 name=b'published';request=struct.pack('<8s15Q',b'HIAOWN01',0,time.monotonic_ns()+1800_000_000_000,*dirs[:3],*caps,*dirs[3:],len(name),len(inv),0)+b''.join(sha256(b).digest() for b in rawcaps)+name+inv
 reqfd=seal('actual-request',request);(D/'request.bin').write_bytes(request)
 buf=mmap.mmap(-1,len(parts[0]),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC);buf.write(parts[0]);addr=ctypes.addressof(ctypes.c_char.from_buffer(buf))
 f=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)(addr)
 sb=ctypes.create_string_buffer(request);ob=(ctypes.c_ubyte*len(o)).from_buffer(o);wb=(ctypes.c_ubyte*len(w)).from_buffer(w)
 rc=f(ctypes.addressof(sb),len(request),ctypes.addressof(ob),len(o),ctypes.addressof(wb),len(w))
 assert rc==1 and struct.unpack_from('<Q',w)[0]==1,(rc,o[:64].hex())
 composer=(R/'release-frontend-diagnostic-v1/composer-pack.stdout').read_bytes();composerfd=seal('actual-composer',composer,0o500)
 inventory=seal('initial-empty-inventory',struct.pack('<8s2Q',b'HIAINV01',0,0))
 # Publication needs writable retained inventory, not a sealed one.
 inventory=os.memfd_create('diagnostic-inventory',os.MFD_ALLOW_SEALING);fds.append(inventory);os.write(inventory,struct.pack('<8s2Q',b'HIAINV01',0,0))
 values=(stagebase/'hia-result-value.core.bin').read_bytes();vfd=seal('actual-future-value',values,0o500)
 for at,v in {0:5000,8:0,120:composerfd,200:inventory,216:caps[1],224:caps[2],232:caps[0],256:24,3000:len(rawcaps[0]),3008:len(rawcaps[1]),3016:len(rawcaps[2]),3024:len(rawcaps[3]),3032:len(rawcaps[4]),1519984:7,1599904:1,1600000:vfd,1600008:len(values),1600016:len(b'hia-result-value.core.bin')}.items():put(at,v)
 w[1600032:1600032+len(b'hia-result-value.core.bin')]=b'hia-result-value.core.bin'
 statefd=seal('initial-native-state',w)
 os.dup2(statefd,1000);fds.append(1000)
 dumpfd=os.open(D/'terminal-state.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.dup2(dumpfd,1001);fds.extend([dumpfd,1001])
 source=(S/'tools/hia_release_owner_syscalls.S').read_text()
 source=source.replace('    lea r14,[rax+STATE_BYTES]\nadvance:',"""    lea r14,[rax+STATE_BYTES]
    mov eax,17
    mov edi,1000
    mov rsi,r15
    mov edx,STATE_BYTES
    xor r10d,r10d
    syscall
    cmp rax,STATE_BYTES
    jne invalid
    mov eax,39
    syscall
    mov [r15+16],rax
    mov eax,102
    syscall
    mov [r15+24],rax
advance:
    cmp QWORD PTR [r15],6000
    je diagnostic_complete
    mov rax,[r15]
    mov [r14+128],rax""")
 source=source.replace('stage_action:\n','stage_action:\n    mov rax,[r15]\n    mov [r14+128],rax\n')
 source=source.replace('syscall_action:\n','syscall_action:\n    cmp QWORD PTR [r14],60\n    jne diagnostic_after_dump\n    call diagnostic_dump\ndiagnostic_after_dump:\n')
 source += """
diagnostic_complete:
    call diagnostic_dump
    mov eax,60
    xor edi,edi
    syscall
    ud2
diagnostic_dump:
    mov eax,1
    mov edi,1001
    mov rsi,r15
    mov edx,STATE_BYTES+136
    syscall
    ret
"""
 asm=D/'diagnostic-capsule.S';asm.write_text(source);obj=D/'diagnostic-capsule.o';raw=D/'diagnostic-capsule.bin'
 subprocess.run(['/usr/bin/as','--64',str(asm),'-o',str(obj)],check=True,capture_output=True)
 subprocess.run(['/usr/bin/objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
 symbols={name:int(a,16) for a,_,name in (line.split() for line in subprocess.check_output(['/usr/bin/nm','-n',str(obj)],text=True).splitlines())}
 header=bytearray(prefix[:176]);code=bytearray(header+raw.read_bytes());at=len(code)
 for label,part in zip(labels,parts):
  off=176+symbols[label];struct.pack_into('<i',code,off,at-off-4);code+=part;at+=len(part)
 struct.pack_into('<2Q',code,96,len(code),len(code));exe=D/'diagnostic-owner';exe.write_bytes(code);exe.chmod(0o500)
 report['diagnostic_capsule']=pin(bytes(code));report['initial_state']=pin(w);report['request']=pin(request);save()
 t=time.monotonic_ns()
 r=subprocess.run(['/usr/bin/strace','-f','-qq','-s','120','-e','trace=process,execveat','-o',str(D/'trace.log'),str(exe)],stdin=reqfd,pass_fds=tuple(set(fds)),capture_output=True,env={'PATH':''},cwd=D,timeout=300)
 (D/'stdout').write_bytes(r.stdout);(D/'stderr').write_bytes(r.stderr)
 report.update(returncode=r.returncode,elapsed_ns=time.monotonic_ns()-t)
 saved=(D/'terminal-state.bin').read_bytes();report['terminal_state']=pin(saved)
 if len(saved)==4194304+136:
  def q(at):return struct.unpack_from('<Q',saved,at)[0]
  report['terminal']={'phase':q(0),'previous_phase':q(4194304+128),'plan':list(struct.unpack_from('<16Q',saved,4194304)),'dag_index':q(1519984),'node_index':q(1500040),'operation':q(1500048),'args_count':q(1500064),'current_handle':q(1500056),'current_fd':q(144),'current_bytes':q(152),'published':q(1599904)}
 expected=json.loads((S/'docs/HIA_NATIVE_GENERATION_LEASE_RELEASE_BUILD.json').read_text())['products'];report['products']={p.name:pin(p.read_bytes()) for p in (D/'stage').iterdir()};report['products_match_frozen']=all(report['products'].get(n)==v for n,v in expected.items());report['passed']=r.returncode==0 and report.get('terminal',{}).get('phase')==6000 and report['products_match_frozen'];save();print(json.dumps(report,indent=2),flush=True);assert report['passed']
finally:
 for fd in set(fds):
  try:os.close(fd)
  except OSError:pass
