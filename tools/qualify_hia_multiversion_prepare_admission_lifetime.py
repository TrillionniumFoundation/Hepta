from pathlib import Path
import sys,os,ctypes as C,struct,json,hashlib,subprocess,time,fcntl,argparse
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
ap=argparse.ArgumentParser();ap.add_argument('--directory',type=Path,required=True);ap.add_argument('--normalizer',type=Path,required=True);args=ap.parse_args();D=args.directory
from tools import qualify_hia_multiversion_prepare_admission_strict as _client
q=vars(_client);Intake=q['Intake'];get=q['get'];sealed=q['sealed'];sha=q['sha'];strict=q['packet'];legacy=q['ns']['packet']
from tools import generate_hia_multiversion_prepare_admission_packer as p
from tools.qualify_hia_multiversion_components import Image
build=json.loads((D/'build.json').read_text());parts=[]
for row in build['roles']:
 b=Path(row['path']).read_bytes();assert sha(b)==row['sha256'];parts.append(b)
wire=struct.pack('<QQ',p.MAGIC,len(parts))+b''.join(struct.pack('<Q',len(x)) for x in parts)+b''.join(parts)
expected=p.reference_object(parts);pack=Image(D/'packer.flat');w=C.create_string_buffer(4096);rows=[]
bads=[('empty',b''),('short-header',wire[:95]),('truncated',wire[:-1]),('tail',wire+b'0'),('magic',b'INVALID!'+wire[8:])]
for count in (0,9,11,2**64-1):bads.append(('count/'+str(count),wire[:8]+struct.pack('<Q',count)+wire[16:]))
for index in range(10):
 for count in (0,4194305,2**64-1):
  raw=bytearray(wire);struct.pack_into('<Q',raw,16+index*8,count);bads.append((str(index)+'/'+str(count),bytes(raw)))
for label,raw in bads:
 o=C.create_string_buffer(b'\xa5'*len(expected),len(expected));rc=pack(raw,o,w)
 assert rc==0xffffffff and o.raw==b'\xa5'*len(expected),(label,rc)
 rows.append(dict(case='pack/'+label,status=rc))
o=C.create_string_buffer(b'\xa5'*(len(expected)-1),len(expected)-1);rc=pack(wire,o,w);assert rc==0xfffffffe and o.raw==b'\xa5'*(len(expected)-1)
rows.append(dict(case='pack/short-output',status=rc))
o=C.create_string_buffer(len(expected));assert pack(wire,o,w)==len(expected) and o.raw==expected
# This test-only native executable emits the exact fresh original canonical
# basic program after a real half-second sleep. It exercises transport lifetime,
# not normalizer semantics; those are independently covered with the real image.
raw=json.dumps(q['basic'](),separators=(',',':')).encode();core=q['verify_program'](raw).canonical_bytes
payload=struct.pack('<8s7Q',b'HIAVCF01',0,0,0,len(core),len(core),0,0)+core+core
(D/'delay-payload.bin').write_bytes(payload)
assembly=r'''
.intel_syntax noprefix
.global _start
.text
_start:
.Lread:
 xor eax,eax
 xor edi,edi
 lea rsi,[rip+scratch]
 mov edx,65536
 syscall
 test rax,rax
 jg .Lread
.Lsleep:
 mov eax,35
 lea rdi,[rip+duration]
 xor esi,esi
 syscall
 lea r12,[rip+payload]
 mov r13,payload_end-payload
.Lwrite:
 mov eax,1
 mov edi,1
 mov rsi,r12
 mov rdx,r13
 syscall
 cmp rax,-4
 je .Lwrite
 test rax,rax
 jle .Lbad
 add r12,rax
 sub r13,rax
 jne .Lwrite
 xor edi,edi
 jmp .Lexit
.Lbad:
 mov edi,74
.Lexit:
 mov eax,60
 syscall
.section .rodata
duration: .quad 0,500000000
payload:
.incbin "delay-payload.bin"
payload_end:
.bss
.balign 16
scratch: .skip 65536
.section .note.GNU-stack,"",@progbits
'''
(D/'delay.S').write_text(assembly)
subprocess.run(['as','--64','delay.S','-o','delay.o'],cwd=D,check=True)
subprocess.run(['ld','-nostdlib','-static','-z','noexecstack','delay.o','-o','delay-qa-only'],cwd=D,check=True)
fixture=(D/'delay-qa-only').read_bytes();fd=sealed(fixture);native=Intake(D/'prepare-admission-component.so')
def reaped():
 pid,yes=struct.unpack('<2Q',C.string_at(C.addressof(native.w)+(56<<20)+88,16));assert pid>0 and yes==1
 try:os.waitpid(pid,os.WNOHANG)
 except ChildProcessError:pass
 else:raise AssertionError('owned child not reaped')
 return pid
rc,out,streams,elapsed=native.run(legacy(raw,fd,deadline=time.monotonic_ns()+100_000_000));assert rc==7 and get(out,16)==1 and elapsed<1_000_000_000
rows.append(dict(case='legacy-real-deadline',status=rc,detail=get(out,16),elapsed_ns=elapsed,reaped_pid=reaped()))
rc,out,streams,elapsed=native.run(strict(raw,fd));assert rc==0 and elapsed>=450_000_000
rows.append(dict(case='strict-original-verification-has-no-invented-deadline',status=rc,elapsed_ns=elapsed,reaped_pid=reaped(),fresh_canonical_sha256=sha(core),qa_fixture_only=True))
os.close(fd)
actual=args.normalizer.read_bytes()
for label,body,mode,seal in [('unsealed',actual,0o500,0),('nonexec',actual,0o600,15),('bad-elf',b'bad',0o500,15),('empty',b'',0o500,15)]:
 fd=sealed(body,mode,seal)
 rc,out,streams,elapsed=native.run(strict(raw,fd));assert rc==7 and get(out,248)==2,(label,rc,get(out,248));os.fstat(fd);os.close(fd)
 rows.append(dict(case='strict-custody/'+label,status=rc,elapsed_ns=elapsed))
for label,path,flags in [('directory',D,os.O_RDONLY|os.O_DIRECTORY),('regular-image',D/'delay-qa-only',os.O_RDONLY)]:
 fd=os.open(path,flags)
 rc,out,streams,elapsed=native.run(strict(raw,fd));assert rc==7 and get(out,248)==2,(label,rc);os.fstat(fd);os.close(fd)
 rows.append(dict(case='strict-custody/'+label,status=rc,elapsed_ns=elapsed))
report=dict(schema='hepta.hia.multiversion-prepare-admission-lifetime-pack.v1',whole_native_runtime=False,image_sha256=build['image_sha256'],passed=len(rows),failed=0,qa_delay_fixture_sha256=sha(fixture),cases=rows)
(D/'lifetime-pack-qualification.json').write_text(json.dumps(report,indent=2)+'\n')
print('ADMISSION_LIFETIME_PACK_PASS',len(rows),flush=True)
