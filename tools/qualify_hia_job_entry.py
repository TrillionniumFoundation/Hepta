"""Qualify native job entry custody, exact streaming and refusal boundaries.

Controlled native probes inspect their actual argv, executable seals and stdin
seals, then count the supplied bytes. They do not substitute for qualification
of the submit, observation or cancellation owners selected in production.
"""
from __future__ import annotations
import argparse
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import struct
import subprocess

PROBE = r"""
.intel_syntax noprefix
.text
.global _start
_start:
    mov r12,rsp
    cmp QWORD PTR [r12],1
    jne failed
    mov rdi,[r12+8]
    lea rsi,[rip+expected]
compare_argument:
    mov al,[rdi]
    cmp al,[rsi]
    jne failed
    inc rdi
    inc rsi
    test al,al
    jne compare_argument
    mov eax,72
    xor edi,edi
    mov esi,1034
    syscall
    cmp rax,15
    jne failed
    mov r13,rax
    mov eax,257
    mov rdi,-100
    lea rsi,[rip+self_path]
    mov edx,0x80000
    syscall
    cmp rax,3
    jl failed
    mov rdi,rax
    mov eax,72
    mov esi,1034
    syscall
    cmp rax,15
    jne failed
    mov r15,rax
    mov eax,3
    syscall
    sub rsp,65568
    xor r14d,r14d
read_again:
    xor eax,eax
    xor edi,edi
    mov rsi,rsp
    mov edx,65536
    syscall
    cmp rax,-4
    je read_again
    test rax,rax
    js failed
    jz completed
    add r14,rax
    jmp read_again
completed:
    mov [rsp],r14
    mov [rsp+8],r13
    mov [rsp+16],r15
    mov eax,1
    mov edi,1
    mov rsi,rsp
    mov edx,24
    syscall
    cmp rax,24
    jne failed
    xor edi,edi
    jmp exiting
failed:
    mov edi,77
exiting:
    mov eax,60
    syscall
    ud2
self_path: .asciz "/proc/self/exe"
expected: .asciz "TARGET"
"""


def probe(directory: Path, name: str, *, launch=False, jobdir="/hia-entry-probe/jobs/example", binding='{"binding":"fixture","unicode":"Ω"}') -> bytes:
    assembly=directory/(name+'.S');obj=directory/(name+'.o');raw=directory/(name+'.bin')
    source=PROBE.replace('TARGET',name)
    if launch:
        source=source.replace('cmp QWORD PTR [r12],1','cmp QWORD PTR [r12],4')
        start=source.index('    mov eax,72');end=source.index('    mov eax,257',start)
        check=''
        for index,label in [(2,'jobdir'),(3,'binding'),(4,'backend')]:
            check+=f'    mov rdi,[r12+{8*index}]\n    lea rsi,[rip+expected_{label}]\ncompare_{label}:\n    mov al,[rdi]\n    cmp al,[rsi]\n    jne failed\n    inc rdi\n    inc rsi\n    test al,al\n    jne compare_{label}\n'
        source=source[:start]+check+'    xor r13d,r13d\n'+source[end:]
        for label,value in [('jobdir',jobdir),('binding',binding),('backend','systemd')]:
            source+='expected_'+label+': .byte '+','.join(str(b) for b in value.encode()+b'\0')+'\n'
    assembly.write_text(source)
    subprocess.run(['as','--64',str(assembly),'-o',str(obj)],check=True,capture_output=True)
    subprocess.run(['objcopy','-O','binary','-j','.text',str(obj),str(raw)],check=True,capture_output=True)
    if 'R_X86_64' in subprocess.check_output(['objdump','-r',str(obj)],text=True):
        raise ValueError('unresolved probe relocation')
    code=raw.read_bytes();size=176+len(code)
    return (b'\x7fELF\x02\x01\x01'+bytes(9)
        +struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,size,size,4096)
        +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16)+code)


def frame(operation: int, image: bytes, payload: bytes) -> bytes:
    return struct.pack('<8s3Q',b'HIAJEX01',operation,len(image),len(payload))+sha256(image).hexdigest().encode()+image+payload


def qualify(entry: Path, output: Path):
    entry=entry.resolve(strict=True);output=output.resolve();output.mkdir(mode=0o700)
    pin=sha256(entry.read_bytes()).hexdigest()
    images={i:probe(output,name) for i,name in enumerate(('hia-job-submit','hia-job-observation','hia-job-cancel'),1)}
    payloads={1:b'HIAJSB01'+bytes(56),2:struct.pack('<8s9Q',b'HIAJOBQ1',0,0,0,1,0,0,0,64,0),3:b'HIAJCQ02'+bytes(72)}
    cases=[]
    def run(name, wire, *, count=None, arguments=(), env=None, path=None, traced=False):
        command=[str(entry),*arguments]
        if traced:command=['/usr/bin/strace','-f','-qq','-e','trace=execve,execveat,memfd_create,fcntl,close_range,dup2','-o',str(output/(name+'.trace')),*command]
        if path is None:
            result=subprocess.run(command,input=wire,capture_output=True,env=env or {'PATH':''},timeout=180)
        else:
            with path.open('rb') as stream:result=subprocess.run(command,stdin=stream,capture_output=True,env=env or {'PATH':''},timeout=180)
        good=count is not None
        expected=struct.pack('<3Q',count,15,15) if good else b''
        if result.returncode != (0 if good else 65) or result.stdout!=expected or result.stderr:
            raise AssertionError((name,result.returncode,result.stdout[:96],result.stderr[:96]))
        row={'name':name,'returncode':result.returncode,'stdout_hex':result.stdout.hex(),'stdin_bytes':len(wire) if path is None else path.stat().st_size}
        if traced:
            text=(output/(name+'.trace')).read_text();execs=[line for line in text.splitlines() if re.search(r'\bexecveat\(',line)]
            assert len(execs)==1 and 'AT_EMPTY_PATH' in execs[0] and ', "", ' in execs[0],execs
            direct=[line for line in text.splitlines() if re.search(r'\bexecve\(',line)];assert len(direct)==1 and str(entry) in direct[0],direct
            assert 'F_ADD_SEALS' in text and 'CLOSE_RANGE_CLOEXEC' in text
            row['trace_sha256']=sha256(text.encode()).hexdigest();row['sealed_native_target_only']=True
        cases.append(row)
    for operation in (1,2,3):
        run('fixed-role-'+str(operation),frame(operation,images[operation],payloads[operation]),count=len(payloads[operation]),traced=True)
    status=bytearray(payloads[2]);struct.pack_into('<Q',status,8,1);struct.pack_into('<Q',status,72,63)
    run('status-full-facts',frame(2,images[2],status),count=80)
    maximum=images[2]+bytes((4<<20)-len(images[2]));payload=payloads[2]+bytes(65536-80)
    run('maximum-image-and-observation',frame(2,maximum,payload),count=len(payload))
    env={f'ENTRY_{i:03}':'x' for i in range(127)};env['PATH']=''
    run('128-environment-records',frame(2,images[2],payloads[2]),count=80,env=env)
    run('maximum-environment-string',frame(2,images[2],payloads[2]),count=80,env={'ENTRY_LONG':'x'*(8192-len('ENTRY_LONG='))})
    # Sparse request files exercise the original large stream limits without
    # retaining a second host-memory copy or a large captured output.
    for operation,size in [(1,545259584),(3,2162688)]:
        path=output/('maximum-payload-'+str(operation)+'.request')
        raw=struct.pack('<8s3Q',b'HIAJEX01',operation,len(images[operation]),size)+sha256(images[operation]).hexdigest().encode()+images[operation]+payloads[operation]
        with path.open('xb') as stream:stream.write(raw);stream.truncate(96+len(images[operation])+size)
        run('maximum-payload-'+str(operation),b'',count=size,path=path)
    valid=frame(2,images[2],payloads[2])
    controls=[('short-header',valid[:95]),('bad-magic',b'X'+valid[1:]),('short-image',valid[:96+len(images[2])-1]),('short-payload',valid[:-1]),('trailing-byte',valid+b'x'),('bad-hash',valid[:32]+b'0'*64+valid[96:]),('nonhex-hash',valid[:32]+b'G'+valid[33:]),('wrong-payload-role',frame(2,images[2],payloads[3]))]
    bad_image=b'X'+images[2][1:];controls.append(('non-ELF-with-matching-hash',frame(2,bad_image,payloads[2])))
    mutated=bytearray(maximum);mutated[-1]=1;controls.append(('changed-final-image-byte',frame(2,maximum,payload)[:96]+mutated+payload))
    for label,offset,value in [('unknown-operation',8,4),('image-below-minimum',16,63),('image-over-limit',16,(4<<20)+1),('payload-below-minimum',24,79),('observation-payload-over-limit',24,65537),('integer-overflow-image',16,(1<<64)-1),('integer-overflow-payload',24,(1<<64)-1)]:
        wire=bytearray(valid[:96]);struct.pack_into('<Q',wire,offset,value);controls.append((label,bytes(wire)))
    for operation,limit in [(1,545259584),(3,2162688)]:
        wire=bytearray(frame(operation,images[operation],payloads[operation])[:96]);struct.pack_into('<Q',wire,24,limit+1);controls.append(('payload-over-limit-'+str(operation),bytes(wire)))
    for mode,flags in [(0,63),(1,0),(2,0),(1,127)]:
        bad=bytearray(payloads[2]);struct.pack_into('<Q',bad,8,mode);struct.pack_into('<Q',bad,72,flags);controls.append((f'bad-observation-mode-{mode}-flags-{flags}',frame(2,images[2],bad)))
    for name,wire in controls:run(name,wire)
    run('unexpected-argument',valid,arguments=('unexpected',))
    run('environment-over-string-limit',valid,env={'ENTRY_LONG':'x'*(8193-len('ENTRY_LONG='))})
    launch_image=probe(output,'hia-job-launch',launch=True)
    jobdir='/hia-entry-probe/jobs/example';binding='{"binding":"fixture","unicode":"Ω"}'
    def launch_args(image, *, digest=None, directory=jobdir, meta=binding):
        return ['--launch-base64',digest or sha256(image).hexdigest(),directory,meta,
                *[base64.b64encode(image[at:at+49152]).decode() for at in range(0,len(image),49152)]]
    def launch_run(name, arguments, *, good=True, traced=False, env=None, stdin=b'unread-entry-stdin'):
        command=[str(entry),*arguments]
        trace=output/(name+'.trace')
        if traced:command=['/usr/bin/strace','-f','-qq','-s','128','-e','trace=execve,execveat,memfd_create,fcntl,close_range,read','-o',str(trace),*command]
        result=subprocess.run(command,input=stdin,capture_output=True,env=env or {'PATH':''},timeout=180)
        expected=struct.pack('<3Q',len(stdin),0,15) if good else b''
        assert result.returncode==(0 if good else 65) and result.stdout==expected and not result.stderr,(name,result.returncode,result.stdout[:96],result.stderr[:96])
        row={'name':name,'returncode':result.returncode,'stdin_bytes':len(stdin),'argument_bytes':sum(len(a.encode())+1 for a in arguments),'stdout_hex':result.stdout.hex()}
        if traced:
            lines=trace.read_text().splitlines();execs=[i for i,line in enumerate(lines) if re.search(r'\bexecveat\(',line)]
            assert len(execs)==(1 if good else 0),execs
            if good:
                assert 'AT_EMPTY_PATH' in lines[execs[0]] and all(i>execs[0] for i,line in enumerate(lines) if re.search(r'\bread\(',line)),lines
                assert sum(bool(re.search(r'\bexecve\(',line)) for line in lines)==1
                row['sealed_native_launcher_only']=True;row['stdin_untouched_until_target_exec']=True
            row['trace_sha256']=sha256(trace.read_bytes()).hexdigest()
        cases.append(row)
    launch_run('launch-fixed-argv-and-stdin',launch_args(launch_image),traced=True)
    for remainder in (0,1,2):
        image=launch_image+bytes((remainder-len(launch_image))%3)
        launch_run('launch-base64-remainder-'+str(remainder),launch_args(image))
    large=launch_image+bytes((1<<20)-len(launch_image))
    launch_run('launch-maximum-image',launch_args(large),traced=True)
    launch_run('launch-128-environment-records',launch_args(launch_image),env={f'E_{i:03}':'v' for i in range(128)})
    longdir='/'+'d'*4095;longbinding='b'*8192
    boundary=probe(output,'hia-job-launch-boundary',launch=True,jobdir=longdir,binding=longbinding)
    # The boundary probe still receives the production fixed argv[0].
    boundary_source=(output/'hia-job-launch-boundary.S').read_text().replace('.asciz "hia-job-launch-boundary"','.asciz "hia-job-launch"')
    (output/'hia-job-launch-boundary.S').write_text(boundary_source)
    subprocess.run(['as','--64',str(output/'hia-job-launch-boundary.S'),'-o',str(output/'hia-job-launch-boundary.o')],check=True,capture_output=True)
    subprocess.run(['objcopy','-O','binary','-j','.text',str(output/'hia-job-launch-boundary.o'),str(output/'hia-job-launch-boundary.bin')],check=True,capture_output=True)
    code=(output/'hia-job-launch-boundary.bin').read_bytes();boundary=bytearray(boundary[:176]+code);struct.pack_into('<Q',boundary,96,len(boundary));struct.pack_into('<Q',boundary,104,len(boundary))
    launch_run('launch-maximum-jobdir-binding',launch_args(boundary,directory=longdir,meta=longbinding))
    valid=launch_args(launch_image)
    controls=[]
    def changed(index,value):
        args=valid.copy();args[index]=value;return args
    controls += [('launch-wrong-mode',changed(0,'--launch-hex')),('launch-bad-hash',changed(1,'0'*64)),('launch-uppercase-hash',changed(1,sha256(launch_image).hexdigest().upper())),('launch-short-hash',changed(1,'0'*63)),('launch-relative-directory',changed(2,'relative')),('launch-empty-directory',changed(2,'')),('launch-long-directory',changed(2,'/'+'d'*4096)),('launch-empty-binding',changed(3,'')),('launch-long-binding',changed(3,'b'*8193)),('launch-no-image',valid[:4]),('launch-empty-chunk',changed(4,'')),('launch-non-four-chunk',changed(4,valid[4][:-1])),('launch-whitespace',changed(4,' '+valid[4][1:])),('launch-url-alphabet',changed(4,'-'+valid[4][1:])),('launch-padding-first',changed(4,'='+valid[4][1:])),('launch-early-padding',changed(4,'AA=='+valid[4][4:])),('launch-small-nonfinal',valid+['AAAA']),('launch-raw-too-small',launch_args(bytes(63))),('launch-non-ELF-matching-hash',launch_args(b'X'+launch_image[1:])),('launch-image-over-limit',launch_args(large+b'x'))]
    # Noncanonical unused bits would decode to the same byte string if accepted.
    alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    for remainder in (1,2):
        padded=launch_image+bytes((remainder-len(launch_image))%3)
        args=launch_args(padded);chunk=args[-1];at=len(chunk)-(3 if remainder==1 else 2)
        point=alphabet[(alphabet.index(chunk[at])|1)]
        args[-1]=chunk[:at]+point+chunk[at+1:]
        controls.append(('launch-noncanonical-'+str(remainder),args))
    badpadding=valid.copy();badpadding[4]='A'*65532+'AA==';badpadding.append('AAAA');controls.append(('launch-padding-before-last-chunk',badpadding))
    controls.append(('launch-too-many-arguments',['--launch-base64',valid[1],jobdir,binding]+['AAAA']*124))
    controls.append(('launch-argument-over-limit',changed(4,'A'*65540)))
    for name,args in controls:launch_run(name,args,good=False,traced=name in ('launch-bad-hash','launch-noncanonical-1'))
    assert sha256(entry.read_bytes()).hexdigest()==pin
    report={'schema':'hepta.hia.job-entry-qualification.v1','scope':'NATIVE_FIXED_JOB_ENTRY_CUSTODY_AND_STREAM_TRANSPORT','status':'passed','entry_sha256':pin,'cases':cases,'passed':len(cases),'positive_cases':sum(c['returncode']==0 for c in cases),'refusal_cases':sum(c['returncode']!=0 for c in cases),'host_generator_in_target_chain':False}
    (output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');return report


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--entry',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();print(json.dumps(qualify(args.entry,args.output),sort_keys=True))
if __name__=='__main__':main()
