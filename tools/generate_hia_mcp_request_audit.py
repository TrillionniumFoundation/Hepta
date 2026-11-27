"""Author HIA durable request audit components and their native static ELF packer."""
from __future__ import annotations
import importlib, struct, subprocess, tempfile
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document
from tools.generate_hia_json_decode import source_program as generic_json
from tools.generate_hia_native_filter import LINK_SOURCE
ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ('session','files','records','archive','layout','retention','root','scan','write','recovery','leases','open','response','metadata','intent','history','archive_query','batch')
ROLES = COMPONENTS + ('json',)
PACK_MAGIC = b'HIARAU04'

def adapter_source():
    source = '''/* Mechanical Linux syscall/byte-ABI translation. All request,
 * ownership, retention and durable-publication policy is emitted HIA. */
.intel_syntax noprefix
.text
.global _start
.equ STATE_BYTES,33554432
.equ PLAN_BYTES,128
_start:
    sub rsp,160
    mov eax,9
    xor edi,edi
    mov esi,STATE_BYTES+4096
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    syscall
    cmp rax,-4095
    jae invalid
    mov r15,rax
    lea r14,[rax+STATE_BYTES]
    lea r12,[r14+512]
    xor r13d,r13d
advance:
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    mov ecx,PLAN_BYTES
    mov r8,r15
    mov r9d,STATE_BYTES
'''
    for index,name in enumerate(COMPONENTS):
        source += f'    cmp QWORD PTR [r15+16],{index}\n    je module_{name}\n'
    source += '    jmp invalid\n'
    for name in COMPONENTS:
        source += f'module_{name}:\n    .byte 0xe8\n.global audit_{name}_hole\naudit_{name}_hole: .long 0\n    jmp returned\n'
    source += '''returned:
    mov eax,eax
    cmp eax,6
    je advance
    cmp eax,1
    je syscall_action
    cmp eax,2
    je relocate_action
    cmp eax,4
    je json_action
    jmp invalid
'''
    original=(ROOT/'tools/hia_mcp_service_syscalls.S').read_text()
    source += original[original.index('syscall_action:'):original.index('json_action:')]
    source += '''json_action:
    xor ebx,ebx
    xor ebp,ebp
buffer_pair:
    mov rax,[r14+rbx]
    mov rcx,[r14+rbx+8]
    cmp rax,STATE_BYTES
    ja invalid
    mov rdx,STATE_BYTES
    sub rdx,rax
    cmp rcx,rdx
    ja invalid
    add rax,r15
    mov [rsp+rbp],rax
    mov [rsp+rbp+8],rcx
    add ebx,16
    add ebp,16
    cmp ebp,48
    jb buffer_pair
    mov rdi,[rsp]
    mov rsi,[rsp+8]
    mov rdx,[rsp+16]
    mov rcx,[rsp+24]
    mov r8,[rsp+32]
    mov r9,[rsp+40]
    .byte 0xe8
.global audit_json_hole
audit_json_hole: .long 0
    mov eax,eax
    mov [r15+8],rax
    jmp advance
invalid:
    mov eax,60
    mov edi,65
    syscall
    ud2
.section .note.GNU-stack,"",@progbits
'''
    return source

def template():
    with tempfile.TemporaryDirectory(prefix='hia-audit-author-') as temp:
        p=Path(temp);(p/'adapter.S').write_text(adapter_source())
        subprocess.run(['as','--64',str(p/'adapter.S'),'-o',str(p/'adapter.o')],check=True,capture_output=True)
        subprocess.run(['objcopy','-O','binary','-j','.text',str(p/'adapter.o'),str(p/'adapter.bin')],check=True,capture_output=True)
        symbols={name:int(at,16) for at,_,name in (line.split() for line in subprocess.check_output(['nm','-n',str(p/'adapter.o')],text=True).splitlines())}
        if symbols['_start'] != 0 or 'R_X86_64' in subprocess.check_output(['objdump','-r',str(p/'adapter.o')],text=True):
            raise ValueError('audit adapter contains unresolved relocations')
        raw=(p/'adapter.bin').read_bytes()
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)
        +struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
        +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
        +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    return header+raw,{name:176+symbols['audit_'+name+'_hole'] for name in ROLES}

def packer_source():
    prefix,holes=template(); count=len(ROLES); head=8+8*count
    code=f'''def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < {head+count} or uint(s,0,8) != {int.from_bytes(PACK_MAGIC,'little')}:
        return 4294967295
    size = {len(prefix)}
    index = 0
    while index < {count}:
        part = uint(s,8+index*8,8)
        if part == 0 or part > 1048576:
            return 4294967295
        size = size + part
        index = index + 1
    if length(s) != size - {len(prefix)} + {head}:
        return 4294967295
    if size > 16777216 or length(o) < size:
        return 4294967294
'''
    helpers=''
    for bank,start in enumerate(range(0,len(prefix),512)):
        code+=f'    prefix_{bank}(o)\n'
        helpers+=f'\ndef prefix_{bank}(o:mutbuf) -> u64:\n'
        for at in range(start,min(start+512,len(prefix)),8):
            raw=prefix[at:at+8];helpers+=f'    write(o,{at},{int.from_bytes(raw,"little")},{len(raw)})\n'
        helpers+='    return 0\n'
    code+='    write(o,96,size,8)\n    write(o,104,size,8)\n'
    code+=f'    target = {len(prefix)}\n'
    for i,name in enumerate(ROLES):
        code+=f'    write(o,{holes[name]},target - {holes[name]+4},4)\n    target = target + uint(s,{8+i*8},8)\n'
    code+=f'    copy_bytes(s,o,{head},{len(prefix)},size - {len(prefix)})\n    return size\n'
    return code+helpers+LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]

def main():
    import sys
    names=sys.argv[1:] or list(ROLES)+['packer']
    for name in names:
        if name=='json': source=generic_json(wire_spans=True)
        elif name=='packer': source=packer_source()
        else: source=importlib.import_module('tools.generate_hia_mcp_request_audit_'+name).source()
        text=render_assembly(document(source,'mcp_request_audit_'+name))
        path=ROOT/'examples/hia_bootstrap'/('mcp_request_audit_'+name+'.hepta')
        path.write_text(text);print(path.name,len(text))
    (ROOT/'tools/hia_mcp_request_audit_syscalls.S').write_text(adapter_source())
if __name__=='__main__':main()
