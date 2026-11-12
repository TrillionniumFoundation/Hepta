"""Mechanical per-entry timing hooks for the exact ordinary-impact executor.

This is diagnostic development only. All sixty-three HIA semantic images stay
byte-identical. Removing the four calls and this one assembly block must recover
the complete original executor byte-for-byte. No successful qualification is
inferred from a timing run.
"""
from hashlib import sha1,sha256
import json,time
from pathlib import Path
ORIGINAL_GIT="aeaf61efa6fde911dd5a031adaa55b865e407518"
TRACE_FD=198
HOOKS=(
("entry_role_checked:\n    mov rax,[r14+rax*8]",
 "entry_role_checked:\n    call hia_trace_controller_before\n    mov rax,[r14+rax*8]"),
("    call rax\n    cmp eax,128",
 "    call rax\n    call hia_trace_controller_after\n    cmp eax,128"),
("actual_component_call:\n    mov rax,[r12+40]",
 "actual_component_call:\n    call hia_trace_component_before\n    mov rax,[r12+40]"),
("    call qword ptr [r14+rax*8]\n    mov eax,eax",
 "    call qword ptr [r14+rax*8]\n    call hia_trace_component_after\n    mov eax,eax"))
ROUTINES=r"""
/* BEGIN HIA mechanical timing only; complete GPR and flags preservation. */
.equ HIA_TRACE_FD,@TRACE_FD@
.equ HIA_TRACE_CPU_CLOCK,@CPU_CLOCK@
.equ HIA_TRACE_WALL_CLOCK,@WALL_CLOCK@
.macro HIA_TRACE_START name, stage
\name:
    pushfq
    push rax
    mov eax,\stage
    jmp hia_trace_common
.endm
HIA_TRACE_START hia_trace_controller_before,1
HIA_TRACE_START hia_trace_controller_after,2
HIA_TRACE_START hia_trace_component_before,3
HIA_TRACE_START hia_trace_component_after,4
hia_trace_common:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub rsp,128
    mov [rsp+8],rax
    mov rax,@TRACE_MAGIC@
    mov [rsp],rax
    mov edi,HIA_TRACE_CPU_CLOCK
    lea rsi,[rsp+16]
    mov eax,228
    syscall
    test rax,rax
    jne hia_trace_abort
    mov edi,HIA_TRACE_WALL_CLOCK
    lea rsi,[rsp+32]
    mov eax,228
    syscall
    test rax,rax
    jne hia_trace_abort
    mov rax,[r15+ROLE]
    mov [rsp+48],rax
    mov rax,[r15+KIND]
    mov [rsp+56],rax
    mov rax,[r15+LEASE]
    mov [rsp+64],rax
    mov rax,[r15+SEQ]
    mov [rsp+72],rax
    mov rax,[r12+8]
    mov [rsp+80],rax
    mov rax,[r12+32]
    mov [rsp+88],rax
    mov rax,[r12+56]
    mov [rsp+96],rax
    mov rax,[r12+72]
    mov [rsp+104],rax
    mov rax,[r12+88]
    mov [rsp+112],rax
    mov rax,[rsp+240]
    mov [rsp+120],rax
    mov edi,HIA_TRACE_FD
    mov rsi,rsp
    mov edx,128
hia_trace_write:
    mov eax,1
    syscall
    cmp rax,-4
    je hia_trace_write
    test rax,rax
    jle hia_trace_abort
    cmp rax,rdx
    ja hia_trace_abort
    add rsi,rax
    sub rdx,rax
    jne hia_trace_write
    add rsp,128
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    ret
hia_trace_abort:
    mov edi,71
    mov eax,60
    syscall
    ud2
/* END HIA mechanical timing only. */
"""
def gitsha(raw):
    return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def instrument(raw):
    assert gitsha(raw)==ORIGINAL_GIT
    original=raw.decode("ascii")
    block=ROUTINES.replace("@TRACE_FD@",str(TRACE_FD))
    block=block.replace("@CPU_CLOCK@",str(time.CLOCK_THREAD_CPUTIME_ID))
    block=block.replace("@WALL_CLOCK@",str(time.CLOCK_MONOTONIC))
    block=block.replace("@TRACE_MAGIC@",str(int.from_bytes(b"HIAIPT01","little")))
    assert "@" not in block
    changed=original
    for before,after in HOOKS:
        assert changed.count(before)==1,before
        changed=changed.replace(before,after,1)
    marker="\nspool_name:\n"
    assert changed.count(marker)==1
    changed=changed.replace(marker,"\n"+block+marker,1)
    reversed_source=changed.replace("\n"+block+marker,marker,1)
    for before,after in reversed(HOOKS):
        assert reversed_source.count(after)==1,after
        reversed_source=reversed_source.replace(after,before,1)
    assert reversed_source.encode("ascii")==raw
    result=changed.encode("ascii")
    proof=dict(schema="hia-impact-mechanical-entry-trace-source-v1",
        original=dict(bytes=len(raw),gitsha=gitsha(raw),sha256=sha256(raw).hexdigest()),
        traced=dict(bytes=len(result),gitsha=gitsha(result),sha256=sha256(result).hexdigest()),
        hooks=4,complete_reverse_bytes_equal=True,changed_HIA_semantic_images=0,
        trace_fd=TRACE_FD,clock_gettime_syscall=228,
        thread_CPU_clock=int(time.CLOCK_THREAD_CPUTIME_ID),
        monotonic_clock=int(time.CLOCK_MONOTONIC),
        frame_u64_words=16,all_GPR_and_RFLAGS_preserved=True,
        return_EAX_preserved=True,host_business_owner_added=False,
        whole_stack_closed=False,semantic_qualification=False)
    return result,proof
if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser()
    p.add_argument("--original",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    raw=a.original.read_bytes();changed,proof=instrument(raw)
    (a.output/"original.S").write_bytes(raw)
    (a.output/"timed.S").write_bytes(changed)
    (a.output/"source-reverse-proof.json").write_text(json.dumps(proof,indent=2,sort_keys=True)+"\n")
    assert a.original.read_bytes()==raw
