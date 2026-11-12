"""Specialize only the top-level immutable input framing of exact 63-role ELF.

No mode/schema/digest/diagnostic decision is made in assembly. HIA receives the
whole 64B command. Program/ordinary children, cleanup, syscalls, bounds, command
correlation and result transport retain the exact original instruction text.
"""
from hashlib import sha256
from pathlib import Path
import argparse,difflib,json
ORIGINAL_SHA="6c8e7c8dfdbbbe1da653834c67e19f733922937f86531c88179713c018770cac"
OLD_MASK=".equ TWO_READ_MASK,0xe0bf80bee2ac0462"
NEW_MASK=".equ TWO_READ_MASK,0x60bf80bee2ac0462"
BEGIN="    /* Exact immutable byte framing. HIA interprets JSON and public policy. */\n"
END="input_exact:\n"
FRAMING=r'''    /* Worker-private immutable command + one raw source view.
     * All mode/profile/schema/representation decisions remain HIA-owned. */
    cmp qword ptr [rip+executable_policy],4
    jne abi_error
    mov rsi,r13
    mov edx,64
    call input_exact
    mov rax,0x3130495057414948
    cmp [r13],rax
    jne abi_error
    cmp qword ptr [r13+56],0
    jne abi_error
    mov rax,[r13+8]
    test rax,rax
    jz abi_error
    cmp rax,-1
    je abi_error
    mov [r15+LEASE],rax
    mov rax,[r13+24]
    mov [r15+DIGITS],rax
    mov qword ptr [r15+KIND],2
    mov qword ptr [r15+DEPTH],0
    mov edi,1
    mov rsi,[r13+32]
    call resize_slot
    mov rsi,[r15+1*32]
    mov rdx,[r15+1*32+8]
    call input_exact
    mov edi,1
    mov esi,1
    call protect_slot
worker_input_end:
    xor eax,eax
    xor edi,edi
    lea rsi,[r15+4096]
    mov edx,1
    syscall
    cmp rax,-4
    je worker_input_end
    test rax,rax
    js io_error
    jnz abi_error
    mov rbx,[r15+2*32]
    mov qword ptr [rbx+4096],1
    mov qword ptr [rbx+4096+16],1048576
    mov rax,[r15+1*32+8]
    mov [rbx+4096+1*8],rax
    mov qword ptr [r15+ROLE],56
    mov [r15+CMDPTR],r13
    mov qword ptr [r15+CMDLEN],64
    jmp controller_entry
'''
def compose(raw):
    assert sha256(raw).hexdigest()==ORIGINAL_SHA
    original=raw.decode("utf-8")
    assert original.count(BEGIN)==1 and original.count(END)==1 and original.count(OLD_MASK)==1
    start=original.index(BEGIN);end=original.index(END,start)
    replaced=original[:start]+FRAMING+original[end:]
    result=replaced.replace(OLD_MASK,NEW_MASK,1)
    assert result[result.index(END):]==original[end:]
    assert result[:start]==original[:start].replace(OLD_MASK,NEW_MASK,1)
    assert int.from_bytes(b"HIAWPI01","little")==0x3130495057414948
    before=int(OLD_MASK.rsplit(",",1)[1],16);after=int(NEW_MASK.rsplit(",",1)[1],16)
    assert after==((before|(1<<61)|(1<<62))&~(1<<63))
    return result.encode("utf-8")
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    raw=a.source.read_bytes();result=compose(raw);a.out.mkdir(parents=True,exist_ok=False)
    (a.out/"original-executor.S").write_bytes(raw)
    (a.out/"worker-program-executor.S").write_bytes(result)
    (a.out/"executor.diff").write_text("".join(difflib.unified_diff(
        raw.decode().splitlines(True),result.decode().splitlines(True),fromfile="original",tofile="worker")))
    proof=dict(schema="hia-worker-program-fixed-executor-composition-r1",
        status="SOURCE_COMPOSED_ONLY",original_sha256=sha256(raw).hexdigest(),
        source_sha256=sha256(result).hexdigest(),source_bytes=len(result),
        changes=["top-level immutable input framing","top-level roles61/62 read-only and63 writable output"],
        all_instructions_from_input_exact_to_end_unchanged=True,
        child_context_program_ordinary_lifetimes_unchanged=True,
        assembler_executions=0,native_entries=0,semantic_owner_in_executor=False)
    (a.out/"composition.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
    assert a.source.read_bytes()==raw
    print(json.dumps(proof,sort_keys=True),flush=True)
if __name__=="__main__":main()
