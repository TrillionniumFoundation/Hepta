"""Add fixed publication filesystem mechanics to the passed finite carrier.

NEW AUTHORING ONLY. This revision also reserves parent roles 8..10 for
publication, path, and SHA images. No CLI grammar, path policy, publication
transaction, hash, receipt or error presentation is implemented here. Operation 19 receives only
HIA-issued syscall numbers, owned FD tokens and exact buffer descriptors.
The original service child graph and every original primitive body stay intact.
"""
from hashlib import sha256
from pathlib import Path
import argparse,json

BASE_SHA="f06b915cdfb415894e05c8c4a3e7bbdba9fe9c0bc5b8791878516f91cdfa66de"

EXTENSION=r'''
/* op19 args: syscall-kind, FD token, first slot/offset/extent, integer A,
 * second slot/offset/extent, integer B, zero, zero. Raw result goes to the
 * unchanged ACK word 5. HIA obtains any writable result through VIEW.
 * An FD token is an index in a dynamically grown private registry; no fixed
 * number-of-files or nesting quota is introduced. Token -1 is AT_FDCWD only
 * for the explicit *at forms. No descriptor is borrowed from the CLI process.
 */
.equ PFS_TABLE,3072
.equ PFS_CAP,3080
.equ PFS_LIVE,3088
.equ PFS_FIRST,3096
.equ PFS_SECOND,3104
.equ PFS_TARGET,3112
.equ PFS_GROW_OLD,3120
.equ PFS_GROW_BYTES,3128
.equ PFS_GROW_NEW,3136

op_filesystem:
    mov edi,14
    call reserved_tail
    mov rax,[r12+32]
    test rax,rax
    jz abi_error
    cmp rax,22
    ja abi_error
    cmp rax,1
    je pfs_open
    cmp rax,2
    je pfs_close
    cmp rax,3
    je pfs_fstat
    cmp rax,4
    je pfs_read
    cmp rax,5
    je pfs_write
    cmp rax,6
    je pfs_sync
    cmp rax,7
    je pfs_stat
    cmp rax,8
    je pfs_stat
    cmp rax,9
    je pfs_link
    cmp rax,10
    je pfs_unlink
    cmp rax,11
    je pfs_mkdir
    cmp rax,12
    je pfs_rmdir
    cmp rax,13
    je pfs_readlink
    cmp rax,14
    je pfs_getcwd
    cmp rax,15
    je pfs_random
    cmp rax,16
    je pfs_openat
    cmp rax,17
    je pfs_fstatat
    cmp rax,18
    je pfs_getdents
    cmp rax,19
    je pfs_fchmod
    cmp rax,20
    je pfs_chmod
    cmp rax,21
    je pfs_unlinkat
    jmp pfs_fchmodat2

/* Exact empty descriptors use an existing view and zero extent. The reserved
 * numeric fields are checked in each row before entering the kernel. */
pfs_no_first:
    cmp qword ptr [r12+48],0
    jne abi_error
    cmp qword ptr [r12+56],0
    jne abi_error
    cmp qword ptr [r12+64],0
    jne abi_error
    ret
pfs_no_second:
    cmp qword ptr [r12+80],0
    jne abi_error
    cmp qword ptr [r12+88],0
    jne abi_error
    cmp qword ptr [r12+96],0
    jne abi_error
    ret
pfs_no_integers:
    cmp qword ptr [r12+72],0
    jne abi_error
    cmp qword ptr [r12+104],0
    jne abi_error
    ret
pfs_no_fd:
    cmp qword ptr [r12+40],0
    jne abi_error
    ret
pfs_first_ro:
    mov rdi,[r12+48]
    mov rsi,[r12+56]
    mov rdx,[r12+64]
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
    mov [r15+PFS_FIRST],rax
    ret
pfs_first_rw:
    mov rdi,[r12+48]
    cmp rdi,4
    jb abi_error
    mov rsi,[r12+56]
    mov rdx,[r12+64]
    call range_view
    cmp qword ptr [rcx+24],0
    jne abi_error
    mov r8,[r15+BUS_PINNED]
    bt r8,rdi
    jc abi_error
    mov [r15+PFS_FIRST],rax
    ret
pfs_second_ro:
    mov rdi,[r12+80]
    mov rsi,[r12+88]
    mov rdx,[r12+96]
    call range_view
    cmp qword ptr [rcx+24],1
    jne abi_error
    mov [r15+PFS_SECOND],rax
    ret
pfs_second_rw:
    mov rdi,[r12+80]
    cmp rdi,4
    jb abi_error
    mov rsi,[r12+88]
    mov rdx,[r12+96]
    call range_view
    cmp qword ptr [rcx+24],0
    jne abi_error
    mov r8,[r15+BUS_PINNED]
    bt r8,rdi
    jc abi_error
    mov [r15+PFS_SECOND],rax
    ret
pfs_path_first:
    call pfs_first_ro
    jmp pfs_path_exact
pfs_path_second:
    call pfs_second_ro
pfs_path_exact:
    test rdx,rdx
    jz abi_error
    cmp byte ptr [rax+rdx-1],0
    jne abi_error
    xor ecx,ecx
    dec rdx
pfs_path_byte:
    cmp rcx,rdx
    jae pfs_path_done
    cmp byte ptr [rax+rcx],0
    je abi_error
    inc rcx
    jmp pfs_path_byte
pfs_path_done:
    ret

/* Input token in RDI. FD 0 is a valid live result. */
pfs_owned:
    cmp rdi,[r15+PFS_CAP]
    jae abi_error
    mov rax,[r15+PFS_TABLE]
    test rax,rax
    jz abi_error
    mov rdi,[rax+rdi*8]
    test rdi,rdi
    js abi_error
    ret
pfs_owned_or_cwd:
    cmp rdi,-1
    jne pfs_owned
    mov rdi,-100
    ret

/* Reserve the caller's chosen empty token before open/openat. Successful raw
 * open is committed once. Failed opens leave the same token empty. */
pfs_target:
    mov rax,[r12+40]
    mov [r15+PFS_TARGET],rax
    cmp rax,[r15+PFS_CAP]
    jb pfs_target_check
    add rax,1
    jc abi_error
    mov rcx,rax
    shr rcx,61
    jnz abi_error
    shl rax,3
    add rax,4095
    jc abi_error
    and rax,-4096
    test rax,rax
    jz abi_error
    mov [r15+PFS_GROW_BYTES],rax
    mov rdx,[r15+PFS_TABLE]
    mov [r15+PFS_GROW_OLD],rdx
    xor edi,edi
    mov rsi,rax
    call map_rw
    mov [r15+PFS_GROW_NEW],rax
    mov rdi,rax
    mov rcx,[r15+PFS_GROW_BYTES]
    shr rcx,3
    mov rax,-1
    rep stosq
    mov rsi,[r15+PFS_GROW_OLD]
    test rsi,rsi
    jz pfs_target_store
    mov rdi,[r15+PFS_GROW_NEW]
    mov rcx,[r15+PFS_CAP]
    shl rcx,3
    rep movsb
    mov rdi,[r15+PFS_GROW_OLD]
    mov rsi,[r15+PFS_CAP]
    shl rsi,3
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
pfs_target_store:
    mov rax,[r15+PFS_GROW_NEW]
    mov [r15+PFS_TABLE],rax
    mov rcx,[r15+PFS_GROW_BYTES]
    shr rcx,3
    mov [r15+PFS_CAP],rcx
pfs_target_check:
    mov rcx,[r15+PFS_TARGET]
    mov rdx,[r15+PFS_TABLE]
    cmp qword ptr [rdx+rcx*8],-1
    jne abi_error
    ret
pfs_open_result:
    test rax,rax
    js pfs_result
    mov rcx,[r15+PFS_TARGET]
    mov rdx,[r15+PFS_TABLE]
    cmp qword ptr [rdx+rcx*8],-1
    jne abi_error
    mov [rdx+rcx*8],rax
    add qword ptr [r15+PFS_LIVE],1
    jc abi_error
    jmp pfs_result

pfs_open:
    call pfs_no_second
    call pfs_path_first
    call pfs_target
    mov rdi,[r15+PFS_FIRST]
    mov rsi,[r12+72]
    mov rdx,[r12+104]
    mov eax,2
    syscall
    jmp pfs_open_result
pfs_openat:
    call pfs_path_first
    /* A second descriptor is not used; its slot word is the directory token. */
    cmp qword ptr [r12+88],0
    jne abi_error
    cmp qword ptr [r12+96],0
    jne abi_error
    call pfs_target
    mov rdi,[r12+80]
    call pfs_owned_or_cwd
    mov rsi,[r15+PFS_FIRST]
    mov rdx,[r12+72]
    mov r10,[r12+104]
    mov eax,257
    syscall
    jmp pfs_open_result
pfs_close:
    call pfs_no_first
    call pfs_no_second
    call pfs_no_integers
    mov rdi,[r12+40]
    call pfs_owned
    mov rcx,[r12+40]
    mov rdx,[r15+PFS_TABLE]
    mov qword ptr [rdx+rcx*8],-1
    cmp qword ptr [r15+PFS_LIVE],0
    je abi_error
    dec qword ptr [r15+PFS_LIVE]
    mov eax,3
    syscall
    jmp pfs_result
pfs_fstat:
    call pfs_no_second
    call pfs_no_integers
    call pfs_first_rw
    cmp qword ptr [r12+64],144
    jne abi_error
    mov rdi,[r12+40]
    call pfs_owned
    mov rsi,[r15+PFS_FIRST]
    mov eax,5
    syscall
    jmp pfs_result
pfs_read:
    call pfs_no_second
    call pfs_no_integers
    call pfs_first_rw
    mov rdi,[r12+40]
    call pfs_owned
    mov rsi,[r15+PFS_FIRST]
    mov rdx,[r12+64]
    xor eax,eax
    syscall
    jmp pfs_result
pfs_write:
    call pfs_no_second
    call pfs_no_integers
    call pfs_first_ro
    mov rdi,[r12+40]
    call pfs_owned
    mov rsi,[r15+PFS_FIRST]
    mov rdx,[r12+64]
    mov eax,1
    syscall
    jmp pfs_result
pfs_sync:
    call pfs_no_first
    call pfs_no_second
    call pfs_no_integers
    mov rdi,[r12+40]
    call pfs_owned
    mov eax,74
    syscall
    jmp pfs_result
pfs_stat:
    call pfs_no_fd
    call pfs_no_integers
    call pfs_path_first
    call pfs_second_rw
    cmp qword ptr [r12+96],144
    jne abi_error
    mov rdi,[r15+PFS_FIRST]
    mov rsi,[r15+PFS_SECOND]
    mov eax,4
    cmp qword ptr [r12+32],7
    je pfs_stat_call
    mov eax,6
pfs_stat_call:
    syscall
    jmp pfs_result
pfs_link:
    call pfs_no_fd
    call pfs_no_integers
    call pfs_path_first
    call pfs_path_second
    mov rdi,[r15+PFS_FIRST]
    mov rsi,[r15+PFS_SECOND]
    mov eax,86
    syscall
    jmp pfs_result
pfs_unlink:
    call pfs_no_fd
    call pfs_no_second
    call pfs_no_integers
    call pfs_path_first
    mov rdi,[r15+PFS_FIRST]
    mov eax,87
    syscall
    jmp pfs_result
pfs_mkdir:
    call pfs_no_fd
    call pfs_no_second
    cmp qword ptr [r12+72],0
    jne abi_error
    call pfs_path_first
    mov rdi,[r15+PFS_FIRST]
    mov rsi,[r12+104]
    mov eax,83
    syscall
    jmp pfs_result
pfs_rmdir:
    call pfs_no_fd
    call pfs_no_second
    call pfs_no_integers
    call pfs_path_first
    mov rdi,[r15+PFS_FIRST]
    mov eax,84
    syscall
    jmp pfs_result
pfs_readlink:
    call pfs_no_fd
    call pfs_no_integers
    call pfs_path_first
    call pfs_second_rw
    mov rdi,[r15+PFS_FIRST]
    mov rsi,[r15+PFS_SECOND]
    mov rdx,[r12+96]
    mov eax,89
    syscall
    jmp pfs_result
pfs_getcwd:
    call pfs_no_fd
    call pfs_no_second
    call pfs_no_integers
    call pfs_first_rw
    mov rdi,[r15+PFS_FIRST]
    mov rsi,[r12+64]
    mov eax,79
    syscall
    jmp pfs_result
pfs_random:
    call pfs_no_fd
    call pfs_no_second
    cmp qword ptr [r12+104],0
    jne abi_error
    call pfs_first_rw
    mov rdi,[r15+PFS_FIRST]
    mov rsi,[r12+64]
    mov rdx,[r12+72]
    mov eax,318
    syscall
    jmp pfs_result
pfs_fstatat:
    cmp qword ptr [r12+104],0
    jne abi_error
    call pfs_path_first
    call pfs_second_rw
    cmp qword ptr [r12+96],144
    jne abi_error
    mov rdi,[r12+40]
    call pfs_owned_or_cwd
    mov rsi,[r15+PFS_FIRST]
    mov rdx,[r15+PFS_SECOND]
    mov r10,[r12+72]
    mov eax,262
    syscall
    jmp pfs_result
pfs_getdents:
    call pfs_no_second
    call pfs_no_integers
    call pfs_first_rw
    mov rdi,[r12+40]
    call pfs_owned
    mov rsi,[r15+PFS_FIRST]
    mov rdx,[r12+64]
    mov eax,217
    syscall
    jmp pfs_result
pfs_fchmod:
    call pfs_no_first
    call pfs_no_second
    cmp qword ptr [r12+72],0
    jne abi_error
    mov rdi,[r12+40]
    call pfs_owned
    mov rsi,[r12+104]
    mov eax,91
    syscall
    jmp pfs_result
pfs_chmod:
    call pfs_no_fd
    call pfs_no_second
    cmp qword ptr [r12+72],0
    jne abi_error
    call pfs_path_first
    mov rdi,[r15+PFS_FIRST]
    mov rsi,[r12+104]
    mov eax,90
    syscall
    jmp pfs_result
pfs_unlinkat:
    call pfs_no_second
    cmp qword ptr [r12+104],0
    jne abi_error
    call pfs_path_first
    mov rdi,[r12+40]
    call pfs_owned_or_cwd
    mov rsi,[r15+PFS_FIRST]
    mov rdx,[r12+72]
    mov eax,263
    syscall
    jmp pfs_result
pfs_fchmodat2:
    call pfs_no_second
    call pfs_path_first
    mov rdi,[r12+40]
    call pfs_owned_or_cwd
    mov rsi,[r15+PFS_FIRST]
    mov rdx,[r12+104]
    mov r10,[r12+72]
    mov eax,452
    syscall
pfs_result:
    mov [r13+40],rax
    jmp controller_entry
'''
def one(source,old,new):
    assert source.count(old)==1,(old,source.count(old))
    return source.replace(old,new,1)
def compose(raw):
    assert sha256(raw).hexdigest()==BASE_SHA
    text=raw.decode("ascii")
    text=one(text,"    cmp rax,17\n    je op_business\n    jmp abi_error\n",
        "    cmp rax,17\n    je op_business\n    cmp rax,19\n    je op_filesystem\n    jmp abi_error\n")
    text=one(text,".equ TWO_READ_MASK,0x78\n",".equ TWO_READ_MASK,0x378\n")
    text=one(text,"    cmp rax,6\n    ja abi_error\n    cmp qword ptr [r14+rax*8],0\n",
        "    cmp rax,10\n    ja abi_error\n    cmp rax,7\n    je abi_error\n    cmp qword ptr [r14+rax*8],0\n")
    text=one(text,"op_business:\n    cmp qword ptr [r15+FD],-1\n",
        "op_business:\n    cmp qword ptr [r15+PFS_LIVE],0\n    jne abi_error\n    cmp qword ptr [r15+FD],-1\n")
    text=one(text,"terminal_event:\n    mov rax,[r15+SEQ]\n",
        "terminal_event:\n    cmp qword ptr [r15+PFS_LIVE],0\n    jne abi_error\n    mov rax,[r15+SEQ]\n")
    text=one(text,"\nterminal_event:\n","\n"+EXTENSION+"\nterminal_event:\n")
    return text.encode("ascii")
def main():
    p=argparse.ArgumentParser();p.add_argument("--base",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    raw=a.base.read_bytes();new=compose(raw)
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_bytes(new)
    assert a.base.read_bytes()==raw and a.out.read_bytes()==new
    print(json.dumps(dict(scope="NEW_UNEXECUTED_PUBLICATION_FS_MECHANICS",
        source_bytes=len(new),source_sha256=sha256(new).hexdigest(),
        base_sha256=BASE_SHA,base_bytes=len(raw),syscalls=22,
        existing_program_child_body_changed=False,
        path_or_publication_policy_in_carrier=False),sort_keys=True))
if __name__=="__main__":main()
