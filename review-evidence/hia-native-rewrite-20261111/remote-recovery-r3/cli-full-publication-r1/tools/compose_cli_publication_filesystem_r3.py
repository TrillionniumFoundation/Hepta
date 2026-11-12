"""Publication filesystem r3: three raw primitives for complete temp cleanup.
This is a new unexecuted mechanical revision. The actual passed r2 composer is
loaded from one immutable verified snapshot; its complete service suffix stays
unchanged. New parent roles 11/12/13/14 are staging writer/create/cleanup/presentation.
"""
from pathlib import Path
from hashlib import sha256
import argparse,json
OLD_SHA="925f97d39a30301dc035cc4e505a1533cde9da70a8b629b8ce3cbc2e6ecc5088"
EXTRA=r'''
pfs_dup_cloexec:
    call pfs_no_first
    call pfs_no_integers
    cmp qword ptr [r12+88],0
    jne abi_error
    cmp qword ptr [r12+96],0
    jne abi_error
    call pfs_target
    mov rdi,[r12+80]
    call pfs_owned
    mov esi,1030
    xor edx,edx
    mov eax,72
    syscall
    jmp pfs_open_result

pfs_clock:
    call pfs_no_fd
    call pfs_no_second
    cmp qword ptr [r12+104],0
    jne abi_error
    call pfs_first_rw
    cmp qword ptr [r12+64],16
    jne abi_error
    mov rdi,[r12+72]
    mov rsi,[r15+PFS_FIRST]
    mov eax,228
    syscall
    jmp pfs_result

pfs_pid:
    call pfs_no_fd
    call pfs_no_first
    call pfs_no_second
    call pfs_no_integers
    mov eax,39
    syscall
    jmp pfs_result
'''
def one(raw,old,new):
    assert raw.count(old)==1,(old,raw.count(old))
    return raw.replace(old,new,1)
def compose(base,old_path):
    raw=Path(old_path).read_bytes();assert sha256(raw).hexdigest()==OLD_SHA
    ns={"__name__":"frozen_publication_fs_r2","__file__":str(Path(old_path).resolve())}
    exec(compile(raw,str(old_path),"exec"),ns)
    original=ns["compose"](base);text=original.decode("ascii")
    text=one(text,".equ TWO_READ_MASK,0x378\n",".equ TWO_READ_MASK,0x7b78\n")
    text=one(text,"    cmp rax,10\n    ja abi_error\n    cmp rax,7\n",
        "    cmp rax,14\n    ja abi_error\n    cmp rax,7\n")
    text=one(text,"    cmp rax,22\n    ja abi_error\n","    cmp rax,25\n    ja abi_error\n")
    text=one(text,"    cmp rax,21\n    je pfs_unlinkat\n    jmp pfs_fchmodat2\n",
        "    cmp rax,21\n    je pfs_unlinkat\n    cmp rax,22\n    je pfs_fchmodat2\n"
        "    cmp rax,23\n    je pfs_dup_cloexec\n    cmp rax,24\n    je pfs_clock\n    jmp pfs_pid\n")
    text=one(text,"    mov eax,452\n    syscall\npfs_result:\n",
        "    mov eax,452\n    syscall\n    jmp pfs_result\n"+EXTRA+"\npfs_result:\n")
    assert text[text.index(".equ svc_"):]==original.decode("ascii")[original.decode("ascii").index(".equ svc_"):]
    assert Path(old_path).read_bytes()==raw
    return text.encode("ascii")
def main():
    p=argparse.ArgumentParser();p.add_argument("--base",type=Path,required=True)
    p.add_argument("--old-composer",type=Path,required=True);p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    base=a.base.read_bytes();new=compose(base,a.old_composer)
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_bytes(new);assert a.out.read_bytes()==new and a.base.read_bytes()==base
    print(json.dumps(dict(status="NEW_MECHANICAL_SOURCE_NOT_EXECUTED",bytes=len(new),sha256=sha256(new).hexdigest(),
        original_composer_sha256=OLD_SHA,raw_primitives=25,parent_roles=14,
        original_service_suffix_unchanged=True),sort_keys=True))
if __name__=="__main__":main()
