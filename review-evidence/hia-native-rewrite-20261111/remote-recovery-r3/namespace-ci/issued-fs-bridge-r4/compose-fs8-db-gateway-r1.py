"""Strict new FS8 mechanical composer over the exact previous six-role template.
No filesystem/SQLite policy is evaluated here. Output is still packed by HIA.
"""
from __future__ import annotations
import sys
sys.dont_write_bytecode=True
import argparse,hashlib,importlib.util,json
from pathlib import Path
OLD_COMPOSER_SHA="5d35ff33c37cabfcc31d0b3d04b5efe591f9832feb246a4263872af8cc3f3c96"
OLD_RESULT_SHA="8876c8172b3f2166e1482e53f0698517dad1fde164c4b59bd481186d437b2224"
RESULT_SHA="fc47cfc647affed2db900351834845b819c4c07f838dcb701a3a03f418813b9b"
EDITS=json.loads("[[\"    cmp rax,24\\n    ja protocol_failure\\n    mov [r15+PRIMITIVE_OP],rax\",\"    cmp rax,29\\n    ja protocol_failure\\n    mov [r15+PRIMITIVE_OP],rax\"],[\"    cmp eax,23\\n    je primitive_getlk\\n    jmp primitive_fchown\\n\",\"    cmp eax,23\\n    je primitive_getlk\\n    cmp eax,24\\n    je primitive_fchown\\n    cmp eax,25\\n    je primitive_openat\\n    cmp eax,26\\n    je primitive_getpid\\n    cmp eax,27\\n    je primitive_access\\n    cmp eax,28\\n    je primitive_openat\\n    jmp primitive_statat\\n\"],[\"\\nprimitive_fchown:\\n\",\"\\nprimitive_getpid:\\n    /* Exactly one actual process-ID syscall; no host-supplied PID. */\\n    mov eax,39\\n    jmp perform_primitive\\nprimitive_access:\\n    /* The HIA op27 signature is access(path, mode), using the real UID. */\\n    call check_path_payload\\n    lea rdi,[r12+256]\\n    mov rsi,[r12+72]\\n    mov eax,21\\n    jmp perform_primitive\\n\\nprimitive_fchown:\\n\"],[\"    cmp ecx,18\\n    je primitive_stat_extent\\n    cmp ecx,23\",\"    cmp ecx,18\\n    je primitive_stat_extent\\n    cmp ecx,29\\n    je primitive_stat_extent\\n    cmp ecx,23\"]]")
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    p=argparse.ArgumentParser()
    p.add_argument("base",type=Path);p.add_argument("output",type=Path)
    p.add_argument("--old-composer",type=Path,required=True)
    a=p.parse_args()
    before=a.base.read_bytes();old_raw=a.old_composer.read_bytes()
    assert sha(old_raw)==OLD_COMPOSER_SHA
    spec=importlib.util.spec_from_file_location("namespace_exact_previous_six_role_composer",a.old_composer)
    mod=importlib.util.module_from_spec(spec)
    exec(compile(old_raw,str(a.old_composer),"exec"),mod.__dict__)
    old=mod.compose(before.decode("utf-8"))
    assert sha(old.encode())==OLD_RESULT_SHA
    current=old
    for previous,replacement in EDITS:
        assert current.count(previous)==1
        current=current.replace(previous,replacement,1)
    restored=current
    for previous,replacement in reversed(EDITS):
        assert restored.count(replacement)==1
        restored=restored.replace(replacement,previous,1)
    assert restored==old
    raw=current.encode("utf-8");assert sha(raw)==RESULT_SHA
    assert a.base.read_bytes()==before and a.old_composer.read_bytes()==old_raw
    with a.output.open("xb") as stream:stream.write(raw)
    assert a.output.read_bytes()==raw
    print(json.dumps(dict(bytes=len(raw),sha256=RESULT_SHA,
        original_six_role_sha256=OLD_RESULT_SHA,extra_mechanical_edits=4,
        no_policy_code_or_syscall_executed=True),sort_keys=True))
if __name__=="__main__":main()
