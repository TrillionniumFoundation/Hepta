"""Authoring helpers for an explicit Linux-x86-64 owned-allocation profile.

This module does not broaden the selfhost parser, verifier, effects or claims.
``SOURCE`` contains ordinary restricted authoring functions which emit inline,
position-independent machine code.  After B0 the checked-in HIA compiler runs
these functions itself; no Python encoder or callback participates in a call.

The allocator is anonymous mmap, not the compiler's 1 MiB scratch buffer.  It
has a distinct runtime contract from the general backend's libc allocator:
Linux x86-64 mmap returns fresh, zeroed memory or an allocation failure, and
munmap of each exact live allocation succeeds.  A failed release terminates as
a runtime-contract violation; it is not a newly declared Core ``owner.drop``
trap.  Admission must keep this assumption visible.  This is finite executable
implementation evidence, not general allocation/refinement proof.

Static ownership and effect checks must precede these helpers: no duplicate
owners, no use after move/drop, no move/drop with live loans, all normal paths
consume local owners/loans, and multi-result arity/types agree with Core.
"""
from __future__ import annotations

from hashlib import sha256

from hepta.hia_machine_x64 import Code


PROFILE = "selfhost-owned-linux-x86_64-mmap-v1"
RUNTIME_ASSUMPTIONS = (
    "Linux x86-64 LP64 syscall ABI: mmap=9, munmap=11; ordinary SysV register preservation",
    "private anonymous mmap returns fresh zeroed nonaliasing storage or a kernel error",
    "munmap of the exact still-live allocation succeeds; otherwise the runtime contract has failed",
    "allocation availability may differ from libc; no allocator-performance or failure-sequence equivalence is claimed",
    "native execution has no Core VM step, heap or call budget; process limits remain execution-environment limits",
    "kernel, loader and hardware are trusted; this profile is not a new machine-refinement proof",
)
OWNED_OPCODES = (
    "buffer.new", "buffer.try_new", "owner.move", "owner.drop", "chain.empty",
    "chain.try_push", "chain.pop", "chain.is_empty", "chain.head_read", "chain.head_mut",
)
CHAIN_NODE_BYTES = 24


def _finish(code):
    data, relocations = code.finalize()
    if relocations:
        raise AssertionError("owned inline runtime must not carry external relocations")
    return data


def _allocate():
    """rsi=size -> rax=pointer, rdx=length, r8=success; no stack use."""
    c = Code()
    c.test("rsi", "rsi"); c.jcc("e", "empty")
    # The general Core object-size model excludes the unsigned upper half.
    c.jcc("s", "failed")
    c.mov_imm("rax", 9); c.mov_imm("rdi", 0)
    c.mov_imm("rdx", 3)  # PROT_READ | PROT_WRITE
    c.mov_imm("r10", 0x22)  # MAP_PRIVATE | MAP_ANONYMOUS; never MAP_FIXED
    c.mov_imm("r8", -1); c.mov_imm("r9", 0)
    c.emit(b"\x0f\x05")
    # This is the raw kernel return, not libc's MAP_FAILED/errno convention.
    c.alu_imm("cmp", "rax", -4095); c.jcc("ae", "failed")
    c.test("rax", "rax"); c.jcc("ne", "success")
    # Preserve a null descriptor exclusively for empty/failure.  An unusual
    # successful address-zero mapping is released before declining it.
    c.mov_imm("rdi", 0); c.mov_imm("rax", 11); c.emit(b"\x0f\x05")
    c.test("rax", "rax"); c.jcc("e", "failed"); c.ud2()
    c.label("success")
    c.mov_rr("rdx", "rsi"); c.mov_imm("r8", 1); c.jmp("done")
    c.label("empty")
    c.mov_imm("rax", 0); c.mov_imm("rdx", 0); c.mov_imm("r8", 1); c.jmp("done")
    c.label("failed")
    c.mov_imm("rax", 0); c.mov_imm("rdx", 0); c.mov_imm("r8", 0)
    c.label("done")
    return _finish(c)


def _release():
    """rdi=pointer, rsi=length. Empty owners make no syscall; r8/r9 survive."""
    c = Code()
    c.test("rsi", "rsi"); c.jcc("e", "done")
    c.mov_imm("rax", 11); c.emit(b"\x0f\x05")
    c.test("rax", "rax"); c.jcc("e", "done")
    # Outside the supported allocator assumption: never claim a failed free
    # released ownership.  This is not a new defined Core trap category.
    c.ud2()
    c.label("done")
    return _finish(c)


def _push(allocate):
    """rdi=head,rsi=payload ptr,rdx=len -> rax=head,rcx=ptr,rdx=len,r8=ok."""
    c = Code()
    # Preserve the consumed inputs across the allocation syscall.  A failed
    # push returns the same ownership in fresh SSA names, not empty stand-ins.
    c.push("rdi"); c.push("rsi"); c.push("rdx")
    c.mov_imm("rsi", CHAIN_NODE_BYTES); c.emit(allocate)
    c.pop("rdx"); c.pop("rcx"); c.pop("rdi")
    c.test("r8", "r8"); c.jcc("e", "failed")
    c.store("rax", 0, "rcx"); c.store("rax", 8, "rdx"); c.store("rax", 16, "rdi")
    c.mov_imm("rcx", 0); c.mov_imm("rdx", 0); c.jmp("done")
    c.label("failed"); c.mov_rr("rax", "rdi")
    c.label("done")
    return _finish(c)


def _pop(release):
    """rdi=head -> rax=tail,rcx=payload ptr,rdx=len,r8=present."""
    c = Code()
    c.test("rdi", "rdi"); c.jcc("e", "empty")
    c.load("r9", "rdi", 0); c.load("rdx", "rdi", 8); c.load("r8", "rdi", 16)
    c.mov_imm("rsi", CHAIN_NODE_BYTES); c.emit(release)
    c.mov_rr("rax", "r8"); c.mov_rr("rcx", "r9"); c.mov_imm("r8", 1); c.jmp("done")
    c.label("empty")
    for register in ("rax", "rcx", "rdx", "r8"):
        c.mov_imm(register, 0)
    c.label("done")
    return _finish(c)


def _drop_chain(release):
    """rdi=head. Iterative destruction, independent of chain length in stack."""
    c = Code()
    c.label("loop")
    c.test("rdi", "rdi"); c.jcc("e", "done")
    c.mov_rr("r9", "rdi"); c.load("r8", "rdi", 16)
    c.load("rsi", "rdi", 8); c.load("rdi", "rdi", 0); c.emit(release)
    c.mov_rr("rdi", "r9"); c.mov_imm("rsi", CHAIN_NODE_BYTES); c.emit(release)
    c.mov_rr("rdi", "r8"); c.jmp("loop")
    c.label("done")
    return _finish(c)


def _head():
    c = Code()
    c.test("rax", "rax"); c.jcc("ne", "present"); c.ud2()
    c.label("present")
    c.load("rdx", "rax", 8); c.load("rax", "rax", 0)
    return _finish(c)


def _is_empty():
    c = Code()
    c.test("rax", "rax")
    c.emit(b"\x0f\x94\xc0\x0f\xb6\xc0")  # sete al; movzx eax,al
    return _finish(c)


ALLOCATE = _allocate()
RELEASE = _release()
FRAGMENTS = {
    "allocate": ALLOCATE,
    "release": RELEASE,
    "push": _push(ALLOCATE),
    "pop": _pop(RELEASE),
    "drop_chain": _drop_chain(RELEASE),
    "head": _head(),
    "is_empty": _is_empty(),
}


def fragment_manifest():
    return {name: {"bytes": len(data), "sha256": sha256(data).hexdigest()}
            for name, data in sorted(FRAGMENTS.items())}


def _fragment_source(name, data):
    lines = [f"def owned_bytes_{name}(o:mutbuf, w:mutbuf) -> u64:"]
    for index in range(0, len(data), 8):
        chunk = data[index:index + 8]
        lines.append(f"    emit_bytes(o, w, {int.from_bytes(chunk, 'little')}, {len(chunk)})")
    lines.append("    return 0\n")
    return "\n".join(lines)


# Helpers deliberately take explicit SSA destination numbers. The parser can
# retain its chosen bounded multi-output vector without changing this module.
# Every descriptor uses the existing 16-byte SSA slot. A chain's spare word is
# always zero; runtime node storage is payload(ptr,len), then successor pointer.
SOURCE = r'''
def owned_store_pair(o:mutbuf, w:mutbuf, out:u64) -> u64:
    store_var(o, w, out, 0)
    emit_bytes(o, w, MOV_RAX_RDX, 3)
    store_var(o, w, out, 1)
    return 0

def owned_store_transfer(o:mutbuf, w:mutbuf, chain:u64, payload:u64, ok:u64) -> u64:
    store_var(o, w, chain, 0)
    emit_bytes(o, w, ZERO_RAX, 3)
    store_var(o, w, chain, 1)
    emit_bytes(o, w, MOV_RAX_RCX, 3)
    store_var(o, w, payload, 0)
    emit_bytes(o, w, MOV_RAX_RDX, 3)
    store_var(o, w, payload, 1)
    emit_bytes(o, w, MOV_RAX_R8, 3)
    store_var(o, w, ok, 0)
    return 0

def owned_allocate(o:mutbuf, w:mutbuf, size:u64, out:u64, ok:u64, trapping:u64) -> u64:
    load_var(o, w, 6, size, 0)
    owned_bytes_allocate(o, w)
    if trapping == 1:
        emit_bytes(o, w, REQUIRE_R8_TRUE, 7)
    owned_store_pair(o, w, out)
    if trapping == 0:
        emit_bytes(o, w, MOV_RAX_R8, 3)
        store_var(o, w, ok, 0)
    return 0

def owned_move(o:mutbuf, w:mutbuf, source:u64, out:u64) -> u64:
    load_var(o, w, 0, source, 0)
    store_var(o, w, out, 0)
    load_var(o, w, 0, source, 1)
    store_var(o, w, out, 1)
    return 0

def owned_drop(o:mutbuf, w:mutbuf, source:u64, kind:u64) -> u64:
    load_var(o, w, 7, source, 0)
    if kind == 9:
        owned_bytes_drop_chain(o, w)
    else:
        load_var(o, w, 6, source, 1)
        owned_bytes_release(o, w)
    return 0

def owned_empty(o:mutbuf, w:mutbuf, out:u64) -> u64:
    emit_bytes(o, w, ZERO_RAX, 3)
    store_var(o, w, out, 0)
    store_var(o, w, out, 1)
    return 0

def owned_is_empty(o:mutbuf, w:mutbuf, source:u64, out:u64) -> u64:
    load_var(o, w, 0, source, 0)
    owned_bytes_is_empty(o, w)
    store_var(o, w, out, 0)
    return 0

def owned_head(o:mutbuf, w:mutbuf, source:u64, out:u64) -> u64:
    load_var(o, w, 0, source, 0)
    owned_bytes_head(o, w)
    owned_store_pair(o, w, out)
    return 0

def owned_push(o:mutbuf, w:mutbuf, chain:u64, payload:u64, out_chain:u64, out_payload:u64, ok:u64) -> u64:
    load_var(o, w, 7, chain, 0)
    load_var(o, w, 6, payload, 0)
    load_var(o, w, 2, payload, 1)
    owned_bytes_push(o, w)
    owned_store_transfer(o, w, out_chain, out_payload, ok)
    return 0

def owned_pop(o:mutbuf, w:mutbuf, chain:u64, out_chain:u64, out_payload:u64, ok:u64) -> u64:
    load_var(o, w, 7, chain, 0)
    owned_bytes_pop(o, w)
    owned_store_transfer(o, w, out_chain, out_payload, ok)
    return 0
'''
for _token, _bytes in {
    "MOV_RAX_RDX": bytes.fromhex("4889d0"),
    "MOV_RAX_RCX": bytes.fromhex("4889c8"),
    "MOV_RAX_R8": bytes.fromhex("4c89c0"),
    "ZERO_RAX": bytes.fromhex("4831c0"),
    "REQUIRE_R8_TRUE": bytes.fromhex("4d85c075020f0b"),
}.items():
    SOURCE = SOURCE.replace(_token, str(int.from_bytes(_bytes, "little")))
SOURCE += "\n".join(_fragment_source(name, data) for name, data in FRAGMENTS.items())
