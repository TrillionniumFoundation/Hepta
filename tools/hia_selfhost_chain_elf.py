"""Author the bounded Core chain lowering for explicit libc-bound ELF output.

These byte fragments are generated only before B0. Successors run the emitted
HIA writer, validate ordinary chain input, and record allocator relocations
themselves. They do not invoke Python or borrow the compiler scratch as a heap.
Nodes contain payload pointer, payload length and next pointer (24 bytes).
The shared destructor iterates with a fixed frame independent of chain length.
"""
from __future__ import annotations

from hepta.hia_machine_x64 import Code


def _push():
    # Inline entry: caller RSP is 16-byte aligned; preserve the two consumed
    # descriptors across calloc in exactly 32 bytes, including alignment pad.
    c = Code()
    c.alu_imm("sub", "rsp", 8)
    c.push("rdi"); c.push("rsi"); c.push("rdx")
    c.mov_imm("rdi", 1); c.mov_imm("rsi", 24); c.call("calloc")
    c.pop("rdx"); c.pop("rcx"); c.pop("rdi")
    c.alu_imm("add", "rsp", 8)
    c.test("rax", "rax"); c.jcc("e", "failed")
    c.store("rax", 0, "rcx"); c.store("rax", 8, "rdx"); c.store("rax", 16, "rdi")
    c.mov_imm("rcx", 0); c.mov_imm("rdx", 0); c.mov_imm("r8", 1); c.jmp("done")
    c.label("failed"); c.mov_rr("rax", "rdi"); c.mov_imm("r8", 0)
    c.label("done")
    return c.finalize()


def _pop():
    c = Code()
    c.test("rdi", "rdi"); c.jcc("e", "empty")
    c.load("rax", "rdi", 16); c.push("rax")
    c.load("rcx", "rdi", 0); c.push("rcx")
    c.load("rdx", "rdi", 8); c.push("rdx")
    c.alu_imm("sub", "rsp", 8); c.call("free"); c.alu_imm("add", "rsp", 8)
    c.pop("rdx"); c.pop("rcx"); c.pop("rax")
    c.mov_imm("r8", 1); c.jmp("done")
    c.label("empty")
    for reg in ("rax", "rcx", "rdx", "r8"):
        c.mov_imm(reg, 0)
    c.label("done")
    return c.finalize()


def _drop():
    # A callable internal helper, unlike the other inline fragments. Entry
    # RSP is 8 mod 16; push rbp and a 16-byte frame align every libc call.
    c = Code()
    c.push("rbp"); c.mov_rr("rbp", "rsp"); c.alu_imm("sub", "rsp", 16)
    c.store("rbp", -8, "rdi")
    c.label("loop")
    c.load("rdx", "rbp", -8); c.test("rdx", "rdx"); c.jcc("e", "done")
    c.load("rax", "rdx", 16); c.store("rbp", -16, "rax")
    c.load("rdi", "rdx", 0); c.test("rdi", "rdi"); c.jcc("e", "node")
    c.call("free")
    c.label("node")
    c.load("rdi", "rbp", -8); c.call("free")
    c.load("rax", "rbp", -16); c.store("rbp", -8, "rax")
    c.jmp("loop")
    c.label("done"); c.leave(); c.ret()
    return c.finalize()


def _head():
    c = Code()
    c.test("rax", "rax"); c.jcc("ne", "present"); c.ud2()
    c.label("present")
    c.load("rdx", "rax", 8); c.load("rax", "rax", 0)
    return c.finalize()


def _is_empty():
    c = Code()
    c.test("rax", "rax"); c.emit(bytes.fromhex("0f94c00fb6c0"))
    return c.finalize()


FRAGMENTS = {"push": _push(), "pop": _pop(), "drop": _drop(), "head": _head(), "is_empty": _is_empty()}


def _fragment(name, data, relocations):
    lines = [f"def chain_bytes_{name}(o:mutbuf, w:mutbuf) -> u64:"]

    def emit(raw):
        for pos in range(0, len(raw), 8):
            part = raw[pos:pos + 8]
            lines.append(f"    emit_bytes(o, w, {int.from_bytes(part, 'little')}, {len(part)})")

    cursor = 0
    for row in relocations:
        at = row["offset"]
        if (row["symbol"] not in {"calloc", "free"} or row["type"] != 4 or row["addend"] != -4
                or data[at - 1:at + 4] != b"\xe8\0\0\0\0" or at - 1 < cursor):
            raise AssertionError("unreviewed chain allocator relocation")
        emit(data[cursor:at - 1])
        lines.append("    owned_import(o, w, " + str({"calloc": 0, "free": 1}[row["symbol"]]) + ")")
        cursor = at + 4
    emit(data[cursor:])
    lines.append("    return 0\n")
    return "\n".join(lines)


SOURCE = r'''
def chain_drop_call(o:mutbuf, w:mutbuf, source:u64) -> u64:
    put(w, 360, 1)
    load_var(o, w, 7, source, 0)
    emit(o, w, 232)
    relocation(o, w, 4, 0)
    return 0

def chain_drop_helper(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 360) == 0:
        return 0
    put(w, 368, get(w, 56))
    chain_bytes_drop(o, w)
    return 0

def chain_store_transfer(o:mutbuf, w:mutbuf, out:u64, payload:u64, ok:u64) -> u64:
    store_var(o, w, out, 0)
    emit_bytes(o, w, ZERO_RAX, 3)
    store_var(o, w, out, 1)
    emit_bytes(o, w, MOV_RAX_RCX, 3)
    store_var(o, w, payload, 0)
    emit_bytes(o, w, MOV_RAX_RDX, 3)
    store_var(o, w, payload, 1)
    emit_bytes(o, w, MOV_RAX_R8, 3)
    store_var(o, w, ok, 0)
    return 0

def chain_instruction(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, at:u64) -> u64:
    count = get(w, 288)
    out = get(w, 296)
    t = get(w, 304)
    if op == @chain.empty@:
        if n != 0 or count != 1 or t != 9:
            return fail(w, 67)
        owned_immediate(o, w, 0, out, 0)
        owned_immediate(o, w, 0, out, 1)
        return 0
    if n == 0 or at != 9:
        return fail(w, 67)
    if op == @chain.is_empty@:
        if n != 1 or count != 1 or t != 5:
            return fail(w, 67)
        load_var(o, w, 0, a, 0)
        chain_bytes_is_empty(o, w)
        store_var(o, w, out, 0)
        return 0
    if op == @chain.head_read@ or op == @chain.head_mut@:
        want = 6 + op - @chain.head_read@
        if n != 1 or count != 1 or t != want:
            return fail(w, 67)
        loan_borrow(w, a, t)
        load_var(o, w, 0, a, 0)
        chain_bytes_head(o, w)
        store_var(o, w, out, 0)
        emit_bytes(o, w, MOV_RAX_RDX, 3)
        store_var(o, w, out, 1)
        return 0
    if count != 3 or t != 9 or get(w, 320) != 8 or get(w, 336) != 5:
        return fail(w, 67)
    if get(w, FBASE + get(w, 72) * FSTRIDE + 176) != 1:
        return fail(w, 65)
    owner_free(w, a)
    if get(w, 40) != 0:
        return 0
    if op == @chain.try_push@:
        if n != 2:
            return fail(w, 67)
        b = get(w, ARGS + 8)
        if variable(w, b) != 8:
            return fail(w, 67)
        owner_free(w, b)
        if get(w, 40) != 0:
            return 0
        load_var(o, w, 7, a, 0)
        load_var(o, w, 6, b, 0)
        load_var(o, w, 2, b, 1)
        chain_bytes_push(o, w)
        owner_consume(w, b)
    else:
        if op != @chain.pop@ or n != 1:
            return fail(w, 67)
        load_var(o, w, 7, a, 0)
        chain_bytes_pop(o, w)
    chain_store_transfer(o, w, out, get(w, 312), get(w, 328))
    owner_consume(w, a)
    return 0
'''
for _token, _bytes in {
    "MOV_RAX_RDX": bytes.fromhex("4889d0"),
    "MOV_RAX_RCX": bytes.fromhex("4889c8"),
    "MOV_RAX_R8": bytes.fromhex("4c89c0"),
    "ZERO_RAX": bytes.fromhex("4831c0"),
}.items():
    SOURCE = SOURCE.replace(_token, str(int.from_bytes(_bytes, "little")))
SOURCE += "\n".join(_fragment(name, *parts) for name, parts in FRAGMENTS.items())
