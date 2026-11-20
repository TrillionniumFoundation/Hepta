"""Opt-in, directly encoded SSE2 implementations of three checked Core loops.

The independently implemented consumer is ``hia_verified_simd_check``.  An
emitted object is deliberately not an execution approval: the final linked
ELF must pass that consumer before a caller selects this path.
"""
from __future__ import annotations

from dataclasses import dataclass

from .hia_machine_elf import write_elf_object
from .hia_machine_x64 import Code
from .hia_program import verify_program


KINDS = ("sum_u8", "all_zero_u8", "copy_u8")


def _v(name, typ):
    return {"name": name, "type": typ}


def _op(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args), "out": [_v(*x) for x in out], "attrs": attrs}


def _block(name, params, ops, term):
    return {"id": name, "params": [_v(*x) for x in params], "ops": ops, "term": term}


def _jump(target, args):
    return {"op": "jump", "target": target, "args": list(args)}


def _branch(cond, then, then_args, otherwise, else_args):
    return {"op": "branch", "cond": cond,
            "then": {"target": then, "args": list(then_args)},
            "else": {"target": otherwise, "args": list(else_args)}}


def simd_kernel_program(kind, name="calculate"):
    """Return an admitted primitive Core for one complete forward byte loop.

    Direct ABI: read kernels take ``(source, extent, count)``; copy takes
    ``(destination, destination_extent, source, source_extent, count)``.
    The return is a u64, not the older foreign-wrapper packed u32 result.
    ``count == 0`` does not touch either pointer.  The separate direct ABI
    rejects null/nonwrapping-range failures and copy overlap with abort.
    """
    if kind not in KINDS:
        raise ValueError("unknown verified SIMD kernel")
    copy = kind == "copy_u8"
    params = ([("destination", "mutbuf")] if copy else []) + [("source", "readbuf"), ("count", "usize")]
    state = params + [("index", "usize")] + ([] if copy else [("total", "u64")])
    def ps(prefix):
        return [(prefix + n, t) for n, t in state]
    def ns(prefix):
        return [prefix + n for n, _ in state]
    entry = [_op("buffer.len", ["source"], [("source_extent", "usize")]),
             _op("compare.le", ["count", "source_extent"], [("source_fits", "bool")])]
    valid = "source_fits"
    if copy:
        entry += [_op("buffer.len", ["destination"], [("destination_extent", "usize")]),
                  _op("compare.le", ["count", "destination_extent"], [("destination_fits", "bool")]),
                  _op("bool.and", ["source_fits", "destination_fits"], [("fits", "bool")])]
        valid = "fits"
    entry += [_op("const", out=[("zero", "usize")], value=0)]
    if not copy:
        entry += [_op("const", out=[("initial", "u64")], value=0)]
    incoming = [n for n, _ in params] + ["zero"] + ([] if copy else ["initial"])
    body = [_op("buffer.load", ["b_source", "b_index"], [("byte", "u8")])]
    if copy:
        body += [_op("buffer.store", ["b_destination", "b_index", "byte"])]
    else:
        body += [_op("int.cast", ["byte"], [("wide", "u64")], mode="wrap"),
                 _op("int.add.wrap" if kind == "sum_u8" else "bit.or", ["b_total", "wide"], [("next_total", "u64")])]
    body += [_op("const", out=[("one", "usize")], value=1),
             _op("int.add.wrap", ["b_index", "one"], [("next_index", "usize")])]
    back = ["b_" + n for n, _ in params] + ["next_index"] + ([] if copy else ["next_total"])
    done = []
    answer = "d_count" if copy else "d_total"
    if copy:
        done = [_op("int.cast", ["d_count"], [("answer", "u64")], mode="wrap")]
        answer = "answer"
    if kind == "all_zero_u8":
        done = [_op("const", out=[("done_zero", "u64")], value=0),
                _op("const", out=[("done_one", "u64")], value=1),
                _op("compare.eq", ["d_total", "done_zero"], [("all_zero", "bool")]),
                _op("select", ["all_zero", "done_one", "done_zero"], [("answer", "u64")])]
        answer = "answer"
    doc = {"schema": "hepta.hia.program.v8", "module": "verified_" + kind,
           "functions": [{"name": name, "params": [_v(*p) for p in params], "returns": ["u64"],
                          "effects": ["read", "trap", "write"] if copy else ["read", "trap"],
                          "entry": "entry", "blocks": [
        _block("entry", params, entry, _branch(valid, "loop", incoming, "invalid", [])),
        _block("loop", ps("l_"), [_op("compare.lt", ["l_index", "l_count"], [("more", "bool")])],
               _branch("more", "body", ns("l_"), "done", ns("l_"))),
        _block("body", ps("b_"), body, _jump("loop", back)),
        _block("done", ps("d_"), done, {"op": "ret", "values": [answer]}),
        _block("invalid", [], [], {"op": "trap", "code": "bounds"}),
    ]}]}
    return verify_program(doc)


@dataclass(frozen=True)
class VerifiedSIMDMachine:
    kind: str
    export: str
    core_sha256: str
    text_bytes: bytes
    object_bytes: bytes
    abi: str
    vector_unroll: int = 1


def emit_verified_simd(document, *, unroll=4):
    """Emit a candidate only for an independently recognized Core recurrence."""
    from .hia_verified_simd_check import recognize_simd_core, VerifiedSIMDRejected
    if type(unroll) is not int or unroll not in (1, 4):
        raise VerifiedSIMDRejected("SIMD unroll must be exactly 1 or 4")
    checked = verify_program(document)
    kind, export = recognize_simd_core(checked)
    code = Code(move_immediate="mov32_if_exact", alu_immediate="imm8_if_exact")
    if kind == "copy_u8":
        _copy(code, unroll)
    else:
        _reduce(code, kind, unroll)
    text, relocations = code.finalize()
    obj = write_elf_object(text, [{"name": export, "offset": 0, "size": len(text), "global": True}], relocations)
    abi = ("u64(dst, dst_extent, src, src_extent, count)" if kind == "copy_u8"
           else "u64(src, src_extent, count)")
    return VerifiedSIMDMachine(kind, export, checked.sha256, text, obj, abi, unroll)


def _abort(code):
    code.label("abort")
    code.alu_imm("sub", "rsp", 8)
    code.call("abort")
    code.ud2()


def _vector_memory(c, opcode, base, displacement=0):
    """MOVDQU between xmm1 and a declared unaligned chunk of the span."""
    # Only the forward kernel's two pointer registers are accepted.  Keeping
    # the displacement explicit lets the independent decoder recover every
    # accessed byte without trusting this encoder's account of the range.
    if base not in ("rdi", "rdx") or displacement not in (0, 16, 32, 48):
        raise ValueError("unsupported SIMD chunk address")
    modrm = 8 + (7 if base == "rdi" else 2)
    address = bytes([modrm]) if displacement == 0 else bytes([modrm | 0x40, displacement])
    c.emit(bytes([0xf3, 0x0f, opcode]) + address)


def _reduction_chunk(c, kind, displacement=0):
    _vector_memory(c, 0x6f, "rdi", displacement)
    if kind == "sum_u8":
        c.emit(bytes.fromhex("660ff6ca660fd4c1"))  # psadbw xmm1,xmm2; paddq xmm0,xmm1
    else:
        c.emit(bytes.fromhex("660febc1"))  # por xmm0,xmm1


def _reduce(c, kind, unroll):
    c.mov_imm("rax", 0)
    c.cmp("rdx", "rsi")
    c.jcc("a", "abort")
    c.test("rdx", "rdx")
    c.jcc("e", "done")
    c.test("rdi", "rdi")
    c.jcc("e", "abort")
    c.mov_rr("r9", "rdi")
    c.add("r9", "rdx")
    c.jcc("b", "abort")
    c.mov_rr("r10", "rdx")
    c.emit(bytes.fromhex("660fefc0"))  # pxor xmm0,xmm0
    c.emit(bytes.fromhex("660fefd2"))  # pxor xmm2,xmm2
    if unroll == 4:
        c.label("bulk")
        c.alu_imm("cmp", "r10", 64)
        c.jcc("b", "vector")
        for displacement in (0, 16, 32, 48):
            _reduction_chunk(c, kind, displacement)
        c.alu_imm("add", "rdi", 64)
        c.alu_imm("sub", "r10", 64)
        c.jmp("bulk")
    c.label("vector")
    c.alu_imm("cmp", "r10", 16)
    c.jcc("b", "horizontal")
    _reduction_chunk(c, kind)
    c.alu_imm("add", "rdi", 16)
    c.alu_imm("sub", "r10", 16)
    c.jmp("vector")
    c.label("horizontal")
    c.emit(bytes.fromhex("66480f7ec0660f73d80866490f7ec1"))
    (c.add if kind == "sum_u8" else c.or_)("rax", "r9")
    c.label("tail")
    c.test("r10", "r10")
    c.jcc("e", "done")
    c.load_u8("r9", "rdi")
    (c.add if kind == "sum_u8" else c.or_)("rax", "r9")
    c.alu_imm("add", "rdi", 1)
    c.alu_imm("sub", "r10", 1)
    c.jmp("tail")
    c.label("done")
    if kind == "all_zero_u8":
        c.test("rax", "rax")
        c.setcc("e", "rax")
    c.ret()
    _abort(c)


def _copy(c, unroll):
    c.mov_rr("rax", "r8")
    c.cmp("r8", "rsi")
    c.jcc("a", "abort")
    c.cmp("r8", "rcx")
    c.jcc("a", "abort")
    c.test("r8", "r8")
    c.jcc("e", "done")
    for pointer, end in (("rdi", "r9"), ("rdx", "r10")):
        c.test(pointer, pointer)
        c.jcc("e", "abort")
        c.mov_rr(end, pointer)
        c.add(end, "r8")
        c.jcc("b", "abort")
    c.cmp("r9", "rdx")
    c.jcc("be", "admitted")
    c.cmp("r10", "rdi")
    c.jcc("a", "abort")
    c.label("admitted")
    c.mov_rr("r10", "r8")
    if unroll == 4:
        c.label("bulk")
        c.alu_imm("cmp", "r10", 64)
        c.jcc("b", "vector")
        for displacement in (0, 16, 32, 48):
            _vector_memory(c, 0x6f, "rdx", displacement)
            _vector_memory(c, 0x7f, "rdi", displacement)
        c.alu_imm("add", "rdi", 64)
        c.alu_imm("add", "rdx", 64)
        c.alu_imm("sub", "r10", 64)
        c.jmp("bulk")
    c.label("vector")
    c.alu_imm("cmp", "r10", 16)
    c.jcc("b", "tail")
    _vector_memory(c, 0x6f, "rdx")
    _vector_memory(c, 0x7f, "rdi")
    c.alu_imm("add", "rdi", 16)
    c.alu_imm("add", "rdx", 16)
    c.alu_imm("sub", "r10", 16)
    c.jmp("vector")
    c.label("tail")
    c.test("r10", "r10")
    c.jcc("e", "done")
    c.load_u8("r9", "rdx")
    c.store_u8("rdi", 0, "r9")
    c.alu_imm("add", "rdi", 1)
    c.alu_imm("add", "rdx", 1)
    c.alu_imm("sub", "r10", 1)
    c.jmp("tail")
    c.label("done")
    c.ret()
    _abort(c)
