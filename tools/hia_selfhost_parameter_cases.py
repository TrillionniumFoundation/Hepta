"""Resource parameter SSA boundaries, including a retained compiler-trap regression.

Historical names above v2047 are now admitted by exact-name interning.
The original fixture IDs remain in the positive execution inventory.
"""
from __future__ import annotations

from tools.hia_selfhost_bulk import Body
from tools.hia_selfhost_owned_elf_cases import HEADER

INITIAL = bytes([0xa5]) * 8


def _argument(body, typ):
    if typ in {"readbuf", "mutbuf"}:
        # Ensure the same closed allocator ELF shape in all four cases. This
        # empty allocation has no runtime allocator call and no live residue.
        empty = body.value("buffer", "buffer.new", [body.const("usize", 0)])
        body.effect("owner.drop", [empty])
        return "v0" if typ == "readbuf" else "v1"
    if typ == "buffer":
        return body.value("buffer", "buffer.new", [body.const("usize", 4)])
    return body.value("chain", "chain.empty")


def _body(typ, name):
    b = Body(20)
    if typ == "chain":
        empty = b.value("bool", "chain.is_empty", [name])
        b.effect("owner.drop", [name])
        result = b.value("u32", "select", [empty, b.const("u32", 1), b.const("u32", 0)])
    else:
        if typ == "mutbuf":
            b.effect("buffer.fill", [name, b.const("u8", 41)])
        length = b.value("usize", "buffer.len", [name])
        if typ == "buffer":
            b.effect("owner.drop", [name])
        result = b.value("u32", "int.cast", [length], {"mode": "wrap"})
    return b.text() + "  ret(" + result + ")\n"


def source(typ, index, *, signature=False):
    b = Body(); argument = _argument(b, typ); name = "v" + str(index)
    if signature:
        result = b.value("u32", "call", [argument], {"function": "f1"})
        helper = ("fn f1(" + name + ":" + typ + ") -> (u32) effects(alloc,read,write,trap) entry(b0)\n"
            "block b0(" + name + ":" + typ + ")\n" + _body(typ, name) + "end\n")
        return (HEADER + b.text() + "  ret(" + result + ")\nend\n" + helper).encode()
    return (HEADER + b.text() + "  jump b1(" + argument + ")\nblock b1(" + name + ":" + typ + ")\n"
            + _body(typ, name) + "end\n").encode()


def cases():
    return [{"id": "parameter-boundary-" + typ + "-2047", "source": source(typ, 2047).decode(),
             "expected_result": {"readbuf": 0, "mutbuf": 8, "buffer": 4, "chain": 1}[typ],
             "expected_output_hex": ((bytes([41]) * 8) if typ == "mutbuf" else INITIAL).hex()}
            for typ in ("readbuf", "mutbuf", "buffer", "chain")]


def historical_refusals():
    return {"parameter-profile-" + ("function-" if signature else "block-") + typ + "-" + str(index):
            source(typ, index, signature=signature)
            for signature in (False, True)
            for typ in ("readbuf", "mutbuf", "buffer", "chain")
            for index in (2048, 8192, (1 << 64) - 1)}


def expanded_name_cases():
    from tools.hia_selfhost_names import core_observed_case
    return [core_observed_case(name, source) for name, source in historical_refusals().items()]


def refusals():
    # Every former exclusion here was a spelling restriction, not a Core error.
    return {}
