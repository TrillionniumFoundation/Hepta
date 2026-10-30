"""Prospective task contracts, independently written oracles and labelled controls.

The reference builders are used only by the no-generation control phase. They
must never be included in a model prompt or treated as Agent observations.
"""
from __future__ import annotations

import copy

MASK = (1 << 32) - 1
TASKS = (
    {"id": "quota_clip", "description": "Implement target(x: u32, y: u32) -> u32. A pool has capacity 1000. x is already used; y is the requested amount. Return min(y, max(0, 1000-x)), using mathematical integers for this specification. Inputs span the full u32 range.",
     "public": [[0, 7], [998, 8], [1000, 9], [1001, 0], [999, 1], [4294967295, 4294967295]]},
    {"id": "rotate_lane", "description": "Implement target(x: u32, y: u32) -> u32. Let low be the low 16 bits of x and high be its high 16 bits. Rotate low RIGHT within exactly 16 bits by y modulo 16 positions, then XOR that 16-bit result with high. Return the unsigned 16-bit result widened to u32. Rotation by zero is identity.",
     "public": [[0, 0], [1, 1], [305419896, 4], [4294967295, 16], [65536, 31], [32768, 15]]},
    {"id": "weighted_prefix", "description": "Implement target(x: u32, y: u32) -> u32. Let count = y modulo 33. For integer i from 0 through count-1, form term = ((x+i) modulo 2^32) XOR (17*i). Return the sum of the terms modulo 2^32; an empty prefix returns zero. Any implementation satisfying this mathematical contract for every u32 input is allowed.",
     "public": [[0, 0], [9, 1], [5, 3], [4294967295, 2], [7, 33], [2147483648, 32]]},
    {"id": "buffer_lane", "description": "Implement target(x: u32, y: u32) -> u32. Let n = x modulo 17 + 1 and index = y modulo n. Allocate a zeroed owned byte buffer of length n, write the low 8 bits of (x+y modulo 2^32) at index, then read that byte back. Return 256*n + readback as u32. End local loans and release the owner before normal return. The use of an owned buffer, an actual store and load is required: do not replace them with a scalar shortcut. Rust should use a Vec<u8> and explicitly drop it after reading.",
     "public": [[0, 0], [16, 31], [17, 255], [4294967295, 1], [2, 1000], [256, 257]]},
)


def oracle(task_id: str, x: int, y: int) -> int:
    if task_id == "quota_clip":
        return min(y, max(0, 1000 - x))
    if task_id == "rotate_lane":
        bits = [(x >> i) & 1 for i in range(16)]
        rotated = sum(bits[(i + y % 16) % 16] << i for i in range(16))
        return rotated ^ (x // 65536)
    if task_id == "weighted_prefix":
        # Independent mathematical sequence, not either implementation's CFG.
        return sum(((x + i) % (1 << 32)) ^ (17 * i) for i in range(y % 33)) % (1 << 32)
    if task_id == "buffer_lane":
        data = [0 for _ in range(x % 17 + 1)]
        data[y % len(data)] = (x + y) % 256
        return 256 * len(data) + data[y % len(data)]
    raise ValueError("unregistered task")


def cases(task, hidden=False):
    if not hidden:
        return copy.deepcopy(task["public"])
    # Frozen before generation; never disclose this function or cases in prompts.
    state = 0x7E31A9C5
    result = [[0, 4294967295], [4294967295, 0], [65535, 15], [65536, 16],
              [999, 4294967295], [1001, 1], [4294967294, 32], [4294967295, 65]]
    for _ in range(64):
        state = (1103515245 * state + 12345) & MASK
        x = state
        state = (1103515245 * state + 12345) & MASK
        result.append([x, state])
    return result


def p(name, typ="u32"):
    return {"name": name, "type": typ}


def op(name, args=(), output=None, typ="u32", **attrs):
    return {"op": name, "args": list(args), "out": [] if output is None else [p(output, typ)], "attrs": attrs}


def const(name, value, typ="u32"):
    return op("const", output=name, typ=typ, value=value)


def block(name, names, ops, term):
    return {"id": name, "params": [p(n) if isinstance(n, str) else p(*n) for n in names], "ops": ops, "term": term}


def ret(name):
    return {"op": "ret", "values": [name]}


def jump(name, *args):
    return {"op": "jump", "target": name, "args": list(args)}


def branch(cond, yes, no):
    return {"op": "branch", "cond": cond, "then": {"target": yes[0], "args": list(yes[1:])},
            "else": {"target": no[0], "args": list(no[1:])}}


def program(blocks, effects=("trap",)):
    return {"schema": "hepta.hia.program.v6", "module": "public_tool_candidate", "exports": ["target"],
            "functions": [{"name": "target", "params": [p("x"), p("y")], "returns": ["u32"],
                           "effects": list(effects), "entry": "entry", "blocks": blocks}]}


def reference(task_id, language):
    if language == "rust":
        return {"quota_clip": "fn target(x:u32,y:u32)->u32 { y.min(1000u32.saturating_sub(x)) }",
                "rotate_lane": "fn target(x:u32,y:u32)->u32 { let a=x&65535; let n=y%16; (((a>>n)|(a<<(16-n)))&65535)^(x>>16) }",
                "weighted_prefix": "fn target(x:u32,y:u32)->u32 { let mut acc=0u32; for i in 0..y%33 { acc=acc.wrapping_add(x.wrapping_add(i)^(17*i)); } acc }",
                "buffer_lane": "fn target(x:u32,y:u32)->u32 { let n=(x%17+1) as usize; let mut data=vec![0u8;n]; let index=(y as usize)%n; data[index]=x.wrapping_add(y) as u8; let readback=data[index] as u32; drop(data); 256*n as u32+readback }"}[task_id]
    if task_id == "quota_clip":
        return program([
            block("entry", ["x", "y"], [const("cap", 1000), op("compare.ge", ["x", "cap"], "full", "bool")], branch("full", ("zero",), ("room", "x", "y", "cap"))),
            block("zero", [], [const("z", 0)], ret("z")),
            block("room", ["u", "r", "c"], [op("int.sub.checked", ["c", "u"], "left"), op("compare.le", ["r", "left"], "fits", "bool")], branch("fits", ("answer", "r"), ("answer", "left"))),
            block("answer", ["value"], [], ret("value"))])
    if task_id == "rotate_lane":
        return program([block("entry", ["x", "y"], [const("mask", 65535), const("sixteen", 16),
            op("bit.and", ["x", "mask"], "low"), op("int.rem.checked", ["y", "sixteen"], "n"),
            op("int.sub.checked", ["sixteen", "n"], "back"), op("int.shr.checked", ["low", "n"], "right"),
            op("int.shl.checked", ["low", "back"], "left"), op("bit.or", ["right", "left"], "wide"),
            op("bit.and", ["wide", "mask"], "rot"), op("int.shr.checked", ["x", "sixteen"], "high"),
            op("bit.xor", ["rot", "high"], "answer")], ret("answer"))])
    if task_id == "weighted_prefix":
        return program([
            block("entry", ["x", "y"], [const("mod", 33), const("z", 0), op("int.rem.checked", ["y", "mod"], "n")], jump("loop", "x", "n", "z", "z")),
            block("loop", ["lx", "ln", "li", "la"], [op("compare.lt", ["li", "ln"], "more", "bool")], branch("more", ("body", "lx", "ln", "li", "la"), ("done", "la"))),
            block("body", ["bx", "bn", "bi", "ba"], [const("weight", 17), const("one", 1), op("int.add.wrap", ["bx", "bi"], "v"), op("int.mul.checked", ["bi", "weight"], "w"), op("bit.xor", ["v", "w"], "t"), op("int.add.wrap", ["ba", "t"], "a2"), op("int.add.checked", ["bi", "one"], "i2")], jump("loop", "bx", "bn", "i2", "a2")),
            block("done", ["a"], [], ret("a"))])
    if task_id == "buffer_lane":
        return program([block("entry", ["x", "y"], [const("seventeen", 17), const("one", 1), const("weight", 256),
            op("int.rem.checked", ["x", "seventeen"], "n0"), op("int.add.checked", ["n0", "one"], "n"),
            op("int.rem.checked", ["y", "n"], "index"), op("int.cast", ["n"], "size", "usize", mode="checked"),
            op("int.cast", ["index"], "pos", "usize", mode="checked"), op("int.add.wrap", ["x", "y"], "sum"),
            op("int.cast", ["sum"], "byte", "u8", mode="wrap"), op("buffer.new", ["size"], "owner", "buffer"),
            op("borrow.mut", ["owner"], "writer", "mutbuf"), op("buffer.store", ["writer", "pos", "byte"]),
            op("loan.end", ["writer"]), op("borrow.read", ["owner"], "reader", "readbuf"),
            op("buffer.load", ["reader", "pos"], "readbyte", "u8"), op("loan.end", ["reader"]),
            op("owner.drop", ["owner"]), op("int.cast", ["readbyte"], "readback", mode="checked"),
            op("int.mul.checked", ["weight", "n"], "tag"), op("int.add.checked", ["tag", "readback"], "answer")], ret("answer"))], ("alloc", "read", "write", "trap"))
    raise ValueError("unregistered task")
