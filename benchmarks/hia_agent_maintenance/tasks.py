"""New authored maintenance contracts, initial programs and independent oracles.

Initial programs implement the previous contracts. Reference repairs are used
only by no-generation controls. Hidden cases and reference repairs never enter
model prompts. These tasks do not represent a C++ library migration population.
"""
from __future__ import annotations

import copy
from hashlib import sha256

MASK = (1 << 32) - 1
TASKS = (
    {"id": "quota_reserve",
     "previous_contract": "Return min(y, max(0, 4096-x)) for unsigned 32-bit used x and requested y.",
     "description": "Maintain the supplied target(x:u32,y:u32)->u32 function. The 4096-unit pool now permanently reserves 64 units, and an individual request is capped at 768 units. Return min(y, 768, max(0, 4032-x)), interpreting this specification in mathematical integers over all u32 inputs. Preserve the exported signature and avoid arithmetic traps.",
     "public": [[0, 1], [4000, 100], [4031, 1000], [4032, 1], [0, 800], [4294967295, 4294967295]]},
    {"id": "bitfield_revision",
     "previous_contract": "Rotate the low 16 bits of x RIGHT by y modulo 16 and XOR with x's high 16 bits.",
     "description": "Maintain the supplied target(x:u32,y:u32)->u32 for a revised packet layout. The low 12 bits of x are a lane; bits 12 through 23 are a 12-bit tag; bits 24 through 31 are ignored. Rotate the lane LEFT within exactly 12 bits by y modulo 12 positions, then XOR with the tag. Return that unsigned 12-bit value widened to u32. Rotation by zero is identity. Preserve the exported signature for all u32 inputs.",
     "public": [[1, 1], [11259375, 5], [16773121, 12], [4294967295, 23], [0, 0], [2048, 1]]},
    {"id": "buffer_resize",
     "previous_contract": "Allocate n=x modulo 17+1 zeroed bytes; store low8(x+y modulo 2^32) at y modulo n; read it back; release the owner; return 256*n+readback.",
     "description": "Maintain the supplied target(x:u32,y:u32)->u32 for a revised owned-buffer format. The new length is n=x modulo 23+1; the index is y modulo n; the stored byte is the low 8 bits of x XOR y. Allocate exactly one zeroed owned byte buffer of length n, actually store and read the byte, end local loans and explicitly release the owner before normal return. Return 256*n+readback as u32. Preserve the signature. A scalar shortcut cannot replace the required owned-buffer lifecycle. Rust must use the disclosed Vec<u8> API and explicitly drop it.",
     "public": [[0, 0], [17, 31], [22, 255], [23, 1], [4294967295, 1], [256, 257]]},
)


def oracle(task_id, x, y):
    if task_id == "quota_reserve":
        return min(y, 768, max(0, 4032 - x))
    if task_id == "bitfield_revision":
        # Independent bit-position construction, not either repair's shifts.
        lane = [(x // (1 << i)) % 2 for i in range(12)]
        rotation = sum(lane[(i - y % 12) % 12] * (1 << i) for i in range(12))
        tag = (x // 4096) % 4096
        return rotation ^ tag
    if task_id == "buffer_resize":
        data = [0 for _ in range(x % 23 + 1)]
        data[y % len(data)] = (x ^ y) % 256
        return 256 * len(data) + data[y % len(data)]
    raise ValueError("unregistered maintenance task")


def cases(task, hidden=False):
    if not hidden:
        return copy.deepcopy(task["public"])
    result = [[0, 4294967295], [4294967295, 0], [4095, 12], [4096, 16],
              [4031, 769], [4032, 1], [4294967294, 23], [4294967295, 47]]
    state = int.from_bytes(sha256(("maintenance-v1/" + task["id"]).encode()).digest()[:4], "little")
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


def branch(condition, yes, no):
    return {"op": "branch", "cond": condition, "then": {"target": yes[0], "args": list(yes[1:])},
            "else": {"target": no[0], "args": list(no[1:])}}


def program(blocks, effects=("trap",)):
    return {"schema": "hepta.hia.program.v6", "module": "maintenance_candidate", "exports": ["target"],
            "functions": [{"name": "target", "params": [p("x"), p("y")], "returns": ["u32"],
                           "effects": list(effects), "entry": "entry", "blocks": blocks}]}


def _quota(revised):
    operations = [op("int.sub.checked", ["c", "u"], "left")]
    if revised:
        operations += [const("limit", 768), op("compare.le", ["r", "limit"], "bounded", "bool"),
                       op("select", ["bounded", "r", "limit"], "request")]
    else:
        operations += [op("int.add.wrap", ["r", "zero"], "request")]
    operations.append(op("compare.le", ["request", "left"], "fits", "bool"))
    return program([
        block("entry", ["x", "y"], [const("cap", 4032 if revised else 4096),
            const("z", 0), op("compare.ge", ["x", "cap"], "full", "bool")],
            branch("full", ("zero",), ("room", "x", "y", "cap", "z"))),
        block("zero", [], [const("answer", 0)], ret("answer")),
        block("room", ["u", "r", "c", "zero"], operations,
              branch("fits", ("answer", "request"), ("answer", "left"))),
        block("answer", ["value"], [], ret("value"))])


def _bitfield(revised):
    bits = 12 if revised else 16
    first, second = ("int.shl.checked", "int.shr.checked") if revised else ("int.shr.checked", "int.shl.checked")
    return program([block("entry", ["x", "y"], [const("mask", (1 << bits) - 1),
        const("width", bits), op("bit.and", ["x", "mask"], "low"),
        op("int.rem.checked", ["y", "width"], "n"), op("int.sub.checked", ["width", "n"], "back"),
        op(first, ["low", "n"], "part1"), op(second, ["low", "back"], "part2"),
        op("bit.or", ["part1", "part2"], "wide"), op("bit.and", ["wide", "mask"], "rot"),
        op("int.shr.checked", ["x", "width"], "upper"), op("bit.and", ["upper", "mask"], "tag"),
        op("bit.xor", ["rot", "tag"], "answer")], ret("answer"))])


def _buffer(revised):
    return program([block("entry", ["x", "y"], [const("modulus", 23 if revised else 17),
        const("one", 1), const("weight", 256), op("int.rem.checked", ["x", "modulus"], "n0"),
        op("int.add.checked", ["n0", "one"], "n"), op("int.rem.checked", ["y", "n"], "index"),
        op("int.cast", ["n"], "size", "usize", mode="checked"),
        op("int.cast", ["index"], "pos", "usize", mode="checked"),
        op("bit.xor" if revised else "int.add.wrap", ["x", "y"], "widebyte"),
        op("int.cast", ["widebyte"], "byte", "u8", mode="wrap"),
        op("buffer.new", ["size"], "owner", "buffer"), op("borrow.mut", ["owner"], "writer", "mutbuf"),
        op("buffer.store", ["writer", "pos", "byte"]), op("loan.end", ["writer"]),
        op("borrow.read", ["owner"], "reader", "readbuf"), op("buffer.load", ["reader", "pos"], "loaded", "u8"),
        op("loan.end", ["reader"]), op("owner.drop", ["owner"]),
        op("int.cast", ["loaded"], "readback", mode="checked"),
        op("int.mul.checked", ["weight", "n"], "tag"), op("int.add.checked", ["tag", "readback"], "answer")],
        ret("answer"))], ("alloc", "read", "write", "trap"))


def _candidate(task_id, language, revised):
    if language == "hia":
        return {"quota_reserve": _quota, "bitfield_revision": _bitfield, "buffer_resize": _buffer}[task_id](revised)
    if language != "rust":
        raise ValueError("unsupported language")
    if task_id == "quota_reserve":
        return ("fn target(x:u32,y:u32)->u32 { y.min(768).min(4032u32.saturating_sub(x)) }" if revised
                else "fn target(x:u32,y:u32)->u32 { y.min(4096u32.saturating_sub(x)) }")
    if task_id == "bitfield_revision":
        return ("fn target(x:u32,y:u32)->u32 { let low=x&4095; let n=y%12; (((low<<n)|(low>>(12-n)))&4095)^((x>>12)&4095) }" if revised
                else "fn target(x:u32,y:u32)->u32 { let low=x&65535; let n=y%16; (((low>>n)|(low<<(16-n)))&65535)^(x>>16) }")
    if task_id == "buffer_resize":
        return ("fn target(x:u32,y:u32)->u32 { let n=(x%23+1) as usize; let mut data=vec![0u8;n]; let index=(y as usize)%n; data[index]=(x^y) as u8; let readback=data[index] as u32; drop(data); 256*n as u32+readback }" if revised
                else "fn target(x:u32,y:u32)->u32 { let n=(x%17+1) as usize; let mut data=vec![0u8;n]; let index=(y as usize)%n; data[index]=x.wrapping_add(y) as u8; let readback=data[index] as u32; drop(data); 256*n as u32+readback }")
    raise ValueError("unregistered maintenance task")


def initial(task_id, language):
    return _candidate(task_id, language, False)


def reference(task_id, language):
    return _candidate(task_id, language, True)
