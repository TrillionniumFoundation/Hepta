"""Prospective authored API-maintenance contracts; not a library-upgrade sample."""
from copy import deepcopy
from hashlib import sha256

# Reuse notation helpers only. Prior task contracts, answers and cases remain
# separate and unchanged, and this imported file is bound in the new freeze.
from benchmarks.hia_agent_maintenance.tasks import p, op, const, block, ret, branch, program

MASK = (1 << 32) - 1
TASKS = (
    {"id": "cursor_api_v2",
     "previous_contract": "target(x,y) returns x+y modulo 2^32 for any u32 cursor x and advance y.",
     "description": "Maintain the supplied target(x:u32,y:u32)->u32 for cursor API v2. Valid cursors are 0 through 1000 inclusive. If x exceeds 1000, return the error sentinel 4294967295. Otherwise advance by as much of y as fits without passing 1000, returning the new cursor min(1000,x+y) computed in mathematical integers. Invalid inputs return the sentinel even when y is zero. Preserve the exported signature, avoid arithmetic traps, and do not wrap before clamping.",
     "public": [[0, 1], [999, 2], [1000, 1], [1001, 0], [1, 4294967295], [4294967295, 4294967295]]},
    {"id": "owned_record_api_v2", "resource_contract": "single-owned-buffer-v2",
     "previous_contract": "Allocate n=x modulo 17+1 zeroed bytes, store low8(x XOR y) at y modulo n, read it back, explicitly release the owner, and return 256*n+readback.",
     "description": "Maintain the supplied target(x:u32,y:u32)->u32 for owned record API v2. Allocate exactly one zeroed byte buffer of length n=x modulo 19+2. The index is (x XOR y) modulo n, and the stored byte is low8(x+y modulo 2^32). Actually store at that index, read the stored byte from that same owner, end all local loans and explicitly release the owner before returning 512*n+readback. Preserve the exported signature for all u32 inputs. A scalar shortcut cannot replace the owned-buffer lifecycle. Rust must use the disclosed Vec<u8> API and explicit drop(data).",
     "public": [[0, 0], [17, 31], [18, 255], [19, 1], [4294967295, 1], [256, 257]]},
)


def resource_expected(task_id, x, y):
    if task_id != "owned_record_api_v2":
        raise ValueError("not a registered resource contract")
    length = x % 19 + 2
    index, byte = (x ^ y) % length, (x + y) % 256
    return {"length": length, "index": index, "byte": byte, "result": 512 * length + byte}


def oracle(task_id, x, y):
    if task_id == "cursor_api_v2":
        return MASK if x > 1000 else min(1000, x + y)
    if task_id == "owned_record_api_v2":
        expected = resource_expected(task_id, x, y)
        data = [0] * expected["length"]
        data[expected["index"]] = expected["byte"]
        return 512 * len(data) + data[expected["index"]]
    raise ValueError("unregistered maintenance-v2 task")


def cases(task, hidden=False):
    if not hidden:
        return deepcopy(task["public"])
    rows = [[0, MASK], [MASK, 0], [1000, 0], [1001, 1], [999, MASK],
            [19, MASK], [18, 20], [MASK - 1, MASK]]
    state = int.from_bytes(sha256(("authored-maintenance-v2/" + task["id"]).encode()).digest()[:4], "little")
    for _ in range(64):
        state = (1664525 * state + 1013904223) & MASK
        x = state
        state = (1664525 * state + 1013904223) & MASK
        rows.append([x, state])
    return rows


def _cursor(revised):
    if not revised:
        return program([block("entry", ["x", "y"], [op("int.add.wrap", ["x", "y"], "answer")], ret("answer"))], effects=())
    return program([
        block("entry", ["x", "y"], [const("cap", 1000), op("compare.gt", ["x", "cap"], "invalid", "bool")],
              branch("invalid", ("error",), ("valid", "x", "y", "cap"))),
        block("error", [], [const("sentinel", MASK)], ret("sentinel")),
        block("valid", ["cursor", "requested", "limit"], [op("int.sub.checked", ["limit", "cursor"], "remaining"),
            op("compare.le", ["requested", "remaining"], "fits", "bool"),
            op("select", ["fits", "requested", "remaining"], "advance"),
            op("int.add.checked", ["cursor", "advance"], "answer")], ret("answer"))])


def _buffer(revised):
    return program([block("entry", ["x", "y"], [const("modulus", 19 if revised else 17),
        const("extra", 2 if revised else 1), const("weight", 512 if revised else 256),
        op("int.rem.checked", ["x", "modulus"], "n0"), op("int.add.checked", ["n0", "extra"], "n"),
        op("bit.xor", ["x", "y"], "mixed"),
        op("int.rem.checked", ["mixed" if revised else "y", "n"], "index"),
        op("int.cast", ["n"], "size", "usize", mode="checked"),
        op("int.cast", ["index"], "pos", "usize", mode="checked"),
        op("int.add.wrap" if revised else "bit.xor", ["x", "y"], "widebyte"),
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
        return {"cursor_api_v2": _cursor, "owned_record_api_v2": _buffer}[task_id](revised)
    if language != "rust":
        raise ValueError("unsupported language")
    if task_id == "cursor_api_v2":
        return ("fn target(x:u32,y:u32)->u32 { if x>1000 { 4294967295 } else { x+y.min(1000-x) } }" if revised else
                "fn target(x:u32,y:u32)->u32 { x.wrapping_add(y) }")
    if task_id == "owned_record_api_v2":
        return ("fn target(x:u32,y:u32)->u32 { let n=(x%19+2) as usize; let mut data=vec![0u8;n]; let index=((x^y) as usize)%n; data[index]=x.wrapping_add(y) as u8; let readback=data[index] as u32; drop(data); 512*n as u32+readback }" if revised else
                "fn target(x:u32,y:u32)->u32 { let n=(x%17+1) as usize; let mut data=vec![0u8;n]; let index=(y as usize)%n; data[index]=(x^y) as u8; let readback=data[index] as u32; drop(data); 256*n as u32+readback }")
    raise ValueError("unregistered maintenance-v2 task")


def initial(task_id, language):
    return _candidate(task_id, language, False)


def reference(task_id, language):
    return _candidate(task_id, language, True)
