"""Finite ownership-flow witnesses for the explicit libc-bound ELF profile.

The sources exercise real owned values across moves, calls, loops and renamed
joins. Their Core VM and native observations are finite tests, not a general
ownership or compiler-refinement proof. No allocator or parser limit is raised.
"""
from __future__ import annotations

from tools.hia_selfhost_bulk import Body

HEADER = ("hia-asm.v1 hepta.hia.program.v8 selfhost_elf\n"
    "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(alloc,read,write,trap) entry(b0)\n"
    "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n")
INITIAL = bytes([0xa5]) * 8


def program(body, suffix=""):
    return HEADER + body + "end\n" + suffix


def finish(body, result, suffix=""):
    return program(body.text() + "  ret(" + result + ")\n", suffix)


def tail_source(count):
    b = Body()
    owner = b.value("buffer", "buffer.new", [b.const("usize", 13)])
    result = b.value("u32", "call", [owner, b.const("u32", count)], {"function": "f1"})
    helper = """fn f1(v0:buffer,v1:u32) -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0(v0:buffer,v1:u32)
  v2:u32 = const() {"value":0}
  v3:bool = compare.eq(v1,v2)
  branch v3 b1(v0) b2(v0,v1)
block b1(v4:buffer)
  v5:usize = buffer.len(v4)
  _ = owner.drop(v4)
  v6:u32 = int.cast(v5) {"mode":"wrap"}
  ret(v6)
block b2(v7:buffer,v8:u32)
  v9:u32 = const() {"value":1}
  v10:u32 = int.sub.wrap(v8,v9)
  v11:u32 = call(v7,v10) {"function":"f1"}
  ret(v11)
end
"""
    return finish(b, result, helper)


def cases():
    rows = []

    def add(name, source, result, output=INITIAL):
        rows.append({"id": "flow-" + name, "source": source,
                     "expected_result": result, "expected_output_hex": output.hex()})

    for size in (0, 8):
        b = Body(); length = b.const("usize", size)
        owner = b.value("buffer", "buffer.new", [length])
        for _ in range(4):
            owner = b.value("buffer", "owner.move", [owner])
        view = b.value("mutbuf", "borrow.mut", [owner])
        b.effect("buffer.fill", [view, b.const("u8", 107)])
        b.effect("loan.end", [view])
        read = b.value("readbuf", "borrow.read", [owner])
        b.effect("buffer.copy", ["v1", read, length])
        b.effect("loan.end", [read]); b.effect("owner.drop", [owner])
        add("repeated-move-rebind-" + str(size), finish(b, b.const("u32", size)),
            size, bytes([107]) * size + INITIAL[size:])

    pair_helper = """fn f1(v0:buffer,v1:buffer) -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0(v0:buffer,v1:buffer)
  v2:usize = buffer.len(v0)
  v3:usize = buffer.len(v1)
  v4:usize = int.add.wrap(v2,v3)
  _ = owner.drop(v1)
  _ = owner.drop(v0)
  v5:u32 = int.cast(v4) {"mode":"wrap"}
  ret(v5)
end
"""
    b = Body()
    left = b.value("buffer", "buffer.new", [b.const("usize", 5)])
    right = b.value("buffer", "buffer.new", [b.const("usize", 7)])
    result = b.value("u32", "call", [right, left], {"function": "f1"})
    add("call-two-distinct-owners", finish(b, result, pair_helper), 12)

    forwarding = """fn f1(v0:buffer) -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0(v0:buffer)
  v1:buffer = owner.move(v0)
  v2:u32 = call(v1) {"function":"f2"}
  ret(v2)
end
fn f2(v0:buffer) -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0(v0:buffer)
  v1:usize = buffer.len(v0)
  _ = owner.drop(v0)
  v2:u32 = int.cast(v1) {"mode":"wrap"}
  ret(v2)
end
"""
    b = Body(); owner = b.value("buffer", "buffer.new", [b.const("usize", 19)])
    result = b.value("u32", "call", [owner], {"function": "f1"})
    add("forward-owner-through-two-calls", finish(b, result, forwarding), 19)
    for count in (0, 5):
        add("tail-self-owner-" + str(count), tail_source(count), 13)

    add("nested-loan-permuted-edge", program("""  v3:usize = const() {"value":8}
  v4:buffer = buffer.new(v3)
  v5:mutbuf = borrow.mut(v4)
  v6:readbuf = borrow.read(v5)
  jump b1(v6,v4,v5,v1)
block b1(v7:readbuf,v8:buffer,v9:mutbuf,v10:mutbuf)
  v11:usize = const() {"value":8}
  _ = buffer.copy(v10,v7,v11)
  _ = loan.end(v7)
  _ = loan.end(v9)
  _ = owner.drop(v8)
  v12:u32 = const() {"value":8}
  ret(v12)
"""), 8, bytes(8))

    add("owner-from-later-source-block", program("""  jump b2(v1)
block b1(v3:buffer,v4:mutbuf,v5:mutbuf)
  _ = loan.end(v4)
  v6:readbuf = borrow.read(v3)
  v7:usize = const() {"value":8}
  _ = buffer.copy(v5,v6,v7)
  _ = loan.end(v6)
  _ = owner.drop(v3)
  v8:u32 = const() {"value":67}
  ret(v8)
block b2(v9:mutbuf)
  v10:usize = const() {"value":8}
  v11:buffer = buffer.new(v10)
  v12:mutbuf = borrow.mut(v11)
  v13:u8 = const() {"value":67}
  _ = buffer.fill(v12,v13)
  jump b1(v11,v12,v9)
"""), 67, bytes([67]) * 8)

    add("owner-and-loan-loop", program("""  v3:usize = const() {"value":4}
  v4:buffer = buffer.new(v3)
  v5:mutbuf = borrow.mut(v4)
  v6:usize = const() {"value":0}
  jump b1(v4,v5,v1,v6,v3)
block b1(v7:buffer,v8:mutbuf,v9:mutbuf,v10:usize,v11:usize)
  v12:bool = compare.lt(v10,v11)
  branch v12 b2(v7,v8,v9,v10,v11) b3(v7,v8,v9)
block b2(v13:buffer,v14:mutbuf,v15:mutbuf,v16:usize,v17:usize)
  v18:u8 = int.cast(v16) {"mode":"wrap"}
  _ = buffer.store(v14,v16,v18)
  v19:usize = const() {"value":1}
  v20:usize = int.add.wrap(v16,v19)
  jump b1(v13,v14,v15,v20,v17)
block b3(v21:buffer,v22:mutbuf,v23:mutbuf)
  _ = loan.end(v22)
  v24:readbuf = borrow.read(v21)
  v25:usize = const() {"value":4}
  _ = buffer.copy(v23,v24,v25)
  _ = loan.end(v24)
  _ = owner.drop(v21)
  v26:u32 = const() {"value":4}
  ret(v26)
"""), 4, bytes([0, 1, 2, 3]) + INITIAL[4:])

    for choose in (False, True):
        source = program('  v3:bool = const() {"value":' + str(choose).lower() + "}\n" + """  branch v3 b1() b2()
block b1()
  v4:usize = const() {"value":5}
  v5:buffer = buffer.new(v4)
  jump b3(v5)
block b2()
  v6:usize = const() {"value":7}
  v7:buffer = buffer.new(v6)
  jump b3(v7)
block b3(v8:buffer)
  v9:usize = buffer.len(v8)
  _ = owner.drop(v8)
  v10:u32 = int.cast(v9) {"mode":"wrap"}
  ret(v10)
""")
        add("fresh-owner-join-arm-" + str(int(choose)), source, 5 if choose else 7)

    add("two-owner-swapped-edge", program("""  v3:usize = const() {"value":5}
  v4:usize = const() {"value":7}
  v5:buffer = buffer.new(v3)
  v6:buffer = buffer.new(v4)
  jump b1(v6,v5)
block b1(v7:buffer,v8:buffer)
  v9:usize = buffer.len(v7)
  v10:usize = buffer.len(v8)
  v11:usize = int.add.wrap(v9,v10)
  _ = owner.drop(v7)
  _ = owner.drop(v8)
  v12:u32 = int.cast(v11) {"mode":"wrap"}
  ret(v12)
"""), 12)

    add("two-result-ssa-boundary", program("""  v3:usize = const() {"value":8}
  v2047:buffer,v2046:bool = buffer.try_new(v3)
  v4:readbuf = borrow.read(v2047)
  _ = buffer.copy(v1,v4,v3)
  _ = loan.end(v4)
  _ = owner.drop(v2047)
  v5:u32 = const() {"value":1}
  v6:u32 = const() {"value":0}
  v7:u32 = select(v2046,v5,v6)
  ret(v7)
"""), 1, bytes(8))

    b = Body(); huge = b.const("usize", 1 << 63)
    b.lines.append(f"  v{b.next}:buffer,v{b.next + 1}:bool = buffer.try_new({huge})\n")
    failed = "v" + str(b.next); ok = "v" + str(b.next + 1); b.next += 2
    b.effect("owner.drop", [failed])
    length = b.const("usize", 8); owner = b.value("buffer", "buffer.new", [length])
    read = b.value("readbuf", "borrow.read", [owner])
    b.effect("buffer.copy", ["v1", read, length]); b.effect("loan.end", [read]); b.effect("owner.drop", [owner])
    result = b.value("u32", "select", [ok, b.const("u32", 0), b.const("u32", 8)])
    add("optional-failure-then-live-owner", finish(b, result), 8, bytes(8))
    return rows


def historical_refusals():
    """Invalid ownership graphs plus separately named valid out-of-profile cases."""
    rows = {}
    tail = '  v90:u32 = const() {"value":0}\n  ret(v90)\n'
    new = '  v3:usize = const() {"value":8}\n  v4:buffer = buffer.new(v3)\n'

    def add(name, body, suffix=""):
        rows["flow-" + name] = program(body + tail, suffix).encode()

    add("move-consumed-source", new + "  v5:buffer = owner.move(v4)\n  v6:usize = buffer.len(v4)\n  _ = owner.drop(v5)\n")
    add("drop-consumed-source", new + "  _ = owner.drop(v4)\n  v5:usize = buffer.len(v4)\n")
    add("owner-loan-end", new + "  _ = loan.end(v4)\n")
    add("owner-direct-load", new + "  v5:usize = const() {\"value\":0}\n  v6:u8 = buffer.load(v4,v5)\n  _ = owner.drop(v4)\n")
    add("move-live-read", new + "  v5:readbuf = borrow.read(v4)\n  v6:buffer = owner.move(v4)\n  _ = loan.end(v5)\n  _ = owner.drop(v6)\n")
    add("drop-nested-loan", new + "  v5:mutbuf = borrow.mut(v4)\n  v6:readbuf = borrow.read(v5)\n  _ = owner.drop(v4)\n  _ = loan.end(v6)\n  _ = loan.end(v5)\n")
    add("owner-edge-leak", new + "  jump b1()\nblock b1()\n")
    add("owner-edge-duplicate", new + "  jump b1(v4,v4)\nblock b1(v5:buffer,v6:buffer)\n  _ = owner.drop(v5)\n  _ = owner.drop(v6)\n")
    add("owner-edge-missing-parent", new + "  v5:readbuf = borrow.read(v4)\n  jump b1(v5)\nblock b1(v6:readbuf)\n  _ = loan.end(v6)\n")
    add("owner-edge-missing-child", new + "  v5:readbuf = borrow.read(v4)\n  jump b1(v4)\nblock b1(v6:buffer)\n  _ = owner.drop(v6)\n")

    helper = """fn f1(v0:buffer) -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0(v0:buffer)
  _ = owner.drop(v0)
  v1:u32 = const() {"value":0}
  ret(v1)
end
"""
    call = '  v5:u32 = call(v4) {"function":"f1"}\n'
    add("call-then-owner-use", new + call + "  v6:usize = buffer.len(v4)\n", helper)
    add("call-then-owner-drop", new + call + "  _ = owner.drop(v4)\n", helper)
    add("call-with-live-loan", new + "  v6:readbuf = borrow.read(v4)\n" + call + "  _ = loan.end(v6)\n", helper)
    pair_helper = helper.replace("v0:buffer)", "v0:buffer,v2:buffer)").replace(
        "  _ = owner.drop(v0)\n", "  _ = owner.drop(v0)\n  _ = owner.drop(v2)\n")
    add("call-duplicate-owner", new + '  v5:u32 = call(v4,v4) {"function":"f1"}\n', pair_helper)

    bad_join = """  v3:bool = const() {"value":true}
  branch v3 b1() b2()
block b1()
  v4:usize = const() {"value":1}
  v5:buffer = buffer.new(v4)
  v6:buffer = buffer.new(v4)
  v7:readbuf = borrow.read(v5)
  jump b3(v5,v6,v7)
block b2()
  v8:usize = const() {"value":1}
  v9:buffer = buffer.new(v8)
  v10:buffer = buffer.new(v8)
  v11:readbuf = borrow.read(v10)
  jump b3(v9,v10,v11)
block b3(v12:buffer,v13:buffer,v14:readbuf)
  _ = loan.end(v14)
  _ = owner.drop(v12)
  _ = owner.drop(v13)
"""
    add("join-mismatched-owner-root", bad_join)
    loop = next(row["source"] for row in cases() if row["id"] == "flow-owner-and-loan-loop")
    rows["flow-loop-backedge-consumed-root"] = loop.replace("  jump b1(v13,v14,v15,v20,v17)",
        "  _ = loan.end(v14)\n  _ = owner.drop(v13)\n  jump b1(v13,v14,v15,v20,v17)").encode()

    simple = program(new + "  _ = owner.drop(v4)\n" + tail)
    rows["flow-new-missing-argument"] = simple.replace("buffer.new(v3)", "buffer.new()").encode()
    rows["flow-new-extra-argument"] = simple.replace("buffer.new(v3)", "buffer.new(v3,v3)").encode()
    rows["flow-new-wrong-size-type"] = simple.replace("v3:usize", "v3:u64").encode()
    rows["flow-new-unexpected-attribute"] = simple.replace("buffer.new(v3)", 'buffer.new(v3) {"value":0}').encode()
    rows["flow-drop-extra-argument"] = simple.replace("owner.drop(v4)", "owner.drop(v4,v4)").encode()
    rows["flow-drop-unexpected-result"] = simple.replace("_ = owner.drop(v4)", "v5:u32 = owner.drop(v4)").encode()
    rows["flow-drop-unexpected-attribute"] = simple.replace("owner.drop(v4)", 'owner.drop(v4) {"value":0}').encode()
    rows["flow-move-unexpected-result-type"] = simple.replace("  _ = owner.drop(v4)",
        "  v5:readbuf = owner.move(v4)\n  _ = loan.end(v5)").encode()
    rows["flow-move-missing-result"] = simple.replace("  _ = owner.drop(v4)", "  _ = owner.move(v4)").encode()

    source = next(row["source"] for row in cases() if row["id"] == "flow-two-result-ssa-boundary")
    for index in (2048, 8192, (1 << 64) - 1):
        rows["flow-profile-owner-result-ssa-" + str(index)] = source.replace("v2047", "v" + str(index)).encode()
        rows["flow-profile-bool-result-ssa-" + str(index)] = source.replace("v2046", "v" + str(index)).encode()
    rows["flow-try-too-many-results"] = source.replace("v2047:buffer,v2046:bool", "v2047:buffer,v2046:bool,v5:u32").encode()

    # A dormant owner-parameter function still requires the explicit ELF type
    # profile. These general-Core-valid programs must not enter flat codegen.
    flat = HEADER.replace("v8 selfhost_elf", "v8 selfhost").replace(
        "effects(alloc,read,write,trap)", "effects(read,write,trap)") + tail + "end\n"
    dormant_loop = """fn f1(v0:buffer) -> (u32) effects(read,write,trap) entry(b0)
block b0(v0:buffer)
  jump b1(v0)
block b1(v1:buffer)
  jump b1(v1)
end
"""
    dormant_tail = """fn f1(v0:buffer) -> (u32) effects(read,write,trap) entry(b0)
block b0(v0:buffer)
  v1:u32 = call(v0) {"function":"f1"}
  ret(v1)
end
"""
    rows["flow-profile-flat-dormant-owner-parameter"] = (flat + dormant_loop).encode()
    rows["flow-profile-flat-dormant-owner-tail"] = (flat + dormant_tail).encode()
    return rows


def profile_refusal_ids():
    return {name for name in refusals() if name.startswith("flow-profile-")}


def expanded_name_cases():
    from tools.hia_selfhost_names import core_observed_case
    return [core_observed_case(name, source) for name, source in historical_refusals().items()
            if name.startswith('flow-profile-') and '-ssa-' in name]


def refusals():
    return {name: source for name, source in historical_refusals().items()
            if not (name.startswith('flow-profile-') and '-ssa-' in name)}
