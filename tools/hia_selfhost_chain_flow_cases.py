"""Independent finite chain flow and explicit allocator-failure witnesses.

These are test inputs for the ordinary bounded Core compiler. Profile refusals
remain distinct from invalid Core; no fixture asserts a general refinement
theorem, loader property, or unconditional allocator success.
"""
from __future__ import annotations

import re

from tools.hia_selfhost_bulk import Body
from tools.hia_selfhost_owned_elf_cases import HEADER, multiple

INITIAL = bytes([0xa5]) * 8


def program(body, suffix=""):
    return HEADER + body + "end\n" + suffix


def finish(body, result, suffix=""):
    return program(body.text() + "  ret(" + result + ")\n", suffix)


def payload(body, size, byte):
    owner = body.value("buffer", "buffer.new", [body.const("usize", size)])
    view = body.value("mutbuf", "borrow.mut", [owner])
    body.effect("buffer.fill", [view, body.const("u8", byte)])
    body.effect("loan.end", [view])
    return owner


def populated(body, size=8, byte=61):
    owner = payload(body, size, byte)
    chain = body.value("chain", "chain.empty")
    chain, fallback, ok = multiple(body, ["chain", "buffer", "bool"], "chain.try_push", [chain, owner])
    body.effect("owner.drop", [fallback])
    return chain


def all_true(body, conditions):
    value = conditions[0]
    for condition in conditions[1:]:
        value = body.value("bool", "bool.and", [value, condition])
    return body.value("u32", "select", [value, body.const("u32", 1), body.const("u32", 0)])


def formerly_excluded_owner_result():
    """Unchanged former refusal, now required to execute successfully."""
    return program("""  v3:chain = chain.empty()
  v4:chain,v5:bool = call(v3) {"function":"f1"}
  _ = owner.drop(v4)
  v6:u32 = const() {"value":1}
  v7:u32 = const() {"value":0}
  v8:u32 = select(v5,v6,v7)
  ret(v8)
""", """fn f1(v0:chain) -> (chain,bool) effects(alloc,read,write,trap) entry(b0)
block b0(v0:chain)
  v1:bool = chain.is_empty(v0)
  ret(v0,v1)
end
""")


def cases():
    rows = [{"id": "chain-flow-profile-multiple-call-return-values",
             "source": formerly_excluded_owner_result(), "expected_result": 1,
             "expected_output_hex": INITIAL.hex()}]

    def add(name, source, result, output=INITIAL):
        rows.append({"id": "chain-flow-" + name, "source": source,
                     "expected_result": result, "expected_output_hex": output.hex()})

    b = Body()
    chain = b.value("chain", "chain.empty")
    chain, fallback, present = multiple(b, ["chain", "buffer", "bool"], "chain.pop", [chain])
    length = b.value("usize", "buffer.len", [fallback])
    checks = [b.value("bool", "chain.is_empty", [chain]),
              b.value("bool", "bool.not", [present]),
              b.value("bool", "compare.eq", [length, b.const("usize", 0)])]
    b.effect("owner.drop", [fallback]); b.effect("owner.drop", [chain])
    add("empty-pop-three-results", finish(b, all_true(b, checks)), 1)

    b = Body(); owner = payload(b, 8, 61)
    chain = b.value("chain", "chain.empty")
    chain, fallback, ok = multiple(b, ["chain", "buffer", "bool"], "chain.try_push", [chain, owner])
    checks = [ok, b.value("bool", "bool.not", [b.value("bool", "chain.is_empty", [chain])]),
              b.value("bool", "compare.eq", [b.value("usize", "buffer.len", [fallback]), b.const("usize", 0)])]
    b.effect("owner.drop", [fallback])
    chain, removed, present = multiple(b, ["chain", "buffer", "bool"], "chain.pop", [chain])
    checks += [present, b.value("bool", "chain.is_empty", [chain]),
               b.value("bool", "compare.eq", [b.value("usize", "buffer.len", [removed]), b.const("usize", 8)])]
    read = b.value("readbuf", "borrow.read", [removed])
    b.effect("buffer.copy", ["v1", read, b.const("usize", 8)])
    b.effect("loan.end", [read]); b.effect("owner.drop", [removed]); b.effect("owner.drop", [chain])
    add("successful-push-pop-three-results", finish(b, all_true(b, checks)), 1, bytes([61]) * 8)

    b = Body(); chain = populated(b, 8, 43)
    for _ in range(4):
        chain = b.value("chain", "owner.move", [chain])
    left = b.value("readbuf", "chain.head_read", [chain])
    right = b.value("readbuf", "chain.head_read", [chain])
    query = b.value("bool", "chain.is_empty", [chain])
    b.effect("buffer.copy", ["v1", right, b.const("usize", 8)])
    b.effect("loan.end", [left]); b.effect("loan.end", [right]); b.effect("owner.drop", [chain])
    add("moves-shared-head-query", finish(b, b.value("u32", "select",
        [query, b.const("u32", 0), b.const("u32", 43)])), 43, bytes([43]) * 8)

    add("nested-head-permuted-edge", program("""  v3:usize = const() {"value":8}
  v4:buffer = buffer.new(v3)
  v5:chain = chain.empty()
  v6:chain,v7:buffer,v8:bool = chain.try_push(v5,v4)
  _ = owner.drop(v7)
  v9:mutbuf = chain.head_mut(v6)
  v10:u8 = const() {"value":109}
  _ = buffer.fill(v9,v10)
  v11:readbuf = borrow.read(v9)
  jump b1(v11,v6,v1,v9)
block b1(v12:readbuf,v13:chain,v14:mutbuf,v15:mutbuf)
  v16:bool = chain.is_empty(v13)
  v17:usize = const() {"value":8}
  _ = buffer.copy(v14,v12,v17)
  _ = loan.end(v12)
  _ = loan.end(v15)
  _ = owner.drop(v13)
  v18:u32 = const() {"value":0}
  v19:u32 = const() {"value":109}
  v20:u32 = select(v16,v18,v19)
  ret(v20)
"""), 109, bytes([109]) * 8)

    add("head-loan-loop", program("""  v3:usize = const() {"value":4}
  v4:buffer = buffer.new(v3)
  v5:chain = chain.empty()
  v6:chain,v7:buffer,v8:bool = chain.try_push(v5,v4)
  _ = owner.drop(v7)
  v9:mutbuf = chain.head_mut(v6)
  v10:usize = const() {"value":0}
  jump b1(v6,v9,v1,v10,v3)
block b1(v11:chain,v12:mutbuf,v13:mutbuf,v14:usize,v15:usize)
  v16:bool = compare.lt(v14,v15)
  branch v16 b2(v11,v12,v13,v14,v15) b3(v11,v12,v13)
block b2(v17:chain,v18:mutbuf,v19:mutbuf,v20:usize,v21:usize)
  v22:u8 = int.cast(v20) {"mode":"wrap"}
  _ = buffer.store(v18,v20,v22)
  v23:usize = const() {"value":1}
  v24:usize = int.add.wrap(v20,v23)
  jump b1(v17,v18,v19,v24,v21)
block b3(v25:chain,v26:mutbuf,v27:mutbuf)
  _ = loan.end(v26)
  v28:readbuf = chain.head_read(v25)
  v29:usize = const() {"value":4}
  _ = buffer.copy(v27,v28,v29)
  _ = loan.end(v28)
  _ = owner.drop(v25)
  v30:u32 = const() {"value":4}
  ret(v30)
"""), 4, bytes([0, 1, 2, 3]) + INITIAL[4:])

    add("parent-from-later-source-block", program("""  jump b2(v1)
block b1(v3:chain,v4:mutbuf,v5:mutbuf)
  _ = loan.end(v4)
  v6:readbuf = chain.head_read(v3)
  v7:usize = const() {"value":8}
  _ = buffer.copy(v5,v6,v7)
  _ = loan.end(v6)
  _ = owner.drop(v3)
  v8:u32 = const() {"value":67}
  ret(v8)
block b2(v9:mutbuf)
  v10:usize = const() {"value":8}
  v11:buffer = buffer.new(v10)
  v12:chain = chain.empty()
  v13:chain,v14:buffer,v15:bool = chain.try_push(v12,v11)
  _ = owner.drop(v14)
  v16:mutbuf = chain.head_mut(v13)
  v17:u8 = const() {"value":67}
  _ = buffer.fill(v16,v17)
  jump b1(v13,v16,v9)
"""), 67, bytes([67]) * 8)

    for choose in (False, True):
        add("fresh-chain-join-" + str(int(choose)), program(
            '  v3:bool = const() {"value":' + str(choose).lower() + '}\n' + """  branch v3 b1() b2()
block b1()
  v4:usize = const() {"value":5}
  v5:buffer = buffer.new(v4)
  v6:chain = chain.empty()
  v7:chain,v8:buffer,v9:bool = chain.try_push(v6,v5)
  _ = owner.drop(v8)
  jump b3(v7)
block b2()
  v10:usize = const() {"value":7}
  v11:buffer = buffer.new(v10)
  v12:chain = chain.empty()
  v13:chain,v14:buffer,v15:bool = chain.try_push(v12,v11)
  _ = owner.drop(v14)
  jump b3(v13)
block b3(v16:chain)
  v17:readbuf = chain.head_read(v16)
  v18:usize = buffer.len(v17)
  _ = loan.end(v17)
  _ = owner.drop(v16)
  v19:u32 = int.cast(v18) {"mode":"wrap"}
  ret(v19)
"""), 5 if choose else 7)

    forwarding = """fn f1(v0:chain,v1:mutbuf) -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0(v0:chain,v1:mutbuf)
  v2:chain = owner.move(v0)
  v3:u32 = call(v2,v1) {"function":"f2"}
  ret(v3)
end
fn f2(v0:chain,v1:mutbuf) -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0(v0:chain,v1:mutbuf)
  v2:readbuf = chain.head_read(v0)
  v3:usize = buffer.len(v2)
  _ = buffer.copy(v1,v2,v3)
  _ = loan.end(v2)
  _ = owner.drop(v0)
  v4:u32 = int.cast(v3) {"mode":"wrap"}
  ret(v4)
end
"""
    b = Body(); chain = populated(b, 8, 73)
    result = b.value("u32", "call", [chain, "v1"], {"function": "f1"})
    add("forward-chain-through-two-calls", finish(b, result, forwarding), 8, bytes([73]) * 8)

    pair = """fn f1(v0:chain,v1:chain) -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0(v0:chain,v1:chain)
  v2:readbuf = chain.head_read(v0)
  v3:readbuf = chain.head_read(v1)
  v4:usize = buffer.len(v2)
  v5:usize = buffer.len(v3)
  _ = loan.end(v2)
  _ = loan.end(v3)
  _ = owner.drop(v0)
  _ = owner.drop(v1)
  v6:usize = const() {"value":100}
  v7:usize = int.mul.wrap(v4,v6)
  v8:usize = int.add.wrap(v7,v5)
  v9:u32 = int.cast(v8) {"mode":"wrap"}
  ret(v9)
end
"""
    b = Body(); left = populated(b, 5, 1); right = populated(b, 7, 2)
    result = b.value("u32", "call", [right, left], {"function": "f1"})
    add("two-distinct-chains-permuted-call", finish(b, result, pair), 705)

    tail = """fn f1(v0:chain,v1:u32) -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0(v0:chain,v1:u32)
  v2:u32 = const() {"value":0}
  v3:bool = compare.eq(v1,v2)
  branch v3 b1(v0) b2(v0,v1)
block b1(v4:chain)
  v5:readbuf = chain.head_read(v4)
  v6:usize = buffer.len(v5)
  _ = loan.end(v5)
  _ = owner.drop(v4)
  v7:u32 = int.cast(v6) {"mode":"wrap"}
  ret(v7)
block b2(v8:chain,v9:u32)
  v10:u32 = const() {"value":1}
  v11:u32 = int.sub.wrap(v9,v10)
  v12:u32 = call(v8,v11) {"function":"f1"}
  ret(v12)
end
"""
    for count in (0, 9):
        b = Body(); chain = populated(b, 13, 7)
        result = b.value("u32", "call", [chain, b.const("u32", count)], {"function": "f1"})
        add("tail-self-chain-" + str(count), finish(b, result, tail), 13)

    add("three-result-ssa-boundary", program("""  v3:usize = const() {"value":8}
  v4:buffer = buffer.new(v3)
  v5:chain = chain.empty()
  v2045:chain,v2046:buffer,v2047:bool = chain.try_push(v5,v4)
  v6:usize = buffer.len(v2046)
  _ = owner.drop(v2046)
  v7:chain,v8:buffer,v9:bool = chain.pop(v2045)
  v10:usize = buffer.len(v8)
  _ = owner.drop(v8)
  _ = owner.drop(v7)
  v11:bool = bool.and(v2047,v9)
  v12:usize = const() {"value":0}
  v13:bool = compare.eq(v6,v12)
  v14:bool = compare.eq(v10,v3)
  v15:bool = bool.and(v11,v13)
  v16:bool = bool.and(v15,v14)
  v17:u32 = const() {"value":1}
  v18:u32 = const() {"value":0}
  v19:u32 = select(v16,v17,v18)
  ret(v19)
"""), 1)
    return rows


def refusals():
    rows = {}
    end = '  v100:u32 = const() {"value":0}\n  ret(v100)\n'
    seed = """  v3:usize = const() {"value":8}
  v4:buffer = buffer.new(v3)
  v5:chain = chain.empty()
  v6:chain,v7:buffer,v8:bool = chain.try_push(v5,v4)
  _ = owner.drop(v7)
"""

    def add(name, body, suffix=""):
        rows["chain-flow-" + name] = program(body + end, suffix).encode()

    helper = """fn f1(v0:chain) -> (u32) effects(alloc,read,write,trap) entry(b0)
block b0(v0:chain)
  _ = owner.drop(v0)
  v1:u32 = const() {"value":0}
  ret(v1)
end
"""
    for mutable in (False, True):
        loan = "  v9:" + ("mutbuf = chain.head_mut" if mutable else "readbuf = chain.head_read") + "(v6)\n"
        tag = "mut" if mutable else "read"
        add("drop-with-head-" + tag, seed + loan + "  _ = owner.drop(v6)\n  _ = loan.end(v9)\n")
        add("move-with-head-" + tag, seed + loan + "  v10:chain = owner.move(v6)\n  _ = loan.end(v9)\n  _ = owner.drop(v10)\n")
        add("pop-with-head-" + tag, seed + loan + "  v10:chain,v11:buffer,v12:bool = chain.pop(v6)\n  _ = loan.end(v9)\n  _ = owner.drop(v10)\n  _ = owner.drop(v11)\n")
        add("call-with-head-" + tag, seed + loan + '  v10:u32 = call(v6) {"function":"f1"}\n  _ = loan.end(v9)\n', helper)
        add("push-with-head-" + tag, seed + loan + "  v10:buffer = buffer.new(v3)\n  v11:chain,v12:buffer,v13:bool = chain.try_push(v6,v10)\n  _ = loan.end(v9)\n  _ = owner.drop(v11)\n  _ = owner.drop(v12)\n")
    add("push-with-payload-loan", seed + "  v9:buffer = buffer.new(v3)\n  v10:readbuf = borrow.read(v9)\n  v11:chain,v12:buffer,v13:bool = chain.try_push(v6,v9)\n  _ = loan.end(v10)\n  _ = owner.drop(v11)\n  _ = owner.drop(v12)\n")
    add("query-consumed-push-input", seed + "  v9:bool = chain.is_empty(v5)\n  _ = owner.drop(v6)\n")
    add("reuse-consumed-payload", seed + "  v9:usize = buffer.len(v4)\n  _ = owner.drop(v6)\n")
    add("pop-then-reuse-chain", seed + "  v9:chain,v10:buffer,v11:bool = chain.pop(v6)\n  v12:bool = chain.is_empty(v6)\n  _ = owner.drop(v9)\n  _ = owner.drop(v10)\n")
    add("chain-as-buffer-len", seed + "  v9:usize = buffer.len(v6)\n  _ = owner.drop(v6)\n")
    for mutable in (False, True):
        add("chain-as-ordinary-borrow-" + str(int(mutable)), seed + "  v9:" +
            ("mutbuf = borrow.mut" if mutable else "readbuf = borrow.read") +
            "(v6)\n  _ = loan.end(v9)\n  _ = owner.drop(v6)\n")
    add("chain-as-byte-source", seed + "  _ = buffer.copy(v1,v6,v3)\n  _ = owner.drop(v6)\n")
    add("head-mut-with-shared-sibling", seed + "  v9:readbuf = chain.head_read(v6)\n  v10:mutbuf = chain.head_mut(v6)\n  _ = loan.end(v10)\n  _ = loan.end(v9)\n  _ = owner.drop(v6)\n")
    add("head-read-with-mutable-sibling", seed + "  v9:mutbuf = chain.head_mut(v6)\n  v10:readbuf = chain.head_read(v6)\n  _ = loan.end(v10)\n  _ = loan.end(v9)\n  _ = owner.drop(v6)\n")
    add("end-parent-before-child", seed + "  v9:mutbuf = chain.head_mut(v6)\n  v10:readbuf = borrow.read(v9)\n  _ = loan.end(v9)\n  _ = loan.end(v10)\n  _ = owner.drop(v6)\n")
    add("edge-missing-chain-parent", seed + "  v9:readbuf = chain.head_read(v6)\n  jump b1(v9)\nblock b1(v10:readbuf)\n  _ = loan.end(v10)\n")
    add("edge-missing-head-child", seed + "  v9:readbuf = chain.head_read(v6)\n  jump b1(v6)\nblock b1(v10:chain)\n  _ = owner.drop(v10)\n")
    add("edge-duplicate-chain", seed + "  jump b1(v6,v6)\nblock b1(v9:chain,v10:chain)\n  _ = owner.drop(v9)\n  _ = owner.drop(v10)\n")
    add("call-then-reuse-chain", seed + '  v9:u32 = call(v6) {"function":"f1"}\n  _ = owner.drop(v6)\n', helper)
    pair = helper.replace("v0:chain)", "v0:chain,v2:chain)").replace(
        "  _ = owner.drop(v0)\n", "  _ = owner.drop(v0)\n  _ = owner.drop(v2)\n")
    add("duplicate-chain-call", seed + '  v9:u32 = call(v6,v6) {"function":"f1"}\n', pair)

    simple = program(seed + "  _ = owner.drop(v6)\n" + end)
    mutations = {
        "push-missing-third-result": ("v6:chain,v7:buffer,v8:bool", "v6:chain,v7:buffer"),
        "push-extra-result": ("v6:chain,v7:buffer,v8:bool", "v6:chain,v7:buffer,v8:bool,v9:u32"),
        "push-wrong-result-order": ("v6:chain,v7:buffer,v8:bool", "v6:chain,v7:bool,v8:buffer"),
        "push-duplicate-result": ("v6:chain,v7:buffer,v8:bool", "v6:chain,v7:buffer,v7:bool"),
        "push-result-redefines-consumed-input": ("v6:chain,v7:buffer,v8:bool", "v5:chain,v7:buffer,v8:bool"),
        "push-missing-payload": ("chain.try_push(v5,v4)", "chain.try_push(v5)"),
        "push-extra-argument": ("chain.try_push(v5,v4)", "chain.try_push(v5,v4,v4)"),
        "push-unexpected-attribute": ("chain.try_push(v5,v4)", 'chain.try_push(v5,v4) {"value":0}'),
        "empty-extra-argument": ("chain.empty()", "chain.empty(v3)"),
        "empty-wrong-result-type": ("v5:chain = chain.empty()", "v5:buffer = chain.empty()"),
    }
    for name, (old, new) in mutations.items():
        rows["chain-flow-" + name] = simple.replace(old, new).encode()

    query = program(seed + "  v9:bool = chain.is_empty(v6)\n  _ = owner.drop(v6)\n" + end)
    for name, old, new in (
        ("is-empty-missing-argument", "chain.is_empty(v6)", "chain.is_empty()"),
        ("is-empty-extra-argument", "chain.is_empty(v6)", "chain.is_empty(v6,v6)"),
        ("is-empty-scalar-argument", "chain.is_empty(v6)", "chain.is_empty(v3)"),
        ("is-empty-wrong-output-type", "v9:bool", "v9:u32"),
        ("is-empty-unexpected-attribute", "chain.is_empty(v6)", 'chain.is_empty(v6) {"value":0}'),
        ("empty-unexpected-attribute", "chain.empty()", 'chain.empty() {"value":0}'),
    ):
        rows["chain-flow-" + name] = query.replace(old, new).encode()
    for mutable in (False, True):
        opcode, typ = ("chain.head_mut", "mutbuf") if mutable else ("chain.head_read", "readbuf")
        head_source = program(seed + "  v9:" + typ + " = " + opcode + "(v6)\n"
                              + "  _ = loan.end(v9)\n  _ = owner.drop(v6)\n" + end)
        for name, old, new in (
            ("missing-argument", opcode + "(v6)", opcode + "()"),
            ("extra-argument", opcode + "(v6)", opcode + "(v6,v6)"),
            ("wrong-output-type", "v9:" + typ, "v9:" + ("readbuf" if mutable else "mutbuf")),
            ("unexpected-attribute", opcode + "(v6)", opcode + '(v6) {"value":0}'),
        ):
            rows["chain-flow-head-" + ("mut-" if mutable else "read-") + name] = head_source.replace(old, new).encode()
        rows["chain-flow-profile-head-" + ("mut" if mutable else "read") + "-ssa-8192"] = re.sub(
            r"\bv9\b", "v8192", head_source).encode()

    pop = next(c["source"] for c in cases() if c["id"] == "chain-flow-three-result-ssa-boundary")
    for name, old, new in (
        ("pop-missing-third-result", "v7:chain,v8:buffer,v9:bool", "v7:chain,v8:buffer"),
        ("pop-wrong-result-type", "v7:chain,v8:buffer,v9:bool", "v7:chain,v8:buffer,v9:u32"),
        ("pop-duplicate-result", "v7:chain,v8:buffer,v9:bool", "v7:chain,v8:buffer,v8:bool"),
        ("pop-extra-argument", "chain.pop(v2045)", "chain.pop(v2045,v2045)"),
        ("pop-unexpected-attribute", "chain.pop(v2045)", 'chain.pop(v2045) {"value":0}'),
    ):
        rows["chain-flow-" + name] = pop.replace(old, new).encode()
    for index in (2048, 8192, (1 << 64) - 1):
        for old, field in (("v2045", "chain"), ("v2046", "payload"), ("v2047", "bool")):
            rows["chain-flow-profile-" + field + "-result-ssa-" + str(index)] = pop.replace(old, "v" + str(index)).encode()
        rows["chain-flow-profile-pop-bool-result-ssa-" + str(index)] = re.sub(
            r"\bv9\b", "v" + str(index), pop).encode()
    head = next(c["source"] for c in cases() if c["id"] == "chain-flow-moves-shared-head-query")
    # Use an unambiguous complete SSA token replacement rather than substring v1.
    head_name = re.search(r"  (v[0-9]+):readbuf = chain.head_read", head).group(1)
    rows["chain-flow-profile-head-result-ssa-8192"] = re.sub(r"\b" + head_name + r"\b", "v8192", head).encode()

    rows["chain-flow-profile-flat-chain-op"] = simple.replace("v8 selfhost_elf\n", "v8 selfhost\n", 1).encode()
    flat = HEADER.replace("v8 selfhost_elf", "v8 selfhost") + end + "end\n"
    loop = """fn f1(v0:chain) -> (u32) effects(read,write,trap) entry(b0)
block b0(v0:chain)
  jump b1(v0)
block b1(v1:chain)
  jump b1(v1)
end
"""
    tail = """fn f1(v0:chain) -> (u32) effects(read,write,trap) entry(b0)
block b0(v0:chain)
  v1:u32 = call(v0) {"function":"f1"}
  ret(v1)
end
"""
    rows["chain-flow-profile-flat-dormant-chain-loop"] = (flat + loop).encode()
    rows["chain-flow-profile-flat-dormant-chain-tail"] = (flat + tail).encode()

    # Both incoming paths have identical types but assign the head loan to a
    # different chain position at the join. This is an invalid loan graph.
    add("join-mismatched-chain-parent", """  v3:bool = const() {"value":true}
  branch v3 b1() b2()
block b1()
  v4:usize = const() {"value":1}
  v5:buffer = buffer.new(v4)
  v6:buffer = buffer.new(v4)
  v7:chain = chain.empty()
  v8:chain = chain.empty()
  v9:chain,v10:buffer,v11:bool = chain.try_push(v7,v5)
  _ = owner.drop(v10)
  v12:chain,v13:buffer,v14:bool = chain.try_push(v8,v6)
  _ = owner.drop(v13)
  v15:readbuf = chain.head_read(v9)
  jump b3(v9,v12,v15)
block b2()
  v16:usize = const() {"value":1}
  v17:buffer = buffer.new(v16)
  v18:buffer = buffer.new(v16)
  v19:chain = chain.empty()
  v20:chain = chain.empty()
  v21:chain,v22:buffer,v23:bool = chain.try_push(v19,v17)
  _ = owner.drop(v22)
  v24:chain,v25:buffer,v26:bool = chain.try_push(v20,v18)
  _ = owner.drop(v25)
  v27:readbuf = chain.head_read(v24)
  jump b3(v21,v24,v27)
block b3(v28:chain,v29:chain,v30:readbuf)
  _ = loan.end(v30)
  _ = owner.drop(v28)
  _ = owner.drop(v29)
""")
    return rows


def profile_refusal_ids():
    return {name for name in refusals() if name.startswith("chain-flow-profile-")}


def allocation_failure_cases():
    """The failure index counts real nonempty allocator calls, not VM budgets."""
    rows = []
    for initial_nonempty, payload_size in ((False, 4), (True, 4), (False, 0)):
        b = Body()
        chain = populated(b, 4, 70) if initial_nonempty else b.value("chain", "chain.empty")
        owner = payload(b, payload_size, 31)
        chain, fallback, ok = multiple(b, ["chain", "buffer", "bool"], "chain.try_push", [chain, owner])
        checks = [b.value("bool", "bool.not", [ok]),
                  b.value("bool", "compare.eq", [b.value("usize", "buffer.len", [fallback]), b.const("usize", payload_size)])]
        empty = b.value("bool", "chain.is_empty", [chain])
        checks.append(b.value("bool", "bool.not", [empty]) if initial_nonempty else empty)
        if payload_size:
            read = b.value("readbuf", "borrow.read", [fallback])
            b.effect("buffer.copy", ["v1", read, b.const("usize", payload_size)])
            b.effect("loan.end", [read])
        if initial_nonempty:
            read = b.value("readbuf", "chain.head_read", [chain])
            value = b.value("u8", "buffer.load", [read, b.const("usize", 0)])
            checks.append(b.value("bool", "compare.eq", [value, b.const("u8", 70)]))
            b.effect("loan.end", [read])
        # Both failed outputs are retryable fresh owner names; the next node
        # allocation succeeds, while its payload fallback must now be empty.
        chain, fallback, retry_ok = multiple(b, ["chain", "buffer", "bool"], "chain.try_push", [chain, fallback])
        checks += [retry_ok, b.value("bool", "compare.eq",
                   [b.value("usize", "buffer.len", [fallback]), b.const("usize", 0)])]
        b.effect("owner.drop", [fallback])
        chain, removed, present = multiple(b, ["chain", "buffer", "bool"], "chain.pop", [chain])
        checks += [present, b.value("bool", "compare.eq",
                   [b.value("usize", "buffer.len", [removed]), b.const("usize", payload_size)])]
        empty = b.value("bool", "chain.is_empty", [chain])
        checks.append(b.value("bool", "bool.not", [empty]) if initial_nonempty else empty)
        b.effect("owner.drop", [removed]); b.effect("owner.drop", [chain])
        fail_at = (2 if initial_nonempty else 0) + (1 if payload_size else 0) + 1
        allocations = (2 if initial_nonempty else 0) + (1 if payload_size else 0) + 1
        name = "nonempty" if initial_nonempty else ("empty-zero-payload" if payload_size == 0 else "empty")
        rows.append({"id": "chain-allocator-" + name + "-node-null-and-retry",
            "source": finish(b, all_true(b, checks)), "expected_result": 1,
            "expected_output_hex": (bytes([31]) * payload_size + INITIAL[payload_size:]).hex(),
            "allocation_fail_at": fail_at, "expected_allocation_attempts": fail_at + 1,
            "expected_allocations": allocations, "expected_frees": allocations,
            "expected_failed_allocations": 1})

    b = Body(); owner, ok = multiple(b, ["buffer", "bool"], "buffer.try_new", [b.const("usize", 8)])
    checks = [b.value("bool", "bool.not", [ok])]
    chain = b.value("chain", "chain.empty")
    chain, fallback, pushed = multiple(b, ["chain", "buffer", "bool"], "chain.try_push", [chain, owner])
    checks += [pushed, b.value("bool", "compare.eq",
               [b.value("usize", "buffer.len", [fallback]), b.const("usize", 0)])]
    b.effect("owner.drop", [fallback])
    read = b.value("readbuf", "chain.head_read", [chain])
    checks.append(b.value("bool", "compare.eq", [b.value("usize", "buffer.len", [read]), b.const("usize", 0)]))
    b.effect("loan.end", [read])
    chain, removed, present = multiple(b, ["chain", "buffer", "bool"], "chain.pop", [chain])
    checks += [present, b.value("bool", "chain.is_empty", [chain])]
    b.effect("owner.drop", [removed]); b.effect("owner.drop", [chain])
    rows.append({"id": "chain-allocator-payload-null-empty-owner-can-be-pushed",
        "source": finish(b, all_true(b, checks)), "expected_result": 1,
        "expected_output_hex": INITIAL.hex(), "allocation_fail_at": 1,
        "expected_allocation_attempts": 2, "expected_allocations": 1,
        "expected_frees": 1, "expected_failed_allocations": 1})

    for prior in (False, True):
        b = Body()
        if prior:
            b.effect("buffer.store", ["v1", b.const("usize", 0), b.const("u8", 99)])
        owner = b.value("buffer", "buffer.new", [b.const("usize", 8)])
        b.effect("owner.drop", [owner])
        rows.append({"id": "chain-allocator-required-payload-null-trap-" + str(int(prior)),
            "source": finish(b, b.const("u32", 0)), "expected_trap": "allocation",
            "expected_output_hex": ((bytes([99]) + INITIAL[1:]) if prior else INITIAL).hex(),
            "allocation_fail_at": 1, "expected_allocation_attempts": 1,
            "expected_allocations": 0, "expected_frees": 0, "expected_failed_allocations": 1})
    return rows

