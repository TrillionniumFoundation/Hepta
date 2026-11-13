"""Input-dependent owned-result witnesses, checked by the independent Core VM.

Every owner is consumed, dropped or returned exactly once. These ordinary HIA
programs are compiled by both B3 and its modified-source successor; fixtures do
not adapt native descriptors or smuggle host-created capabilities into the VM.
"""
from __future__ import annotations

from tools.hia_selfhost_bulk import Body
from tools.hia_selfhost_cases import HEADER
from tools.hia_selfhost_multi_results import _call, _read_word, _write_results

OWNED_HEADER = HEADER.replace("v8 selfhost\n", "v8 selfhost_elf\n").replace(
    "effects(read,write,trap)", "effects(alloc,read,write,trap)")


def function(name, arguments, returns, body):
    params = ",".join(f"v{i}:{t}" for i, t in enumerate(arguments))
    return (f"fn {name}({params}) -> ({','.join(returns)}) effects(alloc,read,write,trap) entry(b0)\n"
            f"block b0({params})\n{body}end\n")


def observe(body, owner):
    size = body.value("usize", "buffer.len", [owner])
    view = body.value("readbuf", "borrow.read", [owner])
    byte = body.value("u8", "buffer.load", [view, body.const("usize", 0)])
    body.effect("loan.end", [view])
    body.effect("owner.drop", [owner])
    return [size, byte], ["usize", "u8"]


def cases():
    rows = []

    def add(group, source, arguments, expected):
        raw = b"".join(int(x).to_bytes(8, "little") for x in arguments)
        out = b"".join(int(x).to_bytes(8, "little") for x in expected)
        rows.append({"id": group + "-" + str(sum(c["program"] == group for c in rows)),
            "program": group, "source": source, "source_hex": raw.hex(),
            "initial_hex": (bytes([0xa5]) * len(out)).hex(), "expected_hex": out.hex(),
            "expected_result": 0, "arguments": list(arguments), "expected_values": list(expected),
            "owned_elf_only": True})

    # Preserve the previously refused valid Core fixture as a positive case.
    source = (OWNED_HEADER + '  v3:u32,v4:buffer = call() {"function":"f1"}\n'
        '  _ = owner.drop(v4)\n  ret(v3)\nend\n' + function("f1", [], ["u32", "buffer"],
        '  v0:usize = const() {"value":8}\n  v1:buffer = buffer.new(v0)\n'
        '  v2:u32 = const() {"value":17}\n  ret(v2,v1)\n'))
    # This fixture returns 17 directly instead of the usual observation status.
    add("owner-previously-refused", source, [], [])
    rows[-1]["expected_result"] = 17

    maker = ('  v2:buffer = buffer.new(v0)\n  v3:mutbuf = borrow.mut(v2)\n'
             '  _ = buffer.fill(v3,v1)\n  _ = loan.end(v3)\n')
    for returns, result_line, index in ((["buffer"], "ret(v2)", 0),
            (["u8", "buffer"], "ret(v1,v2)", 1),
            (["buffer", "usize"], "ret(v2,v0)", 0)):
        body = Body()
        n, byte = _read_word(body, "usize", 0), _read_word(body, "u8", 8)
        results = _call(body, returns, [n, byte])
        values, types = observe(body, results[index])
        for i, typ in enumerate(returns):
            if i != index:
                values.append(results[i]); types.append(typ)
        result = _write_results(body, values, types)
        source = OWNED_HEADER + body.text() + f"  ret({result})\nend\n" + function(
            "f1", ["usize", "u8"], returns, maker + "  " + result_line + "\n")
        group = "owner-return-" + "-".join(returns)
        for length, value in ((1, 0), (8, 255), (31, 173)):
            extra = [] if len(returns) == 1 else [value if returns[0] == "u8" else length]
            add(group, source, [length, value], [length, value, *extra])

    # Full 48-byte tuple area: every slot is an owner, including chain's spare word.
    body = Body()
    n, byte = _read_word(body, "usize", 0), _read_word(body, "u8", 8)
    first, chain, second = _call(body, ["buffer", "chain", "buffer"], [n, byte])
    values, types = observe(body, first)
    empty = body.value("bool", "chain.is_empty", [chain]); body.effect("owner.drop", [chain])
    more, more_types = observe(body, second)
    result = _write_results(body, [*values, empty, *more], [*types, "bool", *more_types])
    helper = function("f1", ["usize", "u8"], ["buffer", "chain", "buffer"], maker +
        '  v4:chain = chain.empty()\n  v5:buffer = buffer.new(v0)\n'
        '  v6:mutbuf = borrow.mut(v5)\n  v7:u8 = bit.not(v1)\n'
        '  _ = buffer.fill(v6,v7)\n  _ = loan.end(v6)\n  ret(v2,v4,v5)\n')
    source = OWNED_HEADER + body.text() + f"  ret({result})\nend\n" + helper
    for length, value in ((1, 0), (17, 255), (31, 97)):
        add("owner-three-descriptors", source, [length, value], [length, value, True, length, value ^ 255])

    # An owner transferred through a backward call is not freed in either callee.
    body = Body()
    n, byte = _read_word(body, "usize", 0), _read_word(body, "u8", 8)
    owner, = _call(body, ["buffer"], [n, byte], "f2")
    values, types = observe(body, owner)
    result = _write_results(body, values, types)
    helper = function("f1", ["buffer"], ["buffer"], '  v1:buffer = owner.move(v0)\n  ret(v1)\n')
    helper += function("f2", ["usize", "u8"], ["buffer"], maker +
        '  v4:buffer = call(v2) {"function":"f1"}\n  ret(v4)\n')
    source = OWNED_HEADER + body.text() + f"  ret({result})\nend\n" + helper
    for length, value in ((1, 255), (8, 173), (31, 0)):
        add("owner-backward-transfer", source, [length, value], [length, value])

    # Explicit empty descriptors and fallible allocator result tuples.
    for size in (0, 1, 31):
        body = Body(); n = _read_word(body, "usize", 0)
        owner, ok = _call(body, ["buffer", "bool"], [n])
        length = body.value("usize", "buffer.len", [owner]); body.effect("owner.drop", [owner])
        result = _write_results(body, [length, ok], ["usize", "bool"])
        helper = function("f1", ["usize"], ["buffer", "bool"],
            '  v1:buffer,v2:bool = buffer.try_new(v0)\n  ret(v1,v2)\n')
        source = OWNED_HEADER + body.text() + f"  ret({result})\nend\n" + helper
        add("owner-fallible-empty", source, [size], [size, True])

    # Chain with a live node crosses a tuple boundary, then is popped and cleaned.
    body = Body(); n, byte = _read_word(body, "usize", 0), _read_word(body, "u8", 8)
    chain, remainder, pushed = _call(body, ["chain", "buffer", "bool"], [n, byte])
    body.effect("owner.drop", [remainder])
    from tools.hia_selfhost_owned_elf_cases import multiple
    tail, payload, present = multiple(body, ["chain", "buffer", "bool"], "chain.pop", [chain])
    body.effect("owner.drop", [tail])
    values, types = observe(body, payload)
    result = _write_results(body, [*values, pushed, present], [*types, "bool", "bool"])
    helper = function("f1", ["usize", "u8"], ["chain", "buffer", "bool"], maker +
        '  v4:chain = chain.empty()\n  v5:chain,v6:buffer,v7:bool = chain.try_push(v4,v2)\n'
        '  ret(v5,v6,v7)\n')
    source = OWNED_HEADER + body.text() + f"  ret({result})\nend\n" + helper
    for length, value in ((1, 255), (8, 173), (31, 0)):
        add("owner-chain-node-return", source, [length, value], [length, value, True, True])

    # Exact tail results transfer abstract ownership while native execution reuses
    # the original result pointer and frame, even with a live buffer argument.
    body = Body(); count = _read_word(body, "u8", 0)
    n = body.const("usize", 8); owner = body.value("buffer", "buffer.new", [n])
    result_owner, = _call(body, ["buffer"], [count, owner])
    length = body.value("usize", "buffer.len", [result_owner]); body.effect("owner.drop", [result_owner])
    result = _write_results(body, [length], ["usize"])
    helper = function("f1", ["u8", "buffer"], ["buffer"],
        '  v2:u8 = const() {"value":0}\n  v3:bool = compare.eq(v0,v2)\n'
        '  branch v3 b1(v1) b2(v0,v1)\nblock b1(v4:buffer)\n  ret(v4)\n'
        'block b2(v5:u8,v6:buffer)\n  v7:u8 = const() {"value":1}\n'
        '  v8:u8 = int.sub.wrap(v5,v7)\n  v9:buffer = call(v8,v6) {"function":"f1"}\n'
        '  ret(v9)\n')
    source = OWNED_HEADER + body.text() + f"  ret({result})\nend\n" + helper
    for count in (0, 1, 31):
        add("owner-tail-transfer", source, [count], [8])
    return rows


def refusals():
    # General Core rejection must be observed independently before B0. These
    # unsafe variants must not be made compilable by relaxing lifetime checks.
    base = (OWNED_HEADER + '  v3:buffer = call() {"function":"f1"}\n'
        '  _ = owner.drop(v3)\n  v4:u32 = const() {"value":0}\n  ret(v4)\nend\n' +
        function("f1", [], ["buffer"],
            '  v0:usize = const() {"value":8}\n  v1:buffer = buffer.new(v0)\n  ret(v1)\n'))
    variants = {
        "owner-return-duplicate": base.replace('-> (buffer)', '-> (buffer,buffer)').replace(
            'v3:buffer = call', 'v3:buffer,v5:buffer = call').replace(
            '  _ = owner.drop(v3)', '  _ = owner.drop(v3)\n  _ = owner.drop(v5)').replace('ret(v1)', 'ret(v1,v1)'),
        "owner-return-live-child": base.replace('  ret(v1)', '  v2:readbuf = borrow.read(v1)\n  ret(v1)'),
        "owner-return-dropped": base.replace('  ret(v1)', '  _ = owner.drop(v1)\n  ret(v1)'),
        "owner-return-leaked-sibling": base.replace('  ret(v1)', '  v2:buffer = buffer.new(v0)\n  ret(v1)'),
        "owner-return-caller-use-after-drop": base.replace('  ret(v4)', '  v5:usize = buffer.len(v3)\n  ret(v4)'),
        "owner-return-caller-live-child": base.replace('  _ = owner.drop(v3)',
            '  v5:readbuf = borrow.read(v3)\n  _ = owner.drop(v3)'),
        "owner-return-wrong-scalar-type": base.replace('v3:buffer = call', 'v3:u64 = call').replace(
            '  _ = owner.drop(v3)\n', ''),
    }
    rows = [{"id": name, "source": source, "general_core_expected": "rejected"}
            for name, source in variants.items()]
    rows.append({"id": "owner-return-flat-output", "source": base.replace(
        'v8 selfhost_elf\n', 'v8 selfhost\n'), "general_core_expected": "accepted"})
    return rows
