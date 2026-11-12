"""Independent observable witnesses for zero-result internal HIA functions.

An empty result tuple is not a discarded scalar. Effects, owner consumption,
loan closure and immediate self-tail returns still obey the ordinary Core rules.
"""
from __future__ import annotations

from tools.hia_selfhost_cases import HEADER
from tools.hia_selfhost_multi_results import _function


def cases():
    rows = []

    def add(name, source, inputs, output, *, owned=False):
        rows.append({"id": name + "-" + str(sum(r["program"] == name for r in rows)),
            "program": name, "source": source, "source_hex": bytes(inputs).hex(),
            "initial_hex": "a5", "expected_hex": bytes([output]).hex(),
            "expected_result": 0, "expected_values": [], "owned_elf_only": owned})

    def entry(call, helper, *, owned=False):
        header = HEADER
        if owned:
            header = header.replace("v8 selfhost\n", "v8 selfhost_elf\n").replace(
                "effects(read,write,trap)", "effects(alloc,read,write,trap)")
        return header + call + '  v200:u32 = const() {"value":0}\n  ret(v200)\nend\n' + helper

    empty = entry('  _ = call() {"function":"f1"}\n', _function("f1", [], [], '  ret()\n'))
    add("void-empty", empty, [], 0xa5)

    write = _function("f1", ["readbuf", "mutbuf"], [],
        '  v2:usize = const() {"value":0}\n  v3:u8 = buffer.load(v0,v2)\n'
        '  _ = buffer.store(v1,v2,v3)\n  ret()\n')
    source = entry('  _ = call(v0,v1) {"function":"f1"}\n', write)
    for value in (0, 1, 128, 255):
        add("void-write", source, [value], value)
    backward = _function("f2", ["readbuf", "mutbuf"], [],
        '  _ = call(v0,v1) {"function":"f1"}\n  ret()\n')
    source = entry('  _ = call(v0,v1) {"function":"f2"}\n', write + backward)
    for value in (0, 1, 128, 255):
        add("void-backward", source, [value], value)

    branch = _function("f1", ["readbuf", "mutbuf"], [],
        '  v2:usize = const() {"value":0}\n  v3:u8 = buffer.load(v0,v2)\n'
        '  v4:u8 = const() {"value":0}\n  v5:bool = compare.eq(v3,v4)\n'
        '  branch v5 b1(v1) b2(v1)\nblock b1(v6:mutbuf)\n'
        '  v7:u8 = const() {"value":225}\n  v8:usize = const() {"value":0}\n'
        '  _ = buffer.store(v6,v8,v7)\n  ret()\nblock b2(v9:mutbuf)\n'
        '  v10:u8 = const() {"value":55}\n  v11:usize = const() {"value":0}\n'
        '  _ = buffer.store(v9,v11,v10)\n  ret()\n')
    source = entry('  _ = call(v0,v1) {"function":"f1"}\n', branch)
    for value in (0, 255):
        add("void-branch", source, [value], 225 if value == 0 else 55)

    prefix = ('  v3:usize = const() {"value":0}\n  v4:u8 = buffer.load(v0,v3)\n'
              '  _ = call(v1,v4) {"function":"f1"}\n')
    loop = _function("f1", ["mutbuf", "u8"], [],
        '  jump b1(v0,v1)\nblock b1(v2:mutbuf,v3:u8)\n'
        '  v4:u8 = const() {"value":0}\n  v5:bool = compare.eq(v3,v4)\n'
        '  branch v5 b2(v2) b3(v2,v3)\nblock b2(v6:mutbuf)\n  ret()\n'
        'block b3(v7:mutbuf,v8:u8)\n  v9:usize = const() {"value":0}\n'
        '  _ = buffer.store(v7,v9,v8)\n  v10:u8 = const() {"value":1}\n'
        '  v11:u8 = int.sub.wrap(v8,v10)\n  jump b1(v7,v11)\n')
    tail = _function("f1", ["mutbuf", "u8"], [],
        '  v2:u8 = const() {"value":0}\n  v3:bool = compare.eq(v1,v2)\n'
        '  branch v3 b1(v0) b2(v0,v1)\nblock b1(v4:mutbuf)\n  ret()\n'
        'block b2(v5:mutbuf,v6:u8)\n  v7:usize = const() {"value":0}\n'
        '  _ = buffer.store(v5,v7,v6)\n  v8:u8 = const() {"value":1}\n'
        '  v9:u8 = int.sub.wrap(v6,v8)\n  _ = call(v5,v9) {"function":"f1"}\n  ret()\n')
    for name, helper in (("void-loop", loop), ("void-tail", tail)):
        source = entry(prefix, helper)
        for count in (0, 1, 31, 200):
            add(name, source, [count], 1 if count else 0xa5)

    owner = ('fn f1(v0:buffer,v1:mutbuf) -> () effects(alloc,read,write,trap) entry(b0)\n'
        'block b0(v0:buffer,v1:mutbuf)\n  v2:mutbuf = borrow.mut(v0)\n'
        '  v3:u8 = const() {"value":201}\n  _ = buffer.fill(v2,v3)\n'
        '  v4:usize = const() {"value":0}\n  v5:u8 = buffer.load(v2,v4)\n'
        '  _ = buffer.store(v1,v4,v5)\n  _ = loan.end(v2)\n  _ = owner.drop(v0)\n  ret()\nend\n')
    source = entry('  v3:usize = const() {"value":8}\n  v4:buffer = buffer.new(v3)\n'
        '  _ = call(v4,v1) {"function":"f1"}\n', owner, owned=True)
    add("void-owned", source, [], 201, owned=True)
    return rows


def refusals():
    rows = []
    sources = {r["program"]: r["source"] for r in cases()}
    def reject(name, source, general="rejected"):
        rows.append({"id": name, "source": source, "general_core_expected": general})
    empty = sources["void-empty"]
    reject("void-call-invented-result", empty.replace('_ = call()', 'v3:u32 = call()'))
    reject("void-return-invented-result", empty.replace('  ret()\n',
        '  v0:u32 = const() {"value":0}\n  ret(v0)\n'))
    reject("void-entry", empty.replace('-> (u32)', '-> ()', 1).replace('ret(v200)', 'ret()'), "accepted")
    reject("void-tail-not-immediate", sources["void-tail"].replace(
        '  _ = call(v5,v9) {"function":"f1"}\n  ret()',
        '  _ = call(v5,v9) {"function":"f1"}\n  v10:u8 = const() {"value":7}\n  ret()'), "accepted")
    reject("void-owner-leaked", sources["void-owned"].replace('  _ = owner.drop(v0)\n', ''))
    reject("void-owner-live-loan", sources["void-owned"].replace('  _ = loan.end(v2)\n', ''))
    reject("void-write-effect-missing", sources["void-write"].replace(
        'fn f1(v0:readbuf,v1:mutbuf) -> () effects(read,write,trap)',
        'fn f1(v0:readbuf,v1:mutbuf) -> () effects(read,trap)'))
    return rows
