"""Finite dynamic-chain and iterative-destruction Core/native witnesses."""
from __future__ import annotations

from tools.hia_selfhost_bulk import Body
from tools.hia_selfhost_owned_elf_cases import HEADER, finish, multiple

INITIAL = bytes([0xa5]) * 8


def program(body):
    return (HEADER + body + "end\n").encode()


def loop_source(count, *, drop):
    prefix = f'''  v3:u32 = const() {{"value":{count}}}
  v4:u32 = const() {{"value":0}}
  v5:chain = chain.empty()
  jump b1(v5,v4,v3,v1)
block b1(v6:chain,v7:u32,v8:u32,v9:mutbuf)
  v10:bool = compare.lt(v7,v8)
  branch v10 b2(v6,v7,v8,v9) b3(v6,v9)
block b2(v11:chain,v12:u32,v13:u32,v14:mutbuf)
  v15:usize = const() {{"value":1}}
  v16:buffer = buffer.new(v15)
  v17:mutbuf = borrow.mut(v16)
  v18:u8 = int.cast(v12) {{"mode":"wrap"}}
  _ = buffer.fill(v17,v18)
  _ = loan.end(v17)
  v19:chain,v20:buffer,v21:bool = chain.try_push(v11,v16)
  _ = owner.drop(v20)
  v22:u32 = const() {{"value":1}}
  v23:u32 = int.add.wrap(v12,v22)
  jump b1(v19,v23,v13,v14)
block b3(v24:chain,v25:mutbuf)
'''
    if drop:
        return program(prefix + f'''  v26:mutbuf = chain.head_mut(v24)
  v27:u8 = const() {{"value":174}}
  _ = buffer.fill(v26,v27)
  _ = loan.end(v26)
  v28:readbuf = chain.head_read(v24)
  v29:usize = const() {{"value":1}}
  _ = buffer.copy(v25,v28,v29)
  _ = loan.end(v28)
  v30:chain = owner.move(v24)
  _ = owner.drop(v30)
  v31:u32 = const() {{"value":{count}}}
  ret(v31)
''')
    return program(prefix + '''  v26:u32 = const() {"value":5381}
  jump b4(v24,v26)
block b4(v27:chain,v28:u32)
  v29:bool = chain.is_empty(v27)
  branch v29 b5(v27,v28) b6(v27,v28)
block b5(v30:chain,v31:u32)
  _ = owner.drop(v30)
  ret(v31)
block b6(v32:chain,v33:u32)
  v34:chain,v35:buffer,v36:bool = chain.pop(v32)
  v37:readbuf = borrow.read(v35)
  v38:usize = const() {"value":0}
  v39:u8 = buffer.load(v37,v38)
  _ = loan.end(v37)
  _ = owner.drop(v35)
  v40:u32 = const() {"value":33}
  v41:u32 = int.mul.wrap(v33,v40)
  v42:u32 = int.cast(v39) {"mode":"wrap"}
  v43:u32 = bit.xor(v41,v42)
  jump b4(v34,v43)
''')


def cases():
    rows = []

    def add(name, source, result=None, output=INITIAL, trap=None):
        row = {"id": name, "source": source.decode(), "expected_output_hex": output.hex()}
        if trap is None:
            row["expected_result"] = result
        else:
            row["expected_trap"] = trap
        rows.append(row)

    b = Body(); chain = b.value("chain", "chain.empty")
    empty = b.value("bool", "chain.is_empty", [chain])
    chain, payload, present = multiple(b, ["chain", "buffer", "bool"], "chain.pop", [chain])
    extent = b.value("usize", "buffer.len", [payload]); b.effect("owner.drop", [payload]); b.effect("owner.drop", [chain])
    one = b.const("u32", 1); zero = b.const("u32", 0)
    ok = b.value("bool", "bool.and", [empty, b.value("bool", "bool.not", [present])])
    add("empty-query-and-pop", finish(b, b.value("u32", "select", [ok, one, zero])), 1)

    for count in (0, 1, 17, 5000):
        expected = 5381
        for byte in reversed([i & 255 for i in range(count)]):
            expected = ((expected * 33) ^ byte) & 0xffffffff
        add("lifo-pop-loop-" + str(count), loop_source(count, drop=False), expected)
    for count in (1, 5000):
        add("iterative-drop-loop-" + str(count), loop_source(count, drop=True), count,
            bytes([174]) + INITIAL[1:])

    b = Body(); length = b.const("usize", 8)
    owner = b.value("buffer", "buffer.new", [length]); chain = b.value("chain", "chain.empty")
    chain, fallback, ok = multiple(b, ["chain", "buffer", "bool"], "chain.try_push", [chain, owner])
    b.effect("owner.drop", [fallback]); moved = b.value("chain", "owner.move", [chain])
    view = b.value("mutbuf", "chain.head_mut", [moved]); b.effect("buffer.fill", [view, b.const("u8", 93)])
    # Extent-only chain queries stay legal while a head loan is live.
    empty = b.value("bool", "chain.is_empty", [moved]); child = b.value("readbuf", "borrow.read", [view])
    b.effect("buffer.copy", ["v1", child, length]); b.effect("loan.end", [child]); b.effect("loan.end", [view])
    left = b.value("readbuf", "chain.head_read", [moved]); right = b.value("readbuf", "chain.head_read", [moved])
    b.effect("loan.end", [right]); b.effect("loan.end", [left]); b.effect("owner.drop", [moved])
    add("moved-chain-nested-head-and-shared-siblings", finish(b, b.value("u32", "select",
        [empty, b.const("u32", 0), b.const("u32", 93)])), 93, bytes([93]) * 8)

    for mutable in (False, True):
        for prior in (False, True):
            b = Body()
            if prior:
                b.effect("buffer.store", ["v1", b.const("usize", 0), b.const("u8", 99)])
            chain = b.value("chain", "chain.empty")
            view = b.value("mutbuf" if mutable else "readbuf", "chain.head_mut" if mutable else "chain.head_read", [chain])
            b.effect("loan.end", [view]); b.effect("owner.drop", [chain])
            add("empty-head-" + ("mut-" if mutable else "read-") + str(int(prior)), finish(b, b.const("u32", 0)),
                output=(bytes([99]) + INITIAL[1:]) if prior else INITIAL, trap="bounds")
    return rows
