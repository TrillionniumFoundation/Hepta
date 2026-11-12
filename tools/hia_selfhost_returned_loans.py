"""Native parameter-bound loan returns; no borrowed descriptor may escape its origin."""

SOURCE = r'''
def read_return_loans(s:readbuf, w:mutbuf) -> u64:
    base = FBASE + get(w, 72) * FSTRIDE
    count = get(w, base + 184)
    i = 0
    origin = 0
    t = 0
    formal = 0
    present = 0
    if get(w, 8) == @return_loans@:
        present = 1
        separated(w)
        next_token(s, w)
        adjacent(w)
        expect(s, w, 40)
        expect(s, w, 91)
    while i < count and get(w, 40) == 0:
        origin = 0
        t = get(w, base + 192 + i * 8)
        if present == 1:
            if get(w, 8) == @null@:
                next_token(s, w)
            else:
                formal = expect(s, w, 260)
                if formal >= get(w, base + 24):
                    return fail(w, 62)
                origin = formal + 1
                formal = get(w, base + 48 + formal * 8)
                if (formal != 6 and formal != 7) or (t == 7 and formal != 7):
                    return fail(w, 62)
        if (t == 6 or t == 7) != (origin != 0):
            return fail(w, 62)
        if get(w, 48) == 0:
            put(w, base + 216 + i * 8, origin)
        i = i + 1
        if present == 1 and i < count:
            expect(s, w, 44)
    if present == 1:
        expect(s, w, 93)
        expect(s, w, 41)
        account_nodes(w, 1 + count)
    return 0

def returned_loan(w:mutbuf, v:u64, origin:u64) -> u64:
    if get(w, 264) == 0:
        return 0
    if origin == 0 or byte(w, ORIGINBASE + v) != origin:
        return fail(w, 62)
    loan_access(w, v)
    parent = get(w, CAPBASE + v * 24 + 8)
    if parent != 0:
        if get(w, CAPBASE + (parent - 1) * 24 + 8) != 0:
            return fail(w, 62)
    return 0

def returned_consume(w:mutbuf, v:u64, t:u64) -> u64:
    # All returned capabilities are validated before consuming any of them.
    # variable() still rejects duplicated result identities at this second pass.
    if get(w, 264) == 0:
        return 0
    if owner_type(t) == 1:
        return owner_consume(w, v)
    if t == 6 or t == 7:
        variable(w, v)
        if get(w, CAPBASE + v * 24 + 8) != 0:
            put(w, 280, get(w, 280) - 1)
        put(w, CAPBASE + v * 24 + 16, 0)
    return 0

def call_loan(w:mutbuf, base:u64, slot:u64, v:u64, t:u64) -> u64:
    if get(w, 264) == 0:
        return 0
    origin = get(w, base + 216 + slot * 8)
    if origin == 0 or origin > get(w, base + 24):
        return fail(w, 62)
    a = get(w, ARGS + (origin - 1) * 8)
    loan_borrow(w, a, t)
    loan_produce(w, v, a)
    return 0
'''


def cases():
    from tools.hia_selfhost_bulk import Body
    from tools.hia_selfhost_cases import HEADER
    from tools.hia_selfhost_multi_results import _call
    rows = []
    for mode in ("read", "mut"):
        typ = mode + "buf"
        for construction in ("forward", "child", "cfg", "tail"):
            params = "v0:" + typ + (",v1:u8" if construction == "tail" else "")
            helper = ("fn f1(" + params + ") -> (" + typ
                + ') effects(read,write,trap) entry(b0) return_loans(["v0"])\n'
                + "block b0(" + params + ")\n")
            if construction == "forward":
                helper += "  ret(v0)\nend\n"
            elif construction == "child":
                helper += "  v1:" + typ + " = borrow." + mode + "(v0)\n  ret(v1)\nend\n"
            elif construction == "cfg":
                helper += "  jump b1(v0)\nblock b1(v1:" + typ + ")\n  ret(v1)\nend\n"
            else:
                helper += ('  v2:u8 = const() {"value":0}\n  v3:bool = compare.eq(v1,v2)\n'
                    '  branch v3 b1(v0) b2(v0,v1)\nblock b1(v4:' + typ + ')\n  ret(v4)\n'
                    'block b2(v5:' + typ + ',v6:u8)\n  v7:u8 = const() {"value":1}\n'
                    '  v8:u8 = int.sub.wrap(v6,v7)\n  v9:' + typ
                    + ' = call(v5,v8) {"function":"f1"}\n  ret(v9)\nend\n')
            for byte in (0, 73, 255):
                body = Body()
                args = ["v0" if mode == "read" else "v1"]
                if construction == "tail":
                    args.append(body.const("u8", 3))
                view, = _call(body, [typ], args)
                offset = body.const("usize", 0)
                if mode == "mut":
                    incoming = body.value("u8", "buffer.load", ["v0", offset])
                    body.effect("buffer.store", [view, offset, incoming])
                observed = body.value("u8", "buffer.load", [view, offset])
                body.effect("loan.end", [view])
                body.effect("buffer.store", ["v1", offset, observed])
                result = body.const("u32", 0)
                group = "loan-" + mode + "-" + construction
                rows.append({"id": group + "-" + str(byte), "program": group,
                    "source": HEADER + body.text() + "  ret(" + result + ")\nend\n" + helper,
                    "source_hex": bytes([byte]).hex(), "initial_hex": "a5",
                    "expected_hex": bytes([byte]).hex(), "expected_result": 0,
                    "arguments": [], "expected_values": [], "owned_elf_only": False})
    def add(group, helper, types, args, *, owned=False):
        for byte in (0, 73, 255):
            body = Body()
            parent = None
            owner = None
            if owned:
                owner = body.value("buffer", "buffer.new", [body.const("usize", 1)])
                parent = body.value("mutbuf", "borrow.mut", [owner])
                arguments = [parent]
            else:
                arguments = args
            names = _call(body, types, arguments, "f2" if group == "loan-backward" else "f1")
            index = body.const("usize", 0)
            if owned:
                value = body.value("u8", "buffer.load", ["v0", index])
                body.effect("buffer.store", [names[0], index, value])
            for name, typ in zip(names, types):
                if typ in ("readbuf", "mutbuf"):
                    value = body.value("u8", "buffer.load", [name, index])
                    if typ == "readbuf" or owned:
                        body.effect("buffer.store", ["v1", index, value])
                    body.effect("loan.end", [name])
            if owned:
                body.effect("loan.end", [parent])
                body.effect("owner.drop", [owner])
            result = body.const("u32", 0)
            header = HEADER
            if owned:
                header = header.replace("v8 selfhost\n", "v8 selfhost_elf\n").replace(
                    "effects(read,write,trap)", "effects(alloc,read,write,trap)")
            rows.append({"id": group + "-" + str(byte), "program": group,
                "source": header + body.text() + "  ret(" + result + ")\nend\n" + helper,
                "source_hex": bytes([byte]).hex(), "initial_hex": "a5",
                "expected_hex": bytes([byte]).hex(), "expected_result": 0,
                "arguments": [], "expected_values": [], "owned_elf_only": owned})

    identity = ('fn f1(v0:readbuf) -> (readbuf) effects(read,write,trap) entry(b0) return_loans(["v0"])\n'
                'block b0(v0:readbuf)\n  ret(v0)\nend\n')
    add("loan-backward", identity + identity.replace("f1(", "f2(").replace(
        "  ret(v0)", '  v1:readbuf = call(v0) {"function":"f1"}\n  ret(v1)'), ["readbuf"], ["v0"])
    shared = ('fn f1(v0:readbuf) -> (readbuf,u32,readbuf) effects(read,write,trap) entry(b0) '
              'return_loans(["v0",null,"v0"])\nblock b0(v0:readbuf)\n'
              '  v1:readbuf = borrow.read(v0)\n  v2:readbuf = borrow.read(v0)\n'
              '  v3:u32 = const() {"value":17}\n  ret(v1,v3,v2)\nend\n')
    add("loan-shared-three-slots", shared, ["readbuf", "u32", "readbuf"], ["v0"])
    swapped = ('fn f1(v0:readbuf,v1:mutbuf) -> (mutbuf,readbuf) effects(read,write,trap) entry(b0) '
               'return_loans(["v1","v0"])\nblock b0(v0:readbuf,v1:mutbuf)\n  ret(v1,v0)\nend\n')
    add("loan-swapped-formals", swapped, ["mutbuf", "readbuf"], ["v0", "v1"])
    add("loan-caller-owned-parent", identity.replace("readbuf", "mutbuf"), ["mutbuf"], [], owned=True)
    return rows


def refusals():
    sample = next(row["source"] for row in cases() if row["program"] == "loan-read-forward")
    shared = sample.replace("-> (readbuf) effects", "-> (readbuf,readbuf) effects")
    shared = shared.replace('return_loans(["v0"])', 'return_loans(["v0","v0"])')
    shared = shared.replace("  ret(v0)\nend", "  ret(v0,v0)\nend")
    # Match the caller arity before asking the resource checker to reject the
    # duplicated capability, rather than failing earlier for a trivial shape.
    shared = shared.replace('v3:readbuf = call', 'v3:readbuf,v99:readbuf = call')
    shared = shared.replace('  _ = loan.end(v3)', '  _ = loan.end(v3)\n  _ = loan.end(v99)')
    rows = {
        "loan-missing-metadata": sample.replace(' return_loans(["v0"])', ""),
        "loan-null-origin": sample.replace('return_loans(["v0"])', 'return_loans([null])'),
        "loan-out-of-range-origin": sample.replace('return_loans(["v0"])', 'return_loans(["v1"])'),
        "loan-duplicated-external-return": shared,
        "loan-metadata-extra-entry": sample.replace('return_loans(["v0"])', 'return_loans(["v0",null])'),
        "loan-metadata-trailing-comma": sample.replace('return_loans(["v0"])', 'return_loans(["v0",])'),
        "loan-return-parent-with-child": sample.replace("  ret(v0)\nend", "  v1:readbuf = borrow.read(v0)\n  ret(v0)\nend"),
        "loan-return-grandchild": sample.replace("  ret(v0)\nend", "  v1:readbuf = borrow.read(v0)\n  v2:readbuf = borrow.read(v1)\n  ret(v2)\nend"),
        "loan-use-parent-before-ending-return": sample.replace("  _ = loan.end(v3)", "  v99:usize = const() {\"value\":0}\n  v98:u8 = buffer.load(v0,v99)\n  _ = loan.end(v3)"),
        "loan-end-return-twice": sample.replace("  _ = loan.end(v3)", "  _ = loan.end(v3)\n  _ = loan.end(v3)"),
        "loan-read-formal-cannot-return-mut": sample.replace("-> (readbuf) effects", "-> (mutbuf) effects"),
        "loan-quoted-value-outside-contract": sample.replace("  ret(v0)\nend", '  ret("v0")\nend'),
    }
    rows["loan-parent-and-child-returned-child-first"] = shared.replace(
        "  ret(v0,v0)\nend", "  v1:readbuf = borrow.read(v0)\n  ret(v1,v0)\nend")
    rows["loan-parent-and-child-returned-parent-first"] = shared.replace(
        "  ret(v0,v0)\nend", "  v1:readbuf = borrow.read(v0)\n  ret(v0,v1)\nend")
    # Two same-typed external views have distinct formal provenance. The
    # resource graph alone (two self roots) must not erase that difference.
    two = sample.replace("fn f1(v0:readbuf)", "fn f1(v0:readbuf,v1:readbuf)").replace(
        "block b0(v0:readbuf)", "block b0(v0:readbuf,v1:readbuf)").replace(
        'call(v0) {"function":"f1"}', 'call(v0,v0) {"function":"f1"}')
    rows["loan-wrong-same-type-formal"] = two.replace("  ret(v0)\nend", "  ret(v1)\nend")
    cfg = two.replace("  ret(v0)\nend", '  v2:bool = const() {"value":true}\n'
        '  branch v2 b1(v0,v1) b2(v0,v1)\n'
        'block b1(v3:readbuf,v4:readbuf)\n  jump b3(v3,v4)\n'
        'block b2(v5:readbuf,v6:readbuf)\n  jump b3(v6,v5)\n'
        'block b3(v7:readbuf,v8:readbuf)\n  ret(v7)\nend')
    rows["loan-cfg-join-swaps-formal-origins"] = cfg
    return [{"id": name, "source": source, "general_core_expected": "rejected"}
            for name, source in rows.items()]
