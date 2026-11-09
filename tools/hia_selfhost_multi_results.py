"""Bounded scalar and owned-resource tuples in the native selfhost compiler.

Private calls use three 16-byte slots in a 64-byte aligned result area. Scalars
use the first word; owners transfer both descriptor words without freeing them.
Borrowed-view returns require the exact original-formal provenance contract.
The public f0 borrowed-buffer entry is unchanged.
"""
from __future__ import annotations


SOURCE = r'''
def read_result_types(s:readbuf, w:mutbuf) -> u64:
    base = FBASE + get(w, 72) * FSTRIDE
    count = 0
    first = 0
    t = 0
    while get(w, 8) != 41 and get(w, 40) == 0:
        if count >= 3:
            return fail(w, 3)
        t = read_type(s, w)
        if scalar_type(t) != 1 and resource_type(t) != 1:
            return fail(w, 3)
        if count == 0:
            first = t
        if get(w, 48) == 0:
            put(w, base + 192 + count * 8, t)
        count = count + 1
        if get(w, 8) != 41:
            expect(s, w, 44)
            if get(w, 8) == 41:
                return fail(w, 3)
    expect(s, w, 41)
    if get(w, 48) == 0:
        put(w, base + 184, count)
    account_nodes(w, count)
    return first

def return_results(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    base = FBASE + get(w, 72) * FSTRIDE
    count = 0
    v = 0
    t = 0
    expect(s, w, 40)
    while get(w, 8) != 41 and get(w, 40) == 0:
        if count >= get(w, base + 184):
            return fail(w, 13)
        v = expect(s, w, 256)
        t = variable(w, v)
        if t != get(w, base + 192 + count * 8):
            return fail(w, 13)
        if owner_type(t) == 1:
            owner_free(w, v)
        if t == 6 or t == 7:
            returned_loan(w, v, get(w, base + 216 + count * 8))
        put(w, 400 + count * 8, v)
        if get(w, 256) != 0:
            if v != get(w, 296 + count * 16):
                return fail(w, 59)
        else:
            load_var(o, w, 0, v, 0)
            mem(o, w, 139, 2, 5, 18446744073709551608)
            mem(o, w, 137, 0, 2, count * 16)
            if resource_type(t) == 1:
                load_var(o, w, 0, v, 1)
                mem(o, w, 137, 0, 2, count * 16 + 8)
        count = count + 1
        if get(w, 8) != 41:
            expect(s, w, 44)
            if get(w, 8) == 41:
                return fail(w, 13)
    expect(s, w, 41)
    if count != get(w, base + 184):
        return fail(w, 13)
    i = 0
    while i < count:
        returned_consume(w, get(w, 400 + i * 8), get(w, base + 192 + i * 8))
        i = i + 1
    loan_finish(w)
    account_nodes(w, 3 + count)
    if get(w, 256) == 0:
        emit(o, w, 201)
        emit(o, w, 195)
    return 0

def call_results(o:mutbuf, w:mutbuf, callee:u64) -> u64:
    if get(w, 40) != 0:
        return 0
    base = FBASE + callee * FSTRIDE
    count = get(w, 288)
    i = 0
    v = 0
    t = 0
    if get(w, 48) > 0:
        if count != get(w, base + 184):
            return fail(w, 24)
    while i < count:
        v = get(w, 296 + i * 16)
        t = get(w, 304 + i * 16)
        if scalar_type(t) != 1 and resource_type(t) != 1:
            return fail(w, 24)
        if get(w, 48) > 0:
            if t != get(w, base + 192 + i * 8):
                return fail(w, 24)
        define(w, v, t)
        if get(w, 40) != 0:
            return 0
        if owner_type(t) == 1:
            owner_produce(w, v)
        if t == 6 or t == 7:
            call_loan(w, base, i, v, t)
        if get(w, 256) == 0:
            mem(o, w, 139, 0, 5, 0 - frame(w) + 512 + i * 16)
            store_var(o, w, v, 0)
            if resource_type(t) == 1:
                mem(o, w, 139, 0, 5, 0 - frame(w) + 512 + i * 16 + 8)
                store_var(o, w, v, 1)
        i = i + 1
    return 0
'''


def _call(body, types, args, callee="f1"):
    names = ["v" + str(body.next + i) for i in range(len(types))]
    body.next += len(types)
    body.lines.append("  " + ",".join(name + ":" + typ for name, typ in zip(names, types))
                      + " = call(" + ",".join(args) + ') {"function":"' + callee + '"}\n')
    return names


def _read_word(body, typ, offset):
    value = body.const("u64", 0)
    for i in range(8):
        byte = body.value("u8", "buffer.load", ["v0", body.const("usize", offset + i)])
        wide = body.value("u64", "int.cast", [byte], {"mode": "wrap"})
        shifted = body.value("u64", "int.shl.checked", [wide, body.const("u64", i * 8)])
        value = body.value("u64", "bit.or", [value, shifted])
    if typ == "bool":
        return body.value("bool", "compare.ne", [value, body.const("u64", 0)])
    return body.value(typ, "int.cast", [value], {"mode": "wrap"})


def _write_results(body, names, types):
    for position, (name, typ) in enumerate(zip(names, types)):
        if typ == "bool":
            word = body.value("u64", "select", [name, body.const("u64", 1), body.const("u64", 0)])
        else:
            word = body.value("u64", "int.cast", [name], {"mode": "wrap"})
        for i in range(8):
            shifted = body.value("u64", "int.shr.checked", [word, body.const("u64", i * 8)])
            byte = body.value("u8", "int.cast", [shifted], {"mode": "wrap"})
            body.effect("buffer.store", ["v1", body.const("usize", position * 8 + i), byte])
    return body.const("u32", 0)


def _scalar_program(argument_types, return_types, helpers, *, callee="f1"):
    from tools.hia_selfhost_bulk import Body
    from tools.hia_selfhost_cases import HEADER
    body = Body()
    args = [_read_word(body, typ, i * 8) for i, typ in enumerate(argument_types)]
    names = _call(body, return_types, args, callee)
    result = _write_results(body, names, return_types)
    return HEADER + body.text() + "  ret(" + result + ")\nend\n" + helpers


def _function(name, argument_types, return_types, body):
    params = ",".join("v" + str(i) + ":" + typ for i, typ in enumerate(argument_types))
    return ("fn " + name + "(" + params + ") -> (" + ",".join(return_types)
            + ") effects(read,write,trap) entry(b0)\nblock b0(" + params + ")\n" + body + "end\n")


def cases():
    """Input-dependent scalar tuples plus CFG, lifetime and call combinations."""
    from tools.hia_selfhost_bulk import Body
    from tools.hia_selfhost_cases import HEADER
    rows = []

    def add(group, source, arguments, expected, *, owned=False):
        raw = b"".join(int(x).to_bytes(8, "little") for x in arguments)
        output = b"".join(int(x).to_bytes(8, "little") for x in expected)
        rows.append({"id": group + "-" + str(sum(row["program"] == group for row in rows)),
            "program": group, "source": source, "source_hex": raw.hex(),
            "initial_hex": (bytes([0xa5]) * len(output)).hex(), "expected_hex": output.hex(),
            "expected_result": 0, "arguments": list(arguments), "expected_values": list(expected),
            "owned_elf_only": owned})

    for typ, bits in (("u8", 8), ("u16", 16), ("u32", 32), ("u64", 64), ("usize", 64), ("bool", 1)):
        types = [typ, typ]
        helper = _function("f1", types, types, "  ret(v1,v0)\n")
        source = _scalar_program(types, types, helper)
        bound = (1 << bits) - 1
        values = ((0, bound), (bound, 0), (1 << (bits - 1), (1 << (bits - 1)) - 1), (bound, bound))
        if typ == "bool":
            values = ((False, False), (False, True), (True, False), (True, True))
        for left, right in values:
            add("pair-" + typ, source, [left, right], [right, left])

    args, returns = ["u64", "u16", "bool"], ["bool", "u64", "u16"]
    helper = _function("f1", args, returns, "  ret(v2,v0,v1)\n")
    source = _scalar_program(args, returns, helper)
    triple_values = ((0, 0, False), ((1 << 64) - 1, 65535, True), (1 << 63, 32768, False))
    for value in triple_values:
        add("triple-mixed", source, value, [value[2], value[0], value[1]])

    # The wrapper is defined after the helper: forward entry -> f2, backward f2 -> f1.
    backward = _function("f2", args, returns,
        '  v3:bool,v4:u64,v5:u16 = call(v0,v1,v2) {"function":"f1"}\n  ret(v3,v4,v5)\n')
    source = _scalar_program(args, returns, helper + backward, callee="f2")
    for value in triple_values:
        add("triple-backward-call", source, value, [value[2], value[0], value[1]])

    helper = _function("f1", ["u64", "u64", "bool"], ["u64", "u64"],
        "  branch v2 b1(v0,v1) b2(v0,v1)\n"
        "block b1(v3:u64,v4:u64)\n  ret(v4,v3)\n"
        "block b2(v5:u64,v6:u64)\n  ret(v5,v6)\n")
    source = _scalar_program(["u64", "u64", "bool"], ["u64", "u64"], helper)
    for condition in (False, True):
        value = [(1 << 64) - 1, 1 << 63, condition]
        add("pair-branch", source, value, list(reversed(value[:2])) if condition else value[:2])

    helper = _function("f1", ["u8", "u64", "u64"], ["u64", "u64"],
        "  jump b1(v0,v1,v2)\n"
        "block b1(v3:u8,v4:u64,v5:u64)\n"
        '  v6:u8 = const() {"value":0}\n  v7:bool = compare.eq(v3,v6)\n'
        "  branch v7 b2(v4,v5) b3(v3,v4,v5)\n"
        "block b2(v8:u64,v9:u64)\n  ret(v8,v9)\n"
        "block b3(v10:u8,v11:u64,v12:u64)\n"
        '  v13:u8 = const() {"value":1}\n  v14:u8 = int.sub.wrap(v10,v13)\n'
        "  jump b1(v14,v12,v11)\n")
    source = _scalar_program(["u8", "u64", "u64"], ["u64", "u64"], helper)
    for count in (0, 1, 2, 31):
        value = [count, (1 << 64) - 1, 1 << 63]
        add("pair-loop", source, value, list(reversed(value[1:])) if count % 2 else value[1:])

    tail = _function("f1", ["u8", "u64", "u64"], ["u64", "u64"],
        '  v3:u8 = const() {"value":0}\n  v4:bool = compare.eq(v0,v3)\n'
        "  branch v4 b1(v1,v2) b2(v0,v1,v2)\n"
        "block b1(v5:u64,v6:u64)\n  ret(v5,v6)\n"
        "block b2(v7:u8,v8:u64,v9:u64)\n"
        '  v10:u8 = const() {"value":1}\n  v11:u8 = int.sub.wrap(v7,v10)\n'
        '  v12:u64,v13:u64 = call(v11,v9,v8) {"function":"f1"}\n  ret(v12,v13)\n')
    source = _scalar_program(["u8", "u64", "u64"], ["u64", "u64"], tail)
    for count in (0, 1, 2, 255):
        value = [count, (1 << 64) - 1, 1 << 63]
        add("pair-tail", source, value, list(reversed(value[1:])) if count % 2 else value[1:])

    # Caller-owned borrowed view crosses the same call boundary as two scalars.
    body = Body()
    results = _call(body, ["usize", "u8"], ["v0"])
    result = _write_results(body, results, ["usize", "u8"])
    helper = _function("f1", ["readbuf"], ["usize", "u8"],
        '  v1:usize = buffer.len(v0)\n  v2:usize = const() {"value":0}\n'
        '  v3:u8 = buffer.load(v0,v2)\n  ret(v1,v3)\n')
    source = HEADER + body.text() + "  ret(" + result + ")\nend\n" + helper
    for value in (17, 255):
        add("pair-borrowed-argument", source, [value], [8, value])

    # Consume an owner, close its child loan, and return only observed scalars.
    body = Body()
    owner = body.value("buffer", "buffer.new", [body.const("usize", 8)])
    results = _call(body, ["usize", "u8"], [owner])
    result = _write_results(body, results, ["usize", "u8"])
    helper = ("fn f1(v0:buffer) -> (usize,u8) effects(alloc,read,write,trap) entry(b0)\n"
        "block b0(v0:buffer)\n  v1:mutbuf = borrow.mut(v0)\n"
        '  v2:u8 = const() {"value":201}\n  _ = buffer.fill(v1,v2)\n'
        '  v3:usize = buffer.len(v1)\n  v4:usize = const() {"value":0}\n'
        "  v5:u8 = buffer.load(v1,v4)\n  _ = loan.end(v1)\n  _ = owner.drop(v0)\n  ret(v3,v5)\nend\n")
    source = (HEADER.replace("v8 selfhost\n", "v8 selfhost_elf\n")
              .replace("effects(read,write,trap)", "effects(alloc,read,write,trap)")
              + body.text() + "  ret(" + result + ")\nend\n" + helper)
    add("pair-owned-argument", source, [], [8, 201], owned=True)
    from tools.hia_selfhost_void_results import cases as void_cases
    from tools.hia_selfhost_owner_results import cases as owner_cases
    from tools.hia_selfhost_returned_loans import cases as loan_cases
    return rows + void_cases() + owner_cases() + loan_cases()


def refusals():
    """Invalid Core shapes and valid general Core outside this bounded profile."""
    from tools.hia_selfhost_cases import HEADER
    base = (HEADER + '  v3:u32 = const() {"value":5}\n  v4:u16 = const() {"value":12}\n'
        '  v5:u16,v6:u32 = call(v3,v4) {"function":"f1"}\n  ret(v6)\nend\n'
        "fn f1(v0:u32,v1:u16) -> (u16,u32) effects(read,write,trap) entry(b0)\n"
        "block b0(v0:u32,v1:u16)\n  ret(v1,v0)\nend\n")
    rows = {}
    def reject(name, source, general="rejected"):
        rows[name] = {"id": name, "source": source, "general_core_expected": general}
    reject("call-too-few-results", base.replace("v5:u16,v6:u32 = call", "v6:u32 = call"))
    reject("call-too-many-results", base.replace("v5:u16,v6:u32 = call", "v5:u16,v6:u32,v7:u8 = call"))
    reject("call-discarded-results", base.replace("v5:u16,v6:u32 = call", "_ = call").replace("ret(v6)", "ret(v3)"))
    reject("second-result-wrong-type", base.replace("v6:u32 = call", "v6:u64 = call").replace("ret(v6)", "ret(v3)"))
    reject("duplicate-result-name", base.replace("v5:u16,v6:u32", "v6:u16,v6:u32"))
    reject("result-redefines-argument", base.replace("v5:u16,v6:u32", "v5:u16,v3:u32").replace("ret(v6)", "ret(v3)"))
    reject("ret-too-few-values", base.replace("ret(v1,v0)", "ret(v1)"))
    reject("ret-too-many-values", base.replace("ret(v1,v0)", "ret(v1,v0,v1)"))
    reject("ret-wrong-order", base.replace("ret(v1,v0)", "ret(v0,v1)"))
    reject("ret-trailing-comma", base.replace("ret(v1,v0)", "ret(v1,v0,)"))
    reject("signature-trailing-comma", base.replace("-> (u16,u32)", "-> (u16,u32,)"))
    reject("entry-multiple-results", base.replace("-> (u32)", "-> (u32,u32)", 1).replace("ret(v6)", "ret(v6,v3)"), "accepted")
    reject("four-scalar-results", base.replace("v5:u16,v6:u32 = call", "v5:u16,v6:u32,v7:u16,v8:u32 = call")
        .replace("-> (u16,u32)", "-> (u16,u32,u16,u32)").replace("ret(v1,v0)", "ret(v1,v0,v1,v0)"), "accepted")
    tail = next(row["source"] for row in cases() if row["program"] == "pair-tail")
    reject("tail-results-reordered", tail.replace("ret(v12,v13)", "ret(v13,v12)"), "accepted")
    reject("tail-result-replaced", tail.replace("ret(v12,v13)", "ret(v12,v9)"), "accepted")
    reject("tail-result-then-operation", tail.replace("  ret(v12,v13)",
        '  v14:u64 = int.add.wrap(v12,v13)\n  ret(v14,v13)'), "accepted")
    owner = (HEADER.replace("v8 selfhost\n", "v8 selfhost_elf\n")
        .replace("effects(read,write,trap)", "effects(alloc,read,write,trap)")
        + '  v3:u32,v4:buffer = call() {"function":"f1"}\n  _ = owner.drop(v4)\n  ret(v3)\nend\n'
        "fn f1() -> (u32,buffer) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n"
        '  v0:usize = const() {"value":8}\n  v1:buffer = buffer.new(v0)\n'
        '  v2:u32 = const() {"value":17}\n  ret(v2,v1)\nend\n')
    # A valid owner return is now in the positive family; do not relabel it
    # as a refusal merely because previous compiler profiles did not admit it.
    from tools.hia_selfhost_void_results import refusals as void_refusals
    from tools.hia_selfhost_owner_results import refusals as owner_refusals
    from tools.hia_selfhost_returned_loans import refusals as loan_refusals
    return list(rows.values()) + void_refusals() + owner_refusals() + loan_refusals()


def independent_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    from tools.hia_selfhost_loans import reference_source
    accepted, rejected = [], []
    for case in cases():
        checked = assemble_program(case["source"].encode())
        wrapper = reference_source(case)
        reference_entry = "reference_entry"
        reference_program = assemble_program(wrapper)
        arguments = []
        expected = [case["expected_result"], *bytes.fromhex(case["expected_hex"])]
        if case["program"] == "pair-tail" and case["arguments"][0] == 255:
            # The VM uses ordinary frames, unlike the native same-frame tail
            # jump. Calling this scalar helper directly fits its unchanged
            # 256-frame limit; an allocation wrapper plus f0 would not.
            reference_entry, reference_program, arguments = "f1", checked, case["arguments"]
            expected = case["expected_values"]
        result = execute_program(reference_program, reference_entry, arguments)
        if result.get("status") != "returned" or result["values"] != expected:
            raise AssertionError({"case": case["id"], "expected": expected, "actual": result})
        accepted.append({**case, "core_sha256": checked.sha256,
                         "reference_source": wrapper.decode() if reference_entry == "reference_entry" else case["source"],
                         "reference_entry": reference_entry, "reference_arguments": arguments,
                         "reference_result": result})
    for case in refusals():
        try:
            checked = assemble_program(case["source"].encode())
            result = {"status": "accepted", "core_sha256": checked.sha256}
        except HIAProgramRejected as exc:
            result = {"status": "rejected", "code": exc.code, "message": str(exc)}
        if result["status"] != case["general_core_expected"]:
            raise AssertionError({"case": case["id"], "unexpected_reference": result})
        rejected.append({**case, "reference_result": result})
    return {"cases": accepted, "refusals": rejected,
        "before_B0": True, "all_input_correctness_proved": False,
        "returned_resources_supported": True, "returned_loans_supported": True, "public_entry_abi_changed": False}


def qualify(directory, compilers, checks, reference, *, family="multi"):
    from tools.qualify_hia_selfhost import (INVALID, NO_SPACE, compile_stage, digest,
        inspect_selfhost_object, invoke, observe_native_tool)
    from tools.qualify_hia_selfhost_owned_elf import inspect_owned_object
    observations = []
    for label, compiler in compilers:
        images = {}
        for case in reference["cases"]:
            program = case["program"]
            prefix = label + "-" + family + "-" + program
            if program not in images:
                source = case["source"].encode()
                owned = case["owned_elf_only"]
                flat = None
                if not owned:
                    flat, receipt = compile_stage(directory, prefix + "-flat", compiler, source)
                    observations.append(receipt)
                object_source = source if owned else source.replace(b"v8 selfhost\n", b"v8 selfhost_elf\n", 1)
                obj, receipt = compile_stage(directory, prefix + "-object", compiler, object_source, output_extension=".o")
                inspection = inspect_owned_object(obj.read_bytes()) if owned else inspect_selfhost_object(obj.read_bytes())
                observations.append({**receipt, "inspection": inspection})
                if flat is not None:
                    checks[prefix + "-flat-elf-text"] = inspection["text_sha256"] == digest(flat.read_bytes())
                linked = directory / (prefix + ".so")
                args = ["-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                        "-z", "relro", "-z", "now", "--build-id=none", obj]
                if owned:
                    args.append("-lc")
                tool = observe_native_tool(directory, prefix + "-link", "ld", [*args, "-o", linked])
                if tool["returncode"]:
                    raise AssertionError(tool)
                observations.append(tool)
                images[program] = [("elf", linked, "linked-selfhost")]
                if flat is not None:
                    images[program].append(("flat", flat, "flat-x86-64"))
                short, _ = invoke(directory, prefix + "-short-output", compiler, object_source,
                                  capacity=receipt["produced_bytes"] - 1)
                checks[prefix + "-short-output"] = bool(short.get("status") == "returned"
                    and short.get("core_u32") == NO_SPACE and short.get("output_unchanged"))
                observations.append(short)
            for kind, image, image_format in images[program]:
                name = label + "-" + family + "-" + case["id"] + "-" + kind
                initial = bytes.fromhex(case["initial_hex"])
                result, output = invoke(directory, name, image, bytes.fromhex(case["source_hex"]),
                    image_format=image_format, capacity=len(initial), workspace_size=0,
                    output_initial=initial, observe_trap_writes=True)
                checks[name] = bool(result.get("status") == "returned" and result.get("abi_status") == 0
                    and result.get("core_u32") == case["expected_result"] and result.get("source_unchanged")
                    and not result.get("forbidden_compiler_modules_loaded") and output.hex() == case["expected_hex"])
                observations.append({"case": case["id"], "native": result, "actual_hex": output.hex(),
                                     "expected_hex": case["expected_hex"]})
        for case in reference["refusals"]:
            name = label + "-" + family + "-reject-" + case["id"]
            result, output = invoke(directory, name, compiler, case["source"].encode(), capacity=512)
            checks[name] = bool(result.get("status") == "returned" and result.get("core_u32") == INVALID
                and result.get("source_unchanged") and result.get("output_unchanged")
                and output == bytes([0xa5]) * 512)
            observations.append({"case": case["id"], "native": result,
                                 "general_core_expected": case["general_core_expected"]})
    return observations
