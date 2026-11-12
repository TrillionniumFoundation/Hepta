"""Input-dependent scalar select witnesses for the bounded native compiler.

The Core VM observations precede B0. Native programs decode a condition and both
values from caller bytes, and preserve all result bits in an eight-byte output.
"""
from __future__ import annotations

import json

WIDTHS = {"u8": 8, "u16": 16, "u32": 32, "u64": 64, "usize": 64}
HEADER = ("hia-asm.v1 hepta.hia.program.v8 selfhost\n"
    "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
    "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n")


def select_cases():
    rows = []
    for typ, width in WIDTHS.items():
        high, mask = 1 << (width - 1), (1 << width) - 1
        pairs = ((0, mask), (mask, 0), (high, high - 1), (high - 1, high),
                 (1, mask), (mask, 1), (mask, mask))
        for condition in (False, True):
            for left, right in pairs:
                rows.append({"type": typ, "condition": condition, "left": left,
                             "right": right, "expected": left if condition else right})
    for condition in (False, True):
        for left in (False, True):
            for right in (False, True):
                rows.append({"type": "bool", "condition": condition, "left": left,
                             "right": right, "expected": left if condition else right})
    return rows


def select_source(typ):
    """Compile once per type; all three select operands depend on input bytes."""
    if typ not in (*WIDTHS, "bool"):
        raise ValueError("unsupported select fixture type")
    lines, serial = [], 3
    def op(kind, opcode, args=(), attrs=None):
        nonlocal serial
        name = "v" + str(serial)
        serial += 1
        suffix = " " + json.dumps(attrs, separators=(",", ":")) if attrs else ""
        lines.append("  " + name + ":" + kind + " = " + opcode + "(" + ",".join(args) + ")" + suffix)
        return name
    def const(kind, value):
        return op(kind, "const", attrs={"value": value})
    def read_word(base):
        value = const("u64", 0)
        for index in range(8):
            offset = const("usize", base + index)
            byte = op("u8", "buffer.load", ["v0", offset])
            wide = op("u64", "int.cast", [byte], {"mode": "wrap"})
            amount = const("u64", index * 8)
            part = op("u64", "int.shl.checked", [wide, amount])
            value = op("u64", "bit.or", [value, part])
        if typ == "bool":
            return op("bool", "compare.ne", [value, const("u64", 0)])
        return op(typ, "int.cast", [value], {"mode": "wrap"})
    first = op("u8", "buffer.load", ["v0", const("usize", 0)])
    condition = op("bool", "compare.ne", [first, const("u8", 0)])
    left, right = read_word(1), read_word(9)
    chosen = op(typ, "select", [condition, left, right])
    if typ == "bool":
        word = op("u64", "call", [chosen], {"function": "f1"})
    else:
        word = op("u64", "int.cast", [chosen], {"mode": "wrap"})
    for index in range(8):
        amount = const("u64", index * 8)
        shifted = op("u64", "int.shr.checked", [word, amount])
        byte = op("u8", "int.cast", [shifted], {"mode": "wrap"})
        offset = const("usize", index)
        lines.append("  _ = buffer.store(v1," + offset + "," + byte + ")")
    result = op("u32", "int.cast", [word], {"mode": "wrap"})
    source = HEADER + "\n".join(lines) + "\n  ret(" + result + ")\nend\n"
    if typ == "bool":
        source += ("fn f1(v0:bool) -> (u64) effects(read,write,trap) entry(b0)\n"
            "block b0(v0:bool)\n  branch v0 b1() b2()\n"
            'block b1()\n  v1:u64 = const() {"value":1}\n  ret(v1)\n'
            'block b2()\n  v2:u64 = const() {"value":0}\n  ret(v2)\nend\n')
    return source.encode()


def select_refusals():
    prefix = (HEADER + '  v3:bool = const() {"value":true}\n'
        '  v4:u32 = const() {"value":1}\n  v5:u32 = const() {"value":2}\n')
    source = (prefix + "  v6:u32 = select(v3,v4,v5)\n  ret(v6)\nend\n").encode()
    rows = {"arity-" + str(len(args)): source.replace(b"select(v3,v4,v5)",
            ("select(" + ",".join(args) + ")").encode())
            for args in ((), ("v3",), ("v3", "v4"), ("v3", "v4", "v5", "v4"))}
    rows.update({
        "non-bool-condition": source.replace(b"select(v3,v4,v5)", b"select(v4,v4,v5)"),
        "unlike-values": source.replace(b"v5:u32", b"v5:u64"),
        "same-width-unlike-values": source.replace(b"v4:u32", b"v4:u64").replace(b"v5:u32", b"v5:usize")
            .replace(b"v6:u32", b"v6:u64").replace(b"  ret(v6)", b'  v7:u32 = const() {"value":0}\n  ret(v7)'),
        "wrong-result-type": source.replace(b"v6:u32", b"v6:u64").replace(b"ret(v6)", b"ret(v4)"),
        "discarded-result": source.replace(b"v6:u32 = select", b"_ = select").replace(b"ret(v6)", b"ret(v4)"),
        "readbuf-selection": (prefix + "  v6:readbuf = select(v3,v0,v0)\n  ret(v4)\nend\n").encode(),
        "mutbuf-selection": (prefix + "  v6:mutbuf = select(v3,v1,v2)\n  ret(v4)\nend\n").encode(),
        "resource-as-scalar": source.replace(b"select(v3,v4,v5)", b"select(v3,v0,v0)"),
        "resource-condition": source.replace(b"select(v3,v4,v5)", b"select(v0,v4,v5)"),
    })
    return rows


def boolean_equality_source(opcode):
    """Read both booleans from caller bytes; return their equality comparison."""
    if opcode not in {"compare.eq", "compare.ne"}:
        raise ValueError("boolean comparison admits equality and inequality only")
    return (HEADER +
        '  v3:usize = const() {"value":0}\n'
        '  v4:usize = const() {"value":1}\n'
        '  v5:u8 = buffer.load(v0,v3)\n'
        '  v6:u8 = buffer.load(v0,v4)\n'
        '  v7:u8 = const() {"value":0}\n'
        '  v8:bool = compare.ne(v5,v7)\n'
        '  v9:bool = compare.ne(v6,v7)\n'
        '  v10:bool = ' + opcode + '(v8,v9)\n'
        '  branch v10 b1() b2()\n'
        'block b1()\n  v11:u32 = const() {"value":1}\n  ret(v11)\n'
        'block b2()\n  v12:u32 = const() {"value":0}\n  ret(v12)\nend\n').encode()


def boolean_equality_refusals():
    source = boolean_equality_source("compare.eq")
    target = b"v10:bool = compare.eq(v8,v9)"
    substitutions = {"ordered-" + opcode: b"v10:bool = " + opcode.encode() + b"(v8,v9)"
                     for opcode in ("compare.lt", "compare.le", "compare.gt", "compare.ge")}
    substitutions.update({
        "mixed-left": b"v10:bool = compare.eq(v5,v9)",
        "mixed-right": b"v10:bool = compare.eq(v8,v6)",
        "resource-left": b"v10:bool = compare.eq(v0,v9)",
        "resource-right": b"v10:bool = compare.eq(v8,v0)",
        "wrong-result": b"v10:u8 = compare.eq(v8,v9)",
        "missing-result": b"_ = compare.eq(v8,v9)",
        "empty-arity": b"v10:bool = compare.eq()",
        "short-arity": b"v10:bool = compare.eq(v8)",
        "long-arity": b"v10:bool = compare.eq(v8,v9,v8)",
    })
    rows = {name: source.replace(target, replacement) for name, replacement in substitutions.items()}
    rows["missing-result"] = rows["missing-result"].replace(b"branch v10", b"branch v8")
    return rows


def independent_boolean_equality_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    observations, rejected = [], []
    for opcode in ("compare.eq", "compare.ne"):
        source = ("hia-asm.v1 hepta.hia.program.v8 boolean_equality_reference\n"
            "fn f0(v0:bool,v1:bool) -> (bool) effects() entry(b0)\n"
            "block b0(v0:bool,v1:bool)\n  v2:bool = " + opcode + "(v0,v1)\n  ret(v2)\nend\n").encode()
        checked = assemble_program(source)
        assemble_program(boolean_equality_source(opcode))
        for left in (0, 1, 2, 255):
            for right in (0, 1, 2, 255):
                expected = bool(left) == bool(right) if opcode == "compare.eq" else bool(left) != bool(right)
                result = execute_program(checked, "f0", [bool(left), bool(right)])
                assert result["status"] == "returned" and result["values"] == [expected], result
                observations.append({"opcode": opcode, "input_hex": bytes((left, right)).hex(),
                    "expected": expected, "core_sha256": checked.sha256, "reference_result": result})
    for name, source in boolean_equality_refusals().items():
        try:
            assemble_program(source)
        except HIAProgramRejected as exc:
            rejected.append({"case": name, "code": exc.code, "message": str(exc)})
        else:
            raise AssertionError("independent checker admitted " + name)
    return {"cases": observations, "rejections": rejected}


def qualify_boolean_equality(directory, compilers, checks, reference):
    from tools.qualify_hia_selfhost import (INVALID, NO_SPACE, compile_stage,
        digest, inspect_selfhost_object, invoke)
    observations = []
    for label, compiler in compilers:
        for opcode in ("compare.eq", "compare.ne"):
            name = label + "-boolean-" + opcode
            source = boolean_equality_source(opcode)
            executable, build = compile_stage(directory, name + "-build", compiler, source)
            observations.append(build)
            for index, case in enumerate(row for row in reference["cases"] if row["opcode"] == opcode):
                result, output = invoke(directory, name + "-case-" + str(index), executable,
                    bytes.fromhex(case["input_hex"]), capacity=8, workspace_size=0)
                checks[result["case"]] = bool(result.get("status") == "returned"
                    and result.get("core_u32") == int(case["expected"])
                    and result.get("source_unchanged") and result.get("output_unchanged")
                    and output == bytes([0xa5]) * 8)
                observations.append({**result, "expected": case["expected"]})
            short, _ = invoke(directory, name + "-short-output", compiler, source,
                capacity=build["produced_bytes"] - 1)
            checks[short["case"]] = bool(short.get("status") == "returned"
                and short.get("core_u32") == NO_SPACE and short.get("output_unchanged"))
            observations.append(short)
            obj, obj_build = compile_stage(directory, name + "-object", compiler,
                source.replace(b"v8 selfhost\n", b"v8 selfhost_elf\n", 1), output_extension=".o")
            inventory = inspect_selfhost_object(obj.read_bytes())
            checks[name + "-elf-text"] = inventory["text_sha256"] == digest(executable.read_bytes())
            observations.append({**obj_build, "object_inspection": inventory})
        for name, source in boolean_equality_refusals().items():
            result, _ = invoke(directory, label + "-boolean-equality-reject-" + name, compiler, source)
            checks[result["case"]] = bool(result.get("status") == "returned"
                and result.get("core_u32") == INVALID and result.get("output_unchanged")
                and result.get("source_unchanged"))
            observations.append(result)
    return observations


def independent_select_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    programs, observations, rejected = {}, [], []
    for case in select_cases():
        typ = case["type"]
        if typ not in programs:
            text = ("hia-asm.v1 hepta.hia.program.v8 select_reference\n"
                "fn f0(v0:bool,v1:" + typ + ",v2:" + typ + ") -> (" + typ + ") effects(read,write,trap) entry(b0)\n"
                "block b0(v0:bool,v1:" + typ + ",v2:" + typ + ")\n"
                "  v3:" + typ + " = select(v0,v1,v2)\n  ret(v3)\nend\n")
            programs[typ] = assemble_program(text.encode())
        checked = programs[typ]
        result = execute_program(checked, "f0", [case["condition"], case["left"], case["right"]])
        assert result["status"] == "returned" and result["values"] == [case["expected"]], result
        observations.append({**case, "core_sha256": checked.sha256, "reference_result": result})
    for name, source in select_refusals().items():
        try:
            assemble_program(source)
        except HIAProgramRejected as exc:
            rejected.append({"case": name, "code": exc.code, "message": str(exc)})
        else:
            raise AssertionError("independent checker admitted " + name)
    return {"cases": observations, "rejections": rejected,
            "boolean_equality": independent_boolean_equality_reference()}


def qualify_select(directory, compilers, checks, reference):
    from tools.qualify_hia_selfhost import (INVALID, NO_SPACE, compile_stage,
        digest, inspect_selfhost_object, invoke)
    observations = []
    for label, compiler in compilers:
        for typ in (*WIDTHS, "bool"):
            name = label + "-select-" + typ
            source = select_source(typ)
            executable, build = compile_stage(directory, name + "-build", compiler, source)
            observations.append(build)
            for index, case in enumerate(c for c in reference["cases"] if c["type"] == typ):
                data = (bytes([int(case["condition"])]) + int(case["left"]).to_bytes(8, "little")
                        + int(case["right"]).to_bytes(8, "little"))
                result, output = invoke(directory, name + "-case-" + str(index), executable,
                                        data, capacity=8, workspace_size=0)
                expected = int(case["expected"])
                checks[result["case"]] = bool(result.get("status") == "returned"
                    and result.get("core_u32") == expected & 0xffffffff
                    and output == expected.to_bytes(8, "little") and result.get("source_unchanged"))
                observations.append({**result, "expected": case["expected"],
                                     "condition": case["condition"], "type": typ})
            short, _ = invoke(directory, name + "-short-output", compiler, source,
                              capacity=build["produced_bytes"] - 1)
            checks[short["case"]] = bool(short.get("status") == "returned"
                and short.get("core_u32") == NO_SPACE and short.get("output_unchanged"))
            observations.append(short)
            obj, obj_build = compile_stage(directory, name + "-object", compiler,
                source.replace(b"v8 selfhost\n", b"v8 selfhost_elf\n", 1), output_extension=".o")
            inventory = inspect_selfhost_object(obj.read_bytes())
            checks[name + "-elf-text"] = inventory["text_sha256"] == digest(executable.read_bytes())
            observations.append({**obj_build, "object_inspection": inventory})
        for name, source in select_refusals().items():
            result, _ = invoke(directory, label + "-select-reject-" + name, compiler, source)
            checks[result["case"]] = bool(result.get("status") == "returned"
                and result.get("core_u32") == INVALID and result.get("output_unchanged")
                and result.get("source_unchanged"))
            observations.append(result)
    observations.extend(qualify_boolean_equality(directory, compilers, checks, reference["boolean_equality"]))
    return observations
