"""Independent small Core fixtures for v9 word-memory conformance."""
from copy import deepcopy

SCHEMA = "hepta.hia.program.v9"
ORDERS = {"le": "little", "be": "big"}
WORD_OPS = tuple(f"buffer.{mode}.u64.{order}"
                 for mode in ("load", "store") for order in ORDERS)


def param(name, typ):
    return {"name": name, "type": typ}


def instruction(op, args=(), out=(), **attrs):
    return {"op": op, "args": list(args),
            "out": [param(*value) for value in out], "attrs": attrs}


def literal(name, typ, value):
    return instruction("const", out=[(name, typ)], value=value)


def block(name, params, ops, term):
    return {"id": name, "params": deepcopy(params), "ops": ops, "term": term}


def ret(*values):
    return {"op": "ret", "values": list(values)}


def jump(target, *args):
    return {"op": "jump", "target": target, "args": list(args)}


def owned_program():
    """Fill with old byte stores, then load a word or store and read one byte.

    Every initial byte is (index*17+value)&255. This oracle does not use a new
    word store to initialize a new word load, or vice versa.
    """
    functions = []
    for mode in ("load", "store"):
        for order in ORDERS:
            name = mode + "_" + order
            args = [param("n", "usize"), param("offset", "usize"),
                    param("value", "u64"), param("probe", "usize")]
            entry = block("entry", args, [
                instruction("buffer.new", ["n"], [("owner", "buffer")]),
                instruction("borrow.mut", ["owner"], [("view", "mutbuf")]),
                literal("zero", "usize", 0),
            ], jump("check", "owner", "view", "n", "offset", "value", "probe", "zero"))
            def fields(prefix):
                return [param(prefix + name, typ) for name, typ in (
                    ("owner", "buffer"), ("view", "mutbuf"), ("n", "usize"),
                    ("offset", "usize"), ("value", "u64"), ("probe", "usize"),
                    ("i", "usize"))]
            check_args, fill_args, read_args = fields("c"), fields("w"), fields("r")
            check = block("check", check_args, [
                instruction("compare.lt", ["ci", "cn"], [("more", "bool")]),
            ], {"op": "branch", "cond": "more",
                "then": {"target": "fill", "args": [p["name"] for p in check_args]},
                "else": {"target": "read", "args": [p["name"] for p in check_args]}})
            fill = block("fill", fill_args, [
                instruction("int.cast", ["wi"], [("wide", "u64")], mode="wrap"),
                literal("factor", "u64", 17),
                instruction("int.mul.wrap", ["wide", "factor"], [("times", "u64")]),
                instruction("int.add.wrap", ["times", "wvalue"], [("pattern", "u64")]),
                instruction("int.cast", ["pattern"], [("byte", "u8")], mode="wrap"),
                instruction("buffer.store", ["wview", "wi", "byte"]),
                literal("one", "usize", 1),
                instruction("int.add.wrap", ["wi", "one"], [("next", "usize")]),
            ], jump("check", *[p["name"] for p in fill_args[:-1]], "next"))
            ops = []
            if mode == "load":
                ops.append(instruction(f"buffer.load.u64.{order}",
                                       ["rview", "roffset"], [("answer", "u64")]))
            else:
                ops += [
                    instruction(f"buffer.store.u64.{order}", ["rview", "roffset", "rvalue"]),
                    instruction("buffer.load", ["rview", "rprobe"], [("observed", "u8")]),
                    instruction("int.cast", ["observed"], [("answer", "u64")], mode="wrap"),
                ]
            ops += [instruction("loan.end", ["rview"]), instruction("owner.drop", ["rowner"])]
            read = block("read", read_args, ops, ret("answer"))
            functions.append({"name": name, "params": args, "returns": ["u64"],
                              "effects": ["alloc", "read", "write", "trap"],
                              "entry": "entry", "blocks": [entry, check, fill, read]})
    return {"schema": SCHEMA, "module": "word_memory",
            "exports": [f["name"] for f in functions], "functions": functions}


def expected(mode, order, n, offset, value, probe):
    data = bytearray((i * 17 + value) & 255 for i in range(n))
    if offset > n or 8 > n - offset:
        return None
    if mode == "load":
        return int.from_bytes(data[offset:offset + 8], ORDERS[order])
    data[offset:offset + 8] = value.to_bytes(8, ORDERS[order])
    return data[probe]


def acyclic_program():
    ops = [literal("size", "usize", 17), literal("offset", "usize", 1),
           literal("value", "u64", 0xFEDCBA9876543210),
           instruction("buffer.new", ["size"], [("owner", "buffer")]),
           instruction("borrow.mut", ["owner"], [("view", "mutbuf")]),
           instruction("buffer.store.u64.le", ["view", "offset", "value"]),
           instruction("buffer.load.u64.be", ["view", "offset"], [("result", "u64")]),
           instruction("loan.end", ["view"]), instruction("owner.drop", ["owner"])]
    return {"schema": SCHEMA, "module": "acyclic_word_memory", "exports": ["probe"],
            "functions": [{"name": "probe", "params": [], "returns": ["u64"],
                           "effects": ["alloc", "read", "write", "trap"],
                           "entry": "entry", "blocks": [block("entry", [], ops, ret("result"))]}]}


def foreign_program():
    """17-byte command: operation byte, offset LE u64, value LE u64.

    Target is the second borrowed buffer; successful loads write eight result
    bytes to the third. All framing uses old byte operations. A word bounds
    failure occurs before any target/result write in the selected branch.
    """
    args = [param("source", "readbuf"), param("target", "mutbuf"), param("result", "mutbuf")]
    def abi_fields(prefix):
        return [param(prefix + p["name"], p["type"]) for p in args]
    check = block("entry", args, [
        instruction("buffer.len", ["source"], [("source_n", "usize")]),
        literal("header", "usize", 17),
        instruction("compare.ge", ["source_n", "header"], [("source_ok", "bool")]),
    ], {"op": "branch", "cond": "source_ok",
        "then": {"target": "capacity", "args": [p["name"] for p in args]},
        "else": {"target": "bad", "args": [p["name"] for p in args]}})
    capacity_fields = abi_fields("c")
    capacity = block("capacity", capacity_fields, [
        instruction("buffer.len", ["cresult"], [("result_n", "usize")]),
        literal("eight", "usize", 8),
        instruction("compare.ge", ["result_n", "eight"], [("result_ok", "bool")]),
    ], {"op": "branch", "cond": "result_ok",
        "then": {"target": "decode", "args": [p["name"] for p in capacity_fields]},
        "else": {"target": "short", "args": [p["name"] for p in capacity_fields]}})
    decode_fields = abi_fields("d")
    decode = block("decode", decode_fields, [
        literal("command_at", "usize", 0), literal("offset_at", "usize", 1),
        literal("value_at", "usize", 9),
        instruction("buffer.load", ["dsource", "command_at"], [("command", "u8")]),
        instruction("call", ["dsource", "offset_at"], [("offset_word", "u64")], function="get"),
        instruction("int.cast", ["offset_word"], [("offset", "usize")], mode="wrap"),
        instruction("call", ["dsource", "value_at"], [("value", "u64")], function="get"),
    ], jump("select0", "dtarget", "dresult", "offset", "value", "command"))
    blocks = [check, capacity, decode]
    for index, (mode, order) in enumerate((m, o) for m in ("load", "store") for o in ORDERS):
        def operation_fields(prefix):
            return [param(prefix + n, t) for n, t in (
                ("target", "mutbuf"), ("result", "mutbuf"), ("offset", "usize"),
                ("value", "u64"), ("command", "u8"))]
        prefix = "s" + str(index)
        fields = operation_fields(prefix)
        blocks.append(block("select" + str(index), fields, [
            literal(prefix + "tag", "u8", index),
            instruction("compare.eq", [prefix + "command", prefix + "tag"], [(prefix + "yes", "bool")]),
        ], {"op": "branch", "cond": prefix + "yes",
            "then": {"target": "operation" + str(index), "args": [p["name"] for p in fields]},
            "else": {"target": "select" + str(index + 1) if index < 3 else "bad_command",
                     "args": [p["name"] for p in fields]}}))
        prefix = "o" + str(index)
        fields = operation_fields(prefix)
        ops = []
        if mode == "load":
            ops += [
                instruction(f"buffer.load.u64.{order}", [prefix + "target", prefix + "offset"],
                            [(prefix + "loaded", "u64")]),
                instruction("call", [prefix + "result", prefix + "loaded"], function="put"),
            ]
        else:
            ops.append(instruction(f"buffer.store.u64.{order}",
                                   [prefix + "target", prefix + "offset", prefix + "value"]))
        ops.append(literal(prefix + "ok", "u32", 8))
        blocks.append(block("operation" + str(index), fields, ops, ret(prefix + "ok")))
    for name, code in (("bad", 0xFFFFFFFF), ("short", 0xFFFFFFFE)):
        blocks.append(block(name, abi_fields(name), [literal(name + "_code", "u32", code)],
                            ret(name + "_code")))
    blocks.append(block("bad_command", operation_fields("badop"),
                        [literal("badop_code", "u32", 0xFFFFFFFF)], ret("badop_code")))
    main = {"name": "f0", "params": args, "returns": ["u32"],
            "effects": ["read", "write", "trap"], "entry": "entry", "blocks": blocks}
    get_args = [param("input", "readbuf"), param("begin", "usize")]
    get_ops = [literal("acc0", "u64", 0)]
    put_args = [param("output", "mutbuf"), param("input_value", "u64")]
    put_ops = []
    for index in range(8):
        get_ops += [
            literal(f"delta{index}", "usize", index),
            instruction("int.add.checked", ["begin", f"delta{index}"], [(f"at{index}", "usize")]),
            instruction("buffer.load", ["input", f"at{index}"], [(f"byte{index}", "u8")]),
            instruction("int.cast", [f"byte{index}"], [(f"wide{index}", "u64")], mode="wrap"),
            literal(f"shift{index}", "u64", index * 8),
            instruction("int.shl.checked", [f"wide{index}", f"shift{index}"], [(f"part{index}", "u64")]),
            instruction("bit.or", [f"acc{index}", f"part{index}"], [(f"acc{index + 1}", "u64")]),
        ]
        put_ops += [
            literal(f"at{index}", "usize", index),
            literal(f"shift{index}", "u64", index * 8),
            instruction("int.shr.checked", ["input_value", f"shift{index}"], [(f"part{index}", "u64")]),
            instruction("int.cast", [f"part{index}"], [(f"byte{index}", "u8")], mode="wrap"),
            instruction("buffer.store", ["output", f"at{index}", f"byte{index}"]),
        ]
    get = {"name": "get", "params": get_args, "returns": ["u64"], "effects": ["read", "trap"],
           "entry": "entry", "blocks": [block("entry", get_args, get_ops, ret("acc8"))]}
    put = {"name": "put", "params": put_args, "returns": [], "effects": ["write", "trap"],
           "entry": "entry", "blocks": [block("entry", put_args, put_ops, ret())]}
    return {"schema": SCHEMA, "module": "selfhost_elf", "functions": [main, get, put]}
