"""Independent Core and native witnesses for explicit borrowed-view lifetimes.

The VM wrappers own their buffers. Successor machines receive caller-owned,
disjoint allocations. Incoming capability graphs, not receipts or fixture
names, determine native admission. These cases are finite qualification.
"""
from __future__ import annotations

from tools.hia_selfhost_bulk import Body
from tools.hia_selfhost_cases import HEADER

INPUT = bytes(range(101, 109))
OUTPUT = bytes(range(31, 39))


def _program(body, suffix=""):
    return (HEADER + body + "end\n" + suffix).encode()


def _finish(body, value, suffix=""):
    return _program(body.text() + f"  ret({value})\n", suffix)


def loan_cases():
    rows = []

    def add(name, source, result, output=OUTPUT, data=INPUT):
        rows.append({"id": name, "source": source.decode(), "expected_result": result,
                     "initial_hex": OUTPUT.hex() if len(output) else "",
                     "source_hex": data.hex(), "expected_hex": output.hex()})

    def load(b, view, index):
        return b.value("u8", "buffer.load", [view, b.const("usize", index)])

    def widen(b, value):
        return b.value("u32", "int.cast", [value], {"mode": "wrap"})

    for depth in (1, 8, 32):
        b = Body(); parent = "v0"; loans = []
        for _ in range(depth):
            parent = b.value("readbuf", "borrow.read", [parent]); loans.append(parent)
        result = widen(b, load(b, parent, 2))
        for loan in reversed(loans): b.effect("loan.end", [loan])
        add("shared-depth-" + str(depth), _finish(b, result), 103)

    b = Body(); left = b.value("readbuf", "borrow.read", ["v0"])
    right = b.value("readbuf", "borrow.read", ["v0"])
    a, c = widen(b, load(b, left, 0)), widen(b, load(b, right, 1))
    result = b.value("u32", "int.add.wrap", [a, c])
    b.effect("loan.end", [left]); b.effect("loan.end", [right])
    add("shared-siblings", _finish(b, result), 203)

    b = Body(); view = b.value("mutbuf", "borrow.mut", ["v1"])
    b.effect("buffer.store", [view, b.const("usize", 3), b.const("u8", 199)])
    b.effect("loan.end", [view]); result = widen(b, load(b, "v1", 3))
    changed = bytearray(OUTPUT); changed[3] = 199
    add("mutable-store", _finish(b, result), 199, bytes(changed))

    b = Body(); parent = b.value("mutbuf", "borrow.mut", ["v1"])
    child = b.value("mutbuf", "borrow.mut", [parent])
    b.effect("buffer.store", [child, b.const("usize", 0), b.const("u8", 201)])
    b.effect("loan.end", [child])
    b.effect("buffer.store", [parent, b.const("usize", 1), b.const("u8", 202)])
    b.effect("loan.end", [parent])
    a, c = widen(b, load(b, "v1", 0)), widen(b, load(b, "v1", 1))
    result = b.value("u32", "int.add.wrap", [a, c])
    add("nested-mutable", _finish(b, result), 403, bytes([201, 202]) + OUTPUT[2:])

    b = Body(); view = b.value("readbuf", "borrow.read", ["v1"])
    result = widen(b, load(b, view, 4)); b.effect("loan.end", [view])
    b.effect("buffer.store", ["v1", b.const("usize", 0), b.const("u8", 99)])
    add("shared-from-mutable", _finish(b, result), 35, bytes([99]) + OUTPUT[1:])

    b = Body(); parent = b.value("mutbuf", "borrow.mut", ["v1"])
    left = b.value("readbuf", "borrow.read", [parent])
    right = b.value("readbuf", "borrow.read", [parent])
    a, c = widen(b, load(b, left, 0)), widen(b, load(b, right, 1))
    result = b.value("u32", "int.add.wrap", [a, c])
    for view in (left, right, parent): b.effect("loan.end", [view])
    add("shared-siblings-under-mutable", _finish(b, result), 63)

    for size in (0, 8):
        b = Body(); view = b.value("mutbuf", "borrow.mut", ["v1"])
        extent = b.value("usize", "buffer.len", ["v1"])
        result = widen(b, extent); b.effect("loan.end", [view])
        add("parent-extent-" + str(size), _finish(b, result), size,
            OUTPUT if size else b"", INPUT if size else b"")

    b = Body(); source = b.value("readbuf", "borrow.read", ["v0"])
    dest = b.value("mutbuf", "borrow.mut", ["v1"])
    b.effect("buffer.copy", [dest, source, b.const("usize", 5)])
    for view in (source, dest): b.effect("loan.end", [view])
    add("disjoint-child-copy", _finish(b, b.const("u32", 0)), 0, INPUT[:5] + OUTPUT[5:])

    b = Body(); view = b.value("readbuf", "borrow.read", ["v1"])
    b.effect("loan.end", [view]); mutable = b.value("mutbuf", "borrow.mut", ["v1"])
    b.effect("buffer.fill", [mutable, b.const("u8", 201)])
    b.effect("loan.end", [mutable])
    add("exclusive-after-shared-close", _finish(b, b.const("u32", 201)), 201, bytes([201]) * 8)

    read_helper = ("fn f1(v0:readbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
                   "block b0(v0:readbuf)\n  v1:usize = const() {\"value\":0}\n"
                   "  v2:u8 = buffer.load(v0,v1)\n  v3:u32 = int.cast(v2) {\"mode\":\"wrap\"}\n"
                   "  ret(v3)\nend\n")
    b = Body(); view = b.value("readbuf", "borrow.read", ["v0"])
    result = b.value("u32", "call", [view], {"function": "f1"}); b.effect("loan.end", [view])
    add("call-local-read", _finish(b, result, read_helper), 101)
    nested_helper = read_helper.replace("  v1:usize", "  v4:readbuf = borrow.read(v0)\n  v1:usize")
    nested_helper = nested_helper.replace("buffer.load(v0,", "buffer.load(v4,")
    nested_helper = nested_helper.replace("  ret(v3)", "  _ = loan.end(v4)\n  ret(v3)")
    add("call-nested-read", _finish(b, result, nested_helper), 101)

    alias_helper = ("fn f1(v0:readbuf,v1:readbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
                    "block b0(v0:readbuf,v1:readbuf)\n  v2:usize = const() {\"value\":0}\n"
                    "  v3:u8 = buffer.load(v0,v2)\n  v4:u8 = buffer.load(v1,v2)\n"
                    "  v5:u32 = int.cast(v3) {\"mode\":\"wrap\"}\n"
                    "  v6:u32 = int.cast(v4) {\"mode\":\"wrap\"}\n"
                    "  v7:u32 = int.add.wrap(v5,v6)\n  ret(v7)\nend\n")
    b = Body(); a = b.value("readbuf", "borrow.read", ["v0"])
    c = b.value("readbuf", "borrow.read", ["v0"])
    result = b.value("u32", "call", [a, c], {"function": "f1"})
    for view in (a, c): b.effect("loan.end", [view])
    add("call-shared-root-aliases", _finish(b, result, alias_helper), 202)

    mut_helper = ("fn f1(v0:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
                  "block b0(v0:mutbuf)\n  v1:u8 = const() {\"value\":99}\n"
                  "  _ = buffer.fill(v0,v1)\n  v2:u32 = const() {\"value\":0}\n  ret(v2)\nend\n")
    b = Body(); view = b.value("mutbuf", "borrow.mut", ["v1"])
    result = b.value("u32", "call", [view], {"function": "f1"}); b.effect("loan.end", [view])
    add("call-local-mutable", _finish(b, result, mut_helper), 0, bytes([99]) * 8)

    source = _program("""  v3:mutbuf = borrow.mut(v1)
  v4:readbuf = borrow.read(v3)
  jump b1(v4,v1,v3)
block b1(v5:readbuf,v6:mutbuf,v7:mutbuf)
  v8:usize = const() {"value":0}
  v9:u8 = buffer.load(v5,v8)
  _ = loan.end(v5)
  _ = loan.end(v7)
  v10:u32 = int.cast(v9) {"mode":"wrap"}
  ret(v10)
""")
    add("nested-graph-through-permuted-edge", source, 31)

    source = _program("""  jump b2(v1)
block b1(v3:mutbuf,v4:mutbuf)
  _ = loan.end(v4)
  v5:u32 = const() {"value":17}
  ret(v5)
block b2(v6:mutbuf)
  v7:mutbuf = borrow.mut(v6)
  v8:u8 = const() {"value":77}
  _ = buffer.fill(v7,v8)
  jump b1(v6,v7)
""")
    add("incoming-from-later-source-block", source, 17, bytes([77]) * 8)

    branch = _program("""  v3:mutbuf = borrow.mut(v1)
  v4:usize = const() {"value":0}
  v5:u8 = buffer.load(v0,v4)
  v6:u8 = const() {"value":0}
  v7:bool = compare.eq(v5,v6)
  branch v7 b1(v1,v3) b2(v1,v3)
block b1(v8:mutbuf,v9:mutbuf)
  v10:u8 = const() {"value":77}
  _ = buffer.fill(v9,v10)
  jump b3(v8,v9)
block b2(v11:mutbuf,v12:mutbuf)
  v13:u8 = const() {"value":88}
  _ = buffer.fill(v12,v13)
  jump b3(v11,v12)
block b3(v14:mutbuf,v15:mutbuf)
  _ = loan.end(v15)
  v16:u32 = const() {"value":0}
  ret(v16)
""")
    for value in (0, 1):
        add("matching-join-arm-" + str(value), branch, 0,
            bytes([77 if value == 0 else 88]) * 8, bytes([value]) + INPUT[1:])

    source = _program("""  v3:mutbuf = borrow.mut(v1)
  v4:usize = const() {"value":0}
  v5:usize = const() {"value":4}
  jump b1(v1,v3,v4,v5)
block b1(v6:mutbuf,v7:mutbuf,v8:usize,v9:usize)
  v10:bool = compare.lt(v8,v9)
  branch v10 b2(v6,v7,v8,v9) b3(v6,v7)
block b2(v11:mutbuf,v12:mutbuf,v13:usize,v14:usize)
  v15:u8 = int.cast(v13) {"mode":"wrap"}
  _ = buffer.store(v12,v13,v15)
  v16:usize = const() {"value":1}
  v17:usize = int.add.wrap(v13,v16)
  jump b1(v11,v12,v17,v14)
block b3(v18:mutbuf,v19:mutbuf)
  _ = loan.end(v19)
  v20:u32 = const() {"value":4}
  ret(v20)
""")
    add("loan-through-loop-backedge", source, 4, bytes([0, 1, 2, 3]) + OUTPUT[4:])

    arguments = ["v3"] + ["v4"] * 14 + ["v1"]
    params = ["v5:mutbuf"] + [f"v{i}:usize" for i in range(6, 20)] + ["v20:mutbuf"]
    source = _program("  v3:mutbuf = borrow.mut(v1)\n  v4:usize = const() {\"value\":7}\n"
                      "  jump b1(" + ",".join(arguments) + ")\nblock b1(" + ",".join(params) + ")\n"
                      "  _ = loan.end(v5)\n  v21:u32 = const() {\"value\":0}\n  ret(v21)\n")
    add("root-parent-index-fifteen", source, 0)
    source = _program('  v2047:readbuf = borrow.read(v0)\n'
                      '  v3:usize = const() {"value":2}\n'
                      '  v4:u8 = buffer.load(v2047,v3)\n  _ = loan.end(v2047)\n'
                      '  v5:u32 = int.cast(v4) {"mode":"wrap"}\n  ret(v5)\n')
    add("loan-result-ssa-2047", source, 103)
    return rows


def loan_refusals():
    result = {}
    tail = '  v90:u32 = const() {"value":0}\n  ret(v90)\n'

    def add(name, body, suffix=""):
        result[name] = _program(body + tail, suffix)

    add("end-external-read", "  _ = loan.end(v0)\n")
    add("end-external-mutable", "  _ = loan.end(v1)\n")
    add("exclusive-from-readonly", "  v3:mutbuf = borrow.mut(v0)\n  _ = loan.end(v3)\n")
    add("shared-result-permission", "  v3:mutbuf = borrow.read(v0)\n  _ = loan.end(v3)\n")
    add("exclusive-result-permission", "  v3:readbuf = borrow.mut(v1)\n  _ = loan.end(v3)\n")
    add("borrow-scalar", '  v3:u32 = const() {"value":1}\n  v4:readbuf = borrow.read(v3)\n  _ = loan.end(v4)\n')
    add("borrow-no-result", "  _ = borrow.read(v0)\n")
    add("borrow-short-arity", "  v3:readbuf = borrow.read()\n  _ = loan.end(v3)\n")
    add("borrow-long-arity", "  v3:readbuf = borrow.read(v0,v0)\n  _ = loan.end(v3)\n")
    add("borrow-unexpected-attribute", '  v3:readbuf = borrow.read(v0) {"value":0}\n  _ = loan.end(v3)\n')
    add("end-unexpected-result", "  v3:readbuf = borrow.read(v0)\n  v4:u32 = loan.end(v3)\n")
    add("end-short-arity", "  _ = loan.end()\n")
    add("end-long-arity", "  v3:readbuf = borrow.read(v0)\n  _ = loan.end(v3,v3)\n")
    add("end-scalar", '  v3:u32 = const() {"value":0}\n  _ = loan.end(v3)\n')
    add("live-local-at-return", "  v3:readbuf = borrow.read(v0)\n")
    add("double-end", "  v3:readbuf = borrow.read(v0)\n  _ = loan.end(v3)\n  _ = loan.end(v3)\n")
    add("end-parent-before-child", "  v3:readbuf = borrow.read(v0)\n  v4:readbuf = borrow.read(v3)\n  _ = loan.end(v3)\n  _ = loan.end(v4)\n")
    for op in ("buffer.load", "buffer.len", "borrow.read"):
        body = "  v3:readbuf = borrow.read(v0)\n  _ = loan.end(v3)\n"
        if op == "buffer.load": body += '  v4:usize = const() {"value":0}\n  v5:u8 = buffer.load(v3,v4)\n'
        elif op == "buffer.len": body += "  v5:usize = buffer.len(v3)\n"
        else: body += "  v5:readbuf = borrow.read(v3)\n  _ = loan.end(v5)\n"
        add("consumed-" + op, body)
    for first, second in (("mut", "mut"), ("read", "mut"), ("mut", "read")):
        typ = lambda kind: "mutbuf" if kind == "mut" else "readbuf"
        add("conflicting-" + first + "-" + second,
            f"  v3:{typ(first)} = borrow.{first}(v1)\n  v4:{typ(second)} = borrow.{second}(v1)\n"
            "  _ = loan.end(v4)\n  _ = loan.end(v3)\n")
    prefix = ('  v3:mutbuf = borrow.mut(v1)\n  v4:usize = const() {"value":0}\n'
              '  v5:u8 = const() {"value":17}\n')
    suspended = {"load": "  v6:u8 = buffer.load(v1,v4)\n",
                 "store": "  _ = buffer.store(v1,v4,v5)\n",
                 "swap": "  _ = buffer.swap(v1,v4,v4)\n",
                 "fill": "  _ = buffer.fill(v1,v5)\n",
                 "fill-range": "  _ = buffer.fill_range(v1,v4,v4,v5)\n",
                 "move": "  _ = buffer.move_within(v1,v4,v4,v4)\n",
                 "copy": "  _ = buffer.copy(v1,v0,v4)\n"}
    for name, statement in suspended.items():
        add("suspended-parent-" + name, prefix + statement + "  _ = loan.end(v3)\n")
    helper = ("fn f1(v0:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\n"
              "block b0(v0:mutbuf)\n  v1:u32 = const() {\"value\":0}\n  ret(v1)\nend\n")
    add("suspended-parent-call", prefix + '  v6:u32 = call(v1) {"function":"f1"}\n  _ = loan.end(v3)\n', helper)
    add("consumed-call", prefix + '  _ = loan.end(v3)\n  v6:u32 = call(v3) {"function":"f1"}\n', helper)

    result["edge-drops-local"] = _program("  v3:readbuf = borrow.read(v0)\n  jump b1(v0)\n"
        "block b1(v4:readbuf)\n" + tail)
    result["edge-drops-parent"] = _program("  v3:readbuf = borrow.read(v0)\n  jump b1(v3)\n"
        "block b1(v4:readbuf)\n  _ = loan.end(v4)\n" + tail)
    result["edge-duplicates-child"] = _program("  v3:readbuf = borrow.read(v0)\n  jump b1(v0,v3,v3)\n"
        "block b1(v4:readbuf,v5:readbuf,v6:readbuf)\n  _ = loan.end(v6)\n  _ = loan.end(v5)\n" + tail)
    result["merge-disagrees-root"] = _program("""  v3:bool = const() {"value":true}
  branch v3 b1(v1,v2) b2(v1,v2)
block b1(v4:mutbuf,v5:mutbuf)
  v6:readbuf = borrow.read(v4)
  jump b3(v4,v5,v6)
block b2(v7:mutbuf,v8:mutbuf)
  v9:readbuf = borrow.read(v8)
  jump b3(v7,v8,v9)
block b3(v10:mutbuf,v11:mutbuf,v12:readbuf)
  _ = loan.end(v12)
""" + tail)
    result["merge-disagrees-parent"] = _program("""  v3:bool = const() {"value":true}
  branch v3 b1(v1) b2(v1)
block b1(v4:mutbuf)
  v5:readbuf = borrow.read(v4)
  v6:readbuf = borrow.read(v5)
  jump b3(v4,v5,v6)
block b2(v7:mutbuf)
  v8:readbuf = borrow.read(v7)
  v9:readbuf = borrow.read(v7)
  jump b3(v7,v8,v9)
block b3(v10:mutbuf,v11:readbuf,v12:readbuf)
  _ = loan.end(v12)
  _ = loan.end(v11)
""" + tail)
    loop = next(case["source"] for case in loan_cases() if case["id"] == "loan-through-loop-backedge")
    result["backedge-duplicates-resource"] = loop.replace("jump b1(v11,v12,v17,v14)", "jump b1(v12,v12,v17,v14)").encode()
    result["loan-result-redefines-source"] = _program("  v0:readbuf = borrow.read(v0)\n  _ = loan.end(v0)\n" + tail)
    return result


def loan_profile_refusals():
    """Valid general Core whose resource results exceed the native SSA ceiling."""
    rows = {}
    for kind, typ, parent in (("read", "readbuf", "v0"), ("mut", "mutbuf", "v1")):
        for index in (2048, 8192, 2**64 - 1):
            rows[kind + "-ssa-" + str(index)] = _program(
                f"  v{index}:{typ} = borrow.{kind}({parent})\n  _ = loan.end(v{index})\n"
                '  v3:u32 = const() {"value":0}\n  ret(v3)\n')
    return rows


def reference_source(case):
    b = Body(0); owners, loans = [], []
    for initial in (bytes.fromhex(case["source_hex"]), bytes.fromhex(case["initial_hex"]), b""):
        owner = b.value("buffer", "buffer.new", [b.const("usize", len(initial))])
        view = b.value("mutbuf", "borrow.mut", [owner])
        # Core buffer.new yields zeroed storage. Materialize every nonzero
        # input byte exactly, coalescing only equal adjacent bytes. This keeps
        # the target program and all observations unchanged while avoiding
        # hundreds of redundant wrapper SSA definitions per large fixture.
        i = 0
        while i < len(initial):
            end = i + 1
            while end < len(initial) and initial[end] == initial[i]:
                end += 1
            value = initial[i]
            if value:
                if end - i >= 3:
                    b.effect("buffer.fill_range", [view, b.const("usize", i),
                        b.const("usize", end - i), b.const("u8", value)])
                else:
                    for index in range(i, end):
                        b.effect("buffer.store", [view, b.const("usize", index), b.const("u8", value)])
            i = end
        owners.append(owner); loans.append(view)
    b.effect("loan.end", [loans[0]])
    loans[0] = b.value("readbuf", "borrow.read", [owners[0]])
    result = b.value("u32", "call", loans, {"function": "f0"})
    values = [result] + [b.value("u8", "buffer.load", [loans[1], b.const("usize", i)])
                         for i in range(len(bytes.fromhex(case["initial_hex"])))]
    for view in loans: b.effect("loan.end", [view])
    for owner in owners: b.effect("owner.drop", [owner])
    returns = ["u32"] + ["u8"] * (len(values) - 1)
    wrapper = ("hia-asm.v1 hepta.hia.program.v8 loan_reference\nfn reference_entry() -> ("
               + ",".join(returns) + ") effects(alloc,read,write,trap) entry(b0)\nblock b0()\n"
               + b.text() + "  ret(" + ",".join(values) + ")\nend\n")
    return (wrapper + case["source"].split("\n", 1)[1]).encode()


def independent_loan_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    cases, rejected, outside_profile = [], [], []
    for case in loan_cases():
        source = reference_source(case)
        actual = execute_program(assemble_program(source), "reference_entry", [])
        expected = [case["expected_result"], *bytes.fromhex(case["expected_hex"])]
        if actual["status"] != "returned" or actual["values"] != expected:
            raise AssertionError((case["id"], expected, actual))
        cases.append({**case, "reference_source": source.decode(), "reference_result": actual})
    for name, source in loan_refusals().items():
        try: assemble_program(source)
        except HIAProgramRejected as exc:
            rejected.append({"id": name, "source": source.decode(), "code": exc.code, "message": str(exc)})
        else: raise AssertionError("independent Core admitted " + name)
    for name, source in loan_profile_refusals().items():
        checked = assemble_program(source)
        outside_profile.append({"id": name, "source": source.decode(), "core_sha256": checked.sha256,
                                "general_core": "accepted", "native_profile": "rejected"})
    return {"cases": cases, "rejected": rejected, "outside_profile": outside_profile, "before_B0": True,
            "claims": {"all_input_proof": False, "owned_resources_supported": False,
                       "returned_loans_supported": True}}


def qualify_loans(directory, compilers, checks, reference):
    from tools.qualify_hia_selfhost import INVALID, compile_stage, digest, inspect_selfhost_object, invoke
    observations = []
    for label, compiler in compilers:
        for case in reference["cases"]:
            name = label + "-loan-" + case["id"]
            image, build = compile_stage(directory, name + "-build", compiler, case["source"].encode())
            initial = bytes.fromhex(case["initial_hex"])
            result, output = invoke(directory, name, image, bytes.fromhex(case["source_hex"]),
                                    capacity=len(initial), workspace_size=0,
                                    output_initial=initial, observe_trap_writes=True)
            checks[name] = bool(result.get("status") == "returned" and result.get("abi_status") == 0
                and result.get("core_u32") == case["expected_result"] and result.get("source_unchanged")
                and not result.get("forbidden_compiler_modules_loaded")
                and result.get("shared_output_observation", {}).get("available")
                and output.hex() == case["expected_hex"])
            observations.append({"case": name, "build": build, "execution": result,
                                 "actual_hex": output.hex(), "expected_hex": case["expected_hex"]})
        for name, source in {**loan_refusals(), **loan_profile_refusals()}.items():
            result, output = invoke(directory, label + "-loan-reject-" + name, compiler, source, capacity=512)
            checks[label + "-loan-reject-" + name] = bool(result.get("status") == "returned"
                and result.get("core_u32") == INVALID and result.get("source_unchanged")
                and result.get("output_unchanged") and output == bytes([0xa5]) * 512)
            observations.append(result)
        for case_name in ("shared-depth-8", "nested-mutable", "loan-through-loop-backedge"):
            source = next(case["source"].encode() for case in reference["cases"] if case["id"] == case_name)
            name = label + "-loan-object-" + case_name
            flat, flat_receipt = compile_stage(directory, name + "-flat", compiler, source)
            obj, obj_receipt = compile_stage(directory, name + "-object", compiler,
                source.replace(b"v8 selfhost\n", b"v8 selfhost_elf\n", 1), output_extension=".o")
            inspection = inspect_selfhost_object(obj.read_bytes())
            checks[name] = inspection["text_sha256"] == digest(flat.read_bytes())
            observations.append({"flat": flat_receipt, "object": obj_receipt, "inspection": inspection})
    return observations
