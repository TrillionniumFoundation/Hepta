"""Independent byte/range witnesses for the native borrowed bulk operations.

These are finite observations. The general Core VM executes each unchanged
borrowed body through its own allocated-owner wrapper before B0 is built.
Native compiler generations use the ordinary assembly interface and preserve
the entire output, including observable writes made before a later bounds trap.
"""
from __future__ import annotations

from tools.hia_selfhost_cases import HEADER

BULK_OPS = ("buffer.fill", "buffer.copy", "buffer.fill_range",
            "buffer.copy_range", "buffer.move_within")
MAX = (1 << 64) - 1


def bulk_source(op, values, *, prior_store=False):
    """Only fixture assembly, with no alternate parsing or machine emission."""
    kinds = {
        "buffer.fill": ("u8",),
        "buffer.copy": ("usize",),
        "buffer.fill_range": ("usize", "usize", "u8"),
        "buffer.copy_range": ("usize", "usize", "usize"),
        "buffer.move_within": ("usize", "usize", "usize"),
    }[op]
    if len(values) != len(kinds):
        raise ValueError("invalid bulk fixture arguments")
    lines, args = [HEADER], ["v1"]
    if op in {"buffer.copy", "buffer.copy_range"}:
        args.append("v0")
    for i, (kind, value) in enumerate(zip(kinds, values), 3):
        lines.append(f'  v{i}:{kind} = const() {{"value":{value}}}\n')
        args.append(f"v{i}")
    if prior_store:
        lines += ['  v20:usize = const() {"value":0}\n',
                  '  v21:u8 = const() {"value":99}\n',
                  '  _ = buffer.store(v1,v20,v21)\n']
    lines += [f"  _ = {op}({','.join(args)})\n",
              '  v22:u32 = const() {"value":0}\n  ret(v22)\nend\n']
    return "".join(lines).encode()


def bulk_oracle(op, values, source, initial, *, prior_store=False):
    """Mathematical range checks precede slice writes; Python ints do not wrap."""
    output = bytearray(initial)
    if prior_store:
        if not output:
            raise ValueError("observer control requires a nonempty destination")
        output[0] = 99
    extent, src_extent = len(output), len(source)
    if op == "buffer.fill":
        offset, size, value = 0, extent, values[0]
        bad = False
    elif op == "buffer.fill_range":
        offset, size, value = values
        bad = offset > extent or size > extent - offset
    elif op == "buffer.copy":
        dst, src, size = 0, 0, values[0]
        bad = size > extent or size > src_extent
    else:
        dst, src, size = values
        if op == "buffer.move_within":
            src_extent = extent
        bad = (dst > extent or size > extent - dst
               or src > src_extent or size > src_extent - src)
    if not bad:
        if op in {"buffer.fill", "buffer.fill_range"}:
            output[offset:offset + size] = bytes([value]) * size
        else:
            # The temporary snapshot defines overlap semantics independently
            # of the native direction choice and its byte-at-a-time loops.
            snapshot = bytes(output) if op == "buffer.move_within" else source
            output[dst:dst + size] = snapshot[src:src + size]
    return bad, bytes(output)


def bulk_cases():
    rows = []
    source = bytes([0x13, 0xe7, 0x00, 0xff, 0x81, 0x45, 0x2a, 0x6c,
                    0x99, 0x02, 0x77, 0x1b, 0x4e, 0xa0, 0x39, 0x5d])
    initial = bytes(range(16))

    def add(op, label, values, data=source, output=initial, *, prior=False):
        trap, expected = bulk_oracle(op, values, data, output, prior_store=prior)
        rows.append({"id": op + "-" + label, "opcode": op, "arguments": list(values),
                     "input_hex": data.hex(), "initial_hex": output.hex(),
                     "trap": trap, "expected_hex": expected.hex(), "prior_store": prior})

    for size in (0, 1, 8, 16):
        add("buffer.fill", "extent-" + str(size), (0xa6,), output=initial[:size])
    for value in (0, 255):
        add("buffer.fill", "byte-" + str(value), (value,))
    for i, (offset, size) in enumerate(((0, 0), (16, 0), (3, 7), (0, 16),
            (15, 1), (17, 0), (MAX, 0), (15, 2), (1, MAX), (MAX, MAX), (0, MAX))):
        add("buffer.fill_range", str(i), (offset, size, 0xd3))
    add("buffer.fill_range", "empty", (0, 0, 99), data=b"", output=b"")
    add("buffer.fill_range", "prior-then-bad-size", (3, 14, 99), prior=True)
    add("buffer.fill_range", "prior-then-bad-offset", (17, 0, 99), prior=True)

    for label, dst_size, src_size, size in (
        ("empty", 0, 0, 0), ("empty-destination", 0, 8, 0),
        ("empty-source", 8, 0, 0), ("one", 1, 1, 1), ("full", 16, 16, 16),
        ("short-destination", 8, 16, 8), ("short-source", 16, 8, 8),
        ("bad-destination", 7, 16, 8), ("bad-source", 16, 7, 8),
        ("maximum-count", 16, 16, MAX)):
        add("buffer.copy", label, (size,), source[:src_size], initial[:dst_size])
    add("buffer.copy", "changed-runtime-source", (16,), bytes(reversed(source)))
    add("buffer.copy", "prior-then-bad-source", (9,), source[:8], prior=True)

    for i, values in enumerate(((0, 0, 0), (16, 16, 0), (2, 3, 7), (0, 0, 16),
            (15, 15, 1), (17, 0, 0), (0, 17, 0), (MAX, 0, 0), (0, MAX, 0),
            (15, 0, 2), (0, 15, 2), (1, 0, MAX), (0, 1, MAX), (MAX, MAX, MAX))):
        add("buffer.copy_range", str(i), values)
    add("buffer.copy_range", "empty", (0, 0, 0), b"", b"")
    add("buffer.copy_range", "prior-then-bad-source", (0, 15, 2), prior=True)
    add("buffer.copy_range", "prior-then-bad-destination", (15, 0, 2), prior=True)

    for label, values in (
        ("zero", (16, 16, 0)), ("equal", (0, 0, 16)),
        ("overlap-right", (3, 0, 12)), ("overlap-left", (0, 3, 12)),
        ("adjacent-right", (8, 0, 8)), ("adjacent-left", (0, 8, 8)),
        ("disjoint-right", (10, 1, 2)), ("disjoint-left", (1, 10, 2)),
        ("bad-destination-offset", (17, 0, 0)), ("bad-source-offset", (0, 17, 0)),
        ("bad-destination-range", (15, 0, 2)), ("bad-source-range", (0, 15, 2)),
        ("maximum-destination", (MAX, 0, 0)), ("maximum-source", (0, MAX, 0)),
        ("wrapped-destination", (1, 0, MAX)), ("wrapped-source", (0, 1, MAX))):
        add("buffer.move_within", label, values)
    add("buffer.move_within", "empty", (0, 0, 0), b"", b"")
    add("buffer.move_within", "changed-runtime-bytes", (3, 0, 12), output=source)
    add("buffer.move_within", "prior-then-bad-source", (0, 15, 2), prior=True)
    add("buffer.move_within", "prior-then-bad-destination", (15, 0, 2), prior=True)
    return rows


def bulk_refusals():
    rows = {}
    samples = {"buffer.fill": (42,), "buffer.copy": (4,),
               "buffer.fill_range": (0, 4, 42), "buffer.copy_range": (0, 0, 4),
               "buffer.move_within": (1, 0, 4)}
    for op, values in samples.items():
        source = bulk_source(op, values)
        line = next(line for line in source.splitlines() if b" = " + op.encode() + b"(" in line)
        args = line.split(b"(", 1)[1].rstrip(b")").split(b",")
        rows[op + "-readonly-destination"] = source.replace(op.encode() + b"(v1,", op.encode() + b"(v0,")
        rows[op + "-short-arity"] = source.replace(line, b"  _ = " + op.encode() + b"(" + b",".join(args[:-1]) + b")")
        rows[op + "-long-arity"] = source.replace(line, line[:-1] + b"," + args[-1] + b")")
        rows[op + "-result"] = source.replace(b"_ = " + op.encode(), b"v30:u32 = " + op.encode())
        rows[op + "-attributes"] = source.replace(line, line + b' {"mode":"wrap"}')
        rows[op + "-wrong-scalar-type"] = source.replace(b"v3:u8", b"v3:u64") if op == "buffer.fill" else source.replace(b"v3:usize", b"v3:u64")
        if op in {"buffer.copy", "buffer.copy_range"}:
            rows[op + "-mutable-source"] = source.replace(op.encode() + b"(v1,v0,", op.encode() + b"(v1,v2,")
            rows[op + "-same-buffer"] = source.replace(op.encode() + b"(v1,v0,", op.encode() + b"(v1,v1,")
        for i, kind in enumerate(("u8",) if op == "buffer.fill" else
                (("usize",) if op == "buffer.copy" else
                 (("usize", "usize", "u8") if op == "buffer.fill_range" else ("usize",) * 3)), 3):
            replacement = b"u32" if kind in {"usize", "u8"} else b"bool"
            rows[op + "-argument-type-" + str(i)] = source.replace(f"v{i}:{kind}".encode(), f"v{i}:".encode() + replacement)
    return rows


def reference_source(case):
    # This import is fixture authoring only. It is never present in successors.
    from tests.test_hia_selfhost_language_coverage import buffer_reference_source
    initial = bytes.fromhex(case["initial_hex"])
    return buffer_reference_source({
        "source": bulk_source(case["opcode"], case["arguments"], prior_store=case["prior_store"]),
        "input": bytes.fromhex(case["input_hex"]), "capacity": len(initial),
        "workspace_size": 0, "output_initial": initial,
    })


def language_fixtures():
    """Positive bulk cases in the complete opcode witness inventory."""
    fixtures = []
    for op in BULK_OPS:
        case = next(row for row in bulk_cases() if row["opcode"] == op and not row["trap"]
                    and len(bytes.fromhex(row["initial_hex"])) == 16
                    and row["expected_hex"] != row["initial_hex"])
        fixtures.append({"id": "bulk-" + case["id"], "kind": "buffer",
            "source": bulk_source(op, case["arguments"]), "input": bytes.fromhex(case["input_hex"]),
            "capacity": 16, "workspace_size": 0, "output_initial": bytes.fromhex(case["initial_hex"]),
            "expected_result": 0, "expected_output": bytes.fromhex(case["expected_hex"]),
            "case_ids": [case["id"]]})
    return fixtures


def independent_bulk_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    from hepta.hia_program_runtime import HIAProgramTrap
    observations, refusals = [], []
    for case in bulk_cases():
        source = reference_source(case)
        checked = assemble_program(source)
        try:
            result = execute_program(checked, "reference_entry", [])
        except HIAProgramTrap as exc:
            result = {"status": "trapped", "trap": exc.code, "message": str(exc)}
        if case["trap"]:
            good = result.get("status") == "trapped" and result.get("trap") == "bounds"
        else:
            expected = list(bytes.fromhex(case["expected_hex"]))
            # General Core returns a scalar for a one-value result tuple.
            expected_result = expected[0] if len(expected) == 1 else expected
            good = result.get("status") == "returned" and result.get("result") == expected_result
        if not good:
            raise AssertionError({"case": case, "reference": result})
        observations.append({**case, "reference_source": source.decode(),
                             "reference_core_sha256": checked.sha256, "reference_result": result})
    for name, source in bulk_refusals().items():
        try:
            assemble_program(source)
        except HIAProgramRejected as exc:
            refusals.append({"id": name, "code": exc.code, "message": str(exc)})
        else:
            raise AssertionError("general Core admitted bulk refusal " + name)
    return {"cases": observations, "rejections": refusals}


def qualify_bulk(directory, compilers, checks, reference):
    from tools.qualify_hia_selfhost import INVALID, compile_stage, invoke, inspect_selfhost_object, digest
    observations = []
    for label, compiler in compilers:
        for case in reference["cases"]:
            name = label + "-bulk-" + case["id"]
            source = bulk_source(case["opcode"], case["arguments"], prior_store=case["prior_store"])
            image, build = compile_stage(directory, name + "-build", compiler, source)
            initial = bytes.fromhex(case["initial_hex"])
            result, output = invoke(directory, name, image, bytes.fromhex(case["input_hex"]),
                capacity=len(initial), workspace_size=0, output_initial=initial, observe_trap_writes=True)
            witness = result.get("shared_output_observation", {})
            if case["trap"]:
                good = result.get("status") == "child_failed" and result.get("returncode") == -4
            else:
                good = (result.get("status") == "returned" and result.get("abi_status") == 0
                        and result.get("core_u32") == 0 and result.get("source_unchanged"))
            checks[name] = bool(good and witness.get("available") and output.hex() == case["expected_hex"])
            observations.append({"case": case["id"], "compiler": label, "build": build,
                "execution": result, "expected_hex": case["expected_hex"], "observed_hex": output.hex()})
        for op in BULK_OPS:
            case = next(row for row in reference["cases"] if row["opcode"] == op and not row["trap"] and len(bytes.fromhex(row["initial_hex"])) == 16)
            source = bulk_source(op, case["arguments"])
            stem = label + "-bulk-object-" + op
            flat, _ = compile_stage(directory, stem + "-flat", compiler, source)
            obj, build = compile_stage(directory, stem, compiler,
                source.replace(b"v8 selfhost\n", b"v8 selfhost_elf\n", 1), output_extension=".o")
            info = inspect_selfhost_object(obj.read_bytes())
            checks[stem] = info["text_sha256"] == digest(flat.read_bytes())
            observations.append({"case": stem, "build": build, "object_inspection": info})
        for name, source in bulk_refusals().items():
            result, _ = invoke(directory, label + "-bulk-reject-" + name, compiler, source, capacity=512)
            checks[label + "_bulk_reject_" + name] = bool(result.get("status") == "returned"
                and result.get("core_u32") == INVALID and result.get("output_unchanged")
                and result.get("source_unchanged"))
            observations.append(result)
    return observations
