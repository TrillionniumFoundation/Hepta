"""Explicit-trap and assembly-wire witnesses for native Selfhost-Core.

General Core supplies trap-code observations before B0. Native code retains
only the existing UD2 process outcome, with real shared-output observations.
Line-budget witnesses compare the independent frontend's byte limits directly.
"""
from __future__ import annotations

from hashlib import sha256

from tools.hia_selfhost_cases import HEADER
from tools.hia_selfhost_limits import MAX_LINE_BYTES, MAX_SOURCE_LINES

TRAP_CODES = ("user", "overflow", "division_by_zero", "bounds", "allocation")


def trap_fixtures():
    rows = []
    for code in TRAP_CODES:
        for prior in (False, True):
            for shape in ("direct", "call"):
                source = HEADER + ('  v3:usize = const() {"value":0}\n'
                    '  v4:u8 = const() {"value":99}\n')
                if prior:
                    source += '  _ = buffer.store(v1,v3,v4)\n'
                if shape == "direct":
                    source += f'  trap {code}\nend\n'
                else:
                    source += ('  v5:u8 = buffer.load(v0,v3)\n'
                        '  v6:u8 = const() {"value":0}\n'
                        '  v7:bool = compare.ne(v5,v6)\n'
                        '  v8:u32 = call(v7) {"function":"f1"}\n'
                        '  v9:usize = const() {"value":1}\n'
                        '  v10:u8 = const() {"value":77}\n'
                        '  _ = buffer.store(v1,v9,v10)\n'
                        '  ret(v8)\nend\n'
                        'fn f1(v0:bool) -> (u32) effects(read,write,trap) entry(b0)\n'
                        'block b0(v0:bool)\n'
                        '  branch v0 b1() b2()\nblock b1()\n'
                        f'  trap {code}\nblock b2()\n'
                        '  v1:u32 = const() {"value":7}\n  ret(v1)\nend\n')
                for taken in ((True,) if shape == "direct" else (False, True)):
                    expected = bytearray([0xa5] * 8)
                    if prior:
                        expected[0] = 99
                    if not taken:
                        expected[1] = 77
                    rows.append({"case": f"trap-{code}-{shape}-{int(prior)}-{int(taken)}",
                        "source": source.encode(), "input": bytes([int(taken)]) if shape == "call" else b"",
                        "code": code, "shape": shape, "prior_store": prior,
                        "taken": taken, "expected_output": bytes(expected)})
    return rows


def trap_refusals():
    base = (HEADER + '  trap user\nend\n').encode()
    result = {name: base.replace(b"trap user", term) for name, term in (
        ("unknown-code", b"trap imaginary"), ("wrong-keyword-code", b"trap wrap"),
        ("quoted-code", b'trap "user"'), ("missing-code", b"trap"),
        ("extra-code", b"trap user bounds"), ("parenthesized-code", b"trap(user)"),
        ("missing-separator", b"trapuser"), ("numeric-code", b"trap 1"),
        ("instruction-after-trap", b'trap user\n  v3:u32 = const() {"value":7}'))}
    # A trap in place of the immediate return cannot authorize self-tail lowering.
    result["self-call-then-trap"] = (HEADER +
        '  v3:u32 = call(v0,v1,v2) {"function":"f0"}\n  trap user\nend\n').encode()
    return result


def wire_fixtures():
    base = (HEADER + '  v3:u32 = const() {"value":7}\n  ret(v3)\nend\n').encode()
    lines = base.split(b"\n")
    rows = []
    for where, index in (("header", 0), ("instruction", 3), ("end", 5), ("trailing", 6)):
        for over in (False, True):
            limit = MAX_LINE_BYTES + int(over)
            padded = list(lines)
            padded[index] = b" " * (limit - len(padded[index])) + padded[index]
            rows.append({"case": f"wire-{where}-{limit}", "source": b"\n".join(padded),
                "accepted": not over, "failure_code": 62 if over else 0,
                "expected_line_bytes": limit})
    # The native grammar already rejects interior empty lines. This witness
    # specifically tests the preflight's line ceiling before grammar parsing.
    over_lines = base + b"\n" * (MAX_SOURCE_LINES + 1 - len(lines))
    assert len(over_lines.split(b"\n")) == MAX_SOURCE_LINES + 1
    rows.append({"case": f"wire-lines-{MAX_SOURCE_LINES + 1}", "source": over_lines,
                 "accepted": False, "failure_code": 63,
                 "expected_lines": MAX_SOURCE_LINES + 1})
    return rows


def _owned_reference(source, data):
    """Add owned buffers around unchanged borrowed functions for the Core VM."""
    from hepta.hia_agent_assembly import assemble_program
    doc = assemble_program(source).as_dict()
    ops, serial = [], 0

    def op(code, args=(), typ=None, **attrs):
        nonlocal serial
        name = f"v{serial}" if typ else None
        serial += int(typ is not None)
        ops.append({"op": code, "args": list(args), "out": [{"name": name, "type": typ}] if typ else [],
                    "attrs": attrs})
        return name

    owners, loans = [], []
    for initial in (data, bytes([0xa5]) * 8, b""):
        length = op("const", typ="usize", value=len(initial))
        owner = op("buffer.new", [length], "buffer")
        loan = op("borrow.mut", [owner], "mutbuf")
        for index, value in enumerate(initial):
            offset = op("const", typ="usize", value=index)
            byte = op("const", typ="u8", value=value)
            op("buffer.store", [loan, offset, byte])
        owners.append(owner)
        loans.append(loan)
    op("loan.end", [loans[0]])
    loans[0] = op("borrow.read", [owners[0]], "readbuf")
    returned = [op("call", loans, "u32", function="f0")]
    for index in range(8):
        offset = op("const", typ="usize", value=index)
        returned.append(op("buffer.load", [loans[1], offset], "u8"))
    for loan in loans:
        op("loan.end", [loan])
    for owner in owners:
        op("owner.drop", [owner])
    doc["functions"].append({"name": "reference", "params": [], "returns": ["u32"] + ["u8"] * 8,
        "effects": ["alloc", "read", "write", "trap"], "entry": "entry",
        "blocks": [{"id": "entry", "params": [], "ops": ops,
                    "term": {"op": "ret", "values": returned}}]})
    return doc


def independent_control_reference():
    from hepta.hia_agent_assembly import assemble_program, MAX_LINE_BYTES as FRONTEND_LINE_BYTES
    from hepta.hia_agent_assembly import MAX_LINES as FRONTEND_LINES
    from hepta.hia_opcodes import TRAP_CODES as CORE_TRAP_CODES
    from hepta.hia_program import HIAProgramRejected, execute_program
    from hepta.hia_program_runtime import HIAProgramTrap
    assert set(TRAP_CODES) == set(CORE_TRAP_CODES)
    assert MAX_LINE_BYTES == FRONTEND_LINE_BYTES and MAX_SOURCE_LINES == FRONTEND_LINES
    traps, refused, wire = [], [], []
    for fixture in trap_fixtures():
        checked = assemble_program(fixture["source"])
        try:
            observed = execute_program(_owned_reference(fixture["source"], fixture["input"]), "reference", [])
        except HIAProgramTrap as exc:
            observed = {"status": "trapped", "trap": exc.code, "report": exc.report}
        if fixture["taken"]:
            assert observed["status"] == "trapped" and observed["trap"] == fixture["code"], observed
        else:
            assert observed["status"] == "returned" and observed["result"] == [7, *fixture["expected_output"]], observed
        traps.append({key: value for key, value in fixture.items() if not isinstance(value, bytes)} |
            {"source_sha256": sha256(fixture["source"]).hexdigest(), "core_sha256": checked.sha256,
             "input_hex": fixture["input"].hex(), "expected_output_hex": fixture["expected_output"].hex(),
             "reference_result": observed,
             "reference_change": "add owned buffer wrapper; retain original borrowed functions unchanged"})
    for name, source in trap_refusals().items():
        try:
            assemble_program(source)
        except HIAProgramRejected as exc:
            observed = {"status": "rejected", "code": exc.code}
        else:
            observed = {"status": "accepted"}
        assert observed["status"] == ("accepted" if name == "self-call-then-trap" else "rejected"), (name, observed)
        refused.append({"case": name, "source_sha256": sha256(source).hexdigest(), "reference_result": observed})
    for fixture in wire_fixtures():
        try:
            checked = assemble_program(fixture["source"])
        except HIAProgramRejected as exc:
            observed = {"status": "rejected", "code": exc.code}
        else:
            doc = checked.as_dict()
            doc["functions"][0]["params"] = []
            doc["functions"][0]["blocks"][0]["params"] = []
            observed = execute_program(doc, "f0", [])
        assert observed["status"] == ("returned" if fixture["accepted"] else "rejected"), (fixture, observed)
        if fixture["accepted"]:
            assert observed["result"] == 7
        else:
            assert observed["code"] == "E_HIA_ASSEMBLY_LIMIT"
        wire.append({key: value for key, value in fixture.items() if not isinstance(value, bytes)} |
            {"source_sha256": sha256(fixture["source"]).hexdigest(), "reference_result": observed})
    return {"traps": traps, "refusals": refused, "wire": wire,
        "scope": "Core VM identifies trap code; native flat ABI exposes UD2 and observed output bytes only"}


def qualify_control(directory, compilers, checks, reference):
    from tools.qualify_hia_selfhost import INVALID, compile_stage, invoke
    observations = []
    references = {row["case"]: row for row in reference["traps"]}
    for label, compiler in compilers:
        for fixture in trap_fixtures():
            name = label + "-" + fixture["case"]
            image, build = compile_stage(directory, name + "-code", compiler, fixture["source"])
            run, output = invoke(directory, name, image, fixture["input"], capacity=8, workspace_size=0,
                                 observe_trap_writes=True)
            correct = (run.get("status") == "child_failed" and run.get("returncode") == -4
                if fixture["taken"] else run.get("status") == "returned" and run.get("core_u32") == 7)
            checks[name] = bool(correct and run.get("shared_output_observation", {}).get("available")
                                and output == fixture["expected_output"])
            observations.append({"case": name, "kind": "explicit_trap", "build": build, "execution": run,
                "code": fixture["code"], "taken": fixture["taken"], "prior_store": fixture["prior_store"],
                "observed_output_hex": output.hex(), "expected_output_hex": fixture["expected_output"].hex(),
                "reference_core_sha256": references[fixture["case"]]["core_sha256"]})
        for name, source in trap_refusals().items():
            case = label + "-trap-reject-" + name
            run, _ = invoke(directory, case, compiler, source, capacity=512)
            checks[case] = (run.get("status") == "returned" and run.get("core_u32") == INVALID
                and run.get("output_unchanged") and run.get("source_unchanged"))
            observations.append({"case": case, "kind": "rejected_trap", "execution": run})
        for fixture in wire_fixtures():
            case = label + "-" + fixture["case"]
            if fixture["accepted"]:
                image, build = compile_stage(directory, case + "-code", compiler, fixture["source"])
                run, _ = invoke(directory, case, image, b"", capacity=0, workspace_size=0)
                checks[case] = run.get("status") == "returned" and run.get("core_u32") == 7
                observations.append({"case": case, "kind": "wire_accepted", "build": build, "execution": run})
            else:
                run, _ = invoke(directory, case, compiler, fixture["source"], capacity=512, workspace_fill=0xa7)
                checks[case] = (run.get("status") == "returned" and run.get("core_u32") == INVALID
                    and run.get("output_unchanged") and run.get("source_unchanged")
                    and run.get("workspace_header", {}).get("40") == fixture["failure_code"])
                observations.append({"case": case, "kind": "wire_rejected", "execution": run})
    return observations

