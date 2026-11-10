"""Finite Core input/VM witnesses for four libc-bound owned-buffer operations."""
from __future__ import annotations

from tools.hia_selfhost_bulk import Body

HEADER = ("hia-asm.v1 hepta.hia.program.v8 selfhost_elf\n"
    "fn f0(v0:readbuf,v1:mutbuf,v2:mutbuf) -> (u32) effects(alloc,read,write,trap) entry(b0)\n"
    "block b0(v0:readbuf,v1:mutbuf,v2:mutbuf)\n")


def finish(body, result, suffix=""):
    return (HEADER + body.text() + f"  ret({result})\nend\n" + suffix).encode()


def multiple(body, types, opcode, arguments):
    outputs = ["v" + str(body.next + i) for i in range(len(types))]
    body.next += len(types)
    body.lines.append("  " + ",".join(name + ":" + typ for name, typ in zip(outputs, types)) +
                      " = " + opcode + "(" + ",".join(arguments) + ")\n")
    return outputs


def allocation_case(size, *, optional=False, prior=False):
    b = Body()
    if prior:
        b.effect("buffer.store", ["v1", b.const("usize", 0), b.const("u8", 99)])
    length = b.const("usize", size)
    if optional:
        owner, ok = multiple(b, ["buffer", "bool"], "buffer.try_new", [length])
    else:
        owner = b.value("buffer", "buffer.new", [length])
    extent = b.value("usize", "buffer.len", [owner])
    view = b.value("readbuf", "borrow.read", [owner])
    # The requested copy is itself runtime-bounded by the returned owner length.
    maximum = b.const("usize", 8)
    small = b.value("bool", "compare.lt", [extent, maximum])
    amount = b.value("usize", "select", [small, extent, maximum])
    b.effect("buffer.copy", ["v1", view, amount])
    b.effect("loan.end", [view]); b.effect("owner.drop", [owner])
    result = b.value("u32", "int.cast", [extent], {"mode": "wrap"})
    if optional:
        failure = b.const("u32", 0xffffffff)
        result = b.value("u32", "select", [ok, result, failure])
    return finish(b, result)


def cases():
    rows = []
    initial = bytes([0xa5]) * 8
    for optional in (False, True):
        for size in (0, 1, 8, 4096, 2097169):
            rows.append({"id": ("try" if optional else "new") + "-" + str(size),
                "source": allocation_case(size, optional=optional).decode(),
                "expected_result": size, "expected_output_hex": (bytes(min(size, 8)) + initial[min(size, 8):]).hex()})
    for size in (1 << 63, (1 << 64) - 1, 1 << 62):
        rows.append({"id": "try-failure-" + str(size), "source": allocation_case(size, optional=True).decode(),
            "expected_result": 0xffffffff, "expected_output_hex": initial.hex(),
            "vm_budget_expected": size == (1 << 62)})
    for prior in (False, True):
        rows.append({"id": "new-allocation-trap-" + str(int(prior)),
            "source": allocation_case(1 << 63, prior=prior).decode(), "expected_trap": "allocation",
            "expected_output_hex": ((bytes([99]) + initial[1:]) if prior else initial).hex()})
    b = Body(); length = b.const("usize", 8)
    owner = b.value("buffer", "buffer.new", [length]); moved = b.value("buffer", "owner.move", [owner])
    view = b.value("mutbuf", "borrow.mut", [moved]); b.effect("buffer.fill", [view, b.const("u8", 173)])
    b.effect("loan.end", [view]); read = b.value("readbuf", "borrow.read", [moved])
    b.effect("buffer.copy", ["v1", read, length]); b.effect("loan.end", [read]); b.effect("owner.drop", [moved])
    rows.append({"id": "move-nested-loan-and-drop", "source": finish(b, b.const("u32", 173)).decode(),
                 "expected_result": 173, "expected_output_hex": (bytes([173]) * 8).hex()})
    helper = ("fn f1(v0:buffer) -> (u32) effects(alloc,read,write,trap) entry(b0)\n"
              "block b0(v0:buffer)\n  v1:usize = buffer.len(v0)\n  _ = owner.drop(v0)\n"
              "  v2:u32 = int.cast(v1) {\"mode\":\"wrap\"}\n  ret(v2)\nend\n")
    b = Body(); owner = b.value("buffer", "buffer.new", [b.const("usize", 23)])
    result = b.value("u32", "call", [owner], {"function": "f1"})
    rows.append({"id": "owned-call-consumes-input", "source": finish(b, result, helper).decode(),
                 "expected_result": 23, "expected_output_hex": initial.hex()})
    return rows


def historical_refusals():
    source = allocation_case(8, optional=True)
    return {
        "flat-allocator-imports-refused": source.replace(b"v8 selfhost_elf\n", b"v8 selfhost\n", 1),
        "missing-alloc-effect": source.replace(b"effects(alloc,read,write,trap)", b"effects(read,write,trap)"),
        "missing-try-result": source.replace(b"v4:buffer,v5:bool", b"v4:buffer"),
        "swapped-try-result-types": source.replace(b"v4:buffer,v5:bool", b"v4:bool,v5:buffer"),
        "duplicate-try-result": source.replace(b"v4:buffer,v5:bool", b"v4:buffer,v4:bool"),
        "out-of-profile-owner-ssa": source.replace(b"v4", b"v8192"),
        "out-of-profile-bool-ssa": source.replace(b"v5", b"v8192"),
        "leaked-owner": source.replace(b"  _ = owner.drop(v4)\n", b""),
        "duplicate-owner-drop": source.replace(b"  _ = owner.drop(v4)\n", b"  _ = owner.drop(v4)\n  _ = owner.drop(v4)\n"),
        "drop-with-live-loan": source.replace(b"  _ = loan.end(v7)\n", b"").replace(
            b"  _ = owner.drop(v4)\n", b"  _ = owner.drop(v4)\n  _ = loan.end(v7)\n"),
        "direct-owner-memory-access": source.replace(b"buffer.copy(v1,v7,", b"buffer.copy(v1,v4,"),
    }


def reference(case):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine, _Owner, _View, HIAProgramTrap, HIAProgramBudgetExceeded
    checked = assemble_program(case["source"])
    machine = _Machine(checked, 10_000_000, 16 * 1024**2, None, 256)
    roots = [_Owner(-1, bytearray()), _Owner(-2, bytearray([0xa5] * 8)), _Owner(-3, bytearray())]
    arguments = [_View(roots[0], False), _View(roots[1], True), _View(roots[2], True)]
    function = next(fn for fn in checked.as_dict()["functions"] if fn["name"] == "f0")
    try:
        values = machine.invoke(function, arguments)
    except (HIAProgramTrap, HIAProgramBudgetExceeded) as error:
        status = "trapped" if isinstance(error, HIAProgramTrap) else "budget_exceeded"
        report = machine.report("f0", status, error=error)
    else:
        report = machine.report("f0", "returned", values=values)
        if machine.owners or machine.chains or machine.loans_started != machine.loans_ended:
            raise AssertionError("normal return leaves owned state")
    report["external_output_hex"] = roots[1].data.hex()
    report["external_bytes_are_separate_from_owned_heap_ledger"] = True
    if case.get("vm_budget_expected"):
        assert report["status"] == "budget_exceeded" and report["error"]["code"] == "heap", report
    elif "expected_trap" in case:
        assert report["status"] == "trapped" and report["error"]["code"] == case["expected_trap"], report
    else:
        assert report["status"] == "returned" and report["result"] == case["expected_result"], report
    assert report["external_output_hex"] == case["expected_output_hex"], report
    return report


def expanded_name_cases():
    from tools.hia_selfhost_names import core_observed_case
    return [core_observed_case(name, source) for name, source in historical_refusals().items()
            if name.startswith('out-of-profile-')]


def refusals():
    return {name: source for name, source in historical_refusals().items()
            if not (name.startswith('out-of-profile-'))}
