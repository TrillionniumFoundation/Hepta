"""Explicit Core trap terminators: HIA admission plus independent VM witnesses.

A trap is a terminal error path, not a normal return requiring owner cleanup.
Native UD2 is observed as SIGILL; this byte ABI does not return a trap-code word.
"""
from __future__ import annotations

SOURCE = r'''
def explicit_trap(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    require_effects(w, 8)
    next_token(s, w)
    separated(w)
    code = get(w, 8)
    if code < @allocation@ or code > @user@:
        return fail(w, 67)
    next_token(s, w)
    account_nodes(w, 3)
    emit_bytes(o, w, 2831, 2)
    return 0
'''

CODES = ("allocation", "bounds", "division_by_zero", "overflow", "user")


def cases():
    from tools.hia_selfhost_cases import HEADER
    rows = []
    store = ('  v3:usize = const() {"value":0}\n  v4:u8 = const() {"value":77}\n'
             '  _ = buffer.store(v1,v3,v4)\n')
    for code in CODES:
        for prior in (False, True):
            rows.append({"id": "explicit-" + code + "-" + str(int(prior)),
                "source": HEADER + (store if prior else "") + "  trap " + code + "\nend\n",
                "source_hex": "", "initial_hex": "a5" * 8,
                "expected_hex": ("4d" if prior else "a5") + "a5" * 7,
                "expected_trap": code, "owned_elf_only": False})
    branch = (HEADER + '  v3:usize = const() {"value":0}\n  v4:u8 = buffer.load(v0,v3)\n'
        '  v5:u8 = const() {"value":0}\n  v6:bool = compare.eq(v4,v5)\n'
        '  branch v6 b1(v1) b2(v1)\nblock b1(v7:mutbuf)\n'
        '  v8:u32 = const() {"value":7}\n  ret(v8)\nblock b2(v9:mutbuf)\n'
        '  v10:usize = const() {"value":0}\n  v11:u8 = const() {"value":77}\n'
        '  _ = buffer.store(v9,v10,v11)\n  trap user\nend\n')
    for value in (0, 1, 255):
        row = {"id": "explicit-branch-" + str(value), "source": branch,
            "source_hex": bytes([value]).hex(), "initial_hex": "a5" * 8,
            "expected_hex": ("4d" if value else "a5") + "a5" * 7, "owned_elf_only": False}
        row["expected_trap" if value else "expected_result"] = "user" if value else 7
        rows.append(row)
    call = (HEADER + '  v3:u32 = call(v1) {"function":"f1"}\n  ret(v3)\nend\n'
        'fn f1(v0:mutbuf) -> (u32) effects(read,write,trap) entry(b0)\nblock b0(v0:mutbuf)\n'
        '  v1:usize = const() {"value":0}\n  v2:u8 = const() {"value":77}\n'
        '  _ = buffer.store(v0,v1,v2)\n  trap bounds\nend\n')
    rows.append({"id": "explicit-scalar-callee", "source": call, "source_hex": "", "initial_hex": "a5"*8,
        "expected_hex": "4d" + "a5"*7, "expected_trap": "bounds", "owned_elf_only": False})
    void = (HEADER + '  _ = call() {"function":"f1"}\n  v3:u32 = const() {"value":0}\n'
        '  ret(v3)\nend\nfn f1() -> () effects(trap) entry(b0)\nblock b0()\n  trap overflow\nend\n')
    rows.append({"id": "explicit-void-callee", "source": void, "source_hex": "", "initial_hex": "a5"*8,
        "expected_hex": "a5"*8, "expected_trap": "overflow", "owned_elf_only": False})
    owned = HEADER.replace("v8 selfhost\n", "v8 selfhost_elf\n").replace(
        "effects(read,write,trap)", "effects(alloc,read,write,trap)")
    owned += (store + '  v5:usize = const() {"value":8}\n  v6:buffer = buffer.new(v5)\n'
        '  v7:mutbuf = borrow.mut(v6)\n  _ = buffer.fill(v7,v4)\n  trap allocation\nend\n')
    rows.append({"id": "explicit-live-owner-and-loan", "source": owned, "source_hex": "", "initial_hex": "a5"*8,
        "expected_hex": "4d" + "a5"*7, "expected_trap": "allocation", "owned_elf_only": True,
        "expected_live_owners": 1, "expected_live_loans": 1})
    return rows


def refusals():
    from tools.hia_selfhost_cases import HEADER
    base = HEADER + "  trap user\nend\n"
    return [{"id": name, "source": source} for name, source in {
        "explicit-unknown-code": base.replace("trap user", "trap unknown"),
        "explicit-missing-code": base.replace("trap user", "trap"),
        "explicit-quoted-code": base.replace("trap user", 'trap "user"'),
        "explicit-extra-code": base.replace("trap user", "trap user overflow"),
        "explicit-trailing-return": base.replace("trap user", 'trap user\n  v3:u32 = const() {"value":0}\n  ret(v3)'),
        "explicit-missing-trap-effect": base.replace("effects(read,write,trap)", "effects(read,write)"),
    }.items()]


def independent_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected
    from hepta.hia_program_runtime import _Machine, _Owner, _View, HIAProgramTrap
    accepted, rejected = [], []
    for case in cases():
        checked = assemble_program(case["source"].encode())
        machine = _Machine(checked, 1_000_000, 16 << 20, None, 256)
        # Privileged oracle harness for the same disjoint borrowed byte ABI as
        # the native caller; these are not fabricated public VM capabilities.
        roots = [_Owner(-1, bytearray.fromhex(case["source_hex"])),
                 _Owner(-2, bytearray.fromhex(case["initial_hex"])), _Owner(-3, bytearray())]
        arguments = [_View(roots[0], False), _View(roots[1], True), _View(roots[2], True)]
        entry = next(fn for fn in checked.as_dict()["functions"] if fn["name"] == "f0")
        try:
            values = machine.invoke(entry, arguments)
        except HIAProgramTrap as exc:
            result = machine.report("f0", "trapped", error=exc)
        else:
            result = machine.report("f0", "returned", values=values)
        if "expected_trap" in case:
            good = result["status"] == "trapped" and result["error"]["code"] == case["expected_trap"]
        else:
            good = result["status"] == "returned" and result["values"] == [case["expected_result"]]
        if (not good or roots[1].data.hex() != case["expected_hex"]
                or roots[0].data.hex() != case["source_hex"]
                or result["resources"]["live_owners"] != case.get("expected_live_owners", 0)
                or result["resources"]["live_local_loans"] != case.get("expected_live_loans", 0)):
            raise AssertionError({"case": case["id"], "result": result, "output_hex": roots[1].data.hex()})
        accepted.append({**case, "core_sha256": checked.sha256, "reference_result": result,
            "reference_output_hex": roots[1].data.hex()})
    for case in refusals():
        try:
            assemble_program(case["source"].encode())
        except HIAProgramRejected as exc:
            rejected.append({**case, "reference_result": {"status": "rejected", "code": exc.code}})
        else:
            raise AssertionError("invalid explicit trap accepted: " + case["id"])
    return {"cases": accepted, "refusals": rejected, "before_B0": True,
        "all_input_correctness_proved": False, "native_trap_code_word_returned": False}


def qualify(directory, compilers, checks, reference):
    from tools.qualify_hia_selfhost import compile_stage, invoke, observe_native_tool, INVALID, NO_SPACE
    from tools.qualify_hia_selfhost_owned_elf import inspect_owned_object
    from tools.qualify_hia_selfhost import inspect_selfhost_object
    observations = []
    for label, compiler in compilers:
        for case in reference["cases"]:
            prefix = label + "-" + case["id"]
            source = case["source"].encode()
            images = []
            if not case["owned_elf_only"]:
                image, receipt = compile_stage(directory, prefix + "-flat-build", compiler, source)
                images.append(("flat", image, "flat-x86-64")); observations.append(receipt)
                source = source.replace(b"v8 selfhost\n", b"v8 selfhost_elf\n", 1)
            obj, receipt = compile_stage(directory, prefix + "-elf-build", compiler, source, output_extension=".o")
            inspection = (inspect_owned_object if case["owned_elf_only"] else inspect_selfhost_object)(obj.read_bytes())
            observations.append({**receipt, "inspection": inspection})
            linked = directory / (prefix + ".so")
            args = ["-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack", "-z", "relro", "-z", "now", "--build-id=none", obj]
            if case["owned_elf_only"]: args.append("-lc")
            tool = observe_native_tool(directory, prefix + "-link", "ld", [*args, "-o", linked])
            if tool["returncode"]: raise AssertionError(tool)
            observations.append(tool); images.append(("elf", linked, "linked-selfhost"))
            short, _ = invoke(directory, prefix + "-short", compiler, source, capacity=receipt["produced_bytes"]-1)
            checks[prefix + "-short"] = bool(short.get("status") == "returned" and short.get("core_u32") == NO_SPACE
                and short.get("source_unchanged") and short.get("output_unchanged"))
            observations.append(short)
            for kind, image, image_format in images:
                name = prefix + "-" + kind
                result, output = invoke(directory, name, image, bytes.fromhex(case["source_hex"]),
                    image_format=image_format, capacity=8, workspace_size=0,
                    output_initial=bytes.fromhex(case["initial_hex"]), observe_trap_writes=True)
                good = (result.get("status") == "child_failed" and result.get("returncode") == -4
                        if "expected_trap" in case else result.get("status") == "returned"
                        and result.get("abi_status") == 0 and result.get("core_u32") == case["expected_result"]
                        and result.get("source_unchanged"))
                checks[name] = bool(good and output.hex() == case["expected_hex"])
                observations.append({"case": case["id"], "native": result, "actual_hex": output.hex()})
        for case in reference["refusals"]:
            name = label + "-reject-" + case["id"]
            result, output = invoke(directory, name, compiler, case["source"].encode(), capacity=512)
            checks[name] = bool(result.get("status") == "returned" and result.get("core_u32") == INVALID
                and result.get("source_unchanged") and result.get("output_unchanged") and output == b"\xa5" * 512)
            observations.append({"case": case["id"], "native": result})
    return observations
