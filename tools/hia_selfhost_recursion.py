"""Actual recursive Core witnesses for the bounded native call-frame profile.

Former refusal bytes remain owned by their original fixtures. Normal completion
is compared with the independent VM. Native budget exhaustion is an explicit
UD2/SIGILL boundary, not the VM's Python exception or an equivalence of reports.
"""
from __future__ import annotations
from hashlib import sha256

MULTI_PROMOTIONS = frozenset({"tail-results-reordered", "tail-result-replaced",
    "tail-result-then-operation", "void-tail-not-immediate"})


def former_refusals():
    from tools.hia_selfhost_cases import recursion_refusals
    from tools.hia_selfhost_tailcalls import tail_refusals
    from tools.hia_selfhost_multi_results import refusals
    rows = [{"id": "recursion-" + name, "source": source, "family": "scalar"}
            for name, source in recursion_refusals().items()]
    rows += [{"id": "tail-" + name, "source": source, "family": "scalar"}
             for name, (source, accepted) in tail_refusals().items() if accepted]
    rows += [{"id": "multi-" + row["id"], "source": row["source"].encode(), "family": "multi"}
             for row in refusals() if row["id"] in MULTI_PROMOTIONS]
    return rows


def promotion_inventory():
    return [{"id": row["id"], "source_sha256": sha256(row["source"]).hexdigest(),
             "family": row["family"], "native_profile_expected": "compiled"}
            for row in former_refusals()]


def mutual_source(count):
    from tools.hia_selfhost_tailcalls import scalar_tail_source
    head, helper = scalar_tail_source(count).split(b"fn f1(", 1)
    helper = b"fn f1(" + helper
    return head + helper.replace(b'{"function":"f1"}', b'{"function":"f2"}') + helper.replace(b"fn f1(", b"fn f2(", 1)


def full_frame_source(count):
    """2048 genuinely distinct SSA names; a large suffix alone is not a frame."""
    from tools.hia_selfhost_cases import HEADER
    source = (HEADER + f'  v3:u32 = const() {{"value":{count}}}\n'
              '  v4:u32 = call(v3) {"function":"f1"}\n  ret(v4)\nend\n'
              'fn f1(v0:u32) -> (u32) effects(read,write,trap) entry(b0)\n'
              'block b0(v0:u32)\n')
    source += ''.join(f'  v{i}:u32 = const() {{"value":0}}\n' for i in range(1, 2041))
    source += ('  v2041:u32 = const() {"value":0}\n'
        '  v2042:bool = compare.eq(v0,v2041)\n'
        '  branch v2042 b1(v0) b2(v0)\n'
        'block b1(v2043:u32)\n  ret(v2043)\n'
        'block b2(v2044:u32)\n  v2045:u32 = const() {"value":1}\n'
        '  v2046:u32 = int.sub.wrap(v2044,v2045)\n'
        '  v2047:u32 = call(v2046) {"function":"f1"}\n  ret(v2044)\nend\n')
    return source.encode()


def scalar_cases():
    from tools.hia_selfhost_tailcalls import scalar_tail_source
    rows = [dict(row) for row in former_refusals() if row["family"] == "scalar"]
    for count in (0, 1, 63, 127, 254, 255):
        rows.append({"id": "mutual-finite-" + str(count), "source": mutual_source(count)})
        source = scalar_tail_source(count).replace(b'  ret(v15)\n',
            b'  v17:u32 = int.add.wrap(v15,v13)\n  ret(v17)\n')
        rows.append({"id": "non-tail-finite-" + str(count), "source": source})
    # Root: 752 bytes including return address/saved rbp. Helper: 33440.
    # 188 helper frames fit 6 MiB; the 189th must trap before stack probing.
    for count in (187, 188):
        rows.append({"id": "full-frame-" + str(count), "source": full_frame_source(count),
                     "native_stack_budget_trap": count == 188})
    return rows


def independent_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from hepta.hia_program_runtime import HIAProgramBudgetExceeded
    rows = []
    for case in scalar_cases():
        checked = assemble_program(case["source"])
        doc = checked.as_dict()
        root = doc["functions"][0]
        unused = {p["name"] for p in root["params"]}
        assert not any(unused.intersection(op["args"]) for block in root["blocks"] for op in block["ops"])
        root["params"] = []
        root["blocks"][0]["params"] = []
        try:
            result = execute_program(doc, "f0", [], max_steps=1000000)
        except HIAProgramBudgetExceeded as exc:
            result = exc.report
            if result["error"]["code"] != "calls":
                raise AssertionError(result)
        native_trap = case.get("native_stack_budget_trap", False) or result["status"] == "budget_exceeded"
        rows.append({**case, "source": case["source"].decode(),
            "source_sha256": sha256(case["source"]).hexdigest(), "core_sha256": checked.sha256,
            "reference_result": result, "native_budget_trap": native_trap,
            "reference_boundary_change": "remove only unused borrowed root parameters; helper bytes and ordinary VM recursion retained"})
    return {"cases": rows, "former_refusals": promotion_inventory(),
        "live_frames": 256, "private_frame_bytes": 6 << 20,
        "budget_mapping": "VM calls budget -> native SIGILL; native private-byte budget is additional and explicit",
        "exception_reports_equal": False, "unbounded_recursion_claimed": False}


def promoted_multi_cases():
    """Execute original tuple/void sources; append witnesses without deleting old cases."""
    import struct
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from tools.hia_selfhost_multi_results import refusals
    from tools.hia_selfhost_void_results import cases as void_cases
    rows = []
    for item in refusals():
        if item["id"] not in MULTI_PROMOTIONS:
            continue
        program = "recursion-promoted-" + item["id"]
        if item["id"] == "void-tail-not-immediate":
            for original in void_cases():
                if original["program"] == "void-tail":
                    rows.append({**original, "id": program + '-' + str(len(rows)),
                        "program": program, "source": item["source"], "historical_refusal_id": item["id"]})
            continue
        checked = assemble_program(item["source"].encode())
        for count in (0, 1, 2, 63, 127, 254):
            arguments = [count, (1 << 64) - 1, 1 << 63]
            answer = execute_program(checked, "f1", arguments)
            if answer["status"] != "returned":
                raise AssertionError(answer)
            values = answer["values"]
            rows.append({"id": program + '-' + str(count), "program": program,
                "source": item["source"], "arguments": arguments,
                "source_hex": struct.pack('<3Q', *arguments).hex(), "initial_hex": 'a5' * 16,
                "expected_hex": struct.pack('<2Q', *values).hex(), "expected_result": 0,
                "expected_values": values, "owned_elf_only": False,
                "historical_refusal_id": item["id"], "helper_reference_result": answer})
    return rows


def qualify(directory, compilers, checks, reference):
    from tools.qualify_hia_selfhost import compile_stage, invoke, inspect_selfhost_object, digest, NO_SPACE
    observations = []
    for label, compiler in compilers:
        for case in reference["cases"]:
            prefix = label + '-recursive-' + case["id"]
            source = case["source"].encode()
            flat, build = compile_stage(directory, prefix + '-flat', compiler, source)
            obj_source = source.replace(b'v8 selfhost\n', b'v8 selfhost_elf\n', 1)
            obj, obj_build = compile_stage(directory, prefix + '-elf', compiler, obj_source, output_extension='.o')
            inventory = inspect_selfhost_object(obj.read_bytes())
            checks[prefix + '-flat-elf-text'] = inventory['text_sha256'] == digest(flat.read_bytes())
            actual, output = invoke(directory, prefix + '-run', flat, b'', capacity=0,
                                    workspace_size=0, observe_trap_writes=True)
            if case['native_budget_trap']:
                checks[prefix + '-execution'] = actual.get('status') == 'child_failed' and actual.get('returncode') == -4
            else:
                checks[prefix + '-execution'] = (actual.get('status') == 'returned'
                    and actual.get('abi_status') == 0 and actual.get('core_u32') == case['reference_result']['result'])
            short, _ = invoke(directory, prefix + '-short-output', compiler, source,
                              capacity=build['produced_bytes'] - 1)
            checks[prefix + '-short-output'] = (short.get('status') == 'returned'
                and short.get('core_u32') == NO_SPACE and short.get('source_unchanged') and short.get('output_unchanged'))
            observations.append({'case': case['id'], 'source_sha256': case['source_sha256'],
                'reference_result': case['reference_result'], 'native_budget_trap': case['native_budget_trap'],
                'build': build, 'object': {**obj_build, 'inventory': inventory}, 'native': actual, 'short': short})
    return observations
