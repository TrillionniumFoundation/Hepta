"""Independent boundary fixtures for the bounded Selfhost-Core v5 capacity.

The fixture renderer only creates ordinary assembly bytes. All admission is
performed by the general Core checker before B0 and again by each native
successor. Over-budget inputs are retained; no checker limit is monkeypatched.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json

from tools.hia_selfhost_cases import HEADER
from tools.hia_selfhost_limits import MAX_INSTRUCTIONS, MAX_CORE_NODES


def count_nodes(value):
    """Count a complete fixture tree, independently of native parser charges."""
    pending, total = [value], 0
    while pending:
        current = pending.pop()
        total += 1
        if isinstance(current, dict):
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return total


def instruction_capacity_source(instructions):
    if not 3072 <= instructions <= MAX_INSTRUCTIONS + 1:
        raise ValueError("capacity fixture requires 3072..8193 operations")
    functions = (instructions + 1023) // 1024
    remaining, lines = instructions, []
    for fn in range(functions):
        size = min(1024, remaining)
        remaining -= size
        if fn == 0:
            lines += [HEADER, '  v3:u32 = const() {"value":0}\n']
            current, serial, overhead = 3, 4, 2
        else:
            lines += [f"fn f{fn}(v0:u32) -> (u32) effects(read,write,trap) entry(b0)\n",
                      "block b0(v0:u32)\n"]
            current, serial, overhead = 0, 1, 1
        one = serial
        lines.append(f'  v{one}:u32 = const() {{"value":1}}\n')
        serial += 1
        has_call = fn + 1 < functions
        for _ in range(size - overhead - int(has_call)):
            lines.append(f"  v{serial}:u32 = int.add.wrap(v{current},v{one})\n")
            current, serial = serial, serial + 1
        if has_call:
            lines.append(f'  v{serial}:u32 = call(v{current}) {{"function":"f{fn + 1}"}}\n')
            current = serial
        lines.append(f"  ret(v{current})\nend\n")
    return "".join(lines).encode(), instructions - 2 * functions


def _fixture_assembly(document):
    # Intentionally does not call render_assembly: that would reject limit+1
    # before the native compiler could observe the original source bytes.
    def params(values):
        return ",".join(p["name"] + ":" + p["type"] for p in values)
    lines = ["hia-asm.v1 hepta.hia.program.v8 selfhost"]
    for fn in document["functions"]:
        lines.append(f'fn {fn["name"]}({params(fn["params"])}) -> ({fn["returns"][0]}) effects(read,write,trap) entry(b0)')
        for block in fn["blocks"]:
            lines.append(f'block {block["id"]}({params(block["params"])})')
            for op in block["ops"]:
                line = f'{params(op["out"]) or "_"}={op["op"]}({",".join(op["args"])})'
                if op["attrs"]:
                    line += " " + json.dumps(op["attrs"], separators=(",", ":"))
                lines.append(line)
            term = block["term"]
            if term["op"] == "ret":
                lines.append("ret(" + ",".join(term["values"]) + ")")
            else:
                left, right = term["then"], term["else"]
                lines.append(f'branch {term["cond"]} {left["target"]}({",".join(left["args"])}) {right["target"]}({",".join(right["args"])})')
        lines.append("end")
    return ("\n".join(lines) + "\n").encode()


def structural_capacity_fixture(over=False):
    """Exactly 262144 or 262145 Core nodes, below all other source limits."""
    def op(name, args, output, attrs=None):
        return {"op": name, "args": args, "out": [output], "attrs": attrs or {}}
    root_params = [{"name": "v0", "type": "readbuf"},
                   {"name": "v1", "type": "mutbuf"},
                   {"name": "v2", "type": "mutbuf"}]
    functions = [{"name": "f0", "params": root_params, "returns": ["u32"],
        "effects": ["read", "write", "trap"], "entry": "b0", "blocks": [{
            "id": "b0", "params": deepcopy(root_params),
            "ops": [op("const", [], {"name": "v3", "type": "u32"}, {"value": 0})],
            "term": {"op": "ret", "values": ["v3"]}}]}]
    for fn in range(1, 17):
        block_count = 1 if fn == 16 else 53
        blocks, serial = [], 16 * block_count
        for block in range(block_count):
            params = [{"name": f"v{16 * block + i}", "type": "bool" if i == 15 else "u8"}
                      for i in range(16)]
            names = [p["name"] for p in params]
            operations = []
            if fn != 16 and block == 0:
                for _ in range(500 + (7 if fn == 1 else 0)):
                    operations.append(op("call", names, {"name": f"v{serial}", "type": "u8"}, {"function": "f16"}))
                    serial += 1
                if fn == 1:
                    for _ in range(3):
                        operations.append(op("int.add.wrap", names[:2], {"name": f"v{serial}", "type": "u8"}))
                        serial += 1
                    operations.append(op("int.add.wrap" if over else "const",
                        names[:2] if over else [], {"name": f"v{serial}", "type": "u8"},
                        {} if over else {"value": 0}))
                    serial += 1
            if block + 1 == block_count:
                term = {"op": "ret", "values": [names[0]]}
            else:
                edge = {"target": f"b{block + 1}", "args": names}
                term = {"op": "branch", "cond": names[15], "then": edge, "else": deepcopy(edge)}
            blocks.append({"id": f"b{block}", "params": params, "ops": operations, "term": term})
        functions.append({"name": f"f{fn}", "params": deepcopy(blocks[0]["params"]),
                          "returns": ["u8"], "effects": ["read", "write", "trap"],
                          "entry": "b0", "blocks": blocks})
    document = {"schema": "hepta.hia.program.v8", "module": "selfhost", "functions": functions}
    if count_nodes(document) != MAX_CORE_NODES + int(over):
        raise AssertionError("structural fixture is not at its declared boundary")
    source = _fixture_assembly(document)
    if len(source) > 1 << 20:
        raise AssertionError("structural fixture exceeds the separate source byte limit")
    return source, document


def independent_capacity_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    observations = []
    for size in (3072, 3073, MAX_INSTRUCTIONS, MAX_INSTRUCTIONS + 1):
        source, expected = instruction_capacity_source(size)
        checked = assemble_program(source)
        scalar = checked.as_dict()
        # These borrowed entry parameters are unused. Retain every operation,
        # branch and call while making the entry invocable by the scalar VM.
        scalar["functions"][0]["params"] = []
        scalar["functions"][0]["blocks"][0]["params"] = []
        result = execute_program(scalar, "f0", [])
        if result["result"] != expected:
            raise AssertionError("independent Core execution disagrees with integer oracle")
        observations.append({"case": "instructions-" + str(size), "instructions": size,
            "source_bytes": len(source), "source_sha256": sha256(source).hexdigest(),
            "core_sha256": checked.sha256, "core_nodes": count_nodes(checked.as_dict()),
            "expected_result": expected, "general_core": "accepted", "reference_result": result,
            "scalar_reference_change": "remove three unused borrowed entry parameters; all operations and control flow unchanged",
            "selfhost_profile_expected": "accepted" if size <= MAX_INSTRUCTIONS else "instruction_limit_rejected"})
    for over in (False, True):
        source, document = structural_capacity_fixture(over)
        entry = {"case": "structural-nodes-" + str(MAX_CORE_NODES + int(over)),
            "source_sha256": sha256(source).hexdigest(), "source_bytes": len(source),
            "core_nodes": count_nodes(document),
            "canonical_bytes": len(json.dumps(document, sort_keys=True, separators=(",", ":")).encode())}
        try:
            checked = assemble_program(source)
        except HIAProgramRejected as exc:
            if not over or exc.code != "E_HIA_LIMIT":
                raise
            entry.update(general_core="rejected", code=exc.code)
        else:
            if over or checked.as_dict() != document:
                raise AssertionError("structural reference admitted the wrong tree")
            entry.update(general_core="accepted", core_sha256=checked.sha256)
        observations.append(entry)
    return {"profile_instruction_limit": MAX_INSTRUCTIONS, "core_node_limit": MAX_CORE_NODES,
            "observations": observations}


def qualify_capacity(directory, compilers, checks, reference):
    from tools.qualify_hia_selfhost import (INVALID, NO_SPACE, compile_stage, invoke,
                                          inspect_selfhost_object, digest)
    observations = []
    refs = {r["case"]: r for r in reference["observations"]}
    for label, compiler in compilers:
        for size in (3072, 3073, MAX_INSTRUCTIONS):
            case = label + "-capacity-" + str(size)
            source, expected = instruction_capacity_source(size)
            image, build = compile_stage(directory, case, compiler, source, workspace_fill=0xa7)
            observations.append(build)
            header = build["workspace_header"]
            checks[case + "-counts"] = (header["112"] == size
                and header["248"] == refs["instructions-" + str(size)]["core_nodes"])
            run, _ = invoke(directory, case + "-run", image, b"", capacity=0, workspace_size=0)
            checks[case + "-behavior"] = (run.get("status") == "returned" and run.get("core_u32") == expected)
            observations.append(run)
            if size == MAX_INSTRUCTIONS:
                obj, obj_build = compile_stage(directory, case + "-elf", compiler,
                    source.replace(b"v8 selfhost\n", b"v8 selfhost_elf\n", 1), output_extension=".o")
                inspection = inspect_selfhost_object(obj.read_bytes())
                checks[case + "-elf-text"] = inspection["text_sha256"] == digest(image.read_bytes())
                observations.append({**obj_build, "object_inspection": inspection})
                short, _ = invoke(directory, case + "-short-output", compiler, source,
                                  capacity=build["produced_bytes"] - 1)
                checks[case + "-preflight"] = (short.get("status") == "returned"
                    and short.get("core_u32") == NO_SPACE and short.get("output_unchanged")
                    and short.get("workspace_header", {}).get("224") == header["224"])
                observations.append(short)
        source, _ = instruction_capacity_source(MAX_INSTRUCTIONS + 1)
        case = label + "-capacity-over-limit"
        rejected, _ = invoke(directory, case, compiler, source)
        checks[case] = (rejected.get("status") == "returned" and rejected.get("core_u32") == INVALID
            and rejected.get("output_unchanged") and rejected.get("source_unchanged")
            and rejected.get("workspace_header", {}).get("40") == 54)
        observations.append(rejected)
        for over in (False, True):
            source, _ = structural_capacity_fixture(over)
            case = label + "-capacity-nodes-" + str(MAX_CORE_NODES + int(over))
            result, _ = invoke(directory, case, compiler, source, capacity=32, workspace_fill=0xa7)
            # The exact-limit source passes semantic/node checks and reaches
            # output preflight. +1 must be rejected in pass zero, before output.
            checks[case] = (result.get("status") == "returned"
                and result.get("core_u32") == (INVALID if over else NO_SPACE)
                and result.get("output_unchanged") and result.get("source_unchanged")
                and result.get("workspace_header", {}).get("248") == MAX_CORE_NODES + int(over)
                and result.get("workspace_header", {}).get("40") == (58 if over else 0))
            observations.append(result)
    return observations
