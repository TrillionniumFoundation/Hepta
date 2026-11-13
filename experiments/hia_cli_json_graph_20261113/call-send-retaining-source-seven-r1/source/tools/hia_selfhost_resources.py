"""Differential cases for native borrowed-resource operations in Selfhost-Core.

The resource reference executes the independent general Core VM before B0. Native
successors receive ordinary assembly and are compared against reference bytes.
"""
from __future__ import annotations

from tools.hia_selfhost_cases import HEADER

SWAP_CASES = (
    ("distinct", bytes([10, 20, 30, 40]), 0, 3),
    ("reversed", bytes([10, 20, 30, 40]), 3, 0),
    ("middle", bytes([10, 20, 30, 40]), 1, 2),
    ("same-valid", bytes([10, 20, 30, 40]), 2, 2),
    ("first-oob", bytes([10, 20, 30, 40]), 4, 1),
    ("second-oob", bytes([10, 20, 30, 40]), 1, 4),
    ("same-oob", bytes([10, 20, 30, 40]), 4, 4),
    ("maximum-index", bytes([10, 20, 30, 40]), 0, 2**64 - 1),
    ("empty", b"", 0, 0),
)


def swap_source(left, right):
    return (HEADER + f'  v3:usize = const() {{"value":{left}}}\n'
            f'  v4:usize = const() {{"value":{right}}}\n'
            '  _ = buffer.swap(v1,v3,v4)\n'
            '  v5:u32 = const() {"value":0}\n  ret(v5)\nend\n').encode()


def swap_refusals():
    source = swap_source(0, 3)
    return {
        "readonly": source.replace(b"buffer.swap(v1,", b"buffer.swap(v0,"),
        "index-type": source.replace(b"v4:usize", b"v4:u32"),
        "result-binding": source.replace(b"_ = buffer.swap", b"v6:u8 = buffer.swap"),
        "short-arity": source.replace(b"buffer.swap(v1,v3,v4)", b"buffer.swap(v1,v3)"),
        "long-arity": source.replace(b"buffer.swap(v1,v3,v4)", b"buffer.swap(v1,v3,v4,v4)"),
    }


def reference_source(initial, left, right):
    prefix = ("hia-asm.v1 hepta.hia.program.v8 swap_reference\n"
              "fn f0() -> (" + ",".join(["u8"] * len(initial) or ["u32"]) +
              ") effects(alloc,read,write,trap) entry(b0)\nblock b0()\n"
              f'  v0:usize = const() {{"value":{len(initial)}}}\n'
              "  v1:buffer = buffer.new(v0)\n  v2:mutbuf = borrow.mut(v1)\n")
    lines, results, variable = [prefix], [], 3
    for index, value in enumerate(initial):
        lines += [f'  v{variable}:usize = const() {{"value":{index}}}\n',
                  f'  v{variable+1}:u8 = const() {{"value":{value}}}\n',
                  f"  _ = buffer.store(v2,v{variable},v{variable+1})\n"]
        variable += 2
    lines += [f'  v{variable}:usize = const() {{"value":{left}}}\n',
              f'  v{variable+1}:usize = const() {{"value":{right}}}\n',
              f"  _ = buffer.swap(v2,v{variable},v{variable+1})\n"]
    variable += 2
    for index in range(len(initial)):
        lines += [f'  v{variable}:usize = const() {{"value":{index}}}\n',
                  f"  v{variable+1}:u8 = buffer.load(v2,v{variable})\n"]
        results.append(f"v{variable+1}")
        variable += 2
    if not results:
        lines.append(f'  v{variable}:u32 = const() {{"value":0}}\n')
        results.append(f"v{variable}")
    lines += ["  _ = loan.end(v2)\n  _ = owner.drop(v1)\n",
              "  ret(" + ",".join(results) + ")\nend\n"]
    return "".join(lines).encode()


def independent_resource_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected, execute_program
    from hepta.hia_program_runtime import HIAProgramTrap
    observations = []
    for name, initial, left, right in SWAP_CASES:
        source = reference_source(initial, left, right)
        checked = assemble_program(source)
        try:
            result = execute_program(checked, "f0", [])
        except HIAProgramTrap as exc:
            result = {"status": "trapped", "trap": exc.code, "message": str(exc)}
        trap = left >= len(initial) or right >= len(initial)
        expected = bytearray(initial)
        if not trap:
            expected[left], expected[right] = expected[right], expected[left]
            assert result["status"] == "returned" and result["result"] == list(expected), result
        else:
            assert result["status"] == "trapped" and result["trap"] == "bounds", result
        observations.append({"case": name, "initial_hex": initial.hex(), "left": left,
                             "right": right, "trap": trap, "expected_hex": bytes(expected).hex(),
                             "reference_source": source.decode(), "reference_result": result})
    rejected = []
    for name, source in swap_refusals().items():
        try:
            assemble_program(source)
        except HIAProgramRejected as exc:
            rejected.append({"case": name, "code": exc.code, "message": str(exc)})
        else:
            raise AssertionError("independent checker admitted " + name)
    return {"cases": observations, "rejections": rejected}


def qualify_resources(directory, compilers, checks, reference):
    from tools.qualify_hia_selfhost import INVALID, compile_stage, invoke, inspect_selfhost_object, digest
    observations = []
    for label, compiler in compilers:
        for case in reference["cases"]:
            name = label + "-swap-" + case["case"]
            source = swap_source(case["left"], case["right"])
            executable, build = compile_stage(directory, name + "-build", compiler, source)
            observations.append(build)
            initial = bytes.fromhex(case["initial_hex"])
            result, output = invoke(directory, name, executable, b"", capacity=len(initial),
                                    workspace_size=0, output_initial=initial, observe_trap_writes=True)
            witness = result.get("shared_output_observation", {})
            if case["trap"]:
                good = (result.get("status") == "child_failed" and result.get("returncode") == -4
                        and witness.get("available") and witness.get("unchanged"))
            else:
                good = (result.get("status") == "returned" and result.get("core_u32") == 0
                        and witness.get("available") and output.hex() == case["expected_hex"])
            checks[name.replace("-", "_")] = bool(good)
            observations.append(result)
        # Positive control for the trap observer: a prior independent store
        # survives a later trapping swap. A process crash must not be mistaken
        # for transactional rollback or for a copied initial-output receipt.
        source = swap_source(0, 4).replace(
            b"  _ = buffer.swap", b'  v6:u8 = const() {"value":99}\n'
            b"  _ = buffer.store(v1,v3,v6)\n  _ = buffer.swap")
        executable, build = compile_stage(directory, label + "-swap-observer-control-build", compiler, source)
        observations.append(build)
        result, output = invoke(directory, label + "-swap-observer-control", executable, b"",
            capacity=4, workspace_size=0, output_initial=bytes([10, 20, 30, 40]), observe_trap_writes=True)
        checks[label + "_swap_observer_sees_prior_write_before_trap"] = bool(
            result.get("status") == "child_failed" and result.get("returncode") == -4
            and result.get("shared_output_observation", {}).get("available")
            and output == bytes([99, 20, 30, 40]))
        observations.append(result)
        source = swap_source(0, 3)
        flat, flat_build = compile_stage(directory, label + "-swap-object-reference", compiler, source)
        observations.append(flat_build)
        obj, build = compile_stage(directory, label + "-swap-object", compiler, source.replace(b"v8 selfhost\n", b"v8 selfhost_elf\n", 1), output_extension=".o")
        obj_info = inspect_selfhost_object(obj.read_bytes())
        checks[label + "_swap_elf_text_matches_flat"] = obj_info["text_sha256"] == digest(flat.read_bytes())
        observations.append({**build, "object_inspection": obj_info})
        for name, source in swap_refusals().items():
            result, _ = invoke(directory, label + "-swap-reject-" + name, compiler, source)
            checks[label + "_swap_reject_" + name] = bool(
                result.get("status") == "returned" and result.get("core_u32") == INVALID
                and result.get("output_unchanged") and result.get("source_unchanged"))
            observations.append(result)
    return observations
