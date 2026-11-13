"""Finite chain input qualification under ordinary explicit libc ELF linkage.

The successor compiler translates these inputs itself. Core VM and independent
direct backend observations are host-side references, not successor compilers.
This does not qualify arbitrary ELF loading or prove general machine refinement.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))


def qualify(directory, compiler):
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import HIAProgramRejected
    from hepta.hia_program_native import emit_program_machine, compile_program_machine
    from tools.hia_selfhost_chain_cases import cases
    from tools.hia_selfhost_chain_flow_cases import cases as flow_cases, refusals, profile_refusal_ids, expanded_name_cases as flow_name_cases
    from tools.hia_selfhost_parameter_cases import cases as parameter_cases, refusals as parameter_refusals, expanded_name_cases as parameter_name_cases
    from tools.hia_selfhost_owned_elf_cases import reference
    from tools.qualify_hia_selfhost_owned_elf import inspect_owned_object
    from tools.qualify_hia_selfhost import compile_stage, invoke, observe_native_tool, INVALID, NO_SPACE
    directory, compiler = Path(directory), Path(compiler)
    directory.mkdir(parents=True, exist_ok=False)
    report = {"schema": "hepta.hia.selfhost-chain-elf-qualification.v1", "status": "started",
        "compiler_sha256": sha256(compiler.read_bytes()).hexdigest(),
        "scope": "six dynamic chain operations and chain move/drop/loans under the bounded explicit ELF profile",
        "allocator_contract": "ordinary fresh nonaliasing calloc or null, and free of valid live storage",
        "global_core_or_machine_refinement_proved": False,
        "general_multi_result_call_return_abi_supported": False, "cases": [], "refusals": []}
    try:
        for case in [*cases(), *flow_cases(), *parameter_cases(), *flow_name_cases(), *parameter_name_cases()]:
            label, source = case["id"], case["source"].encode()
            (directory / (label + ".hepta")).write_bytes(source)
            ref = reference(case)
            obj, compilation = compile_stage(directory, label + "-object", compiler, source, output_extension=".o")
            inspection = inspect_owned_object(obj.read_bytes())
            tools = [observe_native_tool(directory, label + "-readelf", "readelf", ["-W", "-h", "-S", "-s", "-r", obj])]
            linked = directory / (label + ".so")
            tools.append(observe_native_tool(directory, label + "-link", "ld", ["-m", "elf_x86_64", "-shared",
                "-z", "defs", "-z", "noexecstack", "-z", "relro", "-z", "now", "--build-id=none", obj, "-lc", "-o", linked]))
            if not all(row["returncode"] == 0 for row in tools):
                raise AssertionError(tools)
            observed, output = invoke(directory, label + "-run", linked, b"", image_format="linked-selfhost",
                capacity=8, workspace_size=0, output_initial=bytes([0xa5] * 8), observe_trap_writes=True)
            checked = assemble_program(source)
            direct_image = emit_program_machine(checked, foreign_buffer_exports=(("f0", 1 << 20),))
            direct = directory / (label + "-direct.so")
            direct_build = compile_program_machine(direct_image, program=checked, output=direct, linker="ld")
            oracle, oracle_output = invoke(directory, label + "-direct-run", direct, b"", image_format="seed-shared",
                capacity=8, workspace_size=0, output_initial=bytes([0xa5] * 8), observe_trap_writes=True)
            if "expected_trap" in case:
                good = (observed.get("status") == "child_failed" and observed.get("returncode") == -4
                        and oracle.get("status") == "child_failed" and oracle.get("returncode") == -6)
            else:
                good = (observed.get("status") == oracle.get("status") == "returned"
                        and observed.get("core_u32") == oracle.get("core_u32") == case["expected_result"]
                        and observed.get("source_unchanged") and oracle.get("source_unchanged"))
            good = bool(good and output.hex() == oracle_output.hex() == case["expected_output_hex"])
            report["cases"].append({"case": case, "reference": ref, "compilation": compilation,
                "inspection": inspection, "tools": tools, "native": observed, "output_hex": output.hex(),
                "independent_direct_build": direct_build, "independent_direct_native": oracle, "pass": good})
            if not good:
                raise AssertionError(report["cases"][-1])
            if label in {"empty-query-and-pop", "chain-flow-three-result-ssa-boundary"}:
                short, _ = invoke(directory, label + "-short", compiler, source, capacity=obj.stat().st_size - 1)
                if not (short.get("status") == "returned" and short.get("core_u32") == NO_SPACE
                        and short.get("output_unchanged") and short.get("source_unchanged")):
                    raise AssertionError(short)
                report["cases"][-1]["short_output_transactional"] = short
        parameter_negative = parameter_refusals()
        profile_ids = profile_refusal_ids() | set(parameter_negative)
        for name, source in {**refusals(), **parameter_negative}.items():
            expected = name in profile_ids
            canonical = "accepted_general_core"
            try:
                assemble_program(source)
                accepted = True
            except HIAProgramRejected as error:
                canonical, accepted = error.code, False
            if accepted != expected:
                raise AssertionError({"case": name, "canonical": canonical, "expected_accepted": expected})
            observed, _ = invoke(directory, "reject-" + name, compiler, source)
            good = bool(observed.get("status") == "returned" and observed.get("core_u32") == INVALID
                        and observed.get("output_unchanged") and observed.get("source_unchanged"))
            report["refusals"].append({"name": name, "source": source.decode(), "canonical": canonical,
                "general_core_expected": "accepted" if expected else "rejected", "observation": observed, "pass": good})
            if not good:
                raise AssertionError(report["refusals"][-1])
        report["status"] = "PASS_SCOPED_CHAIN_ELF"
    finally:
        report["source_files"] = {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in (
            "tools/generate_hia_selfhost.py", "tools/hia_selfhost_owned_elf.py", "tools/hia_selfhost_chain_elf.py",
            "tools/hia_selfhost_chain_cases.py", "tools/qualify_hia_selfhost_chain_elf.py",
            "tools/hia_selfhost_chain_flow_cases.py",
            "tools/hia_selfhost_parameter_cases.py",
            "examples/hia_bootstrap/selfhost.hepta")}
        (directory / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = qualify(args.output, args.compiler)
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]), "refusals": len(report["refusals"])}))
