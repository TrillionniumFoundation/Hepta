"""Replay the exact v4 native compiler's transition into Selfhost-Core v5.

The historical v4 source/image are fixed by digest and copied into the new
evidence directory. No Python parser, verifier, emitter or linker creates any
upgrade generation. This reuses the retained v4 B3; it does not claim to rebuild
that historical B3 from a fresh machine or to prove its compiler correct.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from tools.hia_selfhost_contract import validate_contract
from tools.hia_selfhost_capacity import instruction_capacity_source
from tools.hia_selfhost_limits import MAX_INSTRUCTIONS
from tools.qualify_hia_selfhost import (SOURCE, INVALID, compile_stage, digest,
                                       invoke, source_manifest)

V4 = {
    "profile": "selfhost-core-linux-x86_64-v4",
    "source_commit": "894d2dfce54ff25271b8de2c18c902394484d5cc",
    "source_sha256": "c02cd855f36562bb507cf4dc61da031ceb4dd05775adb4e87ed1884a24b052fa",
    "B3_sha256": "0b66c56e702e0da8897cebcf4f1f686aeff51a343c377fd54b2ff394f0e4f104",
    "instructions": 3072,
}


def upgrade_replay(previous_evidence, output):
    contract = validate_contract()
    before = source_manifest()
    previous_evidence, output = Path(previous_evidence), Path(output)
    old_source = (previous_evidence / "B3.input.bin").read_bytes()
    old_image = (previous_evidence / "B3.image.bin").read_bytes()
    old_receipt = (previous_evidence / "B3.receipt.json").read_bytes()
    receipt = json.loads(old_receipt)
    if (digest(old_source) != V4["source_sha256"] or digest(old_image) != V4["B3_sha256"]
            or receipt.get("input_sha256") != V4["source_sha256"]
            or receipt.get("produced_sha256") != V4["B3_sha256"]):
        raise ValueError("historical v4 source, B3 image or receipt differs from the pinned upgrade input")
    if contract["profile"] != "selfhost-core-linux-x86_64-v5":
        raise ValueError("historical v4-to-v5 upgrade requires the pinned v5 source checkout")
    if any(p.is_symlink() for p in (output, *output.parents)) or output.exists():
        raise ValueError("upgrade replay requires a new nonsymbolic output path")
    output = output.resolve()
    directory = output.with_suffix(".evidence")
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    (directory / "v4-B3.input.bin").write_bytes(old_source)
    old_path = directory / "v4-B3.image.bin"
    old_path.write_bytes(old_image)
    (directory / "v4-B3.receipt.json").write_bytes(old_receipt)
    started = time.monotonic_ns()
    outside_old, _ = instruction_capacity_source(V4["instructions"] + 1)
    refusal, _ = invoke(directory, "v4-refuses-3073", old_path, outside_old)
    checks = {"pinned_v4_refuses_3073": (
        refusal.get("status") == "returned" and refusal.get("core_u32") == INVALID
        and refusal.get("workspace_header", {}).get("40") == 54
        and refusal.get("source_unchanged") and refusal.get("output_unchanged"))}
    source, previous, generations = SOURCE.read_bytes(), old_path, []
    for label in ("U1", "U2", "U3"):
        previous, build = compile_stage(directory, label, previous, source, workspace_fill=0x5a)
        generations.append(build)
    checks["v5_source_fits_v4_instruction_admission"] = (
        generations[0]["workspace_header"]["112"] <= V4["instructions"])
    checks["upgraded_fixed_point"] = len({g["produced_sha256"] for g in generations}) == 1
    checks["upgraded_compiler_differs_from_v4"] = generations[-1]["produced_sha256"] != V4["B3_sha256"]
    checks["upgrade_children_load_no_python_compiler"] = all(
        not g["forbidden_compiler_modules_loaded"] for g in generations)
    maximum_source, expected = instruction_capacity_source(MAX_INSTRUCTIONS)
    maximum_image, maximum_build = compile_stage(directory, "v5-8192-build", previous, maximum_source)
    maximum_run, _ = invoke(directory, "v5-8192-run", maximum_image, b"", capacity=0, workspace_size=0)
    checks["upgraded_compiler_executes_8192_instructions"] = (
        maximum_build["workspace_header"]["112"] == MAX_INSTRUCTIONS
        and maximum_run.get("status") == "returned" and maximum_run.get("core_u32") == expected)
    checks["source_closure_unchanged"] = source_manifest() == before
    result = {"schema": "hepta.hia.selfhost-upgrade.v1",
        "status": "SELFHOST_V4_TO_V5_UPGRADE_PASS" if all(checks.values()) else "FAIL",
        "previous": {**V4, "receipt_sha256": digest(old_receipt)},
        "profile": contract["profile"], "source_manifest": before,
        "source_sha256": digest(source), "checks": checks,
        "old_limit_refusal": refusal, "generations": generations,
        "maximum_build": maximum_build, "maximum_run": maximum_run,
        "wall_elapsed_ns": time.monotonic_ns() - started,
        "claims": {"historical_v4_B3_rebuilt_here": False,
                   "python_parser_or_codegen_used_for_upgrade": False,
                   "external_assembler_or_linker_used_for_upgrade": False,
                   "compiler_correctness_formally_proved": False}}
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    result = upgrade_replay(arguments.previous_evidence, arguments.output)
    print(json.dumps({"status": result["status"], "checks_passed": sum(result["checks"].values()),
                      "checks_total": len(result["checks"]),
                      "generation_sha256": [r["produced_sha256"] for r in result["generations"]],
                      "output": str(arguments.output)}, sort_keys=True))
    raise SystemExit(0 if all(result["checks"].values()) else 1)


if __name__ == "__main__":
    main()
