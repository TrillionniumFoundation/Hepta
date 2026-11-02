#!/usr/bin/env python3
"""Compose all-input normal-return and actual LLVM checks for every export.

This is a selected-artifact proof chain over the existing finite scalar
encoders. It does not prove those encoders, the whole verifier, ownership,
LLVM-to-machine lowering or every possible program in the declared profile.
Every call re-verifies the exact Core and asks fresh solver queries.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_llvm import emit_program_llvm
from hepta.hia_scalar_lowering_check import ScalarLoweringRejected, verify_scalar_lowering
from hepta.hia_scalar_totality import (
    CALL_PROFILE, PROFILE as TOTALITY_PROFILE,
    validate_scalar_call_totality, validate_scalar_totality,
)
from hepta.hia_translation_validation import QUALIFIED_CORE_SCHEMAS

SCHEMA = "hepta.hia.sequential-core-proof-chain.v1"
PROFILE = "hia.sequential-acyclic-scalar-all-exports.v1"
MAX_EXPORTS = 16
SOURCE_FILES = (
    "tools/qualify_hia_sequential_core.py", "hepta/hia_scalar_totality.py",
    "hepta/hia_scalar_call_validation.py", "hepta/hia_scalar_lowering_check.py",
    "hepta/hia_translation_validation.py", "hepta/hia_optimization.py",
    "hepta/hia_program.py", "hepta/hia_capability_flow.py", "hepta/hia_opcodes.py", "hepta/hia_schema.py",
    "hepta/hia_json_preflight.py", "hepta/hia_program_composite.py",
    "hepta/hia_program_runtime.py", "hepta/hia_bounded_memory.py",
    "hepta/hia_program_llvm.py", "hepta/hia_initialization.py",
)
LIMITATIONS = [
    "Every typed input of every public scalar export of this exact Core is quantified, including reachable direct callees.",
    "Functions, operations, acyclic CFG paths, call expansions and proof time are bounded by the existing validators.",
    "The canonical verifier, two scalar encoders, LLVM subset parser and pinned Z3 implementation are trusted, not machine-proved refinements.",
    "This is per-artifact translation validation; it is not a theorem for every legal program or every program in the profile.",
    "Resource ownership, loans, loops, recursion, concurrency, FFI, hardware, LLVM machine-code lowering and C ABI are outside the composed claim.",
    "Normal return excludes specified program traps in the mathematical models, not process/resource-budget failures.",
    "Retained JSON is reproducible evidence, not an execution or publication certificate.",
]


def _source_identity():
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE_FILES}


def _now_ns():
    return time.monotonic_ns()


def _remaining_ms(started, timeout_ms):
    remaining = timeout_ms - (_now_ns() - started + 999999) // 1000000
    if remaining <= 0:
        raise ValueError("whole_proof_deadline_exhausted")
    return remaining


def _evaluate(document, *, timeout_ms=10000):
    started = _now_ns()
    report = {
        "schema": SCHEMA, "profile": PROFILE, "passed": False,
        "status": "unknown", "reason": None, "timeout_ms": timeout_ms,
        "core_sha256": None, "input_sha256": None, "llvm_sha256": None,
        "exports": [], "obligations": [], "source_identity": None,
        "source_unchanged": False, "execution_authority": False,
        "claims": {
            "every_public_scalar_export_all_inputs_return_normally": False,
            "every_public_scalar_export_actual_llvm_value_equivalent": False,
            "every_public_scalar_export_actual_llvm_no_abort_or_poison": False,
            "all_legal_programs_proved": False,
            "all_programs_in_profile_proved": False,
            "verifier_or_encoder_refinement_proved": False,
            "ownership_or_resource_safety_proved": False,
            "native_machine_code_or_c_abi_proved": False,
        },
        "limitations": list(LIMITATIONS),
    }
    checked = emitted = None
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30000:
        report["reason"] = "invalid_proof_timeout"
        return report, checked, emitted
    try:
        report["source_identity"] = _source_identity()
        checked = verify_program(document)
        core = checked.as_dict()
        report.update(core_sha256=checked.sha256, input_sha256=checked.input_sha256)
        if checked.structured_bytes is not None or core["schema"] not in QUALIFIED_CORE_SCHEMAS:
            raise ValueError("explicit_primitive_v1_v7_core_required")
        exports = sorted(checked.scalar_entrypoints)
        report["exports"] = exports
        if not 1 <= len(exports) <= MAX_EXPORTS:
            raise ValueError("nonempty_bounded_public_scalar_export_inventory_required")
        emitted = emit_program_llvm(checked)
        report["llvm_sha256"] = sha256(emitted.text.encode()).hexdigest()
        functions = {fn["name"]: fn for fn in core["functions"]}
        for function in exports:
            has_calls = any(op["op"] == "call" for block in functions[function]["blocks"]
                            for op in block["ops"])
            totality = (validate_scalar_call_totality if has_calls else validate_scalar_totality)(
                checked, function=function, timeout_ms=min(10000, _remaining_ms(started, timeout_ms)))
            row = {"function": function, "totality": totality, "lowering": None, "passed": False}
            report["obligations"].append(row)
            if not (totality.get("status") == "proved"
                    and totality.get("program_sha256") == checked.sha256
                    and totality.get("input_sha256") == checked.input_sha256
                    and totality.get("function") == function
                    and totality.get("profile") == (CALL_PROFILE if has_calls else TOTALITY_PROFILE)
                    and totality.get("claims", {}).get("all_inputs_return_normally_proved") is True):
                raise ValueError("public_export_normal_return_not_proved:" + function)
            lowering = verify_scalar_lowering(checked, function=function, llvm_text=emitted.text,
                                             timeout_ms=_remaining_ms(started, timeout_ms))
            row["lowering"] = lowering
            if not (lowering.get("verified") is True and lowering.get("status") == "verified"
                    and lowering.get("actual_emitter_output") is True
                    and lowering.get("core_sha256") == checked.sha256
                    and lowering.get("llvm_sha256") == report["llvm_sha256"]
                    and lowering.get("function") == function
                    and lowering.get("claims", {}).get("selected_body_all_input_value_and_abort_equivalence") is True
                    and lowering.get("claims", {}).get("selected_body_poison_unreachable") is True):
                raise ValueError("public_export_actual_llvm_not_proved:" + function)
            row["passed"] = True
        report["source_unchanged"] = _source_identity() == report["source_identity"]
        if not report["source_unchanged"]:
            raise ValueError("proof_implementation_changed")
        _remaining_ms(started, timeout_ms)
        report.update(passed=True, status="proved", reason="all_export_totality_and_actual_lowering_proved")
    except (HIAProgramRejected, ScalarLoweringRejected, ValueError) as error:
        report.update(reason=str(error), error_type=type(error).__name__)
    except Exception as error:
        report.update(reason="incomplete_proof_chain", error_type=type(error).__name__, error=str(error))
    finally:
        report["wall_ns"] = _now_ns() - started
        if report["wall_ns"] > timeout_ms * 1000000:
            report.update(passed=False, status="unknown", reason="whole_proof_deadline_exhausted")
        for key in (
                "every_public_scalar_export_all_inputs_return_normally",
                "every_public_scalar_export_actual_llvm_value_equivalent",
                "every_public_scalar_export_actual_llvm_no_abort_or_poison"):
            report["claims"][key] = report["passed"] is True
    return report, checked, emitted


def verify_sequential_core(document, *, timeout_ms=10000):
    """Freshly check every public scalar export; no receipt input is accepted."""
    return _evaluate(document, timeout_ms=timeout_ms)[0]


def qualify(document, output, *, timeout_ms=10000):
    """Retain the exact Core, actual emitted LLVM and fresh per-export evidence."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    report, checked, emitted = _evaluate(document, timeout_ms=timeout_ms)
    if checked is not None:
        (output / "core.hia.json").write_bytes(checked.canonical_bytes)
    if emitted is not None:
        (output / "program.ll").write_text(emitted.text, encoding="utf-8")
    for index, row in enumerate(report["obligations"]):
        if row["lowering"] is not None:
            query = row["lowering"]["smtlib"]
            (output / f"lowering-{index:02d}.smt2").write_text(query + "\n(check-sat)\n", encoding="utf-8")
    (output / "qualification.json").write_text(
        json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    manifest = {path.name: {"bytes": path.stat().st_size, "sha256": sha256(path.read_bytes()).hexdigest()}
                for path in sorted(output.iterdir()) if path.is_file()}
    (output / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-ms", type=int, default=10000)
    args = parser.parse_args(argv)
    try:
        report = qualify(args.core.read_bytes(), args.output, timeout_ms=args.timeout_ms)
    except (OSError, ValueError) as error:
        print(json.dumps({"passed": False, "error": str(error)}))
        return 2
    print(json.dumps({key: report[key] for key in ("passed", "status", "reason", "core_sha256", "exports", "wall_ns")}))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
