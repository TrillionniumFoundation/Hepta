#!/usr/bin/env python3
"""Check the mathematical initialization-prefix model and targeted negatives.

The result is evidence for the named mathematical model, never an importable
native admission certificate or a proof of the production CFG checker.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.qualify_hia_selected_formal import _run_lean, _support_identity

MODEL = ROOT / "formal/HiaInitializationPrefix.lean"
SCHEMA = "hepta.hia.initialization-prefix-proof.v1"
THEOREMS = frozenset({
    "write_at_index", "write_at_other", "zero_prefix", "write_extends_prefix",
    "prefix_value", "prefix_outside", "prefix_invariant", "completed_fill_initialized",
    "completed_fill_independent_of_initial", "completed_fill_matches_zeroed",
    "increment_within_limit", "incomplete_prefix_is_not_full",
    "completed_exit_is_exact_bound", "completed_exit_establishes_initialized",
    "skipped_zero_stays_uninitialized", "stride_two_leaves_a_hole",
})
SOURCE_FILES = (
    "formal/HiaInitializationPrefix.lean", "formal/toolchain-lock.json",
    "formal/proof-dependencies.txt", "tools/qualify_hia_initialization_prefix.py",
    "tools/qualify_hia_selected_formal.py",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return sha256(data).hexdigest()


def source_identity():
    return {name: digest((ROOT / name).read_bytes()) for name in SOURCE_FILES}


def theorem_dependencies(log):
    found = re.findall(r"^'HiaInitializationPrefix\.([^']+)' depends on axioms: \[([^\]]*)\]$", log, re.M)
    found += [(name, "") for name in re.findall(
        r"^'HiaInitializationPrefix\.([^']+)' does not depend on any axioms$", log, re.M)]
    require(len(found) == len(THEOREMS) and {name for name, _ in found} == THEOREMS,
            "initialization theorem inventory differs")
    result = {name: [part.strip() for part in axioms.split(",") if part.strip()]
              for name, axioms in found}
    require("error:" not in log and "sorryAx" not in log
            and all(set(axioms) <= {"propext", "Classical.choice", "Quot.sound"}
                    for axioms in result.values()),
            "initialization positive proof has an error, placeholder or unexpected axiom")
    return result


def negative_sources(source):
    marker = "| count + 1 => write (fillPrefix initial values count) count (values count)"
    require(source.count(marker) == 1, "initialization model mutation point differs")
    return {
        "starts_at_one": source.replace(marker,
            "| count + 1 => write (fillPrefix initial values count) (count + 1) (values count)"),
        "stride_two": source.replace(marker,
            "| count + 1 => write (fillPrefix initial values count) (count * 2) (values count)"),
        "early_exit_claim": source + '''
namespace HiaInitializationPrefix
example : fillPrefix empty (fun _ => BitVec.ofNat 8 0) 2 2 =
    some (BitVec.ofNat 8 0) := by decide
end HiaInitializationPrefix
''',
    }


def qualify(lean, output_directory):
    started = time.monotonic_ns()
    executable = Path(lean).resolve(strict=True)
    tool_digest = digest(executable.read_bytes())
    lock = json.loads((ROOT / "formal/toolchain-lock.json").read_text())
    require(tool_digest == lock["lean_binary_sha256"], "initialization proof requires the pinned Lean binary SHA-256")
    source = MODEL.read_text()
    sources_before = source_identity()
    support_before = _support_identity(executable)
    output = Path(output_directory).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "positive.lean").write_text(source)
    (output / "lean-support-files.json").write_text(json.dumps(support_before, indent=2) + "\n")
    report = {"schema": SCHEMA, "status": "running", "authority": "mathematical-model-only",
              "source_identity": sources_before, "lean_binary_sha256": tool_digest,
              "support_manifest_sha256": digest((output / "lean-support-files.json").read_bytes()),
              "negative_controls": [], "claims": {
                  "arbitrary_initial_byte_contents_and_lengths": False,
                  "full_contiguous_unit_step_fill_initialized": False,
                  "completed_fill_matches_zeroed_initial_memory": False,
                  "partial_fill_and_bad_schedules_not_certified": False,
                  "actual_cfg_checker_soundness_proved": False,
                  "finite_machine_integer_to_Nat_refinement_proved": False,
                  "allocator_or_native_backend_refinement_proved": False,
                  "whole_language_soundness_proved": False,
                  "production_authority": False},
              "limits": [
                  "Memory is a mathematical Nat-addressed function to optional BitVec8 bytes.",
                  "The contiguous write values are independent of the initial memory contents.",
                  "An actual CFG checker must separately establish this exact write schedule, allocation identity, no early read/escape, and dominating completed-fill exit.",
                  "Allocation success/failure, NULL, zero-length, release and native bounds are not modeled by this theorem.",
                  "Python/CFG/LLVM correspondence is not machine-proved by checking this model."]}
    try:
        positive = _run_lean(executable, output / "positive.lean")
        report["positive"] = positive
        (output / "positive.stdout").write_text(positive["stdout"])
        (output / "positive.stderr").write_text(positive["stderr"])
        require(positive["returncode"] == 0, "Lean rejected initialization-prefix model")
        report["theorems"] = theorem_dependencies(positive["stdout"] + positive["stderr"])
        for name, mutant in negative_sources(source).items():
            path = output / (name + ".lean")
            path.write_text(mutant)
            result = _run_lean(executable, path)
            (output / (name + ".stdout")).write_text(result["stdout"])
            (output / (name + ".stderr")).write_text(result["stderr"])
            require(result["returncode"] == 1 and "error:" in result["stdout"] + result["stderr"],
                    "Lean did not reject the targeted initialization control: " + name)
            report["negative_controls"].append({"name": name, "status": "rejected-as-expected",
                                                 "source_sha256": digest(mutant.encode()), **result})
        require(source_identity() == sources_before and digest(executable.read_bytes()) == tool_digest
                and _support_identity(executable) == support_before,
                "initialization proof source or Lean support changed during checking")
        report["claims"].update(arbitrary_initial_byte_contents_and_lengths=True,
                                full_contiguous_unit_step_fill_initialized=True,
                                completed_fill_matches_zeroed_initial_memory=True,
                                partial_fill_and_bad_schedules_not_certified=True)
        report["status"] = "passed"
    except BaseException as error:
        report.update(status="failed", error={"type": type(error).__name__, "message": str(error)})
    finally:
        report["wall_ns"] = time.monotonic_ns() - started
        (output / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lean", required=True)
    parser.add_argument("--output-directory", required=True)
    args = parser.parse_args()
    report = qualify(args.lean, args.output_directory)
    print(json.dumps({"status": report["status"], "theorems": len(report.get("theorems", {})),
                      "negative_controls": len(report["negative_controls"]), "wall_ns": report["wall_ns"]}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
