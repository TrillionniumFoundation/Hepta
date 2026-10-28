#!/usr/bin/env python3
"""Retain source-bound v8 returned-loan Python/Rust/native qualification bytes."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.test_hia_returned_loans import ReturnedLoanNative, ReturnedLoanRust, ReturnedLoanSemantics


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory():
    paths = set((ROOT / "hepta").glob("*.py"))
    paths.update((ROOT / "rust/hia-core-shadow/src").rglob("*.rs"))
    paths.update((ROOT / "rust/hia-core-shadow/tests").rglob("*.rs"))
    paths.update((ROOT / "examples/hia_returned_loans").glob("*"))
    paths.update(ROOT / name for name in (
        "rust/hia-core-shadow/Cargo.toml", "rust/hia-core-shadow/Cargo.lock",
        "tests/test_hia_returned_loans.py", "tests/test_hia_program.py",
        "tools/qualify_hia_returned_loans.py", "docs/HIA_RETURNED_LOANS_V8.md",
        "examples/hia_resource_core/borrowed_projection.hepta"))
    return {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths) if path.is_file()}


def command(argv):
    try:
        proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=30)
        return {"argv": argv, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": argv, "returncode": None, "error": str(exc)}


def git_observation(head_before, status_before, head_after, status_after):
    """An unavailable Git observation is neither a clean nor a stable source."""
    commands = (head_before, status_before, head_after, status_after)
    observed = all(type(row.get("returncode")) is int and row["returncode"] == 0
                   and type(row.get("stdout")) is str for row in commands)
    observed = observed and all(re.fullmatch(r"[0-9a-f]{40}\n?", row["stdout"]) is not None
                                for row in (head_before, head_after))
    same_head = observed and head_before["stdout"] == head_after["stdout"]
    clean = observed and not status_before["stdout"] and not status_after["stdout"]
    return {"observed": observed, "same_head": same_head, "clean": clean}


def qualify(folder):
    started = datetime.now(timezone.utc).isoformat()
    before, head_before, status_before = inventory(), command(["git", "rev-parse", "HEAD"]), command(["git", "status", "--porcelain"])
    native_dir = folder / "native"
    native_dir.mkdir()
    previous = os.environ.get("HIA_RETURNED_LOAN_NATIVE_DIR")
    os.environ["HIA_RETURNED_LOAN_NATIVE_DIR"] = str(native_dir)
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls)
                               for cls in (ReturnedLoanSemantics, ReturnedLoanRust, ReturnedLoanNative))
    captured = io.StringIO()
    try:
        with redirect_stdout(captured):
            result = unittest.TextTestRunner(stream=captured, verbosity=2).run(suite)
    finally:
        if previous is None:
            os.environ.pop("HIA_RETURNED_LOAN_NATIVE_DIR", None)
        else:
            os.environ["HIA_RETURNED_LOAN_NATIVE_DIR"] = previous
    after, head_after, status_after = inventory(), command(["git", "rev-parse", "HEAD"]), command(["git", "status", "--porcelain"])
    observations, admissions = ReturnedLoanRust.observations, ReturnedLoanRust.admissions
    natives = ReturnedLoanNative.records
    execution_profiles = sorted({row.get("rust", {}).get("profile", "missing")
                                 for row in observations})
    allowed_profiles = {"bounded-cfg-byte-owner-loan-returns-v4", "bounded-cfg-owned-memory-v5"}
    files = {str(p.relative_to(folder)): digest(p) for p in sorted(native_dir.rglob("*")) if p.is_file()}
    git_state = git_observation(head_before, status_before, head_after, status_after)
    stable = (git_state["observed"] and git_state["same_head"] and before == after
              and head_before == head_after and status_before == status_after)
    controls = [control for native in natives for control in native.get("oracle_controls", [])]
    success = (result.wasSuccessful() and not result.skipped and result.testsRun == 10 and stable
               and bool(observations) and all(row.get("matched") for row in observations)
               and set(execution_profiles) <= allowed_profiles
               and bool(admissions) and all(row.get("rejected") for row in admissions)
               and len(natives) == 5 and all(row.get("passed") for row in natives)
               and len(controls) == 2 and all(row.get("oracle_rejected") for row in controls))
    executable = getattr(ReturnedLoanRust, "executable", None)
    executable_before = getattr(ReturnedLoanRust, "executable_sha256", None)
    executable_after = digest(Path(executable)) if executable else None
    success = success and executable_before is not None and executable_before == executable_after
    report = {
        "schema": "hepta.hia.returned-loan-qualification.v2", "core_schema": "hepta.hia.program.v8",
        "wire_contract": "return_loans", "rust_execution_profiles": execution_profiles, "ok": success,
        "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
        "source_before": before, "source_after": after, "source_unchanged": stable,
        "git_head_before": head_before, "git_head_after": head_after,
        "git_status_before": status_before, "git_status_after": status_after,
        "git_observed": git_state["observed"], "git_clean": git_state["clean"],
        "tests": {"run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped)},
        "test_log": captured.getvalue(), "build_process": getattr(ReturnedLoanRust, "build", None),
        "toolchains": {"rustc": command(["rustc", "-vV"]), "cargo": command(["cargo", "-V"]), "python": sys.version},
        "rust_executable": {"path": executable, "sha256": executable_after,
                            "sha256_after_build": executable_before,
                            "unchanged_during_execution": executable_before == executable_after} if executable else None,
        "source_inputs": ReturnedLoanRust.sources, "programs": ReturnedLoanRust.programs,
        "parity_observations": len(observations), "negative_admissions": len(admissions),
        "observed_statuses": dict(Counter(row.get("rust", {}).get("status", "process_failure") for row in observations)),
        "observations": observations, "admissions": admissions, "native": natives,
        "native_successful_calls": sum(row.get("observations", {}).get("calls", 0) for row in natives),
        "native_failure_policy_observations": sum(len(row.get("failure_observations", [])) for row in natives),
        "native_oracle_controls": len(controls), "native_artifact_sha256": files,
        "claims": {
            "actual_interprocedural_returned_loan_execution": success,
            "source_helpers_retained_as_core_calls_and_returns": success,
            "canonical_and_independent_rust_admission_exercised": success,
            "full_python_rust_resource_ledgers_compared": success,
            "actual_linux_x86_64_native_execution_and_allocator_observation": success,
            "native_wrong_value_and_missing_free_controls_rejected": success,
            "v1_v7_returned_loan_rejections_preserved": success,
            "nominal_record_returned_loan_composition_supported": False,
            "asynchronous_cancellation_or_exception_unwinding_supported": False,
            "native_loan_lifetime_ledger_observed": False,
            "full_source_or_llvm_refinement_proved": False,
            "whole_language_soundness_proved": False,
            "absolute_safety_or_global_optimality_proved": False,
            "rust_performance_advantage_proved": False,
            "full_resource_core_closed": False,
        },
        "limits": [
            "This source corpus exercises one returned readbuf/mutbuf plus scalar results. The canonical v8 contract independently supports multiple result positions with explicit parameter origins and checked aliasing; it rejects unconsumed local resources, unrepresented temporary parents and arbitrary lifetime relations.",
            "Source Core v8 is explicit opt-in and currently permits one Buffer<u8>/slice<u8> origin; stored returned borrows and borrowed-record projection returns remain outside this source profile.",
            "Primitive returned loans can compose with existing v8 byte/chain operations. Nominal composite v1/v2/v3 still normalize to v6/v7 and do not gain v8 returned loans.",
            "Steps/heap/call stops preserve actual live resources; they do not perform cleanup or establish async cancellation/unwinding semantics.",
            "The native observer measures allocation calls/free/live bytes and scalar outcomes; compile-time loans have no native runtime ledger.",
            "Native artifacts do not implement VM step/heap/call-depth budgets, and no native recursion/stack/cancellation bound is established.",
            "This qualifier's actual native host is Linux x86-64. Separate v8 qualifiers cover finite AArch64/RV64 execution under QEMU and resource budgets; this report does not inherit their execution counts. Scalar-only Rust shadow still refuses v8.",
            "The scalar translation validator returns unknown for resource/call functions. No optimization admission is granted by these finite observations.",
        ],
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.output.exists() or (args.output.parent / "native").exists():
        parser.error("use a fresh evidence path; existing reports and native bytes are never overwritten")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report = qualify(args.output.parent)
    args.output.write_text(json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2) + "\n")
    args.output.with_suffix(".log").write_text(report["test_log"])
    print(json.dumps({key: report[key] for key in ("ok", "tests", "git_clean", "source_unchanged", "parity_observations",
                                                  "negative_admissions", "native_successful_calls", "native_failure_policy_observations", "native_oracle_controls")}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
