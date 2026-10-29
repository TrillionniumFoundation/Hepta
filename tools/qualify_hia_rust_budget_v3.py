#!/usr/bin/env python3
"""Frozen-source actual bound-v3 observations; not an authority-switch gate."""
from contextlib import redirect_stdout
from datetime import datetime, timezone
from hashlib import sha256
import argparse
import io
import json
import os
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.test_hia_rust_budget_v3 import RustBudgetV3Parity
from tools.qualify_hia_integrated import _source_state
from tools.qualify_hia_rust_bound_depth import tool_identity

METHODS = (
    "test_all_256_depths_have_actual_returns_and_exact_call_stops",
    "test_deep_returned_loans_and_chains_keep_exact_stopped_ledgers",
    "test_ten_million_ticks_execute_and_old_step_limit_still_rejects",
    "test_larger_payload_is_allocated_and_heap_denial_precedes_host_allocation",
    "test_deep_step_stops_and_traps_retain_real_prefixes",
    "test_raw_policy_and_original_entry_admission_remain_strict",
    "test_v1_v2_reports_remain_unchanged_for_all_primitive_schemas",
    "test_rehashed_tampering_and_cross_protocol_replay_reject",
)


def _test_counts(result):
    return {"run": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped),
            "expected_failures": len(result.expectedFailures),
            "unexpected_successes": len(result.unexpectedSuccesses)}


def _complete_test_success(result, expected_count):
    # unittest regards expected failures as successful. Qualification requires
    # every selected method to pass normally, even if a method recorded useful
    # observations before reaching its expected failure.
    counts = _test_counts(result)
    return (result.wasSuccessful() and counts["run"] == expected_count
            and all(value == 0 for key, value in counts.items() if key != "run"))


def qualify(expected_head, output):
    if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
        raise ValueError("expected-head must be an exact full commit SHA")
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError("retain evidence outside the frozen source checkout")
    before = _source_state()
    if before["head"] != expected_head or before["status"]:
        raise ValueError("qualify only the requested clean committed source")
    if set(unittest.defaultTestLoader.getTestCaseNames(RustBudgetV3Parity)) != set(METHODS):
        raise ValueError("review the changed bound-v3 qualification denominator")
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    selected_tools = (("cargo", "cargo", "-V"), ("rustc", os.environ.get("RUSTC", "rustc"), "-vV"))
    tools_before = {label: tool_identity(name, flag) for label, name, flag in selected_tools}
    log = io.StringIO()
    suite = unittest.TestSuite(RustBudgetV3Parity(name) for name in METHODS)
    with redirect_stdout(log):
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    after = _source_state()
    observations = getattr(RustBudgetV3Parity, "observations", [])
    refusals = getattr(RustBudgetV3Parity, "refusals", [])
    compatibility = getattr(RustBudgetV3Parity, "compatibility", [])
    binary = getattr(RustBudgetV3Parity, "executable", None)
    binary_before = getattr(RustBudgetV3Parity, "digest", None)
    binary_after = sha256(binary.read_bytes()).hexdigest() if binary and binary.is_file() else None
    depths = sorted({row["crosscheck"]["request"]["policy"]["max_call_depth"] for row in observations})
    executed_ten_million = any(
        row["crosscheck"]["rust_report"]["max_steps"] == 10_000_000
        and row["crosscheck"]["rust_report"]["steps"] == 10_000_001
        and row["crosscheck"]["rust_report"].get("error") == {"code": "steps"}
        for row in observations)
    large_payload_bytes = max((row["crosscheck"]["rust_report"]["resources"]["peak_bytes"]
                               for row in observations), default=0)
    observed_heap_denial = any(
        row["crosscheck"]["request"]["arguments"] == [1024 * 1024 * 1024 + 1]
        and row["crosscheck"]["rust_report"]["max_heap_bytes"] == 1024 * 1024 * 1024
        and row["crosscheck"]["rust_report"].get("error") == {"code": "heap"}
        and row["crosscheck"]["rust_report"]["resources"]["live_bytes"] == 0
        for row in observations)
    tools_after = {label: tool_identity(name, flag) for label, name, flag in selected_tools}
    passed = (_complete_test_success(result, len(METHODS))
              and before == after and after["status"] == "" and binary_before == binary_after
              and binary_before is not None and depths == list(range(1, 257))
              and observations and all(row["matched"] is True for row in observations)
              and refusals and all(row["rejected"] is True for row in refusals)
              and [row["version"] for row in compatibility] == list(range(1, 9))
              and all(row["unchanged"] is True for row in compatibility)
              and executed_ten_million and large_payload_bytes == 16 * 1024 * 1024 + 1
              and observed_heap_denial and tools_before == tools_after
              and all(row["returncode"] == 0 for row in tools_after.values()))
    report = {
        "schema": "hepta.hia.rust-bound-budget-qualification.v1", "ok": bool(passed),
        "status": "finite_bound_v3_budget_parity_passed" if passed else "finite_bound_v3_not_qualified",
        "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
        "expected_head": expected_head, "source_before": before, "source_after": after,
        "source_unchanged": before == after, "methods": list(METHODS),
        "tests": _test_counts(result), "test_log": log.getvalue(),
        "build_process": getattr(RustBudgetV3Parity, "build", None),
        "binary": {"path": str(binary), "sha256_before": binary_before, "sha256_after": binary_after},
        "toolchains_before": tools_before, "toolchains_after": tools_after,
        "toolchains_unchanged": tools_before == tools_after, "python": sys.version,
        "build_environment": {name: os.environ.get(name) for name in (
            "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "RUSTC",
            "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CARGO_INCREMENTAL")},
        "depths_observed": depths, "positive_observations": len(observations),
        "raw_refusals": len(refusals), "legacy_compatibility_versions": len(compatibility),
        "programs_by_sha256": getattr(RustBudgetV3Parity, "programs", {}),
        "observations": observations, "refusals": refusals, "legacy_compatibility": compatibility,
        "actual_budget_boundaries": {
            "ten_million_allowed_ticks_executed": executed_ten_million,
            "largest_observed_live_logical_bytes": large_payload_bytes,
            "one_gib_policy_overflow_denied_before_allocation": observed_heap_denial,
            "successful_one_gib_allocation_observed": False,
            "process_rss_measured": False,
        },
        "claims": {"finite_bound_v3_policy_observed": bool(passed),
            "production_api_policy_parity": False, "rust_production_admission_authorized": False,
            "native_backend_refinement_proved": False, "whole_language_soundness_proved": False,
            "full_P2_closed": False},
        "limits": ["Finite primitive-v1-v8 corpus and root-inclusive depths 1..256 only.",
            "The byte budget counts logical payload/node bytes, not frame/map overhead or RSS.",
            "Actual allocation evidence is 16 MiB plus one byte, not successful allocation of 1 GiB.",
            "Stopped ledgers establish neither asynchronous cancellation nor complete unwind cleanup.",
            "Public arguments/results remain scalar; original nominal entry restrictions are retained.",
            "Rust allocation-failure indices remain u64 bounded; Python accepts larger positive indices.",
            "Trusted host and pinned executable; archived reports and hashes grant no production admission."],
    }
    (output / "qualification.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    (output / "test.log").write_text(log.getvalue())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--output-directory", required=True, type=Path)
    options = parser.parse_args()
    report = qualify(options.expected_head, options.output_directory)
    print(json.dumps({key: report[key] for key in ("ok", "status", "tests", "positive_observations",
        "raw_refusals", "legacy_compatibility_versions", "source_unchanged", "actual_budget_boundaries")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
