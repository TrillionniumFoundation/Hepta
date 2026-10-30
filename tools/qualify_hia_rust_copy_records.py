#!/usr/bin/env python3
"""Execute the finite raw Rust Copy-record candidate on exact frozen source."""
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

from tests.test_hia_rust_copy_records import RustCopyRecordCandidate
from tools.qualify_hia_integrated import _source_state
from tools.qualify_hia_rust_bound_depth import tool_identity
from tools.qualify_hia_rust_budget_v3 import _test_counts, _complete_test_success

METHODS = (
    "test_raw_nested_and_empty_records_normalize_and_run_without_python",
    "test_raw_loops_resource_calls_refusals_traps_and_stopped_ledgers",
    "test_different_nominal_origins_keep_distinct_bound_requests",
    "test_distinct_same_layout_types_reject_before_calls_returns_and_edges",
    "test_zero_width_values_keep_ssa_identity_and_private_entry_eligibility",
    "test_unsupported_unused_forms_and_bad_primitive_helpers_refuse_whole_input",
    "test_raw_json_refusals_and_old_primitive_protocol_admission_stay_closed",
    "test_exact_type_name_and_value_slot_boundaries",
    "test_erased_return_fanout_refuses_before_wide_name_materialization",
)


def qualify(expected_head, output):
    if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
        raise ValueError("expected-head must name an exact full commit")
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError("retain evidence outside the frozen source checkout")
    before = _source_state()
    if before["head"] != expected_head or before["status"]:
        raise ValueError("qualification requires the requested clean committed source")
    if set(unittest.defaultTestLoader.getTestCaseNames(RustCopyRecordCandidate)) != set(METHODS):
        raise ValueError("review the changed raw Copy-record method denominator")
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    tool_commands = (("cargo", "cargo", "-V"), ("rustc", os.environ.get("RUSTC", "rustc"), "-vV"))
    tools_before = {label: tool_identity(name, flag) for label, name, flag in tool_commands}
    log = io.StringIO()
    with redirect_stdout(log):
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(
            unittest.TestSuite(RustCopyRecordCandidate(name) for name in METHODS))
    after = _source_state()
    normalizations = getattr(RustCopyRecordCandidate, "normalizations", [])
    observations = getattr(RustCopyRecordCandidate, "observations", [])
    refusals = getattr(RustCopyRecordCandidate, "refusals", [])
    raw_inputs = getattr(RustCopyRecordCandidate, "raw_inputs", {})
    binary = getattr(RustCopyRecordCandidate, "executable", None)
    binary_before = getattr(RustCopyRecordCandidate, "digest", None)
    binary_after = sha256(binary.read_bytes()).hexdigest() if binary and binary.is_file() else None
    tools_after = {label: tool_identity(name, flag) for label, name, flag in tool_commands}
    processes = [row["process"] for row in normalizations + observations + refusals]
    independent = all(row["python_admission_elaboration_and_machine_disabled_during_launch"] is True
        and row["child_cwd_outside_repository"] is True
        and row["child_environment"] == {"PATH": "/hepta-no-language-interpreter", "LANG": "C", "LC_ALL": "C"}
        and row["executable_sha256_before"] == row["executable_sha256_after"] == binary_before
        and sha256(raw_inputs[row["stdin_sha256"]].encode()).hexdigest() == row["stdin_sha256"]
        for row in processes)
    passed = (_complete_test_success(result, len(METHODS)) and before == after
        and not after["status"] and binary_before is not None and binary_before == binary_after
        and tools_before == tools_after and all(row["returncode"] == 0 for row in tools_after.values())
        and len(normalizations) == 13 and all(row["exact_core_bytes_and_exports_match"] is True for row in normalizations)
        and len(observations) == 43 and all(row["matched"] is True for row in observations)
        and len(refusals) == 47 and all(row["rejected"] is True for row in refusals)
        and independent)
    report = {
        "schema": "hepta.hia.rust-copy-record-qualification.v1", "ok": bool(passed),
        "status": "finite_raw_rust_copy_records_passed" if passed else "finite_raw_rust_copy_records_not_qualified",
        "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
        "expected_head": expected_head, "source_before": before, "source_after": after,
        "source_unchanged": before == after, "methods": list(METHODS), "tests": _test_counts(result),
        "test_log": log.getvalue(), "build_process": getattr(RustCopyRecordCandidate, "build", None),
        "binary": {"path": str(binary), "sha256_before": binary_before, "sha256_after": binary_after},
        "toolchains_before": tools_before, "toolchains_after": tools_after,
        "toolchains_unchanged": tools_before == tools_after, "python_orchestrator": sys.version,
        "build_environment": {name: os.environ.get(name) for name in (
            "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "RUSTC", "CARGO_INCREMENTAL",
            "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG")},
        "exact_normalizations": len(normalizations), "execution_observations": len(observations),
        "raw_refusals": len(refusals), "native_process_invocations": len(processes),
        "raw_native_path_independent_of_python_admission_normalization_and_execution": independent,
        "raw_inputs_by_sha256": raw_inputs, "normalizations": normalizations,
        "observations": observations, "refusals": refusals,
        "claims": {"finite_rust_raw_nominal_input_implemented_and_observed": bool(passed),
            "all_composite_v1_inputs_supported": False, "complete_python_api_parity": False,
            "rust_production_admission_authorized": False, "native_backend_refinement_proved": False,
            "whole_language_soundness_proved": False, "full_P2_closed": False},
        "limits": [
            "Explicit monomorphic Copy-record candidate only; general nominal input and producer fallback are not accepted.",
            "All declared records are checked, including unused layouts; their scalar leaves and zero-width identities remain distinct before erasure.",
            "Existing primitive v6 Core, verify_owned and bound-v4 Machine; no duplicate evaluator or production-route change.",
            "128 declarations, 64 fields, 32 layout depth, 512 flat fields, 8192 generated names and 32768 value slots.",
            "Emitted scalar references are counted before materialization under the existing 262144 Core-node ceiling.",
            "Scalar/public transport and full policy retain bound-v4's finite limits, including the 1024-byte policy ceiling.",
            "The collector uses Python after each native observation as an independent oracle; the raw native child has no Python search path or repository cwd.",
            "Trusted host/toolchain; PATH controls do not constitute a hostile-code sandbox or transitive runtime closure.",
            "Stored/owned record fields, generics, enums, partial records, tasks and broader lifetimes remain outside this input candidate.",
        ],
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
    print(json.dumps({key: report[key] for key in ("ok", "status", "tests", "exact_normalizations",
        "execution_observations", "raw_refusals", "native_process_invocations", "source_unchanged")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
