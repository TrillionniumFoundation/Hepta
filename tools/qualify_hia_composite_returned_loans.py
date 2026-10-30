#!/usr/bin/env python3
"""Bind the original primitive-origin composite-v4 corpus to clean source.

The newer field-origin corpus remains separately selected and qualified.
"""
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

from tests.test_hia_composite_returned_loans import (
    CompositeReturnedLoanSemantics, CompositeReturnedLoanRust, CompositeReturnedLoanNative)
from tools.qualify_hia_integrated import _source_state
from tools.qualify_hia_rust_bound_depth import tool_identity
from tools.qualify_hia_rust_budget_v3 import _test_counts, _complete_test_success

METHODS = {
    CompositeReturnedLoanSemantics: (
        "test_explicit_profile_preserves_legacy_normalization_and_rejections",
        "test_partial_borrow_return_end_take_restore_with_cfg_and_recursion",
        "test_partial_result_expands_null_origins_before_named_primitive_loan",
        "test_contract_shape_permission_and_generated_name_origins_reject",
        "test_stored_loan_results_partial_fields_and_nominal_origins_reject",
        "test_independent_core_rejects_owner_motion_parent_end_and_wrong_origin",
        "test_uninitialized_finish_and_local_owner_escape_remain_rejected",
        "test_public_scalar_entries_and_unused_invalid_functions_stay_closed",
    ),
    CompositeReturnedLoanRust: (
        "test_actual_same_machine_partial_fields_return_forms_and_flat_results",
        "test_exact_stopped_prefixes_allocation_failure_and_recursive_depth",
        "test_raw_core_rejection_and_original_nominal_entry_before_launch",
    ),
    CompositeReturnedLoanNative: (
        "test_actual_llvm_calls_all_return_forms_and_expanded_partial_result",
        "test_actual_allocator_normal_and_failed_initialized_prefix_cleanup",
    ),
}


def qualify(expected_head, output):
    if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
        raise ValueError("expected-head must be an exact full commit SHA")
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError("retain evidence outside the frozen source checkout")
    before = _source_state()
    if before["head"] != expected_head or before["status"]:
        raise ValueError("qualify only the requested clean committed source")
    for cls, names in METHODS.items():
        if set(unittest.defaultTestLoader.getTestCaseNames(cls)) != set(names):
            raise ValueError("review the changed composite-v4 qualification denominator")
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    selected_tools = (("cargo", "cargo", "-V"), ("rustc", os.environ.get("RUSTC", "rustc"), "-vV"),
                      ("clang", os.environ.get("CLANG", "clang"), "--version"))
    tools_before = {label: tool_identity(name, flag) for label, name, flag in selected_tools}
    previous_native = os.environ.get("HIA_COMPOSITE_V4_NATIVE_DIR")
    os.environ["HIA_COMPOSITE_V4_NATIVE_DIR"] = str(output / "native")
    log = io.StringIO()
    try:
        with redirect_stdout(log):
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(
                unittest.TestSuite(cls(name) for cls, names in METHODS.items() for name in names))
    finally:
        if previous_native is None:
            os.environ.pop("HIA_COMPOSITE_V4_NATIVE_DIR", None)
        else:
            os.environ["HIA_COMPOSITE_V4_NATIVE_DIR"] = previous_native
    after = _source_state()
    rust = getattr(CompositeReturnedLoanRust, "observations", [])
    refusals = getattr(CompositeReturnedLoanRust, "refusals", [])
    native = getattr(CompositeReturnedLoanNative, "observations", [])
    native_calls = sum(len(row.get("native_calls", [])) + int("process" in row) for row in native)
    binary = getattr(CompositeReturnedLoanRust, "executable", None)
    binary_before = getattr(CompositeReturnedLoanRust, "digest", None)
    binary_after = sha256(binary.read_bytes()).hexdigest() if binary and binary.is_file() else None
    tools_after = {label: tool_identity(name, flag) for label, name, flag in selected_tools}
    passed = (_complete_test_success(result, sum(map(len, METHODS.values())))
        and before == after and after["status"] == "" and binary_before == binary_after
        and binary_before is not None and tools_before == tools_after
        and all(row["returncode"] == 0 for row in tools_after.values())
        and len(rust) == 153 and all(row["matched"] is True for row in rust)
        and len(refusals) == 4 and all(row["rejected"] is True for row in refusals)
        and len(native) == 12 and native_calls == 31)
    native_artifacts = {str(path.relative_to(output)): {"sha256": sha256(path.read_bytes()).hexdigest(),
                        "bytes": path.stat().st_size} for path in sorted((output / "native").rglob("*")) if path.is_file()}
    report = {
        "schema": "hepta.hia.composite-returned-loan-qualification.v1", "ok": bool(passed),
        "status": "finite_composite_v4_composition_passed" if passed else "finite_composite_v4_not_qualified",
        "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
        "expected_head": expected_head, "source_before": before, "source_after": after,
        "source_unchanged": before == after,
        "methods": [cls.__module__ + "." + cls.__name__ + "." + name for cls, names in METHODS.items() for name in names],
        "tests": _test_counts(result), "test_log": log.getvalue(),
        "build_process": getattr(CompositeReturnedLoanRust, "build", None),
        "binary": {"path": str(binary), "sha256_before": binary_before, "sha256_after": binary_after},
        "toolchains_before": tools_before, "toolchains_after": tools_after,
        "toolchains_unchanged": tools_before == tools_after, "python": sys.version,
        "build_environment": {name: os.environ.get(name) for name in (
            "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "RUSTC", "CLANG", "LD_LIBRARY_PATH",
            "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CARGO_INCREMENTAL")},
        "rust_observations": len(rust), "raw_rust_refusals": len(refusals), "native_calls": native_calls,
        "programs_by_sha256": getattr(CompositeReturnedLoanRust, "programs", {}),
        "rust": rust, "rust_refusals": refusals, "native": native, "native_artifacts": native_artifacts,
        "claims": {"finite_nominal_partial_returned_loan_composition_observed": bool(passed),
            "all_historical_routes_unified": False, "general_partial_initialization": False,
            "stored_loan_return_lifetimes_supported": False, "general_recursive_adts_supported": False,
            "rust_production_admission_authorized": False, "general_callback_or_foreign_lifetime_abi": False,
            "native_backend_refinement_proved": False, "whole_language_soundness_proved": False,
            "full_P0_closed": False, "full_P1_closed": False},
        "limits": [
            "Only explicit composite v4 normalizes to primitive v8; composite v1/v2/v3 retain their exact targets.",
            "This 13-method corpus uses primitive-formal string origins; checked object/field-path origins have separate regressions. Aggregate stored-loan results and partial stored loans refuse.",
            "This composite-v4 path uses Python nominal admission and independently checked Rust primitive v8 on the same Machine; the separate raw Copy-record candidate accepts only its stated composite-v1 subset.",
            "Native evidence is Linux x86-64 scalar C entrypoints; the allocator observer uses its declared one-byte fixture.",
            "Traps and budget stops retain actual live ledgers; no implicit unwind, async cancellation, raw pointer or provenance support.",
            "Native compilation receipts remain compiled_not_executed; separate native-call rows record the actual executions.",
            "Trusted host/toolchain; hashes and archived reports confer no admission, proof or production promotion.",
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
    print(json.dumps({key: report[key] for key in ("ok", "status", "tests", "rust_observations",
        "raw_rust_refusals", "native_calls", "source_unchanged")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
