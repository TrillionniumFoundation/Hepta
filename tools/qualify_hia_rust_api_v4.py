#!/usr/bin/env python3
"""Frozen-source exact v4 API observations; never production authorization."""
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

from tests.test_hia_rust_api_v4 import RustApiV4Parity
from tools.qualify_hia_integrated import _source_state
from tools.qualify_hia_rust_bound_depth import tool_identity
from tools.qualify_hia_rust_budget_v3 import _test_counts, _complete_test_success

METHODS = (
    "test_tuple_list_and_wide_indices_bind_identical_invocations",
    "test_allocation_order_loans_chains_and_step_stops_keep_exact_ledgers",
    "test_exact_policy_wire_boundary_and_prelaunch_large_integer_refusal",
    "test_native_policy_rejects_noncanonical_hex_and_ambiguous_json",
    "test_python_exact_types_and_original_entry_eligibility_reject_before_launch",
    "test_tiny_budget_or_wide_index_cannot_hide_invalid_unused_function",
    "test_rehashed_policy_tampering_and_cross_protocol_replay_are_rejected",
    "test_legacy_reports_and_refusal_contracts_remain_unchanged",
)


def qualify(expected_head, output):
    if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
        raise ValueError("expected-head must be an exact full commit SHA")
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError("retain evidence outside the frozen source checkout")
    before = _source_state()
    if before["head"] != expected_head or before["status"]:
        raise ValueError("qualify only the requested clean committed source")
    if set(unittest.defaultTestLoader.getTestCaseNames(RustApiV4Parity)) != set(METHODS):
        raise ValueError("review the changed bound-v4 qualification denominator")
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    selected_tools = (("cargo", "cargo", "-V"), ("rustc", os.environ.get("RUSTC", "rustc"), "-vV"))
    tools_before = {label: tool_identity(name, flag) for label, name, flag in selected_tools}
    log = io.StringIO()
    with redirect_stdout(log):
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(
            unittest.TestSuite(RustApiV4Parity(name) for name in METHODS))
    after = _source_state()
    observations = getattr(RustApiV4Parity, "observations", [])
    refusals = getattr(RustApiV4Parity, "refusals", [])
    compatibility = getattr(RustApiV4Parity, "compatibility", [])
    binary = getattr(RustApiV4Parity, "executable", None)
    binary_before = getattr(RustApiV4Parity, "digest", None)
    binary_after = sha256(binary.read_bytes()).hexdigest() if binary and binary.is_file() else None
    tools_after = {label: tool_identity(name, flag) for label, name, flag in selected_tools}
    integer_widths = sorted({int(row["crosscheck"]["request"]["policy"]["allocation_fail_at"], 16).bit_length()
        for row in observations if row["crosscheck"]["request"]["policy"]["allocation_fail_at"] is not None})
    policy_bytes = sorted({len(json.dumps(row["crosscheck"]["request"]["policy"],
        sort_keys=True, separators=(",", ":")).encode()) for row in observations})
    containers = sorted({row["argument_container"] for row in observations})
    passed = (_complete_test_success(result, len(METHODS))
        and before == after and after["status"] == "" and binary_before == binary_after
        and binary_before is not None and tools_before == tools_after
        and all(row["returncode"] == 0 for row in tools_after.values())
        and observations and all(row["matched"] is True for row in observations)
        and refusals and all(row["rejected"] is True for row in refusals)
        and containers == ["list", "tuple"] and 65 in integer_widths and 2049 in integer_widths
        and max(policy_bytes, default=0) == 1024
        and [row["version"] for row in compatibility] == list(range(1, 9))
        and all(row["unchanged"] is True and len(row["reports"]) == 9 for row in compatibility))
    report = {
        "schema": "hepta.hia.rust-bound-api-qualification.v1", "ok": bool(passed),
        "status": "finite_bound_v4_api_parity_passed" if passed else "finite_bound_v4_not_qualified",
        "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
        "expected_head": expected_head, "source_before": before, "source_after": after,
        "source_unchanged": before == after, "methods": list(METHODS),
        "tests": _test_counts(result), "test_log": log.getvalue(),
        "build_process": getattr(RustApiV4Parity, "build", None),
        "binary": {"path": str(binary), "sha256_before": binary_before, "sha256_after": binary_after},
        "toolchains_before": tools_before, "toolchains_after": tools_after,
        "toolchains_unchanged": tools_before == tools_after, "python": sys.version,
        "build_environment": {name: os.environ.get(name) for name in (
            "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "RUSTC",
            "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CARGO_INCREMENTAL")},
        "positive_observations": len(observations), "raw_refusals": len(refusals),
        "argument_containers_observed": containers, "failure_index_bit_widths_observed": integer_widths,
        "policy_wire_byte_sizes_observed": policy_bytes,
        "legacy_compatibility_versions": len(compatibility),
        "programs_by_sha256": getattr(RustApiV4Parity, "programs", {}),
        "observations": observations, "refusals": refusals, "legacy_compatibility": compatibility,
        "claims": {"finite_bound_v4_api_observed": bool(passed),
            "complete_python_api_parity": False, "unbounded_failure_index_transport": False,
            "rust_production_admission_authorized": False, "native_backend_refinement_proved": False,
            "whole_language_soundness_proved": False, "full_P2_closed": False},
        "limits": [
            "The full policy remains at most 1024 bytes; larger Python integers are refused before formatting/launch.",
            "Public scalar arguments remain at most 8192 values and 128 KiB; nominal normalization remains Python-owned.",
            "Only declared primitive-v1-v8 execution profiles are compared; no general ABI or memory/provenance claim.",
            "v1/v2/v3 maintain their existing list/u64 policies and report contracts.",
            "Same Machine and ByteMemory; stopped ledgers are not cancellation or complete unwind cleanup.",
            "Trusted host/pinned executable; archived reports and hashes do not grant production admission.",
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
    print(json.dumps({key: report[key] for key in ("ok", "status", "tests", "positive_observations",
        "raw_refusals", "legacy_compatibility_versions", "source_unchanged",
        "failure_index_bit_widths_observed", "policy_wire_byte_sizes_observed")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
