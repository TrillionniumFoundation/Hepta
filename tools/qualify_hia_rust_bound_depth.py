#!/usr/bin/env python3
"""Fresh finite bound-v2 policy evidence; never a production authority gate."""
from contextlib import redirect_stdout
from datetime import datetime, timezone
from hashlib import sha256
import argparse
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.test_hia_rust_bound_depth import RustBoundDepthParity
from tools.qualify_hia_integrated import _source_state

METHODS = (
    "test_all_depths_have_root_inclusive_scalar_boundaries_and_exact_ticks",
    "test_recursive_returned_loans_and_chain_transfers_keep_stopped_owners",
    "test_step_heap_allocation_and_depth_stops_preserve_real_prefixes",
    "test_v1_and_legacy_reports_stay_fixed_at_32_for_every_schema",
    "test_python_policy_and_nominal_entries_reject_before_launch",
    "test_raw_policy_requires_exact_shape_types_bounds_and_json",
    "test_invalid_raw_core_and_typed_arguments_cannot_hide_behind_depth_one",
    "test_rehashed_policy_or_result_tampering_and_cross_version_replays_reject",
)


def tool_identity(name, version_flag):
    path = Path(shutil.which(name) or name).resolve(strict=True)
    result = subprocess.run([str(path), version_flag], capture_output=True, text=True, timeout=15)
    return {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest(),
            "argv": result.args, "returncode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}


def qualify(expected_head, output):
    if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
        raise ValueError("expected-head must be an exact full commit SHA")
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError("retain evidence outside the frozen source checkout")
    before = _source_state()
    if before["head"] != expected_head or before["status"]:
        raise ValueError("qualify only the requested clean committed source")
    discovered = set(unittest.defaultTestLoader.getTestCaseNames(RustBoundDepthParity))
    if discovered != set(METHODS):
        raise ValueError("review the changed bound-depth qualification denominator")
    output.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    selected_tools = (("cargo", "cargo", "-V"), ("rustc", os.environ.get("RUSTC", "rustc"), "-vV"))
    tools_before = {label: tool_identity(name, flag) for label, name, flag in selected_tools}
    log = io.StringIO()
    suite = unittest.TestSuite(RustBoundDepthParity(name) for name in METHODS)
    with redirect_stdout(log):
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    after = _source_state()
    observations = getattr(RustBoundDepthParity, "observations", [])
    refusals = getattr(RustBoundDepthParity, "refusals", [])
    compatibility = getattr(RustBoundDepthParity, "compatibility", [])
    binary = getattr(RustBoundDepthParity, "executable", None)
    binary_before = getattr(RustBoundDepthParity, "digest", None)
    binary_after = sha256(binary.read_bytes()).hexdigest() if binary and binary.is_file() else None
    depths = sorted({row["crosscheck"]["request"]["policy"]["max_call_depth"] for row in observations})
    tools_after = {label: tool_identity(name, flag) for label, name, flag in selected_tools}
    passed = (result.wasSuccessful() and not result.skipped and result.testsRun == len(METHODS)
              and before == after and after["status"] == "" and binary_before == binary_after
              and binary_before is not None and depths == list(range(1, 33))
              and observations and all(row["matched"] is True for row in observations)
              and refusals and all(row["rejected"] is True for row in refusals)
              and [row["version"] for row in compatibility] == list(range(1, 9))
              and all(row["unchanged"] is True for row in compatibility)
              and tools_before == tools_after
              and all(row["returncode"] == 0 for row in tools_after.values()))
    report = {
        "schema": "hepta.hia.rust-bound-depth-qualification.v1", "ok": bool(passed),
        "status": "finite_bound_v2_depth_parity_passed" if passed else "finite_bound_v2_depth_not_qualified",
        "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
        "expected_head": expected_head, "source_before": before, "source_after": after,
        "source_unchanged": before == after, "methods": list(METHODS),
        "tests": {"run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
                  "skipped": len(result.skipped)}, "test_log": log.getvalue(),
        "build_process": getattr(RustBoundDepthParity, "build", None),
        "binary": {"path": str(binary), "sha256_before": binary_before, "sha256_after": binary_after},
        "toolchains_before": tools_before, "toolchains_after": tools_after,
        "toolchains_unchanged": tools_before == tools_after, "python": sys.version,
        "build_environment": {name: os.environ.get(name) for name in (
            "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "RUSTC",
            "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CARGO_INCREMENTAL")},
        "depths_observed": depths, "positive_observations": len(observations),
        "raw_refusals": len(refusals), "legacy_compatibility_versions": len(compatibility),
        "programs_by_sha256": getattr(RustBoundDepthParity, "programs", {}),
        "observations": observations, "refusals": refusals, "legacy_compatibility": compatibility,
        "claims": {"finite_bound_v2_policy_observed": bool(passed),
            "production_api_policy_parity": False, "rust_production_admission_authorized": False,
            "native_backend_refinement_proved": False, "whole_language_soundness_proved": False,
            "full_P2_closed": False},
        "limits": ["Finite primitive-v1-v8 input corpus and root-inclusive depths 1..32 only.",
            "Step cap 1,000,000 and live payload/node cap 16 MiB remain unchanged; neither is RSS.",
            "Stopped ledgers are observations, not asynchronous cancellation or unwind cleanup.",
            "Public arguments/results remain scalar; normalized nominal inputs retain entry restrictions.",
            "Production Python depth/step/heap policies are wider; this is no authority-switch gate.",
            "The host and selected executable are trusted; hashes and archived reports grant no admission."],
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
        "raw_refusals", "legacy_compatibility_versions", "source_unchanged")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
