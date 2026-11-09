#!/usr/bin/env python3
"""Compare original and fixed scalar audits on unchanged retained measurements."""
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tests import test_hia_scalar_controller_controls as fixtures
from tools import measure_hia_scalar_controller_controls as candidate

BASE = "9ba2a6202277e3d3418d3a8205450973174eb812"
old_source = subprocess.check_output([
    "git", "show", BASE + ":tools/measure_hia_scalar_controller_controls.py"], cwd=ROOT)
original = types.ModuleType("original_scalar_outer_audit")
original.__file__ = candidate.__file__
exec(compile(old_source, "original_scalar_outer_audit.py", "exec"), original.__dict__)
fixtures.RetainedScalarOuterIntervalTests.setUpClass()
helper = fixtures.RetainedScalarOuterIntervalTests()
baseline = helper.verify_files(helper.files)
original_summary = candidate.decode(helper.files["SUMMARY.json"])
costs = original_summary["measurement"]
last_end = max(row["end_offset_ns"] for row in original_summary["cells"] if row["status"] != "not_started")
mutations = []
understated = json.loads(json.dumps(original_summary))
understated["measurement"]["outer_wall_ns_to_summary_preparation"] = costs["all_attempted_call_wall_ns"]
understated["measurement"]["admission_capture_export_audit_wall_ns"] = 0
mutations.append(("review_4509542158_understated_outer", understated))
for field in ("outer_wall_ns_to_summary_preparation", "all_attempted_call_wall_ns",
              "admission_capture_export_audit_wall_ns"):
    changed = json.loads(json.dumps(original_summary))
    changed["measurement"][field] = float(changed["measurement"][field])
    mutations.append(("equal_python_float_" + field, changed))

observations = []
for name, summary in mutations:
    files = dict(helper.files)
    files["SUMMARY.json"] = candidate.wire(summary)
    with patch.object(fixtures, "study", original):
        old = helper.verify_files(files)
    assert old["verification"] == "ORIGINAL_BYTES_AND_ACCOUNTING_VERIFIED"
    try:
        helper.verify_files(files)
    except ValueError as error:
        observations.append({"case": name, "old_accepts": True, "fixed_rejects": True,
            "error": str(error), "mutated_summary_sha256": sha256(files["SUMMARY.json"]).hexdigest()})
    else:
        raise AssertionError("fixed verifier accepted inconsistent costs: " + name)

print(json.dumps({"schema": "hepta.hia.scalar-outer-offset-regression.v1",
    "base_commit": BASE, "old_checker_sha256": sha256(old_source).hexdigest(),
    "fixed_checker_sha256": sha256(Path(candidate.__file__).read_bytes()).hexdigest(),
    "archive_sha256": "d9025d10bacdd5e8558625c26fce40130effc87e05fe962a2387bfd4680add6d",
    "original_outer_wall_ns": costs["outer_wall_ns_to_summary_preparation"],
    "call_duration_sum_ns": costs["all_attempted_call_wall_ns"],
    "last_attempted_call_end_offset_ns": last_end,
    "original_positive": baseline, "counterexamples": observations,
    "new_native_calls": 0, "new_provider_calls": 0, "new_benchmark": False,
    "economic_benefit_established": False}, indent=2, sort_keys=True))
