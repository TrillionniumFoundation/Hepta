"""Actual lifecycle composition, address observations and dangerous neighbours."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.pipeline import analyze
from tools.qualify_lifecycle_composition import (ENTRY, DENOMINATOR, EXPECTED_STDOUT,
    instrument_generated_rust, qualify, rejection_candidates, validate_report)


def reseal(document):
    document.pop("sha256", None)
    document["sha256"] = hashlib.sha256(json.dumps(document, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    return document


class LifecycleCompositionSourceTests(unittest.TestCase):
    def test_six_negative_neighbours_have_the_required_frontend_boundary(self):
        cases = rejection_candidates(ENTRY.read_text())
        self.assertEqual(len(cases), 6)
        self.assertEqual(len({c["name"] for c in cases}), 6)
        for case in cases:
            with self.subTest(name=case["name"]):
                analysis = analyze(case["source"], native=False, crate_type="bin")
                self.assertEqual(analysis.report["ok"], case["stage"] == "rustc")
                if case["stage"] == "frontend":
                    self.assertIsNone(analysis.rust)
                    self.assertTrue(set(case["codes"]) <= {d["code"] for d in analysis.report["diagnostics"]})

    def test_observer_requires_exact_generated_registration_sites(self):
        generated = analyze(ENTRY.read_text(), str(ENTRY), native=False, crate_type="bin").rust
        observed = instrument_generated_rust(generated)
        leaked = instrument_generated_rust(generated, leak=True)
        self.assertEqual(observed.count("__hepta_owner_observer::register(h_mode as usize, &h_data);"), 1)
        self.assertEqual(leaked.count("core::mem::forget(h_retained);"), 2)
        self.assertNotEqual(observed, generated)
        self.assertNotEqual(leaked, observed)
        with self.assertRaisesRegex(ValueError, "mutation target"):
            instrument_generated_rust(generated.replace("return h_data;", "return Vec::new();"))

    def test_existing_report_is_not_replaced_or_native_executed(self):
        with tempfile.TemporaryDirectory(prefix="hepta-composition-output-") as td:
            output = Path(td) / "result.json"
            output.write_text("keep")
            with self.assertRaisesRegex(ValueError, "new file"):
                qualify(output, rustc="missing-rustc")
            self.assertEqual(output.read_text(), "keep")

    def test_missing_tool_cannot_qualify(self):
        with tempfile.TemporaryDirectory(prefix="hepta-composition-missing-") as td:
            output = Path(td) / "failure.json"
            result = qualify(output, rustc=str(Path(td) / "absent-rustc"))
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "rejected")
            self.assertFalse(any(result["claims"].values()))
            self.assertNotIn("original", result)
            self.assertEqual(json.loads(output.read_text()), result)


RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")


@unittest.skipUnless(RUSTC, "real pinned Rust 1.90.0 is required")
class LifecycleCompositionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = qualify(rustc=RUSTC)
        if not cls.report["ok"]:
            raise AssertionError(cls.report.get("error"))

    def test_original_three_branches_execute_unmodified_generated_code(self):
        report = self.report
        self.assertEqual(report["denominator"], DENOMINATOR)
        self.assertEqual(report["branch_results"], [136, 1013, 2253])
        self.assertEqual(report["original"]["execution"]["stdout"], EXPECTED_STDOUT)
        self.assertEqual(report["original"]["execution"]["stderr"], "")
        self.assertEqual(report["original"]["execution"]["returncode"], 0)
        self.assertEqual(report["original"]["generated_source_sha256"], report["frontend"]["rust_sha256"])
        self.assertTrue(validate_report(report)["ok"])

    def test_exact_owner_addresses_free_and_native_leak_control_is_detected(self):
        positive = self.report["owner_observation"]
        negative = self.report["induced_leak_control"]
        self.assertEqual(positive["balance"], {"registered_owners": 3, "owner_bytes": 59,
            "allocations": 3, "frees": 3, "live_allocations": 0, "live_bytes": 0})
        self.assertEqual(negative["balance"], {"registered_owners": 3, "owner_bytes": 59,
            "allocations": 3, "frees": 1, "live_allocations": 2, "live_bytes": 40})
        self.assertEqual(negative["execution"]["returncode"], 91)
        self.assertNotEqual(positive["generated_source_sha256"], negative["generated_source_sha256"])
        for owner in positive["observation"]["owners"]:
            self.assertGreater(owner["address"], 0)
            self.assertEqual(owner["allocations"], owner["frees"])

    def test_rejected_lifetimes_are_metadata_only_and_profiles_stay_separate(self):
        self.assertEqual([r["codes"] for r in self.report["native_rejections"]], [["E0505"], ["E0502"]])
        for row in self.report["native_rejections"]:
            self.assertTrue(row["frontend"]["ok"])
            self.assertEqual(row["native_check"]["returncode"], 1)
            self.assertFalse(row["native_execution_attempted"])
            self.assertFalse(row["native_link_attempted"])
            self.assertFalse(row["metadata_emitted"])
        self.assertEqual(len(self.report["frontend_rejections"]), 4)
        self.assertTrue(all(not r["native_compilation_attempted"] for r in self.report["frontend_rejections"]))
        for row in self.report["unsupported_profiles"].values():
            self.assertFalse(row["ok"])
        self.assertFalse(self.report["claims"]["cancellation_latency_bounded"])

    def test_rehashed_forged_claims_counts_sources_and_execution_reject(self):
        changes = [
            lambda d: d["claims"].update(whole_language_soundness_proved=True),
            lambda d: d["claims"].update(original_generated_program_executed=1),
            lambda d: d["denominator"].update(native_lifetime_rejections=0),
            lambda d: d["original"].update(generated_source="fn main() {}"),
            lambda d: d["owner_observation"]["balance"].update(frees=4),
            lambda d: d["native_rejections"][0].update(native_execution_attempted=True),
            lambda d: d["induced_leak_control"]["execution"].update(returncode=0),
            lambda d: d["unsupported_profiles"]["executable_core"].update(ok=True),
        ]
        for change in changes:
            altered = copy.deepcopy(self.report)
            change(altered)
            with self.assertRaises(ValueError):
                validate_report(reseal(altered))


if __name__ == "__main__":
    unittest.main()
