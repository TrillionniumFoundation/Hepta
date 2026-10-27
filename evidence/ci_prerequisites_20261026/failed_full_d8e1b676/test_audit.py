"""Data-only regressions for the independent CI evidence audit."""
from copy import deepcopy
from pathlib import Path
import unittest

import performance_audit as audit
from report_audit import terminal_unit, verify_performance_inputs

ROOT = Path(__file__).resolve().parent


class PerformanceEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reports = {name: audit.parse((ROOT / "originals" / path).read_bytes()) for name, path in (
            ("scalar", "candidate/llvm_native.json"), ("owned", "candidate/llvm_owned.json"),
            ("hia", "hia-unified/performance.json"))}

    def test_three_actual_originals_recompute_without_inventing_their_outcome(self):
        for name, report in self.reports.items():
            with self.subTest(profile=name):
                result = audit.audit_performance(report, name)
                self.assertEqual(result["source_commit"], audit.CANDIDATE)
                self.assertEqual(result["evaluation"]["status"], report["status"])
                self.assertEqual(result["evaluation"]["sample_count"], len(report["raw_samples"]))

    def test_owned_library_binding_rejects_a_different_reported_binary(self):
        report = deepcopy(self.reports["owned"])
        report["raw_samples"][0]["library_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "recorded driver/library"):
            audit.audit_performance(report, "owned")

    def test_owned_consistently_wrong_checksum_still_fails_independent_digest(self):
        report = deepcopy(self.reports["owned"])
        for row in report["raw_samples"]:
            row["checksum"] = 0
            output = audit.parse(row["execution"]["stdout"])
            output["checksum"] = 0
            row["execution"]["stdout"] = audit.wire(output).decode() + "\n"
            row["execution"]["stdout_sha256"] = audit.sha(row["execution"]["stdout"].encode())
        with self.assertRaisesRegex(ValueError, "independent formula digest"):
            audit.audit_performance(report, "owned")

    def test_hia_cannot_use_the_historical_source_owned_order(self):
        report = deepcopy(self.reports["hia"])
        rows = {(row["group"], row["kernel"], row["backend"]): row for row in report["raw_samples"]}
        report["raw_samples"] = [rows[identity] for identity in audit.schedule("owned", audit.KERNELS, audit.BACKENDS, 7)]
        for index, row in enumerate(report["raw_samples"]):
            row["sample_index"] = index
        with self.assertRaisesRegex(ValueError, "sample sequence"):
            audit.audit_performance(report, "hia")

    def test_missing_sample_and_previous_candidate_are_rejected(self):
        for change in ("missing", "old_commit"):
            report = deepcopy(self.reports["scalar"])
            if change == "missing":
                report["raw_samples"].pop()
            else:
                report["git_commit"] = "7ef57d1b380e73269f592fa26fe95f9636c88586"
            with self.subTest(change=change), self.assertRaises(ValueError):
                audit.audit_performance(report, "scalar")

    def test_fresh_protocol_hash_does_not_authorize_relaxed_thresholds(self):
        report = deepcopy(self.reports["scalar"])
        report["protocol"]["maximum_relative_mad"] = 0.5
        report["protocol_sha256"] = audit.sha(audit.wire(report["protocol"]))
        with self.assertRaisesRegex(ValueError, "protocol differs"):
            audit.audit_performance(report, "scalar")

    def test_incomplete_phase_cannot_receive_full_arithmetic_attestation(self):
        report = deepcopy(self.reports["owned"])
        report["phase"] = "measurement"
        with self.assertRaisesRegex(ValueError, "incomplete report"):
            audit.audit_performance(report, "owned")

    def source_files(self):
        index = audit.parse((ROOT / "source-identities.json").read_bytes())
        return {row["git_path"]: (ROOT / row["archived_path"]).read_bytes() for row in index["files"]}

    def test_input_inventory_cannot_shrink_even_when_remaining_hashes_match(self):
        sources = self.source_files()
        for kind in ("owned", "hia"):
            report = deepcopy(self.reports[kind])
            verify_performance_inputs(report, kind, sources)
            report["inputs"].pop(next(iter(report["inputs"])))
            with self.subTest(profile=kind), self.assertRaisesRegex(ValueError, "input inventory"):
                verify_performance_inputs(report, kind, sources)

    def test_benchmark_source_metadata_is_bound_to_retained_source(self):
        sources = self.source_files()
        for kind in ("owned", "hia"):
            report = deepcopy(self.reports[kind])
            report["source_sha256"] = "0" * 64
            with self.subTest(profile=kind), self.assertRaisesRegex(ValueError, "source identity"):
                verify_performance_inputs(report, kind, sources)


class MissingEvidenceTests(unittest.TestCase):
    def test_malformed_retained_raw_is_a_parse_error_not_a_missing_file(self):
        raw = "not-a-counter\n"
        row = {"status": "unavailable", "counters": None,
               "path": audit.LINUX["visible_cgroup_cpu_stat"], "raw": raw,
               "raw_sha256": audit.sha(raw.encode()), "error": {"type": "PermissionError", "errno": 13}}
        with self.assertRaisesRegex(ValueError, "parse-failure type"):
            audit.snapshot(row, "visible_cgroup_cpu_stat")
        row["error"] = {"type": "ValueError", "errno": None}
        audit.snapshot(row, "visible_cgroup_cpu_stat")

    def test_complete_process_cannot_contain_a_capture_error(self):
        row = {"command": ["retained-not-executed"], "returncode": 0, "stdout": "", "stderr": "",
               "stdout_sha256": audit.sha(b""), "stderr_sha256": audit.sha(b""), "capture_error": "truncated"}
        with self.assertRaisesRegex(ValueError, "capture failure"):
            audit.process(row)

    def test_interrupted_unit_is_unknown_and_skip_does_not_become_zero_tests(self):
        partial = terminal_unit(b"test_one ... running\n", None)
        self.assertIsNone(partial["tests_run"])
        self.assertIsNone(partial["skipped"])
        self.assertFalse(partial["zero_skip_gate_pass"])
        skipped = terminal_unit(b"Ran 17 tests in 1.25s\n\nOK (skipped=2)\n", 0)
        self.assertEqual(skipped["tests_run"], 17)
        self.assertEqual(skipped["skipped"], 2)
        self.assertFalse(skipped["zero_skip_gate_pass"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
