"""Native application/oracle qualification and cost-evidence rejection gates."""
import copy
import base64
import os
import shutil
import sys
import unittest

from tools.benchmark_applications import (
    Commands, _latencies, allocation_profile, reference_result, run_qualification, validate_application_report,
)

RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")


class ApplicationOracleTests(unittest.TestCase):
    def test_actual_timeout_retains_partial_execution_output(self):
        commands = Commands()
        with self.assertRaisesRegex(RuntimeError, "partial output retained"):
            commands.run([sys.executable, "-c", "import time;print('native-request-prefix',flush=True);time.sleep(5)"], timeout=.3)
        self.assertEqual(len(commands.records), 1)
        record = commands.records[0]
        self.assertEqual(record["status"], "timeout")
        self.assertIsNone(record["returncode"])
        self.assertIn(b"native-request-prefix", base64.b64decode(record["partial_stdout_base64"]))

    def test_known_packet_and_transform_results(self):
        self.assertEqual(reference_result("packet", 17, 1040), {
            "status": 0, "reserved": 0, "bytes": 1088, "records": 17, "checksum": 2462492060148343815})
        self.assertEqual(reference_result("transform", 17, 1040), {
            "status": 0, "reserved": 0, "bytes": 4352, "records": 17, "checksum": 10050522073513462605})

    def test_distinct_packet_errors_and_transform_header_rejection(self):
        for request, error in [(1041, 2), (1042, 3), (1043, 4)]:
            with self.subTest(request=request):
                result = reference_result("packet", 17, request)
                self.assertEqual((result["status"], result["bytes"], result["records"]), (error, 512, 8))
        self.assertEqual(reference_result("transform", 17, 1041), {
            "status": 2, "reserved": 0, "bytes": 0, "records": 0, "checksum": 0})

    def test_failure_phase_counts_and_cleanup_bytes(self):
        packet = allocation_profile("packet", 17, 1040, 2)
        self.assertEqual((packet["attempts"], packet["allocations"], packet["frees"], packet["failures"],
                          packet["attempted_bytes"], packet["allocated_bytes"], packet["peak_live_bytes"], packet["live_bytes"]),
                         (2, 1, 1, 1, 1344, 1088, 1088, 0))
        transformed = allocation_profile("transform", 17, 1040, 3)
        self.assertEqual((transformed["attempts"], transformed["allocations"], transformed["frees"], transformed["failures"],
                          transformed["attempted_bytes"], transformed["allocated_bytes"], transformed["peak_live_bytes"], transformed["live_bytes"]),
                         (3, 2, 2, 1, 8964, 4612, 4612, 0))
        # Invalid input stops before the second allocation, so a refusal armed
        # for that nonexistent phase must not be counted as an observed failure.
        self.assertEqual(allocation_profile("transform", 17, 1041, 2)["failures"], 0)

    def test_quantiles_are_nearest_rank_and_throughput_uses_all_service_times(self):
        observed = _latencies(list(range(100, 0, -1)))
        self.assertEqual((observed["p50_ns"], observed["p95_ns"], observed["p99_ns"], observed["max_ns"]), (50, 95, 99, 100))
        self.assertEqual(observed["mean_ns"], 50.5)
        self.assertEqual(observed["service_requests_per_second"], 1_000_000_000 / 50.5)


@unittest.skipUnless(RUSTC, "requires the pinned native Rust compiler")
class NativeApplicationQualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_qualification(rustc=RUSTC, trials=1, requests=8, warmups=0)
        if cls.report["status"] != "passed":
            raise AssertionError(cls.report.get("error", "native qualification failed"))

    @staticmethod
    def validate(report):
        validate_application_report(report, minimum_trials=1, minimum_requests=8, minimum_warmups=0)

    def test_real_three_implementation_denominators_and_wrong_binary_control(self):
        self.validate(self.report)
        self.assertEqual(sum(len(batch["samples"]) for batch in self.report["correctness"]), 240)
        self.assertEqual(sum(len(batch["samples"]) for batch in self.report["fault_recovery"]), 30)
        self.assertEqual(sum(len(batch["samples"]) for batch in self.report["measurements"]), 144)
        self.assertEqual(self.report["negative_control"]["returncode"], 41)
        self.assertFalse(self.report["builds"]["hepta_c"]["native"]["rustc_used"])

    def test_development_run_cannot_pass_full_release_thresholds(self):
        with self.assertRaises(ValueError):
            validate_application_report(self.report)

    def test_rejects_missing_execution_stale_sources_false_claims_and_changed_costs(self):
        changes = [
            lambda r: r.update(compiler_sha256="0" * 64),
            lambda r: r["sources"].update({"benchmarks/applications.rs": "0" * 64}),
            lambda r: r["claims"].update(uninstrumented_production_latency_measured=True),
            lambda r: r["claims"].update(multiple_machines_measured=True),
            lambda r: r["timing_contract"]["includes"].remove("allocation_instrumentation"),
            lambda r: r.update(trials=True),
            lambda r: r.update(requests_per_trial=4096),
            lambda r: r.update(profile="full"),
            lambda r: r["builds"]["common"].pop("meter"),
            lambda r: r["builds"]["common"]["driver"].update(object_bytes=0),
            lambda r: r["builds"]["hepta_c"]["native"].update(rustc_used=True),
            lambda r: r["builds"]["hepta_c"]["native"].update(check_only=True),
            lambda r: r["builds"]["hepta_c"]["native"].update(optimization_profile="unroll"),
            lambda r: r["builds"]["hepta_c"]["analysis"].update(checks={}),
            lambda r: r["builds"]["hepta_rust"]["native"].update(flags=None),
            lambda r: r["builds"]["hepta_rust"]["analysis"].update(backend={}),
            lambda r: r["builds"]["rust"].update(allocator_sha256="0" * 64),
            lambda r: r["builds"]["rust"]["link"]["inputs"].update(meter="0" * 64),
            lambda r: r["correctness"].pop(),
            lambda r: r["correctness"][0].update(units=False),
            lambda r: r["correctness"][1]["samples"][0]["result"].update(checksum=0),
            lambda r: r["fault_recovery"].clear(),
            lambda r: r["fault_recovery"][0]["samples"][0]["allocation"].update(failures=0),
            lambda r: r["fault_recovery"][0]["samples"][1]["allocation"].update(live_bytes=1),
            lambda r: r["measurements"].append(r["measurements"][0]),
            lambda r: r["measurements"].__setitem__(0, None),
            lambda r: r["measurements"][0]["samples"].pop(),
            lambda r: r["measurements"][0]["samples"][0].update(request_id=0),
            lambda r: r["measurements"][0]["samples"][0].update(elapsed_ns=0),
            lambda r: r["measurements"][0]["samples"][0].update(oracle_checked=False),
            lambda r: r["measurements"][0]["samples"][0]["allocation"].update(allocations=True),
            lambda r: r["measurements"][0]["samples"][0]["allocation"].update(peak_live_bytes=0),
            lambda r: r["measurements"][0].update(returncode=True),
            lambda r: r["measurements"][0].update(stdout_sha256="0" * 64),
            lambda r: r["measurements"][0].update(executable_sha256="0" * 64),
            lambda r: r["measurements"][0]["process"].update(rss_peak_kib=-1),
            lambda r: r["measurements"][0]["process"].update(rss_vm_hwm_peak_kib=0),
            lambda r: r["measurements"][0]["process"].update(warmup_checksum=0),
            lambda r: r["execution_order"][0]["implementations"].reverse(),
            lambda r: r["execution_order"][0].update(trial=False),
            lambda r: r["summary"][0]["implementations"]["rust"]["latency"].update(p99_ns=1),
            lambda r: r["summary"][0]["implementations"]["rust"].update(every_request_clean=1),
            lambda r: r["summary"][0]["implementations"]["rust"]["allocation_totals"].update(allocated_bytes=0),
            lambda r: r["negative_control"].update(returncode=0),
            lambda r: r["builds"]["wrong"].update(link_returncode=True),
            lambda r: r["builds"]["wrong"].update(executable_bytes=0),
        ]
        for number, change in enumerate(changes):
            with self.subTest(mutation=number):
                report = copy.deepcopy(self.report)
                change(report)
                with self.assertRaises(ValueError):
                    self.validate(report)

    def test_all_observed_slowdowns_are_required_even_when_the_native_run_is_fast(self):
        report = copy.deepcopy(self.report)
        # Fabricating one report entry is rejected whether this particular
        # shared-host sample happened to contain any slower implementation.
        report["all_observed_slowdowns"].append({"application": "packet", "observed_time_ratio": 999})
        with self.assertRaises(ValueError):
            self.validate(report)
        if self.report["all_observed_slowdowns"]:
            report = copy.deepcopy(self.report)
            report["all_observed_slowdowns"].pop()
            with self.assertRaises(ValueError):
                self.validate(report)


if __name__ == "__main__":
    unittest.main()
