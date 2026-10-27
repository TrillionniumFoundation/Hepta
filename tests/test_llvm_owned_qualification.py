"""Frozen resource metrics and tamper controls; no performance timings here."""
from __future__ import annotations

from copy import deepcopy
import base64
import json
import os
import shutil
import sys
import unittest
from unittest.mock import patch

from hepta.llvm_owned_backend import emit_owned_llvm
from hepta.pipeline import analyze
from tools import qualify_llvm_owned as q


def samples():
    return [{"group": group, "kernel": kernel, "backend": backend, "sample_index": index,
             "elapsed_ns": 100_000_000, "checksum": q.timed_checksum(kernel)}
            for index, (group, kernel, backend) in enumerate(q.sample_order())]


class OwnedQualificationPolicyTests(unittest.TestCase):
    def test_evidence_collection_changes_do_not_change_frozen_workload(self):
        frozen = json.loads((q.ROOT / "evidence/llvm-owned-native-20261025/fa4f820.v1.json").read_text())
        self.assertEqual(q.PROTOCOL, frozen["protocol"])
        self.assertEqual(q.sha(q.wire(q.PROTOCOL)), frozen["protocol_sha256"])
        self.assertEqual(q.sha(q.SOURCE.encode()), frozen["source_sha256"])
        self.assertEqual(q.sha(q.RUST_REFERENCE.encode()), frozen["handwritten_rust_sha256"])
        self.assertEqual(q.sha(q.DRIVER.encode()), frozen["driver_source_sha256"])

    def test_real_hepta_workload_has_owned_generic_and_error_lowering(self):
        result = analyze(q.SOURCE, "<owned-qualification>", native=False, crate_type="cdylib")
        self.assertTrue(result.report["ok"], result.report)
        ir = emit_owned_llvm(result.program, result.checked)
        self.assertEqual(set(ir.functions), set(q.KERNELS) | {"two_alloc"})
        self.assertIn("declare noalias ptr @malloc", ir.text)
        self.assertIn("call void @free", ir.text)
        self.assertGreater(len(ir.specializations), len(ir.functions))
        for kernel in q.KERNELS:
            self.assertIn('fn ' + kernel + '(', q.RUST_REFERENCE)

    def test_finite_oracle_covers_zero_wrap_and_capacity_rejection(self):
        self.assertEqual(q.oracle("full_lifecycle", 256, 2**32 - 1), 32640)
        self.assertEqual(q.oracle("full_lifecycle", 2, 255), 255)
        self.assertEqual(q.oracle("two_stage", 0, 90), 0)
        self.assertEqual(q.oracle("constructor_error", 0, 7), 1009)
        self.assertEqual(q.oracle("constructor_error", 2**63, 7), 1008)
        self.assertEqual(q.oracle("two_alloc", 2**64 - 1, 1), 1)
        self.assertEqual(q.correctness_record()["case_count"], 196)
        self.assertEqual(q.correctness_record()["native_calls"], 784)

    def test_frozen_order_complete_both_baselines_and_no_optional_kernel(self):
        rows = samples()
        self.assertEqual(len(rows), 63)
        result = q.evaluate_samples(rows)
        self.assertTrue(result["ok"])
        self.assertEqual(result["geometric_mean_paired_time_ratios"], {"rust": 1.0, "handwritten_rust": 1.0})
        for backend in q.BACKENDS:
            self.assertEqual(sum(row["backend"] == backend for row in rows), 21)

    def test_explicit_order_preserves_complete_groups_and_kernel_inventory(self):
        original = q.sample_order()
        order = [entry for index in range(0, len(original), 3) for entry in reversed(original[index:index + 3])]
        rows = [{"group": g, "kernel": k, "backend": b, "sample_index": i,
                 "elapsed_ns": 100_000_000, "checksum": q.timed_checksum(k)}
                for i, (g, k, b) in enumerate(order)]
        self.assertTrue(q.evaluate_samples(rows, expected_order=order)["ok"])
        with self.assertRaisesRegex(ValueError, "sample order/identity"):
            q.evaluate_samples(rows)
        duplicate = list(order)
        duplicate[1] = duplicate[0]
        boolean = list(order)
        boolean[0] = (False, *boolean[0][1:])
        wrong_kernel = list(order)
        wrong_kernel[0] = (0, q.KERNELS[1], wrong_kernel[0][2])
        for bad in (order[:-1], list(reversed(order)), duplicate, boolean, wrong_kernel, [None] * 63):
            with self.subTest(first=bad[0]), self.assertRaises(ValueError):
                q.evaluate_samples(rows, expected_order=bad)

    def test_rejects_missing_reordered_duplicate_boolean_and_wrong_native_result(self):
        candidates = [samples()[:-1], list(reversed(samples()))]
        duplicate = samples()
        duplicate[1] = deepcopy(duplicate[0])
        candidates.append(duplicate)
        for key, value in (("elapsed_ns", True), ("elapsed_ns", 0), ("checksum", 1), ("sample_index", False)):
            rows = samples()
            rows[0][key] = value
            candidates.append(rows)
        for rows in candidates:
            with self.subTest(first=rows[0]), self.assertRaises(ValueError):
                q.evaluate_samples(rows)

    def test_each_rust_baseline_is_a_gate_and_noise_is_never_passed(self):
        for baseline in ("rust", "handwritten_rust"):
            rows = samples()
            for row in rows:
                if row["backend"] == baseline:
                    row["elapsed_ns"] = 70_000_000
            result = q.evaluate_samples(rows)
            self.assertEqual(result["status"], "performance_failed")
            self.assertTrue(result["performance_threshold_failures"])
        rows = samples()
        for row in rows:
            if row["backend"] == "llvm":
                row["elapsed_ns"] = (100, 100, 110, 120, 130, 140, 150)[row["group"]] * 1_000_000
        self.assertEqual(q.evaluate_samples(rows)["status"], "measurement_inconclusive")
        for elapsed in (49_999_999, 30_000_000_001):
            rows = samples()
            rows[0]["elapsed_ns"] = elapsed
            self.assertEqual(q.evaluate_samples(rows)["status"], "measurement_inconclusive")


class OwnedFailureCaptureTests(unittest.TestCase):
    def test_nonzero_process_preserves_complete_bounded_outputs(self):
        record = q.execute([sys.executable, "-c",
            'import sys;print("o"*5000);sys.stderr.write("e"*6000);sys.exit(23)'])
        self.assertEqual(record["returncode"], 23)
        self.assertEqual(record["stdout"], "o" * 5000 + "\n")
        self.assertEqual(record["stderr"], "e" * 6000)
        with self.assertRaises(q.NativeCommandFailed) as caught:
            q.successful(record)
        self.assertEqual(caught.exception.record, record)

    def test_timeout_retains_raw_invalid_utf8_and_actual_kill_status(self):
        record = q.execute([sys.executable, "-c",
            'import os,time;os.write(1,b"partial\\xff\\n");os.write(2,b"error\\x00");time.sleep(20)'],
            timeout=.5)
        self.assertEqual(record["capture_error"]["code"], "E_CAPTURE_TIMEOUT")
        self.assertTrue(record["capture_available"])
        self.assertIs(type(record["returncode"]), int)
        self.assertLess(record["returncode"], 0)
        for channel, expected in (("stdout", b"partial\xff\n"), ("stderr", b"error\x00")):
            capture = record[channel + "_raw"]
            self.assertEqual(base64.b64decode(capture["prefix_base64"]), expected)
            self.assertEqual(capture["prefix_sha256"], q.sha(expected))
            self.assertEqual(capture["total_bytes"], len(expected))
            self.assertEqual(capture["retained_bytes"], len(expected))
            self.assertIs(capture["truncated"], False)
        with self.assertRaises(q.NativeCommandFailed):
            q.successful(record)

    def test_output_limit_and_encoding_errors_cannot_claim_complete_capture(self):
        noisy = q.execute([sys.executable, "-c", 'import os;os.write(1,b"x"*140000)'])
        self.assertEqual(noisy["capture_error"]["code"], "E_CAPTURE_OUTPUT_SIZE")
        capture = noisy["stdout_raw"]
        self.assertEqual(capture["retained_bytes"], 128000)
        self.assertEqual(len(base64.b64decode(capture["prefix_base64"])), 128000)
        self.assertEqual(capture["total_bytes"], 140000)
        self.assertIs(capture["truncated"], True)
        with self.assertRaises(q.NativeCommandFailed):
            q.successful(noisy)
        encoded = q.execute([sys.executable, "-c", 'import os;os.write(1,b"\\xff")'])
        self.assertEqual(encoded["returncode"], 0)
        self.assertEqual(encoded["capture_error"]["code"], "E_CAPTURE_ENCODING")
        self.assertEqual(base64.b64decode(encoded["stdout_raw"]["prefix_base64"]), b"\xff")
        with self.assertRaises(q.NativeCommandFailed):
            q.successful(encoded)


@unittest.skipUnless(shutil.which("clang") and shutil.which("gcc")
                     and shutil.which(os.environ.get("RUSTC", "rustc")),
                     "native evidence regression requires Clang, GCC and pinned Rust")
class OwnedEvidenceNativeTests(unittest.TestCase):
    def test_mid_measurement_failure_keeps_completed_and_failed_process_evidence(self):
        execute, attempted = q.execute, []
        def interrupted(argv, **kwargs):
            command = list(map(str, argv))
            if command[:5] == ["git", "-C", str(q.ROOT), "status", "--porcelain"]:
                output, error, code = "", "", 0
            elif len(command) == 3 and command[0].endswith("/driver") and command[2] in q.KERNELS:
                attempted.append(command)
                if len(attempted) == 3:
                    output, error, code = "failed-native-output\n" * 300, "failed-native-error\n" * 400, 27
                else:
                    output = json.dumps({"elapsed_ns": 100_000_000, "checksum": q.timed_checksum(command[2]),
                                         "clock_resolution_ns": 1, "process_peak_rss_kib": 1000}) + "\n"
                    error, code = "", 0
            else:
                return execute(argv, **kwargs)
            return {"command": command, "returncode": code, "stdout": output, "stderr": error,
                    "stdout_sha256": q.sha(output.encode()), "stderr_sha256": q.sha(error.encode())}
        with patch.object(q, "execute", side_effect=interrupted):
            report = q.qualify()
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["phase"], "measurement")
        self.assertEqual(len(attempted), 3)
        self.assertEqual(len(report["raw_samples"]), 2)
        self.assertEqual(len(report["process_observations"]), 3)
        self.assertEqual(report["process_observations"][-1]["sample"]["sample_index"], 2)
        for index, row in enumerate(report["raw_samples"]):
            self.assertEqual(row["sample_index"], index)
            self.assertEqual(json.loads(row["execution"]["stdout"])["checksum"], q.timed_checksum(row["kernel"]))
        failure = report["failed_command"]
        self.assertEqual(failure["returncode"], 27)
        self.assertEqual(failure["stdout"], "failed-native-output\n" * 300)
        self.assertEqual(failure["stderr"], "failed-native-error\n" * 400)
        self.assertEqual(report["failed_sample"]["execution"], failure)
        self.assertEqual(report["failed_sample"]["sample_index"], 2)
        self.assertEqual(report["resource_observation"]["status"], "passed")
        with self.assertRaises(ValueError):
            q.validate_report(report)

    def test_actual_build_correctness_and_validator_with_explicitly_simulated_timings(self):
        # Compiler builds, finite execution, allocator refusal and leak detection
        # are real. Only performance subprocesses are replaced, to test evidence
        # relationships without collecting/publishing pre-protocol timings.
        execute = q.execute
        intercepted = []
        def simulated(argv, **kwargs):
            command = list(map(str, argv))
            if command[:5] == ["git", "-C", str(q.ROOT), "status", "--porcelain"]:
                output = ""
            elif len(command) == 3 and command[0].endswith("/driver") and command[2] in q.KERNELS:
                intercepted.append(command)
                output = json.dumps({"elapsed_ns": 100_000_000, "checksum": q.timed_checksum(command[2]),
                                     "clock_resolution_ns": 1, "process_peak_rss_kib": 1000}) + "\n"
            else:
                return execute(argv, **kwargs)
            return {"command": command, "returncode": 0, "stdout": output, "stderr": "",
                    "stdout_sha256": q.sha(output.encode()), "stderr_sha256": q.sha(b"")}
        with patch.object(q, "execute", side_effect=simulated):
            report = q.qualify()
        self.assertTrue(report["ok"], report.get("diagnostic", report.get("evaluation")))
        self.assertEqual(len(intercepted), 63)
        self.assertEqual(len(report["process_observations"]), 63)
        q.validate_report(report, expected_git_commit=report["git_commit"])
        candidates = []
        for field in ("source_sha256", "compiler_tree_sha256", "driver_source_sha256"):
            candidate = deepcopy(report)
            candidate[field] = "0" * 64
            candidates.append(candidate)
        candidate = deepcopy(report)
        candidate["native_receipts"]["llvm_library"]["claims"]["fallback_used"] = True
        candidates.append(candidate)
        candidate = deepcopy(report)
        candidate["native_receipts"]["handwritten_rust_library"]["rust_sha256"] = report["generated_rust_sha256"]
        candidates.append(candidate)
        candidate = deepcopy(report)
        candidate["resource_observation"]["negative"] = deepcopy(candidate["resource_observation"]["positive"])
        candidates.append(candidate)
        candidate = deepcopy(report)
        candidate["correctness"]["case_count"] -= 1
        candidates.append(candidate)
        candidate = deepcopy(report)
        candidate["raw_samples"].pop()
        candidates.append(candidate)
        candidate = deepcopy(report)
        candidate["raw_samples"][0]["elapsed_ns"] = 1
        candidate["evaluation"] = q.evaluate_samples(candidate["raw_samples"])
        candidates.append(candidate)
        candidate = deepcopy(report)
        candidate["raw_samples"][0]["library_sha256"] = "0" * 64
        candidates.append(candidate)
        for mutate in (
            lambda r: r["process_observations"].pop(),
            lambda r: r["process_observations"].reverse(),
            lambda r: r["process_observations"][0]["scope"].update(native_elapsed_replaced=True),
            lambda r: r["process_observations"][0]["children"]["delta"].update(system_cpu_ns=-1),
            lambda r: r["inputs"].update({"tools/performance_observation.py": "0" * 64}),
        ):
            candidate = deepcopy(report)
            mutate(candidate)
            candidates.append(candidate)
        for index, candidate in enumerate(candidates):
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                q.validate_report(candidate)
        # A faithfully represented inconclusive attempt remains auditable, but
        # release validation rejects it even when somebody sets outer ok=True.
        candidate = deepcopy(report)
        row = candidate["raw_samples"][0]
        row["elapsed_ns"] = 1
        output = json.loads(row["execution"]["stdout"])
        output["elapsed_ns"] = 1
        row["execution"]["stdout"] = json.dumps(output)
        row["execution"]["stdout_sha256"] = q.sha(row["execution"]["stdout"].encode())
        candidate["evaluation"] = q.evaluate_samples(candidate["raw_samples"])
        candidate["ok"], candidate["status"] = False, "measurement_inconclusive"
        candidate["claims"]["host_owned_performance_gate_passed"] = False
        q.validate_report(candidate, require_pass=False)
        with self.assertRaises(ValueError):
            q.validate_report(candidate)
        candidate["ok"] = True
        with self.assertRaises(ValueError):
            q.validate_report(candidate, require_pass=False)


if __name__ == "__main__":
    unittest.main()
