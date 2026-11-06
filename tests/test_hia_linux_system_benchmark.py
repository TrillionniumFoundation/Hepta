"""Synthetic parser counterexamples; no fixture is a guest execution or benchmark result."""
import copy
import hashlib
import json
import unittest

from tools import hia_linux_system_benchmark as bench

RUN_ID = "0123456789abcdef01234567"
RELEASE = "6.18.60"
ARGV = ["/synthetic/qemu", "-accel", "tcg,thread=multi", "-kernel", "/synthetic/kernel"]
CONFIG = "# CONFIG_TRANSPARENT_HUGEPAGE is not set\n"
VECTORS = [{"seed":20261106,"iterations":1024,"expected":{"syscall_process_pipe":"65a7758612115fc2","anonymous_memory":"95acb6cc5d3f76b1","tmpfs_files":"bc8f609dbd15c4f5","unix_tcp":"76a7abed2ac215e7"}},{"seed":4294967295,"iterations":64,"expected":{"syscall_process_pipe":"8a9eac67cf09cd21","anonymous_memory":"9b1898198a6b9ae1","tmpfs_files":"3b4a1e2d4caafc47","unix_tcp":"233943b70ae61f4a"}}]


def text_identity(text):
    data = text.encode("utf-8")
    return {"path": "/synthetic/log", "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def synthetic_records(selection="all", seed=20261106, iterations=64):
    chosen = bench.selected_phases(selection)
    checksums = bench.expected_checksums(seed, iterations, selection)
    begin = {
        "event": "begin", "protocol": bench.PROTOCOL, "run_id": RUN_ID, "pid": 1,
        "seed": seed, "iterations": iterations, "release": RELEASE, "machine": "x86_64",
        "clock": "CLOCK_MONOTONIC_RAW", "cpu_affinity": [0], "online_cpus": 2,
        "page_bytes": 4096, "file_bytes": 4096,
        "hugepage_policy": bench.expected_hugepage_policy(CONFIG, selection),
        "deadline_seconds": 180, "selection": selection, "stage_count": len(chosen),
        "defined_stage_count": 4, "warmups_per_stage": 2, "measured_per_stage": 5,
        "expected_samples": len(chosen)*7, "dmi_vendor": "QEMU",
        "dmi_product": "Synthetic parser fixture, not an executed VM",
    }
    rows = [begin]
    for phase in chosen:
        for local in range(7):
            sequence = len(rows)-1
            usage = dict.fromkeys(bench.USAGE_KEYS, 0)
            usage.update(maxrss_before_kib=1024, maxrss_after_kib=2048)
            rows.append({
                "event": "sample", "run_id": RUN_ID, "sequence": sequence, "stage": phase,
                "warmup": local < 2, "sample_index": local if local < 2 else local-2,
                "operation_count": iterations*(2 if phase == "unix_tcp" else 1),
                "operation_unit": bench.UNITS[phase], "duration_ns": 1000+sequence,
                "checksum": checksums[phase], "expected_checksum": checksums[phase],
                "correctness": True, "errno": 0, "reason": "ok",
                "self_rusage_delta": copy.deepcopy(usage),
                "children_rusage_delta": copy.deepcopy(usage),
            })
    rows.append({"event": "summary", "run_id": RUN_ID, "status": "PASS", "selection": selection,
                 "aborted": False, "expected_samples": len(chosen)*7,
                 "emitted_samples": len(chosen)*7, "successful_samples": len(chosen)*7,
                 "completed_stages": len(chosen), "warmups_per_stage": 2,
                 "measured_per_stage": 5, "shutdown_required": True})
    return rows


def serialize(rows, ending="[synthetic] reboot: Power down\n"):
    return "".join(bench.PREFIX+json.dumps(row, separators=(",", ":"))+"\n" for row in rows)+ending


def receipt(text):
    return {"argv": ARGV.copy(), "exit_code": 0, "timed_out": False, "process_group": 12345,
            "process_group_cleanup": {"group": 12345, "scope": "owned_linux_process_group",
                                      "drained": True, "signals": [], "live_members_after": [],
                                      "errors": [], "elapsed_ns": 123},
            "stdout": text_identity(text), "stderr": text_identity("")}


def admit(rows=None, *, text=None, command=None, selection="all", seed=20261106,
          iterations=64, config=CONFIG, expected_argv=None, stderr=""):
    text = serialize(rows if rows is not None else synthetic_records(selection, seed, iterations)) if text is None else text
    return bench.parse_serial(text, run_id=RUN_ID, seed=seed, iterations=iterations,
                              selection=selection, expected_release=RELEASE, config_text=config,
                              command_receipt=receipt(text) if command is None else command,
                              expected_argv=ARGV if expected_argv is None else expected_argv,
                              stderr_text=stderr)


class BenchmarkAdmissionTests(unittest.TestCase):
    def test_literal_checksum_vectors_computed_in_independent_uint64_implementation(self):
        for vector in VECTORS:
            with self.subTest(seed=vector["seed"]):
                self.assertEqual(vector["expected"], bench.expected_checksums(
                    vector["seed"], vector["iterations"], "all"))

    def test_closed_all_phase_fixture(self):
        verdict = admit()
        self.assertEqual("PASS", verdict["status"], verdict["errors"])
        self.assertEqual(28, len(verdict["samples"]))
        self.assertEqual(5, len(verdict["measured_samples"]["tmpfs_files"]))

    def test_each_single_phase_contains_only_seven_samples(self):
        for phase in bench.PHASES:
            with self.subTest(phase=phase):
                verdict = admit(selection=phase, seed=0xffffffff)
                self.assertEqual("PASS", verdict["status"], verdict["errors"])
                self.assertEqual(7, len(verdict["samples"]))
                self.assertEqual({phase}, set(verdict["measured_samples"]))

    def test_wrong_observed_identities_and_counts_rejected(self):
        changes = {"run_id": "f"*24, "seed": 1, "iterations": 65, "release": "wrong",
                   "pid": True, "clock": "CLOCK_MONOTONIC", "online_cpus": 1,
                   "cpu_affinity": [False], "expected_samples": 27, "stage_count": 3}
        for key, value in changes.items():
            with self.subTest(key=key):
                rows = synthetic_records(); rows[0][key] = value
                self.assertEqual("FAIL", admit(rows)["status"])

    def test_partial_duplicate_or_extra_samples_rejected(self):
        rows = synthetic_records()
        cases = [rows[:-2]+rows[-1:], rows[:2]+[copy.deepcopy(rows[1])]+rows[2:],
                 rows+[{"event": "error", "reason": "late"}]]
        for changed in cases:
            self.assertEqual("FAIL", admit(changed)["status"])

    def test_schedule_mutations_rejected(self):
        changes = {"sequence": 9, "stage": "unix_tcp", "warmup": False, "sample_index": 1,
                   "operation_count": 65, "operation_unit": "syscalls", "correctness": False,
                   "errno": 5, "reason": "not_ok"}
        for key, value in changes.items():
            with self.subTest(key=key):
                rows = synthetic_records(); rows[1][key] = value
                self.assertEqual("FAIL", admit(rows)["status"])

    def test_forged_expected_and_actual_checksum_cannot_agree_their_way_to_pass(self):
        rows = synthetic_records()
        rows[1]["checksum"] = rows[1]["expected_checksum"] = "0000000000000000"
        self.assertEqual("FAIL", admit(rows)["status"])

    def test_invalid_duration_types_and_values_rejected(self):
        for value in (0, -1, True, 1.5, 180000000001):
            with self.subTest(value=value):
                rows = synthetic_records(); rows[1]["duration_ns"] = value
                self.assertEqual("FAIL", admit(rows)["status"])

    def test_rusage_missing_negative_boolean_and_regressing_peak_rejected(self):
        for mutation in ("missing", "negative", "bool", "peak"):
            rows = synthetic_records()
            usage = rows[1]["children_rusage_delta"]
            if mutation == "missing": del usage["minor_faults"]
            if mutation == "negative": usage["minor_faults"] = -1
            if mutation == "bool": usage["user_ns"] = True
            if mutation == "peak": usage["maxrss_after_kib"] = 1
            self.assertEqual("FAIL", admit(rows)["status"])

    def test_summary_bool_counts_or_incomplete_stage_rejected(self):
        changes = {"status": "FAIL", "aborted": True, "completed_stages": True,
                   "successful_samples": 27, "shutdown_required": 1, "emitted_samples": 29}
        for key, value in changes.items():
            rows = synthetic_records(); rows[-1][key] = value
            self.assertEqual("FAIL", admit(rows)["status"])

    def test_raw_receipt_hashes_bind_unedited_full_logs(self):
        original = serialize(synthetic_records())
        command = receipt(original)
        self.assertEqual("FAIL", admit(text=original+"changed\n", command=command)["status"])
        self.assertEqual("FAIL", admit(text=original, command=command, stderr="new stderr")["status"])

    def test_raw_crlf_logs_admit_without_newline_rewriting(self):
        raw = serialize(synthetic_records()).replace("\n", "\r\n")
        self.assertEqual("PASS", admit(text=raw)["status"])
        self.assertEqual("FAIL", admit(text=raw.replace("\r\n", "\n"), command=receipt(raw))["status"])

    def test_missing_or_premature_powerdown_rejected(self):
        rows = synthetic_records()
        self.assertEqual("FAIL", admit(text=serialize(rows, ""))["status"])
        self.assertEqual("FAIL", admit(text="reboot: Power down\n"+serialize(rows, ""))["status"])

    def test_unknown_fields_duplicate_keys_and_nan_rejected(self):
        rows = synthetic_records(); rows[1]["extra"] = 0
        self.assertEqual("FAIL", admit(rows)["status"])
        text = serialize(synthetic_records()).replace('"pid":1', '"pid":1,"pid":1', 1)
        self.assertEqual("FAIL", admit(text=text)["status"])
        text = serialize(synthetic_records()).replace('"duration_ns":1000', '"duration_ns":NaN', 1)
        self.assertEqual("FAIL", admit(text=text)["status"])

    def test_failed_or_unproven_process_group_rejected(self):
        text = serialize(synthetic_records())
        candidates = []
        for key, value in (("exit_code", 1), ("timed_out", True), ("cancelled", True),
                           ("incomplete_process_group", True), ("process_group", True)):
            changed = receipt(text); changed[key] = value; candidates.append(changed)
        changed = receipt(text); del changed["process_group_cleanup"]; candidates.append(changed)
        for key, value in (("group", 54321), ("drained", False), ("signals", ["SIGTERM"]),
                           ("errors", ["unobserved"]), ("live_members_after", [{"pid": 2}]),
                           ("elapsed_ns", True)):
            changed = receipt(text); changed["process_group_cleanup"][key] = value; candidates.append(changed)
        for command in candidates:
            self.assertEqual("FAIL", admit(text=text, command=command)["status"])

    def test_frozen_argv_binding_rejected_on_change(self):
        self.assertEqual("FAIL", admit(expected_argv=ARGV+["-changed"])["status"])

    def test_thp_policy_must_match_exact_config(self):
        self.assertEqual("FAIL", admit(config="CONFIG_TRANSPARENT_HUGEPAGE=y\n")["status"])
        rows = synthetic_records(); rows[0]["hugepage_policy"] = "madvise_nohugepage"
        self.assertEqual("FAIL", admit(rows)["status"])
        self.assertEqual("PASS", admit(rows, config="CONFIG_TRANSPARENT_HUGEPAGE=y\n")["status"])
        rows = synthetic_records("unix_tcp"); rows[0]["hugepage_policy"] = "kernel_not_exposed"
        self.assertEqual("FAIL", admit(rows, selection="unix_tcp")["status"])

    def test_duplicate_config_and_invalid_budget_rejected(self):
        self.assertEqual("FAIL", admit(config="CONFIG_TRANSPARENT_HUGEPAGE=y\nCONFIG_TRANSPARENT_HUGEPAGE=n\n")["status"])
        for seed, iterations in ((True, 64), (-1, 64), (2**32, 64), (1, True), (1, 63), (1, 8193)):
            with self.subTest(seed=seed, iterations=iterations):
                with self.assertRaises(ValueError):
                    bench.expected_checksums(seed, iterations)

    def test_qemu_profiles_are_explicit_and_separate(self):
        arguments = dict(qemu="/qemu", qemu_data="/data", bios="/bios", kernel="/kernel",
                         initramfs="/initramfs", run_id=RUN_ID, expected_release=RELEASE,
                         seed=20261106, iterations=64, selection="unix_tcp")
        tcg = bench.qemu_argv(profile="tcg", **arguments)
        kvm = bench.qemu_argv(profile="kvm", **arguments)
        self.assertEqual("tcg,thread=multi", tcg[tcg.index("-accel")+1])
        self.assertEqual("kvm", kvm[kvm.index("-accel")+1])
        self.assertEqual("qemu64,-popcnt,-svm", kvm[kvm.index("-cpu")+1])
        self.assertIn("hia_phase=unix_tcp", kvm[-1])
        for argv in (tcg, kvm):
            self.assertEqual(["loglevel=5"], [item for item in argv[-1].split() if item.startswith("loglevel=")])
            self.assertNotIn("quiet", argv[-1].split())
        with self.assertRaises(ValueError):
            bench.qemu_argv(profile="unqualified", **arguments)


    def test_host_affinity_rejects_outside_duplicate_and_boolean_cpu(self):
        self.assertEqual(((2, 4), (0, 2, 4)), bench.normalize_host_cpus((4, 2), {0, 2, 4}))
        self.assertEqual((None, (0, 2)), bench.normalize_host_cpus(None, {0, 2}))
        for requested in ((3,), (2, 2), (True,), ()):
            with self.subTest(requested=requested):
                with self.assertRaises(ValueError):
                    bench.normalize_host_cpus(requested, {0, 2, 4})


if __name__ == "__main__":
    unittest.main()
