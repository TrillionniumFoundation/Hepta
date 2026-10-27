"""Process telemetry tests use short subprocesses, never benchmark workloads."""
from copy import deepcopy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import performance_observation as observation


class ProcessObservationTests(unittest.TestCase):
    def collect(self, count=2):
        records, expected = [], []
        for index in range(count):
            command = [sys.executable, "-c", "print(sum(range(10000)))"]
            sample = {"sample_index": index, "group": 0, "kernel": "short_process", "backend": "test"}
            result = observation.observe_call(records, command, sample,
                lambda: subprocess.run(command, text=True, capture_output=True, check=True, timeout=10))
            self.assertEqual(result.stdout, "49995000\n")
            expected.append({"sample": sample, "command": command})
        return records, expected

    def test_actual_short_children_are_observed_without_replacing_native_timing(self):
        records, expected = self.collect()
        observation.validate_observations(records, expected)
        for record in records:
            self.assertNotIn("elapsed_ns", record)
            if observation.resource is None:
                self.assertEqual(record["children"]["status"], "unavailable")
            else:
                self.assertEqual(set(record["children"]["after"]["counters"]), set(observation.RUSAGE_FIELDS))
            self.assertIs(record["scope"]["native_elapsed_replaced"], False)
            self.assertIs(record["scope"]["measurement_cause_proved"], False)
        self.assertLessEqual(records[0]["clock"]["end_monotonic_ns"], records[1]["clock"]["start_monotonic_ns"])

    def test_failed_capture_keeps_observation_and_propagates_original_exception(self):
        records = []
        command = [sys.executable, "-c", "raise SystemExit(17)"]
        sample = {"sample_index": 0, "group": 0, "kernel": "short_process", "backend": "test"}
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            observation.observe_call(records, command, sample,
                lambda: subprocess.run(command, capture_output=True, check=True, timeout=10))
        self.assertEqual(caught.exception.returncode, 17)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["state"], "complete")
        self.assertEqual(records[0]["capture_exception"], "CalledProcessError")
        self.assertGreaterEqual(records[0]["clock"]["wall_ns"], 0)
        with self.assertRaises(ValueError):
            observation.validate_observations(records, [{"sample": sample, "command": command}])

    def test_kernel_snapshots_preserve_raw_counters_and_unavailable_is_not_zero(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cpu.stat"
            raw = "usage_usec 81\nuser_usec 51\nsystem_usec 30\nnr_throttled 2\nthrottled_usec 6\n"
            path.write_text(raw)
            snapshot = observation._linux("visible_cgroup_cpu_stat", str(path))
            self.assertEqual(snapshot["status"], "observed")
            self.assertEqual(snapshot["raw"], raw)
            self.assertEqual(snapshot["raw_sha256"], hashlib.sha256(raw.encode()).hexdigest())
            self.assertEqual(snapshot["counters"], {"usage_usec": 81, "user_usec": 51,
                "system_usec": 30, "nr_throttled": 2, "throttled_usec": 6})
            path.unlink()
            missing = observation._linux("visible_cgroup_cpu_stat", str(path))
            self.assertEqual(missing["status"], "unavailable")
            self.assertIsNone(missing["raw"])
            self.assertIsNone(missing["counters"])
            self.assertEqual(missing["error"]["type"], "FileNotFoundError")
            path.write_text("usage_usec nan\n")
            malformed = observation._linux("visible_cgroup_cpu_stat", str(path))
            self.assertEqual(malformed["status"], "unavailable")
            self.assertEqual(malformed["raw"], "usage_usec nan\n")
            self.assertIsNone(malformed["counters"])

    def test_pressure_retains_average_text_but_differences_only_cumulative_totals(self):
        raw = "some avg10=1.25 avg60=0.60 avg300=0.11 total=12345\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=71\n"
        self.assertEqual(observation._parse_linux("host_cpu_pressure", raw),
                         {"some.total_us": 12345, "full.total_us": 71})
        for malformed in (raw + raw, raw.replace("1.25", "nan"), raw.replace("total=71", "total=-1")):
            with self.assertRaises(ValueError):
                observation._parse_linux("host_cpu_pressure", malformed)

    def test_missing_reordered_changed_scope_and_malformed_counters_reject(self):
        records, expected = self.collect()
        changes = [
            lambda r: r.pop(), lambda r: r.reverse(),
            lambda r: r[0]["sample"].update(sample_index=True),
            lambda r: r[0]["command"].append("different"),
            lambda r: r[0]["scope"].update(native_elapsed_replaced=True),
            lambda r: r[0]["scope"].update(sample_selection_or_threshold_adjustment=True),
            lambda r: r[0]["scope"].update(exclusive_cpu_access_proved=True),
            lambda r: r[0]["scope"].update(measurement_cause_proved=True),
            lambda r: r[0]["clock"].update(wall_ns=-1),
            lambda r: r[0]["clock"].update(wall_ns=r[0]["clock"]["wall_ns"] + 1),
            lambda r: r[1]["clock"].update(start_monotonic_ns=0),
            lambda r: r[0]["children"]["delta"].update(user_cpu_ns=-1),
            lambda r: r[0]["children"]["before"]["counters"].update(minor_page_faults=True),
            lambda r: r[0]["linux"].pop("host_cpu_pressure"),
        ]
        for index, mutate in enumerate(changes):
            with self.subTest(mutation=index), self.assertRaises(ValueError):
                candidate = deepcopy(records)
                mutate(candidate)
                observation.validate_observations(candidate, expected)

    def test_counter_reset_and_absent_sources_remain_explicit_without_fake_deltas(self):
        records, expected = self.collect(count=1)
        record = records[0]
        before = {"status": "observed", "counters": dict.fromkeys(observation.RUSAGE_FIELDS, 0), "error": None}
        after = deepcopy(before)
        before["counters"]["user_cpu_ns"], after["counters"]["user_cpu_ns"] = 10, 9
        record["children"] = {"before": before, "after": after, "status": "counter_reset",
                              "delta": None, "decreased_counters": ["user_cpu_ns"]}
        for name, path in observation.LINUX_FILES.items():
            absent = {"path": path, "status": "unavailable", "raw": None, "raw_sha256": None,
                      "counters": None, "error": {"type": "PermissionError", "errno": 13}}
            record["linux"][name] = {"before": deepcopy(absent), "after": deepcopy(absent),
                "status": "unavailable", "delta": None, "decreased_counters": []}
        observation.validate_observations(records, expected)
        forged = deepcopy(records)
        forged[0]["children"].update(status="observed", delta=dict.fromkeys(observation.RUSAGE_FIELDS, 0), decreased_counters=[])
        with self.assertRaises(ValueError):
            observation.validate_observations(forged, expected)
        forged = deepcopy(records)
        forged[0]["linux"]["host_cpu_pressure"].update(delta={"some.total_us": 0})
        with self.assertRaises(ValueError):
            observation.validate_observations(forged, expected)
        forged = deepcopy(records)
        snapshot = forged[0]["linux"]["host_cpu_pressure"]["before"]
        raw = "some avg10=0.00 avg60=0.00 avg300=0.00 total=4\n"
        snapshot.update(raw=raw, raw_sha256=hashlib.sha256(raw.encode()).hexdigest())
        with self.assertRaises(ValueError):
            observation.validate_observations(forged, expected)


if __name__ == "__main__":
    unittest.main()
