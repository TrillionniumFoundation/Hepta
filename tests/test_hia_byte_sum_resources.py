"""Fault injection for full-inventory resource/cost replay; no native timing."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from tools import qualify_hia_outlined_aot as aot
from tools.assess_hia_byte_sum_resources import (
    PROTOCOL_PATH, RAW_RESPONSE_FIELDS, assess, registered_load_schedule, specification,
)
from tools.qualify_hia_native_ndu import METRIC_NAMES, digest, wire


def metrics(n, failed=0, boundary=False):
    attempt = int(n > 0 and (not boundary or n <= 2**63 - 1))
    success = attempt * (1 - failed)
    usable = ((n + 7) // 8) * 8 if success else 0
    result = {name: 0 for name in METRIC_NAMES}
    result.update(attempts=attempt, allocations=success, frees=success,
                  refusals=attempt * failed, requested_total=n * success,
                  usable_total=usable, peak_requested=n * success, peak_usable=usable,
                  stack_anchor=4096, stack_max_distance=128 if attempt else 0)
    return result


def seal(report, *, recompute=False):
    if recompute:
        report["assessment"] = aot.assess(report["measurements"], report["protocol"])
        report["cost_and_memory"] = aot.cost_and_memory(report)
    report.pop("report_sha256", None)
    report["report_sha256"] = digest(report)
    return report


def synthetic_complete_run():
    """A labelled unit-test fixture, never a claim about measured performance."""
    spec = aot.specification()
    bindings = {specification()["historical_protocol_path"]:
                specification()["historical_protocol_file_sha256"]}
    source = {"status": "", "head": "synthetic-unit-test-only"}
    report = {"protocol": spec, "protocol_sha256": digest(spec), "status": "completed",
              "qualification_valid": True, "source_unchanged": True,
              "tool_artifact_identities_unchanged": True,
              "source_before": source, "source_after": deepcopy(source),
              "bindings_before": bindings, "bindings_after": deepcopy(bindings),
              "host": {"exclusive": False, "synthetic": True}, "whole_lifecycle_wall_ns": 1000000,
              "measurements": [], "correctness": [], "refusals": [], "loads": [],
              "backend_build_wall_ns": {}, "artifacts": {}}
    cache = {}
    def checksum(workload, n, seed):
        key = workload, n, seed
        if key not in cache:
            cache[key] = aot.release.checksum(workload, n, seed)
        return cache[key]
    for workload in spec["historical_profile"]["workloads"]:
        report["backend_build_wall_ns"][workload] = {a: 1000 for a in aot.ARMS}
        report["artifacts"][workload] = {a: {"bytes": 4096} for a in aot.ARMS}
        for group in spec["groups"]:
            for seed in group["seeds"]:
                for arm in aot.ARMS:
                    report["loads"].append({"workload": workload, "group": group["name"],
                                            "seed": seed, "backend": arm, "load_ns": 100,
                                            "mapping": {"mapped_bytes": 8192,
                                                        "backing_resident_bytes": 4096,
                                                        "mincore_failed_pages": 0}})
                    for n in group["sizes"]:
                        for calls in spec["batch_loads"]:
                            value = checksum(workload, n, seed)
                            report["measurements"].append({
                                "workload": workload, "group": group["name"], "n": n,
                                "seed": seed, "calls": calls, "backend": arm,
                                "metrics": metrics(n), "times_ns": [100] * spec["samples"],
                                "elapsed_ns": 100 * spec["samples"], "cold_ns": 100,
                                "cold_value": value, "observed": value,
                                "batch_checksum": sum(checksum(workload, n, (seed + i) & (2**32 - 1))
                                                      for i in range(calls)),
                                "maxrss_kib": 1000,
                                "first_library_call": n == group["sizes"][0] and calls == spec["batch_loads"][0],
                            })
        for arm in aot.ARMS:
            for n in spec["correctness_sizes"]:
                for failed in (0, 1):
                    report["correctness"].append({
                        "workload": workload, "backend": arm, "n": n, "seed": 2**32 - 1,
                        "calls": 1, "metrics": metrics(n, failed),
                        "observed": 1001 if n and failed else checksum(workload, n, 2**32 - 1),
                    })
            for n in spec["refusal_boundary_sizes"]:
                report["refusals"].append({
                    "workload": workload, "backend": arm, "n": n,
                    "metrics": metrics(n, 1, True), "observed": 1001 if n else 0,
                })
    report["load_observations"] = [
        {"workload": w, "group": g["name"], "seed": seed, "loadavg": [1.0, 1.0, 1.0],
         "monotonic_ns": index + 1}
        for index, (w, g, seed) in enumerate(
            (w, g, seed) for w in spec["historical_profile"]["workloads"]
            for g in spec["groups"] for seed in g["seeds"])]
    # Match the historical producer exactly: load rows have no seed.
    report["loads"] = [
        {"workload": s["workload"], "group": s["group"], "backend": s["backend"],
         "loaded": 0, "load_ns": 100,
         "mapping": {"status": "observed-loader-segments", "mapped_bytes": 8192,
                     "backing_resident_bytes": 4096, "mincore_failed_pages": 0}}
        for s in registered_load_schedule(spec)]
    for workload, arms in report["artifacts"].items():
        for arm, artifact in arms.items():
            artifact["path"] = "/synthetic-unit-test-only/" + workload + "/" + arm + ".so"
    for row in report["measurements"]:
        row.update(id=0, samples=spec["samples"], cpu_ns=10000, minor_faults=0,
                   major_faults=0, voluntary_switches=0, involuntary_switches=0)
    return seal(report, recompute=True)


def write_synthetic_logs(report, folder):
    """Complete fake driver streams for accounting fault injection only."""
    folder = Path(folder)
    indexed = {(r["workload"], r["group"], r["n"], r["seed"], r["calls"], r["backend"]): r
               for r in report["measurements"]}
    spec = report["protocol"]
    for load, scheduled in zip(report["loads"], registered_load_schedule(spec)):
        w, group, seed, arm = (scheduled[k] for k in ("workload", "group", "seed", "backend"))
        records = [{"sequence": 0, "response_hex": wire({"ready": True, "pid": 123}).hex()}]
        def pair(command, response):
            sequence = (len(records) + 1) // 2
            records.append({"sequence": sequence, "request": command})
            records.append({"sequence": sequence, "response_hex": wire(response).hex()})
        pair("L 0 " + report["artifacts"][w][arm]["path"], {"loaded": 0, "load_ns": load["load_ns"]})
        pair("M 0", deepcopy(load["mapping"]))
        for n in scheduled["sizes"]:
            for calls in spec["batch_loads"]:
                row = indexed[(w, group, n, seed, calls, arm)]
                raw = {k: deepcopy(row[k]) for k in RAW_RESPONSE_FIELDS}
                raw["metrics"] = [row["metrics"][k] for k in METRIC_NAMES]
                pair(f"R 0 {n} {seed} {calls} {spec['samples']} {spec['warmup_calls']} 0", raw)
        pair("Q", {"closed": True})
        records.append({"exit_code": 0, "stderr_hex": ""})
        name = f"timing-{w}-{group}-{scheduled['offset']}-{arm}.jsonl"
        (folder / name).write_bytes(b"".join(wire(r) + b"\n" for r in records))


class ResourceCostGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = synthetic_complete_run()
        cls.directory = tempfile.TemporaryDirectory(prefix="synthetic-aot-traces-")
        cls.raw_directory = Path(cls.directory.name)
        write_synthetic_logs(cls.original, cls.raw_directory)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def evaluate(self, report, spec=None, *, raw_directory=None):
        return assess(report, spec, raw_directory=self.raw_directory if raw_directory is None else raw_directory)

    def test_registered_bytes_and_unchanged_old_denominators(self):
        self.assertEqual(wire(json.loads(PROTOCOL_PATH.read_bytes())), wire(specification()))
        result = self.evaluate(deepcopy(self.original))
        self.assertTrue(result["assessment_valid"])
        self.assertTrue(all("seed" not in r for r in self.original["loads"]))
        self.assertEqual(len(result["load_receipt_associations"]), 144)
        self.assertEqual((result["runtime_gates_passed"], result["runtime_gates_total"]), (372, 372))
        self.assertTrue(result["all_registered_memory_gates_passed"])
        self.assertTrue(result["all_registered_automated_cost_gates_passed"])
        self.assertEqual(result["by_gate"]["memory.peak_requested"]["total"], 1116)
        self.assertEqual(result["by_gate"]["cost.cold_first_call"]["total"], 48)
        self.assertEqual(result["by_gate"]["cost.estimated_automated"]["total"], 1116)
        self.assertFalse(result["full_lifecycle_net_benefit_established"])

    def test_missing_or_duplicate_timing_observation_is_invalid(self):
        for mode in ("missing", "duplicate"):
            report = deepcopy(self.original)
            if mode == "missing":
                report["measurements"].pop()
            else:
                report["measurements"][-1] = deepcopy(report["measurements"][0])
            seal(report)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.evaluate(report)

    def test_native_leak_or_incomplete_metric_field_is_invalid(self):
        for mode in ("leak", "missing", "boolean"):
            report = deepcopy(self.original)
            row = report["measurements"][0]
            if mode == "leak":
                row["metrics"]["live"] = 1
            elif mode == "missing":
                row["metrics"].pop("peak_usable")
            else:
                row["metrics"]["attempts"] = False
            seal(report)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.evaluate(report)

    def test_missing_correctness_refusal_or_load_is_invalid(self):
        for section in ("correctness", "refusals", "loads"):
            report = deepcopy(self.original); report[section].pop(); seal(report)
            with self.subTest(section=section), self.assertRaises(ValueError):
                self.evaluate(report)

    def test_memory_regression_is_retained_as_failed_gate_not_infrastructure_error(self):
        report = deepcopy(self.original)
        row = next(r for r in report["measurements"]
                   if r["backend"] == "hia_guarded_outline" and r["n"] > 0)
        row["metrics"]["usable_total"] += 8
        row["metrics"]["peak_usable"] += 8
        row["metrics"]["stack_max_distance"] += 16
        seal(report, recompute=True)
        with tempfile.TemporaryDirectory(prefix="synthetic-changed-memory-") as folder:
            write_synthetic_logs(report, folder)
            result = self.evaluate(report, raw_directory=folder)
        self.assertTrue(result["assessment_valid"])
        self.assertFalse(result["all_registered_memory_gates_passed"])
        self.assertTrue(result["all_registered_automated_cost_gates_passed"])
        failures = [r["gate"] for r in result["checks"] if not r["passed"]]
        self.assertEqual(len(failures), 6)
        self.assertEqual(set(failures), {"memory.usable_total", "memory.peak_usable", "memory.stack_max_distance"})

    def test_build_cost_regression_is_retained_without_warm_only_substitution(self):
        report = deepcopy(self.original)
        report["backend_build_wall_ns"]["linear"]["hia_guarded_outline"] *= 2
        seal(report, recompute=True)
        result = self.evaluate(report)
        self.assertTrue(result["assessment_valid"])
        self.assertFalse(result["all_registered_automated_cost_gates_passed"])
        self.assertTrue(result["all_registered_memory_gates_passed"])
        self.assertTrue(any(not r["passed"] and r["gate"] == "cost.estimated_automated"
                            for r in result["checks"]))

    def test_removed_cold_markers_and_unrecomputed_cost_ledger_are_invalid(self):
        for mode in ("cold", "cost"):
            report = deepcopy(self.original)
            if mode == "cold":
                for row in report["measurements"]:
                    row["first_library_call"] = False
                seal(report, recompute=True)
            else:
                report["backend_build_wall_ns"]["linear"]["hia_guarded_outline"] *= 2
                seal(report)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.evaluate(report)

    def test_drift_unknown_loader_pages_and_posthoc_ratio_change_are_invalid(self):
        for mode in ("source", "page", "protocol"):
            report = deepcopy(self.original)
            spec = specification()
            if mode == "source":
                report["source_unchanged"] = False
            elif mode == "page":
                report["loads"][0]["mapping"]["mincore_failed_pages"] = 1
            else:
                spec["allocator_metric_ratio_maximum"] = 2
            seal(report)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.evaluate(report, spec)


    def test_missing_raw_stream_or_load_observation_is_invalid(self):
        with tempfile.TemporaryDirectory(prefix="synthetic-missing-traces-") as folder:
            with self.assertRaises(ValueError):
                self.evaluate(deepcopy(self.original), raw_directory=folder)
        report = deepcopy(self.original)
        report["load_observations"].pop()
        seal(report)
        with self.assertRaises(ValueError):
            self.evaluate(report)

    def test_supplied_seed_and_loader_observation_must_match_actual_trace(self):
        for mode in ("seed", "load"):
            report = deepcopy(self.original)
            if mode == "seed":
                report["loads"][0]["seed"] = 1
            else:
                report["loads"][0]["load_ns"] += 1
            seal(report, recompute=True)
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.evaluate(report)

    def test_raw_sample_or_cleanup_tampering_is_not_relabelled_as_complete(self):
        for mode in ("sample", "close"):
            with tempfile.TemporaryDirectory(prefix="synthetic-tampered-traces-") as folder:
                write_synthetic_logs(self.original, folder)
                path = next(Path(folder).glob("*.jsonl"))
                records = [json.loads(line) for line in path.read_bytes().splitlines()]
                if mode == "sample":
                    response = json.loads(bytes.fromhex(records[6]["response_hex"]))
                    response["times_ns"][0] += 1
                    records[6]["response_hex"] = wire(response).hex()
                else:
                    records.pop()
                path.write_bytes(b"".join(wire(r) + b"\n" for r in records))
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    self.evaluate(deepcopy(self.original), raw_directory=folder)


if __name__ == "__main__":
    unittest.main()
