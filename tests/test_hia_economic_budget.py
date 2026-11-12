"""Control-flow deadline regressions using explicit non-native substitutes.

These tests establish admission ordering only. They are not measurement,
native safety, or performance evidence for the research campaign.
"""
from argparse import Namespace
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_economic_search as q


def scenario(mode):
    clock, calls, preparations = [1], [], []
    class Runtime:
        def __init__(self, _baseline, folder, **_kwargs):
            self._directory = folder
            (folder/"generation-0.so").write_bytes(b"explicit mock runtime bytes")
            self.identity = sha256((folder/"generation-0.so").read_bytes()).hexdigest()
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def snapshot(self):
            return {"generations": [{"generation": 0, "artifact_sha256": self.identity}],
                    "current_generation": 0, "cleanup": {"owned_native_release_complete": True,
                        "pending": [], "observed_closed_and_directory_absent": mode != "cleanup_failed"}}
        @contextmanager
        def lease(self):
            yield self
        def call(self, _function, arguments):
            x, d = arguments
            return x if d == 0 else (x//d+x%d) % 256
    def sample(_driver, _artifact, _input, _rows, iterations, **kwargs):
        calls.append({"iterations": iterations, "timeout": kwargs.get("timeout"), "started": clock[0]})
        clock[0] += q.PROTOCOL["search_budget_ns"] if mode == "first_baseline_overrun" else 10_000_000
        failed = mode == "baseline_failed" and iterations == q.PROTOCOL["measurement_calls"]
        return {"status": "failed" if failed else "observed", "iterations": iterations,
                "elapsed_ns": iterations*10, "outer_wall_ns": 10_000_000}
    def choose(_snapshot, **_kwargs):
        clock[0] += q.PROTOCOL["search_budget_ns"]
        return {"action": {"kind": "measure", "candidate_id": "c3"},
                "reason": "explicit mock controller exhausted budget"}
    def prepare(*_args, **_kwargs):
        preparations.append(clock[0])
        raise AssertionError("must not prepare after observed budget exhaustion")
    with tempfile.TemporaryDirectory() as temporary:
        top = Path(temporary)
        rows = [[1,3]]*64
        path = top/"input.txt"
        path.write_text("1 3\n"*64)
        baseline = q.workload()
        candidates = [{"id": cid, "program": baseline} for cid in ("c3", "c10", "c16")]
        rates = dict(lower_ps=10000, upper_ps=10000, median_ps=10000, sample_outer_ns=10_000_000)
        bank = {"sha256": "b"*64, "publication_estimate_ns": 100,
            "profiles": {"test": {cid: dict(rates) for cid in ("abstain", "c3", "c10", "c16")}},
            "prepare": {cid: {"wall_ns": 100} for cid in ("c3", "c10", "c16")}}
        arm = "fixed_stop" if mode == "cleanup_failed" else "arithmetic" if mode == "controller_overrun" else "fixed_three"
        with patch.object(q, "ScalarMultiversionRuntime", Runtime), patch.object(q, "sample", sample), \
             patch.object(q, "prepare", prepare), patch.object(q, "choose_measurement", choose), \
             patch.object(q.time, "perf_counter_ns", lambda: clock[0]):
            result = q.episode(arm, "test", 0, folder=top/"episode", baseline=baseline, candidates=candidates,
                bank=bank, fixed_selected="c3", shared_charge_ns=q.PROTOCOL["search_budget_ns"] if mode == "already_paid" else 0,
                bridge_charge_ns=0, bridge=None, clang="explicit-unused-mock", driver=top/"driver",
                inputs={"online": {"test": (rows,path)}, "holdout": {"test": (rows,path)}})
    return result, calls, preparations


class EconomicBudgetTests(unittest.TestCase):
    def test_paid_budget_blocks_baseline_measurement_and_keeps_baseline_delivery(self):
        result, calls, preparations = scenario("already_paid")
        self.assertEqual(result["status"], "completed", result)
        self.assertEqual([row["iterations"] for row in calls], [q.PROTOCOL["holdout_calls"]])
        self.assertFalse(preparations)
        self.assertEqual(result["stop_reason"], "budget_exhausted_before_baseline_sample")

    def test_first_baseline_overrun_prevents_second_batch(self):
        result, calls, preparations = scenario("first_baseline_overrun")
        self.assertEqual(result["status"], "completed", result)
        self.assertEqual([row["iterations"] for row in calls], [q.PROTOCOL["measurement_calls"], q.PROTOCOL["holdout_calls"]])
        self.assertLessEqual(calls[0]["timeout"], q.PROTOCOL["search_budget_ns"]/1e9)
        self.assertFalse(preparations)

    def test_failed_baseline_is_retained_and_does_not_launch_another_batch(self):
        result, calls, preparations = scenario("baseline_failed")
        self.assertEqual(result["status"], "completed", result)
        self.assertEqual(len(result["failed_samples_retained"]), 1)
        self.assertEqual([row["iterations"] for row in calls], [q.PROTOCOL["measurement_calls"], q.PROTOCOL["holdout_calls"]])
        self.assertFalse(preparations)

    def test_controller_overrun_cannot_start_a_candidate_preparation(self):
        result, calls, preparations = scenario("controller_overrun")
        self.assertEqual(result["status"], "completed", result)
        self.assertEqual([row["iterations"] for row in calls], [q.PROTOCOL["measurement_calls"]]*2+[q.PROTOCOL["holdout_calls"]])
        self.assertEqual(result["stop_reason"], "budget_exhausted_after_controller")
        self.assertFalse(preparations)

    def test_uncertain_after_close_cleanup_cannot_qualify_an_episode(self):
        result, calls, _preparations = scenario("cleanup_failed")
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["status"], "failed")
        self.assertIn("runtime cleanup", result["error"])
        self.assertFalse(result["closed_snapshot"]["cleanup"]["observed_closed_and_directory_absent"])

    def test_proof_overrun_is_recorded_and_cannot_start_equivalence_or_native_build(self):
        source = q.workload()
        clock = [1]
        def totality(program, **_kwargs):
            clock[0] = 100
            return {"status": "proved", "program_sha256": program.sha256, "input_sha256": program.input_sha256}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/"candidate.so"
            with patch.object(q.time, "perf_counter_ns", lambda: clock[0]), \
                 patch.object(q, "validate_scalar_totality", totality), \
                 patch.object(q, "validate_translation") as translation, \
                 patch.object(q, "build_program_native") as build:
                with self.assertRaisesRegex(RuntimeError, "deadline exhausted"):
                    q.prepare(source, source, path, "unused", deadline_ns=50)
            translation.assert_not_called()
            build.assert_not_called()
            receipt = json.loads(path.with_suffix(".prepare.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertEqual(receipt["failed_stage"], "equivalence")
            self.assertEqual(receipt["totality"]["status"], "proved")
            self.assertEqual(receipt["wall_ns"], 99)

    def test_existing_campaign_directory_is_not_changed_by_second_invocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            sentinel = folder/"RESULT.json"
            sentinel.write_bytes(b"original frozen evidence\n")
            with patch.object(q, "_run") as inner:
                with self.assertRaises(FileExistsError):
                    q.run(Namespace(output_directory=folder))
                inner.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b"original frozen evidence\n")
            self.assertEqual(sorted(path.name for path in folder.iterdir()), ["RESULT.json"])


if __name__ == "__main__":
    unittest.main()
