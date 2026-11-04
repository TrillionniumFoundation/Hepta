"""Independent semantic checks for lazy finite-cost witness materialization."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import itertools
from unittest.mock import patch
import unittest

from hepta import hia_ndu_cost as current
from tests.test_hia_ndu_cost import fixture, independent_frontier
from tools import qualify_hia_ndu_lazy_witness as qualification
from tools.qualify_hia_ndu_budget_erasure import corpus, encoded, first_costs


class LazyWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = qualification.load_baseline()

    def test_registered_corpus_preserves_full_outputs_and_independent_minima(self):
        protocol = qualification.load_protocol()
        self.assertEqual(protocol["cases"], 256)
        for number, model in enumerate(corpus(protocol)):
            with self.subTest(case=number):
                qualification.compare_model(self.old, model)

    def test_invalidation_reacquisition_status_and_budget_boundaries(self):
        # Available targets, stale residents and costs deliberately vary across
        # phases, so a batch-insensitive validity or transfer cache is exposed.
        for status, session, ready, quota in itertools.product(
                ("verified", "unknown", "rejected", "timeout"), (False, True),
                ([], ["a"]), (1, 2)):
            model = fixture(4)
            model["session_ready"], model["ready"] = session, ready
            model["memory_budget_bytes"] = quota
            model["variants"][0].update(status=status, valid=[True, False, True, True],
                                        latency_ns=[0, 9000, 0, 9000])
            model["variants"][1].update(valid=[False, True, True, False],
                                        latency_ns=[9000, 0, 9000, 0])
            for key in model["decision"]:
                model["decision"][key] *= 17
            totals = independent_frontier(model)
            minimum = min(totals.values())
            for budget in (0, minimum-1, minimum, minimum+1, model["budget_ns"]):
                with self.subTest(status=status, session=session, ready=ready, quota=quota, budget=budget):
                    candidate = deepcopy(model)
                    candidate["budget_ns"] = budget
                    qualification.compare_model(self.old, candidate)

    def test_zero_cost_lexical_and_skip_ties_remain_identical(self):
        for horizon in range(1, 5):
            for session in (False, True):
                model = fixture(horizon)
                model["budget_ns"] = 0
                model["session_ready"] = session
                model["memory_budget_bytes"] = 2
                model["decision"] = dict.fromkeys(model["decision"], 0)
                model["baseline"]["latency_ns"] = [0] * horizon
                for row in model["variants"]:
                    row.update(prepare_ns=0, proof_ns=0, retire_ns=0, holding_ns=0,
                               latency_ns=[0] * horizon)
                self.assertEqual(encoded(current.exact_control(model)),
                                 encoded(self.old.exact_control(model)))
                qualification.compare_model(self.old, model)
                self.assertEqual(current.exact_control(model)["best"]["actions"][0]["mode"], "skip")

    def test_committed_frontier_and_requests_do_not_share_tail_mutations(self):
        model = fixture(4)
        first = current.build_request(model)
        retained = deepcopy(first)
        plans = list(first["plans"].values())
        other_plans = deepcopy(plans[1:])
        plans[0]["actions"][-1]["costs"]["holding_ns"] += 100
        plans[0]["actions"][-1]["ready_after"].clear()
        self.assertEqual(plans[1:], other_plans)
        self.assertEqual(current.build_request(model), retained)
        self.assertEqual(first_costs(retained["plans"].values()),
                         independent_frontier(model, committed_call=True))

    def test_changed_cost_or_validity_cannot_reuse_a_prior_request_result(self):
        initial = fixture(4)
        before = current.build_request(initial)
        changed = deepcopy(initial)
        changed["variants"][0]["valid"] = [False] * 4
        changed["variants"][1]["proof_ns"] += 98765
        changed["generation"] += 1
        after = current.build_request(changed)
        self.assertNotEqual(before["request"]["snapshot_digest"], after["request"]["snapshot_digest"])
        qualification.compare_model(self.old, changed)
        self.assertEqual(current.build_request(initial), before)

    def test_failed_native_start_keeps_elapsed_cost_and_zero_completed_count(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(qualification.NduSession, "for_stream_profile",
                              side_effect=RuntimeError("recorded native startup refusal")):
                with self.assertRaisesRegex(RuntimeError, "startup refusal"):
                    qualification.native_compare(Path(directory), [fixture()], self.old,
                        SimpleNamespace(bridge="unused", identity="unused"),
                        qualification.load_protocol())
            result = json.loads((Path(directory) / "NATIVE_SUMMARY.json").read_bytes())
            self.assertEqual(result["completed_invocations"], 0)
            self.assertEqual(result["attempted_invocations"], 0)
            self.assertIsInstance(result["startup_ns"], int)
            self.assertGreaterEqual(result["phase_wall_ns_excluding_summary_write"],
                                    result["known_session_total_ns"])
            self.assertFalse(result["all_responses_equal"])

    def test_changed_frozen_source_refuses_before_execution(self):
        with patch.object(type(qualification.BASELINE), "read_bytes", return_value=b"raise RuntimeError('should not execute')"):
            with self.assertRaisesRegex(ValueError, "changed frozen"):
                qualification.load_baseline()

    def test_changed_registration_cannot_omit_cases(self):
        with patch.object(type(qualification.PROTOCOL), "read_bytes", return_value=b'{"cases":0}'):
            with self.assertRaisesRegex(ValueError, "registration"):
                qualification.load_protocol()


if __name__ == "__main__":
    unittest.main()
