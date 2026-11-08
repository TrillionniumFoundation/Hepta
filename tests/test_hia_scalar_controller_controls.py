"""Evidence-integrity tests; all authored native replies below are fixtures.

This module never launches the native evaluator. The separately frozen
64-pair campaign is the only native timing experiment.
"""
from collections import Counter
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from tools import measure_hia_scalar_controller_controls as study


class ScalarControllerEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "objects").mkdir()
        self.store = study.Store(self.root)

    def test_frozen_64_pairs_balance_each_case_and_preserve_all_native_opportunities(self):
        schedule = study.schedule()
        self.assertEqual([row["pair"] for row in schedule], list(range(1, 65)))
        self.assertEqual(Counter(row["order"][0] for row in schedule), {"ordinary": 32, "ndu": 32})
        for case in study.cases():
            entries = [row for row in schedule if row["case_id"] == case["id"]]
            self.assertEqual(Counter(row["order"][0] for row in entries), {"ordinary": 4, "ndu": 4})
            request = study.reference_request(case, "1"*64, 1)
            self.assertTrue(any(not row["hard_violation"] for row in request["candidates"]))
        self.assertEqual(study.protocol()["planned_native_calls"], 64)
        self.assertFalse(study.protocol()["economic_benefit_established"])

    def test_zero_budget_and_empty_feasibility_do_not_dispatch_native_or_count_as_native_cases(self):
        from tools import qualify_hia_macro_multistep as production
        pool = deepcopy(study.cases()[0]["pool"])
        impossible = deepcopy(pool)
        for item in impossible:
            item["quality_complete"] = False
        with patch.object(production, "_native_rank", side_effect=AssertionError("must not run")) as native:
            for candidate_pool, budget in ((pool, 0), (impossible, study.ALLOWANCE_NS), ([], study.ALLOWANCE_NS)):
                for arm in study.ARMS:
                    result = production.checked_pool_selection(arm, candidate_pool,
                        remaining_wall_ns=budget, bridge=None, objective_sha256="1"*64, generation=1)
                    self.assertIsNone(result["selected_id"])
                    self.assertFalse(result["native_ndu_evaluated"])
            native.assert_not_called()

    def test_raw_bytes_are_retained_and_detect_tampering(self):
        original = {"stdin": b"\x00raw\n", "pump": {"stdout": b'{"answer":1}\n', "stderr": b""}}
        ref = self.store.json(self.store.pack(original))
        self.assertEqual(self.store.unpack(study.decode(self.store.read(ref))), original)
        raw_ref = self.store.put(b"original")
        (self.root / raw_ref["path"]).write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "digest"):
            self.store.read(raw_ref)

    def test_object_paths_and_exact_json_keys_fail_closed(self):
        ref = self.store.put(b"x")
        for bad in ({**ref, "path": "../outside"}, {**ref, "bytes": True}, {**ref, "extra": 1}):
            with self.assertRaises(ValueError):
                self.store.read(bad)
        for bad in (b'{"a":1,"a":2}', b'{"a":NaN}'):
            with self.assertRaises(ValueError):
                study.decode(bad)

    def fixture(self):
        """Self-labelled authored reply for audit fault injection, never a process."""
        case = deepcopy(study.cases()[3])
        plan = {"objective_sha256": "1"*64, "native": {"identity": {"upstream_commit": "authored-test-only"}}}
        request = study.reference_request(case, plan["objective_sha256"], 1)
        response = {"schema": "hepta.hia.ndu-response.v1", "request_sha256": study.digest(request),
            "objective_sha256": plan["objective_sha256"], "generation": 1,
            "upstream_commit": "authored-test-only", "pareto_frontier": ["alpha", "beta"], "rejected": [],
            "disposition": "ParetoSetRequiresSlowPath", "advisory_recommendation": None,
            "authority": "ADVISORY_ONLY", "proves_program_safety": False, "authored_unit_fixture": True}
        selection = {"request_sha256": study.digest(request), "native_response_sha256": study.digest(response),
                     "selected_id": "alpha", "incremental_ndu_advantage_established": False}
        result = {"pool": deepcopy(case["pool"]), "remaining_wall_ns": case["remaining_wall_ns"],
            "arm": "ndu", "selected_id": "alpha", "native_ndu_evaluated": True,
            "native_identity": plan["native"]["identity"], "native_request": request,
            "native_response": response, "selection_resolution": selection, "feasible_incumbent_id": "zeta"}
        observation = {"stdin": study.wire(request), "native_identity": plan["native"]["identity"],
            "response_admitted": True, "error": None, "authored_unit_fixture": True,
            "pump": {"started": True, "pid": 1234, "cleanup_confirmed": True, "streams_complete": True,
                "eof": {"stdout": True, "stderr": True}, "returncode": 0, "error": None,
                "stdout": study.wire(response)+b"\n", "stderr": b""}}
        row = {"pair": 1, "arm": "ndu", "status": "completed", "call_error": None,
            "input_sha256": study.digest({"pool": case["pool"], "remaining_wall_ns": case["remaining_wall_ns"],
                "objective_sha256": plan["objective_sha256"], "generation": 1}),
            "wall_ns": 30, "start_offset_ns": 10, "end_offset_ns": 40,
            "cpu_ns": {"parent": 10, "children": 5}}
        self.retain(row, result, observation)
        return case, plan, row, result, observation

    def retain(self, row, result, observation):
        row["result"] = self.store.json(result)
        row["observations"] = self.store.json(self.store.pack([observation]))

    def test_self_consistent_wrong_cost_table_is_not_accepted_as_frozen_input(self):
        case, plan, row, result, observation = self.fixture()
        self.assertEqual(study.audit_completed(row, case, plan, self.store), "alpha")
        result["native_request"]["candidates"][0]["cost_q32"] += 1
        result["native_response"]["request_sha256"] = study.digest(result["native_request"])
        result["selection_resolution"]["request_sha256"] = study.digest(result["native_request"])
        result["selection_resolution"]["native_response_sha256"] = study.digest(result["native_response"])
        observation["stdin"] = study.wire(result["native_request"])
        observation["pump"]["stdout"] = study.wire(result["native_response"])+b"\n"
        self.retain(row, result, observation)
        with self.assertRaisesRegex(ValueError, "frozen pool"):
            study.audit_completed(row, case, plan, self.store)

    def test_unsettled_cleanup_and_false_frontier_are_refused(self):
        for fault in ("cleanup", "frontier", "stdout", "generation", "claim"):
            case, plan, row, result, observation = self.fixture()
            if fault == "cleanup":
                observation["pump"]["cleanup_confirmed"] = False
            elif fault == "frontier":
                result["native_response"]["pareto_frontier"] = ["alpha"]
            elif fault == "stdout":
                observation["pump"]["stdout"] = b"wrong\n"
            elif fault == "generation":
                result["native_response"]["generation"] = 2
            elif fault == "claim":
                result["native_response"]["proves_program_safety"] = True
            if fault in ("frontier", "generation", "claim"):
                observation["pump"]["stdout"] = study.wire(result["native_response"])+b"\n"
                result["selection_resolution"]["native_response_sha256"] = study.digest(result["native_response"])
            self.retain(row, result, observation)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                study.audit_completed(row, case, plan, self.store)

    def test_failures_are_charged_and_unstarted_counterfactuals_are_not_zero(self):
        plan = {"cases": study.cases(), "schedule": study.schedule()}
        rows = []
        for entry in plan["schedule"]:
            for arm in entry["order"]:
                rows.append({"pair": entry["pair"], "arm": arm, "status": "not_started",
                    "audit_error": None, "wall_ns": None, "cpu_ns": None})
        rows[0].update(status="completed", wall_ns=9, cpu_ns={"parent": 3, "children": 0})
        rows[1].update(status="failed", wall_ns=17, cpu_ns={"parent": 4, "children": 5})
        result = study.results_summary(rows, plan, self.store)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["attempted_calls"], 2)
        self.assertEqual(result["failed_calls"], 1)
        self.assertEqual(result["all_attempted_call_wall_ns"]["ndu"]["sum_ns"], 17)
        self.assertIsNone(result["pairs"][0]["ordinary_minus_ndu_wall_ns"])
        self.assertIsNone(result["paired_ordinary_minus_ndu_wall_ns"]["sum_ns"])
        self.assertFalse(result["economic_benefit_established"])

    def test_plan_pin_and_create_only_marker_prevent_silent_retrial(self):
        plan = {"schema": study.SCHEMA, "protocol": study.protocol(), "cases": study.cases(),
                "schedule": study.schedule(), "objective": {}, "objective_sha256": study.digest({})}
        study.write_new(self.root / "PLAN.json", plan)
        expected = sha256((self.root / "PLAN.json").read_bytes()).hexdigest()
        with self.assertRaisesRegex(ValueError, "pre-run pin"):
            study.read_plan(self.root, "0"*64)
        study.write_new(self.root / "RUN-STARTED.json", {"incomplete_prior_attempt": True})
        with patch.object(study, "load_source", side_effect=AssertionError("must not import")) as loader:
            with self.assertRaises(FileExistsError):
                study.run(SimpleNamespace(directory=self.root, expected_plan_sha256=expected))
            loader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
