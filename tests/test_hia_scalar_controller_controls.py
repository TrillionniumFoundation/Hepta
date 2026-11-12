"""Evidence-integrity tests; all authored native replies below are fixtures.

This module never launches the native evaluator. The separately frozen
64-pair campaign is the only native timing experiment.
"""
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import zipfile

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
                "wall_ns": 20,
                "eof": {"stdout": True, "stderr": True}, "returncode": 0, "error": None,
                "stdout": study.wire(response)+b"\n", "stderr": b""}}
        row = {"pair": 1, "arm": "ndu", "status": "completed", "call_error": None,
            "input_sha256": study.digest({"pool": case["pool"], "remaining_wall_ns": case["remaining_wall_ns"],
                "objective_sha256": plan["objective_sha256"], "generation": 1}),
            "wall_ns": 30, "start_offset_ns": 10, "end_offset_ns": 40,
            "cpu_ns": {"parent": 10, "children": 5}}
        self.retain(row, result, observation)
        return case, plan, row, result, observation

    def test_native_pump_wall_is_exact_and_contained_in_completed_call(self):
        for invalid in (None, True, 20.0, -1, 31):
            case, plan, row, result, observation = self.fixture()
            if invalid is None:
                observation["pump"].pop("wall_ns")
            else:
                observation["pump"]["wall_ns"] = invalid
            self.retain(row, result, observation)
            for audit in (study.audit_completed, study.audit_retained_attempt):
                with self.subTest(invalid=invalid, audit=audit.__name__), self.assertRaisesRegex(
                        ValueError, "native pump wall"):
                    audit(row, case, plan, self.store)

    def test_native_pump_interval_accepts_zero_and_exact_call_boundary(self):
        for wall in (0, 30):
            case, plan, row, result, observation = self.fixture()
            observation["pump"]["wall_ns"] = wall
            self.retain(row, result, observation)
            for audit in (study.audit_completed, study.audit_retained_attempt):
                with self.subTest(wall=wall, audit=audit.__name__):
                    self.assertEqual(audit(row, case, plan, self.store), "alpha")

    def test_failed_and_audit_error_attempts_cannot_bypass_pump_wall_check(self):
        for status in ("failed", "completed"):
            for invalid in (None, True, 20.0, -1, 31):
                case, plan, row, result, observation = self.fixture()
                if invalid is None:
                    observation["pump"].pop("wall_ns")
                else:
                    observation["pump"]["wall_ns"] = invalid
                row.update(status=status, audit_error={"authored_fixture": True})
                if status == "failed":
                    row["call_error"] = {"authored_fixture": True}
                    result = None
                self.retain(row, result, observation)
                with self.subTest(status=status, invalid=invalid), self.assertRaisesRegex(
                        ValueError, "native pump wall"):
                    study.audit_retained_attempt(row, case, plan, self.store)

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

    def incomplete_fixture(self):
        """One successful ordinary call and one failed native call, no process."""
        plan = {"cases": study.cases(), "schedule": study.schedule(), "objective_sha256": "1"*64}
        rows = []
        for entry in plan["schedule"]:
            for position, arm in enumerate(entry["order"], 1):
                rows.append({"pair": entry["pair"], "arm": arm, "status": "not_started",
                    "case_id": entry["case_id"], "position": position, "call_error": None,
                    "audit_error": None, "wall_ns": None, "cpu_ns": None,
                    "start_offset_ns": None, "end_offset_ns": None,
                    "result": None, "observations": None})
        case = plan["cases"][0]
        frozen = {"pool": case["pool"], "remaining_wall_ns": case["remaining_wall_ns"],
                  "objective_sha256": plan["objective_sha256"], "generation": 1}
        result = {"pool": case["pool"], "remaining_wall_ns": case["remaining_wall_ns"],
                  "arm": "ordinary", "selected_id": case["expected_id"],
                  "native_ndu_evaluated": False, "native_response": None, "native_identity": None}
        rows[0].update(status="completed", wall_ns=9, start_offset_ns=0, end_offset_ns=9,
            cpu_ns={"parent": 3, "children": 0}, input_sha256=study.digest(frozen),
            result=self.store.json(result), observations=self.store.json([]))
        partial = {"stdin": b"authored incomplete request", "pump": {
            "wall_ns": 11,
            "stdout": b"authored partial reply", "stderr": b"authored diagnostic",
            "streams_complete": False}}
        rows[1].update(status="failed", wall_ns=17, start_offset_ns=9, end_offset_ns=26,
            cpu_ns={"parent": 4, "children": 5}, input_sha256=study.digest(frozen),
            call_error={"type": "AuthoredFixtureError", "message": "not a native run"},
            result=self.store.json(None), observations=self.store.json(self.store.pack([partial])))
        return plan, rows

    def test_failures_are_charged_and_unstarted_counterfactuals_are_not_zero(self):
        plan, rows = self.incomplete_fixture()
        result = study.results_summary(rows, plan, self.store)
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["attempted_calls"], 2)
        self.assertEqual(result["failed_calls"], 1)
        self.assertEqual(result["all_attempted_call_wall_ns"]["ndu"]["sum_ns"], 17)
        self.assertIsNone(result["pairs"][0]["ordinary_minus_ndu_wall_ns"])
        self.assertIsNone(result["paired_ordinary_minus_ndu_wall_ns"]["sum_ns"])
        self.assertFalse(result["economic_benefit_established"])

    def test_incomplete_pair_still_verifies_each_attempted_object_and_raw_stream(self):
        for fault in ("successful-result", "failed-observations", "failed-stdout", "failed-stderr"):
            with self.subTest(fault=fault):
                plan, rows = self.incomplete_fixture()
                if fault == "successful-result":
                    missing = rows[0]["result"]
                elif fault == "failed-observations":
                    missing = rows[1]["observations"]
                else:
                    packed = study.decode(self.store.read(rows[1]["observations"]))
                    missing = packed[0]["pump"][fault.removeprefix("failed-")]["raw_bytes"]
                path = self.root / missing["path"]
                raw = path.read_bytes()
                path.unlink()
                try:
                    with self.assertRaises((ValueError, OSError)):
                        study.results_summary(rows, plan, self.store)
                finally:
                    path.write_bytes(raw)

    def test_completed_cell_is_audited_even_when_its_partner_fails(self):
        plan, rows = self.incomplete_fixture()
        result = study.decode(self.store.read(rows[0]["result"]))
        result["selected_id"] = "wrong-authored-winner"
        rows[0]["result"] = self.store.json(result)
        with self.assertRaisesRegex(ValueError, "same-pool winner"):
            study.results_summary(rows, plan, self.store)

    def test_failed_call_costs_and_statuses_are_checked_without_claiming_success(self):
        for fault in ("wall", "negative-cpu", "boolean-cpu", "interval", "status"):
            plan, rows = self.incomplete_fixture()
            if fault == "wall": rows[1]["wall_ns"] = True
            elif fault == "negative-cpu": rows[1]["cpu_ns"]["children"] = -1
            elif fault == "boolean-cpu": rows[1]["cpu_ns"]["children"] = True
            elif fault == "interval": rows[1]["end_offset_ns"] += 1
            else: rows[1]["status"] = "unknown"
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                study.results_summary(rows, plan, self.store)

    def test_only_one_scheduled_prefix_can_be_attempted_before_stop(self):
        for boundary in ("skipped-first", "unexplained-stop", "resumed-after-failure",
                         "resumed-after-audit", "reordered"):
            plan, rows = self.incomplete_fixture()
            if boundary == "skipped-first":
                rows[0]["status"] = "not_started"
            elif boundary == "unexplained-stop":
                rows[1]["status"] = "not_started"
            elif boundary == "resumed-after-failure":
                rows[2]["status"] = "failed"
            elif boundary == "resumed-after-audit":
                rows[0]["audit_error"] = {"type": "AuthoredAuditFailure"}
            else:
                rows[0], rows[1] = rows[1], rows[0]
            with self.subTest(boundary=boundary), self.assertRaises(ValueError):
                study.results_summary(rows, plan, self.store)

    def test_all_unstarted_initial_admission_and_original_failed_prefix_remain_valid(self):
        plan, rows = self.incomplete_fixture()
        failed = study.results_summary(rows, plan, self.store)
        self.assertEqual(failed["attempted_calls"], 2)
        for row in rows:
            row["status"] = "not_started"
            for key in ("result", "observations", "wall_ns", "cpu_ns", "start_offset_ns",
                        "end_offset_ns", "call_error", "audit_error"):
                row[key] = None
        initial = study.results_summary(rows, plan, self.store)
        self.assertEqual(initial["status"], "INCOMPLETE")
        self.assertEqual(initial["attempted_calls"], 0)
        self.assertIsNone(initial["paired_ordinary_minus_ndu_wall_ns"]["sum_ns"])

    def test_call_intervals_and_full_costs_fit_inside_outer_measurement(self):
        _, rows = self.incomplete_fixture()
        costs = {"all_attempted_call_wall_ns": 26,
            "outer_wall_ns_to_summary_preparation": 26,
            "admission_capture_export_audit_wall_ns": 0}
        study.audit_measurement(rows, costs)  # Exact final boundary is inclusive.
        for boundary in ("late-end", "overlap", "boolean-cost", "negative-cost", "omitted-cost"):
            observed, accounting = deepcopy(rows), deepcopy(costs)
            if boundary == "late-end":
                for row in observed[:2]:
                    row["start_offset_ns"] += 1
                    row["end_offset_ns"] += 1
            elif boundary == "overlap":
                observed[1]["start_offset_ns"] -= 1
                observed[1]["end_offset_ns"] -= 1
            elif boundary == "boolean-cost":
                accounting["admission_capture_export_audit_wall_ns"] = False
            elif boundary == "negative-cost":
                accounting["admission_capture_export_audit_wall_ns"] = -1
            else:
                del accounting["all_attempted_call_wall_ns"]
            with self.subTest(boundary=boundary), self.assertRaises(ValueError):
                study.audit_measurement(observed, accounting)

    def independent_incomplete_fixture(self):
        plan, rows = self.incomplete_fixture()
        objective = {"authored_fixture": True}
        plan.update(schema=study.SCHEMA, protocol=study.protocol(), objective=objective,
                    objective_sha256=study.digest(objective), execution_inputs={})
        case = plan["cases"][0]
        for row in rows[:2]:
            row["input_sha256"] = study.digest({"pool": case["pool"],
                "remaining_wall_ns": case["remaining_wall_ns"],
                "objective_sha256": plan["objective_sha256"], "generation": row["pair"]})
        binary = self.store.put(b"authored fixture, not a native executable")
        receipt = self.store.json({"binary_sha256": binary["sha256"]})
        plan["native"] = {"binary": binary, "build_receipt": receipt, "provenance": None,
            "identity": {"binary_sha256": binary["sha256"], "build_receipt_sha256": receipt["sha256"]}}
        study.write_new(self.root / "PLAN.json", plan)
        pin = sha256((self.root / "PLAN.json").read_bytes()).hexdigest()
        study.write_new(self.root / "RUN-STARTED.json", {"plan_sha256": pin})
        for row in rows:
            study.write_new(self.root / f"cell-{row['pair']:02d}-{row['arm']}.json", row)
        summary = study.results_summary(rows, plan, self.store)
        summary.update(schema=study.SCHEMA, plan_sha256=pin, cells=rows,
            halted_reason={"authored_fixture": True}, execution_inputs_unchanged=True,
            measurement={"all_attempted_call_wall_ns": 26,
                "outer_cpu_ns": {"parent": 10, "children": 7},
                "outer_wall_ns_to_summary_preparation": 31,
                "admission_capture_export_audit_wall_ns": 5})
        study.write_new(self.root / "SUMMARY.json", summary)
        args = SimpleNamespace(directory=self.root, expected_plan_sha256=pin, output=None)
        return args, rows, summary

    def test_independent_verify_refuses_missing_objects_from_incomplete_campaign(self):
        args, rows, summary = self.independent_incomplete_fixture()
        accepted = study.verify(args)
        self.assertEqual(accepted["campaign_status"], "INCOMPLETE")
        self.assertEqual(accepted["completed_pairs"], 0)
        self.assertFalse(accepted["economic_benefit_established"])
        partial = study.decode(self.store.read(rows[1]["observations"]))
        for reference in (rows[0]["result"], rows[1]["observations"],
                          partial[0]["pump"]["stdout"]["raw_bytes"],
                          partial[0]["pump"]["stderr"]["raw_bytes"]):
            path = self.root / reference["path"]
            raw = path.read_bytes()
            path.unlink()
            try:
                with self.subTest(reference=reference), self.assertRaises((ValueError, OSError)):
                    study.verify(args)
            finally:
                path.write_bytes(raw)

    def test_independent_verify_bounds_completed_and_failed_attempts_inside_outer(self):
        for last_status in ("completed", "failed"):
            # Each fixture uses a fresh directory so create-only evidence is
            # preserved independently for both status cases.
            with self.subTest(status=last_status), tempfile.TemporaryDirectory() as directory:
                original_root, original_store = self.root, self.store
                self.root = Path(directory)
                (self.root / "objects").mkdir()
                self.store = study.Store(self.root)
                try:
                    args, rows, summary = self.independent_incomplete_fixture()
                    if last_status == "completed":
                        rows[0].update(start_offset_ns=5, end_offset_ns=14)
                        rows[0]["audit_error"] = {"type": "AuthoredStopBoundary"}
                        rows[1].update(status="not_started", **{key: None for key in (
                            "result", "observations", "wall_ns", "cpu_ns", "start_offset_ns",
                            "end_offset_ns", "call_error", "audit_error")})
                    else:
                        rows[1].update(start_offset_ns=14, end_offset_ns=31)
                    plan = study.read_plan(self.root, args.expected_plan_sha256)
                    summary.update(study.results_summary(rows, plan, self.store))
                    attempted = [row for row in rows if row["status"] != "not_started"]
                    outer = max(row["end_offset_ns"] for row in attempted)
                    call_wall = sum(row["wall_ns"] for row in attempted)
                    summary["measurement"].update(all_attempted_call_wall_ns=call_wall,
                        outer_wall_ns_to_summary_preparation=outer,
                        admission_capture_export_audit_wall_ns=outer-call_wall)
                    for row in rows:
                        (self.root / f"cell-{row['pair']:02d}-{row['arm']}.json").write_bytes(study.wire(row))
                    path = self.root / "SUMMARY.json"
                    path.write_bytes(study.wire(summary))
                    self.assertEqual(study.verify(args)["campaign_status"], "INCOMPLETE")
                    summary["measurement"]["outer_wall_ns_to_summary_preparation"] -= 1
                    summary["measurement"]["admission_capture_export_audit_wall_ns"] -= 1
                    path.write_bytes(study.wire(summary))
                    with self.assertRaisesRegex(ValueError, "attempted call ends outside"):
                        study.verify(args)
                finally:
                    self.root, self.store = original_root, original_store

    def test_independent_verify_all_unstarted_does_not_invent_call_costs(self):
        args, rows, summary = self.independent_incomplete_fixture()
        for row in rows:
            row.update(status="not_started", **{key: None for key in (
                "result", "observations", "wall_ns", "cpu_ns", "start_offset_ns",
                "end_offset_ns", "call_error", "audit_error")})
            (self.root / f"cell-{row['pair']:02d}-{row['arm']}.json").write_bytes(study.wire(row))
        plan = study.read_plan(self.root, args.expected_plan_sha256)
        summary.update(study.results_summary(rows, plan, self.store))
        summary["measurement"] = {"all_attempted_call_wall_ns": 0,
            "outer_cpu_ns": {"parent": 0, "children": 0},
            "outer_wall_ns_to_summary_preparation": 0, "admission_capture_export_audit_wall_ns": 0}
        (self.root / "SUMMARY.json").write_bytes(study.wire(summary))
        result = study.verify(args)
        self.assertEqual(result["campaign_status"], "INCOMPLETE")
        self.assertEqual(result["successful_native_calls"], 0)

    def test_outer_measurements_require_exact_nonnegative_integers(self):
        args, rows, summary = self.independent_incomplete_fixture()
        original = deepcopy(summary)
        for name in ("outer_wall_ns_to_summary_preparation", "all_attempted_call_wall_ns",
                     "admission_capture_export_audit_wall_ns"):
            for invalid in (-1, True, float(original["measurement"][name])):
                changed = deepcopy(original)
                changed["measurement"][name] = invalid
                (self.root / "SUMMARY.json").write_bytes(study.wire(changed))
                with self.subTest(name=name, invalid=invalid), self.assertRaisesRegex(ValueError, "outer cost integers"):
                    study.verify(args)

    def test_incomplete_failed_attempt_cpu_remains_inside_exact_outer_counters(self):
        args, rows, summary = self.independent_incomplete_fixture()
        path = self.root / "SUMMARY.json"
        for cpu in ({"parent": 7, "children": 5}, {"parent": 10, "children": 7}):
            summary["measurement"]["outer_cpu_ns"] = cpu
            path.write_bytes(study.wire(summary))
            self.assertEqual(study.verify(args)["campaign_status"], "INCOMPLETE")
        for invalid in (None, "unmeasured", {}, {"parent": 7},
                        {"parent": 10, "children": 7, "other": 0},
                        {"parent": 6, "children": 5}, {"parent": 7, "children": 4},
                        {"parent": -1, "children": 5}, {"parent": True, "children": 5},
                        {"parent": 7.0, "children": 5}):
            if invalid is None:
                summary["measurement"].pop("outer_cpu_ns", None)
            else:
                summary["measurement"]["outer_cpu_ns"] = invalid
            path.write_bytes(study.wire(summary))
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "outer CPU"):
                study.verify(args)

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
