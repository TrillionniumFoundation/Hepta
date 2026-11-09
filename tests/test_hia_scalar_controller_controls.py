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
            "outer_wall_ns_to_summary_preparation": 0, "admission_capture_export_audit_wall_ns": 0}
        (self.root / "SUMMARY.json").write_bytes(study.wire(summary))
        result = study.verify(args)
        self.assertEqual(result["campaign_status"], "INCOMPLETE")
        self.assertEqual(result["successful_native_calls"], 0)

    def test_outer_measurements_require_exact_nonnegative_integers(self):
        args, rows, summary = self.independent_incomplete_fixture()
        original = deepcopy(summary)
        for name in summary["measurement"]:
            for invalid in (-1, True, float(original["measurement"][name])):
                changed = deepcopy(original)
                changed["measurement"][name] = invalid
                (self.root / "SUMMARY.json").write_bytes(study.wire(changed))
                with self.subTest(name=name, invalid=invalid), self.assertRaisesRegex(ValueError, "outer cost integers"):
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


class RetainedScalarOuterIntervalTests(unittest.TestCase):
    """Offline audit of the original native records; no evaluator is launched."""
    @classmethod
    def setUpClass(cls):
        path = (Path(__file__).resolve().parents[1] / "review-evidence"
                / "hia-ndu-scalar-controls-20261108-23d1" / "original-campaign.zip")
        raw = path.read_bytes()
        if sha256(raw).hexdigest() != "d9025d10bacdd5e8558625c26fce40130effc87e05fe962a2387bfd4680add6d":
            raise AssertionError("retained scalar campaign archive differs")
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if archive.testzip() is not None:
                raise AssertionError("retained scalar campaign CRC differs")
            cls.files = {name.removeprefix("campaign/"): archive.read(name)
                         for name in archive.namelist() if name.startswith("campaign/") and not name.endswith("/")}

    def verify_files(self, files):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_read, original_iterdir = study.read_bytes, Path.iterdir

            def read(path):
                path = Path(path)
                return files[str(path.relative_to(root))] if path.is_relative_to(root) else original_read(path)

            def iterdir(path):
                if path == root / "objects":
                    return iter(root / name for name in files if name.startswith("objects/"))
                return original_iterdir(path)

            args = SimpleNamespace(directory=root, expected_plan_sha256=sha256(files["PLAN.json"]).hexdigest(), output=None)
            with patch.object(study, "read_bytes", read), patch.object(Path, "iterdir", iterdir):
                return study.verify(args)

    def test_original_campaign_keeps_all_128_cells_and_64_native_calls(self):
        result = self.verify_files(self.files)
        self.assertEqual(result["verification"], "ORIGINAL_BYTES_AND_ACCOUNTING_VERIFIED")
        self.assertEqual(result["campaign_status"], "MECHANISM_COMPLETE")
        self.assertEqual((result["scheduled_cells_verified"], result["successful_native_calls"]), (128, 64))
        self.assertEqual(result["new_native_calls"], 0)
        self.assertFalse(result["economic_benefit_established"])

    def test_review_4509542158_understated_outer_is_rejected(self):
        files = dict(self.files)
        summary = study.decode(files["SUMMARY.json"])
        costs = summary["measurement"]
        self.assertEqual(costs["all_attempted_call_wall_ns"], 943383830)
        self.assertEqual(max(row["end_offset_ns"] for row in summary["cells"]), 1280472124)
        costs["outer_wall_ns_to_summary_preparation"] = costs["all_attempted_call_wall_ns"]
        costs["admission_capture_export_audit_wall_ns"] = 0
        files["SUMMARY.json"] = study.wire(summary)
        with self.assertRaisesRegex(ValueError, "attempted call ends outside"):
            self.verify_files(files)

    def test_original_outer_times_cannot_be_replaced_by_equal_python_floats(self):
        for name in ("outer_wall_ns_to_summary_preparation", "all_attempted_call_wall_ns",
                     "admission_capture_export_audit_wall_ns"):
            files = dict(self.files)
            summary = study.decode(files["SUMMARY.json"])
            summary["measurement"][name] = float(summary["measurement"][name])
            files["SUMMARY.json"] = study.wire(summary)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "outer cost integers"):
                self.verify_files(files)

    def test_summary_cannot_replace_exact_original_offsets_and_counts_by_floats(self):
        for field in ("end_offset_ns", "successful_native_calls", "completed_pairs"):
            files = dict(self.files)
            summary = study.decode(files["SUMMARY.json"])
            target = summary["cells"][0] if field == "end_offset_ns" else summary
            original = deepcopy(summary)
            target[field] = float(target[field])
            self.assertEqual(summary, original)
            files["SUMMARY.json"] = study.wire(summary)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "summary differs|recomputation differs"):
                self.verify_files(files)


if __name__ == "__main__":
    unittest.main()
