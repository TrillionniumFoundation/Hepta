"""Registered transformation and real upstream NDU decision boundaries.

Synthetic timings below test arithmetic only. Integration tests execute the
actual pinned Rust evaluator and native compiler; no mock supplies a pass.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import signal
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.clang_capture import CaptureRejected, run_bounded, scoped_capture_deadline
from hepta.hia_ndu import (HIANDURejected, assess_samples, invoke_ndu, make_plan,
                          observe_semantics, prepare_candidate)
from hepta.hia_program import verify_program
from hepta.native_tool_identity import digest_executable
from tests.test_hia_swap_opt import source_program

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = Path(os.environ.get("HIA_NDU_BRIDGE", ROOT / "rust/hia-ndu-bridge/target/release/hia-ndu-bridge"))


def request(*, feasible=True, candidate_cost=5_000_000_000, live_bytes=5):
    return {"schema": "hepta.hia.ndu-request.v1", "objective_sha256": "a" * 64,
            "generation": 1, "maximum_live_bytes": 100, "maximum_artifact_bytes": 100_000,
            "candidates": [
                {"id": "abstain", "core_sha256": "b" * 64, "artifact_sha256": "c" * 64,
                 "evidence_sha256": "d" * 64, "feasible": True,
                 "projected_total_ns": 10_000_000_000, "peak_live_bytes": 5, "artifact_bytes": 1000},
                {"id": "byte_swap", "core_sha256": "e" * 64, "artifact_sha256": "f" * 64,
                 "evidence_sha256": "1" * 64, "feasible": feasible,
                 "projected_total_ns": candidate_cost, "peak_live_bytes": live_bytes, "artifact_bytes": 1000}]}


class CandidatePlanTests(unittest.TestCase):
    def setUp(self):
        self.source = source_program()
        self.plan = make_plan(self.source, entry="swap_candidate")

    def test_candidate_is_reproduced_from_exact_core(self):
        prepared = prepare_candidate(self.source, self.plan)
        self.assertEqual(prepared.replacements, 1)
        self.assertNotEqual(prepared.baseline.sha256, prepared.candidate.sha256)
        again = prepare_candidate(prepared.baseline, prepared.plan,
                                  candidate_bytes=prepared.candidate.canonical_bytes)
        self.assertEqual(again.candidate.sha256, prepared.candidate.sha256)
        self.plan["objective"]["horizon_calls"] = 1
        self.assertEqual(prepared.plan["objective"]["horizon_calls"], 100_000_000)

    def test_type_safe_behavior_change_is_not_registered_rewrite(self):
        prepared = prepare_candidate(self.source, self.plan)
        changed = prepared.candidate.as_dict()
        op = next(op for op in changed["functions"][0]["blocks"][0]["ops"]
                  if op["op"] == "const" and op["attrs"]["value"] == 11)
        op["attrs"]["value"] = 99
        type_safe = verify_program(changed)
        with self.assertRaisesRegex(HIANDURejected, "differs from"):
            prepare_candidate(self.source, self.plan, candidate_bytes=type_safe.canonical_bytes)

    def test_stale_identity_unknown_plan_and_zero_generation_refused(self):
        edits = [("baseline_sha256", "f" * 64), ("generation", 0),
                 ("generation", True), ("pass_id", "model-says-safe"),
                 ("permission", True)]
        for key, value in edits:
            plan = copy.deepcopy(self.plan)
            plan[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(HIANDURejected):
                prepare_candidate(self.source, plan)

    def test_v7_does_not_silently_downgrade(self):
        source = copy.deepcopy(self.source)
        source["schema"] = "hepta.hia.program.v7"
        # Use the actual registered schema spelling, not a forged version name.
        from hepta.hia_schema import SCHEMA_V7
        source["schema"] = SCHEMA_V7
        plan = make_plan(source, entry="swap_candidate")
        prepared = prepare_candidate(source, plan)
        self.assertEqual(prepared.replacements, 1)
        self.assertEqual(prepared.baseline.as_dict()["schema"], SCHEMA_V7)
        self.assertEqual(prepared.candidate.as_dict()["schema"], SCHEMA_V7)
        self.assertEqual(prepared.plan["baseline_sha256"], prepared.baseline.sha256)

    def test_actual_values_traps_failure_and_full_resource_observations(self):
        prepared = prepare_candidate(self.source, self.plan)
        observed = observe_semantics(prepared, [[5, 0, 4, 0], [5, 2, 2, 2]],
                                    negative_cases=[[4, 0, 3, 0], [5, 5, 0, 0], [5, 0, 5, 0], [5, 0, 4, 5]])
        self.assertTrue(observed["ok"])
        self.assertEqual(len(observed["observations"]), 12)
        self.assertTrue(all(row["match"] for row in observed["observations"]))
        self.assertTrue(any(row["baseline"].get("trap_code") == "allocation"
                            for row in observed["observations"]))
        self.assertTrue(any(row["baseline"].get("trap_code") == "bounds"
                            for row in observed["observations"]))

    def test_fill_loop_plan_binds_the_registered_rule(self):
        from hepta.hia_fill_loop_opt import PASS_ID as FILL_PASS
        from tests.test_hia_fill_loop_opt import fill_loop_program
        source = fill_loop_program()
        plan = make_plan(source, entry="fill_probe", pass_id=FILL_PASS)
        candidate = prepare_candidate(source, plan)
        self.assertEqual(candidate.replacements, 1)
        self.assertEqual(candidate.candidate_id, "fill_loop")
        self.assertEqual(candidate.plan["pass_id"], FILL_PASS)
        observed = observe_semantics(candidate, [[1, 7, 0, 0], [32, 173, 31, 17]],
                                     negative_cases=[[0, 7, 0, 0], [4, 7, 4, 0], [4, 256, 0, 0]])
        self.assertTrue(observed["ok"])
        wrong_rule = make_plan(source, entry="fill_probe")
        with self.assertRaisesRegex(HIANDURejected, "differs from"):
            prepare_candidate(source, wrong_rule, candidate_bytes=candidate.candidate.canonical_bytes)

    def test_rule_identifiers_are_closed_and_exact_strings(self):
        for bad in ([], {}, True, "full-view-fill-loop.v2", "model-derived"):
            with self.subTest(value=bad), self.assertRaises(HIANDURejected):
                make_plan(self.source, entry="swap_candidate", pass_id=bad)
            plan = copy.deepcopy(self.plan)
            plan["pass_id"] = bad
            with self.subTest(plan_value=bad), self.assertRaises(HIANDURejected):
                prepare_candidate(self.source, plan)

    def test_checked_reduction_registry_reproduces_exact_candidate_and_trap_order(self):
        from hepta.hia_checked_reduction_opt import PASS_ID as REDUCTION_PASS
        from tests.test_hia_checked_reduction_opt import reduction_probe_program
        source = reduction_probe_program()
        plan = make_plan(source, entry="reduction_probe", pass_id=REDUCTION_PASS)
        candidate = prepare_candidate(source, plan)
        self.assertEqual(candidate.replacements, 1)
        self.assertEqual(candidate.candidate_id, "checked_reduction")
        observed = observe_semantics(candidate, [[0, 7, 9, 3], [16, 11, 32, 17], [512, 13, 5, 255]],
                                     negative_cases=[[2, (1 << 64) - 1, 0, 0],
                                                     [2, (1 << 64) - 1, 0, 256],
                                                     [0, 0, 0, 256]])
        self.assertTrue(observed["ok"], observed)
        wrong_rule = make_plan(source, entry="reduction_probe")
        with self.assertRaisesRegex(HIANDURejected, "differs from"):
            prepare_candidate(source, wrong_rule, candidate_bytes=candidate.candidate.canonical_bytes)


class MeasurementPolicyTests(unittest.TestCase):
    def setUp(self):
        self.objective = make_plan(source_program(), entry="swap_candidate")["objective"]

    def assess(self, pairs, cost=0):
        return assess_samples([{"baseline_ns": b, "candidate_ns": c} for b, c in pairs],
                              calls_per_sample=1000, objective=self.objective, search_cost_ns=cost)

    def test_synthetic_clear_gain_and_cost_projection_arithmetic(self):
        report = self.assess([(1_000_000, 500_000)] * 31)
        self.assertTrue(report["eligible"])
        self.assertEqual(report["projected_baseline_total_ns"], 100_000_000_000)
        self.assertEqual(report["projected_candidate_total_ns"], 52_000_000_000)
        self.assertFalse(report["statistical_confidence_proved"])

    def test_synthetic_regression_tie_and_paid_cost_retain_baseline(self):
        for candidate in (1_000_000, 1_500_000):
            with self.subTest(candidate=candidate):
                self.assertFalse(self.assess([(1_000_000, candidate)] * 31)["eligible"])
        self.objective["horizon_calls"] = 1
        report = self.assess([(1_000_000, 500_000)] * 31)
        self.assertIn("experiment_cost_not_recovered", report["reasons"])

    def test_synthetic_noisy_and_over_budget_measurements_rejected(self):
        report = self.assess([(v, 500_000) for v in [800_000, 1_000_000, 1_200_000] * 10 + [1_000_000]])
        self.assertIn("baseline_timing_noise", report["reasons"])
        self.assertIn("search_cost_budget", self.assess([(1_000_000, 500_000)] * 31,
                                                       cost=60_000_000_000)["reasons"])

    def test_no_sample_trimming_invalid_samples_rejected(self):
        for pairs in ([(1, 1)] * 14, [(1, 1)] * 16, [(1, 1)] * 65, [(1, 0)] * 31):
            with self.subTest(count=len(pairs)), self.assertRaises(HIANDURejected):
                self.assess(pairs)

    def test_objective_must_remain_in_the_declared_profile(self):
        for key, value in (("maximum_mad_ppm", 1_000_000), ("horizon_calls", True),
                           ("minimum_gain_ppm", -1), ("model_override", True)):
            original = copy.deepcopy(self.objective)
            self.objective[key] = value
            with self.subTest(key=key), self.assertRaises(HIANDURejected):
                self.assess([(1_000_000, 500_000)] * 31)
            self.objective = original

    def test_identical_native_bytes_cannot_turn_favorable_noise_into_gain(self):
        samples = [{"baseline_ns": 1_000_000, "candidate_ns": 500_000}] * 31
        ordinary = assess_samples(samples, calls_per_sample=1000, objective=self.objective,
                                  search_cost_ns=0, baseline_artifact_sha256="a" * 64,
                                  candidate_artifact_sha256="b" * 64)
        duplicate = assess_samples(samples, calls_per_sample=1000, objective=self.objective,
                                   search_cost_ns=0, baseline_artifact_sha256="a" * 64,
                                   candidate_artifact_sha256="a" * 64)
        self.assertTrue(ordinary["eligible"])
        self.assertFalse(duplicate["eligible"])
        self.assertEqual(duplicate["reasons"], ["identical_native_artifacts"])
        self.assertTrue(duplicate["native_artifact_identity_checked"])
        self.assertFalse(duplicate["native_artifact_changed"])
        self.assertEqual(duplicate["schema"], "hepta.hia.ndu-measurement-policy.v2")

    def test_partial_or_invalid_native_identity_is_not_a_comparison(self):
        samples = [{"baseline_ns": 1_000_000, "candidate_ns": 500_000}] * 31
        for before, after in (("a" * 64, None), (None, "b" * 64), ("0" * 64, "b" * 64),
                              (True, "b" * 64), ("a" * 64, "B" * 64)):
            with self.subTest(before=before, after=after), self.assertRaises(HIANDURejected):
                assess_samples(samples, calls_per_sample=1000, objective=self.objective,
                               search_cost_ns=0, baseline_artifact_sha256=before,
                               candidate_artifact_sha256=after)


class EvidencePublicationTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX process-group cleanup required")
    def test_cooperative_deadline_reaps_separate_process_group_and_retains_output(self):
        from tools.qualify_hia_ndu import cooperative_deadline
        started = time.monotonic()
        with cooperative_deadline(1) as deadline:
            with self.assertRaises(CaptureRejected) as caught:
                run_bounded([sys.executable, "-c",
                    "import os,sys,time; print('started',os.getpid(),os.getpgrp(),os.getsid(0),flush=True);"
                    "print('partial stderr',file=sys.stderr,flush=True); time.sleep(30)"], timeout=20)
        self.assertTrue(deadline["expired"])
        self.assertEqual(deadline["enforcement"], "tool_poll_and_phase_boundary")
        self.assertFalse(deadline["asynchronous_signal"])
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual(caught.exception.code, "E_CAPTURE_TOTAL_DEADLINE")
        capture = caught.exception.capture
        self.assertIsNotNone(capture)
        self.assertEqual(capture.returncode, -signal.SIGKILL)
        self.assertTrue(capture.stdout.startswith(b"started "))
        pid, group, session = map(int, capture.stdout.split()[1:])
        self.assertEqual((group, session), (pid, pid))
        self.assertNotEqual(group, os.getpgrp())
        self.assertEqual(capture.stderr, b"partial stderr\n")
        self.assertEqual(capture.stdout_total_bytes, len(capture.stdout))
        self.assertEqual(capture.stderr_total_bytes, len(capture.stderr))
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_phase_boundary_deadline_fails_actual_qualifier_before_measurement(self):
        from tools.qualify_hia_ndu import qualify
        source = source_program()
        plan = make_plan(source, entry="swap_candidate")
        with scoped_capture_deadline(.02) as deadline:
            time.sleep(.04)
            report = qualify(source, plan, [[5, 0, 4, 0]], bridge=BRIDGE,
                             expected_bridge_sha256="a" * 64)
        self.assertTrue(deadline.expired)
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "failed_closed_no_change")
        self.assertEqual(report["diagnostics"][0]["code"], "E_CAPTURE_TOTAL_DEADLINE")
        self.assertNotIn("measurement", report)

    def test_cooperative_deadline_retains_partial_measurement_capture(self):
        from tools.hia_ndu_measure import _events, _process
        from tools.qualify_hia_ndu import cooperative_deadline
        # The event is a parser/capture control emitted by a real child. It is
        # not a native timing observation and cannot establish any gain.
        event = {"kind": "sample", "pair": 0, "position": 0, "backend": "baseline",
                 "elapsed_ns": 100, "process_cpu_ns": 80, "checksum": 7}
        child = "import time; print(" + repr(json.dumps(event)) + ",flush=True); time.sleep(30)"
        report = {"processes": [], "correctness": {}}
        with tempfile.TemporaryDirectory() as temporary:
            with cooperative_deadline(1) as deadline:
                row = _process(report, "deadline_capture_control", [sys.executable, "-c", child],
                               Path(temporary), timeout=20)
        self.assertTrue(deadline["expired"])
        self.assertEqual(row["capture_error"], "E_CAPTURE_TOTAL_DEADLINE")
        self.assertEqual(json.loads(row["stdout"]), event)
        _events(report, row)
        self.assertEqual(report["raw_events"], [event])
        self.assertEqual(len(report["raw_samples"]), 1)
        self.assertEqual(report["raw_samples"][0]["baseline_ns"], 100)
        self.assertNotIn("candidate_ns", report["raw_samples"][0])

    def arguments(self, output):
        return ["qualify_hia_ndu", "--program", str(ROOT / "examples/hia_ndu/byte_swap.json"),
                "--cases", str(ROOT / "examples/hia_ndu/byte_swap_cases.json"),
                "--entry", "swap_candidate", "--bridge", str(BRIDGE),
                "--bridge-sha256", "a" * 64, "--output", str(output)]

    def test_existing_output_refused_before_experiment_is_paid(self):
        from tools.qualify_hia_ndu import main
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            output.write_text("existing evidence\n")
            with patch("sys.argv", self.arguments(output)), patch("tools.qualify_hia_ndu.qualify") as search:
                with self.assertRaises(FileExistsError):
                    main()
                search.assert_not_called()
            self.assertEqual(output.read_text(), "existing evidence\n")

    def test_interrupted_experiment_leaves_explicit_failure_record(self):
        from tools.qualify_hia_ndu import main
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            with patch("sys.argv", self.arguments(output)), patch("tools.qualify_hia_ndu.qualify",
                    side_effect=KeyboardInterrupt("injected publication control")):
                with self.assertRaises(KeyboardInterrupt):
                    main()
            report = json.loads(output.read_text())
            self.assertFalse(report["ok"])
            self.assertEqual(report["status"], "interrupted_no_change")
            self.assertFalse(report["activated"])

    def test_cli_rejects_late_return_even_without_a_tool_poll(self):
        from tools.qualify_hia_ndu import main
        # An injected publication-control result is not native performance or
        # evaluator evidence. The elapsed clock and CLI rejection are real.
        def late_result(*args, **kwargs):
            time.sleep(1.05)
            return {"ok": True, "status": "completed_candidate_advised",
                    "decision": "candidate_advised", "activated": False, "diagnostics": []}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            arguments = self.arguments(output) + ["--deadline-seconds", "1"]
            with patch("sys.argv", arguments), patch("tools.qualify_hia_ndu.qualify", side_effect=late_result):
                self.assertEqual(main(), 1)
            report = json.loads(output.read_text())
            self.assertFalse(report["ok"])
            self.assertEqual((report["status"], report["decision"]), ("failed_closed_no_change", "no_change"))
            self.assertTrue(report["cooperative_deadline"]["expired"])
            self.assertFalse(report["cooperative_deadline"]["asynchronous_signal"])
            self.assertEqual(report["diagnostics"][-1]["code"], "E_CAPTURE_TOTAL_DEADLINE")


class FrozenProtocolReportTests(unittest.TestCase):
    """Synthetic report controls only; these are not performance evidence."""

    @classmethod
    def setUpClass(cls):
        path = ROOT / "experiments/hia_ndu_native_20261027/run_frozen.py"
        spec = importlib.util.spec_from_file_location("hia_frozen_report_controls", path)
        cls.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runner)
        cls.protocol = json.loads(path.with_name("protocol.json").read_text())

    def control(self, spec):
        cases = json.loads((ROOT / spec["cases"]).read_text())
        source = verify_program((ROOT / spec["program"]).read_bytes())
        plan = make_plan(source, entry=spec["entry"], pass_id=spec["pass_id"],
                         horizon_calls=self.protocol["horizon_calls"])
        samples, iterations = self.protocol["samples"], self.protocol["iterations"]
        rows = [{"pair": index, "baseline_ns": 2_000_000, "candidate_ns": 1_000_000}
                for index in range(samples)]
        counts = {"cases": len(cases), "paired_samples": samples,
                  "calls_per_sample": iterations * len(cases),
                  "timed_calls_total": 2 * samples * iterations * len(cases),
                  "untimed_correctness_calls": 2 * len(cases)}
        assessment = assess_samples(rows, calls_per_sample=counts["calls_per_sample"],
                                    objective=plan["objective"], search_cost_ns=1,
                                    baseline_artifact_sha256="1" * 64, candidate_artifact_sha256="2" * 64)
        report = {"schema": "hepta.hia.ndu-qualification.v1", "status": "completed_no_change",
                  "ok": True, "decision": "no_change", "activated": False, "plan": plan,
                  "costs": {"total_paid_wall_ns": 1}, "diagnostics": [],
                  "budget_enforcement": {"decision_reserve_ns": assessment["decision_reserve_ns"]},
                  "cooperative_deadline": {**self.protocol["cooperative_deadline"], "expired": False},
                  "assessment": assessment,
                  "measurement": {"ok": True, "status": "finite_pair_measured_no_selection_authority",
                                  "protocol": {"samples": samples, "iterations": iterations,
                                               "sample_trimming": False, "adaptive_repetition": False},
                                  "input": {"entry": spec["entry"], "cases": cases},
                                  "counts": counts, "raw_samples": rows,
                                  "native": {"baseline": {"artifact_sha256": "1" * 64},
                                             "candidate": {"artifact_sha256": "2" * 64}}}}
        return report, cases

    def check(self, report, spec, cases, returncode=0):
        return self.runner.check_report(report, self.protocol, spec, cases=cases, returncode=returncode)

    def test_fixed_reports_match_actual_plan_defaults_and_each_case_inventory(self):
        for spec in self.protocol["runs"]:
            with self.subTest(run=spec["id"]):
                report, cases = self.control(spec)
                result = self.check(report, spec, cases)
                self.assertTrue(result["complete"], result["errors"])
                self.assertTrue(result["measurement_complete"])
                self.assertFalse(result["stop_protocol"])

    def test_reduction_protocol_is_fixed_and_matches_its_actual_inputs(self):
        from hashlib import sha256
        protocol = json.loads((ROOT / "experiments/hia_checked_reduction_20261027/protocol.json").read_text())
        self.assertTrue(protocol["retain_native_artifacts"])
        self.assertEqual((protocol["samples"], protocol["iterations"], len(protocol["runs"])), (31, 50000, 2))
        self.assertFalse(protocol["repeats_until_pass"])
        for item in protocol["input_files"]:
            self.assertEqual(sha256((ROOT / item["path"]).read_bytes()).hexdigest(), item["sha256"])
        for spec in protocol["runs"]:
            cases = json.loads((ROOT / spec["cases"]).read_text())
            expected = self.runner._protocol_expectations(protocol, spec, cases)
            self.assertEqual(expected["counts"]["timed_calls_total"], 55_800_000)
            self.assertEqual(expected["counts"]["untimed_correctness_calls"], 36)
            self.assertEqual(expected["objective"]["maximum_mad_ppm"], 50_000)

    def test_each_objective_reserve_and_native_call_budget_drift_stops_protocol(self):
        spec = self.protocol["runs"][0]
        original, cases = self.control(spec)
        paths = [("plan", "objective", key) for key in original["plan"]["objective"]]
        paths += [("budget_enforcement", "decision_reserve_ns"), ("assessment", "decision_reserve_ns")]
        paths += [("measurement", "protocol", key) for key in ("samples", "iterations")]
        paths += [("measurement", "counts", key) for key in original["measurement"]["counts"]]
        for path in paths:
            changed = copy.deepcopy(original)
            cursor = changed
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] += 1
            with self.subTest(field=".".join(path)):
                result = self.check(changed, spec, cases)
                self.assertFalse(result["complete"])
                self.assertTrue(result["stop_protocol"])
                self.assertTrue(result["errors"])

    def test_expired_truncated_missing_or_changed_case_report_cannot_complete(self):
        spec = self.protocol["runs"][0]
        original, cases = self.control(spec)
        for mode in ("expired", "truncated", "case_bytes", "missing", "exit_code"):
            changed = copy.deepcopy(original)
            if mode == "expired":
                changed["cooperative_deadline"]["expired"] = True
            elif mode == "truncated":
                changed["measurement"]["raw_samples"].pop()
            elif mode == "case_bytes":
                changed["measurement"]["input"]["cases"][0][1] += 1
            elif mode == "missing":
                changed = None
            with self.subTest(mode=mode):
                result = self.check(changed, spec, cases, returncode=1 if mode == "exit_code" else 0)
                self.assertFalse(result["complete"])
                self.assertFalse(result["measurement_complete"])
                self.assertTrue(result["stop_protocol"])

    def test_final_failed_attempt_is_retained_without_inventing_completed_measurement(self):
        spec = self.protocol["runs"][0]
        report, cases = self.control(spec)
        report.update(ok=False, status="failed_closed_no_change",
                      diagnostics=[{"type": "CaptureRejected", "code": "E_CAPTURE_TIMEOUT"}])
        del report["measurement"]
        del report["assessment"]
        result = self.check(report, spec, cases, returncode=1)
        self.assertTrue(result["complete"], result["errors"])
        self.assertFalse(result["measurement_complete"])
        self.assertFalse(result["stop_protocol"])
        self.assertEqual(result["outcome"], "completed_failed_closed_attempt")
        del report["costs"]["total_paid_wall_ns"]
        incomplete = self.check(report, spec, cases, returncode=1)
        self.assertFalse(incomplete["complete"])
        self.assertTrue(incomplete["stop_protocol"])


@unittest.skipUnless(BRIDGE.is_file(), "build the pinned real NDU bridge to execute integration tests")
class ActualNDUBridgeTests(unittest.TestCase):
    def call(self, value):
        return invoke_ndu(value, bridge=BRIDGE, expected_binary_sha256=digest_executable(BRIDGE))

    def test_actual_ndu_recommends_only_advisory_and_binds_support(self):
        report = self.call(request())
        self.assertEqual(report["response"]["advisory_recommendation"], "byte_swap")
        self.assertEqual(report["response"]["authority"], "DENY_ALL")
        self.assertFalse(report["activated"])
        self.assertEqual(report["response"]["generation"], 1)

    def test_receipt_is_bound_to_submitted_snapshot(self):
        from hepta.hia_ndu import identity
        value = request()
        report = self.call(value)
        value["candidates"][1]["projected_total_ns"] = 999
        self.assertEqual(report["request"]["candidates"][1]["projected_total_ns"], 5_000_000_000)
        self.assertEqual(report["request_sha256"], identity(report["request"]))

    def test_actual_ndu_rejects_hard_failure_and_resource_overflow(self):
        for req in (request(feasible=False), request(live_bytes=101)):
            with self.subTest(req=req):
                reply = self.call(req)["response"]
                self.assertEqual(reply["advisory_recommendation"], "abstain")
                self.assertEqual(reply["rejected"][0]["id"], "byte_swap")

    def test_actual_ndu_retains_tie_frontier(self):
        reply = self.call(request(candidate_cost=10_000_000_000))["response"]
        self.assertIsNone(reply["advisory_recommendation"])
        self.assertEqual(reply["disposition"], "ParetoSetRequiresSlowPath")

    def test_missing_or_infeasible_abstain_refused(self):
        missing, infeasible = request(), request()
        missing["candidates"] = missing["candidates"][1:]
        infeasible["candidates"][0]["feasible"] = False
        for value in (missing, infeasible):
            with self.subTest(value=value), self.assertRaises(HIANDURejected):
                self.call(value)

    def test_duplicate_json_and_unknown_fields_refused_by_real_rust(self):
        payload = json.dumps(request())
        payload = payload.replace('"generation": 1', '"generation": 1, "generation": 1')
        result = run_bounded([str(BRIDGE)], input_text=payload)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(json.loads(result.stdout)["ok"])
        value = request()
        value["model_claims_proved"] = True
        with self.assertRaises(HIANDURejected):
            self.call(value)

    def test_wrong_binary_identity_refused_before_launch(self):
        with patch("hepta.hia_ndu.run_bounded") as launch:
            with self.assertRaisesRegex(HIANDURejected, "identity mismatch"):
                invoke_ndu(request(), bridge=BRIDGE, expected_binary_sha256="a" * 64)
            launch.assert_not_called()

    def test_tampered_reply_cannot_change_evidence_generation_or_authority(self):
        reply = self.call(request())["response"]
        for mode in ("generation", "authority", "artifact", "support", "duplicate"):
            changed = copy.deepcopy(reply)
            if mode == "generation":
                changed["generation"] = 2
            elif mode == "authority":
                changed["authority"] = "ALLOW"
            elif mode == "duplicate":
                changed["bindings"][1] = copy.deepcopy(changed["bindings"][0])
            else:
                changed["bindings"][0]["artifact_sha256" if mode == "artifact" else "support_sha256"] = "2" * 64
            with self.subTest(mode=mode), patch("hepta.hia_ndu.run_bounded", return_value=
                    SimpleNamespace(returncode=0, stdout=json.dumps(changed), stderr="")):
                with self.assertRaises(HIANDURejected):
                    self.call(request())

    @unittest.skipUnless(Path("/usr/bin/clang-20").is_file(), "Clang 20 native integration")
    def test_complete_native_candidate_loop_can_select_no_change(self):
        from tools.qualify_hia_ndu import qualify
        source = source_program()
        plan = make_plan(source, entry="swap_candidate", horizon_calls=1)
        report = qualify(source, plan, [[5, 0, 4, 0], [5, 2, 2, 2]],
                         negative_cases=[[5, 5, 0, 0]], bridge=BRIDGE,
                         expected_bridge_sha256=digest_executable(BRIDGE),
                         clang="/usr/bin/clang-20", samples=15, iterations=1000)
        self.assertTrue(report["ok"], report["diagnostics"])
        self.assertEqual(report["decision"], "no_change")
        self.assertTrue(report["claims"]["real_ndu_evaluator_executed"])
        self.assertFalse(report["activated"])
        self.assertIn("experiment_cost_not_recovered", report["assessment"]["reasons"])
        self.assertIn("identical_native_artifacts", report["assessment"]["reasons"])
        self.assertEqual(report["ndu"]["response"]["advisory_recommendation"], "abstain")
        self.assertEqual(len(report["measurement"]["raw_samples"]), 15)

    @unittest.skipUnless(Path("/usr/bin/clang-20").is_file(), "Clang 20 native integration")
    def test_registered_fill_loop_reaches_actual_ndu_with_exact_candidate_identity(self):
        from hepta.hia_fill_loop_opt import PASS_ID as FILL_PASS
        from tests.test_hia_fill_loop_opt import fill_loop_program
        from tools.qualify_hia_ndu import qualify
        source = fill_loop_program()
        plan = make_plan(source, entry="fill_probe", pass_id=FILL_PASS, horizon_calls=1)
        report = qualify(source, plan, [[7, 173, 6, 93]], negative_cases=[[7, 173, 7, 93]],
                         bridge=BRIDGE, expected_bridge_sha256=digest_executable(BRIDGE),
                         clang="/usr/bin/clang-20", samples=15, iterations=2)
        self.assertTrue(report["ok"], report["diagnostics"])
        self.assertEqual(report["decision"], "no_change")
        self.assertEqual(report["candidate"]["relation"], "exact_reproduced_fill_loop")
        self.assertEqual([candidate["id"] for candidate in report["ndu"]["request"]["candidates"]],
                         ["abstain", "fill_loop"])
        self.assertTrue(report["claims"]["real_ndu_evaluator_executed"])
        self.assertFalse(report["activated"])


if __name__ == "__main__":
    unittest.main()
