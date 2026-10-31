"""Maintenance contracts, public/hidden separation and independent VM controls."""
from copy import deepcopy
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from tools import qualify_hia_agent_maintenance as study


class _MaintenanceTransportFixture:
    """Controlled owner receipts only: no model, evaluator, child or hidden case."""

    usage = {"input_tokens": 11, "cached_input_tokens": 0, "output_tokens": 5,
             "reasoning_output_tokens": 2, "total_tokens": 18}
    hidden_marker = "synthetic-private-output-not-a-real-hidden-answer"

    def __init__(self, phase, fault, fault_cell=1):
        self.phase, self.fault, self.fault_cell = phase, fault, fault_cell
        self.launches = []
        self.cells = []
        self.injected = False

    def events(self, warnings):
        fixture = self

        class Events:
            turn_count = 0
            usage = None
            action = None

            def line(self, raw):
                self.turn_count = 1
                self.usage = dict(fixture.usage)
                self.action = json.loads(raw)

            def complete(self):
                return {"text": json.dumps(self.action), "usage": dict(self.usage)}

        return Events()

    def run_owned(self, argv, cwd, output, *, on_line=None, **kwargs):
        output = Path(output)
        if "_evaluate" in argv:
            phase = argv[argv.index("--mode") + 1]
            request = output.parent.parent
        else:
            phase, request = "model", output.parent
        cell = request.parent
        if cell not in self.cells:
            self.cells.append(cell)
        # Popen is replaced with a spy by every test. This is a controlled
        # launch-attempt counter, never a real subprocess or cleanup proof.
        study.subprocess.Popen(["controlled-fixture", phase])
        self.launches.append(phase)
        output.mkdir(parents=True)
        inject = (not self.injected and phase == self.phase
                  and len(self.cells) == self.fault_cell)
        self.injected |= inject
        process = {"status": "exited", "returncode": 0, "cleanup_confirmed": True,
                   "leader_reaped": True, "signal_delivered": True, "streams_complete": True,
                   "wall_ns": 47, "fixture_only": True}
        if phase == "model":
            # A public fault follows a check, so the original runner would
            # issue another model request; all other cells submit a final RPC.
            action = "check" if (self.phase == "public" and not self.injected) else "final"
            raw = json.dumps({"action": action, "candidate": {"fixture_only": True}}).encode()
            on_line(raw)
        else:
            raw = (self.hidden_marker if phase == "hidden" else "synthetic-public-prefix").encode()
            result = {"accepted": True, "correct": True, "hidden_evaluated": phase == "hidden",
                      "status": "accepted", "fixture_only": True}
            if phase == "hidden":
                result["synthetic_private_value"] = self.hidden_marker
            if inject and self.fault in {"compile_rejected", "cases_failed"}:
                result.update(accepted=False, correct=False, status=self.fault)
            study.save(Path(argv[argv.index("--output") + 1]) / "RESULT.json", result)
        (output / "stdout.raw").write_bytes(raw)
        (output / "stderr.raw").write_bytes(b"synthetic stderr prefix")
        if inject:
            if self.fault in {"uncertain", "contradictory_exit", "unreturned_receipt", "hidden_record_failure"}:
                process.update(status="cleanup_uncertain", cleanup_confirmed=False,
                               leader_reaped=False, streams_complete=False)
                if self.fault == "contradictory_exit":
                    process["status"] = "exited"
            elif self.fault in {"wall_timeout", "process_failure"}:
                process.update(status=self.fault, returncode=-9 if self.fault == "wall_timeout" else 1)
        study.save(output / "PROCESS.json", process)
        if inject and self.fault == "unreturned_receipt":
            raise OSError("synthetic owner receipt publication failure")
        return process


class MaintenanceCleanupTests(unittest.TestCase):
    """Exercise real runner control flow with synthetic, nonexecuting owners."""

    def exercise(self, phase, fault, *, fault_cell=1):
        with tempfile.TemporaryDirectory(prefix="hia-maintenance-cleanup-test-") as temp:
            root = Path(temp)
            registry = root / "synthetic-registry"
            registry.mkdir()
            # These are explicitly invalid test-only registration identities.
            # Production admission is patched; no real review is authorized.
            frozen_bytes = b'{"fixture_only":true}\n'
            (registry / "FREEZE.json").write_bytes(frozen_bytes)
            review = root / "synthetic-review.json"
            study.save(review, {"fixture_only": True, "decision": "allow_generation",
                "freeze_sha256": hashlib.sha256(frozen_bytes).hexdigest(),
                "controls_sha256": "fixture-controls-not-a-real-digest", "model_requests_by_reviewer": 0})
            cfg = study.protocol()
            fixture = _MaintenanceTransportFixture(phase, fault, fault_cell)
            original_save = study.save

            def save_fixture(path, record):
                if fault == "hidden_record_failure" and Path(path).name == "HIDDEN.json":
                    raise OSError("synthetic hidden receipt write failure")
                return original_save(path, record)

            with ExitStack() as stack:
                stack.enter_context(patch.object(study, "HERE", registry))
                stack.enter_context(patch.object(study, "protocol", return_value=cfg))
                stack.enter_context(patch.object(study, "verify_freeze", return_value={
                    "controls": {"sha256": "fixture-controls-not-a-real-digest"}}))
                stack.enter_context(patch.object(study.subprocess, "check_output", return_value=frozen_bytes))
                stack.enter_context(patch.object(study.subprocess, "run"))
                popen = stack.enter_context(patch.object(study.subprocess, "Popen"))
                stack.enter_context(patch.object(study, "public_prompt", return_value={"fixture_only": True}))
                stack.enter_context(patch.object(study.TASK_MODULE, "cases", side_effect=AssertionError("hidden evaluation forbidden")))
                stack.enter_context(patch.object(study.TASK_MODULE, "reference", side_effect=AssertionError("author answer forbidden")))
                stack.enter_context(patch.object(study, "CodexEvents", side_effect=fixture.events))
                stack.enter_context(patch.object(study, "recover_reported_usage", return_value=dict(fixture.usage)))
                stack.enter_context(patch.object(study, "run_owned", side_effect=fixture.run_owned))
                stack.enter_context(patch.object(study, "save", side_effect=save_fixture))
                result_code = study.run(root / "run", review, "synthetic-test-registration")
            result = json.loads((root / "run/RESULT.json").read_bytes())
            records = {str(p.relative_to(root / "run")): p.read_bytes()
                       for p in (root / "run").rglob("*") if p.is_file()}
            for name, raw in records.items():
                if name.endswith("REQUEST.json") or name.endswith("PUBLIC_FEEDBACK.json"):
                    self.assertNotIn(fixture.hidden_marker.encode(), raw, name)
            self.assertEqual(popen.call_count, len(fixture.launches))
            return result_code, result, fixture.launches, records

    def assert_poison_stops(self, phase, fault="uncertain", *, fault_cell=1):
        code, result, launches, records = self.exercise(phase, fault, fault_cell=fault_cell)
        prefix = ["model", "public", "hidden"] * (fault_cell - 1)
        prefix += {"model": ["model"], "public": ["model", "public"],
                   "hidden": ["model", "public", "hidden"]}[phase]
        self.assertEqual(launches, prefix, "no launch is allowed after uncertain cleanup")
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result.get("experiment_poisoned"))
        self.assertEqual(len(result["cells"]), fault_cell)
        row = result["cells"][-1]
        self.assertEqual(row["status"], "terminal_cleanup_uncertain")
        self.assertTrue(row.get("experiment_poisoned"))
        self.assertEqual(row["cleanup_uncertainty"]["phase"], phase)
        self.assertEqual(row["charged_tokens"], 18)
        self.assertEqual(row["requests"][0]["observed_usage"], _MaintenanceTransportFixture.usage)
        self.assertGreaterEqual(row["wall_ns"], 0)
        self.assertTrue(all(not group["descriptive_hia_advantage_gate"]
                            for group in result["summary"]["by_requested_model"].values()))
        self.assertEqual(sum(name.endswith("/REQUEST.json") for name in records), fault_cell)
        self.assertFalse(any(name.endswith("/PUBLIC_FEEDBACK.json") for name in records))
        self.assertTrue(any(name.endswith("/transport/stdout.raw") for name in records))
        processes = [json.loads(raw) for name, raw in records.items() if name.endswith("/PROCESS.json")]
        self.assertEqual(len(processes), len(launches))
        self.assertTrue(all(process["wall_ns"] == 47 for process in processes))
        if phase == "public":
            call = row["tool_calls"][0]
            self.assertEqual(call["public"]["status"], "evaluation_cleanup_uncertain")
            self.assertGreaterEqual(call["wall_ns"], 0)
        if phase == "hidden":
            self.assertTrue(row["hidden_evaluated"])
            self.assertGreaterEqual(row["hidden_wall_ns"], 0)
            terminal_cell = row["task"] + "-" + row["model"] + "-" + row["language"] + "/"
            hidden = [json.loads(raw) for name, raw in records.items()
                      if name.startswith(terminal_cell) and name.endswith("/HIDDEN.json")]
            if fault == "hidden_record_failure":
                self.assertEqual(hidden, [])
                self.assertEqual(row["requests"][-1]["error"]["type"], "OSError")
            else:
                self.assertEqual(len(hidden), 1)
                self.assertEqual(hidden[0]["status"], "evaluation_cleanup_uncertain")
        if fault == "unreturned_receipt":
            self.assertIsNone(row["cleanup_uncertainty"]["process"])
            self.assertEqual(row["cleanup_uncertainty"]["transport_error"]["type"], "OSError")
            self.assertGreaterEqual(row["cleanup_uncertainty"]["transport_call_wall_ns"], 0)

    def test_public_uncertain_cleanup_stops_requests_and_remaining_cells(self):
        self.assert_poison_stops("public")

    def test_hidden_uncertain_cleanup_stops_remaining_cells_without_feedback(self):
        self.assert_poison_stops("hidden")

    def test_model_uncertain_cleanup_stops_evaluators_and_remaining_cells(self):
        self.assert_poison_stops("model")

    def test_public_success_status_cannot_override_uncertain_cleanup(self):
        self.assert_poison_stops("public", "contradictory_exit")

    def test_hidden_success_status_cannot_override_uncertain_cleanup(self):
        self.assert_poison_stops("hidden", "contradictory_exit")

    def test_model_success_status_cannot_override_uncertain_cleanup(self):
        self.assert_poison_stops("model", "contradictory_exit")

    def test_public_unreturned_owner_receipt_stops_experiment_and_retains_prefix(self):
        self.assert_poison_stops("public", "unreturned_receipt")

    def test_hidden_unreturned_owner_receipt_stops_experiment_and_retains_prefix(self):
        self.assert_poison_stops("hidden", "unreturned_receipt")

    def test_model_unreturned_owner_receipt_stops_experiment_and_retains_prefix(self):
        self.assert_poison_stops("model", "unreturned_receipt")

    def test_uncertainty_after_completed_cells_never_starts_the_next_cell(self):
        self.assert_poison_stops("hidden", fault_cell=2)

    def test_hidden_receipt_write_failure_cannot_clear_experiment_poison(self):
        self.assert_poison_stops("hidden", "hidden_record_failure")

    def test_confirmed_public_compile_and_test_failures_allow_fresh_requests(self):
        for failure in ("compile_rejected", "cases_failed", "wall_timeout"):
            with self.subTest(failure=failure):
                code, result, launches, _ = self.exercise("public", failure)
                self.assertEqual(code, 0)
                self.assertEqual(result["status"], "all_cells_attempted")
                self.assertEqual(len(result["cells"]), 12)
                self.assertEqual(launches[:5], ["model", "public", "model", "public", "hidden"])
                self.assertEqual(result["cells"][0]["public_failed_checks"], 1)
                self.assertEqual(result["cells"][0]["charged_tokens"], 36)

    def test_confirmed_hidden_failure_remains_terminal_only_for_its_cell(self):
        for failure in ("cases_failed", "wall_timeout"):
            with self.subTest(failure=failure):
                code, result, launches, _ = self.exercise("hidden", failure)
                self.assertEqual(code, 0)
                self.assertEqual(len(result["cells"]), 12)
                self.assertEqual(result["cells"][0]["status"], "hidden_failed")
                self.assertEqual(launches, ["model", "public", "hidden"] * 12)

    def test_confirmed_model_failure_preserves_distinct_remaining_cells(self):
        code, result, launches, _ = self.exercise("model", "process_failure")
        self.assertEqual(code, 0)
        self.assertEqual(len(result["cells"]), 12)
        self.assertEqual(result["cells"][0]["status"], "terminal_runtime_or_protocol_failure")
        self.assertEqual(launches, ["model"] + ["model", "public", "hidden"] * 11)

    def test_stale_freeze_refuses_source_drift_before_tools_or_generation(self):
        with patch.object(study, "bindings", return_value={"synthetic-source-drift": "fixture-only"}), \
             patch.object(study, "tool_bindings", side_effect=AssertionError("tool admission reached")), \
             patch.object(study, "run_owned", side_effect=AssertionError("process launch reached")):
            with self.assertRaisesRegex(ValueError, "registered source/tool identity drift"):
                study.verify_freeze()


class _MaintenanceWallFixture(_MaintenanceTransportFixture):
    """Advance a synthetic monotonic clock at actual runner phase boundaries."""

    def __init__(self, *, after=None, preparation=None, fail_save=None):
        super().__init__("unused", "unused")
        self.now = 0.0
        self.after = after or {}
        self.preparation = preparation or {}
        self.preparation_done = set()
        self.fail_save = fail_save
        self.calls = []
        self.clock = SimpleNamespace(monotonic=lambda: self.now,
                                     monotonic_ns=lambda: int(self.now * 1_000_000_000))

    def run_owned(self, argv, cwd, output, **kwargs):
        phase = argv[argv.index("--mode") + 1] if "_evaluate" in argv else "model"
        self.calls.append({"phase": phase, "at": self.now, "allowance": kwargs["wall_seconds"]})
        result = super().run_owned(argv, cwd, output, **kwargs)
        self.now += self.after.get(phase, 0)
        return result

    def save_with(self, original, path, value):
        name = Path(path).name
        if name == self.fail_save:
            raise OSError("synthetic refused-phase receipt write failure")
        result = original(path, value)
        if name in self.preparation and name not in self.preparation_done:
            self.now += self.preparation[name]
            self.preparation_done.add(name)
        return result


class MaintenanceWallAdmissionTests(unittest.TestCase):
    """No model, evaluator, hidden answer or child is executed by these cases."""

    def exercise(self, *, after=None, preparation=None, fail_save=None,
                 experiment_deadline=100, cell_seconds=20, reserve_seconds=10):
        with tempfile.TemporaryDirectory(prefix="hia-maintenance-wall-test-") as temp:
            root = Path(temp)
            fixture = _MaintenanceWallFixture(after=after, preparation=preparation, fail_save=fail_save)
            cfg = study.protocol()
            cfg = {**cfg, "model": cfg["models"][0], "max_cell_wall_seconds": cell_seconds,
                   "cleanup_reserve_seconds": reserve_seconds}
            original_save = study.save
            row, error = None, None
            with ExitStack() as stack:
                popen = stack.enter_context(patch.object(study.subprocess, "Popen"))
                stack.enter_context(patch.object(study, "time", fixture.clock))
                stack.enter_context(patch.object(study, "public_prompt", return_value={"fixture_only": True}))
                stack.enter_context(patch.object(study.TASK_MODULE, "cases", side_effect=AssertionError("hidden evaluation forbidden")))
                stack.enter_context(patch.object(study.TASK_MODULE, "reference", side_effect=AssertionError("author answer forbidden")))
                stack.enter_context(patch.object(study, "CodexEvents", side_effect=fixture.events))
                stack.enter_context(patch.object(study, "recover_reported_usage", return_value=dict(fixture.usage)))
                stack.enter_context(patch.object(study, "run_owned", side_effect=fixture.run_owned))
                stack.enter_context(patch.object(study, "save", side_effect=lambda path, value: fixture.save_with(original_save, path, value)))
                try:
                    row = study.run_cell({"id": "synthetic-wall-case"}, "hia", root / "cell", experiment_deadline, cfg)
                except OSError as exc:
                    error = exc
            records = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            self.assertEqual(popen.call_count, len(fixture.launches))
            for name, raw in records.items():
                if name.endswith("REQUEST.json") or name.endswith("PUBLIC_FEEDBACK.json"):
                    self.assertNotIn(fixture.hidden_marker.encode(), raw)
            return row, error, fixture, records

    def assert_refused(self, row, error, fixture, phase, prefix):
        self.assertIsNone(error)
        self.assertEqual(fixture.launches, prefix, "expired work must not start another owner call")
        self.assertEqual(row["status"], "wall_budget")
        self.assertFalse(row["correct"])
        self.assertFalse(row["hidden_evaluated"])
        self.assertFalse(row["experiment_poisoned"], "a refusal before launch is not uncertain cleanup")
        refusal = row.get("wall_budget_refusal", {})
        self.assertEqual(refusal.get("phase"), phase)
        self.assertIs(refusal.get("owner_call_attempted"), False)
        self.assertLessEqual(refusal.get("remaining_seconds", 1), 0)
        self.assertEqual(row["charged_tokens"], 18 if prefix else 0)
        if prefix:
            self.assertTrue(row["complete_usage"])
            self.assertEqual(row["requests"][0]["observed_usage"], fixture.usage)
            self.assertGreaterEqual(row["wall_ns"], 10_000_000_000)
        else:
            self.assertTrue(row["requests"][0].get("model_launch_refused"))
            self.assertTrue(row["requests"][0].get("empty_cwd_removed"))

    def test_model_preparation_expiry_refuses_owner_without_uncertain_cleanup(self):
        for filename in ("REQUEST.json", "CELL.json"):
            with self.subTest(filename=filename):
                row, error, fixture, _ = self.exercise(preparation={filename: 12})
                self.assert_refused(row, error, fixture, "model", [])

    def test_public_owner_cannot_start_after_model_exhausts_work_budget(self):
        for elapsed in (10, 12):
            with self.subTest(elapsed=elapsed):
                row, error, fixture, _ = self.exercise(after={"model": elapsed})
                self.assert_refused(row, error, fixture, "public", ["model"])

    def test_hidden_owner_cannot_start_after_public_exhausts_work_budget(self):
        for elapsed in (10, 12):
            with self.subTest(elapsed=elapsed):
                row, error, fixture, records = self.exercise(after={"public": elapsed})
                self.assert_refused(row, error, fixture, "hidden", ["model", "public"])
                self.assertTrue(row["tool_calls"][0]["public"]["accepted"])
                self.assertFalse(any(name.endswith("HIDDEN.json") for name in records))

    def test_public_preparation_is_rechecked_before_owner_call(self):
        row, error, fixture, _ = self.exercise(preparation={"CANDIDATE.json": 12})
        self.assert_refused(row, error, fixture, "public", ["model"])

    def test_hidden_preparation_is_rechecked_before_owner_call(self):
        row, error, fixture, records = self.exercise(preparation={"BUILD.json": 12})
        self.assert_refused(row, error, fixture, "hidden", ["model", "public"])
        self.assertFalse(any(name.endswith("HIDDEN.json") for name in records))

    def test_positive_model_allowance_excludes_request_preparation(self):
        row, error, fixture, _ = self.exercise(preparation={"REQUEST.json": 3},
                                              after={"model": 1, "public": 2, "hidden": 1})
        self.assertIsNone(error)
        self.assertEqual(fixture.launches, ["model", "public", "hidden"])
        self.assertTrue(row["correct"] and row["complete_usage"])
        self.assertEqual(row["charged_tokens"], 18)
        for call in fixture.calls:
            self.assertGreater(call["allowance"], 0)
            self.assertLessEqual(call["allowance"], 10 - call["at"])

    def test_positive_evaluator_allowance_excludes_its_preparation(self):
        row, error, fixture, _ = self.exercise(preparation={"CANDIDATE.json": 2, "BUILD.json": 3},
                                              after={"model": 1, "public": 2, "hidden": 1})
        self.assertIsNone(error)
        self.assertEqual(fixture.launches, ["model", "public", "hidden"])
        self.assertTrue(row["correct"] and row["complete_usage"])
        for call in fixture.calls:
            self.assertGreater(call["allowance"], 0)
            self.assertLessEqual(call["allowance"], 10 - call["at"])

    def test_refusal_receipt_failure_cannot_start_another_phase(self):
        row, error, fixture, _ = self.exercise(after={"model": 12}, fail_save="RECEIPT.json")
        self.assertIsInstance(error, OSError)
        self.assertIsNone(row)
        self.assertEqual(fixture.launches, ["model"])

    def test_experiment_deadline_remains_the_tighter_admission_bound(self):
        row, error, fixture, _ = self.exercise(after={"model": 10},
                                              experiment_deadline=20, cell_seconds=720)
        self.assert_refused(row, error, fixture, "public", ["model"])


class MaintenanceStudyTests(unittest.TestCase):
    def test_every_author_repair_matches_independent_oracle_and_real_resource_witness(self):
        for task in study.TASKS:
            candidate = study.TASK_MODULE.reference(task["id"], "hia")
            verify_program(candidate)
            for values in study.TASK_MODULE.cases(task) + study.TASK_MODULE.cases(task, hidden=True):
                with self.subTest(task=task["id"], values=values):
                    observation = study.execute_hia_contract(candidate, task, values)
                    self.assertEqual(observation["result"], study.TASK_MODULE.oracle(task["id"], *values))
                    self.assertEqual(observation["resources"]["live_owners"], 0)
                    self.assertEqual(observation["resources"]["live_local_loans"], 0)

    def test_initial_programs_are_valid_and_require_actual_maintenance(self):
        for task in study.TASKS:
            initial = study.TASK_MODULE.initial(task["id"], "hia")
            verify_program(initial)
            changed = []
            for values in task["public"]:
                old = execute_program(initial, "target", values)["result"]
                changed.append(old != study.TASK_MODULE.oracle(task["id"], *values))
            self.assertTrue(any(changed), task["id"])
            self.assertNotEqual(initial, study.TASK_MODULE.reference(task["id"], "hia"))

    def test_public_prompt_contains_initial_code_but_never_reads_reference_or_hidden_cases(self):
        for task in study.TASKS:
            for language in ("hia", "rust"):
                with patch.object(study.TASK_MODULE, "reference", side_effect=AssertionError("private reference read")), \
                     patch.object(study.TASK_MODULE, "cases", side_effect=AssertionError("hidden generator read")):
                    prompt = study.public_prompt(task, language)
                self.assertEqual(prompt["initial_candidate"], study.TASK_MODULE.initial(task["id"], language))
                self.assertEqual([row["args"] for row in prompt["public_cases"]], task["public"])
                self.assertEqual(len(prompt["public_cases"]), 6)
                self.assertNotIn("hidden_cases", prompt)
                self.assertNotIn("reference", prompt)

    def test_hidden_feedback_is_terminal_and_cannot_enter_public_conversation(self):
        with self.assertRaisesRegex(ValueError, "terminal"):
            study.public_feedback({"hidden_evaluated": True, "accepted": False}, "0" * 64)
        result = {"hidden_evaluated": False, "accepted": False, "status": "cases_failed",
                  "private_secret": "not a public key"}
        self.assertNotIn("private_secret", study.public_feedback(result, "0" * 64))

    def test_removed_owner_drop_is_rejected_by_actual_core_verifier(self):
        task = next(t for t in study.TASKS if t["id"] == "buffer_resize")
        candidate = study.TASK_MODULE.reference(task["id"], "hia")
        body = candidate["functions"][0]["blocks"][0]
        body["ops"] = [op for op in body["ops"] if op["op"] != "owner.drop"]
        with self.assertRaises(ValueError):
            verify_program(candidate)

    def test_model_tiers_are_not_pooled_and_unknown_cost_never_claims_advantage(self):
        rows = []
        for model in study.protocol()["models"]:
            for task in study.TASKS:
                for language in ("hia", "rust"):
                    rows.append({"model": model, "task": task["id"], "language": language,
                                 "correct": True, "complete_usage": language == "rust",
                                 "requests": [{}], "charged_tokens": 1 if language == "hia" else 2,
                                 "public_failed_checks": 0, "wall_ns": 1 if language == "hia" else 2})
        result = study.summary(rows)
        self.assertEqual(set(result["by_requested_model"]), {"gpt-6.1-sol", "gpt-6-luna"})
        self.assertFalse(result["cross_model_pooling_used"])
        self.assertIsNone(result["human_review_time_ns"])
        self.assertFalse(result["human_cost_advantage_proved"])
        self.assertFalse(result["full_cost_advantage_proved"])
        self.assertTrue(all(not group["descriptive_hia_advantage_gate"]
                            for group in result["by_requested_model"].values()))

    def test_transport_limits_are_inherited_without_mutating_original_protocol(self):
        cfg = study.protocol()
        self.assertEqual(cfg["transport"], {"stdout_limit_bytes": 16777216,
                                          "stderr_limit_bytes": 4194304,
                                          "max_jsonl_line_bytes": 1048576})
        self.assertFalse(cfg["previous_negative_results_replaced"])

    def test_language_order_uses_stable_model_identity_when_iteration_order_reverses(self):
        cfg = study.protocol()
        self.assertEqual([study.language_order(i, "gpt-6.1-sol", cfg)[0] for i in range(3)],
                         ["hia", "rust", "hia"])
        self.assertEqual([study.language_order(i, "gpt-6-luna", cfg)[0] for i in range(3)],
                         ["rust", "hia", "rust"])


if __name__ == "__main__":
    unittest.main()
