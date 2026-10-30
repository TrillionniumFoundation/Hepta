"""New author controls and absent-provider evidence are not model observations."""
from copy import deepcopy
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from tools.qualify_hia_agent_maintenance import (
    PROTOCOL_PATH, TASK_MODULE, bindings, evaluate_patch, execute_contract, parse_action, provider_preflight,
    public_prompt, run_cell, run_registered, summarize_cells, task_controls, wire,
)


class FreshMaintenanceTests(unittest.TestCase):
    def test_actual_failed_startup_raw_replays_only_exact_registered_warnings(self):
        from tools.hia_agent_codex_transport import CodexEvents, EventFailure
        protocol = json.loads(PROTOCOL_PATH.read_bytes())
        amendment = protocol["amendments"][-1]
        raw = (PROTOCOL_PATH.parents[2] / amendment["raw_fixture"]).read_bytes()
        self.assertEqual(sha256(raw).hexdigest(),
                         "006bf62e8d9d462fcb419ee49a53212ef77ce038e466775bc8bc6f1dd4e95f63")
        self.assertEqual(sha256(raw).hexdigest(), amendment["raw_fixture_sha256"])
        lines = raw.splitlines()
        parser = CodexEvents(protocol["registered_startup_warnings"])
        for line in lines:
            parser.line(line)
        self.assertEqual(len(protocol["registered_startup_warnings"]), 4)
        self.assertEqual(sorted(Counter(protocol["registered_startup_warnings"]).values()), [1, 1, 2])
        self.assertEqual(parser.warning_counts, dict(Counter(protocol["registered_startup_warnings"])))
        self.assertEqual((parser.thread_count, parser.turn_count), (1, 1))
        self.assertEqual(parser.messages, [])
        self.assertIsNone(parser.usage)
        self.assertTrue(parser.unknown_usage)
        # Replaying an actual startup failure never manufactures a model
        # answer or known usage; original attempt01 remains ineligible.
        with self.assertRaisesRegex(EventFailure, "INCOMPLETE_RESPONSE_OR_USAGE"):
            parser.complete()
        original = CodexEvents([])
        original.line(lines[0])
        with self.assertRaisesRegex(EventFailure, "TOOL_OR_UNREGISTERED_ITEM"):
            original.line(lines[1])

    def test_actual_startup_warning_registry_rejects_unknown_excess_and_late_items(self):
        from tools.hia_agent_codex_transport import CodexEvents, EventFailure
        protocol = json.loads(PROTOCOL_PATH.read_bytes())
        amendment = protocol["amendments"][-1]
        events = [json.loads(line) for line in
                  (PROTOCOL_PATH.parents[2] / amendment["raw_fixture"]).read_bytes().splitlines()]
        thread, warning, turn = events[0], events[1], events[-1]
        unknown = deepcopy(warning)
        unknown["item"]["message"] += " unregistered suffix"
        malformed = deepcopy(warning)
        malformed["item"]["accepted"] = True
        cases = {
            "unknown": [thread, unknown],
            "third_occurrence_of_two_allowed": [thread, warning, warning, warning],
            "known_warning_after_turn": [thread, turn, warning],
            "known_warning_before_thread": [warning],
            "malformed_known_warning": [thread, malformed],
            "tool_event": [thread, turn, {"type": "item.completed", "item": {
                "id": "tool", "type": "command_execution", "command": "forbidden"}}],
        }
        for label, stream in cases.items():
            with self.subTest(label=label), self.assertRaises(EventFailure):
                parser = CodexEvents(protocol["registered_startup_warnings"])
                for event in stream:
                    parser.line(wire(event))

    def test_warning_amendment_preserves_original_tasks_model_scoring_and_budgets(self):
        protocol = json.loads(PROTOCOL_PATH.read_bytes())
        protected = {key: value for key, value in protocol.items() if key not in {
            "registered_startup_warnings", "pre_generation_cli_observation", "amendments"}}
        expected = "846981cff1b157b3570fb66ed1451df10289160bac9df727cfd96c10c9a62a3d"
        self.assertEqual(sha256(wire(protected)).hexdigest(), expected)
        amendment = protocol["amendments"][-1]
        self.assertEqual(amendment["unchanged_protocol_fields_sha256"], expected)
        self.assertEqual(amendment["original_registration_commit"],
                         "03c8205271dc5e8f9c5cad806e46056bffe2bc02")
        self.assertFalse(amendment["failed_attempt_replaced"])
        self.assertFalse(amendment["complete_usage_observed"])
        self.assertEqual(amendment["complete_answers"], 0)

    def test_new_positive_and_negative_controls_run_actual_bounded_vm(self):
        for task in TASK_MODULE.TASKS:
            with self.subTest(task=task["id"]):
                report, source = task_controls(task)
                self.assertTrue(report["positive"]["all_correct"])
                self.assertGreater(report["negative"]["failed_count"], 0)
                self.assertEqual(report["positive"]["case_count"], 34)
                self.assertEqual(report["model_requests"], 0)
                self.assertEqual(len(source["functions"]), 26)
                if task["resource_witness"]:
                    events = report["positive"]["cases"][0]["operation_events"]
                    self.assertEqual([event["op"] for event in events], ["allocate", "store", "load", "drop"])

    def test_matching_scalar_answer_cannot_forge_resource_witness(self):
        task = TASK_MODULE.TASKS[1]
        source = TASK_MODULE.source(task["id"])
        target = source["functions"][0]
        target["effects"] = []
        target["blocks"][0]["ops"] = [TASK_MODULE.const("result", TASK_MODULE.oracle(task["id"], 0, 0))]
        verify_program(source)
        with self.assertRaisesRegex(ValueError, "real allocation"):
            execute_contract(source, task, [0, 0])

    def test_missing_provider_stays_unknown_and_never_executes_a_substitute(self):
        with patch("tools.qualify_hia_agent_maintenance.shutil.which", return_value=None), \
                patch("tools.qualify_hia_agent_maintenance.subprocess.run", side_effect=AssertionError("must not execute")):
            result = provider_preflight("/explicit/missing/codex")
        self.assertFalse(result["provider_executable_available"])
        self.assertEqual(result["model_requests"], 0)
        self.assertIsNone(result["executable_identity"])
        self.assertFalse(result["provider_connectivity_verified"])

    def test_executable_presence_does_not_claim_inference_or_run_it(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            command = root / "fake-provider"
            command.write_text("#!/bin/sh\nexit 99\n")
            command.chmod(0o700)
            with patch("tools.qualify_hia_agent_maintenance.subprocess.run", side_effect=AssertionError("must not execute")):
                result = provider_preflight(str(command))
            self.assertTrue(result["provider_executable_available"])
            self.assertFalse(result["executable_invoked"])
            self.assertFalse(result["provider_connectivity_verified"])
            self.assertEqual(result["model_requests"], 0)

    def test_protocol_is_fresh_maintenance_and_no_replacement_claim(self):
        protocol = json.loads(PROTOCOL_PATH.read_bytes())
        self.assertEqual(protocol["tasks"], [row["id"] for row in TASK_MODULE.TASKS])
        self.assertEqual(protocol["arms"], ["complete-json", "focused-json"])
        self.assertFalse(protocol["previous_negative_results_replaced"])
        self.assertTrue(protocol["registered_generation_runner_available"])
        self.assertFalse(protocol["model_efficiency_claim"])
        self.assertNotEqual(protocol["tasks"], ["quota_clip", "rotate_lane", "weighted_prefix", "buffer_lane"])

    def test_symbolic_registration_ref_rejects_before_git_or_provider(self):
        for ref in ("HEAD", "main", "A" * 40, "a" * 39):
            with self.subTest(ref=ref), patch("tools.qualify_hia_agent_maintenance.subprocess.run",
                    side_effect=AssertionError("must not execute")), self.assertRaises(ValueError):
                bindings(ref)

    def test_live_rpc_is_closed_and_never_repairs_model_json(self):
        for value in ('{"action":"exec"}', '{"action":"catalog","path":"tasks.py"}',
                      '{"action":"catalog","action":"final"}', '```json\n{"action":"catalog"}\n```',
                      '{"action":"final","patch_sha256":"bad"}', '{"action":"check"}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_action(value)

    def test_live_prompt_has_only_public_cases_and_no_author_patch(self):
        task = TASK_MODULE.TASKS[0]
        for arm in ("complete-json", "focused-json"):
            prompt = public_prompt(task, arm)
            self.assertEqual([row["arguments"] for row in prompt["public_cases"]], task["public"])
            self.assertNotIn("author_patch", wire(prompt).decode())
            self.assertNotIn("hidden", prompt)

    def test_live_patch_scope_blocks_noneditable_bodies_and_interface_migration(self):
        task = TASK_MODULE.TASKS[0]
        source = TASK_MODULE.source(task["id"])
        good = TASK_MODULE.author_patch(task["id"], verify_program(source).sha256)
        candidate, feedback = evaluate_patch(source, task, good)
        self.assertIsNotNone(candidate)
        self.assertTrue(feedback["accepted"])
        for request in (dict(good, schema="hepta.hia.patch.v2", interface_policy="migrate"),
                        {**good, "edits": [{"action": "replace_function", "function": "target",
                                           "definition": dict(source["functions"][0], effects=[])}]}):
            candidate, feedback = evaluate_patch(source, task, request)
            self.assertIsNone(candidate)
            self.assertFalse(feedback["accepted"])

    def test_registered_run_without_provider_records_blocked_zero_requests(self):
        with tempfile.TemporaryDirectory() as folder, \
                patch("tools.qualify_hia_agent_maintenance.bindings", return_value={}), \
                patch("tools.qualify_hia_agent_maintenance.shutil.which", return_value=None), \
                patch("tools.qualify_hia_agent_maintenance.run_owned", side_effect=AssertionError("must not launch")):
            code = run_registered(Path(folder) / "attempt", registration_commit="a" * 40)
            result = json.loads((Path(folder) / "attempt/RESULT.json").read_bytes())
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["model_requests"], 0)
        self.assertEqual(result["cells"], [])

    def test_scripted_transport_control_retains_usage_and_terminal_hidden_separation(self):
        # These are authored unit-test JSONL fixtures, explicitly ineligible as
        # model evidence. The real runner has no reference-answer fallback.
        task = TASK_MODULE.TASKS[0]
        source = TASK_MODULE.source(task["id"])
        good = TASK_MODULE.author_patch(task["id"], verify_program(source).sha256)
        from hashlib import sha256
        actions = [{"action": "check", "patch": good},
                   {"action": "final", "patch_sha256": sha256(wire(good)).hexdigest()}]
        usage = {"input_tokens": 20, "cached_input_tokens": 3, "cache_write_input_tokens": 0,
                 "output_tokens": 5, "reasoning_output_tokens": 2}
        seen = []

        def scripted(argv, cwd, output, **options):
            seen.append(options["input_bytes"])
            action = actions[len(seen) - 1]
            events = [{"type": "thread.started", "thread_id": "unit-control"}, {"type": "turn.started"},
                {"type": "item.completed", "item": {"id": "answer", "type": "agent_message", "text": wire(action).decode()}},
                {"type": "turn.completed", "usage": usage}]
            output.mkdir()
            raw = b"\n".join(wire(event) for event in events) + b"\n"
            (output / "stdout.raw").write_bytes(raw)
            (output / "stderr.raw").write_bytes(b"")
            for event in events:
                options["on_line"](wire(event))
            return {"status": "exited", "cleanup_confirmed": True, "leader_reaped": True}

        cfg = json.loads(PROTOCOL_PATH.read_bytes())
        with tempfile.TemporaryDirectory() as folder, \
                patch("tools.qualify_hia_agent_maintenance.run_owned", side_effect=scripted):
            row = run_cell(task, "focused-json", Path(folder) / "cell", cfg, {"path": "/scripted-unit-control"},
                lambda: None, experiment_deadline=time.monotonic() + 30,
                observation_kind="scripted-transport-unit-control")
            terminal = list((Path(folder) / "cell").glob("*/TERMINAL_HIDDEN.json"))
            self.assertEqual(len(terminal), 1)
        self.assertTrue(row["correct"])
        self.assertTrue(row["complete_usage"])
        self.assertEqual(row["token_units"], 54)
        self.assertEqual(row["observed_usage_totals"]["cached_input_tokens"], 6)
        self.assertFalse(row["model_result_eligible"])
        self.assertEqual(len(seen), 2)
        self.assertNotIn(b"TERMINAL_HIDDEN", seen[1])
        self.assertNotIn(wire(TASK_MODULE.cases(task, hidden=True)), seen[1])
        # A post-hidden evidence failure must invalidate a previously correct
        # result. It may not survive as an eligible success in the aggregate.
        from tools.qualify_hia_agent_maintenance import save as actual_save
        def fail_final_feedback(path, value):
            if Path(path).name == "PUBLIC_FEEDBACK.json" and Path(path).parent.name == "request-1":
                raise OSError("authored final evidence failure injection")
            actual_save(path, value)
        seen.clear()
        with tempfile.TemporaryDirectory() as folder, \
                patch("tools.qualify_hia_agent_maintenance.run_owned", side_effect=scripted), \
                patch("tools.qualify_hia_agent_maintenance.save", side_effect=fail_final_feedback):
            failed = run_cell(task, "focused-json", Path(folder) / "cell", cfg, {"path": "/scripted-unit-control"},
                lambda: None, experiment_deadline=time.monotonic() + 30,
                observation_kind="scripted-transport-unit-control")
        self.assertTrue(failed["hidden_evaluated"])
        self.assertEqual(failed["status"], "terminal_provider_or_protocol_failure")
        self.assertFalse(failed["correct"])

    def test_unknown_usage_or_scripted_controls_cannot_win_model_comparison(self):
        cfg = json.loads(PROTOCOL_PATH.read_bytes())
        rows = [{"task": task, "arm": arm, "status": "correct", "wall_ns": 10, "known_token_units": 5,
                 "complete_usage": True, "correct": True, "hidden_evaluated": True,
                 "actual_wall_budget_passed": True, "model_result_eligible": True,
                 "public_failed_checks": 0, "provider_requests_attempted": 1}
                for task in cfg["tasks"] for arm in cfg["arms"]]
        rows[0]["complete_usage"] = False
        report = summarize_cells(rows, cfg, 100)
        self.assertIsNone(report["arm_totals"]["complete-json"]["token_units"])
        self.assertFalse(report["all_registered_model_cells_eligible"])
        self.assertFalse(report["descriptive_focused_context_advantage"])
        rows[0]["complete_usage"] = True
        rows[0]["model_result_eligible"] = False
        self.assertFalse(summarize_cells(rows, cfg, 100)["all_registered_model_cells_eligible"])
        rows[0]["model_result_eligible"] = True
        self.assertTrue(summarize_cells(rows, cfg, 100)["all_registered_model_cells_eligible"])
        rows[0]["status"] = "terminal_provider_or_protocol_failure"
        self.assertFalse(summarize_cells(rows, cfg, 100)["all_registered_model_cells_eligible"])
        self.assertEqual(summarize_cells(rows, cfg, 100)["arm_totals"]["complete-json"]["successes"], 1)
        rows[0]["status"] = "correct"
        expired = summarize_cells(rows, cfg, cfg["max_experiment_wall_seconds"] * 1_000_000_000 + 1)
        self.assertFalse(expired["actual_experiment_wall_budget_passed"])
        self.assertFalse(expired["all_registered_model_cells_eligible"])

    def test_explicit_transport_limits_use_actual_process_without_old_protocol(self):
        from tools.hia_agent_codex_transport import run_owned
        caps = {"stdout_limit_bytes": 4096, "stderr_limit_bytes": 4096, "max_jsonl_line_bytes": 1024}
        with tempfile.TemporaryDirectory() as folder, \
                patch("tools.hia_agent_codex_transport.protocol", side_effect=AssertionError("old protocol read")):
            root = Path(folder)
            observed = run_owned([sys.executable, "-c", "print('explicit-transport-control')"], root,
                root / "transport", wall_seconds=3, transport_config=caps)
            self.assertEqual(observed["status"], "exited")
            self.assertTrue(observed["cleanup_confirmed"])
            self.assertEqual((root / "transport/stdout.raw").read_bytes(), b"explicit-transport-control\n")


if __name__ == "__main__":
    unittest.main()
