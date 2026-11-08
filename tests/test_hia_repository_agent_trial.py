"""Authored local transport controls. No model, service or account is contacted."""
from __future__ import annotations

import hashlib
import errno
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.hia_agent_codex_transport import EventFailure, identity
from tools.hia_agent_fresh_session import FreshEvents
from tools.hia_repository_agent_trial import (
    RepositoryEvents, _read_cancel_request, request_trial_cancel, run_trial, settle_stream, snapshot_repository,
)


def event(kind, **fields):
    return {"type": kind, **fields}


def sequence(*middle, usage=None, terminal="turn.completed"):
    return [event("thread.started", thread_id="authored-fixture"), event("turn.started"),
            *middle, event(terminal, usage=usage)]


class SettlementTests(unittest.TestCase):
    def settle(self, events, complete=True):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stdout.raw"
            path.write_bytes(b"\n".join(json.dumps(e).encode() for e in events) + b"\n")
            return settle_stream(path, streams_complete=complete)

    def test_three_counter_usage_does_not_invent_reasoning_or_fee(self):
        result = self.settle(sequence(usage={"input_tokens": 120, "cached_input_tokens": 30, "output_tokens": 17}))
        self.assertTrue(result["reported_usage_settled"])
        self.assertEqual(result["input_plus_output_tokens"], 137)
        self.assertIsNone(result["auxiliary_usage"]["reasoning_output_tokens"])
        self.assertIsNone(result["billed_cost"])
        self.assertFalse(result["full_monetary_cost_complete"])

    def test_reasoning_and_cache_are_not_charged_twice(self):
        usage = {"input_tokens": 100, "cached_input_tokens": 40, "cache_write_input_tokens": 10,
                 "output_tokens": 30, "reasoning_output_tokens": 20}
        result = self.settle(sequence(usage=usage))
        self.assertEqual(result["reported_usage"], usage)
        self.assertEqual(result["input_plus_output_tokens"], 130)
        self.assertFalse(result["auxiliary_counters_added_again"])

    def test_failed_turn_retains_original_usage(self):
        result = self.settle(sequence(terminal="turn.failed", usage={"input_tokens": 5, "output_tokens": 9}))
        self.assertTrue(result["reported_usage_settled"])
        self.assertEqual(result["input_plus_output_tokens"], 14)
        self.assertEqual(result["terminal_observations"][0]["event_type"], "turn.failed")

    def test_unknown_usage_is_not_zero(self):
        for usage in (None, {"input_tokens": 1}, {"input_tokens": True, "output_tokens": 1},
                      {"input_tokens": -1, "output_tokens": 2},
                      {"input_tokens": 5, "output_tokens": 3, "cached_input_tokens": 6}):
            with self.subTest(usage=usage):
                result = self.settle(sequence(usage=usage))
                self.assertFalse(result["reported_usage_settled"])
                self.assertIsNone(result["input_plus_output_tokens"])

    def test_truncated_stream_and_duplicate_terminal_cannot_settle(self):
        events = sequence(usage={"input_tokens": 1, "output_tokens": 2})
        self.assertFalse(self.settle(events, complete=False)["reported_usage_settled"])
        events.append(event("turn.completed", usage={"input_tokens": 9, "output_tokens": 9}))
        result = self.settle(events)
        self.assertFalse(result["reported_usage_settled"])
        self.assertEqual(len(result["terminal_observations"]), 2)
        self.assertTrue(result["parse_errors"])

    def test_malformed_line_prevents_settlement_but_keeps_original_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stdout.raw"
            raw = b'{"type":"turn.failed","type":"turn.completed"}\n'
            raw += json.dumps(event("turn.completed", usage={"input_tokens": 9, "output_tokens": 2})).encode() + b"\n"
            path.write_bytes(raw)
            result = settle_stream(path, streams_complete=True)
            self.assertFalse(result["reported_usage_settled"])
            self.assertEqual(result["invalid_json_lines"], 1)
            self.assertEqual(result["terminal_observations"][0]["usage"]["input_tokens"], 9)

    def test_command_attempts_are_unique_and_failures_survive(self):
        item = {"id": "c1", "type": "command_execution", "command": "public-test", "status": "in_progress"}
        result = self.settle(sequence(event("item.started", item=item),
            event("item.updated", item=item),
            event("item.completed", item={**item, "status": "failed", "exit_code": 1}),
            event("item.completed", item={"id": "f1", "type": "file_change", "status": "completed", "changes": []}),
            usage={"input_tokens": 1, "output_tokens": 2}))
        self.assertEqual(result["unique_item_counts"]["command_execution"], 1)
        self.assertEqual(len(result["failed_or_cancelled_items"]), 1)
        self.assertEqual(result["unique_item_counts"]["file_change"], 1)

    def test_later_success_or_reused_id_cannot_erase_original_failure(self):
        first = {"id": "c1", "type": "command_execution", "status": "failed", "exit_code": 4}
        result = self.settle(sequence(event("item.completed", item=first),
            event("item.updated", item={**first, "status": "cancelled"}),
            event("item.completed", item={**first, "status": "completed", "exit_code": 0}),
            event("item.completed", item={"id": "c1", "type": "file_change", "status": "completed"}),
            usage={"input_tokens": 1, "output_tokens": 2}))
        self.assertEqual(result["unique_item_counts"]["command_execution"], 1)
        self.assertEqual(result["unique_item_counts"]["file_change"], 1)
        self.assertEqual([row["line"] for row in result["failed_or_cancelled_items"]], [3, 4])
        self.assertEqual([row["status"] for row in result["failed_or_cancelled_items"]], ["failed", "cancelled"])
        self.assertEqual(result["input_plus_output_tokens"], 3)

    def test_transport_receipt_binds_the_bytes_actually_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stdout.raw"
            raw = b"\n".join(json.dumps(e).encode() for e in sequence(
                usage={"input_tokens": 1, "output_tokens": 2})) + b"\n"
            path.write_bytes(raw)
            process = {"streams_complete": True, "files": {"stdout.raw": identity(path)},
                       "bytes_observed": {"stdout": len(raw)}}
            result = settle_stream(path, streams_complete=True, transport_receipt=process)
            self.assertTrue(result["reported_usage_settled"])
            path.write_bytes(raw.replace(b'"input_tokens": 1', b'"input_tokens": 9'))
            altered = settle_stream(path, streams_complete=True, transport_receipt=process)
            self.assertEqual(altered["invalid_json_lines"], 0)
            self.assertTrue(altered["capture"]["untruncated"])
            self.assertFalse(altered["capture"]["transport_stdout_matches"])
            self.assertFalse(altered["reported_usage_settled"])
            self.assertEqual(altered["terminal_observations"][0]["usage"]["input_tokens"], 9)
            self.assertEqual(altered["raw_stream"]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_old_mcp_only_profile_is_not_relaxed(self):
        old, new = FreshEvents("hia_trial"), RepositoryEvents()
        for e in (event("thread.started", thread_id="x"), event("turn.started")):
            old.line(json.dumps(e).encode())
            new.line(json.dumps(e).encode())
        raw = json.dumps(event("item.completed", item={"id": "1", "type": "command_execution"})).encode()
        new.line(raw)
        with self.assertRaises(EventFailure):
            old.line(raw)

    def test_foreign_mcp_requires_separate_registration(self):
        p = RepositoryEvents()
        for e in (event("thread.started", thread_id="x"), event("turn.started")):
            p.line(json.dumps(e).encode())
        with self.assertRaises(EventFailure):
            p.line(json.dumps(event("item.started", item={"id": "1", "type": "mcp_tool_call", "server": "unregistered"})).encode())


class OwnedProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repository"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / "input.txt").write_text("before\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "input.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Authored fixture", "-c", "user.email=fixture@invalid.test",
                        "commit", "-q", "-m", "authored local fixture"], check=True)
        self.commit = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"]).decode().strip()
        self.tree = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD^{tree}"]).decode().strip()
        self.prompt = self.root / "public.txt"
        self.prompt.write_text("Authored local transport control; no provider or task claim.\n")

    def tearDown(self):
        self.temp.cleanup()

    def registration(self, body, wall=5, tokens=50):
        child = self.root / "authored_child.py"
        child.write_text(body)
        path = self.root / "registration.json"
        path.write_text(json.dumps({"schema": "hepta.hia.repository-agent-launch.v1",
            "argv": [str(Path(sys.executable).resolve()), "-u", str(child)],
            "repository": str(self.repo), "source_commit": self.commit, "source_tree": self.tree,
            "public_prompt": str(self.prompt), "public_prompt_sha256": hashlib.sha256(self.prompt.read_bytes()).hexdigest(),
            "executable_sha256": identity(sys.executable)["sha256"], "requested_model": "authored-fixture-no-model",
            "requested_profile": {"kind": "local-control"}, "wall_limit_seconds": wall,
            "token_review_limit": tokens, "allowed_mcp_servers": [],
            "session_freshness_attestation": {"kind": "none", "reason": "authored fixture"}}))
        return path

    def test_real_subprocess_keeps_changes_usage_and_nonzero_exit(self):
        events = sequence(event("item.completed", item={"id": "c1", "type": "command_execution", "status": "failed", "exit_code": 4}),
                          usage={"input_tokens": 10, "cached_input_tokens": 4, "output_tokens": 5})
        body = ("from pathlib import Path\nimport json,sys\nsys.stdin.buffer.read()\n"
                "Path('input.txt').write_text('after\\n')\nPath('new.txt').write_text('new file\\n')\n"
                + "\n".join("print(" + repr(json.dumps(e)) + ", flush=True)" for e in events)
                + "\nsys.exit(4)\n")
        result = run_trial(self.registration(body), self.root / "result")
        self.assertEqual(result["process"]["returncode"], 4)
        self.assertTrue(result["process"]["cleanup_confirmed"])
        self.assertEqual(result["metering"]["input_plus_output_tokens"], 15)
        self.assertIn(b"+after", (self.root / "result/after/tracked.patch").read_bytes())
        self.assertEqual((self.root / "result/after/new-files/new.txt").read_text(), "new file\n")
        self.assertGreaterEqual(result["whole_trial_wall_ns"], result["process"]["wall_ns"])
        self.assertEqual(result["task_acceptance"], "HOLD")
        self.assertFalse(result["full_cost_complete"])
        with self.assertRaises(FileExistsError):
            run_trial(self.root / "registration.json", self.root / "result")

    def test_timeout_retains_raw_prefix_and_unknown_usage(self):
        body = ("import time\nprint('{\"type\":\"thread.started\",\"thread_id\":\"local\"}',flush=True)\n"
                "print('{\"type\":\"turn.started\"}',flush=True)\ntime.sleep(10)\n")
        result = run_trial(self.registration(body, wall=1), self.root / "timeout")
        self.assertEqual(result["process"]["status"], "wall_timeout")
        self.assertTrue(result["process"]["cleanup_confirmed"])
        self.assertFalse(result["metering"]["reported_usage_settled"])
        self.assertIsNone(result["within_token_review_limit"])
        self.assertFalse(result["hard_mid_turn_token_limit"])

    def test_pipe_eof_after_stdout_truncation_cannot_settle_a_terminal_prefix(self):
        prefix = b"\n".join(json.dumps(e).encode() for e in sequence(
            usage={"input_tokens": 1, "output_tokens": 2})) + b"\n"
        omitted = json.dumps(event("turn.completed", usage={"input_tokens": 100, "output_tokens": 200})).encode() + b"\n"
        body = "import os\nos.write(1, " + repr(prefix + omitted) + ")\n"
        with patch.dict("tools.hia_repository_agent_trial.LIMITS", stdout_limit_bytes=len(prefix)):
            result = run_trial(self.registration(body), self.root / "truncated")
        self.assertEqual(result["process"]["status"], "output_limit")
        self.assertTrue(result["process"]["streams_complete"])
        self.assertGreater(result["process"]["bytes_observed"]["stdout"], len(prefix))
        self.assertTrue(result["metering"]["capture"]["transport_stdout_matches"])
        self.assertFalse(result["metering"]["capture"]["untruncated"])
        self.assertFalse(result["metering"]["reported_usage_settled"])
        self.assertEqual(result["metering"]["terminal_observations"][0]["usage"],
                         {"input_tokens": 1, "output_tokens": 2})
        self.assertIsNone(result["metering"]["input_plus_output_tokens"])
        self.assertIsNone(result["within_token_review_limit"])

    def test_non_sha_baseline_rejected_before_git_or_launch(self):
        registration = self.registration("raise RuntimeError('must not launch')\n")
        reg = json.loads(registration.read_text()); reg["source_commit"] = "--no-index"
        registration.write_text(json.dumps(reg))
        with self.assertRaisesRegex(ValueError, "FROZEN_LAUNCH"):
            run_trial(registration, self.root / "invalid-pin")
        self.assertFalse((self.root / "invalid-pin").exists())

    def test_baseline_change_refuses_launch(self):
        registration = self.registration("raise RuntimeError('must not launch')\n")
        (self.repo / "input.txt").write_text("unexpected change\n")
        with self.assertRaisesRegex(ValueError, "BASELINE_CHANGED"):
            run_trial(registration, self.root / "rejected")
        record = json.loads((self.root / "rejected/TRIAL.json").read_text())
        self.assertEqual(record["cli_sessions_started"], 0)
        self.assertFalse((self.root / "rejected/provider").exists())

    def test_bound_cancel_stops_original_process_without_usage_invention(self):
        target = self.root / "cancelled"
        requester = self.root / "requester.py"
        module_root = str(Path(__file__).resolve().parents[1])
        requester.write_text(
            "import json,sys,time\nfrom pathlib import Path\n"
            "sys.path.insert(0," + repr(module_root) + ")\n"
            "from tools.hia_repository_agent_trial import request_trial_cancel\n"
            "root=Path(" + repr(str(target)) + ")\n"
            "deadline=time.monotonic()+5\n"
            "while time.monotonic()<deadline:\n"
            " p=root/'provider/PROCESS.json'\n"
            " if p.exists() and json.loads(p.read_text()).get('status')=='running':\n"
            "  result=request_trial_cancel(root,'authored local cancellation control')\n"
            "  assert result['status']=='requested'\n"
            "  break\n"
            " time.sleep(0.01)\n"
            "else: raise RuntimeError('original process did not become observable')\n")
        helper = subprocess.Popen([sys.executable, '-B', str(requester)])
        try:
            result = run_trial(self.registration("import time\ntime.sleep(10)\n", wall=5), target)
            self.assertEqual(helper.wait(timeout=6), 0)
        finally:
            if helper.poll() is None:
                helper.terminate()
                helper.wait(timeout=3)
        self.assertEqual(result['process']['status'], 'coordinator_stop')
        self.assertTrue(result['process']['cleanup_confirmed'])
        self.assertTrue(result['cancellation_observation']['valid'])
        self.assertEqual(result['cancellation_observation']['request']['registration_sha256'],
                         result['registration']['sha256'])
        self.assertIsNone(result['metering']['reported_usage'])
        self.assertFalse(result['full_cost_complete'])
        before = (target / 'CANCEL_REQUEST.json').read_bytes()
        self.assertEqual(request_trial_cancel(target, 'another reason')['status'], 'already_requested')
        self.assertEqual((target / 'CANCEL_REQUEST.json').read_bytes(), before)

    def test_foreign_cancel_record_does_not_stop_original_process(self):
        target = self.root / 'foreign-cancel'
        foreign = {'schema': 'hepta.hia.repository-agent-cancel.v1',
                   'registration_sha256': '0' * 64, 'reason': 'another task', 'requested_unix_ns': 1}
        events = sequence(usage={'input_tokens': 7, 'output_tokens': 3})
        body = ("from pathlib import Path\nimport time\n"
                "Path(" + repr(str(target / 'CANCEL_REQUEST.json')) + ").write_text(" + repr(json.dumps(foreign)) + ")\n"
                "time.sleep(0.2)\n" +
                "\n".join("print(" + repr(json.dumps(e)) + ",flush=True)" for e in events))
        result = run_trial(self.registration(body), target)
        self.assertEqual(result['process']['returncode'], 0)
        self.assertEqual(result['process']['status'], 'exited')
        self.assertFalse(result['cancellation_observation']['valid'])
        self.assertEqual(result['metering']['input_plus_output_tokens'], 10)
        with self.assertRaisesRegex(ValueError, 'CANCEL_EXISTING_REQUEST'):
            request_trial_cancel(target, 'must not replace foreign record')

    def test_cancel_observed_before_launch_starts_no_process(self):
        target = self.root / 'prelaunch-cancel'
        registration = self.registration("raise RuntimeError('must not start')\n")
        def capture_then_cancel(*args, **kwargs):
            before = snapshot_repository(*args, **kwargs)
            self.assertEqual(request_trial_cancel(target, 'stop during preflight')['status'], 'requested')
            return before
        with patch('tools.hia_repository_agent_trial.snapshot_repository', side_effect=capture_then_cancel), \
             patch('tools.hia_repository_agent_trial.run_owned') as launch:
            result = run_trial(registration, target)
        self.assertEqual(result['status'], 'cancelled_before_launch')
        self.assertEqual(result['cli_sessions_started'], 0)
        launch.assert_not_called()
        self.assertFalse((target / 'provider').exists())

    def test_terminal_trial_cancel_is_read_only(self):
        events = sequence(usage={'input_tokens': 1, 'output_tokens': 1})
        body = "\n".join("print(" + repr(json.dumps(e)) + ",flush=True)" for e in events)
        target = self.root / 'terminal-cancel'
        run_trial(self.registration(body), target)
        result = request_trial_cancel(target, 'late request')
        self.assertEqual(result['status'], 'already_terminal')
        self.assertFalse((target / 'CANCEL_REQUEST.json').exists())

    def test_unreadable_request_is_not_a_cancellation(self):
        with patch('tools.hia_repository_agent_trial.os.open',
                   side_effect=PermissionError(errno.EACCES, 'authored read failure')):
            result = _read_cancel_request(self.root, '0' * 64)
        self.assertFalse(result['valid'])
        self.assertEqual(result['reason'], 'request_read_error')
        self.assertEqual(result['errno'], errno.EACCES)

    def test_request_publication_failure_leaves_no_partial_final_record(self):
        target = self.root / 'publication-failure'
        events = sequence(usage={'input_tokens': 1, 'output_tokens': 1})
        body = "\n".join("print(" + repr(json.dumps(e)) + ",flush=True)" for e in events)
        run_trial(self.registration(body), target)
        record_path = target / 'TRIAL.json'
        record = json.loads(record_path.read_text())
        record['status'] = 'preflight'  # Authored publication control; no process is running.
        record_path.write_text(json.dumps(record))
        with patch('tools.hia_repository_agent_trial.os.link',
                   side_effect=OSError(errno.EIO, 'authored publication interruption')):
            with self.assertRaises(OSError):
                request_trial_cancel(target, 'publication control')
        self.assertFalse((target / 'CANCEL_REQUEST.json').exists())
        self.assertEqual(list(target.glob('.hia-cancel-*')), [])


if __name__ == "__main__":
    unittest.main()
