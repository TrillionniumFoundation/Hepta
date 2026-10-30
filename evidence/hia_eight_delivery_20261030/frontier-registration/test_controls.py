"""Non-generation controls for the prospective adapter and owned process cleanup."""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pilot


USAGE = {"input_tokens": 7, "cached_input_tokens": 3, "cache_write_input_tokens": 0,
         "output_tokens": 2, "reasoning_output_tokens": 0}


def start(parser):
    parser.line(b'{"type":"thread.started","thread_id":"dummy"}')
    parser.line(b'{"type":"turn.started"}')


class EventControls(unittest.TestCase):
    def test_actual_retained_bootstrap_parses_without_new_generation(self):
        parser = pilot.CodexEvents(pilot.protocol()["registered_startup_warnings"])
        for line in (pilot.HERE / "bootstrap/codex-runtime-probe.jsonl").read_bytes().splitlines():
            parser.line(line)
        response = parser.complete()
        self.assertEqual(response["text"], "READY")
        self.assertEqual(response["usage"]["input_tokens"], 14583)
        self.assertEqual(response["usage"]["output_tokens"], 5)
        self.assertEqual(response["usage"]["reasoning_output_tokens"], 0)

    def test_tool_and_unknown_events_refuse_even_with_plausible_answer(self):
        for item in ("command_execution", "mcp_tool_call", "file_change", "web_search", "future_item"):
            parser = pilot.CodexEvents([])
            start(parser)
            with self.subTest(item=item), self.assertRaises(pilot.EventFailure):
                parser.line(pilot.canonical({"type": "item.started", "item": {"type": item}}))
        parser = pilot.CodexEvents([])
        with self.assertRaises(pilot.EventFailure):
            parser.line(b'{"type":"future_event"}')

    def test_startup_warning_exact_phase_and_multiplicity(self):
        warnings = pilot.protocol()["registered_startup_warnings"]
        warning = warnings[0]
        parser = pilot.CodexEvents(warnings)
        parser.line(b'{"type":"thread.started","thread_id":"dummy"}')
        event = pilot.canonical({"type": "item.completed", "item": {"id": "warning", "type": "error", "message": warning}})
        for _ in range(warnings.count(warning)):
            parser.line(event)
        with self.assertRaises(pilot.EventFailure):
            parser.line(event)
        parser = pilot.CodexEvents(warnings)
        start(parser)
        with self.assertRaises(pilot.EventFailure):
            parser.line(event)

    def test_usage_unknown_bool_negative_and_cache_inconsistency_refuse(self):
        for value in (None, {}, {**USAGE, "output_tokens": True},
                      {**USAGE, "reasoning_output_tokens": -1},
                      {**USAGE, "cached_input_tokens": 8}, {**USAGE, "future_cost_tokens": 99}):
            parser = pilot.CodexEvents([])
            start(parser)
            with self.subTest(value=value), self.assertRaises(pilot.EventFailure):
                parser.line(pilot.canonical({"type": "turn.completed", "usage": value}))
        parser = pilot.CodexEvents([])
        start(parser)
        parser.line(b'{"type":"item.completed","item":{"id":"dummy-message","type":"agent_message","text":"{}"}}')
        with self.assertRaises(pilot.EventFailure):
            parser.complete()

    def test_duplicate_event_and_usage_fields_are_not_last_value_wins(self):
        for raw in (b'{"type":"turn.started","type":"future_event"}',
                    b'{"type":"turn.completed","usage":{"output_tokens":1,"output_tokens":0}}'):
            with self.assertRaises(pilot.EventFailure):
                pilot.strict_json(raw)

    def test_multiple_answers_refuse_and_reasoning_budget_is_conservative(self):
        parser = pilot.CodexEvents([])
        start(parser)
        for _ in range(2):
            parser.line(b'{"type":"item.completed","item":{"id":"dummy-message","type":"agent_message","text":"{}"}}')
        parser.line(pilot.canonical({"type": "turn.completed", "usage": USAGE}))
        with self.assertRaises(pilot.EventFailure):
            parser.complete()
        self.assertEqual(pilot.usage_charge({**USAGE, "reasoning_output_tokens": 4}), 13)


class OwnedProcessControls(unittest.TestCase):
    def test_expired_budget_never_launches_process(self):
        with tempfile.TemporaryDirectory(prefix="frontier-expired-", dir=pilot.HERE) as temporary:
            root = Path(temporary)
            with patch.object(pilot.subprocess, "Popen") as launch:
                result = pilot.run_owned(["must-not-start"], root, root / "transport", wall_seconds=0)
            launch.assert_not_called()
            self.assertEqual(result["status"], "wall_timeout_before_launch")
            self.assertNotIn("pid", result)

    def test_lost_child_ownership_never_signals_and_uncertain_reap_never_retries(self):
        for lose_ownership in (True, False):
            with self.subTest(lose_ownership=lose_ownership), tempfile.TemporaryDirectory(
                    prefix="frontier-reap-", dir=pilot.HERE) as temporary:
                root = Path(temporary)
                pipes = []
                for _ in range(2):
                    read_fd, write_fd = os.pipe()
                    os.close(write_fd)
                    pipes.append(os.fdopen(read_fd, "rb"))
                fake = SimpleNamespace(pid=900001, stdout=pipes[0], stderr=pipes[1])
                waits = []
                def fake_wait(timeout):
                    waits.append(timeout)
                    raise ChildProcessError("already consumed; never signal numeric pid again")
                fake.wait = fake_wait
                def observe(kind, pid, flags):
                    if pid == os.getpid() or lose_ownership:
                        raise ChildProcessError("no owned child")
                    return SimpleNamespace(si_pid=fake.pid)
                with patch.object(pilot.subprocess, "Popen", return_value=fake), \
                     patch.object(pilot.os, "waitid", side_effect=observe), \
                     patch.object(pilot.os, "killpg") as kill:
                    result = pilot.run_owned(["dummy"], root, root / "transport", wall_seconds=1)
                self.assertEqual(kill.call_count, 0 if lose_ownership else 1)
                self.assertEqual(len(waits), 0 if lose_ownership else 1)
                self.assertFalse(result["leader_reaped"])
                self.assertFalse(result["cleanup_confirmed"])
                self.assertNotEqual(result["status"], "exited")

    def test_timeout_kills_owned_group_before_leader_reap_and_retains_output(self):
        with tempfile.TemporaryDirectory(prefix="frontier-owned-", dir=pilot.HERE) as temporary:
            root = Path(temporary)
            code = ("import subprocess,sys,time;"
                    "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);"
                    "print(p.pid,flush=True);time.sleep(30)")
            result = pilot.run_owned([sys.executable, "-c", code], root, root / "transport", wall_seconds=0.25)
            self.assertEqual(result["status"], "wall_timeout")
            self.assertTrue(result["group_kill_before_reap"])
            self.assertTrue(result["leader_reaped"])
            self.assertTrue(result["streams_complete"])
            child = int((root / "transport/stdout.raw").read_text())
            status_path = Path("/proc") / str(child) / "status"
            if status_path.exists():
                # An adopted, already-dead zombie is not a live escaped worker.
                self.assertIn("State:\tZ", status_path.read_text())
            self.assertLess(result["wall_ns"]/1e9, 3)

    def test_live_forbidden_event_stops_process_and_usage_is_still_retained(self):
        with tempfile.TemporaryDirectory(prefix="frontier-event-", dir=pilot.HERE) as temporary:
            root = Path(temporary)
            stream = b"\n".join((
                b'{"type":"thread.started","thread_id":"dummy"}',
                b'{"type":"turn.started"}',
                b'{"type":"item.started","item":{"type":"command_execution"}}',
                pilot.canonical({"type": "turn.completed", "usage": USAGE}))) + b"\n"
            code = "import os,time;os.write(1," + repr(stream) + ");time.sleep(30)"
            parser = pilot.CodexEvents([])
            result = pilot.run_owned([sys.executable, "-c", code], root, root / "transport",
                                     wall_seconds=5, on_line=parser.line)
            self.assertEqual(result["status"], "protocol_violation")
            self.assertTrue(result["group_kill_before_reap"])
            self.assertTrue(result["leader_reaped"])
            self.assertEqual(pilot.recover_reported_usage(root / "transport/stdout.raw"), USAGE)

    def test_output_limit_preserves_bounded_raw_prefix_and_rejects(self):
        with tempfile.TemporaryDirectory(prefix="frontier-output-", dir=pilot.HERE) as temporary:
            root = Path(temporary)
            cap = pilot.protocol()["transport"]["stderr_limit_bytes"]
            code = "import os,time;os.write(2,b'x'*" + str(cap+65536) + ");time.sleep(30)"
            result = pilot.run_owned([sys.executable, "-c", code], root, root / "transport", wall_seconds=5)
            self.assertEqual(result["status"], "output_limit")
            self.assertEqual((root / "transport/stderr.raw").stat().st_size, cap)
            self.assertGreater(result["bytes_observed"]["stderr"], cap)
            self.assertTrue(result["leader_reaped"])


class GateControls(unittest.TestCase):
    def fake_identity(self, path):
        return {"path": str(path), "sha256": "1"*64, "bytes": 1}

    def test_failed_first_qualification_stops_remaining_qualification_and_main(self):
        with tempfile.TemporaryDirectory(prefix="frontier-gate-", dir=pilot.HERE) as temporary:
            output = Path(temporary)/"run"
            calls = []
            def cell(stage, task, arm, root, deadline, cfg, frozen, rows):
                calls.append(stage)
                row = {"status": "public_repairs_exhausted", "correct": False,
                       "hidden_evaluated": False, "attempts": []}
                rows.append(row)
                return row
            with patch.object(pilot, "checked_review", return_value={}), \
                 patch.object(pilot, "verify_freeze", return_value={}), \
                 patch.object(pilot, "identity", side_effect=self.fake_identity), \
                 patch.object(pilot, "run_cell", side_effect=cell):
                pilot.experiment(output, "review", "controls")
            result = json.loads((output/"RESULT.json").read_text())
            self.assertEqual(calls, ["calibration"])
            self.assertFalse(result["qualification_eligible"])
            self.assertEqual(result["main_cells_started"], 0)

    def test_main_infrastructure_failure_stops_next_main_cell(self):
        with tempfile.TemporaryDirectory(prefix="frontier-main-stop-", dir=pilot.HERE) as temporary:
            output = Path(temporary)/"run"
            calls = []
            def cell(stage, task, arm, root, deadline, cfg, frozen, rows):
                calls.append(stage)
                row = {"status": "correct" if stage=="calibration" else "infrastructure_failure",
                       "correct": stage=="calibration", "hidden_evaluated": True,
                       "attempts": [{"usage": USAGE, "observed_usage": USAGE,
                                     "unknown_usage": False, "process": {"status": "exited"}}]}
                rows.append(row)
                return row
            with patch.object(pilot, "checked_review", return_value={}), \
                 patch.object(pilot, "verify_freeze", return_value={}), \
                 patch.object(pilot, "identity", side_effect=self.fake_identity), \
                 patch.object(pilot, "run_cell", side_effect=cell):
                pilot.experiment(output, "review", "controls")
            result = json.loads((output/"RESULT.json").read_text())
            self.assertEqual(calls, ["calibration"]*3+["main"])
            self.assertEqual(result["main_cells_started"], 1)
            self.assertEqual(result["status"], "main_protocol_or_runtime_stop")

    def test_identity_failure_before_qualification_ticket_never_sets_eligible(self):
        with tempfile.TemporaryDirectory(prefix="frontier-ticket-", dir=pilot.HERE) as temporary:
            output=Path(temporary)/"run"
            def cell(stage, task, arm, root, deadline, cfg, frozen, rows):
                row={"correct":True,"hidden_evaluated":True,"status":"correct",
                     "attempts":[{"usage":USAGE,"observed_usage":USAGE,"unknown_usage":False,
                                  "process":{"status":"exited"}}]}
                rows.append(row);return row
            with patch.object(pilot,"checked_review",return_value={}), \
                 patch.object(pilot,"verify_freeze",side_effect=ValueError("frozen source changed")), \
                 patch.object(pilot,"identity",side_effect=self.fake_identity), \
                 patch.object(pilot,"run_cell",side_effect=cell):
                pilot.experiment(output,"review","controls")
            result=json.loads((output/"RESULT.json").read_text())
            self.assertFalse(result["qualification_eligible"])
            self.assertEqual(result["main_cells_started"],0)
            self.assertFalse((output/"QUALIFICATION.json").exists())

    def test_hidden_execution_is_terminal_and_cannot_generate_public_repair(self):
        with tempfile.TemporaryDirectory(prefix="frontier-hidden-", dir=pilot.HERE) as temporary:
            root = Path(temporary)
            task,arm = pilot.support.cells("calibration")[0]
            cfg = pilot.protocol()
            cfg["model_cwd_root"] = str(root/"separate-cwds")
            frozen = {"prompt_bindings": pilot.support.prompt_bindings()}
            def transport(argv, cwd, output, *, input_bytes, wall_seconds, on_line):
                output.mkdir(parents=True)
                events = [{"type":"thread.started","thread_id":"dummy"}, {"type":"turn.started"},
                          {"type":"item.completed","item":{"id":"answer","type":"agent_message","text":"{}"}},
                          {"type":"turn.completed","usage":USAGE}]
                data=b"\n".join(pilot.canonical(e) for e in events)+b"\n"
                (output/"stdout.raw").write_bytes(data)
                for e in events: on_line(pilot.canonical(e))
                return {"status":"exited","pid":900001}
            observed={"status":"hidden_failed","correct":False,"hidden_evaluated":True,
                      "public":{"feedback":{"diagnostic":"public only"}}}
            rows=[]
            with patch.object(pilot, "verify_freeze", return_value=frozen), \
                 patch.object(pilot, "run_owned", side_effect=transport) as generated, \
                 patch.object(pilot, "evaluate_isolated", return_value=observed):
                row=pilot.run_cell("calibration",task,arm,root,time.monotonic()+60,cfg,frozen,rows)
            self.assertEqual(generated.call_count,1)
            self.assertTrue(row["hidden_evaluated"])
            self.assertFalse(list(root.rglob("REPAIR.json")))

    def test_hidden_artifact_drift_remains_terminal_infrastructure_failure(self):
        with tempfile.TemporaryDirectory(prefix="frontier-drift-", dir=pilot.HERE) as temporary:
            root=Path(temporary);query={"source_revision":"fixed"}
            (root/"query.json").write_text(json.dumps(query));(root/"answer.txt").write_text("{}")
            args=SimpleNamespace(stage="calibration",task="dummy",arm="calibration",
                query=str(root/"query.json"),response=str(root/"answer.txt"),reference=False,
                output=str(root/"evaluation"))
            task={"hidden_cases":[],"hidden_expected":[]}
            session=SimpleNamespace(query=lambda:query)
            with patch.object(pilot,"choose_task",return_value=task), \
                 patch.object(pilot.support,"session_for",return_value=session), \
                 patch.object(pilot.validation,"evaluate",return_value={"accepted":True,"status":"correct","build":{}}), \
                 patch.object(pilot.evaluator,"execute",return_value={"status":"correct","artifact_unchanged":False}):
                pilot.evaluate_worker(args)
            result=json.loads((root/"evaluation/EVALUATION.json").read_text())
            self.assertEqual(result["status"],"infrastructure_failure")
            self.assertTrue(result["hidden_evaluated"])
            self.assertFalse(result["correct"])

    def test_usage_observed_before_incomplete_stream_is_not_complete_usage(self):
        with tempfile.TemporaryDirectory(prefix="frontier-partial-cost-", dir=pilot.HERE) as temporary:
            root=Path(temporary);task,arm=pilot.support.cells("calibration")[0]
            cfg=pilot.protocol();cfg["model_cwd_root"]=str(root/"separate-cwds")
            frozen={"prompt_bindings":pilot.support.prompt_bindings()}
            def transport(argv,cwd,output,*,input_bytes,wall_seconds,on_line):
                output.mkdir(parents=True)
                events=[{"type":"thread.started","thread_id":"dummy"},{"type":"turn.started"},
                        {"type":"item.completed","item":{"id":"answer","type":"agent_message","text":"{}"}},
                        {"type":"turn.completed","usage":USAGE}]
                (output/"stdout.raw").write_bytes(b"\n".join(pilot.canonical(e) for e in events)+b"\n")
                for e in events:on_line(pilot.canonical(e))
                return {"status":"output_limit","pid":900001}
            with patch.object(pilot,"verify_freeze",return_value=frozen), \
                 patch.object(pilot,"run_owned",side_effect=transport), \
                 patch.object(pilot,"evaluate_isolated") as evaluate:
                row=pilot.run_cell("calibration",task,arm,root,time.monotonic()+60,cfg,frozen,[])
            evaluate.assert_not_called()
            attempt=row["attempts"][0]
            self.assertIsNone(attempt["usage"])
            self.assertEqual(attempt["observed_usage"],USAGE)
            self.assertTrue(attempt["unknown_usage"])

    def test_post_transport_evidence_write_failure_preserves_actual_launch_and_unknown_cost(self):
        with tempfile.TemporaryDirectory(prefix="frontier-write-fault-", dir=pilot.HERE) as temporary:
            root=Path(temporary);task,arm=pilot.support.cells("calibration")[0]
            cfg=pilot.protocol();cfg["model_cwd_root"]=str(root/"separate-cwds")
            frozen={"prompt_bindings":pilot.support.prompt_bindings()}
            real_owned=pilot.run_owned;real_save=pilot.save
            events=[{"type":"thread.started","thread_id":"synthetic"},{"type":"turn.started"},
                    {"type":"item.completed","item":{"id":"answer","type":"agent_message","text":"{}"}},
                    {"type":"turn.completed","usage":USAGE}]
            raw=b"\n".join(pilot.canonical(e) for e in events)+b"\n"
            def synthetic(argv,cwd,output,**kwargs):
                return real_owned([sys.executable,"-c","import os;os.write(1,"+repr(raw)+")"],
                                  cwd,output,**kwargs)
            def faulty_save(path,value):
                if Path(path).name=="EVENTS.json":
                    raise OSError("synthetic evidence write failure after child completed")
                return real_save(path,value)
            with patch.object(pilot,"verify_freeze",return_value=frozen), \
                 patch.object(pilot,"run_owned",side_effect=synthetic), \
                 patch.object(pilot,"save",side_effect=faulty_save), \
                 patch.object(pilot,"evaluate_isolated") as evaluate:
                row=pilot.run_cell("calibration",task,arm,root,time.monotonic()+60,cfg,frozen,[])
            evaluate.assert_not_called()
            attempt=row["attempts"][0]
            self.assertTrue(attempt["request_started"])
            self.assertTrue(attempt["process"]["cleanup_confirmed"])
            self.assertIsNone(attempt["usage"])
            self.assertEqual(attempt["observed_usage"],USAGE)
            self.assertTrue(attempt["unknown_usage"])
            self.assertEqual(row["status"],"terminal_protocol_or_runtime_failure")
            def recorded_cell(stage,task,arm,root,deadline,cfg,frozen,rows):
                rows.append(row);return row
            with patch.object(pilot,"checked_review",return_value={}), \
                 patch.object(pilot,"verify_freeze",return_value={}), \
                 patch.object(pilot,"identity",side_effect=self.fake_identity), \
                 patch.object(pilot,"run_cell",side_effect=recorded_cell):
                pilot.experiment(root/"summary","review","controls")
            result=json.loads((root/"summary/RESULT.json").read_text())
            self.assertEqual(result["requests"],1)
            self.assertEqual(result["unknown_usage_requests"],1)
            self.assertIsNone(result["total_reported_input_plus_output"])
            self.assertEqual(result["reported_input_tokens"],7)

    def test_transport_exception_before_return_retains_indeterminate_launch_cost(self):
        with tempfile.TemporaryDirectory(prefix="frontier-return-fault-", dir=pilot.HERE) as temporary:
            root=Path(temporary);task,arm=pilot.support.cells("calibration")[0]
            cfg=pilot.protocol();cfg["model_cwd_root"]=str(root/"separate-cwds")
            frozen={"prompt_bindings":pilot.support.prompt_bindings()}
            def interrupted_return(*args, **kwargs):
                on_line=kwargs["on_line"]
                for event in ({"type":"thread.started","thread_id":"synthetic"},
                              {"type":"turn.started"},
                              {"type":"item.completed","item":{"id":"answer","type":"agent_message","text":"{}"}},
                              {"type":"turn.completed","usage":USAGE}):
                    on_line(pilot.canonical(event))
                raise OSError("transport receipt write failed after usage observation")
            with patch.object(pilot,"verify_freeze",return_value=frozen), \
                 patch.object(pilot,"run_owned",side_effect=interrupted_return):
                row=pilot.run_cell("calibration",task,arm,root,time.monotonic()+60,cfg,frozen,[])
            attempt=row["attempts"][0]
            self.assertTrue(attempt["cli_launch_attempted"])
            self.assertIsNone(attempt["request_started"])
            self.assertTrue(attempt["unknown_usage"])
            self.assertEqual(attempt["observed_usage"],USAGE)
            self.assertTrue(attempt["actual_generation_observed"])
            def recorded_cell(stage,task,arm,root,deadline,cfg,frozen,rows):
                rows.append(row);return row
            with patch.object(pilot,"checked_review",return_value={}), \
                 patch.object(pilot,"verify_freeze",return_value={}), \
                 patch.object(pilot,"identity",side_effect=self.fake_identity), \
                 patch.object(pilot,"run_cell",side_effect=recorded_cell):
                pilot.experiment(root/"summary","review","controls")
            result=json.loads((root/"summary/RESULT.json").read_text())
            self.assertEqual(result["cli_start_outcome_unknown"],1)
            self.assertEqual(result["requests"],1)
            self.assertEqual(result["unknown_usage_requests"],1)
            self.assertIsNone(result["total_reported_input_plus_output"])
            self.assertEqual(result["reported_input_tokens"],7)
            self.assertEqual(result["reported_output_tokens"],2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
