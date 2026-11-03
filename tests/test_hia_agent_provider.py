"""Provider access failures cannot become coding successes or zero token cost."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_agent_provider as provider

PROCESS = {"status": "exited", "returncode": 0, "cleanup_confirmed": True,
           "leader_reaped": True, "streams_complete": True}
USAGE = {"input_tokens": 10, "cached_input_tokens": 2, "cache_write_input_tokens": 0,
         "output_tokens": 1, "reasoning_output_tokens": 0}
QUOTA = "You've hit your usage limit. Try again later."


def wire(events):
    return b"".join(provider.canonical(e) + b"\n" for e in events)


def success(text="AVAILABLE"):
    return [{"type": "thread.started", "thread_id": "test-fixture"}, {"type": "turn.started"},
            {"type": "item.completed", "item": {"id": "x", "type": "agent_message", "text": text}},
            {"type": "turn.completed", "usage": deepcopy(USAGE)}]


class ProviderTests(unittest.TestCase):
    def test_quota_and_unsupported_remain_unknown_usage(self):
        unsupported = json.dumps({"type": "error", "status": 400, "error": {"code": "model_not_found"}})
        for message, expected in ((QUOTA, "account_quota"), (unsupported, "unsupported_selector")):
            raw = wire([{"type": "error", "message": message}, {"type": "turn.failed", "error": {"message": message}}])
            result = provider.classify({**PROCESS, "status": "process_failure", "returncode": 1}, raw)
            self.assertEqual(result["diagnosis"], expected)
            self.assertIsNone(result["usage"])
            self.assertFalse(result["available"])
            self.assertEqual(result["provider_messages"], [message])
            self.assertEqual((result["coding_task_requests"], result["task_successes"]), (0, 0))

    def test_complete_probe_has_usage_but_is_not_a_coding_success(self):
        result = provider.classify(PROCESS, wire(success()))
        self.assertTrue(result["available"])
        self.assertEqual(result["usage"], USAGE)
        self.assertEqual(result["task_successes"], 0)
        for tail in (b"not-json\n", b"null\n", b"\n", b"\xff\n"):
            with self.subTest(tail=tail):
                result = provider.classify(PROCESS, wire(success()) + tail)
                self.assertFalse(result["available"])
                self.assertEqual(result["diagnosis"], "protocol_failure")
                self.assertIsNone(result["usage"])
                self.assertIn("error", result)

    def test_quoted_quota_is_not_a_provider_error(self):
        result = provider.classify(PROCESS, wire(success(QUOTA)))
        self.assertFalse(result["account_block_observed"])
        self.assertFalse(result["available"])

    def test_missing_duplicate_and_boolean_usage_cannot_admit(self):
        malformed = success()
        malformed[-1]["usage"]["input_tokens"] = True
        for events in (success()[:-1], success() + [success()[-1]], malformed):
            result = provider.classify(PROCESS, wire(events))
            self.assertFalse(result["available"])
            self.assertIsNone(result["usage"])
        self.assertFalse(provider.classify(PROCESS, b'{"type":"error","type":"turn.completed"}\n')["available"])

    def test_tools_unknown_events_and_unclean_success_cannot_admit(self):
        for event in ({"type": "new.event"}, {"type": "item.started", "item": {"type": "command_execution"}}):
            with self.assertRaises(ValueError):
                provider._guard(wire([event]))
            self.assertFalse(provider.classify(PROCESS, wire(success() + [event]))["available"])
        result = provider.classify({**PROCESS, "cleanup_confirmed": False}, wire(success()))
        self.assertEqual(result["diagnosis"], "cleanup_uncertain")
        self.assertFalse(result["available"])

    def test_batch_stops_after_quota_or_uncertain_cleanup(self):
        quota = wire([{"type": "error", "message": QUOTA}])
        cases = [(quota, PROCESS, "account_quota", "not_attempted_after_account_quota"),
                 (quota + b"not-json\n", PROCESS, "account_quota", "not_attempted_after_account_quota"),
                 (wire(success()), {**PROCESS, "cleanup_confirmed": False},
                  "cleanup_uncertain", "not_attempted_after_uncertain_cleanup")]
        for field in ("cleanup_confirmed", "leader_reaped", "streams_complete"):
            cases.append((b"not-json\n", {**PROCESS, field: False},
                          "cleanup_uncertain", "not_attempted_after_uncertain_cleanup"))
        for raw, process, diagnosis, stop in cases:
            with self.subTest(raw=raw, process=process):
                classified = provider.classify(process, raw)
                self.assertEqual(classified["diagnosis"], diagnosis)
                self.assertFalse(classified["available"])
                if diagnosis == "account_quota":
                    self.assertTrue(classified["account_block_observed"])
                    self.assertEqual(classified["provider_messages"], [QUOTA])
                    self.assertIsNone(classified["usage"])
                if b"not-json" in raw:
                    self.assertIn("error", classified)
                calls = []
                def execute(argv, cwd, output, **kwargs):
                    calls.append(argv)
                    output.mkdir()
                    (output / "stdout.raw").write_bytes(raw)
                    return deepcopy(process)
                # Cleanup must stop the batch even if a classifier reports a
                # generic protocol diagnosis. Quota uses its observed signal.
                with tempfile.TemporaryDirectory() as folder, patch.object(
                        provider, "classify", return_value={**classified, "diagnosis": "protocol_failure"}):
                    rows = provider.probe_batch("/fixture/codex", ["first", "second"], Path(folder), 10, execute=execute)
                self.assertEqual(len(calls), 1)
                self.assertEqual(len(rows), 2)
                self.assertFalse(rows[1]["attempted"])
                self.assertEqual(rows[1]["diagnosis"], stop)
                self.assertIsNone(rows[1]["usage"])
                self.assertFalse(rows[1]["available"])

    def test_catalog_is_not_entitlement_and_incomplete_pages_refuse(self):
        ack = {"id": 1, "result": {"userAgent": "fixture"}}
        row = {"id": "model", "model": "model", "isDefault": True}
        response = {"id": 2, "result": {"data": [row], "nextCursor": None}}
        result = provider.catalog_response(wire([ack, response]))
        self.assertFalse(result["account_entitlement_attested"])
        self.assertEqual(result["model_generation_requests"], 0)
        bad = []
        for mutation in (lambda r: r["result"].update(nextCursor="next"),
                         lambda r: r["result"]["data"].append(deepcopy(row)),
                         lambda r: r["result"]["data"][0].update(isDefault=1),
                         lambda r: r.update(id=True)):
            changed = deepcopy(response)
            mutation(changed)
            bad.append([ack, changed])
        bad.append([ack, response, {"method": "turn/started"}])
        for events in bad:
            with self.assertRaises(ValueError):
                provider.catalog_response(wire(events))
        # Malformed recorded rows must still produce a structured blocked
        # report. Replay has no executable or provider connection.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for index, row in enumerate((None, [], "not-an-object", 1, True)):
                with self.subTest(replay_row=row):
                    source = root / (str(index) + ".json")
                    source.write_text(json.dumps({"schema": "hepta.hia.agent-availability-diagnostic.v1",
                                                  "coding_task_requests": 0, "rows": [row]}))
                    output = root / ("replay-" + str(index))
                    result = subprocess.run([sys.executable, "-B", str(Path(provider.__file__)), "replay",
                                             "--input", str(source), "--output", str(output)],
                                            capture_output=True, timeout=20)
                    self.assertEqual(result.returncode, 1, result.stderr.decode())
                    self.assertNotIn(b"Traceback", result.stderr)
                    report = json.loads((output / "RESULT.json").read_text())
                    self.assertEqual(report["status"], "blocked")
                    self.assertEqual(report["error"]["type"], "ValueError")
                    self.assertEqual(report["error"]["message"], "recorded diagnostic row must be an object")
                    self.assertEqual((report["coding_task_requests"], report["task_successes"]), (0, 0))

    def test_real_pipe_ack_order_and_owned_probe_cleanup(self):
        # An explicitly non-model executable checks the adapter's actual
        # stdin/stdout ordering and process lifecycle without account access.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            executable = root / "non-model-fixture"
            executable.write_text("#!" + sys.executable + "\n" +
                "import json,sys\n" +
                "if 'app-server' in sys.argv:\n" +
                " init=json.loads(input()); assert init['method']=='initialize'\n" +
                " assert init['params']['capabilities']['optOutNotificationMethods']==['remoteControl/status/changed']\n" +
                " print(json.dumps({'id':1,'result':{'userAgent':'non-model-fixture'}}),flush=True)\n" +
                " assert json.loads(input())['method']=='initialized'\n" +
                " assert json.loads(input())=={'id':2,'method':'model/list','params':{}}\n" +
                " print(json.dumps({'id':2,'result':{'data':[{'id':'fixture','model':'fixture','isDefault':True}],'nextCursor':None}}),flush=True)\n" +
                " assert sys.stdin.read()==''\n" +
                "else:\n" +
                " assert sys.argv[1]=='exec' and '--ephemeral' in sys.argv and 'read-only' in sys.argv\n" +
                " assert sys.stdin.buffer.read()==" + repr(provider.PROMPT) + "\n" +
                " sys.stdout.buffer.write(" + repr(wire(success())) + ")\n")
            executable.chmod(0o700)
            output = root / "catalog"
            result = subprocess.run([sys.executable, "-B", str(Path(provider.__file__)), "catalog",
                                     "--codex", str(executable), "--output", str(output), "--wall-seconds", "10"],
                                    capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            report = json.loads((output / "RESULT.json").read_text())
            self.assertEqual(report["status"], "catalog_observed")
            self.assertTrue(report["process"]["cleanup_confirmed"])
            self.assertFalse(report["account_entitlement_attested"])
            batch = root / "batch"
            batch.mkdir()
            rows = provider.probe_batch(str(executable), ["fixture"], batch, 10)
            self.assertTrue(rows[0]["available"])
            self.assertTrue(rows[0]["process"]["cleanup_confirmed"])
            self.assertEqual(rows[0]["usage"], USAGE)


if __name__ == "__main__":
    unittest.main()
