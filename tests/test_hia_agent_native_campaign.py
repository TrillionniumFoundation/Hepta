"""Real persistent-store checks for qualification ownership and recovery.

The transport-loss case deliberately loses an already committed artifact reply.
No remote MCP endpoint or real Agent deployment is claimed by these tests.
"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_service import HIAAgentService
from tools import hia_agent_native_qualification as qualification


class QualificationCampaignTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-campaign-test-")
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_cli_requires_explicit_campaign_before_any_transport_or_evidence(self):
        output = self.root / "missing.json"
        with patch.object(qualification, "MCPStdio") as transport, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                qualification.main(["--output", str(output), "--mcp-command-json", '["unused"]'])
        self.assertEqual(caught.exception.code, 2)
        transport.assert_not_called()
        self.assertFalse(output.exists())

    def test_invalid_campaign_cannot_start_a_transport_or_use_an_arbitrary_slot(self):
        for identity in ("", "../slot", "/slot", "campaign/other", "x" * 97, "雪", "x\n"):
            with self.subTest(identity=identity), patch.object(qualification, "MCPStdio") as transport, \
                    redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    qualification.main(["--output", str(self.root / "invalid.json"),
                        "--campaign-id", identity, "--mcp-command-json", '["unused"]'])
                self.assertEqual(caught.exception.code, 2)
                transport.assert_not_called()
                self.assertFalse((self.root / "invalid.json").exists())

    def test_existing_output_is_preserved_and_refused_before_dispatch(self):
        output = self.root / "original.json"
        original = b'{"status":"original evidence"}\n'
        output.write_bytes(original)
        with patch.object(qualification, "MCPStdio") as transport:
            with self.assertRaises(FileExistsError):
                qualification.main(["--output", str(output), "--campaign-id", "output-refusal",
                                    "--mcp-command-json", '["unused"]'])
        transport.assert_not_called()
        self.assertEqual(output.read_bytes(), original)
        self.assertFalse(output.with_name(output.name + ".calls.jsonl").exists())

    def test_two_campaigns_share_store_but_not_slot_and_reconnect_does_not_reexecute(self):
        state = self.root / "worker"
        service = HIAAgentService(state)
        bindings = [qualification.campaign_binding("campaign-a"),
                    qualification.campaign_binding("campaign-b")]
        clients, results = [], []
        try:
            for binding in bindings:
                client = qualification.ToolClient(service.call)
                session = qualification.Session(client, prefix=binding["request_prefix"])
                results.append(qualification.scripted_loop(session, target_slot=binding["target_slot"]))
                clients.append(client)
            self.assertEqual({row[0] for row in service.store.db.execute("SELECT name FROM slots")},
                             {binding["target_slot"] for binding in bindings})
            for binding, result in zip(bindings, results):
                self.assertEqual(result["adoption"]["target_slot"], binding["target_slot"])
                self.assertEqual(result["adoption"]["previous"], {"generation": "0", "epoch": "0"})
                self.assertEqual(result["stale_adoption"]["status"], "rejected")
                self.assertEqual(result["rollback"]["target_slot"], binding["target_slot"])
                self.assertEqual(result["rollback"]["current"]["generation"], "0")
            first_keys = {r["arguments"]["request_key"] for r in clients[0].records
                          if "request_key" in r["arguments"]}
            second_keys = {r["arguments"]["request_key"] for r in clients[1].records
                           if "request_key" in r["arguments"]}
            self.assertFalse(first_keys & second_keys)
            tables = ("requests", "contexts", "slots", "versions", "execution_budgets")
            before = {name: [tuple(row) for row in service.store.db.execute("SELECT * FROM " + name)]
                      for name in tables}
        finally:
            service.close()

        restarted = HIAAgentService(state)
        try:
            client = qualification.ToolClient(restarted.call)
            session = qualification.Session(client, prefix=bindings[0]["request_prefix"])
            with ExitStack() as stack:
                for method in ("artifact", "context", "candidate", "verify", "emit",
                               "evaluate", "adopt", "rollback"):
                    stack.enter_context(patch.object(restarted, "_hia_" + method,
                        side_effect=AssertionError("replay executed mutation: " + method)))
                replay = qualification.scripted_loop(session, target_slot=bindings[0]["target_slot"])
            self.assertEqual(replay, results[0])
            self.assertEqual([(r["tool"], r["arguments"], r["response"]) for r in client.records],
                             [(r["tool"], r["arguments"], r["response"]) for r in clients[0].records])
            after = {name: [tuple(row) for row in restarted.store.db.execute("SELECT * FROM " + name)]
                     for name in tables}
            self.assertEqual(after, before)

            original = next(r for r in clients[0].records if r["tool"] == "hia_artifact")
            changed = deepcopy(original["arguments"])
            changed["source"]["text"] = "changed payload under original campaign key"
            refused = restarted.call("hia_artifact", changed)
            self.assertEqual(refused["status"], "rejected")
            self.assertEqual(refused["error"]["code"], "E_HIA_REQUEST_CONFLICT")
            self.assertEqual(restarted.call("hia_artifact", original["arguments"]), original["response"])
        finally:
            restarted.close()

    def test_committed_but_lost_reply_retains_original_intent_for_recovery(self):
        service = HIAAgentService(self.root / "worker")
        output = self.root / "lost-reply.json"
        original_reply = {}
        closed = []

        class LostReplyTransport:
            initialized = {"test_fixture": True}
            protocol_records = []

            def list_tools(self):
                return service.catalog["tools"]

            def call(self, tool, arguments):
                if tool == "hia_artifact":
                    # Assert that original bytes were durably recorded before
                    # the simulated remote effect, not after the exception.
                    rows = [json.loads(line) for line in output.with_name(
                        output.name + ".calls.jsonl").read_text().splitlines()]
                    if rows[-1]["phase"] != "intent" or rows[-1]["arguments"] != arguments:
                        raise AssertionError("original intent missing before dispatch")
                    original_reply["value"] = service.call(tool, arguments)
                    raise TimeoutError("test fixture lost a committed artifact response")
                return service.call(tool, arguments)

            def close(self):
                closed.append(True)

        try:
            with patch.object(qualification, "MCPStdio", return_value=LostReplyTransport()):
                with self.assertRaises(TimeoutError), redirect_stdout(io.StringIO()):
                    qualification.main(["--output", str(output), "--campaign-id", "lost-reply",
                                        "--mcp-command-json", '["test-fixture"]'])
            report = json.loads(output.read_text())
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["error_type"], "TimeoutError")
            self.assertEqual(closed, [True])
            self.assertFalse(report["formal_endpoint_qualified"])
            rows = [json.loads(line) for line in output.with_name(
                output.name + ".calls.jsonl").read_text().splitlines()]
            intent, error = rows[-2:]
            self.assertEqual(intent["phase"], "intent")
            self.assertEqual(error["phase"], "error")
            self.assertEqual(error["outcome"], "unknown")
            self.assertEqual(intent["arguments"], error["arguments"])
            self.assertEqual(error["arguments"], report["calls"][-1]["arguments"])
            count = service.store.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            replay = service.call(intent["tool"], intent["arguments"])
            self.assertEqual(replay, original_reply["value"])
            self.assertEqual(service.store.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0], count)
        finally:
            service.close()


if __name__ == "__main__":
    unittest.main()
