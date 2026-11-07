"""Targeted adapter tests; these are not native lifecycle or Agent evidence."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import http_qualification as h


def pending():
    return {"contract_version": "hepta.hia.agent-native.v1", "status": "unknown",
            "request_id": "hia_" + "a" * 64,
            "operation": {"host": "x230", "job_id": "owned-job", "request_sha256": "a" * 64,
                          "report_artifact": None}}


class AdapterTests(unittest.TestCase):
    def test_json_and_multiline_sse_match(self):
        expected = {"jsonrpc": "2.0", "id": 7, "result": {"done": True}}
        self.assertEqual(h.response_messages(json.dumps(expected).encode()), [expected])
        self.assertEqual(h.response_messages(
            b'event: message\ndata: {"jsonrpc":"2.0",\ndata: "id":7,"result":{"done":true}}\n\n'), [expected])
        with self.assertRaises(h.QualificationFailure):
            h.response_messages(b": keepalive\n\n")

    def test_slot_substitution_preserves_zero_cas_and_other_fields(self):
        session = object.__new__(h.OwnedSlotSession)
        session.target_slot = "qualification-http-c81a938150d2-372e7da9-r1"
        session.prefix, session.sequence = "http-c81-r1", 0
        session.catalog_sha256, session.context = "b" * 64, {"id": "context"}
        current = {"generation": "0", "epoch": "0"}
        args = session.arguments(target_slot="qualification", expected_current=current, candidate_artifact={"x": 1})
        self.assertEqual(args, {"catalog_sha256": "b" * 64, "context": {"id": "context"},
                               "request_key": "http-c81-r1/1/call", "target_slot": session.target_slot,
                               "expected_current": current, "candidate_artifact": {"x": 1}})
        with self.assertRaises(h.QualificationFailure):
            session.arguments(target_slot="someone-elses-slot")

    def test_original_pending_identity_must_match_host_and_digest(self):
        self.assertEqual(h.MCPHTTP.pending_identity(pending()), ("x230", "owned-job", "a" * 64))
        for edit in (lambda x: x["operation"].update(host="main"),
                     lambda x: x.update(request_id="hia_" + "b" * 64)):
            response = pending()
            edit(response)
            with self.assertRaises(h.QualificationFailure):
                h.MCPHTTP.pending_identity(response)

    def test_report_requires_every_durable_field_strictly_true(self):
        response = {"contract_version": "hepta.hia.agent-native.v1", "status": "rejected"}
        report = {"schema": "hia-agent-worker-report-v1", "tool": "hia_adopt",
                  "request_sha256": "a" * 64, "profile_sha256": "b" * 64,
                  **h.PINS, "complete": True, "response": response}
        raw = json.dumps(report).encode()
        terminal = {"job_id": "owned-job", "state": "succeeded", "exit_code": 0,
                    "output_complete": True, "output_durable": True, "terminal_publication_confirmed": True}
        def part(data):
            return {"offset": 0, "next_offset": len(data), "size": len(data), "eof": True,
                    "bytes_hex": data.hex(), "text": data.decode()}
        page = {"job_id": "owned-job", "stdout": part(raw), "stderr": part(b"")}
        transport = object.__new__(h.MCPHTTP)
        transport.timeout = 1
        for key in ("output_complete", "output_durable", "terminal_publication_confirmed"):
            for value in (None, False, 1):
                bad = {**terminal, key: value}
                transport.owner_observation = lambda name, args, value=bad: value
                with self.subTest(key=key, value=value), self.assertRaises(h.QualificationFailure):
                    transport.original_report(("x230", "owned-job", "a" * 64), "hia_adopt")
        transport.owner_observation = lambda name, args: terminal if name == "process_wait" else page
        self.assertEqual(transport.original_report(("x230", "owned-job", "a" * 64), "hia_adopt"), report)
        page["stdout"]["next_offset"] -= 1
        with self.assertRaises(h.QualificationFailure):
            transport.original_report(("x230", "owned-job", "a" * 64), "hia_adopt")

    def test_pending_reconciliation_replays_only_identical_original_arguments(self):
        transport = object.__new__(h.MCPHTTP)
        transport.timeout = 1
        terminal = {"contract_version": "hepta.hia.agent-native.v1", "status": "rejected"}
        supplied = [pending(), terminal]
        calls = []
        def rpc(method, params):
            calls.append((method, params))
            return {"structuredContent": supplied.pop(0)}
        transport.rpc = rpc
        transport.original_report = lambda identity, name: {"response": terminal}
        args = {"request_key": "original-only", "expected_current": {"generation": "0", "epoch": "0"}}
        self.assertEqual(transport.call("hia_adopt", args), terminal)
        self.assertEqual(calls, [("tools/call", {"name": "hia_adopt", "arguments": args})] * 2)

    def test_pending_result_is_never_replaced_with_raw_worker_report(self):
        transport = object.__new__(h.MCPHTTP)
        transport.timeout = 1
        transport.rpc = lambda *_: {"structuredContent": pending()}
        transport.original_report = lambda *_: {"response": {"status": "completed"}}
        with self.assertRaisesRegex(h.QualificationFailure, "remains unadmitted"):
            transport.call("hia_adopt", {"request_key": "original-only"})

    def test_http_redirects_are_not_followed(self):
        self.assertIsNone(h.NoRedirect().redirect_request(None, None, 307, "", {}, "https://example.invalid"))

    def test_existing_registration_stops_before_token_or_http(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(h, "token_bytes") as read:
            with self.assertRaises(FileExistsError):
                h.main(["--url", "http://127.0.0.1:8791/mcp", "--token-file", "/unused",
                        "--output", directory, "--runtime-commit", "c81a938150d2e533843a42af77739cb888812338",
                        "--target-slot", "qualification-http-c81a938150d2-372e7da9-r1", "--prefix", "http-c81-r1"])
            read.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
