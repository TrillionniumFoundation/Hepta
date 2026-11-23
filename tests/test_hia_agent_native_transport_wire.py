"""Reject malformed JSON-RPC response identities at the qualification boundary."""
import io
import sys
import time
import unittest
from types import SimpleNamespace

from tools.hia_agent_native_transport import MCPStdio, QualificationFailure


class MCPWireEnvelopeTests(unittest.TestCase):
    def make_client(self, replies):
        client = object.__new__(MCPStdio)
        client.timeout = 2
        client.counter = 0
        client.process = SimpleNamespace(stdin=io.BytesIO())
        client.protocol_records = []
        iterator = iter(replies)
        client._read_message = lambda deadline: next(iterator)
        return client

    def test_boolean_id_cannot_impersonate_numeric_id(self):
        client = self.make_client([
            {"jsonrpc": "2.0", "id": True, "result": {"winner": "forged"}},
            {"jsonrpc": "2.0", "id": 1, "result": {"winner": "genuine"}},
        ])
        self.assertEqual(client.rpc("tools/list", {}), {"winner": "genuine"})

    def test_float_id_cannot_impersonate_numeric_id(self):
        client = self.make_client([
            {"jsonrpc": "2.0", "id": 1.0, "result": {"winner": "forged"}},
            {"jsonrpc": "2.0", "id": 1, "result": {"winner": "genuine"}},
        ])
        self.assertEqual(client.rpc("tools/list", {}), {"winner": "genuine"})

    def test_valid_notification_is_not_accepted_as_a_reply(self):
        client = self.make_client([
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}},
            {"jsonrpc": "2.0", "id": 1, "result": {"status": "completed"}},
        ])
        self.assertEqual(client.rpc("tools/list", {}), {"status": "completed"})

    def test_non_object_response_is_rejected(self):
        client = self.make_client([[{"id": 1}]])
        with self.assertRaises(QualificationFailure):
            client.rpc("tools/list", {})

    def test_backend_exit_without_reply_is_observed_and_never_retried(self):
        # A real stdio process acknowledges initialize then exits on tools/list.
        # A missing tool reply must remain an unknown operation, not completion.
        server = """
import json, sys
sys.stdin.readline()
print(json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}), flush=True)
sys.stdin.readline()
sys.stdin.readline()
"""
        started = time.monotonic()
        with MCPStdio([sys.executable, "-u", "-c", server], timeout=3) as client:
            with self.assertRaises(QualificationFailure):
                client.rpc("tools/list", {})
            self.assertEqual(client.counter, 2)
        self.assertLess(time.monotonic() - started, 8)

    def test_wrong_jsonrpc_version_cannot_be_accepted(self):
        client = self.make_client([{"jsonrpc": "1.0", "id": 1, "result": {}}])
        with self.assertRaises(QualificationFailure):
            client.rpc("tools/list", {})

    def test_dual_result_and_error_is_rejected(self):
        client = self.make_client([
            {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": -1}},
        ])
        with self.assertRaises(QualificationFailure):
            client.rpc("tools/list", {})


if __name__ == "__main__":
    unittest.main()
