"""No-model controls for contract recovery and the owned CLI exit race."""
import copy
import errno
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from hepta.hia_agent_contract import catalog, validate, input_diagnostic
from hepta.hia_agent_store import AgentRejected
from tools import hia_agent_codex_transport as transport
from tools.hia_agent_fresh_session import FreshEvents, run_session


class ContractRecoveryTests(unittest.TestCase):
    def setUp(self):
        data, self.sha = catalog()
        self.tools = {item['name']: item for item in data['tools']}

    def test_hash_error_names_the_field_and_rejects_original_72_chars(self):
        request = {'catalog_sha256': 'a' * 72,
            'artifact': {'id': 'artifact', 'sha256': 'b' * 64, 'uri': 'hia://artifacts/artifact'}}
        with self.assertRaisesRegex(AgentRejected, 'arguments.catalog_sha256'):
            validate(request, self.tools['hia_read']['inputSchema'])
        request['catalog_sha256'] = self.sha
        validate(request, self.tools['hia_read']['inputSchema'])

    def test_import_diagnostic_names_missing_contract_fields(self):
        request = {'catalog_sha256': self.sha, 'request_key': 'trial/import/1',
            'context': {'id': 'context', 'sha256': 'c' * 64},
            'change': {'kind': 'import', 'program': {'not': 'a retained artifact'}}}
        with self.assertRaisesRegex(AgentRejected, 'arguments.change: missing fields format, source'):
            validate(request, self.tools['hia_candidate']['inputSchema'])
        request['request_key'] = 'trial/import/2'
        request['change'] = {'kind': 'import', 'format': 'hia-asm.v1', 'source': {
            'id': 'artifact', 'sha256': 'b' * 64, 'uri': 'hia://artifacts/artifact'}}
        validate(request, self.tools['hia_candidate']['inputSchema'])

    def test_tagged_union_diagnostic_does_not_relax_oneof(self):
        schema = {'oneOf': [{'type': 'object', 'properties': {'kind': {'const': 'x'}}},
                            {'type': 'object', 'properties': {'kind': {'const': 'x'}}}]}
        with self.assertRaisesRegex(AgentRejected, 'does not match oneOf'):
            validate({'kind': 'x'}, schema)
        with self.assertRaisesRegex(AgentRejected, 'does not match oneOf'):
            validate({'kind': 'unregistered'}, schema)
        with self.assertRaisesRegex(AgentRejected, 'does not match oneOf'):
            validate({'kind': 'x'}, {'oneOf':[False, {'type':'object',
                'properties':{'kind':False}}]})

    def test_catalog_has_neutral_discoverable_recovery(self):
        self.assertEqual(len(self.tools), 11)
        self.assertIn('result.artifact', self.tools['hia_artifact']['description'])
        self.assertIn('fresh request key', self.tools['hia_candidate']['description'])
        self.assertIn('64', self.tools['hia_read']['inputSchema']['properties']['catalog_sha256']['description'])

    def test_bridge_hint_neither_repairs_nor_refunds_and_reveals_no_answer(self):
        request = {'catalog_sha256':'a' * 72, 'artifact':{'id':'artifact','sha256':'b' * 64,
            'uri':'hia://artifacts/artifact'}}
        original = copy.deepcopy(request)
        result = input_diagnostic('hia_read', request)
        self.assertIn('arguments.catalog_sha256', result['message'])
        self.assertFalse(result['automatic_repair'])
        self.assertFalse(result['attempt_refunded'])
        self.assertEqual(request, original)
        request['catalog_sha256'] = self.sha
        self.assertIsNone(input_diagnostic('hia_read', request))
        self.assertIsNone(input_diagnostic('foreign_tool', {}))


class OwnedExitTests(unittest.TestCase):
    def run_child(self, source, **kwargs):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = transport.run_owned([sys.executable, '-B', '-c', source], root, root / 'transport',
                wall_seconds=kwargs.pop('wall_seconds', 2), **kwargs)
            stdout = (root / 'transport/stdout.raw').read_bytes()
            stderr = (root / 'transport/stderr.raw').read_bytes()
            return result, stdout, stderr

    def test_fast_terminal_child_never_requires_late_getpgid(self):
        with patch.object(transport.os, 'getpgid', side_effect=ProcessLookupError('macOS zombie race')):
            result, stdout, _ = self.run_child("print('done')")
        self.assertTrue(result['leader_reaped'], result)
        self.assertTrue(result['cleanup_confirmed'], result)
        self.assertEqual(stdout, b'done\n')
        self.assertEqual(result['status'], 'exited')
        self.assertTrue(result['signal_attempted_before_reap'])

    def test_timeout_stops_owned_group_and_retains_original_output(self):
        result, stdout, _ = self.run_child("import time; print('started',flush=True); time.sleep(20)", wall_seconds=.15)
        self.assertEqual(result['status'], 'wall_timeout')
        self.assertTrue(result['cleanup_confirmed'], result)
        self.assertEqual(stdout, b'started\n')
        self.assertGreaterEqual(result['cpu_ns']['children'], 0)

    def test_terminal_group_absence_has_exact_owned_pre_reap_receipt(self):
        with patch.object(transport.os, 'killpg', side_effect=ProcessLookupError(errno.ESRCH, 'group absent')):
            result, _, _ = self.run_child('pass')
        self.assertTrue(result['owned_terminal_before_signal'])
        self.assertTrue(result['group_absent_before_reap'])
        self.assertTrue(result['cleanup_confirmed'])
        self.assertFalse(result['signal_delivered'])

    def test_eperm_without_exact_zombie_and_empty_after_is_unknown(self):
        with patch.object(transport.os, 'killpg', side_effect=PermissionError(errno.EPERM, 'denied')), \
             patch.object(transport, '_group_snapshot', return_value=[]):
            result, _, _ = self.run_child('pass')
        self.assertTrue(result['leader_reaped'])
        self.assertFalse(result['cleanup_confirmed'])
        self.assertEqual(result['status'], 'cleanup_uncertain')

    def test_original_expired_deadline_cannot_start_a_process(self):
        with patch.object(transport.subprocess, 'Popen', side_effect=AssertionError('must not launch')):
            result, _, _ = self.run_child('pass', absolute_deadline_unix_ns=time.time_ns()-1)
        self.assertNotIn('pid', result)
        self.assertEqual(result['status'], 'wall_timeout_before_launch')


class FreshReceiptTests(unittest.TestCase):
    def test_cancellation_actor_and_wire_counts_remain_unknown(self):
        stream = FreshEvents('hia_trial')
        rows = [{'type':'thread.started','thread_id':'fake'}, {'type':'turn.started'},
            {'type':'item.completed','item':{'id':'i1','type':'mcp_tool_call','server':'hia_trial',
                'tool':'hia_artifact','error':{'message':'user cancelled MCP tool call'},'result':None}},
            {'type':'turn.completed','usage':{'input_tokens':100,'cached_input_tokens':90,
                'output_tokens':10,'reasoning_output_tokens':3}}]
        for row in rows: stream.line(json.dumps(row).encode())
        result = stream.summary()
        self.assertEqual(result['input_plus_output_tokens'], 110)
        self.assertIsNone(result['actual_hia_wire_calls'])
        self.assertIsNone(result['cancellation_observations'][0]['actor'])
        self.assertIsNone(result['cancellation_observations'][0]['cause'])

    def test_no_model_cli_fixture_exercises_shared_cleanup_and_limits(self):
        rows = [{'type':'thread.started','thread_id':'authored-fixture'}, {'type':'turn.started'},
            {'type':'item.completed','item':{'id':'answer','type':'agent_message','text':'fixture only'}},
            {'type':'turn.completed','usage':{'input_tokens':7,'output_tokens':5}}]
        raw = b''.join(json.dumps(row).encode()+b'\n' for row in rows)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            argv = [sys.executable, '-B', '-c', 'import os; os.write(1,'+repr(raw)+')']
            result = run_session(argv, root, root/'out', public_prompt=b'no model fixture',
                executable_sha256=transport.identity(sys.executable)['sha256'],
                deadline_unix_ns=time.time_ns()+5_000_000_000,
                deadline_monotonic_ns=time.monotonic_ns()+5_000_000_000,
                max_wall_seconds=3, token_review_limit=11)
        self.assertTrue(result['process']['cleanup_confirmed'], result)
        self.assertFalse(result['within_token_review_limit'])
        self.assertEqual(result['p1_acceptance'], 'HOLD')
        self.assertEqual(result['cli_sessions_started'], 1)
        self.assertIsNone(result['provider_http_request_count'])

    def test_foreign_tool_and_nonfinite_json_are_rejected(self):
        stream = FreshEvents('hia_trial')
        for row in [{'type':'thread.started'}, {'type':'turn.started'}]: stream.line(json.dumps(row).encode())
        with self.assertRaisesRegex(ValueError, 'FOREIGN_TOOL'):
            stream.line(json.dumps({'type':'item.started','item':{'id':'x','type':'mcp_tool_call',
                'server':'another','tool':'hia_read'}}).encode())
        with self.assertRaisesRegex(ValueError, 'NONFINITE_JSON'):
            transport.strict_json(b'{"x":NaN}')


if __name__ == '__main__':
    unittest.main()
