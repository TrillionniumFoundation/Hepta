"""Exercise the standalone HIA session owner across real fragmented stdio."""

from hashlib import sha256
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import tempfile
import unittest

from tools.generate_hia_mcp_connection import LIMIT, ROOT, SOURCE, render


class McpConnectionSourceTests(unittest.TestCase):
    def test_fixed_path_is_generated_from_the_shared_mcp_classifier(self):
        self.assertEqual((ROOT / SOURCE).read_text(), render())


def message(method, identifier=None, params=None):
    value = {'jsonrpc': '2.0', 'method': method}
    if identifier is not None:
        value['id'] = identifier
    if params is not None:
        value['params'] = params
    return json.dumps(value, ensure_ascii=True).encode() + b'\n'


INITIALIZE = {
    'protocolVersion': '2025-06-18', 'capabilities': {},
    'clientInfo': {'name': 'installed-test', 'version': '1'},
}


@unittest.skipUnless(os.environ.get('HIA_TEST_MCP_CONNECTION_EXE'), 'standalone MCP connection required')
class McpConnectionExecutableTests(unittest.TestCase):
    def setUp(self):
        parent = self.enterContext(tempfile.TemporaryDirectory(prefix='hia-mcp-session-'))
        self.directory = Path(parent)
        self.executable = self.directory / 'hia-agent-mcp-connection'
        supplied = Path(os.environ['HIA_TEST_MCP_CONNECTION_EXE'])
        shutil.copyfile(supplied, self.executable)
        self.executable.chmod(0o500)
        self.assertEqual(sha256(supplied.read_bytes()).digest(), sha256(self.executable.read_bytes()).digest())
        from tools.qualify_hia_selfhost_cli import inspect_executable
        self.assertFalse(inspect_executable(self.executable.read_bytes())['dynamic_loader'])

    def run_connection(self, data):
        return subprocess.run([self.executable], cwd=self.directory, input=data, capture_output=True,
                              env={'PATH': ''}, timeout=8)

    def test_actual_connection_keeps_phase_and_ids_across_split_and_burst_frames(self):
        pending = message('initialize', 'a☺', INITIALIZE)
        with subprocess.Popen([self.executable], cwd=self.directory, bufsize=0, env={'PATH': ''},
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            self.addCleanup(process.kill)
            with selectors.DefaultSelector() as ready:
                ready.register(process.stdout, selectors.EVENT_READ)
                process.stdin.write(pending[:17])
                self.assertFalse(ready.select(0.03), 'partial frames must not spend session state')
                process.stdin.write(pending[17:])
                self.assertTrue(ready.select(5), 'initialize response did not arrive')
                response = process.stdout.readline()
            self.assertIn(b'"id":"a\\u263a"', response)
            initial = json.loads(response)
            self.assertEqual(initial['result']['protocolVersion'], '2025-06-18')
            self.assertEqual(initial['result']['capabilities'], {})
            # The malformed notification cannot mark the session ready.
            burst = (message('notifications/initialized', params=[1]).replace(b'[1]', b'1')
                     + message('tools/list', 2) + message('ping', 3)
                     + message('notifications/initialized')
                     + message('tools/list', 4)
                     + message('initialize', 5, INITIALIZE)
                     + message('tools/call', 6, {'name': 'hia_emit', 'arguments': {}}))
            stdout, stderr = process.communicate(burst, timeout=8)
        self.assertEqual((process.returncode, stderr), (0, b''))
        responses = [json.loads(row) for row in stdout.splitlines()]
        self.assertEqual([row['id'] for row in responses], [2, 3, 4, 5, 6])
        self.assertEqual([row.get('error', {}).get('code') for row in responses], [-32002, None, None, -32002, -32601])
        self.assertEqual(responses[1]['result'], {})
        self.assertEqual(responses[2]['result'], {'tools': []})
        fresh = self.run_connection(message('notifications/initialized') + message('tools/list', 7))
        self.assertEqual(json.loads(fresh.stdout)['error']['code'], -32002)
        self.assertEqual(list(self.directory.iterdir()), [self.executable])

    def test_exact_limit_and_eof_do_not_publish_an_incomplete_message(self):
        request = message('ping', 1)
        exact = b' ' * (LIMIT - len(request) + 1) + request
        result = self.run_connection(exact)
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        self.assertEqual(json.loads(result.stdout)['result'], {})
        for raw in (b' ' + exact + request, request[:-1]):
            result = self.run_connection(raw)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (64, b'', b''))
        result = self.run_connection(b'not JSON\n{}\n' + request)
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        parsed = [json.loads(row) for row in result.stdout.splitlines()]
        self.assertEqual([row['error']['code'] for row in parsed[:2]], [-32700, -32600])
        self.assertEqual(parsed[2]['result'], {})
