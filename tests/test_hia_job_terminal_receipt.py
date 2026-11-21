"""The sealed HIA classifier consumes the unchanged JSON receipt bytes."""

import json
import os
from pathlib import Path
import struct
import subprocess
import unittest

from hepta.hia_scalar_reference_native import sealed_reference_bytes


class JobTerminalReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get('HEPTA_HIA_JOB_TERMINAL_RECEIPT_EXECUTABLE')
        if not path:
            raise unittest.SkipTest('requires the installed HIA receipt executable')
        cls.program = Path(path)

    def classify(self, payload):
        with sealed_reference_bytes(payload) as fd:
            os.lseek(fd, 0, os.SEEK_SET)
            result = subprocess.run([self.program], stdin=fd, env={'PATH': ''}, timeout=5,
                                    capture_output=True, check=True)
        self.assertFalse(result.stderr)
        if len(result.stdout) == 8:
            return struct.unpack('<Q', result.stdout)[0], None
        size, magic, state = struct.unpack('<Q8sQ', result.stdout)
        self.assertEqual((size, magic), (16, b'HIAJTV01'))
        return size, state

    def test_original_state_precedence(self):
        for receipt, expected in (
                ({}, 4), ({'exit_code': None}, 0), ({'exit_code': 0}, 5),
                ({'exit_code': -9}, 4), ({'exit_code': 0, 'output_durable': False}, 4),
                ({'exit_code': 0, 'output_complete': None}, 4),
                ({'exit_code': 0, 'output_complete': True, 'output_durable': True}, 5),
                ({'exit_code': 0, 'cancelled': True}, 3),
                ({'exit_code': 1, 'cancelled': True, 'timed_out': True}, 2),
                ({'exit_code': 0, 'cancelled': True, 'timed_out': True, 'effect_outcome': 'unknown'}, 1),
                ({'exit_code': 0, 'future': [{'timed_out': True}, {'exit_code': -1}]}, 5)):
            with self.subTest(receipt=receipt):
                raw = json.dumps(receipt, ensure_ascii=True).encode()
                self.assertEqual(self.classify(raw), (16, expected))
        self.assertEqual(self.classify(b' { "exit_code" : -0 }\n'), (16, 5))
        self.assertEqual(self.classify(b'{"effect_outcome":"u\\u006eknown","exit_code":0}'), (16, 1))

    def test_malformed_and_unsupported_types_never_publish_terminal_status(self):
        for raw in (b'[]', b'{"exit_code":0,"exit_\\u0063ode":0}',
                    b'{"timed_out":"false","exit_code":0}', b'{"exit_code":0.0}',
                    b'{"exit_code":"0"}', b'{"exit_code":0} {}'):
            with self.subTest(raw=raw):
                status, state = self.classify(raw)
                self.assertGreaterEqual(status, 0xfffffff0)
                self.assertIsNone(state)
