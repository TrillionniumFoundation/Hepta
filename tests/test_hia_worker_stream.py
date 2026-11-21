"""Exercise sealed HIA stream admission with actual inherited descriptors."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_contract import VERSION
from hepta.hia_agent_store import wire
from hepta.hia_scalar_reference_native import sealed_reference_bytes
from hepta.hia_worker_request_native import (
    ADMISSION_FRAME, ADMISSION_INPUT_MAGIC, MAX_BYTES, NativeRequestRejected,
    NativeWorkerRequest, _standalone_admit,
)


class WorkerStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get('HEPTA_HIA_WORKER_STREAM_EXECUTABLE')
        if not path:
            raise unittest.SkipTest('requires the installed HIA worker stream executable')
        cls.executable = Path(path).read_bytes()
        cls.catalog = 'c' * 64
        cls.request = {'schema': 'hia-agent-worker-request-v1', 'tool': 'hia_describe',
                       'arguments': {'section': 'manifest'}, 'profile_sha256': 'b' * 64,
                       'catalog_sha256': cls.catalog}
        cls.request['request_sha256'] = hashlib.sha256(wire(cls.request)).hexdigest()

    def admit(self, raw):
        with tempfile.TemporaryFile() as stream, patch(
                'hepta.hia_native_helpers.pinned_worker_admission_executable',
                return_value=self.executable):
            stream.write(raw)
            stream.seek(0)
            result = NativeWorkerRequest.admit_stdin_for_terminal(stream, self.catalog)
            self.assertEqual(stream.tell(), len(raw))
            return result

    def test_exact_bytes_and_one_terminal(self):
        raw = b' ' + wire(self.request) + b'\r\n'
        request, terminal = self.admit(raw)
        self.assertEqual(request, self.request)
        pins = {'backend_sha256': 'd' * 64, 'worker_sha256': 'e' * 64}
        body = wire({'contract_version': VERSION, 'request_id': 'r-stream',
                     'status': 'completed', 'result': {}})
        report = terminal(pins, body)
        self.assertIn(self.request['request_sha256'].encode(), report)
        with self.assertRaisesRegex(ValueError, 'terminal report was not admitted'):
            terminal(pins, body)
        status, arena = _standalone_admit(self.executable, raw, self.catalog,
                                          sys.get_int_max_str_digits())
        self.assertGreater(status, 0)
        self.assertGreaterEqual(len(arena), 64)

    def test_exact_limit_and_refusals(self):
        raw = wire(self.request)
        self.assertEqual(self.admit(raw.ljust(MAX_BYTES, b' '))[0], self.request)
        with self.assertRaisesRegex(ValueError, 'bytes within 8 MiB'):
            self.admit(raw.ljust(MAX_BYTES + 1, b' '))
        with self.assertRaisesRegex(ValueError, 'invalid JSON syntax'):
            self.admit(b'')
        wrong = {**self.request, 'request_sha256': '0' * 64}
        with self.assertRaises(NativeRequestRejected) as caught:
            self.admit(wire(wrong))
        self.assertEqual(caught.exception.request, wrong)

    def test_source_descriptor_cannot_be_standard_or_out_of_range(self):
        header = ADMISSION_FRAME.pack(ADMISSION_INPUT_MAGIC, 0, 0, self.catalog.encode())
        for argument in ('', '0', '1', '2', '-1', 'a', '2147483648'):
            with self.subTest(argument=argument), sealed_reference_bytes(header) as metadata:
                result = subprocess.run([os.environ['HEPTA_HIA_WORKER_STREAM_EXECUTABLE'], argument],
                                        stdin=metadata, capture_output=True, timeout=5)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (64, b'', b''))
