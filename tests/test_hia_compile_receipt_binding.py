"""Actual byte ABI and explicitly substituted compile-receipt controls.

The retained compiler is an explicit test input, not a new cold qualification.
Its path and SHA must both be supplied. Hand-written machine emitters and
transport substitutions are labeled separately from the real HIA compilation.
"""
from __future__ import annotations

import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_selfhost as shared


ROOT = Path(__file__).resolve().parents[1]
COMPILER = 'HEPTA_HIA_COMPILE_RECEIPT_COMPILER'
COMPILER_SHA256 = 'HEPTA_HIA_COMPILE_RECEIPT_COMPILER_SHA256'
OBSERVATIONS = 'HEPTA_HIA_COMPILE_RECEIPT_OBSERVATIONS'
PAYLOAD = bytes.fromhex('b82a000000c39090')  # independent function: return 42


def digest(raw):
    return sha256(raw).hexdigest()


def machine_emitter(status=0):
    # Store a known eight-byte image, then return status:u32/length:u32.
    return (b'\x48\xb8' + PAYLOAD + b'\x48\x89\x02\x48\xb8'
            + struct.pack('<Q', (status << 32) | len(PAYLOAD)) + b'\xc3')


@unittest.skipUnless(sys.platform == 'linux' and platform.machine() == 'x86_64',
                     'actual compile byte-ABI controls require Linux x86-64')
class CompileReceiptNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected, expected = os.environ.get(COMPILER), os.environ.get(COMPILER_SHA256)
        if not selected or not expected or re.fullmatch('[0-9a-f]{64}', expected) is None:
            raise AssertionError('supply an explicit retained compiler path and exact SHA256 for these native controls')
        cls.compiler = Path(selected).resolve(strict=True)
        cls.compiler_bytes = cls.compiler.read_bytes()
        if digest(cls.compiler_bytes) != expected:
            raise AssertionError('retained compile-receipt test compiler bytes differ')
        root = os.environ.get(OBSERVATIONS)
        if root:
            cls.directory = Path(root) / cls.__name__
            cls.directory.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-compile-receipt-')
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.directory = Path(cls.temporary.name)
        # This fixture deliberately exercises the original disposable child.
        # Its seed, linked and flat return conventions are separate controls.
        original_child = patch.object(shared, 'NATIVE_OBSERVER', None)
        original_child.start()
        cls.addClassCleanup(original_child.stop)
        cls.source = b'independent byte-ABI emitter input; not HIA source'
        cls.fixture = cls.directory / 'independent-emitter.bin'
        cls.fixture.write_bytes(machine_emitter())
        cls.base_receipt, cls.base_output = shared.invoke(cls.directory, 'recorded-positive',
                                                        cls.fixture, cls.source)
        if cls.base_receipt.get('abi_status') != 0 or cls.base_output[:8] != PAYLOAD:
            raise AssertionError('independent actual byte-ABI fixture did not execute')
        cls.control_observations = []
        cls.tool_observations = []

    @classmethod
    def tearDownClass(cls):
        unchanged = cls.compiler.read_bytes() == cls.compiler_bytes
        report = {'schema': 'hepta.hia.compile-receipt-test-observations.v1',
            'compiler_path': str(cls.compiler), 'compiler_sha256': digest(cls.compiler_bytes),
            'compiler_unchanged': unchanged, 'compiler_cold_qualification_performed': False,
            'controlled_transport_observations': cls.control_observations,
            'assembler_linker_observations': cls.tool_observations,
            'python': sys.version, 'public_return_schema_changed': False}
        (cls.directory / 'observations.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        if not unchanged:
            raise AssertionError('retained compiler changed during native receipt controls')

    def test_actual_flat_success_preserves_existing_receipt_fields_and_bytes(self):
        recorded = []
        original = shared.invoke

        def observe(*args, **kwargs):
            result, output = original(*args, **kwargs)
            recorded.append(copy.deepcopy(result))
            return result, output

        with patch.object(shared, 'invoke', side_effect=observe):
            image, result = shared.compile_stage(self.directory, 'actual-flat-success',
                                                 self.fixture, self.source)
        self.assertEqual(image.read_bytes(), PAYLOAD)
        self.assertEqual(result['produced_bytes'], len(PAYLOAD))
        self.assertEqual(result['produced_sha256'], digest(PAYLOAD))
        previous = {key: value for key, value in result.items()
                    if key not in {'produced_image', 'produced_bytes', 'produced_sha256'}}
        self.assertEqual(json.dumps(previous, sort_keys=True), json.dumps(recorded[0], sort_keys=True))
        self.assertEqual(json.loads((self.directory / 'actual-flat-success.receipt.json').read_bytes()), result)
        execution, output = shared.invoke(self.directory, 'actual-flat-produced-run', image, b'',
                                          capacity=1, workspace_size=1)
        self.assertEqual(execution['abi_status'], 0)
        self.assertEqual(execution['core_u32'], 42)
        self.assertEqual(output, b'\xa5')

    def test_actual_nonzero_status_with_correct_output_cannot_publish_an_image(self):
        failed = self.directory / 'independent-emitter-status-one.bin'
        failed.write_bytes(machine_emitter(status=1))
        with self.assertRaises(AssertionError):
            shared.compile_stage(self.directory, 'actual-status-one', failed, self.source)
        receipt = json.loads((self.directory / 'actual-status-one.receipt.json').read_bytes())
        self.assertEqual(receipt['abi_status'], 1)
        self.assertEqual(receipt['result_u64'], (1 << 32) | len(PAYLOAD))
        self.assertEqual(receipt['core_u32'], len(PAYLOAD))
        self.assertEqual((self.directory / 'actual-status-one.output.bin').read_bytes()[:8], PAYLOAD)
        self.assertFalse((self.directory / 'actual-status-one.image.bin').exists())

    def test_original_seven_malformed_transport_cases_refuse_before_publication(self):
        # These values are substituted into a receipt obtained from the real
        # independent fixture. They are not claimed as real compiler returns.
        changes = (
            ('abi-status-false', {'abi_status': False}),
            ('abi-status-float-zero', {'abi_status': 0.0}),
            ('source-unchanged-integer', {'source_unchanged': 1}),
            ('forbidden-modules-false', {'forbidden_compiler_modules_loaded': False}),
            ('core-size-bool', {'core_u32': True}),
            ('result-mismatch', {'result_u64': 7}),
            ('wrong-return-encoding', {'return_encoding': 'packed-ABI-status-and-u32'}),
        )
        for label, changed in changes:
            with self.subTest(case=label):
                result = {**copy.deepcopy(self.base_receipt), **changed}
                with patch.object(shared, 'invoke', return_value=(result, self.base_output)) as invocation:
                    with self.assertRaises(AssertionError):
                        shared.compile_stage(self.directory, label, self.fixture, self.source)
                invocation.assert_called_once()
                self.assertFalse((self.directory / (label + '.image.bin')).exists())
                self.assertFalse((self.directory / (label + '.receipt.json')).exists())
                self.control_observations.append({'case': label, 'rejected': True,
                    'scope': 'controlled transport substitution, not native compiler execution',
                    'receipt': result})

    def test_consumed_identities_complete_output_and_buffer_contract_are_bound(self):
        changes = (
            ('image-hash', {'image_sha256': 'a' * 64}),
            ('artifact-hash', {'artifact_sha256': 'b' * 64}),
            ('source-hash', {'source_sha256': 'c' * 64}),
            ('input-hash', {'input_sha256': 'd' * 64}),
            ('input-size-bool', {'input_bytes': True}),
            ('output-hash', {'output_sha256': 'e' * 64}),
            ('result-bool', {'result_u64': True}),
            ('wrong-format', {'format': 'seed-shared'}),
            ('output-capacity', {'limits': {**self.base_receipt['limits'], 'output_capacity': 8}}),
            ('workspace-capacity', {'limits': {**self.base_receipt['limits'], 'workspace_bytes': 0}}),
        )
        for label, changed in changes:
            with self.subTest(case=label):
                result = {**copy.deepcopy(self.base_receipt), **changed}
                with patch.object(shared, 'invoke', return_value=(result, self.base_output)):
                    with self.assertRaises(AssertionError):
                        shared.compile_stage(self.directory, label, self.fixture, self.source)
                self.assertFalse((self.directory / (label + '.image.bin')).exists())
                self.control_observations.append({'case': label, 'rejected': True,
                    'scope': 'controlled transport substitution, not native compiler execution',
                    'receipt': result})
        shortened = self.base_output[:8]
        result = {**copy.deepcopy(self.base_receipt), 'output_sha256': digest(shortened)}
        with patch.object(shared, 'invoke', return_value=(result, shortened)):
            with self.assertRaises(AssertionError):
                shared.compile_stage(self.directory, 'truncated-full-buffer', self.fixture, self.source)
        self.assertFalse((self.directory / 'truncated-full-buffer.image.bin').exists())

    def test_seed_and_linked_return_conventions_remain_accepted(self):
        source = self.directory / 'independent-emitter.S'
        source.write_text('.text\n.globl f0\n.type f0,@function\nf0:\n.byte '
            + ','.join(str(byte) for byte in machine_emitter())
            + '\n.size f0,.-f0\n.section .note.GNU-stack,"",@progbits\n')
        obj, library = self.directory / 'independent-emitter.o', self.directory / 'independent-emitter.so'
        assembler, linker = shutil.which('as'), shutil.which('ld')
        self.assertIsNotNone(assembler)
        self.assertIsNotNone(linker)
        for command in ([assembler, '--64', str(source), '-o', str(obj)],
                        [linker, '-shared', '-z', 'defs', '-z', 'noexecstack', '--build-id=none', str(obj), '-o', str(library)]):
            before = Path(command[0]).read_bytes()
            completed = subprocess.run(command, capture_output=True, text=True, timeout=20)
            self.tool_observations.append({'command': command, 'tool_sha256': digest(before),
                'returncode': completed.returncode, 'stdout': completed.stdout, 'stderr': completed.stderr,
                'tool_unchanged': Path(command[0]).read_bytes() == before})
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(Path(command[0]).read_bytes(), before)
        for image_format, encoding in [('seed-shared', 'packed-ABI-status-and-u32'),
                                       ('linked-selfhost', 'zero-extended-u32')]:
            with self.subTest(format=image_format):
                image, result = shared.compile_stage(self.directory, 'actual-' + image_format,
                    library, self.source, image_format=image_format)
                self.assertEqual(result['return_encoding'], encoding)
                self.assertEqual(result['result_u64'], len(PAYLOAD))
                self.assertEqual(image.read_bytes(), PAYLOAD)

    def test_real_retained_hia_compilation_and_generated_behavior(self):
        source = (ROOT / 'examples/hia_bootstrap/bytesum.hepta').read_bytes()
        image, result = shared.compile_stage(self.directory, 'actual-hia-bytesum', self.compiler, source)
        self.assertEqual(result['image_sha256'], digest(self.compiler_bytes))
        self.assertEqual(result['source_sha256'], digest(source))
        self.assertEqual(result['produced_sha256'], digest(image.read_bytes()))
        for index, data in enumerate((b'', b'receipt source binding', bytes(range(256)) * 4)):
            expected = 5381
            for byte in data:
                expected = ((expected * 33) ^ byte) & 0xffffffff
            execution, output = shared.invoke(self.directory, 'actual-hia-run-' + str(index),
                                              image, data, capacity=1, workspace_size=1)
            self.assertEqual(execution['abi_status'], 0)
            self.assertEqual(execution['core_u32'], expected)
            self.assertEqual(output, bytes([expected & 255]))
            self.assertIs(execution['source_unchanged'], True)
        self.assertEqual((ROOT / 'examples/hia_bootstrap/bytesum.hepta').read_bytes(), source)


if __name__ == '__main__':
    unittest.main()
