"""Differential controls for the independent Safe Core x86 decoder."""
from __future__ import annotations

import itertools
import os
import random
import unittest
from unittest.mock import patch

from hepta.hia_safe_core_x64 import SafeCoreMachineRejected, _reference_decode
from hepta.hia_safe_core_x64_decode_native import SELECTOR, SOURCE, installed_safe_core_x64_decode


class SafeCoreX64DecodeSourceTests(unittest.TestCase):
    def test_native_decoder_source_matches_independent_rules(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_safe_core_x64_decode import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))


class SafeCoreX64DecodeNativeTests(unittest.TestCase):
    def setUp(self):
        selected = os.environ.get(SELECTOR)
        if not selected:
            self.skipTest('requires a bound HIA Safe Core x86 decoder')
        self.native = installed_safe_core_x64_decode(selected)

    def test_all_byte_pairs_and_complete_instruction_controls(self):
        def outcome(decode, raw):
            try:
                return None, decode(raw)
            except SafeCoreMachineRejected as exc:
                return str(exc), None

        corpus = bytes.fromhex(
            '4157 415f 48b8ffffffffffffffff b834120000 c9 c3 90 '
            'e8f0ffffff e900000000 90 0f8400000000 90 400f95c0 4d0f45c1 480fafc3 '
            '480fb68424f0ffffff 0f0b 40888424f0ffffff 4889d1 48898c24f0ffffff '
            '488b8c24f0ffffff 488d8c24f0ffffff 4801c1 4829c1 4821c1 4809c1 4831c1 4839c1 4885c1 '
            '4881c0f0ffffff 4883e8ff 48c1e03f 48c1e800 48f7d0'
        )
        rng = random.Random(2996)
        samples = itertools.chain(
            (b'', b'\x90' * 8192, b'\x90' * 8193, b'\x90' * 65537, corpus),
            (bytes((opcode,)) for opcode in range(256)),
            map(bytes, itertools.product(range(256), repeat=2)),
            (corpus[:i] + bytes((value,)) + corpus[i + 1:]
             for i in range(len(corpus)) for value in (0, 0x40, 0x48, 0x90, 0xff)),
            (rng.randbytes(rng.randrange(1, 96)) for _ in range(4096)),
        )
        for index, raw in enumerate(samples):
            self.assertEqual(outcome(self.native.decode, raw), outcome(_reference_decode, raw),
                             (index, raw[:32].hex(), len(raw)))

    def test_actual_consumer_proves_from_installed_decoder_without_host_decode(self):
        from hashlib import sha256
        from pathlib import Path
        import tempfile

        from hepta.hia_program import verify_program
        from hepta.hia_program_native import compile_program_machine, emit_program_machine
        from hepta.hia_safe_core import validate_safe_core_artifact
        from tests.test_hia_program import arithmetic

        core = verify_program(arithmetic('int.mul.wrap', 'u32'))
        image = emit_program_machine(core)
        with tempfile.TemporaryDirectory(prefix='hia-safe-core-x64-') as root:
            final = Path(root) / 'candidate.so'
            compile_program_machine(image, program=core, output=final, linker='ld')
            with patch('hepta.hia_safe_core_x64._reference_decode',
                       side_effect=AssertionError('host decoder entered the Safe Core checker')):
                proof = validate_safe_core_artifact(core, image.object_bytes, final.read_bytes())
        self.assertTrue(proof['ok'], proof)
        self.assertEqual(proof['source_identity']['native_x64_decoder_image_sha256'], self.native.image_sha256)
        self.assertEqual(proof['source_identity']['native_x64_decoder_source_sha256'],
                         sha256(SOURCE.read_bytes()).hexdigest())
        self.assertFalse(proof['checker']['producer_reemission_used'])


if __name__ == '__main__':
    unittest.main()
