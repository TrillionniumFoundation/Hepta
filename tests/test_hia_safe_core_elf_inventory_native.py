"""Independent Safe Core ELF inventory checks against the retained reader."""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_safe_core_elf import _ELF, SafeCoreELFRejected
from hepta.hia_safe_core_elf_inventory_native import SELECTOR, SOURCE, installed_safe_core_elf_inventory


class SafeCoreElfInventorySourceTests(unittest.TestCase):
    def test_checked_in_native_source_matches_the_independent_reader(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_safe_core_elf_inventory import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))


class SafeCoreElfInventoryNativeTests(unittest.TestCase):
    def setUp(self):
        selected = os.environ.get(SELECTOR)
        if not selected:
            self.skipTest('requires a bound HIA Safe Core ELF inventory')
        self.native = installed_safe_core_elf_inventory(selected)
        from hepta.hia_program import verify_program
        from hepta.hia_program_native import compile_program_machine, emit_program_machine
        from tests.test_hia_program import arithmetic

        self.core = verify_program(arithmetic('int.mul.wrap', 'u32'))
        image = emit_program_machine(self.core)
        with tempfile.TemporaryDirectory(prefix='hia-safe-core-elf-') as root:
            final = Path(root) / 'candidate.so'
            compile_program_machine(image, program=self.core, output=final, linker='ld')
            self.object_bytes, self.final_bytes = image.object_bytes, final.read_bytes()

    def test_ordinary_elf_inventory_and_diagnostics_match(self):
        def old(data, kind):
            elf = _ELF.__new__(_ELF)
            elf._reference_inventory(data, kind)
            return elf.sections, elf.segments

        def capture(reader, data, kind):
            try:
                return reader(data, kind)
            except SafeCoreELFRejected as exc:
                return str(exc)

        rng = random.Random(2997)
        for kind, original in ((1, self.object_bytes), (3, self.final_bytes)):
            phoff, shoff = struct.unpack_from('<2Q', original, 32)
            phnum, shnum = struct.unpack_from('<H2xH', original, 56)
            offsets = [*range(64), *range(shoff, shoff + 64 * shnum),
                       *range(phoff, phoff + 56 * phnum)]
            samples = [original, original[:-1], original[:64], b'']
            for at in offsets:
                for byte in (0, 1, 0x55, 0x80, 0xff):
                    samples.append(original[:at] + bytes((byte,)) + original[at + 1:])
            for _ in range(256):
                at = rng.randrange(len(original))
                samples.append(original[:at] + rng.randbytes(1) + original[at + 1:])
            for index, sample in enumerate(samples):
                self.assertEqual(capture(self.native.inventory, sample, kind), capture(old, sample, kind),
                                 (kind, index))

    def test_actual_consumer_uses_and_pins_native_inventory(self):
        from hepta.hia_safe_core import validate_safe_core_artifact

        with patch.object(_ELF, '_reference_inventory',
                          side_effect=AssertionError('host ELF inventory entered the checker')):
            result = validate_safe_core_artifact(self.core, self.object_bytes, self.final_bytes)
        self.assertTrue(result['ok'], result)
        closure = result['source_identity']
        self.assertEqual(closure['native_elf_inventory_image_sha256'], self.native.image_sha256)
        self.assertEqual(closure['native_elf_inventory_source_sha256'], sha256(SOURCE.read_bytes()).hexdigest())
        self.assertFalse(result['checker']['producer_reemission_used'])


if __name__ == '__main__':
    unittest.main()
