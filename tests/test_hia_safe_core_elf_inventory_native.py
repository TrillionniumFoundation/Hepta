"""Independent Safe Core ELF inventory checks against the retained reader."""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

from hepta import hia_safe_core_elf as elf_reader
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

    def test_native_symbols_names_and_load_mappings_match_owned_elf(self):
        for kind, data in ((1, self.object_bytes), (3, self.final_bytes)):
            reference = _ELF.__new__(_ELF)
            reference._reference_inventory(data, kind)
            selected = _ELF(data, kind)
            for name in ('.symtab', '.dynsym') if kind == 3 else ('.symtab',):
                self.assertEqual(selected.symbols(name), reference.symbols(name))
            for section in reference.sections:
                if kind == 3 and section['flags'] & 2 and section['size']:
                    permissions = 6 if section['flags'] & 1 else 5 if section['flags'] & 4 else 4
                    self.assertEqual(selected.load_binding(section, permissions),
                                     reference.load_binding(section, permissions))
            text = reference.section('.text')
            cases = ((text, 4), (dict(text, addr=(1 << 64) - 1), 5),
                     (dict(text, offset=text['offset'] + 1), 5))
            for section, permissions in cases:
                with self.assertRaises(SafeCoreELFRejected) as expected:
                    reference.load_binding(section, permissions)
                with self.assertRaises(SafeCoreELFRejected) as actual:
                    selected.load_binding(section, permissions)
                self.assertEqual(str(actual.exception), str(expected.exception))

    def test_actual_consumer_uses_and_pins_native_inventory(self):
        from hepta.hia_safe_core import validate_safe_core_artifact

        boundaries = ('_reference_inventory', '_reference_symbols', '_reference_string', '_reference_load_binding')
        blocked = {name: Mock(side_effect=AssertionError('host ELF boundary entered: ' + name))
                   for name in boundaries}
        loader_boundaries = ('_reference_dynamic_tags', '_reference_sysv_lookup', '_reference_gnu_lookup')
        loader_blocked = {name: Mock(side_effect=AssertionError('host loader check entered: ' + name))
                          for name in loader_boundaries}
        with patch.multiple(_ELF, **blocked), patch.multiple(elf_reader, **loader_blocked):
            result = validate_safe_core_artifact(self.core, self.object_bytes, self.final_bytes)
        self.assertTrue(result['ok'], result)
        closure = result['source_identity']
        self.assertEqual(closure['native_elf_inventory_image_sha256'], self.native.image_sha256)
        self.assertEqual(closure['native_elf_inventory_source_sha256'], sha256(SOURCE.read_bytes()).hexdigest())
        self.assertFalse(result['checker']['producer_reemission_used'])

    def test_dynamic_and_lookup_bytes_match_retained_checker(self):
        def result(check, *args, **kwargs):
            try:
                return check(*args, **kwargs)
            except SafeCoreELFRejected as exc:
                return str(exc)

        final = _ELF(self.final_bytes, 3)
        dynamic, got, rela = (final.section(name) for name in ('.dynamic', '.got', '.rela.plt'))
        tags = elf_reader._reference_dynamic_tags(final, dynamic, got, rela)
        self.assertEqual(self.native.dynamic_tags(self.final_bytes, dynamic, got, rela), tags)
        dynsymbols = final.symbols('.dynsym')
        export = dynsymbols[2]['name']

        for name, key, gnu in (('.dynamic', None, False), ('.hash', 4, False),
                               ('.gnu.hash', 0x6ffffef5, True)):
            table = final.section(name)
            for at, original in enumerate(table['data']):
                for value in (0, 1, 128, 255):
                    if value == original:
                        continue
                    changed = table['data'][:at] + bytes((value,)) + table['data'][at + 1:]
                    offset = table['offset']
                    data = self.final_bytes[:offset] + changed + self.final_bytes[offset + len(changed):]
                    section = dict(table, data=changed)
                    if key is None:
                        expected = result(elf_reader._reference_dynamic_tags, final, section, got, rela)
                        actual = result(self.native.dynamic_tags, data, section, got, rela)
                    else:
                        check, symbol_arg = ((elf_reader._reference_gnu_lookup, export) if gnu else
                                             (elf_reader._reference_sysv_lookup, dynsymbols))
                        expected = result(check, section, tags[key], symbol_arg)
                        actual = result(self.native.verify_hash, data, section, tags[key], export, gnu=gnu)
                    self.assertEqual(actual, expected, (name, at, value))


if __name__ == '__main__':
    unittest.main()
