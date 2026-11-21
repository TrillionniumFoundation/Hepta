"""Independent Safe Core ELF inventory checks against the retained reader."""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile
from types import SimpleNamespace
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

    def test_owned_shared_layout_checks_loader_authority_before_publishing_symbols(self):
        from hepta import elf_shared_abi
        from hepta import hia_safe_core_elf_inventory_native

        def observed(reader, raw):
            try:
                return reader(raw)
            except elf_shared_abi.ELFSharedABIRejected as error:
                return str(error)

        final = self.final_bytes
        phoff, shoff = struct.unpack_from('<2Q', final, 32)
        phnum, shnum = struct.unpack_from('<H2xH', final, 56)
        dynamic = next(phoff + i * 56 for i in range(phnum)
                       if struct.unpack_from('<I', final, phoff + i * 56)[0] == 2)
        dynoff = struct.unpack_from('<Q', final, dynamic + 8)[0]
        dynsize = struct.unpack_from('<Q', final, dynamic + 32)[0]
        offsets = (*range(64), *range(phoff, phoff + 56 * phnum),
                   *range(shoff, shoff + 64 * shnum), *range(dynoff, dynoff + dynsize))
        baseline = elf_shared_abi._reference_owned_shared_layout
        self.assertEqual(self.native.owned_shared_layout(final), baseline(final))
        for at in offsets:
            for value in (0, 1, 127, 255):
                if value == final[at]:
                    continue
                damaged = final[:at] + bytes((value,)) + final[at + 1:]
                self.assertEqual(observed(self.native.owned_shared_layout, damaged),
                                 observed(baseline, damaged), (at, value))
        with patch.object(hia_safe_core_elf_inventory_native, 'selected_safe_core_elf_inventory', return_value=None):
            expected = elf_shared_abi.inspect_owned_shared_elf(final, ('calculate',))
        with patch.object(elf_shared_abi, '_reference_owned_shared_symbols',
                          side_effect=AssertionError('host publication reader entered')):
            self.assertEqual(elf_shared_abi.inspect_owned_shared_elf(final, ('calculate',)), expected)

    def test_owned_shared_symbol_policy_preserves_ordered_diagnostics_and_prefix_names(self):
        from hepta import elf_shared_abi

        exports = ('Aa', 'Aaa', 'Aab', 'Aac', '_x', 'long_' + 'x' * 507, 'run', 'z9')
        source = '\n'.join(f'unsigned {name}(void) {{ return {index}; }}'
                           for index, name in enumerate(exports) if name != 'run')
        source += '\nextern void *malloc(unsigned long); void *run(void) { return malloc(32); }\n'
        with tempfile.TemporaryDirectory(prefix='hia-owned-symbol-') as root:
            output = Path(root) / 'candidate.so'
            subprocess.run(['cc', '-x', 'c', '-fPIC', '-shared', '-Wl,-z,noexecstack', '-o', output, '-'],
                           input=source.encode('ascii'), check=True)
            raw = output.read_bytes()
        expected = elf_shared_abi._reference_owned_shared_symbols(raw)
        self.assertEqual(expected[0], set(exports))
        self.assertIn('malloc', expected[1])
        self.assertEqual(self.native.owned_shared_symbols(raw), expected)
        self.assertEqual(self.native.owned_shared_symbols(raw, exports), (*expected, True))
        for changed in (exports[:-1], exports[:3] + ('Aad',) + exports[4:], tuple(reversed(exports)),
                        exports[:5] + (exports[5] + 'x',) + exports[6:],
                        tuple(sorted((*exports[:-1], 'malloc')))):
            with self.subTest(expected_names=changed):
                self.assertEqual(self.native.owned_shared_symbols(raw, changed), (*expected, False))

        def observed(reader, data):
            try:
                return reader(data)
            except elf_shared_abi.ELFSharedABIRejected as error:
                return str(error)

        _, _, _, symoff, symsize, stroff, strsize = self.native.owned_shared_layout(raw)
        for at in (*range(symoff, symoff + symsize), *range(stroff, stroff + strsize)):
            for replacement in (0, 1, 127, 255):
                if replacement != raw[at]:
                    changed = raw[:at] + bytes((replacement,)) + raw[at + 1:]
                    self.assertEqual(observed(self.native.owned_shared_symbols, changed),
                                     observed(elf_shared_abi._reference_owned_shared_symbols, changed), (at, replacement))
        with patch.object(elf_shared_abi, '_reference_owned_shared_symbols',
                          side_effect=AssertionError('host shared ABI reader entered')):
            report = elf_shared_abi.inspect_owned_shared_elf(raw, exports)
            self.assertEqual(report['dynamic_exports'], list(exports))
            self.assertEqual(report['unresolved_imports'], sorted(expected[1]))
            with self.assertRaisesRegex(elf_shared_abi.ELFSharedABIRejected, 'public ABI symbols differ from source'):
                elf_shared_abi.inspect_owned_shared_elf(raw, exports[:-1])

    def test_native_symbols_names_and_load_mappings_match_owned_elf(self):
        from hepta.hia_safe_core_elf_inventory_native import SECTION_AUTHORITIES

        for kind, data in ((1, self.object_bytes), (3, self.final_bytes)):
            reference = _ELF.__new__(_ELF)
            reference._reference_inventory(data, kind)
            selected = _ELF(data, kind)
            self.assertEqual(selected.authorities, {
                name: reference.by_name.get(name) for name in SECTION_AUTHORITIES
            })
            selected.by_name.update({name: {'unexpected': True} for name in SECTION_AUTHORITIES})
            for name in SECTION_AUTHORITIES:
                if name in reference.by_name:
                    self.assertEqual(selected.section(name), reference.section(name))
                else:
                    with self.assertRaisesRegex(SafeCoreELFRejected, 'missing section'):
                        selected.section(name)
            text = reference.section('.text')
            self.assertEqual(self.native.owned_functions(data, kind),
                             elf_reader._reference_functions(reference, text, '.symtab'))
            for name in ('.symtab', '.dynsym') if kind == 3 else ('.symtab',):
                rows = reference.symbols(name)
                self.assertEqual(selected.symbols(name), rows)
                self.assertEqual(elf_reader._functions(selected, text, name),
                                 elf_reader._reference_functions(reference, text, name))
                table = reference.section(name)
                function = next(index for index, row in enumerate(rows)
                                if row['info'] & 15 == 2 and row['shndx'] == text['index'])
                offset = table['offset'] + 24 * function
                corrupted = (data[:offset + 16] + bytes(8) + data[offset + 24:],
                             data[:offset + 8] + struct.pack('<Q', text['addr'] + text['size'])
                             + data[offset + 16:],
                             data[:table['offset']] + data[offset:offset + 24]
                             + data[table['offset'] + 24:])
                for mutation in corrupted:
                    historical = _ELF.__new__(_ELF)
                    historical._reference_inventory(mutation, kind)
                    with self.assertRaises(SafeCoreELFRejected) as old:
                        elf_reader._reference_functions(historical, text, name)
                    with self.assertRaises(SafeCoreELFRejected) as native:
                        elf_reader._functions(_ELF(mutation, kind), text, name)
                    self.assertEqual(str(native.exception), str(old.exception))
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
        loader_boundaries = ('_lookup_tables', '_reference_dynamic_tags',
                             '_reference_sysv_lookup', '_reference_gnu_lookup',
                             '_reference_plt_slot', '_reference_object_relocations',
                             '_reference_symbol_versions', '_reference_relro', '_reference_functions',
                             '_reference_function_link', '_reference_dynamic_symbols',
                             '_reference_loader_sections', '_reference_unwinding', '_reference_text_geometry',
                             '_reference_executable_layout',
                             '_reference_dynamic_relocations', '_reference_dynamic_order',
                             '_reference_object_inventory')
        loader_blocked = {name: Mock(side_effect=AssertionError('host loader check entered: ' + name))
                          for name in loader_boundaries}
        bridge_boundaries = ('verify_function_link', 'verify_executable_layout',
                             'verify_relro', 'verify_dynamic_relocations', 'verify_plt_slot',
                             'verify_dynamic_symbols', 'verify_loader_executable', 'verify_loader_lookup',
                             'object_relocations')
        bridge_blocked = {name: Mock(side_effect=AssertionError('host encoded ELF authority: ' + name))
                          for name in bridge_boundaries}
        with (
            patch.multiple(_ELF, **blocked),
            patch.multiple(elf_reader, **loader_blocked),
            patch.multiple(type(self.native), **bridge_blocked),
        ):
            result = validate_safe_core_artifact(self.core, self.object_bytes, self.final_bytes)
        self.assertTrue(result['ok'], result)
        closure = result['source_identity']
        self.assertEqual(closure['native_elf_inventory_image_sha256'], self.native.image_sha256)
        self.assertEqual(closure['native_elf_inventory_source_sha256'], sha256(SOURCE.read_bytes()).hexdigest())
        self.assertFalse(result['checker']['producer_reemission_used'])

    def test_native_cross_image_bindings_match_direct_and_wrapper_geometry(self):
        def observed(check, args):
            try:
                return check(*args)
            except SafeCoreELFRejected as error:
                return str(error)

        name, helper = 'entry_impl', '__hia_native_fn_0'
        address = 0x1020
        original = {
            name: dict(name=name, value=8, size=4, info=18, other=0),
            helper: dict(name=helper, value=0, size=8, info=2, other=0),
        }
        linked = {key: {**row, 'value': address + row['value']}
                  for key, row in reversed(tuple(original.items()))}
        cases = [
            (original, linked, name, 12, address),
            ({helper: original[helper]}, {helper: linked[helper]}, helper, 8, address),
            ({name: original[name]}, linked, name, 12, address),
            (original, linked, helper, 12, address),
            ({**original, helper: {**original[helper], 'size': 7}}, linked, name, 12, address),
            (original, {**linked, name: {**linked[name], 'value': address + 9}}, name, 12, address),
            (original, {**linked, helper: {**linked[helper], 'other': 1}}, name, 12, address),
        ]
        for args in cases:
            with self.subTest(source=args[0], target=args[1], export=args[2]):
                self.assertEqual(observed(self.native.verify_function_link, args),
                                 observed(elf_reader._reference_function_link, args))

        source = self.native.owned_function_receipt(self.object_bytes, 1)
        target = self.native.owned_function_receipt(self.final_bytes, 3)
        self.assertEqual(source[0], self.native.owned_functions(self.object_bytes, 1))
        self.assertEqual(target[0], self.native.owned_functions(self.final_bytes, 3))
        raw_object, raw_final = (_ELF(self.object_bytes, 1), _ELF(self.final_bytes, 3))
        export, = self.core.scalar_entrypoints
        self.assertIs(self.native.verify_owned_function_link(source, target, export),
                      elf_reader._reference_function_link(
                          source[0], target[0], export,
                          raw_object.section('.text')['size'], raw_final.section('.text')['addr'],
                      ))
        helper = target[0].get('__hia_native_fn_0')
        self.assertEqual(self.native.verify_owned_function_link(source, target, export, receipt=True),
                         (helper is None, source[0][export]['value'], target[0][export]['value'],
                          0 if helper is None else helper['value']))

    def test_dynamic_symbol_authority_matches_original_checks(self):
        original = _ELF.__new__(_ELF)
        original._reference_inventory(self.final_bytes, 3)
        text = original.section('.text')
        dynamic = original.section('.dynsym')
        strings = original.sections[dynamic['link']]
        rows = original.symbols('.dynsym')
        export = next(row for row in rows if row['shndx'] == text['index'])
        abort_index = next(index for index, row in enumerate(rows) if row['name'] == 'abort')
        export_index = rows.index(export)
        abort_row = dynamic['offset'] + 24 * abort_index
        export_row = dynamic['offset'] + 24 * export_index
        abort_name = strings['offset'] + struct.unpack_from('<I', self.final_bytes, abort_row)[0]

        def expected(data):
            elf = _ELF.__new__(_ELF)
            elf._reference_inventory(data, 3)
            symbols = elf_reader._reference_dynamic_symbols(elf, text, export)
            mask = sum(1 << index for index, row in enumerate(symbols) if row['name'] == 'abort')
            return symbols, mask

        def result(check, data):
            try:
                return check(data)
            except SafeCoreELFRejected as error:
                return str(error)

        samples = [self.final_bytes]
        for offset, value in ((abort_name, ord('x')), (abort_row, 0),
                              (export_row + 4, 2), (export_row + 5, 1),
                              (export_row + 6, 0), (export_row + 16, 0)):
            changed = bytearray(self.final_bytes)
            changed[offset] = value
            samples.append(bytes(changed))
        for data in samples:
            with self.subTest(digest=sha256(data).hexdigest()):
                actual = result(lambda raw: self.native.verify_dynamic_symbols(raw, dynamic['index'], text, export), data)
                self.assertEqual(actual, result(expected, data))

    def test_native_loader_layout_matches_original_order_and_named_rejections(self):
        def original(data):
            final = _ELF.__new__(_ELF)
            final._reference_inventory(data, 3)
            return final

        def observed(check, data):
            try:
                return check(data)
            except SafeCoreELFRejected as error:
                return str(error)

        final = original(self.final_bytes)
        phoff, shoff = struct.unpack_from('<2Q', self.final_bytes, 32)
        text, plt, got = (final.section(name) for name in ('.text', '.plt', '.got'))
        rela, dynsym, strtab = (final.section(name) for name in ('.rela.plt', '.dynsym', '.strtab'))

        def changed(section, field, replacement, variant='<Q'):
            data = bytearray(self.final_bytes)
            struct.pack_into(variant, data, shoff + 64 * section['index'] + field, replacement)
            return bytes(data)

        def reference_exec(data):
            elf = original(data)
            return elf_reader._reference_executable_layout(
                elf, elf.section('.text'), elf.section('.plt'), elf.section('.got'),
            )

        def reference_reloc(data):
            elf = original(data)
            return elf_reader._reference_dynamic_relocations(elf, elf.section('.rela.plt'), elf.section('.got'))

        def reference_executable(data):
            elf = original(data)
            text, plt, got, rela = (elf.section(name, kind) for name, kind in
                                    (('.text', 1), ('.plt', 1), ('.got', 1), ('.rela.plt', 4)))
            elf_reader._reference_executable_layout(elf, text, plt, got)
            elf_reader._reference_relro(elf, elf.load_binding(got, 6), got)
            elf_reader._reference_dynamic_relocations(elf, rela, got)
            elf_reader._reference_plt_slot(plt, got, rela, elf.symbols('.dynsym'))

        extra_exec = bytearray(self.final_bytes)
        for index, segment in enumerate(final.segments):
            if segment['type'] == 1 and segment['flags'] == 4:
                struct.pack_into('<I', extra_exec, phoff + index * 56 + 4, 5)
                break
        else:
            self.fail('original expected readable load missing from actual fixture')
        wrong_plt = bytearray(self.final_bytes)
        wrong_plt[plt['offset']] ^= 1
        abort_mask = sum(1 << index for index, row in enumerate(final.symbols('.dynsym'))
                         if row['name'] == 'abort')
        cases = (
            (lambda raw: elf_reader._reference_loader_sections(original(raw)),
             self.native.verify_loader_sections,
             (changed(dynsym, 8, dynsym['flags'] & ~2), changed(strtab, 8, 2),
              changed(dynsym, 24, dynsym['offset'] + 1))),
            (reference_exec, lambda raw: self.native.verify_executable_layout(raw, text, plt, got),
             (changed(plt, 8, 2), changed(strtab, 8, 4), changed(text, 32, text['size'] - 1), bytes(extra_exec))),
            (reference_reloc, lambda raw: self.native.verify_dynamic_relocations(raw, rela, dynsym, got),
             (changed(rela, 40, got['index'], '<I'), changed(strtab, 4, 4, '<I'), changed(rela, 56, 16))),
            (reference_executable, lambda raw: self.native.verify_loader_executable(raw, abort_mask),
             (changed(plt, 8, 2), bytes(extra_exec), changed(got, 24, got['offset'] + 1),
              changed(rela, 40, got['index'], '<I'), bytes(wrong_plt))),
        )
        for reference, native, supplied in cases:
            for data in (self.final_bytes, *supplied):
                with self.subTest(digest=sha256(data).hexdigest()):
                    expected = observed(reference, data)
                    self.assertEqual(observed(native, data), expected)
                    if data is not self.final_bytes:
                        self.assertIsInstance(expected, str)
                        self.assertTrue(expected.startswith('E_HIA_SAFE_CORE_ELF: '))

    def test_final_dynamic_order_and_object_inventory_match_original(self):
        def original(data, kind):
            elf = _ELF.__new__(_ELF)
            elf._reference_inventory(data, kind)
            return elf

        def observe(call):
            try:
                return call()
            except SafeCoreELFRejected as error:
                return str(error)

        final = original(self.final_bytes, 3)
        dynsym = final.section('.dynsym')
        export = final.symbols('.dynsym')[2]['name']
        changed = bytearray(self.final_bytes)
        changed[dynsym['offset'] + 24 + 4] = 2
        for image in (self.final_bytes, bytes(changed)):
            for name in (export, 'another_entry'):
                expected = observe(lambda: elf_reader._reference_dynamic_order(
                    original(image, 3).symbols('.dynsym'), name,
                ))
                self.assertEqual(observe(lambda: self.native.verify_dynamic_order(image, dynsym, name)), expected)

        obj = original(self.object_bytes, 1)
        rela, text, symbols = (obj.section(name) for name in ('.rela.text', '.text', '.symtab'))
        shoff = struct.unpack_from('<Q', self.object_bytes, 40)[0]
        changed = bytearray(self.object_bytes)
        struct.pack_into('<I', changed, shoff + 64 * rela['index'] + 44, symbols['index'])
        for image in (self.object_bytes, bytes(changed)):
            for direct in (False, True):
                elf = original(image, 1)
                expected = observe(lambda: elf_reader._reference_object_inventory(
                    elf, elf.section('.rela.text'), elf.section('.text'), direct,
                ))
                self.assertEqual(observe(lambda: self.native.verify_object_inventory(
                    image, rela, text, symbols, direct=direct,
                )), expected)

    def test_unwinding_and_exact_text_geometry_match_the_reference(self):
        obj, final = _ELF(self.object_bytes, 1), _ELF(self.final_bytes, 3)
        source, linked = obj.section('.text'), final.section('.text')
        frame = final.section('.eh_frame')

        def changed(data, section, fields, suffix=b''):
            shoff = struct.unpack_from('<Q', data, 40)[0]
            raw = bytearray(data)
            for field, value in fields.items():
                struct.pack_into('<Q', raw, shoff + section['index'] * 64 + field, value)
            return bytes(raw) + suffix

        self.native.verify_unwinding(self.final_bytes, frame)
        nonempty = changed(self.final_bytes, frame, {32: 1})
        with self.assertRaisesRegex(SafeCoreELFRejected, 'unreviewed nonempty unwinding metadata'):
            self.native.verify_unwinding(nonempty, frame)

        self.native.verify_text_geometry(self.object_bytes, source, linked, source['data'])
        cases = (
            (self.object_bytes, linked, source['data'][:-1]),
            (self.object_bytes, linked, bytes([source['data'][0] ^ 1]) + source['data'][1:]),
            (self.object_bytes, dict(linked, flags=2), source['data']),
            (changed(self.object_bytes, source, {16: 1}), linked, source['data']),
        )
        for data, target, supplied in cases:
            with self.assertRaisesRegex(SafeCoreELFRejected, 'source and final text shapes differ'):
                self.native.verify_text_geometry(data, source, target, supplied)
        for size in (65536, 65537):
            supplied = bytes([63]) * size
            data = changed(self.object_bytes, source, {24: len(self.object_bytes), 32: size}, supplied)
            target = dict(linked, size=size)
            if size == 65536:
                self.native.verify_text_geometry(data, source, target, supplied)
            else:
                with self.assertRaisesRegex(SafeCoreELFRejected, 'Safe Core text budget exceeded'):
                    self.native.verify_text_geometry(data, source, target, supplied)
                with self.assertRaisesRegex(SafeCoreELFRejected, 'source and final text shapes differ'):
                    self.native.verify_text_geometry(data, source, target, bytes(size))

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

        def reference_lookup(data, name):
            reference = _ELF.__new__(_ELF)
            reference._reference_inventory(data, 3)
            table, slots, relocations = (reference.section(section, kind) for section, kind in
                                         (('.dynamic', 6), ('.got', 1), ('.rela.plt', 4)))
            authority = elf_reader._reference_dynamic_tags(reference, table, slots, relocations)
            return elf_reader._lookup_tables(reference, authority, reference.symbols('.dynsym'), name)

        def reference_final(data, name):
            reference = _ELF.__new__(_ELF)
            reference._reference_inventory(data, 3)
            text, plt, got, rela = (reference.section(section_name, kind) for section_name, kind in
                                    (('.text', 1), ('.plt', 1), ('.got', 1), ('.rela.plt', 4)))
            functions = elf_reader._reference_functions(reference, text, '.symtab')
            elf_reader.require(name in functions, 'loader export identity differs')
            symbols = elf_reader._reference_dynamic_symbols(reference, text, functions[name])
            elf_reader._reference_executable_layout(reference, text, plt, got)
            elf_reader._reference_relro(reference, reference.load_binding(got, 6), got)
            elf_reader._reference_dynamic_relocations(reference, rela, got)
            elf_reader._reference_plt_slot(plt, got, rela, symbols)
            reference.load_binding(reference.section('.dynamic', 6), 6)
            return reference_lookup(data, name)

        self.native.verify_loader_lookup(self.final_bytes, export)
        self.native.verify_final_loader(self.final_bytes, export)
        text, plt = (final.section(name, 1) for name in ('.text', '.plt'))
        self.assertEqual(self.native.verify_final_loader(self.final_bytes, export, receipt=True),
                         (text['offset'], text['addr'], text['size'], plt['addr'] + 16))
        for name in (export + 'x', '', export[:-1], 'abort'):
            self.assertEqual(result(self.native.verify_loader_lookup, self.final_bytes, name),
                             result(reference_lookup, self.final_bytes, name))
            self.assertEqual(result(self.native.verify_final_loader, self.final_bytes, name),
                             result(reference_final, self.final_bytes, name))

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
                    self.assertEqual(result(self.native.verify_loader_lookup, data, export),
                                     result(reference_lookup, data, export), (name, at, value))
                    self.assertEqual(result(self.native.verify_final_loader, data, export),
                                     result(reference_final, data, export), (name, at, value))

        for name in ('.dynsym', '.dynstr', '.gnu.version', '.gnu.version_r'):
            section = final.section(name)
            for offset in range(section['offset'], section['offset'] + section['size']):
                changed = bytearray(self.final_bytes)
                changed[offset] ^= 1
                data = bytes(changed)
                self.assertEqual(result(self.native.verify_loader_lookup, data, export),
                                 result(reference_lookup, data, export), (name, offset))
                self.assertEqual(result(self.native.verify_final_loader, data, export),
                                 result(reference_final, data, export), (name, offset))

    def test_standalone_final_loader_receipt_uses_raw_elf_with_empty_path(self):
        selected = os.environ.get('HEPTA_HIA_SAFE_CORE_LOADER_EXECUTABLE')
        if not selected:
            self.skipTest('requires a matching cold-built hia-safe-core-loader executable')
        executable = Path(selected).resolve(strict=True)
        export, = self.core.scalar_entrypoints
        encoded = export.encode('ascii')
        header = struct.pack('<Q256s', len(encoded), encoded)
        good = header + self.final_bytes

        def execute(raw, *arguments):
            result = subprocess.run((executable, *arguments), input=raw, capture_output=True,
                                    env={'PATH': ''}, timeout=10)
            return result.returncode, result.stdout, result.stderr

        self.assertEqual(execute(good), (0, bytes(24), b''))
        self.assertEqual(execute(good, 'unexpected'), (64, b'', b''))
        wrong_name = struct.pack('<Q256s', len(encoded) + 1, encoded + b'x')
        oversized = struct.pack('<Q256s', 257, encoded)
        final = _ELF(self.final_bytes, 3)
        for name in ('.plt', '.hash', '.gnu.hash', '.gnu.version_r'):
            at = final.section(name)['offset']
            changed = bytearray(self.final_bytes)
            changed[at] ^= 1
            with self.subTest(section=name):
                self.assertEqual(execute(header + changed), (2, b'', b''))
        for invalid in (header[:-1], good[:-1], header + self.object_bytes,
                        wrong_name + self.final_bytes, oversized + self.final_bytes):
            self.assertEqual(execute(invalid), (2, b'', b''))

    def test_standalone_binder_binds_both_raw_images_and_exact_relocations(self):
        selected = os.environ.get('HEPTA_HIA_SAFE_CORE_BIND_EXECUTABLE')
        if not selected:
            self.skipTest('requires a matching cold-built hia-safe-core-bind executable')
        from tools.generate_hia_safe_core_binder import FRAME_MAGIC, REPLY_MAGIC

        executable = Path(selected).resolve(strict=True)
        export, = self.core.scalar_entrypoints
        name = export.encode('ascii')
        header = struct.pack('<4Q256s', FRAME_MAGIC, len(self.object_bytes),
                             len(self.final_bytes), len(name), name)
        expected = elf_reader.bind_final_artifact(self.object_bytes, self.final_bytes, export, native_wire=True)
        linked = _ELF(self.final_bytes, 3)
        text, plt = linked.section('.text'), linked.section('.plt')
        row, = [rel for rel in expected['binding']['relocations'] if rel['symbol'] != 'abort']
        relocations = expected['_native_relocation_wire']
        coordinates = struct.pack('<10Q', REPLY_MAGIC, text['offset'], text['addr'], text['size'],
                                  expected['entry'], row['linked_target'], plt['addr'] + 16,
                                  0, len(relocations), 0)

        def execute(raw):
            result = subprocess.run((executable,), input=raw, capture_output=True,
                                    env={'PATH': ''}, timeout=10)
            return result.returncode, result.stdout, result.stderr

        good = header + self.object_bytes + self.final_bytes
        self.assertEqual(execute(good), (0, coordinates + expected['text'] + relocations, b''))
        obj = _ELF(self.object_bytes, 1)
        for at in (0, len(header) - 1, len(header) + obj.section('.rela.text')['offset'] + 16,
                   len(header) + len(self.object_bytes) + text['offset'],
                   len(header) + len(self.object_bytes) + plt['offset']):
            changed = bytearray(good)
            changed[at] ^= 1
            with self.subTest(offset=at):
                self.assertEqual(execute(changed), (2, b'', b''))
        self.assertEqual(execute(good[:-1]), (2, b'', b''))

    def test_native_relocations_match_real_link_and_retained_rejections(self):
        def result(check, *args):
            try:
                return check(*args)
            except SafeCoreELFRejected as exc:
                return str(exc)

        obj, final = _ELF(self.object_bytes, 1), _ELF(self.final_bytes, 3)
        plt, got, rela = (final.section(name) for name in ('.plt', '.got', '.rela.plt'))
        dynamic_symbols = final.symbols('.dynsym')
        abort_mask = sum(1 << i for i, row in enumerate(dynamic_symbols) if row['name'] == 'abort')
        self.native.verify_plt_slot(self.final_bytes, plt, got, rela, abort_mask)
        for table in (plt, rela):
            for index in range(table['size']):
                changed = bytearray(table['data'])
                changed[index] ^= 1
                at = table['offset']
                data = self.final_bytes[:at] + bytes(changed) + self.final_bytes[at + table['size']:]
                regions = [dict(section, data=bytes(changed)) if section is table else section
                           for section in (plt, got, rela)]
                self.assertEqual(result(self.native.verify_plt_slot, data, *regions, abort_mask),
                                 result(elf_reader._reference_plt_slot, *regions, dynamic_symbols),
                                 (table['name'], index))

        source, linked = obj.section('.text'), final.section('.text')
        relocations = obj.section('.rela.text')
        functions = elf_reader._functions(final, linked, '.symtab')
        helper = functions['__hia_native_fn_0']['value']
        self.assertEqual(self.native.object_relocations(self.object_bytes, relocations, source, linked, plt, helper),
                         elf_reader._reference_object_relocations(obj, relocations, source['data'],
                                                                 linked, plt, functions))
        for table in (relocations, linked):
            for index in range(table['size']):
                changed = bytearray(table['data'])
                changed[index] ^= 1
                at = table['offset']
                changed_table = dict(table, data=bytes(changed))
                if table is relocations:
                    data = self.object_bytes[:at] + bytes(changed) + self.object_bytes[at + table['size']:]
                    section, link = changed_table, linked
                else:
                    data, section, link = self.object_bytes, relocations, changed_table
                self.assertEqual(result(self.native.object_relocations, data, section, source, link, plt, helper),
                                 result(elf_reader._reference_object_relocations, obj, section,
                                        source['data'], link, plt, functions),
                                 (table['name'], index))

    def test_direct_kernel_final_binding_uses_native_relocation_owner(self):
        from hepta.hia_verified_scalar import build_verified_scalar, emit_verified_scalar
        from tests.test_hia_program import arithmetic

        document = arithmetic('int.add.checked', 'u64')
        image = emit_verified_scalar(document)
        with tempfile.TemporaryDirectory(prefix='hia-direct-kernel-elf-') as temporary:
            output = Path(temporary) / 'direct.so'
            with patch.object(elf_reader, '_reference_object_relocations',
                              side_effect=AssertionError('host relocation owner entered')):
                report = build_verified_scalar(document, output, image=image)
                linked = output.read_bytes()
                binding = elf_reader.bind_final_artifact(image.object_bytes, linked, image.export)
        self.assertTrue(report['validation']['complete'])
        self.assertEqual(binding['binding']['function_shape'], 'direct_entry')
        self.assertEqual([row['symbol'] for row in binding['binding']['relocations']], ['abort'])
        with patch.dict(os.environ, {SELECTOR: ''}):
            del os.environ[SELECTOR]
            reference = elf_reader.bind_final_artifact(image.object_bytes, linked, image.export)
        self.assertEqual(binding, reference)

    def test_native_version_and_relro_rules_match_reference(self):
        final = _ELF(self.final_bytes, 3)
        dynamic, got, rela = (final.section(name) for name in ('.dynamic', '.got', '.rela.plt'))
        tags = elf_reader._reference_dynamic_tags(final, dynamic, got, rela)
        writable = final.load_binding(got, 6)
        versions, needed, strings = (final.section(name) for name in
                                     ('.gnu.version', '.gnu.version_r', '.dynstr'))

        def result(check, *args):
            try:
                return check(*args)
            except SafeCoreELFRejected as exc:
                return str(exc)

        def native_versions(data, records, requirements, names, loader_tags):
            self.native.verify_version_tables(data, records, requirements, loader_tags)
            self.native.verify_version_names(data, requirements, names)

        def reference_versions(data, records, requirements, names, loader_tags):
            reference = _ELF.__new__(_ELF)
            reference._reference_inventory(data, 3)
            elf_reader._reference_symbol_versions(reference, loader_tags, records, requirements)

        native_versions(self.final_bytes, versions, needed, strings, tags)
        for table in (versions, needed, strings):
            for index in range(table['size']):
                changed = bytearray(table['data'])
                changed[index] ^= 128
                at = table['offset']
                data = self.final_bytes[:at] + bytes(changed) + self.final_bytes[at + table['size']:]
                regions = [dict(section, data=bytes(changed)) if section is table else section
                           for section in (versions, needed, strings)]
                self.assertEqual(result(native_versions, data, *regions, tags),
                                 result(reference_versions, data, *regions, tags), (table['name'], index))
        for absent in (0x6ffffff0, 0x6ffffffe, 0x6fffffff):
            reduced = {tag: value for tag, value in tags.items() if tag != absent}
            args = (self.final_bytes, versions, needed, strings, reduced)
            self.assertEqual(result(native_versions, *args), result(reference_versions, *args), absent)

        self.native.verify_relro(self.final_bytes, writable, got)
        phoff = struct.unpack_from('<Q', self.final_bytes, 32)[0]
        ordinal = next(index for index, row in enumerate(final.segments) if row['type'] == 0x6474e552)
        base = phoff + ordinal * 56
        for index in range(56):
            data = bytearray(self.final_bytes)
            data[base + index] ^= 1
            kind, flags, offset, addr, _, filesz, memsz, align = struct.unpack_from('<II6Q', data, base)
            segments = list(final.segments)
            segments[ordinal] = dict(type=kind, flags=flags, offset=offset, addr=addr,
                                     filesz=filesz, memsz=memsz, align=align)
            self.assertEqual(result(self.native.verify_relro, bytes(data), writable, got),
                             result(elf_reader._reference_relro, SimpleNamespace(segments=segments),
                                    writable, got), index)


if __name__ == '__main__':
    unittest.main()
