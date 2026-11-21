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
        for kind, data in ((1, self.object_bytes), (3, self.final_bytes)):
            reference = _ELF.__new__(_ELF)
            reference._reference_inventory(data, kind)
            selected = _ELF(data, kind)
            text = reference.section('.text')
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
        loader_boundaries = ('_reference_dynamic_tags', '_reference_sysv_lookup', '_reference_gnu_lookup',
                             '_reference_plt_slot', '_reference_object_relocations',
                             '_reference_symbol_versions', '_reference_relro', '_reference_functions',
                             '_reference_function_link', '_reference_dynamic_symbols')
        loader_blocked = {name: Mock(side_effect=AssertionError('host loader check entered: ' + name))
                          for name in loader_boundaries}
        with patch.multiple(_ELF, **blocked), patch.multiple(elf_reader, **loader_blocked):
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
