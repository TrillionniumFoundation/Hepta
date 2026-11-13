"""Original mapping decisions, independent Core VM, and actual Linux loaders."""
from __future__ import annotations

import ctypes
import fcntl
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import native_mapping_identity as current
from hepta import native_mapping_native as native
from hepta.hia_agent_assembly import assemble_program, render_assembly
from tools import generate_hia_native_mapping as generator

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/native_mapping_identity_539c1c04.py.txt'
ORIGINAL_SHA = 'e85114ea20081dc97ccca299e80a954c3c2165de63d22b776948a1c4001ff010'
COLD_REPORT = 'HEPTA_HIA_NATIVE_MAPPING_COLD_REPORT'
DEVELOPMENT_COMPILER = 'HEPTA_HIA_NATIVE_MAPPING_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_NATIVE_MAPPING_EVIDENCE'
GOOD = b'1000-2000 r-xp 200 08:01 42'
ADDRESSES = {'entry': 0x1234}


def digest(raw):
    return sha256(raw).hexdigest()


def original_module():
    raw = FIXTURE.read_bytes()
    if digest(raw) != ORIGINAL_SHA:
        raise AssertionError('independent original mapping source changed')
    namespace = {'__name__': 'original_mapping_539c1c04'}
    exec(compile(raw, str(FIXTURE), 'exec'), namespace)
    return namespace


def reference(raw, addresses=ADDRESSES):
    try:
        return ('returned', current._reference_mapping_matches(raw, addresses, (8, 1), 42, 0x4000))
    except current.NativeMappingRejected as error:
        return ('rejected', str(error))
    except (ValueError, TypeError, OverflowError):
        return ('rejected', 'E_NATIVE_MAPPING: unable to establish actual loaded file identity')


def interpret(checked, raw, addresses=ADDRESSES, *, state=None, output_size=None):
    from hepta.hia_program_runtime import _Machine, _Owner, _View
    state = native.state_bytes(addresses, (8, 1), 42, 0x4000) if state is None else state
    output = b'\xa5' * (16 + len(addresses) * 8 if output_size is None else output_size)
    owners = [_Owner(i + 1, bytearray(value)) for i, value in enumerate((raw, output, state))]
    machine = _Machine(checked, 10_000_000, 32 << 20, None, 128)
    values = machine.invoke(machine.functions['f0'], [_View(owner, i != 0) for i, owner in enumerate(owners)])
    if bytes(owners[0].data) != raw:
        raise AssertionError('mapping VM changed immutable kernel bytes')
    return values[0], bytes(owners[1].data), bytes(owners[2].data), machine.steps


def decoded(code, output, addresses):
    if code:
        return ('rejected', 'E_NATIVE_MAPPING: ' + native.REASONS[code])
    magic, count = struct.unpack_from('<2Q', output)
    if (magic, count) != (native.RESULT_MAGIC, len(addresses)):
        raise AssertionError('mapping response differs')
    return ('returned', {name: [{'file_offset': offset, 'permissions': 'r-xp'}]
                         for name, offset in zip(addresses, struct.unpack_from('<' + 'Q' * count, output, 16))})


def cases():
    huge = b'1' + b'0' * 80
    return (
        ('ordinary', GOOD),
        ('prefix-underscore', b'+0x_1000-+0X_2000 r-xp +0x_200 0_8:+01 +4_2'),
        ('zero-and-whitespace', b'\t001000-002000\vr-xp\f0200\t08:01 00042 /path with spaces\xff\n'),
        ('crlf', b'3000-4000 strange 0 00:-0 -0\r\n' + GOOD + b'\r'),
        ('unmatched-large', huge + b'-2' + b'0' * 80 + b' odd ' + huge + b' ' + huge + b':0 42\n' + GOOD),
        ('unmatched-large-inode', b'3000-4000 odd 0 08:01 ' + b'9' * 100 + b'\n' + GOOD),
        ('equal-large-interval', huge + b'-0x0' + huge + b' odd 0 0:0 0\n' + GOOD),
        ('ordered-large-interval', huge + b'-' + huge[:-1] + b'1 odd 0 0:0 0\n' + GOOD),
        ('duplicate', GOOD + b'\n' + GOOD),
        ('missing', b'3000-4000 r-xp 0 8:1 42'),
        ('blank', b'\n' + GOOD),
        ('missing-field', b'1000-2000 r-xp 0 08:01'),
        ('separator-priority', b'zzz r-xp bad broken bad'),
        ('integer-before-interval', b'2000-1000 r-xp _0 8:1 42'),
        ('ascii-before-interval', b'2000-1000 r-xp\xff 0 8:1 42'),
        ('bad-permissions', b'1000-2000 rwxp 0 8:1 42'),
        ('different-inode', b'1000-2000 r-xp 0 8:1 43'),
        ('large-matching-inode', b'1000-2000 r-xp 0 8:1 ' + b'9' * 100),
        ('negative-offset', b'1000-2000 r-xp -1 8:1 42'),
        ('negative-zero', b'1000-2000 r-xp -0 8:1 42'),
        ('offset-overflow', b'1000-2000 r-xp 10000000000000000 8:1 42'),
        ('addition-overflow', b'1000-2000 r-xp ffffffffffffffff 8:1 42'),
        ('past-file', b'1000-2000 r-xp 4000 8:1 42'),
        ('empty', b''),
    )


class NativeMappingSourceTests(unittest.TestCase):
    def test_generated_HIA_stays_in_original_compiler_profile(self):
        expected = render_assembly(generator.document(generator.source(), 'native_mapping'))
        self.assertEqual(native.SOURCE.read_text(), expected)
        checked = assemble_program(expected.encode()).as_dict()
        self.assertLessEqual(len(checked['functions']), 128)
        self.assertLessEqual(sum(len(f['blocks']) for f in checked['functions']), 1536)
        self.assertLessEqual(sum(len(b['ops']) for f in checked['functions'] for b in f['blocks']), 8192)

    def test_original_parser_body_is_preserved_as_independent_reference(self):
        original_module()
        raw = FIXTURE.read_text()
        start = raw.index('        matches = {name: [] for name in symbols}')
        end = raw.index('        final = os.fstat(fd)', start)
        body = '\n'.join(line[4:] if line else '' for line in raw[start:end].split('\n'))
        body = body.replace('for name in symbols', 'for name in addresses').replace('initial.st_ino', 'expected_inode').replace('initial.st_size', 'file_bytes')
        self.assertIn(body, Path(current.__file__).read_text())

    def test_ordinary_VM_matches_original_numeric_and_refusal_order(self):
        checked = assemble_program(native.SOURCE.read_bytes())
        for name, raw in cases():
            with self.subTest(name=name):
                code, output, state, steps = interpret(checked, raw)
                self.assertEqual(decoded(code, output, ADDRESSES), reference(raw))
                if code:
                    self.assertEqual(output, b'\xa5' * len(output))
                self.assertLess(steps, 10_000_000)

@unittest.skipUnless(platform.system() == 'Linux' and platform.machine().lower() in ('x86_64', 'amd64')
                     and shutil.which('as') and shutil.which('ld'), 'Linux x86-64 and as/ld required')
class NativeMappingNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools import qualify_hia_selfhost as qualification
        from tools.build_hia_native_mapping import build
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        cold, development = os.environ.get(COLD_REPORT), os.environ.get(DEVELOPMENT_COMPILER)
        if cold and development:
            raise ValueError('cold and development mapping inputs are mutually exclusive')
        cls.temporary = None
        if EVIDENCE in os.environ:
            parent = Path(os.environ[EVIDENCE]); parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            cls.root = parent / 'candidate'; cls.root.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-mapping-component-')
            cls.root = Path(cls.temporary.name)
        cls.before = {p.relative_to(ROOT).as_posix(): p.read_bytes()
                      for folder in ('hepta', 'tools') for p in (ROOT / folder).rglob('*.py')}
        for path in (native.SOURCE, FIXTURE, Path(__file__)):
            cls.before[path.relative_to(ROOT).as_posix()] = path.read_bytes()
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in',
                     'tests/test_hia_agent_installed_resources.py'):
            cls.before[name] = (ROOT / name).read_bytes()
        (cls.root / 'source-before.json').write_text(json.dumps({k: digest(v) for k, v in cls.before.items()}, indent=2, sort_keys=True) + '\n')
        cls.checked = assemble_program(native.SOURCE.read_bytes())
        # Independent VM output precedes any new native compiler or helper.
        cls.reference = []
        for name, raw in cases():
            code, output, state, steps = interpret(cls.checked, raw)
            if decoded(code, output, ADDRESSES) != reference(raw):
                raise AssertionError('pre-native mapping VM differs from original parser')
            cls.reference.append({'name': name, 'source_sha256': digest(raw), 'code': code,
                                  'output_hex': output.hex(), 'state_sha256': digest(state), 'steps': steps})
        (cls.root / 'independent-reference.json').write_text(json.dumps(cls.reference, indent=2, sort_keys=True) + '\n')
        if cold:
            from tools.build_hia_json_preflight import admit_cold_build
            cls.cold_bytes = Path(cold).read_bytes()
            report = json.loads(cls.cold_bytes)
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            admit_cold_build(compiler.read_bytes(), cls.cold_bytes)
            cls.scope = 'MATCHING_SOURCE_COLD_COMPONENT'
        elif development:
            compiler = Path(development); cls.scope = 'RETAINED_COMPILER_DEVELOPMENT_COMPONENT'
        else:
            seed, _ = qualification.build_seed(cls.root)
            compiler, _ = qualification.compile_stage(cls.root, 'B1', seed, qualification.SOURCE.read_bytes(), image_format='seed-shared')
            cls.scope = 'ISOLATED_CURRENT_SOURCE_BOOTSTRAP_COMPONENT'
        cls.compiler = compiler; cls.compiler_bytes = compiler.read_bytes()
        cls.manifest = build(cls.root / 'build', compiler, cold, development=not bool(cold))
        cls.image = native.installed_native_mapping(cls.manifest)
        cls.records = []

    @classmethod
    def tearDownClass(cls):
        unchanged = all((ROOT / path).read_bytes() == raw for path, raw in cls.before.items())
        unchanged = unchanged and cls.compiler.read_bytes() == cls.compiler_bytes
        report = {'scope': cls.scope, 'source_and_compiler_unchanged': unchanged,
                  'native_image_sha256': cls.image.image_sha256, 'observations': cls.records,
                  'whole_stack_rewritten_in_hia': False, 'all_input_equivalence_proved': False}
        (cls.root / 'observations.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        if cls.temporary is not None:
            cls.temporary.cleanup()
        if not unchanged:
            raise AssertionError('mapping component source or compiler changed')

    def native_frame(self, raw, addresses=ADDRESSES):
        original = native.state_bytes(addresses, (8, 1), 42, 0x4000)
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        state = ctypes.create_string_buffer(original, len(original))
        initial = b'\xa5' * (16 + 8 * len(addresses))
        output = ctypes.create_string_buffer(initial, len(initial))
        result = self.image._entry(source, len(raw), output, len(initial), state, len(original))
        self.assertEqual(source.raw[:len(raw)], raw)
        self.assertEqual(state.raw[:64 + 8 * len(addresses)], original[:64 + 8 * len(addresses)])
        return result, output.raw, state.raw

    def test_actual_HIA_complete_buffers_match_independent_VM_and_original(self):
        for name, raw in cases():
            with self.subTest(name=name):
                actual = self.native_frame(raw)
                expected = interpret(self.checked, raw)[:3]
                self.assertEqual(actual, expected)
                self.assertEqual(decoded(actual[0], actual[1], ADDRESSES), reference(raw))
                self.records.append({'case': name, 'source_sha256': digest(raw), 'status': actual[0],
                                     'all_output_and_workspace_bytes_equal_VM': True})

    def test_all_128_symbols_and_original_maps_capacity_remain_supported(self):
        addresses = {'entry' + str(i): 0x1234 for i in range(128)}
        self.assertEqual(self.image.matches(GOOD, addresses, (8, 1), 42, 0x4000), reference(GOOD, addresses)[1])
        raw = GOOD + b' ' + b'x' * (native.MAX_MAPS_BYTES - len(GOOD) - 1)
        self.assertEqual(len(raw), 16 << 20)
        self.assertEqual(self.image.matches(raw, ADDRESSES, (8, 1), 42, 0x4000), reference(raw)[1])
        with self.assertRaises(ValueError):
            self.image.matches(raw + b'x', ADDRESSES, (8, 1), 42, 0x4000)
        self.records.append({'case': 'original-capacity', 'maps_bytes': len(raw), 'symbols': 128})

    def test_decimal_digit_limit_and_large_unmatched_values_preserve_python(self):
        limit = sys.get_int_max_str_digits()
        for digits in (100, 4299, 4300, 4301):
            raw = b'3000-4000 odd 0 0:0 ' + b'0' * digits + b'\n' + GOOD
            expected = reference(raw)
            try:
                actual = ('returned', self.image.matches(raw, ADDRESSES, (8, 1), 42, 0x4000))
            except current.NativeMappingRejected as error:
                actual = ('rejected', str(error))
            self.assertEqual(actual, expected)
        self.records.append({'case': 'decimal-limit', 'actual_digit_limit': limit})

    def fixture(self, name, value):
        folder = self.root / name; folder.mkdir()
        source = folder / 'entry.S'
        source.write_text('.text\n.globl entry\n.type entry,@function\nentry:\n mov $' + str(value) + ',%eax\n ret\n.section .note.GNU-stack,"",@progbits\n')
        obj, image = folder / 'entry.o', folder / 'entry.so'
        for command in (['as', '--64', str(source), '-o', str(obj)],
                        ['ld', '-shared', '-z', 'defs', '-z', 'noexecstack', '-z', 'relro', '-z', 'now', '--build-id=none', str(obj), '-o', str(image)]):
            subprocess.run(command, check=True, capture_output=True, timeout=20)
        return image

    def test_real_sealed_DSO_entries_equal_unchanged_original_and_execute(self):
        import _ctypes
        image = self.fixture('real-loader', 37)
        descriptor = os.memfd_create('hia-mapping-test', os.MFD_ALLOW_SEALING)
        library = None
        try:
            os.write(descriptor, image.read_bytes())
            fcntl.fcntl(descriptor, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
            library = ctypes.CDLL('/proc/self/fd/' + str(descriptor), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            entry = library.entry; entry.argtypes = []; entry.restype = ctypes.c_uint64
            symbols = {'entry': entry}
            before = original_module()['verify_loaded_symbols'](descriptor, symbols)
            with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), \
                    patch.object(current, '_reference_mapping_matches', side_effect=AssertionError('selected native route cannot use Python policy')):
                actual = current.verify_loaded_symbols(descriptor, symbols)
            self.assertEqual(actual, before)
            self.assertEqual(entry(), 37)
            self.records.append({'case': 'real-loader', 'mapping': actual, 'native_result': 37})
        finally:
            if library is not None:
                _ctypes.dlclose(library._handle)
            os.close(descriptor)

    def test_original_input_rejections_still_precede_native_selection(self):
        old = original_module()
        with patch.dict(os.environ, {native.SELECTOR: 'unread-missing-manifest'}), \
                patch.object(native, 'installed_native_mapping', side_effect=AssertionError('must not select')) as selected:
            for descriptor, symbols in ((-1, {}), (True, {}), (0, {}), (0, {'entry': object()})):
                with self.subTest(descriptor=descriptor, symbols=symbols):
                    observed = []
                    for call in (old['verify_loaded_symbols'], current.verify_loaded_symbols):
                        try:
                            call(descriptor, symbols)
                        except ValueError as error:
                            observed.append((type(error).__name__, str(error)))
                    self.assertEqual(len(observed), 2)
                    self.assertEqual(observed[0], observed[1])
        selected.assert_not_called()

    def test_anonymous_helper_loader_and_real_bad_ABI_do_not_reenter_mapping(self):
        # These are explicitly hostile native ABI fixtures, not HIA outputs.
        for raw in (bytes.fromhex('48 b8 01 00 00 00 01 00 00 00 c3'),
                    bytes.fromhex('31 c0 c3'),
                    bytes.fromhex('c6 07 61 31 c0 c3')):
            with patch.object(current, 'verify_loaded_symbols', side_effect=AssertionError('recursive mapping gate')) as mapping:
                image = native.NativeMappingImage(raw, digest(raw))
            mapping.assert_not_called()
            try:
                with self.assertRaises(ValueError):
                    image.matches(GOOD, ADDRESSES, (8, 1), 42, 0x4000)
            finally:
                image._entry = None; image._mapping.close()

    def test_actual_fd_reuse_refuses_retained_loader_object_before_new_entry(self):
        import _ctypes
        old_image = self.fixture('retained-old', 17)
        new_image = self.fixture('retained-new', 23)
        descriptor = os.memfd_create('hia-retained-mapping', os.MFD_ALLOW_SEALING)
        old_library = new_library = None
        try:
            os.write(descriptor, old_image.read_bytes())
            fcntl.fcntl(descriptor, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
            old_inode = os.fstat(descriptor).st_ino
            old_library = ctypes.CDLL('/proc/self/fd/' + str(descriptor), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            old_function = old_library.entry
            old_function.argtypes = []; old_function.restype = ctypes.c_uint64
            original_module()['verify_loaded_symbols'](descriptor, {'entry': old_function})
            self.assertEqual(old_function(), 17)
            old_number = descriptor
            os.close(descriptor); descriptor = None
            descriptor = os.memfd_create('hia-retained-mapping', os.MFD_ALLOW_SEALING)
            self.assertEqual(descriptor, old_number)
            os.write(descriptor, new_image.read_bytes())
            fcntl.fcntl(descriptor, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
            new_inode = os.fstat(descriptor).st_ino
            self.assertNotEqual(old_inode, new_inode)
            new_library = ctypes.CDLL('/proc/self/fd/' + str(descriptor), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            new_function = new_library.entry
            self.assertEqual(ctypes.cast(new_function, ctypes.c_void_p).value,
                             ctypes.cast(old_function, ctypes.c_void_p).value)
            observations = []
            with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), \
                    patch.object(current, '_reference_mapping_matches', side_effect=AssertionError('no Python fallback')):
                for call in (original_module()['verify_loaded_symbols'], current.verify_loaded_symbols):
                    try:
                        call(descriptor, {'entry': new_function})
                    except ValueError as error:
                        observations.append((type(error).__name__, str(error)))
            self.assertEqual(len(observations), 2)
            self.assertEqual(observations[0], observations[1])
            self.assertIn('different file object', observations[1][1])
            self.records.append({'case': 'actual-retained-loader-fd-reuse', 'old_inode': old_inode,
                                 'new_inode': new_inode, 'same_function_address': True,
                                 'refusal': observations[1]})
        finally:
            if new_library is not None:
                _ctypes.dlclose(new_library._handle)
            if old_library is not None:
                _ctypes.dlclose(old_library._handle)
            if descriptor is not None:
                os.close(descriptor)

    def test_unknown_kernel_evidence_and_final_readback_keep_original_order(self):
        import _ctypes
        image = self.fixture('kernel-boundary', 31)
        descriptor = os.memfd_create('hia-kernel-mapping', os.MFD_ALLOW_SEALING)
        library = None
        try:
            os.write(descriptor, image.read_bytes())
            fcntl.fcntl(descriptor, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
            library = ctypes.CDLL('/proc/self/fd/' + str(descriptor), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            function = library.entry
            old = original_module()['verify_loaded_symbols']
            real_open = open
            def unavailable(path, *args, **kwargs):
                if path == '/proc/self/maps':
                    raise PermissionError('explicit unavailable kernel observation')
                return real_open(path, *args, **kwargs)
            with patch('builtins.open', side_effect=unavailable), \
                    patch.object(native, 'selected_native_mapping', side_effect=AssertionError('must fail before native selection')) as selection:
                for call in (old, current.verify_loaded_symbols):
                    with self.assertRaisesRegex(ValueError, 'unable to establish actual loaded file identity'):
                        call(descriptor, {'entry': function})
            selection.assert_not_called()
            real_stat = os.fstat(descriptor)
            changed = SimpleNamespace(st_dev=real_stat.st_dev, st_ino=real_stat.st_ino + 1, st_size=real_stat.st_size)
            for call in (old, current.verify_loaded_symbols):
                with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), \
                        patch('os.fstat', side_effect=[real_stat, changed]) as stat_calls, \
                        self.assertRaisesRegex(ValueError, 'sealed descriptor changed during mapping admission'):
                    call(descriptor, {'entry': function})
                self.assertEqual(stat_calls.call_count, 2)
            self.records.append({'case': 'unknown-and-final-readback', 'actual_inode': real_stat.st_ino,
                                 'unknown_refused_before_selection': True, 'final_stat_drift_refused': True})
        finally:
            if library is not None:
                _ctypes.dlclose(library._handle)
            os.close(descriptor)

    def test_complete_public_exception_causes_equal_original_first_bad_token(self):
        import _ctypes
        image = self.fixture('public-error-causes', 41)
        descriptor = os.memfd_create('hia-public-mapping-errors', os.MFD_ALLOW_SEALING)
        library = None
        try:
            os.write(descriptor, image.read_bytes())
            fcntl.fcntl(descriptor, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
            library = ctypes.CDLL('/proc/self/fd/' + str(descriptor), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            function = library.entry
            address = ctypes.cast(function, ctypes.c_void_p).value
            metadata = os.fstat(descriptor)
            good = (f'{address:x}-{address + 1:x} r-xp 0 '
                    f'{os.major(metadata.st_dev):x}:{os.minor(metadata.st_dev):x} {metadata.st_ino}').encode()
            inputs = [
                ('lower', b'wrong-20 r-xp 0 0:0 0'),
                ('upper', b'10-wrong r-xp 0 0:0 0'),
                ('offset', b'10-20 r-xp nope 0:0 0'),
                ('major', b'10-20 r-xp 0 wrong:0 0'),
                ('minor', b'10-20 r-xp 0 0:wrong 0'),
                ('inode', b'10-20 r-xp 0 0:0 nope'),
                ('non-ascii', b'10-20 r-x\xff 0 0:0 0'),
                ('number-before-ascii', b'20-10 r-x\xff wrong 0:0 0'),
                ('ascii-before-interval', b'20-10 r-x\xff 0 0:0 0'),
                ('separator-before-number', b'wrong r-x\xff wrong broken nope'),
                ('long-invalid-token', b'10-20 r-xp ' + b'0' * 300 + b'wrong 0:0 0'),
            ]
            limit = sys.get_int_max_str_digits()
            if limit:
                inputs.append(('actual-decimal-digit-limit', b'10-20 r-xp 0 0:0 ' + b'0' * (limit + 1)))
            real_open = open
            old = original_module()['verify_loaded_symbols']
            for name, prefix in inputs:
                raw = prefix + b'\n' + good
                def captured(path, *args, **kwargs):
                    return io.BytesIO(raw) if path == '/proc/self/maps' else real_open(path, *args, **kwargs)
                observations = []
                with patch.dict(os.environ, {native.SELECTOR: str(self.manifest)}), \
                        patch('builtins.open', side_effect=captured), \
                        patch.object(current, '_reference_mapping_matches', side_effect=AssertionError('no native fallback')):
                    for call in (old, current.verify_loaded_symbols):
                        try:
                            call(descriptor, {'entry': function})
                        except ValueError as error:
                            cause = error.__cause__
                            observations.append((type(error).__name__, str(error),
                                                 None if cause is None else (type(cause).__name__, str(cause))))
                with self.subTest(name=name):
                    self.assertEqual(len(observations), 2)
                    self.assertEqual(observations[0], observations[1])
                self.records.append({'case': 'full-public-synthetic-maps-' + name,
                                     'source_sha256': digest(raw), 'exception': observations[1]})
        finally:
            if library is not None:
                _ctypes.dlclose(library._handle)
            os.close(descriptor)

    def test_default_has_no_native_import_and_empty_selection_cannot_fallback(self):
        import _ctypes
        import builtins
        image = self.fixture('default-selection', 43)
        descriptor = os.memfd_create('hia-default-selection', os.MFD_ALLOW_SEALING)
        library = None
        try:
            os.write(descriptor, image.read_bytes())
            fcntl.fcntl(descriptor, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
            library = ctypes.CDLL('/proc/self/fd/' + str(descriptor), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            symbols = {'entry': library.entry}
            old = original_module()['verify_loaded_symbols'](descriptor, symbols)
            original_import = builtins.__import__
            def guarded(name, *args, **kwargs):
                if name.endswith('native_mapping_native'):
                    raise AssertionError('default mapping must not import the native loader')
                return original_import(name, *args, **kwargs)
            with patch.dict(os.environ):
                os.environ.pop(native.SELECTOR, None)
                with patch('builtins.__import__', side_effect=guarded):
                    self.assertEqual(current.verify_loaded_symbols(descriptor, symbols), old)
            with patch.dict(os.environ, {native.SELECTOR: ''}), \
                    patch.object(current, '_reference_mapping_matches', side_effect=AssertionError('empty selector cannot fallback')), \
                    self.assertRaises(current.NativeMappingRejected) as refused:
                current.verify_loaded_symbols(descriptor, symbols)
            self.assertIs(type(refused.exception.__cause__), ValueError)
            self.assertEqual(str(refused.exception.__cause__), 'native mapping selector must not be empty')
            self.records.append({'case': 'default-and-empty-selection', 'default_native_imports': 0,
                                 'empty_selection_refused_without_fallback': True})
        finally:
            if library is not None:
                _ctypes.dlclose(library._handle)
            os.close(descriptor)

    def test_actual_compiler_receipts_cannot_publish_inconsistent_mapping_manifest(self):
        from tools import build_hia_native_mapping as builder
        original = builder.compile_stage
        for key in ('result_u64', 'image_sha256', 'source_sha256', 'output_sha256'):
            folder = self.root / ('bad-receipt-' + key)
            def changed(*args, **kwargs):
                image, receipt = original(*args, **kwargs)
                receipt = dict(receipt)
                receipt[key] = receipt['core_u32'] + (1 << 32) if key == 'result_u64' else '0' * 64
                return image, receipt
            with patch.object(builder, 'compile_stage', side_effect=changed), self.assertRaises(ValueError):
                builder.build(folder, self.compiler, development=True)
            self.assertFalse((folder / 'manifest.json').exists())
            self.assertFalse((folder / 'build.json').exists())
            self.records.append({'case': 'actual-compiler-bad-receipt', 'field': key,
                                 'manifest_published': False})

    def test_actual_installed_wheel_uses_selected_HIA_and_rejects_warm_source_drift(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        folder = self.root / 'installed-mapping'; folder.mkdir()
        source = folder / 'source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        def command(label, arguments):
            with (folder / (label + '.log')).open('xb') as output:
                result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=source,
                                        stdout=output, stderr=subprocess.STDOUT, timeout=60)
            self.assertEqual(result.returncode, 0, (folder / (label + '.log')).read_text())
        command('sdist', ['setup.py', 'sdist', '--dist-dir', folder / 'sdist'])
        archive, = (folder / 'sdist').glob('*.tar.gz')
        with tarfile.open(archive) as handle:
            name, = (name for name in handle.getnames() if name.endswith('/examples/hia_bootstrap/native_mapping.hepta'))
            self.assertEqual(handle.extractfile(name).read(), native.SOURCE.read_bytes())
        command('wheel', ['-m', 'pip', 'wheel', '--no-index', '--no-deps', '--no-build-isolation',
                          '--wheel-dir', folder / 'wheels', archive])
        wheel, = (folder / 'wheels').glob('*.whl')
        installed = folder / 'installed'
        command('install', ['-m', 'pip', 'install', '--no-index', '--no-deps', '--target', installed, wheel])
        dso = self.fixture('installed-real-entry', 47)
        script = r'''
import _ctypes, ctypes, fcntl, json, os, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
from hepta import native_mapping_identity as public
from hepta import native_mapping_native as native
assert Path(public.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve())
assert native.SOURCE == Path(sys.argv[1]) / 'hepta/_data/examples/hia_bootstrap/native_mapping.hepta'
os.environ[native.SELECTOR] = sys.argv[2]
descriptor = os.memfd_create('hia-installed-mapping', os.MFD_ALLOW_SEALING)
library = None
try:
    os.write(descriptor, Path(sys.argv[3]).read_bytes())
    fcntl.fcntl(descriptor, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
    library = ctypes.CDLL('/proc/self/fd/' + str(descriptor), mode=os.RTLD_LOCAL | os.RTLD_NOW)
    function = library.entry; function.argtypes = []; function.restype = ctypes.c_uint64
    with patch.object(public, '_reference_mapping_matches', side_effect=AssertionError('installed path cannot use Python policy')):
        observed = public.verify_loaded_symbols(descriptor, {'entry': function})
        assert observed['inode'] == os.fstat(descriptor).st_ino
        assert function() == 47
        source = native.SOURCE.read_bytes()
        refusals = []
        try:
            for replacement in (source + b'\n', None):
                if replacement is None:
                    native.SOURCE.unlink()
                else:
                    native.SOURCE.write_bytes(replacement)
                try:
                    public.verify_loaded_symbols(descriptor, {'entry': function})
                except public.NativeMappingRejected as error:
                    refusals.append((type(error.__cause__).__name__, str(error.__cause__)))
                else:
                    raise AssertionError('warm selected image concealed missing or changed package source')
        finally:
            native.SOURCE.write_bytes(source)
        assert refusals[0] == ('ValueError', 'native HIA JSON source identity mismatch')
        assert refusals[1][0] == 'FileNotFoundError'
    print(json.dumps({'actual_result': 47, 'mapping': observed, 'installed_source': str(native.SOURCE),
                      'warm_source_refusals': refusals, 'python_policy_fallback': False}, sort_keys=True))
finally:
    if library is not None:
        _ctypes.dlclose(library._handle)
    os.close(descriptor)
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(installed),
                                 str(self.manifest), str(dso)], cwd=folder, capture_output=True, timeout=20)
        (folder / 'installed.stdout.bin').write_bytes(result.stdout)
        (folder / 'installed.stderr.bin').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.records.append({'case': 'actual-sdist-wheel-installed-mapping',
                             'wheel_sha256': digest(wheel.read_bytes()),
                             'observations': json.loads(result.stdout)})

    def test_actual_operator_pinned_helper_scope_preserves_owner_and_selection(self):
        import _ctypes
        from hepta import hia_native_helpers as authority
        bundle = self.root / 'mapping-helpers.json'
        bundle.write_text(json.dumps({'schema': authority.SCHEMA, 'target': authority.TARGET,
                                     'abi': authority.ABI, 'helpers': [{
                                         'selector': native.SELECTOR,
                                         'manifest_path': self.manifest.relative_to(self.root).as_posix(),
                                         'manifest_sha256': digest(self.manifest.read_bytes())}]}))
        pin = digest(bundle.read_bytes())
        image = self.fixture('pinned-helper-entry', 49)
        descriptor = os.memfd_create('hia-pinned-helper-entry', os.MFD_ALLOW_SEALING)
        library = None
        try:
            os.write(descriptor, image.read_bytes())
            fcntl.fcntl(descriptor, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
            library = ctypes.CDLL('/proc/self/fd/' + str(descriptor), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            entry = library.entry; entry.argtypes = []; entry.restype = ctypes.c_uint64
            expected = original_module()['verify_loaded_symbols'](descriptor, {'entry': entry})
            environment = {key: value for key, value in os.environ.items()
                           if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(current, '_reference_mapping_matches', side_effect=AssertionError('pinned mapping cannot fallback')):
                with authority.native_helpers_scope(str(bundle), pin):
                    self.assertEqual(current.verify_loaded_symbols(descriptor, {'entry': entry}), expected)
                    self.assertEqual(entry(), 49)
                    refused = []
                    def wrong_owner():
                        try:
                            current.verify_loaded_symbols(descriptor, {'entry': entry})
                        except current.NativeMappingRejected as error:
                            refused.append(str(error.__cause__))
                    worker = threading.Thread(target=wrong_owner)
                    worker.start(); worker.join(timeout=10)
                    self.assertFalse(worker.is_alive())
                    self.assertEqual(refused, ['native helper worker scope belongs to its original process and thread'])
                    with patch.dict(os.environ, {native.SELECTOR: str(bundle)}), self.assertRaises(current.NativeMappingRejected):
                        current.verify_loaded_symbols(descriptor, {'entry': entry})
                    self.assertEqual(authority.native_helpers_identity(), {'native_helpers_sha256': pin})
                self.assertNotIn(native.SELECTOR, os.environ)
            self.records.append({'case': 'operator-pinned-mapping-helper', 'bundle_sha256': pin,
                                 'actual_result': 49, 'foreign_thread_refused': True,
                                 'changed_selection_refused': True, 'environment_restored': True})
        finally:
            if library is not None:
                _ctypes.dlclose(library._handle)
            os.close(descriptor)


if __name__ == '__main__':
    unittest.main()
