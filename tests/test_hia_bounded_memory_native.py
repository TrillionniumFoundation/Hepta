"""Original-memory differential, independent VM and selected ordinary callers."""
from __future__ import annotations

import ast
import ctypes
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import tracemalloc
import unittest
from unittest.mock import patch

from hepta import hia_bounded_memory as memory
from hepta.hia_bounded_memory_native import (
    SOURCE, SCHEMA, SELECTOR, NativeBoundedMemory, installed_bounded_memory,
    packet, _integer_facts)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/bounded_memory_a7710b5.py.txt'


def original():
    namespace = {}
    exec(compile(FIXTURE.read_bytes(), str(FIXTURE), 'exec'), namespace)
    return namespace


def observed(method, target, args):
    try:
        result = method(target, *args)
        return ('returned', result)
    except ValueError as error:
        return (type(error).__name__, str(error))


def interpreted(raw, initial):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    body = Body(0)
    owners, views = [], []
    for data in (raw, initial, b''):
        owner = body.value('buffer', 'buffer.new', [body.const('usize', len(data))])
        view = body.value('mutbuf', 'borrow.mut', [owner])
        for i, value in enumerate(data):
            if value:
                body.effect('buffer.store', [view, body.const('usize', i), body.const('u8', value)])
        owners.append(owner)
        views.append(view)
    body.effect('loan.end', [views[0]])
    views[0] = body.value('readbuf', 'borrow.read', [owners[0]])
    result = body.value('u32', 'call', views, {'function': 'f0'})
    outputs = [result, *[body.value('u8', 'buffer.load', [views[1], body.const('usize', i)])
                          for i in range(len(initial))]]
    for view in views:
        body.effect('loan.end', [view])
    for owner in owners:
        body.effect('owner.drop', [owner])
    text = ('hia-asm.v1 hepta.hia.program.v8 memory_observer\nfn observe() -> ('
        + ','.join(['u32'] + ['u8'] * len(initial))
        + ') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
        + body.text() + '  ret(' + ','.join(outputs) + ')\nend\n'
        + SOURCE.read_text().split('\n', 1)[1])
    # Keep the complete independent VM path unselected for this observation.
    with patch.dict(os.environ):
        os.environ.pop(SELECTOR, None)
        report = execute_program(assemble_program(text), 'observe', [], max_steps=100000)
    if report['status'] != 'returned':
        raise AssertionError(report)
    if report['resources']['live_owners'] or report['resources']['live_local_loans']:
        raise AssertionError(report)
    return report['values'][0], bytes(report['values'][1:])


class BoundedMemorySourceTests(unittest.TestCase):
    def test_source_reproduces_and_original_bodies_are_unchanged(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_bounded_memory import document
        self.assertEqual(render_assembly(document()), SOURCE.read_text())
        frozen = {n.name: n for n in ast.parse(FIXTURE.read_text()).body if isinstance(n, ast.FunctionDef)}
        current = {n.name: n for n in ast.parse((ROOT / 'hepta/hia_bounded_memory.py').read_text()).body
                   if isinstance(n, ast.FunctionDef)}
        for name in ('_range', 'fill_bytes', 'move_bytes'):
            actual = current[name if name == '_range' else '_reference_' + name]
            actual.name = name
            self.assertEqual(ast.dump(actual), ast.dump(frozen[name]))

    def test_independent_VM_full_buffers_and_error_order_before_native(self):
        cases = [(1, 1, 3, 177, 0, b'a\xb1\xb1\xb1ef'),
                 (2, 1, 5, 0, 0, b'aabcde'), (2, 0, 5, 1, 0, b'bcdeff'),
                 (1, 7, 0, False, 1, b'abcdef'),
                 (1, 6, 0, False, 2, b'abcdef'),
                 (2, 0, 0, 7, 1, b'abcdef'),
                 (1, -(1 << 1000), 0, 7, 1, b'abcdef')]
        for operation, first, count, last, status, target in cases:
            raw = packet(operation, bytearray(b'abcdef'), first, count, last)
            self.assertEqual(interpreted(raw, b'abcdef'), (status, target))

    def test_installed_sources_and_bounded_integer_observations(self):
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        self.assertIn('examples/hia_bootstrap/bounded_memory.hepta', NATIVE_SOURCE_FILES)
        self.assertIn('include examples/hia_bootstrap/bounded_memory.hepta', (ROOT / 'MANIFEST.in').read_text())
        for value in (None, False, True, 1.0, '1', [], {}):
            self.assertEqual(_integer_facts(value), (0, 0))
        self.assertEqual(_integer_facts(0), (1, 0))
        self.assertEqual(_integer_facts((1 << 64) - 1), (1, (1 << 64) - 1))
        self.assertEqual(_integer_facts(1 << 64), (5, 0))
        self.assertEqual(_integer_facts((1 << 64) + 1), (5, 0))
        self.assertEqual(_integer_facts(-1), (3, 0))
        self.assertEqual(_integer_facts(-(1 << 63)), (3, 0))
        self.assertEqual(_integer_facts(-(1 << 100000)), (7, 0))
        self.assertEqual(_integer_facts(-(1 << 100000) + 1), (7, 0))

    def test_packet_scratch_is_bounded_for_huge_negative_inputs(self):
        # The input already exists before the original 64 KiB scratch gate.
        # Negative PyLong bitwise masking used to copy all of these digits,
        # even when an earlier buffer/range fact already required refusal.
        negative = -(1 << 8_000_000) + 1
        target = bytearray(b'abc')
        cases = ((1, target, negative, 0, 7),
                 (1, target, 0, negative, 7),
                 (1, target, 0, 0, negative),
                 (1, target, 4, 0, negative),
                 (1, None, negative, negative, negative),
                 (2, target, 0, 0, negative))
        for arguments in cases:
            tracemalloc.start()
            try:
                raw = packet(*arguments)
                _, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            self.assertEqual(len(raw), 80)
            self.assertLess(peak, 64 << 10)


class BoundedMemoryNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if interpreted(packet(2, bytearray(b'abcdef'), 1, 5, 0), b'abcdef') != (0, b'aabcde'):
            raise AssertionError('independent VM before native build')
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-bounded-memory-')
        cls.folder = Path(cls.temp.name)
        from tools.qualify_hia_selfhost import build_seed, compile_stage
        from tools.build_hia_bounded_memory import build
        cold = os.environ.get('HEPTA_HIA_BOUNDED_MEMORY_COLD_REPORT')
        if cold is not None:
            if not cold:
                raise ValueError('bounded-memory cold report selector must not be empty')
            report = json.loads(Path(cold).read_bytes())
            if report['status'] != 'COLD_SELFHOST_REPLAY_PASS' or not all(report['checks'].values()):
                raise ValueError('matching cold report did not pass')
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            if report['generation_sha256'] != [sha256(compiler.read_bytes()).hexdigest()] * 3:
                raise ValueError('cold compiler identity differs')
        else:
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            if first.read_bytes() != compiler.read_bytes():
                raise AssertionError('development compiler fixed point differs')
        cls.compiler = compiler
        cls.manifest = build(cls.folder / 'built', compiler, cold, development=cold is None)
        cls.build = json.loads((cls.manifest.parent / 'build.json').read_bytes())
        cls.native = installed_bounded_memory(str(cls.manifest))
        cls.reference = original()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def compare(self, operation, initial, args):
        expected = bytearray(initial)
        actual = bytearray(initial)
        before = observed(self.reference[operation], expected, args)
        after = observed(getattr(self.native, operation), actual, args)
        self.assertEqual((after, actual), (before, expected), (operation, args))

    def test_all_exact_kinds_and_integer_boundaries_preserve_first_refusal(self):
        class Foreign:
            def __getattribute__(self, name):
                raise AssertionError('unexpected foreign observation: ' + name)
        class SubInt(int):
            pass
        class SubBytes(bytearray):
            pass
        values = (None, False, True, 0.0, '0', [], {}, Foreign(), SubInt(0),
                  -1, 0, 1, 3, 4, 255, 256, (1 << 64) - 1, 1 << 64,
                  1 << 100000, -(1 << 100000))
        for value in values:
            for index in range(3):
                args = [0, 0, 7]
                args[index] = value
                self.compare('fill_bytes', b'abc', args)
                args = [0, 0, 0]
                args[index] = value
                self.compare('move_bytes', b'abc', args)
        for buffer in (None, b'abc', 'abc', [], memoryview(bytearray(b'abc')), SubBytes(b'abc'), Foreign()):
            for name, args in (('fill_bytes', (0, 0, False)), ('move_bytes', (0, 0, False))):
                self.assertEqual(observed(self.reference[name], buffer, args),
                                 observed(getattr(self.native, name), buffer, args))
        for args in ((4, 0, False), (3, 0, False), (-1, -1, False), (0, 4, False)):
            self.compare('fill_bytes', b'abc', args)

    def test_public_huge_negative_refusals_keep_original_order_and_bounded_scratch(self):
        negative = -(1 << 8_000_000) + 1
        cases = (('fill_bytes', None, (negative, negative, negative)),
                 ('fill_bytes', b'abc', (negative, 0, False)),
                 ('fill_bytes', b'abc', (0, negative, False)),
                 ('fill_bytes', b'abc', (4, 0, negative)),
                 ('fill_bytes', b'abc', (3, 0, negative)),
                 ('fill_bytes', b'abc', (0, 0, negative)),
                 ('move_bytes', None, (0, negative, 0)),
                 ('move_bytes', b'abc', (negative, 4, 0)),
                 ('move_bytes', b'abc', (0, negative, 0)),
                 ('move_bytes', b'abc', (0, 0, negative)))
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(memory, '_reference_fill_bytes', side_effect=AssertionError('host fill owner')),
              patch.object(memory, '_reference_move_bytes', side_effect=AssertionError('host move owner'))):
            for name, initial, arguments in cases:
                expected = None if initial is None else bytearray(initial)
                target = None if initial is None else bytearray(initial)
                before = observed(self.reference[name], expected, arguments)
                method = getattr(memory, name)
                tracemalloc.start()
                try:
                    after = observed(method, target, arguments)
                    _, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
                self.assertEqual((after, target), (before, expected))
                self.assertEqual(after[0], 'ValueError')
                self.assertLess(peak, 64 << 10, name)

    def test_full_overlap_domain_and_random_differential(self):
        for size in (0, 1, 2, 3, 5, 8, 17):
            initial = bytes((i * 19 + 3) % 256 for i in range(size))
            for destination in range(size + 2):
                for source in range(size + 2):
                    for count in range(size + 2):
                        self.compare('move_bytes', initial, (destination, source, count))
        rng = random.Random(724950)
        for _ in range(300):
            size = rng.randrange(65537)
            initial = rng.randbytes(size)
            count = rng.randrange(size + 1)
            destination = rng.randrange(size - count + 1)
            source = rng.randrange(size - count + 1)
            self.compare('move_bytes', initial, (destination, source, count))
            self.compare('fill_bytes', initial, (destination, count, rng.randrange(256)))

    def test_native_direct_above_old_chunk_and_large_extents(self):
        for extent in (4095, 4096, 4097, 8193, 4 << 20, 64 << 20):
            target = bytearray(extent)
            self.native.fill_bytes(target, 0, extent, 173)
            self.assertEqual(target.count(173), extent)
            self.native.fill_bytes(target, extent // 2, extent - extent // 2, 29)
            self.native.move_bytes(target, 1, 0, extent - 1)
            self.assertEqual(target.count(173), extent // 2 + 1)
            self.native.move_bytes(target, 0, 1, extent - 1)
            self.assertEqual(target.count(173), extent // 2)
            del target

    def test_original_memory_suites_selected_with_reference_forbidden(self):
        selected = unittest.defaultTestLoader.loadTestsFromNames([
            'tests.test_hia_bounded_memory', 'tests.test_hia_bounded_memory_fast'])
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(memory, '_reference_fill_bytes', side_effect=AssertionError('host fill owner')),
              patch.object(memory, '_reference_move_bytes', side_effect=AssertionError('host move owner'))):
            stream = io.StringIO()
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(selected)
        self.assertEqual(result.testsRun, 9, stream.getvalue())
        self.assertTrue(result.wasSuccessful(), stream.getvalue())
        self.assertFalse(result.skipped, stream.getvalue())

    def test_real_VM_fill_move_ranges_resources_and_traps_selected(self):
        from hepta.hia_program import execute_program
        from hepta.hia_program_runtime import HIAProgramTrap
        from tests.test_hia_bulk_memory import bulk_program
        from tests.test_hia_overlap_move import move_program
        from tests.test_hia_range_fill_v6 import fill_program
        fixtures = [(bulk_program(), 'bulk', [12, 8, 177]),
                    (move_program(), 'move_bytes', [5, 1, 0, 4, 3]),
                    (move_program(), 'move_bytes', [5, 0, 1, 4, 3]),
                    (fill_program(), 'fill_range', [8, 2, 3, 29, 3])]
        with patch.dict(os.environ):
            os.environ.pop(SELECTOR, None)
            references = [execute_program(*args) for args in fixtures]
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(memory, '_reference_fill_bytes', side_effect=AssertionError('host fill owner')),
              patch.object(memory, '_reference_move_bytes', side_effect=AssertionError('host move owner'))):
            for args, expected in zip(fixtures, references):
                self.assertEqual(execute_program(*args), expected)
            with self.assertRaises(HIAProgramTrap) as raised:
                execute_program(move_program(), 'move_bytes', [5, 1, 0, 5, 0])
            self.assertEqual(raised.exception.code, 'bounds')

    def test_no_callbacks_or_live_views_after_return_and_failure(self):
        target = bytearray(b'abcdef')
        self.native.fill_bytes(target, 0, 1, 29)
        target.extend(b'g')
        with self.assertRaisesRegex(ValueError, 'E_HIA_VM_RANGE'):
            self.native.move_bytes(target, 0, 100, 1)
        target.extend(b'h')
        self.assertEqual(target, bytearray(b'\x1dbcdefgh'))
        receipt = self.build['native_compile_receipt']
        self.assertEqual(receipt['forbidden_compiler_modules_loaded'], [])
        self.assertTrue(receipt['source_unchanged'])

    def test_retained_exception_traceback_does_not_retain_buffer_export(self):
        errors = []
        target = bytearray(b'abc')
        for method, args in ((self.native.fill_bytes, (0, 4, 0)),
                             (self.native.fill_bytes, (0, 0, False)),
                             (self.native.move_bytes, (0, 100, 1))):
            try:
                method(target, *args)
            except ValueError as error:
                errors.append(error)
            else:
                self.fail('expected original rejection')
            target.extend(b'x')
        with patch.object(self.native, '_memory_entry', lambda *_arguments: 1 << 32):
            try:
                self.native.fill_bytes(target, 0, 1, 0)
            except RuntimeError as error:
                errors.append(error)
            target.extend(b'y')
        self.assertEqual(len(errors), 4)
        self.assertTrue(all(error.__traceback__ is not None for error in errors))
        self.assertEqual(target, b'abcxxxy')

    def test_actual_pinned_helper_scope_thread_and_terminal_identity(self):
        from hepta import hia_native_helpers as authority
        bundle = self.folder / 'memory-helpers.json'
        bundle.write_text(json.dumps({'schema': authority.SCHEMA, 'target': authority.TARGET,
            'abi': authority.ABI, 'helpers': [{'selector': SELECTOR,
                'manifest_path': self.manifest.relative_to(self.folder).as_posix(),
                'manifest_sha256': sha256(self.manifest.read_bytes()).hexdigest()}]}))
        pin = sha256(bundle.read_bytes()).hexdigest()
        environment = {key: value for key, value in os.environ.items()
            if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        with (patch.dict(os.environ, environment, clear=True),
              patch.object(memory, '_reference_fill_bytes', side_effect=AssertionError('pinned fill fallback')),
              patch.object(memory, '_reference_move_bytes', side_effect=AssertionError('pinned move fallback'))):
            with authority.native_helpers_scope(str(bundle), pin):
                target = bytearray(b'abcdef')
                memory.fill_bytes(target, 2, 2, 29)
                memory.move_bytes(target, 1, 0, 5)
                self.assertEqual(target, b'aab\x1d\x1de')
                refused = []

                def wrong_owner():
                    try:
                        memory.fill_bytes(bytearray(b'abc'), 0, 1, 0)
                    except ValueError as error:
                        refused.append(str(error))

                worker = threading.Thread(target=wrong_owner)
                worker.start()
                worker.join(timeout=10)
                self.assertFalse(worker.is_alive())
                self.assertEqual(refused, ['native helper worker scope belongs to its original process and thread'])
                with patch.dict(os.environ, {SELECTOR: str(bundle)}):
                    with self.assertRaisesRegex(ValueError, 'outside the pinned worker bundle'):
                        memory.move_bytes(target, 0, 1, 5)
                    with self.assertRaisesRegex(ValueError, 'selection changed'):
                        authority.native_helpers_identity()
                self.assertEqual(authority.native_helpers_identity(), {'native_helpers_sha256': pin})
            self.assertNotIn(SELECTOR, os.environ)

    def test_short_corrupt_protocol_refuses_before_any_mutation(self):
        raw = packet(1, bytearray(b'abcdef'), 0, 6, 255)
        variants = [raw[:i] for i in range(len(raw))]
        for at, value in ((0, 0), (8, 0), (8, 3), (24, 1)):
            changed = bytearray(raw)
            struct.pack_into('<Q', changed, at, value)
            variants.append(bytes(changed))
        for wire in variants:
            source = ctypes.create_string_buffer(wire, max(1, len(wire)))
            data = bytearray(b'abcdef')
            target = (ctypes.c_ubyte * len(data)).from_buffer(data)
            result = self.native._memory_entry(source, len(wire), target, len(data), None, 0)
            self.assertEqual(result, 3)
            self.assertEqual(data, b'abcdef')
        with patch.object(self.native, '_memory_entry', return_value=1 << 32):
            with self.assertRaisesRegex(RuntimeError, 'invalid native'):
                self.native.fill_bytes(bytearray(b'abc'), 0, 1, 0)

    def test_selector_missing_empty_and_drift_have_no_fallback(self):
        for path in ('', str(self.manifest) + '.missing'):
            with (patch.dict(os.environ, {SELECTOR: path}),
                  patch.object(memory, '_reference_fill_bytes', side_effect=AssertionError('fallback')),
                  self.assertRaises((ValueError, FileNotFoundError))):
                memory.fill_bytes(bytearray(b'abc'), 0, 1, 0)
        # The common loader binds the resource bytes even after its image cache
        # is warm. A detached source copy avoids mutating the product source.
        detached = self.folder / 'detached.hepta'
        detached.write_bytes(SOURCE.read_bytes())
        with patch('hepta.hia_bounded_memory_native.SOURCE', detached):
            installed_bounded_memory(str(self.manifest))
            detached.write_bytes(detached.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'source identity'):
                installed_bounded_memory(str(self.manifest))
            detached.unlink()
            with self.assertRaises(FileNotFoundError):
                installed_bounded_memory(str(self.manifest))

    def test_strict_builder_refuses_wrong_current_cold_before_output(self):
        from tools.build_hia_bounded_memory import build
        invalid = self.folder / 'wrong-cold.json'
        invalid.write_text('{}')
        destination = self.folder / 'wrong-build'
        with self.assertRaises((ValueError, KeyError)):
            build(destination, self.compiler, invalid)
        self.assertFalse(destination.exists())

    def test_actual_isolated_sdist_wheel_uses_native_memory_with_no_reference(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        folder = self.folder / 'installed-memory'
        folder.mkdir()
        source = folder / 'source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

        def command(label, arguments):
            with (folder / (label + '.log')).open('xb') as output:
                result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=source,
                    stdout=output, stderr=subprocess.STDOUT, timeout=60)
            self.assertEqual(result.returncode, 0, (folder / (label + '.log')).read_text())

        command('sdist', ['setup.py', 'sdist', '--dist-dir', folder / 'sdist'])
        archive, = (folder / 'sdist').glob('*.tar.gz')
        with tarfile.open(archive) as handle:
            name, = (name for name in handle.getnames() if name.endswith(
                '/examples/hia_bootstrap/bounded_memory.hepta'))
            self.assertEqual(handle.extractfile(name).read(), SOURCE.read_bytes())
        command('wheel', ['-m', 'pip', 'wheel', '--no-index', '--no-deps', '--no-build-isolation',
            '--wheel-dir', folder / 'wheels', archive])
        wheel, = (folder / 'wheels').glob('*.whl')
        installed = folder / 'installed'
        command('install', ['-m', 'pip', 'install', '--no-index', '--no-deps', '--target', installed, wheel])
        script = r'''
import os, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
from hepta import hia_bounded_memory as public
from hepta import hia_bounded_memory_native as native
assert Path(public.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve())
assert native.SOURCE == Path(sys.argv[1]) / 'hepta/_data/examples/hia_bootstrap/bounded_memory.hepta'
os.environ[native.SELECTOR] = sys.argv[2]
with patch.object(public, '_reference_fill_bytes', side_effect=AssertionError('installed Python fill')), \
        patch.object(public, '_reference_move_bytes', side_effect=AssertionError('installed Python move')):
    target = bytearray(b'abcdef')
    public.fill_bytes(target, 2, 2, 29)
    assert target == bytearray(b'ab\x1d\x1def')
    public.move_bytes(target, 1, 0, 5)
    assert target == bytearray(b'aab\x1d\x1de')
    try:
        public.fill_bytes(target, 6, 0, False)
    except ValueError as error:
        assert str(error) == 'E_HIA_VM_VALUE: expected u8'
    else:
        raise AssertionError('invalid zero-length fill was accepted')
    original = native.SOURCE.read_bytes()
    try:
        native.SOURCE.write_bytes(original + b'\n')
        try:
            public.move_bytes(target, 0, 1, 5)
        except ValueError as error:
            assert str(error) == 'native HIA JSON source identity mismatch'
        else:
            raise AssertionError('changed installed source used cached native image')
        native.SOURCE.unlink()
        try:
            public.fill_bytes(target, 0, 1, 0)
        except FileNotFoundError:
            pass
        else:
            raise AssertionError('missing installed source used cached native image')
    finally:
        native.SOURCE.write_bytes(original)
print('ACTUAL_INSTALLED_NATIVE_MEMORY_PASS')
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script,
            str(installed), str(self.manifest)], cwd=folder, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), b'ACTUAL_INSTALLED_NATIVE_MEMORY_PASS')


if __name__ == '__main__':
    unittest.main()
