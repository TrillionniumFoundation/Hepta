"""Permanent controls for the explicit HIA checkout-source owner.

Native groups require either a current-source cold report or an explicitly
selected development compiler. No compiler is guessed or bootstrapped.
The original thirteen machine/VM controls and eleven ordered filesystem
controls are retained; extra controls bind permanent build/install custody.
"""
from __future__ import annotations
import ast
from concurrent.futures import ThreadPoolExecutor
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
import tempfile
import time
import traceback
import unittest
from unittest.mock import patch
import zipfile

from hepta import hia_source_admission_native as adapter

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / adapter.SOURCE_NAME
REFERENCE = ROOT / 'tests/fixtures/hia_source_admission_reference.hiaasm'
REFERENCE_SHA256 = '55097a1db37eb9c2771e6988c6299ac90b87a02b437f1c48527e9e64ee408298'
FROZEN_HIA_SHA256 = 'e7e0bdf576dd721c36d98a2b1855bcd34a2ab480094c322a3629ddc26de192f6'
COLD_REPORT = 'HEPTA_HIA_SOURCE_ADMISSION_COLD_REPORT'
DEVELOPMENT_COMPILER = 'HEPTA_HIA_SOURCE_ADMISSION_DEVELOPMENT_COMPILER'
EVIDENCE_DIRECTORY = 'HEPTA_HIA_SOURCE_ADMISSION_EVIDENCE'
_FIXTURE = None
_FIXTURE_ERROR = None


def _json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('ascii')


def _write(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()


def _selection():
    cold, development = os.environ.get(COLD_REPORT), os.environ.get(DEVELOPMENT_COMPILER)
    if cold and development:
        raise ValueError('cold and development source-admission inputs are mutually exclusive')
    if not cold and not development:
        raise unittest.SkipTest('explicit fresh cold report or retained development compiler required')
    return cold, development


class _NativeFixture:
    def __init__(self):
        if sys.flags.optimize:
            raise RuntimeError('source-admission assertion controls require normal Python execution')
        cold, development = _selection()
        from tools import build_hia_source_admission as builder
        from tools.qualify_hia_selfhost import compile_stage
        evidence = os.environ.get(EVIDENCE_DIRECTORY)
        self.temporary = None
        if evidence:
            base = Path(evidence).resolve()
            base.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.folder = base / 'source-admission'
            self.folder.mkdir(mode=0o700)
        else:
            self.temporary = tempfile.TemporaryDirectory(prefix='hia-source-admission-')
            self.folder = Path(self.temporary.name)
        self.cold_sources = None
        self.snapshots = {ROOT / name: (ROOT / name).read_bytes()
                          for name in builder.DEVELOPMENT_INPUT_NAMES}
        if sha256(self.snapshots[REFERENCE]).hexdigest() != REFERENCE_SHA256:
            raise AssertionError('retained original HIA source changed')
        if cold:
            self.cold = Path(cold).resolve(strict=True)
            self.snapshots[self.cold] = self.cold.read_bytes()
            report = json.loads(self.snapshots[self.cold])
            nested_path = Path(report['nested_report'])
            self.snapshots[nested_path] = nested_path.read_bytes()
            nested = json.loads(self.snapshots[nested_path])
            self.compiler = Path(nested['generations'][-1]['produced_image']).resolve(strict=True)
            self.scope = 'MATCHING_SOURCE_COLD_BUILT_COMPONENT'
        else:
            self.cold = None
            self.compiler = Path(development).resolve(strict=True)
            self.scope = 'EXPLICIT_COMPILER_DEVELOPMENT_COMPONENT'
        self.snapshots[self.compiler] = self.compiler.read_bytes()
        if self.cold is not None:
            self.manifest = builder.build(self.folder / 'native', self.compiler, self.cold)
            self.cold_sources = builder.current_sources()
        else:
            self.manifest = builder.build_development(self.folder / 'native', self.compiler)
        self.metadata = json.loads(self.manifest.read_bytes())
        self.image_path = self.manifest.parent / self.metadata['image_path']
        self.native = adapter.installed_source_admission(self.manifest)
        self.compilation = {
            'image': str(self.image_path),
            'image_sha256': self.metadata['image_sha256'],
            'source_sha256': self.metadata['source_sha256'],
            'compiler_sha256': self.metadata['compiler_sha256'],
        }
        for path in self.manifest.parent.iterdir():
            if path.is_file():
                self.snapshots[path] = path.read_bytes()
        reference_folder = self.folder / 'reference'
        reference_folder.mkdir(mode=0o700)
        reference_path, receipt = compile_stage(
            reference_folder, 'source-admission-reference',
            self.compiler, self.snapshots[REFERENCE])
        reference_image = reference_path.read_bytes()
        builder.admit_compile_receipt(receipt, compiler_bytes=self.snapshots[self.compiler],
                                      source_bytes=self.snapshots[REFERENCE],
                                      image_bytes=reference_image)
        recorded = json.loads((reference_folder / 'source-admission-reference.receipt.json').read_bytes(),
                              object_pairs_hook=builder._pairs)
        builder.admit_compile_receipt(recorded, compiler_bytes=self.snapshots[self.compiler],
                                      source_bytes=self.snapshots[REFERENCE],
                                      image_bytes=reference_image)
        if _json_bytes(receipt) != _json_bytes(recorded):
            raise AssertionError('retained HIA reference compile receipt readback differs')
        self.reference = adapter.NativeSourceAdmissionImage(
            reference_image, sha256(reference_image).hexdigest(), REFERENCE, REFERENCE_SHA256)
        for path in reference_folder.iterdir():
            if path.is_file():
                self.snapshots[path] = path.read_bytes()
        self.check()
        self.observe('fixture.json', {
            'scope': self.scope, 'compiler_sha256': sha256(self.snapshots[self.compiler]).hexdigest(),
            'source_sha256': self.metadata['source_sha256'],
            'image_sha256': self.metadata['image_sha256'],
            'reference_source_sha256': REFERENCE_SHA256,
            'reference_image_sha256': self.reference.image_sha256,
            'original_compile_timeout_seconds': 20,
            'current_source_cold': self.cold is not None,
            'whole_stack_qualified': False, 'default_activated': False,
        })

    def observe(self, name, value):
        _write(self.folder / name, _json_bytes(value))

    def check(self):
        for path, raw in self.snapshots.items():
            if path.read_bytes() != raw:
                raise AssertionError('source-admission fixture input/output changed: ' + str(path))
        if self.cold_sources is not None:
            from tools.build_hia_source_admission import current_sources
            if current_sources() != self.cold_sources:
                raise AssertionError('cold source manifest changed during component controls')


def _fixture():
    global _FIXTURE, _FIXTURE_ERROR
    if _FIXTURE is None:
        if _FIXTURE_ERROR is not None:
            raise RuntimeError('prior native fixture setup failed; no implicit compile retry') from _FIXTURE_ERROR
        try:
            _FIXTURE = _NativeFixture()
        except unittest.SkipTest:
            raise
        except BaseException as error:
            _FIXTURE_ERROR = error
            raise
    return _FIXTURE


def tearDownModule():
    if _FIXTURE is not None:
        _FIXTURE.check()
        _FIXTURE.observe('custody-final.json', {
            'scope': _FIXTURE.scope, 'all_bound_bytes_unchanged': True,
            'snapshots': {str(p): {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}
                          for p, raw in _FIXTURE.snapshots.items()},
            'test_status': 'SEE_ORIGINAL_UNITTEST_RESULT',
        })
        if _FIXTURE.temporary is not None:
            _FIXTURE.temporary.cleanup()


def image():
    return _fixture().native




class SourceAdmissionSourceTests(unittest.TestCase):
    def test_generated_r3_asset_and_original_compiler_limits(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_source_admission import document
        raw = SOURCE.read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), FROZEN_HIA_SHA256)
        self.assertEqual(sha256(REFERENCE.read_bytes()).hexdigest(), REFERENCE_SHA256)
        doc = document()
        self.assertEqual(render_assembly(doc).encode(), raw)
        blocks = [block for function in doc['functions'] for block in function['blocks']]
        self.assertLessEqual(len(doc['functions']), 128)
        self.assertLessEqual(len(blocks), 1536)
        self.assertLessEqual(sum(len(block['ops']) for block in blocks), 8192)
        self.assertLessEqual(max(len(block['params']) for block in blocks), 16)
        self.assertLessEqual(len(raw), 1 << 20)

    def test_explicit_transport_has_no_authoring_or_default_policy_route(self):
        tree = ast.parse((ROOT / 'hepta/hia_source_admission_native.py').read_text())
        imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertFalse(any(name == 'tools' or (name or '').startswith('tools.') for name in imports))
        imports = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                   for alias in node.names]
        self.assertFalse(any(name == 'tools' or name.startswith('tools.') for name in imports))
        owner = next(node for node in tree.body
                     if isinstance(node, ast.ClassDef) and node.name == 'NativeFileDigests')
        calls = [node.func.id for node in ast.walk(owner)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertFalse({'sha256', 'sorted', 'set', 'file_digests', 'current_sources'} & set(calls))
        from tools import hia_selfhost_contract as contract
        import inspect
        default = ast.parse(inspect.getsource(contract.file_digests))
        self.assertNotIn('native_file_digests', ast.dump(default))
        self.assertNotIn('installed_source_admission', ast.dump(default))

    def test_fixture_requires_explicit_nonconflicting_compiler_authority(self):
        with patch.dict(os.environ, {COLD_REPORT: '', DEVELOPMENT_COMPILER: ''}):
            with self.assertRaises(unittest.SkipTest):
                _selection()
        with patch.dict(os.environ, {COLD_REPORT: '/cold', DEVELOPMENT_COMPILER: '/dev'}):
            with self.assertRaisesRegex(ValueError, 'mutually exclusive'):
                _selection()

    def test_production_builder_rejects_partial_cold_before_output_or_compile(self):
        from tools import build_hia_source_admission as builder
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            compiler, cold, output = folder / 'compiler', folder / 'cold', folder / 'output'
            compiler.write_bytes(b'unqualified compiler')
            for report in ({}, {'status': 'COLD_SELFHOST_REPLAY_PASS'},
                           {'scope': 'EXPLICIT_COMPILER_DEVELOPMENT_COMPONENT'}):
                cold.write_bytes(_json_bytes(report))
                with patch.object(builder, 'compile_stage', side_effect=AssertionError('cold refusal compiled')), \
                     patch.object(builder, 'build_development', side_effect=AssertionError('cold refusal fell back')):
                    with self.assertRaises(ValueError):
                        builder.build(output, compiler, cold)
                self.assertFalse(output.exists())
                self.assertEqual(compiler.read_bytes(), b'unqualified compiler')

    def test_production_builder_requires_every_component_source_in_admitted_closure(self):
        from tools import build_hia_source_admission as builder
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            compiler, cold, output = folder / 'compiler', folder / 'cold', folder / 'output'
            compiler.write_bytes(b'controlled gate test input')
            cold.write_bytes(b'{}')
            # A synthetic gate return tests the outer builder's mandatory
            # membership check only; it grants no real cold qualification.
            with patch.object(builder, 'admit_cold_build', return_value={}), \
                 patch.object(builder, 'compile_stage', side_effect=AssertionError('partial closure compiled')):
                with self.assertRaisesRegex(ValueError, 'complete matching cold'):
                    builder.build(output, compiler, cold)
            self.assertFalse(output.exists())


def init_wire(names, nonce=17, declared_count=None):
    n = len(names) if declared_count is None else declared_count
    raw = bytearray(struct.pack('<4Q', 0, nonce, n, len(names)-n))
    for i, name in enumerate(names):
        value = name.encode('utf-8', 'surrogatepass')
        raw += struct.pack('<2Q', i, len(value)) + value
    return bytes(raw)


def raw_call(native, wire, state, *, output_size=512, state_size=None):
    source = ctypes.create_string_buffer(wire+b'\x33'*16, len(wire)+16)
    output = ctypes.create_string_buffer(b'\x5a'*(output_size+16), output_size+16)
    before = source.raw
    code = native._entry(source, len(wire), output, output_size, state,
                         len(state) if state_size is None else state_size)
    assert source.raw == before
    assert output.raw[output_size:] == b'\x5a'*16
    return code, output.raw[:output_size]


def sealed_state(raw):
    """Independent test-only checksum, never runtime admission authority."""
    value = bytearray(raw)
    extent = struct.unpack_from('<Q', value, 64)[0]
    h = 14695981039346656037
    for i, b in enumerate(value[:extent]):
        if not 120 <= i < 128:
            h = ((h ^ b) * 1099511628211) & ((1 << 64)-1)
    struct.pack_into('<Q', value, 120, h)
    return bytes(value)


def vm_buffers(wires, state_size=1688, output_size=128):
    import ast
    from tools.generate_hia_source_admission import source_program
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    body = Body(0)
    owners, views = [], []
    for size in (output_size, state_size):
        owner = body.value('buffer', 'buffer.new', [body.const('usize', size)])
        owners.append(owner)
        views.append(body.value('mutbuf', 'borrow.mut', [owner]))
    results = []
    for wire in wires:
        owner = body.value('buffer', 'buffer.new', [body.const('usize', len(wire))])
        view = body.value('mutbuf', 'borrow.mut', [owner])
        for i, value in enumerate(wire):
            if value:
                body.effect('buffer.store', [view, body.const('usize', i), body.const('u8', value)])
        body.effect('loan.end', [view])
        read = body.value('readbuf', 'borrow.read', [owner])
        results.append(body.value('u32', 'call', [read, *views], {'function': 'f0'}))
        body.effect('loan.end', [read]); body.effect('owner.drop', [owner])
    observed = []
    names = {node.name: 'f'+str(i) for i, node in enumerate(ast.parse(source_program()).body)}
    for view, size in zip(views, (output_size, state_size)):
        # Losslessly pack the complete buffers into u64 returns so the original
        # 256-item assembly list limit remains unchanged.
        assert size % 8 == 0
        observed.extend(body.value('u64', 'call', [view, body.const('u64', i)],
                                   {'function': names['get']}) for i in range(0, size, 8))
    for view in views: body.effect('loan.end', [view])
    for owner in owners: body.effect('owner.drop', [owner])
    source = ('hia-asm.v1 hepta.hia.program.v8 source_admission_vm\n'
              'fn observe() -> ('+','.join(['u32']*len(results)+['u64']*len(observed))+') '
              'effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+body.text()
              +'  ret('+','.join([*results, *observed])+')\nend\n'
              +SOURCE.read_text().split('\n', 1)[1])
    with patch.dict(os.environ, {key: '' for key in os.environ if key.startswith('HEPTA_HIA_')}):
        actual = execute_program(assemble_program(source), 'observe', [], max_steps=2_000_000)
    if actual['status'] != 'returned':
        raise AssertionError(actual)
    raw = b''.join(struct.pack('<Q', value) for value in actual['values'][len(wires):])
    return actual['values'][:len(wires)], raw, actual['steps']


class NativeSourceAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = image()

    def test_sha_padding_random_vectors_and_no_8MiB_payload_cap(self):
        rng = random.Random(0x821256)
        vectors = [b'', b'abc', bytes(range(256)), b'a'*1_000_000]
        vectors += [rng.randbytes(n) for n in (1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256)]
        vectors += [rng.randbytes(rng.randrange(1025)) for _ in range(40)]
        vectors += [b'.\x00\x80\xff'*((8 << 20)//4+1)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for i, raw in enumerate(vectors):
                with self.subTest(size=len(raw), i=i):
                    (root/'input').write_bytes(raw)
                    result = self.native.create().run(root, ('input',))
                    self.assertEqual(result, {'input': sha256(raw).hexdigest()})

    def test_native_union_order_duplicates_unicode_long_names_and_empty_map(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'hepta').mkdir()
            names = ['z', 'a', 'é', '中', '😀', '\udcfe', 'x'*240]
            for i, name in enumerate(names): (root/name).write_bytes(bytes([i]))
            (root/'hepta'/'dynamic.py').write_bytes(b'dynamic')
            declared = tuple(reversed(names)) + ('z', 'a', 'hepta/dynamic.py')
            result = self.native.create().run(root, declared)
            expected = {name: sha256((root/name).read_bytes()).hexdigest()
                        for name in sorted(set(declared))}
            self.assertEqual(list(result.items()), list(expected.items()))
            (root/'hepta'/'dynamic.py').unlink()
            self.assertEqual(self.native.create().run(root, ()), {})
            for invalid in ('', 'a\x00b'):
                owner = self.native.create()
                with self.assertRaises((IsADirectoryError, ValueError)):
                    owner.run(root, (invalid,))
                self.assertFalse(owner.complete)
                self.assertEqual(owner.failure_receipt[0], 4)

    def test_stale_foreign_nonce_outcomes_and_mutated_state_refuse_without_write(self):
        state = ctypes.create_string_buffer(2048)
        self.assertEqual(raw_call(self.native, init_wire(['a']), state)[0], 0)
        self.assertEqual(raw_call(self.native, adapter.packet(1, 17, 0), state)[0], 0)
        pending = state.raw
        wires = [adapter.packet(1, 17, 0), adapter.packet(1, 17, 1),
                 adapter.packet(2, 18, 1, b'abc'), adapter.packet(2, 17, 0, b'abc'),
                 struct.pack('<4Q', 2, 17, 1, 4)+b'abc', struct.pack('<3Q', 8, 17, 1)]
        for wire in wires:
            with self.subTest(wire=wire.hex()):
                self.assertEqual(raw_call(self.native, wire, state)[0], 16)
                self.assertEqual(state.raw, pending)
        for offset in (0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 120, 1536, 1648):
            state = ctypes.create_string_buffer(pending, len(pending))
            state[offset] = bytes([state.raw[offset] ^ 1])
            before = state.raw
            self.assertEqual(raw_call(self.native, adapter.packet(2, 17, 1, b'abc'), state)[0], 16)
            self.assertEqual(state.raw, before)
        state = ctypes.create_string_buffer(pending, len(pending))
        self.assertEqual(raw_call(self.native, adapter.packet(2, 17, 1, b'abc'), state)[0], 0)
        done = state.raw
        self.assertEqual(raw_call(self.native, adapter.packet(2, 17, 1, b'abc'), state)[0], 16)
        self.assertEqual(state.raw, done)

    def test_capacity_and_sequence_exhaustion_refuse_without_wrap_or_partial_map(self):
        wire = init_wire(['a'])
        small = ctypes.create_string_buffer(1536)
        code, output = raw_call(self.native, wire, small)
        self.assertEqual(code, 1); self.assertEqual(small.raw, b'\0'*1536)
        extent = struct.unpack_from('<Q', output, 40)[0]
        state = ctypes.create_string_buffer(extent)
        self.assertEqual(raw_call(self.native, wire, state)[0], 0)
        struct.pack_into('<Q', state, 32, (1 << 64)-1)
        value = sealed_state(state.raw); state = ctypes.create_string_buffer(value, len(value))
        before = state.raw
        self.assertEqual(raw_call(self.native, adapter.packet(1, 17, (1 << 64)-1), state)[0], 16)
        self.assertEqual(state.raw, before)
        fresh = ctypes.create_string_buffer(extent)
        raw_call(self.native, wire, fresh); raw_call(self.native, adapter.packet(1, 17, 0), fresh)
        raw_call(self.native, adapter.packet(2, 17, 1, b'abc'), fresh)
        before = fresh.raw
        code, output = raw_call(self.native, adapter.packet(1, 17, 1), fresh, output_size=48)
        self.assertEqual(code, 1); self.assertEqual(fresh.raw, before)
        self.assertEqual(struct.unpack_from('<6Q', output)[:2], (1, 6))
        self.assertEqual(raw_call(self.native, adapter.packet(1, 17, 1), fresh)[0], 0)
        complete = fresh.raw
        self.assertEqual(raw_call(self.native, adapter.packet(1, 17, 1), fresh)[0], 16)
        self.assertEqual(fresh.raw, complete)

    def test_malformed_init_and_state_canaries(self):
        valid = init_wire(['a'])
        malformed = [b'', b'\0'*8, valid[:-1], valid+b'x',
                     struct.pack('<4Q', 0, 0, 0, 0), struct.pack('<4Q', 0, 17, (1 << 64)-1, 2),
                     struct.pack('<4Q', 0, 17, 1, 0)+struct.pack('<2Q', 9, 1)+b'a']
        for wire in malformed:
            state = ctypes.create_string_buffer(b'\0'*2048+b'\xa5'*16, 2064)
            code, _ = raw_call(self.native, wire, state, state_size=2048)
            self.assertIn(code, (16, 0xfffffff1))
            self.assertEqual(state.raw, b'\0'*2048+b'\xa5'*16)
        state = ctypes.create_string_buffer(b'\0'*2048+b'\xa5'*16, 2064)
        self.assertEqual(raw_call(self.native, valid, state, state_size=2048)[0], 0)
        self.assertEqual(state.raw[2048:], b'\xa5'*16)
        before = state.raw
        self.assertEqual(raw_call(self.native, valid, state, state_size=2048)[0], 16)
        self.assertEqual(state.raw, before)

    def test_unknown_native_pre_and_post_entry_never_retry_or_return_partial_map(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'a').write_bytes(b'a'); (root/'b').write_bytes(b'b')
            for target in (1, 2):
                for after in (False, True):
                    owner = self.native.create()
                    real = self.native._entry
                    count = []
                    class LostAck(BaseException): pass
                    def entry(s, sn, o, on, w, wn):
                        operation = struct.unpack('<Q', ctypes.string_at(s, 8))[0]
                        if operation == target:
                            count.append(operation)
                            if after: real(s, sn, o, on, w, wn)
                            raise LostAck('native acknowledgement lost')
                        return real(s, sn, o, on, w, wn)
                    with patch.object(self.native, '_entry', entry):
                        with self.assertRaises(LostAck): owner.run(root, ('a', 'b'))
                        before = (owner.state.raw, owner.reads, owner.calls)
                        with self.assertRaises(adapter.SourceAdmissionRefused): owner.run(root, ('a', 'b'))
                        self.assertEqual((owner.state.raw, owner.reads, owner.calls), before)
                    self.assertEqual(count, [target]); self.assertIsNotNone(owner.pending)
                    self.assertFalse(owner.complete); self.assertLessEqual(owner.reads, 1)

    def test_foreign_error_original_object_close_order_and_failed_note_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'a').write_bytes(b'a')
            owner = self.native.create(); error = OSError(5, 'original exact error')
            real = self.native._entry
            def entry(s, sn, o, on, w, wn):
                if struct.unpack('<Q', ctypes.string_at(s, 8))[0] == 3:
                    raise KeyboardInterrupt('diagnostic ACK loss')
                return real(s, sn, o, on, w, wn)
            with patch.object(Path, 'read_bytes', side_effect=error), patch.object(self.native, '_entry', entry):
                try: owner.run(root, ('a',))
                except OSError as caught: self.assertIs(caught, error)
                else: self.fail('foreign exception swallowed')
            self.assertIs(owner.failure, error); self.assertIsNotNone(owner.pending)
            self.assertFalse(owner.complete)

    def test_transport_reentrancy_and_private_concurrency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'a').write_bytes(b'a')
            owner = self.native.create(); real = Path.read_bytes; reentered = []
            def read(path):
                with self.assertRaises(adapter.SourceAdmissionRefused): owner.run(root, ('a',))
                reentered.append(True)
                return real(path)
            with patch.object(Path, 'read_bytes', read):
                self.assertEqual(owner.run(root, ('a',)), {'a': sha256(b'a').hexdigest()})
            self.assertEqual(reentered, [True])
            with ThreadPoolExecutor(max_workers=4) as pool:
                values = list(pool.map(lambda _: self.native.create().run(root, ('a',)), range(16)))
            self.assertEqual(values, [{'a': sha256(b'a').hexdigest()}]*16)

    def test_source_and_image_drift_refuse_before_mapping(self):
        compilation = _fixture().compilation
        with tempfile.TemporaryDirectory() as directory:
            wrong = Path(directory)/'source'; wrong.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'source identity'):
                adapter.NativeSourceAdmissionImage(Path(compilation['image']).read_bytes(),
                    compilation['image_sha256'], wrong, compilation['source_sha256'])
            with self.assertRaisesRegex(ValueError, 'executable identity'):
                adapter.NativeSourceAdmissionImage(b'changed', compilation['image_sha256'],
                    SOURCE, compilation['source_sha256'])


class IndependentVMTests(unittest.TestCase):
    def test_complete_state_and_output_bytes_match_actual_machine(self):
        native = image()
        wires = [init_wire(['a']), adapter.packet(1, 17, 0),
                 adapter.packet(2, 17, 1, b'abc'), adapter.packet(1, 17, 1)]
        for selected in (wires, wires[:2]+[struct.pack('<4Q', 3, 17, 1, 77)]):
            state = ctypes.create_string_buffer(1688)
            results = []
            for wire in selected:
                code, output = raw_call(native, wire, state, output_size=128)
                results.append(code)
            expected = output+state.raw
            actual_results, actual, steps = vm_buffers(selected)
            self.assertEqual(actual_results, results)
            self.assertEqual(actual, expected)
            path = _fixture().folder/('vm-complete.json' if len(selected)==4 else 'vm-failed.json')
            path.write_text(json.dumps({'results': results, 'steps': steps,
                'complete_output_and_state_equal': True, 'bytes': len(actual),
                'sha256': sha256(actual).hexdigest()}, indent=2)+'\n')


class OptimizedEquivalenceTests(unittest.TestCase):
    def test_every_transition_output_and_state_equal_original_HIA_machine(self):
        original = _fixture().reference
        optimized = image()
        rng = random.Random(0x821512)
        transitions = 0
        for trial in range(16):
            names = [rng.choice(('z', 'a', 'é', '中', '😀', '\udcff'))+str(rng.randrange(12))
                     for _ in range(trial+1)]
            payloads = {name: rng.randbytes(rng.randrange(1537)) for name in names}
            states = [ctypes.create_string_buffer(8192), ctypes.create_string_buffer(8192)]
            nonce = 0x765000+trial
            def compare(wire):
                nonlocal transitions
                left = raw_call(original, wire, states[0], output_size=2048)
                right = raw_call(optimized, wire, states[1], output_size=2048)
                self.assertEqual(right, left)
                self.assertEqual(states[1].raw, states[0].raw)
                transitions += 1
                return struct.unpack_from('<6Q', right[1]), right[1]
            reply, _ = compare(init_wire(names, nonce=nonce, declared_count=len(names)//2))
            self.assertEqual(reply[0:2], (0, 0)); sequence=0
            while True:
                reply, raw = compare(adapter.packet(1, nonce, sequence))
                if reply[1] == 2:
                    actual={}
                    for i in range(reply[4]):
                        handle=struct.unpack_from('<Q',raw,48+i*72)[0]
                        actual[names[handle]]=raw[56+i*72:120+i*72].decode()
                    self.assertEqual(list(actual), sorted(payloads))
                    self.assertEqual(actual, {n:sha256(v).hexdigest() for n,v in payloads.items()})
                    break
                self.assertEqual(reply[0:2], (0, 1)); sequence=reply[3]
                compare(adapter.packet(2, nonce, sequence, payloads[names[reply[4]]]))
        (_fixture().folder/'optimized-transition-equivalence.json').write_text(json.dumps({
            'cases':16,'transitions':transitions,'all_output_and_state_bytes_equal':True,
            'original_image_sha256':original.image_sha256,'optimized_image_sha256':optimized.image_sha256,
            'independent_sha_oracle_equal':True},indent=2)+'\n')


class ReceiptConsistencyTests(unittest.TestCase):
    def test_truncated_or_conflicting_complete_count_is_unknown_without_partial_map(self):
        native = image()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'a').write_bytes(b'a');(root/'b').write_bytes(b'b')
            for altered_count in (0,1,3):
                owner=native.create(nonce=91);real=native._entry;hits=[]
                def entry(s,sn,o,on,w,wn):
                    code=real(s,sn,o,on,w,wn)
                    reply=struct.unpack('<6Q',ctypes.string_at(o,48))
                    if reply[:2]==(0,2):
                        hits.append(reply)
                        ctypes.memmove(o,struct.pack('<6Q',0,2,reply[2],reply[3],
                            altered_count,48+altered_count*72),48)
                    return code
                with patch.object(native,'_entry',entry):
                    with self.assertRaises(adapter.SourceAdmissionUnknown):owner.run(root,('a','b'))
                    before=(owner.state.raw,owner.reads,owner.calls)
                    with self.assertRaises(adapter.SourceAdmissionRefused):owner.run(root,('a','b'))
                    self.assertEqual((owner.state.raw,owner.reads,owner.calls),before)
                self.assertEqual(len(hits),1);self.assertFalse(owner.complete)
                self.assertEqual(struct.unpack_from('<Q',owner.state,48)[0],2)

    def test_wrong_initial_count_cannot_authorize_surplus_file_reads(self):
        native=image();owner=native.create(nonce=92);real=native._entry;hits=[]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'a').write_bytes(b'a')
            def entry(s,sn,o,on,w,wn):
                code=real(s,sn,o,on,w,wn)
                reply=struct.unpack('<6Q',ctypes.string_at(o,48))
                if reply[:2]==(0,0) and reply[3]==0:
                    hits.append(reply)
                    ctypes.memmove(o,struct.pack('<6Q',0,0,reply[2],0,0,reply[5]),48)
                return code
            with patch.object(native,'_entry',entry):
                with self.assertRaises(adapter.SourceAdmissionUnknown):owner.run(root,('a',))
            self.assertEqual(len(hits),1);self.assertEqual(owner.reads,0);self.assertFalse(owner.complete)

def _freshness_controls(folder, image):
    from tools import hia_selfhost_contract as contract
    original = contract.file_digests
    real_open, real_sha = io.open, sha256
    evidence = folder / 'freshness'
    evidence.mkdir(mode=0o700)
    control_root = evidence / 'source'
    control_root.mkdir(mode=0o700)
    baseline = original(ROOT)
    for name, expected in baseline.items():
        raw = (ROOT / name).read_bytes()
        if real_sha(raw).hexdigest() != expected:
            raise AssertionError('source changed while copying freshness control inputs')
        path = control_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    compilation = _fixture().compilation
    report = {'scope': _fixture().scope + '_ORIGINAL_ELEVEN_FRESHNESS_CONTROLS',
              'python': sys.version, 'image_sha256': compilation['image_sha256'],
              'source_sha256': compilation['source_sha256'], 'controls': [],
              'original_control_report': 'retained prototype COMPARISON.json; immutable archive provenance documented',
              'original_control_report_sha256': 'b262f49e6bd309bf9cea2ffff8383705bb6f242420389880909dea1cad26c3f9',
              'native_stage_events_are_boundary_observations': True,
              'hex_fault_is_after_HIA_digest_ACK_boundary_not_internal_hex_failure': True,
              'current_source_cold': _fixture().cold is not None,
              'whole_cold': False, 'full': False, 'default': False, 'live': False, 'deletion': False,
              'original_limits_changed': False}
    before = original(control_root)
    expected_order = list(before)
    assert before == baseline
    count = len(before)
    assert count >= 3 and 'tests/__init__.py' in before
    def save():
        (evidence/'RESULT.json').write_text(json.dumps(report, indent=2)+'\n')
    save()

    def observe(native=False, *, read_error=None, close_error=None, hash_error=None, hex_error=None):
        events=[]; current=[None]; owner = image.create() if native else None
        class Stream:
            def __init__(self, file, name): self.file,self.name=file,name
            def __enter__(self): events.append(['enter',self.name]);self.file.__enter__();return self
            def read(self,*a,**kw):
                events.append(['read',self.name])
                if self.name==read_error: raise OSError(5,'injected read failure',self.name)
                return self.file.read(*a,**kw)
            def __exit__(self,*args):
                events.append(['close',self.name]);r=self.file.__exit__(*args)
                if self.name==close_error: raise OSError(5,'injected close failure',self.name)
                return r
        def opener(file,*args,**kwargs):
            name=Path(file).relative_to(control_root).as_posix()
            current[0]=name;events.append(['open',name])
            return Stream(real_open(file,*args,**kwargs),name)
        class Hash:
            def __init__(self,value,name):self.value,self.name=value,name
            def hexdigest(self):
                events.append(['hexdigest',self.name])
                if self.name==hex_error: raise ValueError('injected hexdigest failure')
                return self.value.hexdigest()
        def sha(raw):
            if native: raise AssertionError('selected native owner called original Python file hash')
            name=current[0];events.append(['sha256',name])
            if name==hash_error:raise ValueError('injected hash failure')
            return Hash(real_sha(raw),name)
        if native:
            actual_invoke = owner._invoke
            def invoke(wire):
                if int.from_bytes(wire[:8], 'little') == 2:
                    name = current[0]
                    events.append(['sha256', name])
                    if name == hash_error: raise ValueError('injected hash failure')
                    receipt = actual_invoke(wire)
                    events.append(['hexdigest', name])
                    if name == hex_error: raise ValueError('injected hexdigest failure')
                    return receipt
                return actual_invoke(wire)
            owner._invoke = invoke
        result=None;error=None; started=time.perf_counter()
        try:
            with patch.object(io,'open',opener), patch.object(contract,'sha256',sha):
                result = owner.run(control_root, contract.SOURCE_FILES) if native else original(control_root)
        except BaseException as exc:
            error={'class':type(exc).__qualname__,'args':repr(exc.args),
                   'errno':getattr(exc,'errno',None),'filename':getattr(exc,'filename',None),
                   'cause':None if exc.__cause__ is None else type(exc.__cause__).__qualname__,
                   'context':None if exc.__context__ is None else type(exc.__context__).__qualname__}
        row={'events':events,'result_items':None if result is None else list(result.items()),'error':error}
        custody = None
        if native:
            custody = owner.snapshot(); state=custody.pop('state')
            custody['state_sha256']=real_sha(state).hexdigest()
            if error:
                old=(owner.calls,owner.reads,state)
                try:owner.run(control_root,contract.SOURCE_FILES)
                except RuntimeError:pass
                else:raise AssertionError('failed single-use owner replayed')
                assert (owner.calls,owner.reads,owner.state.raw)==old
                assert not owner.complete
        return row, {'wall_seconds': time.perf_counter()-started, 'custody': custody}

    def paired(name, **kwargs):
        original_row,original_info=observe(**kwargs)
        native_row,native_info=observe(True,**kwargs)
        row={'name':name,'original':original_row,'native':native_row,
             'original_info':original_info,'native_info':native_info,'equal':original_row==native_row}
        report['controls'].append(row);save()
        assert original_row==native_row,name
        return original_row

    started=time.perf_counter()
    try:
        r=paired('all_current_sources_original_read_close_hash_order')
        assert r['error'] is None and len(r['events'])==6*count
        assert r['events']==[[event,name] for name in expected_order
                            for event in ('open','enter','read','close','sha256','hexdigest')]
        target=control_root/expected_order[0];raw=target.read_bytes();old=target.stat()
        try:
            target.write_bytes(raw+b'\n# development freshness witness\n')
            os.utime(target,ns=(old.st_atime_ns,old.st_mtime_ns))
            r=paired('changed_bytes_with_original_mtime')
            changed=dict(r['result_items'])
            assert changed[expected_order[0]]!=before[expected_order[0]]
            assert {n for n in changed if changed[n]!=before[n]}=={expected_order[0]}
        finally:
            target.write_bytes(raw);os.utime(target,ns=(old.st_atime_ns,old.st_mtime_ns))
        dynamic=control_root/'hepta'/'zz_development_fresh_witness.py'
        try:
            dynamic.write_bytes(b'# new fresh source input\n')
            r=paired('new_dynamic_python_file_observed')
            assert len(r['result_items'])==count+1 and 'hepta/zz_development_fresh_witness.py' in dict(r['result_items'])
        finally:dynamic.unlink()
        r=paired('removed_dynamic_python_file_not_cached');assert dict(r['result_items'])==before
        first,second=expected_order[:2];moved=[]
        try:
            for i,name in enumerate((first,second)):
                source=control_root/name;backup=evidence/f'native-control-original-missing-{i}'
                source.rename(backup);moved.append((source,backup))
            r=paired('two_missing_inputs_first_sorted_error')
            assert r['error']['class']=='FileNotFoundError' and r['events']==[['open',first]]
        finally:
            for source,backup in reversed(moved):backup.rename(source)
        name='tests/__init__.py';source=control_root/name;backup=evidence/'native-control-original-directory-input'
        source.rename(backup);source.mkdir()
        try:
            r=paired('regular_input_replaced_with_directory')
            assert r['error']['class']=='IsADirectoryError' and r['events'][-1]==['open',name]
        finally:source.rmdir();backup.rename(source)
        for label,key in [('read_failure_prefix','read_error'),('close_failure_prefix','close_error'),
                          ('hash_failure_prefix','hash_error'),('hexdigest_failure_prefix','hex_error')]:
            r=paired(label,**{key:second});assert r['error'] is not None
            assert not any(event==['open',expected_order[2]] for event in r['events'])
        source=control_root/second;backup=evidence/'native-control-original-later-missing';source.rename(backup)
        try:
            r=paired('earlier_hash_failure_precedes_later_missing_read',hash_error=first)
            assert r['error']['class']=='ValueError' and ['open',second] not in r['events']
        finally:backup.rename(source)
        assert original(control_root)==before and original(ROOT)==before
        report.update(status='PASS', source_before_after_equal=True, control_source_restored=True)
    except BaseException:
        report.update(status='FAIL', traceback=traceback.format_exc())
    finally:
        report['wall_seconds']=time.perf_counter()-started
        save()
        summary={k:v for k,v in report.items() if k!='controls'}
        summary['controls']=[{'name':r['name'],'equal':r['equal'],
            'original_error':r['original']['error'], 'native_info':r['native_info']} for r in report['controls']]
        summary['raw_report_bytes']=(evidence/'RESULT.json').stat().st_size
        summary['raw_report_sha256']=real_sha((evidence/'RESULT.json').read_bytes()).hexdigest()
        (evidence/'SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n')
        print(json.dumps(summary,indent=2))
    if report['status'] != 'PASS':
        raise AssertionError(report['traceback'])
    assert len(report['controls']) == 11
    return summary


class SourceAdmissionFreshnessTests(unittest.TestCase):
    def test_all_eleven_original_read_close_hash_failure_and_freshness_controls(self):
        fixture = _fixture()
        summary = _freshness_controls(fixture.folder, fixture.native)
        self.assertEqual(summary['status'], 'PASS')
        self.assertEqual(len(summary['controls']), 11)
        self.assertTrue(all(row['equal'] for row in summary['controls']))
        self.assertTrue(summary['source_before_after_equal'])
        self.assertTrue(summary['control_source_restored'])


class SourceAdmissionCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = _fixture()

    def _selection_files(self, name):
        folder = self.fixture.folder / name
        folder.mkdir(mode=0o700)
        source = folder / 'source.hiaasm'
        source.write_bytes(SOURCE.read_bytes())
        image_path = folder / 'image.bin'
        image_path.write_bytes(self.fixture.image_path.read_bytes())
        metadata = dict(self.fixture.metadata, image_path=image_path.name)
        manifest = folder / 'manifest.json'
        manifest.write_bytes(_json_bytes(metadata))
        return folder, source, image_path, manifest, metadata

    def test_warm_selection_rehashes_source_image_and_manifest_without_replacing_pinned_code(self):
        folder, source, image_path, manifest, metadata = self._selection_files('warm-custody')
        inputs = folder / 'inputs'
        inputs.mkdir()
        (inputs / 'a').write_bytes(b'actual native fresh source')
        expected = {'a': sha256(b'actual native fresh source').hexdigest()}
        with patch.object(adapter, 'SOURCE', source):
            first = adapter.installed_source_admission(manifest)
            self.assertIs(adapter.installed_source_admission(manifest), first)
            self.assertEqual(first.create().run(inputs, ('a',)), expected)
            for target, message in ((source, 'source identity'),
                                    (image_path, 'executable identity')):
                raw, stat = target.read_bytes(), target.stat()
                try:
                    target.write_bytes(raw + b'\nchanged with unchanged timestamp')
                    os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns))
                    with patch.object(adapter, '_mapped', side_effect=AssertionError('changed bytes reached mapping')):
                        with self.assertRaisesRegex(ValueError, message):
                            adapter.installed_source_admission(manifest)
                    # A previously returned immutable mapping is still exactly
                    # the selected code, independently of a later failed load.
                    self.assertEqual(first.create().run(inputs, ('a',)), expected)
                finally:
                    target.write_bytes(raw)
                    os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns))
                self.assertIs(adapter.installed_source_admission(manifest), first)
            for target in (source, image_path, manifest):
                raw = target.read_bytes()
                target.unlink()
                try:
                    with self.assertRaises(OSError):
                        adapter.installed_source_admission(manifest)
                finally:
                    target.write_bytes(raw)
            self.assertIs(adapter.installed_source_admission(manifest), first)
        self.fixture.observe('warm-custody.json', {
            'fresh_source_and_image_bytes_checked_with_original_mtime': True,
            'missing_source_image_manifest_refused': True,
            'prior_immutable_mapping_retained': True,
        })

    def test_malformed_manifest_and_foreign_paths_refuse_before_mapping(self):
        folder, source, image_path, manifest, metadata = self._selection_files('manifest-refusals')
        controls = [b'{}', b'null', b'\xff',
                    _json_bytes(dict(metadata, schema='old')),
                    _json_bytes(dict(metadata, source_sha256=True)),
                    _json_bytes(dict(metadata, image_sha256='G' * 64)),
                    _json_bytes(dict(metadata, compiler_sha256='0')),
                    _json_bytes(dict(metadata, extra=0)),
                    b'{"schema":"duplicate","schema":"duplicate"}',
                    b' ' * (adapter.MAX_MANIFEST_BYTES + 1)]
        controls += [_json_bytes(dict(metadata, image_path=value))
                     for value in ('', '.', '..', '../image.bin', '/image.bin', 'a\x00b', 0, None)]
        with patch.object(adapter, 'SOURCE', source), \
             patch.object(adapter, '_mapped', side_effect=AssertionError('malformed manifest mapped')):
            for raw in controls:
                manifest.write_bytes(raw)
                with self.subTest(raw=raw[:150]):
                    with self.assertRaises((ValueError, UnicodeError)):
                        adapter.installed_source_admission(manifest)
        manifest.write_bytes(_json_bytes(metadata))
        self.assertEqual(image_path.read_bytes(), self.fixture.image_path.read_bytes())
        self.fixture.observe('manifest-refusals.json', {'controls': len(controls), 'mappings': 0})

    def test_changed_admission_readback_is_refused_after_real_mapping(self):
        folder, source, image_path, manifest, metadata = self._selection_files('admission-readback')
        with patch.object(adapter, 'SOURCE', source):
            real = adapter._mapped
            hits = []
            for target in (source, image_path, manifest):
                raw = target.read_bytes()
                def change_after_mapping(*args):
                    result = real(*args)
                    target.write_bytes(raw + b'\n')
                    hits.append(str(target))
                    return result
                try:
                    with patch.object(adapter, '_mapped', side_effect=change_after_mapping):
                        with self.assertRaisesRegex(ValueError, 'changed during admission'):
                            adapter.installed_source_admission(manifest)
                finally:
                    target.write_bytes(raw)
            self.assertEqual(len(hits), 3)
            selected = adapter.installed_source_admission(manifest)
            self.assertEqual(selected.image_sha256, metadata['image_sha256'])
        self.fixture.observe('admission-readback.json', {'changed_inputs_refused': hits})


class SourceAdmissionBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = _fixture()

    def _compile_transport(self, *, mutate=None, collision=False):
        """Inject at the fixed compiler transport using actual retained bytes.

        This does not re-run a compiler or establish a new cold result. It
        checks this builder's refusal/publication boundaries independently.
        """
        fixture = self.fixture
        original = json.loads((fixture.manifest.parent / 'source-admission.receipt.json').read_bytes())
        image_bytes = fixture.image_path.read_bytes()
        def compile_result(output, label, compiler, source):
            self.assertEqual(label, 'source-admission')
            self.assertEqual(compiler.read_bytes(), fixture.snapshots[fixture.compiler])
            self.assertEqual(source, fixture.snapshots[SOURCE])
            image_path = output / (label + '.image.bin')
            image_path.write_bytes(image_bytes)
            receipt = dict(original, case=label, produced_image=str(image_path))
            if mutate:
                mutate(receipt)
            (output / (label + '.receipt.json')).write_bytes(_json_bytes(receipt))
            if collision:
                (output / 'development-manifest.json').write_bytes(b'previous publication')
            return image_path, receipt
        return compile_result

    def test_exact_actual_receipt_required_and_existing_manifest_never_overwritten(self):
        from tools import build_hia_source_admission as builder
        changes = {
            'boolean_status_word': lambda value: value.update(abi_status=False),
            'wrong_input': lambda value: value.update(input_sha256='0' * 64),
            'wrong_output': lambda value: value.update(produced_sha256='0' * 64),
            'wrong_byte_count': lambda value: value.update(produced_bytes=value['produced_bytes'] + 1),
            'missing_unchanged': lambda value: value.pop('source_unchanged'),
            'wrong_invocation': lambda value: value.update(case='another-compile'),
            'wrong_image_path': lambda value: value.update(produced_image='elsewhere.image.bin'),
        }
        for name, mutate in changes.items():
            output = self.fixture.folder / ('bad-receipt-' + name)
            with self.subTest(case=name), patch.object(builder, 'compile_stage',
                    side_effect=self._compile_transport(mutate=mutate)):
                with self.assertRaises(ValueError):
                    builder.build_development(output, self.fixture.compiler)
                self.assertFalse((output / 'development-manifest.json').exists())
        output = self.fixture.folder / 'publication-collision'
        with patch.object(builder, 'compile_stage',
                          side_effect=self._compile_transport(collision=True)):
            with self.assertRaises(FileExistsError):
                builder.build_development(output, self.fixture.compiler)
        self.assertEqual((output / 'development-manifest.json').read_bytes(), b'previous publication')
        with patch.object(builder, 'compile_stage', side_effect=AssertionError('existing output recompiled')):
            with self.assertRaises(FileExistsError):
                builder.build_development(output, self.fixture.compiler)

    def test_receipt_disk_and_consumed_source_readback_precede_manifest_publication(self):
        from tools import build_hia_source_admission as builder
        output = self.fixture.folder / 'receipt-readback-drift'
        real = self._compile_transport()
        def receipt_drift(*args):
            image_path, receipt = real(*args)
            recorded = dict(receipt, case='different-readback')
            (args[0] / 'source-admission.receipt.json').write_bytes(_json_bytes(recorded))
            return image_path, receipt
        with patch.object(builder, 'compile_stage', side_effect=receipt_drift):
            with self.assertRaisesRegex(ValueError, 'receipt readback differs'):
                builder.build_development(output, self.fixture.compiler)
        self.assertFalse((output / 'development-manifest.json').exists())
        # Mutate an isolated component copy, never the checked-out source.
        copy_root = self.fixture.folder / 'build-input-copy'
        copy_root.mkdir(mode=0o700)
        for name in builder.DEVELOPMENT_INPUT_NAMES:
            path = copy_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
        output = self.fixture.folder / 'source-readback-drift'
        def source_drift(*args):
            value = real(*args)
            path = copy_root / builder.SOURCE_NAME
            path.write_bytes(path.read_bytes() + b'\nchanged after compile')
            return value
        with patch.object(builder, 'ROOT', copy_root), \
             patch.object(builder, 'compile_stage', side_effect=source_drift):
            with self.assertRaisesRegex(ValueError, 'input or output bytes changed'):
                builder.build_development(output, self.fixture.compiler)
        self.assertFalse((output / 'development-manifest.json').exists())




class SourceAdmissionInstalledTests(unittest.TestCase):
    def test_real_wheel_resource_custody_without_authoring_or_checkout_fallback(self):
        fixture = _fixture()
        work = fixture.folder / 'installed-wheel'
        work.mkdir(mode=0o700)
        project = work / 'project'
        project.mkdir(mode=0o700)
        for name in ('pyproject.toml', 'setup.py', 'MANIFEST.in', 'README.md'):
            shutil.copyfile(ROOT / name, project / name)
        for path in ROOT.glob('LICENSE*'):
            if path.is_file():
                shutil.copyfile(path, project / path.name)
        shutil.copytree(ROOT / 'hepta', project / 'hepta',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '_data'))
        tree = ast.parse((ROOT / 'hepta/hia_agent_contract.py').read_text())
        resources = []
        for symbol in ('DISCOVERY_FILES', 'NATIVE_SOURCE_FILES', 'SOURCE_BUILD_FILES', 'COMPILER_BUILD_FILES', 'PUBLICATION_BUILD_FILES'):
            rows = [node for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == symbol
                            for target in node.targets)]
            self.assertEqual(len(rows), 1, symbol)
            names = ast.literal_eval(rows[0].value)
            resources.extend(('docs/' + name for name in names)
                             if symbol == 'DISCOVERY_FILES' else names)
        self.assertIn(adapter.SOURCE_NAME, resources, 'source-admission installed resource is not registered')
        self.assertEqual(resources.count(adapter.SOURCE_NAME), 1)
        for name in resources:
            path = project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        wheels = work / 'wheels'
        wheels.mkdir()
        built = subprocess.run([sys.executable, '-B', '-m', 'pip', 'wheel', '--no-deps',
            '--no-build-isolation', '--wheel-dir', str(wheels), str(project)],
            capture_output=True, timeout=120)
        _write(work / 'wheel.stdout', built.stdout)
        _write(work / 'wheel.stderr', built.stderr)
        self.assertEqual(built.returncode, 0, built.stderr.decode('utf-8', 'replace'))
        packages = list(wheels.glob('*.whl'))
        self.assertEqual(len(packages), 1)
        installed = work / 'installed'
        installed.mkdir()
        with zipfile.ZipFile(packages[0]) as wheel:
            names = wheel.namelist()
            self.assertFalse(any(name.startswith('tools/') for name in names))
            wanted = 'hepta/_data/' + adapter.SOURCE_NAME
            self.assertEqual(wheel.read(wanted), SOURCE.read_bytes())
            for row in wheel.infolist():
                self.assertFalse(Path(row.filename).is_absolute() or '..' in Path(row.filename).parts)
                self.assertNotEqual((row.external_attr >> 16) & 0o170000, 0o120000)
            wheel.extractall(installed)
        child = r'''
import importlib.abc,json,os,sys
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed source admission imported authoring tools')
sys.meta_path.insert(0,NoAuthoring())
import hepta.hia_source_admission_native as native
installed=Path(sys.argv[1]).resolve()
assert Path(native.__file__).resolve().is_relative_to(installed)
assert native.SOURCE.resolve().is_relative_to(installed/'hepta'/'_data')
owner=native.installed_source_admission(sys.argv[2])
root=Path(sys.argv[3]);root.mkdir();(root/'hepta').mkdir()
(root/'z').write_bytes(b'z');(root/'hepta'/'dynamic.py').write_bytes(b'# fresh source')
expected={'hepta/dynamic.py':sha256(b'# fresh source').hexdigest(),'z':sha256(b'z').hexdigest()}
with patch.object(native,'sha256',side_effect=AssertionError('hosted file digest called')):
    actual=native.native_file_digests(root,owner,source_files=('z',))
assert actual==expected and list(actual)==list(expected)
source=native.SOURCE;raw=source.read_bytes()
# A matching cwd copy is deliberately available. A missing installed resource
# must still fail; neither cwd nor a prior immutable mapping grants admission.
fallback=Path.cwd()/native.SOURCE_NAME;fallback.parent.mkdir(parents=True,exist_ok=True)
fallback.write_bytes(raw)
source.unlink()
try:
    try:native.installed_source_admission(sys.argv[2])
    except OSError:pass
    else:raise AssertionError('missing installed source fell back to cwd or warm mapping')
finally:source.write_bytes(raw)
source.write_bytes(raw+b'\nchanged')
try:
    try:native.installed_source_admission(sys.argv[2])
    except ValueError:pass
    else:raise AssertionError('changed installed resource reused warm mapping')
finally:source.write_bytes(raw)
assert native.installed_source_admission(sys.argv[2]) is owner
assert not any(name=='tools' or name.startswith('tools.') for name in sys.modules)
print(json.dumps({'actual_HIA_fresh_map':True,'missing_resource_refused':True,
 'changed_resource_refused':True,'cwd_fallback_refused':True,
 'hosted_file_hash_called':False,'authoring_imported':False}))
'''
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('HEPTA_HIA_') and key not in {'PYTHONPATH', 'PYTHONHOME'}}
        environment['PATH'] = ''
        ran = subprocess.run([sys.executable, '-I', '-B', '-c', child,
                              str(installed), str(fixture.manifest), str(work / 'inputs')],
                             cwd=work, env=environment, capture_output=True, timeout=30)
        _write(work / 'application.stdout', ran.stdout)
        _write(work / 'application.stderr', ran.stderr)
        self.assertEqual(ran.returncode, 0, ran.stderr.decode('utf-8', 'replace'))
        fixture.observe('installed-wheel.json', {
            'wheel': {'bytes': packages[0].stat().st_size,
                      'sha256': sha256(packages[0].read_bytes()).hexdigest()},
            'result': json.loads(ran.stdout),
            'scope': fixture.scope,
        })


if __name__ == '__main__':
    unittest.main(verbosity=2)
