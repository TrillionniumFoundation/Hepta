"""Complete native nominal exits, exact original refusals and partial state."""
from __future__ import annotations

from copy import deepcopy
import ctypes
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_instruction_policy_native import transport
from hepta.hia_nominal_terminators_native import (SOURCE, SCHEMA, SELECTOR, MAGIC,
    INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES, ERRORS, TerminatorPacket,
    NativeNominalTerminators, installed_nominal_terminators, selected_nominal_terminators)
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import execute_program
from tests import test_hia_program_composite as fixtures
from tests import test_hia_partial_record as partials
from tests import test_hia_composite_returned_loans as loans
from tests.test_hia_program import b, branch, c, f, i, jump, ret

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_NOMINAL_TERMINATORS_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_NOMINAL_TERMINATORS_DEVELOPMENT_MANIFEST'


def outcome(call):
    try:
        return call(), None
    except HIAProgramRejected as error:
        return None, (error.code, str(error))


def scalar_edges():
    return fixtures.module([], f('choose', [('condition', 'bool'), ('value', 'u32')], ['u32'], [], [
        b('entry', [('condition', 'bool'), ('value', 'u32')], [],
          branch('condition', ('left', 'value'), ('right', 'value'))),
        b('left', [('left_value', 'u32')], [], jump('done', 'left_value')),
        b('right', [('right_value', 'u32')], [], jump('done', 'right_value')),
        b('done', [('answer', 'u32')], [], ret('answer'))]))


class NominalTerminatorsSourceTests(unittest.TestCase):
    def test_exact_ordinary_hia_source_and_original_profile_limits(self):
        from tools import generate_hia_nominal_terminators as generator
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        from hepta.hia_agent_assembly import render_assembly
        document = generator.document()
        self.assertEqual(render_assembly(document).encode(), SOURCE.read_bytes())
        self.assertLessEqual(len(document['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in document['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for fn in document['functions']
                                 for block in fn['blocks']), MAX_INSTRUCTIONS)
        self.assertLessEqual(max(len(block['params']) for fn in document['functions']
                                 for block in fn['blocks']), 16)
        self.assertEqual((generator.MAGIC, generator.INPUT_BYTES, generator.OUTPUT_BYTES,
                          generator.WORKSPACE_BYTES), (MAGIC, INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES))
        verify_core(document)

    def test_missing_selected_image_never_enters_original_branch(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(selected_nominal_terminators())
        with patch.dict(os.environ, {SELECTOR: '/missing-nominal-terminators'}), patch.object(
                composite._Elaborator, '_reference_nominal_terminator',
                side_effect=AssertionError('host terminator used')):
            with self.assertRaises(HIAProgramRejected):
                verify_core(scalar_edges())

    def test_packet_preserves_object_and_type_identity_without_semantic_queries(self):
        class ForbiddenKey:
            def __str__(self):
                raise AssertionError('semantic display key expanded')
            def __eq__(self, other):
                raise AssertionError('semantic type compared in transport')
            def __hash__(self):
                raise AssertionError('semantic type hashed in transport')
        typ = composite._Type(ForbiddenKey(), 'record', ())
        value = composite._Value(typ, ())
        packet = TerminatorPacket(ret('a', 'z'), {'a': value, 'z': value},
                                  {'entry': [('arg', typ)]}, (typ, typ), 8192)
        self.assertEqual((len(packet.types), len(packet.values)), (1, 1))
        self.assertIs(type(packet.wire), bytes)


class NominalTerminatorsAdapterTests(unittest.TestCase):
    def image(self, data, *, mutate=False):
        image = object.__new__(NativeNominalTerminators)
        def entry(source, size, output, capacity, workspace, workspace_size):
            if mutate:
                ctypes.memmove(source, b'x', 1)
            if type(data) is int:
                return data
            ctypes.memmove(output, data, len(data))
            return len(data)
        image._entry = entry
        return image

    def frame(self, *, error=0, serial=7, request=0, structured=1, flags=(), term=None,
              reserved=0, size_delta=0, count_delta=0):
        if term is None and not error and not request:
            term = ret()
        body = b''.join(struct.pack('<Q', flag) for flag in flags) + transport(term)
        return struct.pack('<8Q', MAGIC, error, serial, len(body)+size_delta,
                           request, structured, len(flags)+count_delta, reserved) + body

    def test_complete_frame_flags_counter_and_graph_are_checked(self):
        source = transport([7, ret(), [], [], [], []])
        valid = self.frame()
        result = self.image(valid).lower_packet(source, [], 7)
        self.assertEqual(result.term, ret()); self.assertFalse(result.error)
        bad = [0, 0xfffffff1, valid[:-1], self.frame(error=25), self.frame(serial=8),
               self.frame(request=2), self.frame(structured=0), self.frame(error=1),
               self.frame(error=2, request=1), self.frame(request=1, term=ret()),
               self.frame(error=2, term=ret()), self.frame(reserved=1),
               self.frame(size_delta=1), self.frame(count_delta=1)]
        for data in bad:
            with self.subTest(data=repr(data)[:70]), self.assertRaises(HIAProgramRejected):
                self.image(data).lower_packet(source, [], 7)
        with self.assertRaisesRegex(HIAProgramRejected, 'original bytes changed'):
            self.image(valid, mutate=True).lower_packet(source, [], 7)

    def test_refusal_prefix_is_monotonic_and_delegation_has_no_effect(self):
        typ = composite._Type('buffer', 'primitive', ('buffer',), linear=True)
        value = composite._Value(typ, ('owner',))
        source = TerminatorPacket(ret('owner'), {'owner': value}, {}, (typ,), 7).wire
        result = self.image(self.frame(error=7, flags=[1])).lower_packet(source, [value], 7)
        self.assertEqual(result.states, [(value, True)])
        self.assertFalse(value.consumed)
        with self.assertRaises(HIAProgramRejected):
            result.admit()
        for frame in (self.frame(flags=[2]), self.frame(request=1, flags=[1])):
            with self.assertRaises(HIAProgramRejected):
                self.image(frame).lower_packet(source, [value], 7)
        value.consumed = True
        with self.assertRaises(HIAProgramRejected):
            self.image(self.frame(error=7, flags=[0])).lower_packet(source, [value], 7)


class NominalTerminatorsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development fixture cannot override cold source custody')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-nominal-terminators-')
        cls.addClassCleanup(cls.temporary.cleanup); cls.folder = Path(cls.temporary.name)
        if development:
            supplied = Path(development); value = json.loads(supplied.read_bytes()); name = value['image_path']
            assert type(name) is str and Path(name).name == name
            shutil.copyfile(supplied.parent / name, cls.folder / name)
            cls.manifest = cls.folder / 'manifest.json'; cls.manifest.write_bytes(supplied.read_bytes())
            cls.fixture_scope = 'DEVELOPMENT_ONLY'
        elif cold:
            from tools.build_hia_json_preflight import build
            report = json.loads(Path(cold).read_bytes()); nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold), candidate='nominal-terminators')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder); source = SOURCE.with_name('selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            image, receipt = compile_stage(cls.folder, 'nominal-terminators', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_text(json.dumps(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
                image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
            (cls.folder / 'development-compile.json').write_text(json.dumps(receipt))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native = installed_nominal_terminators(str(cls.manifest))

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def compare_at_terms(self, document, variants):
        reference = composite._Elaborator._reference_nominal_terminator
        native = composite._Elaborator.lower_nominal_terminator
        test, observations = self, []
        def compare(owner, block, env, signatures, flattened, result, fn,
                    value, consume, live_required, edge, ops):
            initial_serial, saved_result = owner.serial, deepcopy(result)
            flags = {id(v): (v, v.consumed) for v in env.values()}
            original = block['term']
            choices = [deepcopy(original), *variants(block, env, signatures, fn)]
            def restore():
                owner.serial = initial_serial; result[:] = deepcopy(saved_result)
                for item, consumed in flags.values():
                    item.consumed = consumed
            for term in choices:
                block['term'] = term; restore()
                args = (owner, block, env, signatures, flattened, result, fn,
                        value, consume, live_required, edge, ops)
                _, expected_error = outcome(lambda: reference(*args))
                expected = (expected_error, owner.serial, deepcopy(result),
                            [(name, item.consumed) for name, item in env.items()])
                restore()
                _, actual_error = outcome(lambda: native(*args))
                actual = (actual_error, owner.serial, deepcopy(result),
                          [(name, item.consumed) for name, item in env.items()])
                test.assertEqual(actual, expected, repr(term))
                observations.append((term, actual_error))
            block['term'] = original; restore()
            return native(owner, block, env, signatures, flattened, result, fn,
                          value, consume, live_required, edge, ops)
        with self.selected(), patch.object(composite._Elaborator, 'lower_nominal_terminator', compare):
            result = outcome(lambda: composite.elaborate_program(document))
        return observations, result

    def test_exact_complete_core_four_schemas_and_unchanged_runtime(self):
        makers = (scalar_edges, fixtures.stored_loan_program, fixtures.enum_owner_program,
                  fixtures.task_program, fixtures.scalar_task_program, fixtures.owned_result_task_program,
                  partials.roundtrip_program, partials.task_partial_program, loans.pair_program)
        for maker in makers:
            document = maker(); expected = composite.elaborate_program(document)
            with self.selected(), patch.object(composite._Elaborator, '_reference_nominal_terminator',
                    side_effect=AssertionError('host terminator called')):
                actual = composite.elaborate_program(document)
            self.assertEqual(actual, expected, maker.__name__)
        for version in range(1, 5):
            document = scalar_edges(); document['schema'] = 'hepta.hia.composite.v' + str(version)
            with self.selected():
                program = verify_core(document)
            for condition in (True, False):
                self.assertEqual(execute_program(program, 'choose', [condition, 37])['result'], 37)

    def test_all_terminator_keys_names_missing_targets_and_refusal_order(self):
        def variants(block, env, signatures, fn):
            name = next(iter(env), 'undefined')
            target = next(iter(signatures))
            edge = {'target': target, 'args': [name]}
            return [None, [], {}, {'op': None}, {'op': 'unknown'},
                {'op': 'jump'}, {'op': 'branch'}, {'op': 'ret'}, {'op': 'trap'},
                {'op': 'jump', **edge, 'extra': 0},
                jump(1, name), jump('h2internal_target', name), jump('absent', 'undefined'),
                {'op': 'jump', 'target': target, 'args': False}, jump(target, 7),
                jump(target, 'undefined'), jump(target, 'h2internal_bad'),
                ret(7), ret('undefined'), ret('h2internal_bad'), ret(),
                {'op': 'ret', 'values': {}},
                {'op': 'branch', 'cond': 7, 'then': edge, 'else': edge},
                {'op': 'branch', 'cond': 'undefined', 'then': None, 'else': None},
                {'op': 'branch', 'cond': name, 'then': None, 'else': edge},
                {'op': 'branch', 'cond': name, 'then': edge, 'else': None},
                {'op': 'branch', 'cond': name, 'then': {'target': 'absent', 'args': []}, 'else': None},
                {'op': 'trap', 'code': {'nested': [None, True, -7, -0.0, '汉\ud800']}},
                {'op': 'trap', 'code': ['not-yet-primitive-code']},
                {'op': 'trap', 'code': 'user', 'extra': 1}]
        observations, result = self.compare_at_terms(scalar_edges(), variants)
        self.assertGreater(len(observations), 100)
        self.assertIsNone(result[1])
        self.assertTrue(any(error and error[0] == 'E_HIA_NAME' for _, error in observations))

    def test_owner_return_duplicate_partial_consumption_and_live_edge_order(self):
        document = fixtures.module([], f('transfer', [('owner', 'buffer'), ('other', 'buffer')],
            ['buffer', 'buffer'], [], [b('entry', [('owner', 'buffer'), ('other', 'buffer')], [],
                ret('owner', 'other'))]))
        def variants(block, env, signatures, fn):
            return [ret('owner', 'owner'), ret('owner'), ret('other', 'owner'),
                    jump('entry', 'owner', 'owner'), jump('entry', 'owner'),
                    jump('entry', 'other', 'owner'), jump('absent', 'owner', 'owner')]
        observations, result = self.compare_at_terms(document, variants)
        self.assertIsNone(result[1])
        for code in (7, 15, 16):
            self.assertTrue(any(error and error[0] == ERRORS[code][0] and
                                error[1].endswith(ERRORS[code][1]) for _, error in observations))

    def test_shared_value_aliases_external_loans_and_nominal_identity(self):
        owner = composite._Type('buffer', 'primitive', ('buffer',), linear=True)
        item = composite._Value(owner, ('owned',))
        result = self.native.lower(ret('a', 'z'), {'a': item, 'z': item}, {}, (owner, owner), 8192)
        self.assertEqual(result.error, 7)
        self.assertEqual(result.states, [(item, True)])
        self.assertFalse(item.consumed)
        external = composite._Value(owner, ('external',), external=True)
        result = self.native.lower(ret(), {'loan': external}, {}, (), 0)
        self.assertEqual(result.error, 0)
        a = composite._Type('A<>', 'record', ('u32',))
        z = composite._Type('Z<>', 'record', ('u32',))
        value = composite._Value(a, ('part',))
        result = self.native.lower(ret('value'), {'value': value}, {}, (z,), 0)
        self.assertEqual(result.error, 21)
        left = composite._Type('u32', 'primitive', ('u32',))
        right = composite._Type('u32', 'primitive', ('u32',))
        value = composite._Value(left, ('part',))
        result = self.native.lower(ret('value'), {'value': value}, {}, (right,), 0)
        self.assertEqual(result.term, ret('part'))

    def test_complete_large_repeated_return_preserves_full_logical_array(self):
        typ = composite._Type('Wide<>', 'record', ('u32',) * 512)
        names = tuple(('part_' + str(i)).ljust(128, '_') for i in range(512))
        item = composite._Value(typ, names)
        result = self.native.lower(ret(*(['value'] * 8193)), {'value': item}, {}, (typ,) * 8193, 0)
        self.assertEqual(result.error, 0)
        self.assertEqual(len(result.term['values']), 8193 * 512)
        self.assertEqual(result.term['values'][:512], list(names))
        self.assertEqual(result.term['values'][-512:], list(names))
        self.assertEqual(result.states, [(item, False)])

    def test_match_delegation_has_no_effect_before_existing_owner(self):
        typ = composite._Type('bool', 'primitive', ('bool',))
        item = composite._Value(typ, ('primitive',))
        term = {'op': 'match', 'malformed': ['kept-for-original-owner']}
        result = self.native.lower(term, {'value': item}, {}, (), 8192)
        self.assertEqual((result.error, result.request, result.serial, result.term), (0, 1, 8192, None))
        self.assertEqual(result.states, [(item, False)])
        self.assertTrue(result.structured)
        result = self.native.lower(None, {'value': item}, {}, (), 8192)
        self.assertEqual((result.error, result.request, result.structured), (1, 0, False))

    def test_public_large_return_keeps_original_late_core_limit(self):
        declarations = [fixtures.record('Small', [('field_' + str(i), 'u32') for i in range(64)]),
                        fixtures.record('Wide', [('chunk_' + str(i), 'Small') for i in range(8)])]
        document = fixtures.module(declarations, f('large', [('input', 'Wide')], ['Wide'] * 8193, [],
            [b('entry', [('input', 'Wide')], [], ret(*(['input'] * 8193)))]))
        with patch.dict(os.environ, {SELECTOR: ''}):
            _, expected = outcome(lambda: verify_core(document))
        self.assertIsNotNone(expected)
        self.assertEqual(expected[0], 'E_HIA_LIMIT')
        with self.selected(), patch.object(composite._Elaborator, '_reference_nominal_terminator',
                side_effect=AssertionError('host terminator called')):
            _, actual = outcome(lambda: verify_core(document))
        self.assertEqual(actual, expected)

    def test_large_zero_width_environment_and_full_slot_inventory(self):
        empty = composite._Type('Empty<>', 'record', ())
        environment = {'empty_' + str(i): composite._Value(empty, ()) for i in range(15000)}
        result = self.native.lower(ret(*environment), environment, {}, (empty,) * 15000, 8192)
        self.assertEqual((result.error, result.term, result.serial), (0, ret(), 8192))
        self.assertEqual(len(result.states), 15000)
        self.assertFalse(any(flag for _, flag in result.states))
        wide = composite._Type('Wide<>', 'record', ('u32',) * 512)
        environment = {'wide_' + str(i): composite._Value(wide,
            tuple('part_' + str(i) + '_' + str(j) for j in range(512))) for i in range(64)}
        result = self.native.lower(ret(*environment), environment, {}, (wide,) * 64, 0)
        self.assertEqual((result.error, len(result.term['values'])), (0, 32768))

    def test_private_bounds_invalid_packets_nonzero_scratch_and_concurrent_calls(self):
        from concurrent.futures import ThreadPoolExecutor
        context = TerminatorPacket(ret(), {}, {}, (), 8192)
        data = context.wire; source = ctypes.create_string_buffer(data)
        output = ctypes.create_string_buffer(OUTPUT_BYTES + 32)
        workspace = ctypes.create_string_buffer(WORKSPACE_BYTES + 32)
        ctypes.memset(ctypes.addressof(output) + OUTPUT_BYTES, 0xA7, 32)
        ctypes.memset(ctypes.addressof(workspace) + WORKSPACE_BYTES, 0xB9, 32)
        for oc, wc in ((OUTPUT_BYTES-1, WORKSPACE_BYTES), (OUTPUT_BYTES, WORKSPACE_BYTES-1)):
            self.assertEqual(self.native._entry(source, len(data), output, oc, workspace, wc), 0xfffffff1)
        frames = []
        for fill in (0, 165, 255):
            ctypes.memset(workspace, fill, WORKSPACE_BYTES)
            extent = self.native._entry(source, len(data), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
            self.assertGreaterEqual(extent, 80)
            frames.append(ctypes.string_at(output, extent))
        self.assertTrue(all(frame == frames[0] for frame in frames))
        self.assertEqual(ctypes.string_at(ctypes.addressof(output)+OUTPUT_BYTES, 32), b'\xa7'*32)
        self.assertEqual(ctypes.string_at(ctypes.addressof(workspace)+WORKSPACE_BYTES, 32), b'\xb9'*32)
        self.assertEqual(ctypes.string_at(source, len(data)), data)
        nested = None
        for _ in range(129):
            nested = [nested]
        invalid = [b'', data[:-1], data+b'\0', transport(nested),
                   transport([0, ret(), [], [], []]), transport([8193, ret(), [], [], [], []]),
                   transport([0, ret(), [['unknown', [], False]], [], [], []]),
                   transport([0, ret(), [], [['bad', 0, [], False, False, 0]], [], []])]
        for malformed in invalid:
            bad = ctypes.create_string_buffer(malformed, max(1, len(malformed)))
            self.assertEqual(self.native._entry(bad, len(malformed), output, OUTPUT_BYTES,
                                               workspace, WORKSPACE_BYTES), 0xfffffff1)
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: self.native.lower(ret(), {}, {}, (), 8192), range(6)))
        self.assertTrue(all(result == results[0] for result in results))

    def test_independent_core_vm_matches_native_complete_frames_and_consumption(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(SOURCE.read_bytes())
        scalar = composite._Type('u32', 'primitive', ('u32',))
        owner = composite._Type('buffer', 'primitive', ('buffer',), linear=True)
        n = composite._Value(scalar, ('primitive',)); v = composite._Value(owner, ('owned',))
        contexts = [TerminatorPacket(ret(), {}, {}, (), 0),
                    TerminatorPacket({}, {}, {}, (), 0),
                    TerminatorPacket(ret('n'), {'n': n}, {}, (scalar,), 8192),
                    TerminatorPacket(ret('a', 'z'), {'a': v, 'z': v}, {}, (owner, owner), 8192),
                    TerminatorPacket(jump('next', 'n'), {'n': n}, {'next': [('x', scalar)]}, (), 7),
                    TerminatorPacket({'op': 'trap', 'code': {'raw': [None, -0.0, '汉']}}, {}, {}, (), 0),
                    TerminatorPacket({'op': 'match'}, {'n': n}, {}, (), 0)]
        output, workspace = _Owner(-2, bytearray(OUTPUT_BYTES)), _Owner(-3, bytearray(WORKSPACE_BYTES))
        for context in contexts:
            data = context.wire; source = _Owner(-1, bytearray(data))
            machine = _Machine(checked, 20_000_000, 128 << 20, None, 256)
            extent = machine.invoke(checked.as_dict()['functions'][0],
                [_View(source, False), _View(output, True), _View(workspace, True)])[0]
            self.assertTrue(80 <= extent <= OUTPUT_BYTES)
            native_source = ctypes.create_string_buffer(data)
            native_output = ctypes.create_string_buffer(OUTPUT_BYTES)
            native_workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
            native_extent = self.native._entry(native_source, len(data), native_output, OUTPUT_BYTES,
                                               native_workspace, WORKSPACE_BYTES)
            self.assertEqual(native_extent, extent)
            self.assertEqual(ctypes.string_at(native_output, extent), bytes(output.data[:extent]))
            self.assertEqual(bytes(source.data), data)

    def test_installed_wheel_without_authoring_or_host_terminator(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/nominal_terminators.hiaasm', NATIVE_SOURCE_FILES)
        source = self.folder / 'wheel-source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        names = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES
        for name in (*names, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            destination = source / name; destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        wheels, installed = self.folder / 'wheels', self.folder / 'installed'
        built = subprocess.run([sys.executable, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
            '--wheel-dir', str(wheels), str(source)], cwd=source, capture_output=True, timeout=120,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        wheel, = wheels.glob('*.whl')
        copied = subprocess.run([sys.executable, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--target', str(installed), str(wheel)], cwd=self.folder, capture_output=True, timeout=120,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(copied.returncode, 0, copied.stdout + copied.stderr)
        child = '''import sys,importlib.abc
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed terminator imported authoring tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_nominal_terminators_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('host terminator called')
composite._Elaborator._reference_nominal_terminator=absent
try: result=verify_core(Path(sys.argv[2]).read_bytes())
except HIAProgramRejected:
    if sys.argv[3]=='refuse':print('REFUSED')
    else:raise
else:
    assert sys.argv[3]=='accept','invalid installed custody accepted'
    sys.stdout.buffer.write(result.canonical_bytes)
'''
        data = self.folder / 'installed-input.json'
        def run(mode, manifest=self.manifest):
            return subprocess.run([sys.executable, '-I', '-S', '-B', '-c', child,
                str(installed), str(data), mode], cwd=self.folder, capture_output=True, timeout=30,
                env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', SELECTOR: str(manifest)})
        for maker in (scalar_edges, fixtures.stored_loan_program, partials.roundtrip_program, loans.pair_program):
            document = maker(); data.write_text(json.dumps(document))
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document).canonical_bytes
            result = run('accept')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
        resource = installed / 'hepta/_data/examples/hia_bootstrap/nominal_terminators.hiaasm'
        original = resource.read_bytes()
        for missing in (False, True):
            try:
                resource.unlink() if missing else resource.write_bytes(original + b'\n')
                result = run('refuse')
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))
            finally:
                resource.write_bytes(original)
        bad = self.folder / 'bad-installed-manifest.json'; bad.write_bytes(b'{}')
        result = run('refuse', bad)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))

    def test_original_nominal_resource_and_loan_suites_with_host_terminator_disabled(self):
        names = ('tests.test_hia_program_composite', 'tests.test_hia_partial_record',
                 'tests.test_hia_composite_returned_loans.CompositeReturnedLoans')
        loader = unittest.TestLoader(); suite = loader.loadTestsFromNames(names)
        self.assertEqual(loader.errors, [])
        log = io.StringIO()
        with self.selected(), patch.object(composite._Elaborator, '_reference_nominal_terminator',
                side_effect=AssertionError('host terminator called')):
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        self.assertTrue(result.wasSuccessful(), log.getvalue())
        self.assertEqual((result.testsRun, len(result.skipped), len(result.expectedFailures),
                          len(result.unexpectedSuccesses)), (75, 0, 0, 0), log.getvalue())

    def test_real_machine_control_flow_allocator_refusal_and_owned_cleanup(self):
        from tests.test_hia_record_operations_native import resource_program
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        cc = shutil.which('cc'); self.assertIsNotNone(cc)
        driver = r'''
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
void *__real_calloc(size_t,size_t); void __real_free(void *);
static void *live; static size_t allocations, frees, refusals; static bool refuse;
void *__wrap_calloc(size_t n,size_t w){
  if(refuse){refuse=false;refusals++;return NULL;}
  void *p=__real_calloc(n,w);if(p){if(live)exit(80);live=p;allocations++;}return p;
}
void __wrap_free(void *p){if(p){if(live!=p)exit(81);live=NULL;frees++;}__real_free(p);}
size_t record_case(size_t);
int main(void){
  if(record_case(7)!=24 || record_case(0)!=17)return 82;
  refuse=true;if(record_case(7)!=17 || refuse || live)return 83;
  printf("%zu %zu %zu\n",allocations,frees,refusals);
  return allocations!=1 || frees!=1 || refusals!=1;
}
'''
        with self.selected(), patch.object(composite._Elaborator, '_reference_nominal_terminator',
                side_effect=AssertionError('host terminator called')):
            checked = verify_core(resource_program())
        obj = self.folder / 'terminator-effects.o'
        compile_program_machine(emit_program_machine(checked), program=checked, output=obj, kind='object', linker=cc)
        source, executable = self.folder / 'terminator-effects.c', self.folder / 'terminator-effects'
        source.write_text(driver)
        built = subprocess.run([cc, '-std=c11', '-O2', str(source), str(obj),
            '-Wl,--wrap=calloc', '-Wl,--wrap=free', '-o', str(executable)], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(executable)], capture_output=True, timeout=30)
        self.assertEqual((ran.returncode, ran.stdout, ran.stderr), (0, b'1 1 1\n', b''))

    def test_selected_manifest_image_and_source_hash_fail_closed(self):
        loaded = installed_nominal_terminators(str(self.manifest))
        self.assertIsNotNone(loaded)
        original = self.manifest.read_bytes()
        for field in ('source_sha256', 'image_sha256'):
            value = json.loads(original); value[field] = '0' * 64
            target = self.folder / ('bad-' + field + '.json'); target.write_text(json.dumps(value))
            with self.subTest(field=field), self.assertRaises((ValueError, OSError)):
                installed_nominal_terminators(str(target))
        value = json.loads(original); value['compiler_sha256'] = 'invalid'
        target = self.folder / 'bad-compiler-syntax.json'; target.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            installed_nominal_terminators(str(target))


if __name__ == '__main__':
    unittest.main()
