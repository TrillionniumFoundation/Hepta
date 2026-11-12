"""Complete module production, retained object identity and ordered refusals."""
from __future__ import annotations
from copy import deepcopy
import ctypes
from dataclasses import replace
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
import weakref

from hepta import hia_program_composite as composite
from hepta.hia_instruction_policy_native import transport
from hepta.hia_nominal_module_native import (SOURCE, SCHEMA, SELECTOR, MAGIC,
    INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES, ModuleContext, ModuleResult,
    NativeNominalModule, installed_nominal_module, selected_nominal_module)
from hepta.hia_program import HIAProgramRejected, verify_core
from tests import test_hia_program_composite as fixtures
from tests import test_hia_partial_record as partials
from tests import test_hia_composite_returned_loans as loans
from tests.test_hia_nominal_terminators_native import scalar_edges
from tests.test_hia_program import b, f, ret

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_NOMINAL_MODULE_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_NOMINAL_MODULE_DEVELOPMENT_MANIFEST'


def outcome(call):
    try:
        return call(), None
    except HIAProgramRejected as exc:
        return None, (exc.code, str(exc))


class HeldOwner:
    """Pre-admitted callback fixture retaining exact complete object values."""
    def __init__(self, count=2, *, block_count=1, helper_count=1):
        self.document = {'schema': 'hepta.hia.composite.v1', 'module': 'held',
                         'functions': [{'index': index} for index in range(count)]}
        self.helpers = []
        self.events = []
        self.produced = []
        self.block_count = block_count
        self.helper_count = helper_count
        self.scalar = composite._Type('u32', 'primitive', ('u32',))
        self.held_signatures = {'z': ((), (self.scalar,)), 'a': ((), ())}

    @property
    def signatures(self):
        self.events.append('signatures')
        return self.held_signatures

    def function(self, raw):
        self.events.append(raw['index'])
        value = {'name': 'f' + str(raw['index']), 'blocks': [{}] * self.block_count,
                 'held': {'signed_zero': -0.0, 'raw': '汉\ud800'}}
        self.produced.append(value)
        if raw['index'] == 0:
            self.helpers.extend({'name': 'h' + str(i), 'blocks': [{}]}
                                for i in range(self.helper_count))
        return value


class NominalModuleSourceTests(unittest.TestCase):
    def test_source_is_ordinary_hia_with_existing_compiler_limits(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools import generate_hia_nominal_module as generator
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        doc = generator.document()
        self.assertEqual(render_assembly(doc).encode(), SOURCE.read_bytes())
        self.assertLessEqual(len(doc['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in doc['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(bl['ops']) for fn in doc['functions'] for bl in fn['blocks']), MAX_INSTRUCTIONS)
        self.assertLessEqual(max(len(bl['params']) for fn in doc['functions'] for bl in fn['blocks']), 16)
        verify_core(doc)

    def test_selected_missing_image_never_falls_back(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(selected_nominal_module())
        with patch.dict(os.environ, {SELECTOR: '/missing-module-image'}), patch.object(
                composite._Elaborator, '_reference_lower', side_effect=AssertionError('host module')):
            with self.assertRaises(HIAProgramRejected):
                verify_core(scalar_edges())


class NominalModuleAdapterTests(unittest.TestCase):
    def test_constructor_allocation_failure_releases_arenas_with_original_traceback_held(self):
        from hepta import hia_nominal_module_native as module
        allocate = ctypes.create_string_buffer
        for position in (1, 2):
            for kind in (MemoryError, KeyboardInterrupt):
                error = kind('original allocation failure')
                references = []
                calls = 0
                def fail_at_position(*args, **kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == position:
                        raise error
                    arena = allocate(*args, **kwargs)
                    references.append(weakref.ref(arena))
                    return arena
                with self.subTest(position=position, exception=kind.__name__), \
                        patch.object(module.ctypes, 'create_string_buffer', side_effect=fail_at_position):
                    try:
                        ModuleContext(HeldOwner())
                    except BaseException as actual:
                        held = (actual, actual.__traceback__)
                    else:
                        self.fail('allocation failure was hidden')
                    self.assertIs(held[0], error)
                    self.assertIsNotNone(held[1])
                    self.assertEqual(len(references), position - 1)
                    self.assertTrue(all(reference() is None for reference in references))

    def test_only_current_issued_request_executes_once_and_ack_precedes_resume(self):
        owner = HeldOwner()
        context = ModuleContext(owner)
        self.addCleanup(context.close)
        with self.assertRaisesRegex(HIAProgramRejected, 'current unexecuted native request'):
            context.invoke(ModuleResult(0, 1, 0, 1, 3, None))
        self.assertEqual(owner.events, [])
        image = self.image(self.frame())
        result = image.step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'not been acknowledged'):
            image.step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'current unexecuted native request'):
            context.invoke(replace(result))
        self.assertEqual(owner.events, [])
        context.invoke(result)
        with self.assertRaisesRegex(HIAProgramRejected, 'current unexecuted native request'):
            context.invoke(result)
        self.assertEqual(owner.events, [0])
        self.assertEqual((context.executed, context.completed, context.sequence), (1, 1, 1))
        error = KeyboardInterrupt('original callback interruption')
        def interrupted(raw):
            owner.events.append('interrupted')
            raise error
        owner.function = interrupted
        result = self.image(self.frame(index=1, sequence=2)).step(context)
        references = [weakref.ref(context.output), weakref.ref(context.workspace)]
        try:
            context.invoke(result)
        except BaseException as actual:
            held = (actual, actual.__traceback__)
        else:
            self.fail('callback interruption was hidden')
        self.assertIs(held[0], error)
        self.assertTrue(context.closed)
        self.assertIsNone(context.pending)
        self.assertTrue(all(reference() is None for reference in references))
        with self.assertRaisesRegex(HIAProgramRejected, 'current unexecuted native request'):
            context.invoke(result)
        self.assertEqual(owner.events, [0, 'interrupted'])
        self.assertEqual((context.executed, context.completed), (2, 1))

    def image(self, frame, *, mutate=False):
        image = object.__new__(NativeNominalModule)
        def entry(source, size, output, capacity, workspace, workspace_size):
            if mutate:
                ctypes.memmove(source, b'x', 1)
            if type(frame) is int:
                return frame
            ctypes.memmove(output, frame, len(frame))
            return len(frame)
        image._entry = entry
        return image

    def frame(self, *, error=0, request=1, index=0, sequence=1, pool=3,
              reserved=0, delta=0, value=None):
        graph = transport(value)
        return struct.pack('<8Q', MAGIC, error, request, index, sequence,
                           len(graph) + delta, pool, reserved) + graph

    def test_result_frame_and_input_custody_checked(self):
        good = self.frame()
        result = self.image(good).step(ModuleContext(HeldOwner()))
        self.assertEqual((result.request, result.index, result.sequence), (1, 0, 1))
        bad = [0, 0xfffffff1, good[:-1], self.frame(error=2), self.frame(request=4),
               self.frame(error=1), self.frame(sequence=0), self.frame(sequence=2),
               self.frame(pool=2), self.frame(reserved=1), self.frame(delta=1),
               self.frame(value={}), self.frame(request=0, value={})]
        for frame in bad:
            with self.subTest(frame=repr(frame)[:70]), self.assertRaises(HIAProgramRejected):
                self.image(frame).step(ModuleContext(HeldOwner()))
        with self.assertRaisesRegex(HIAProgramRejected, 'original bytes changed'):
            self.image(good, mutate=True).step(ModuleContext(HeldOwner()))

    def test_callback_identity_order_and_closed_context(self):
        context = ModuleContext(HeldOwner())
        invalid = [ModuleResult(0, 1, 1, 1, 3, None), ModuleResult(0, 2, 0, 1, 3, None),
                   ModuleResult(0, 3, 0, 1, 3, None), ModuleResult(0, 4, 0, 1, 3, None)]
        for result in invalid:
            with self.assertRaises(HIAProgramRejected):
                context.invoke(result)
        self.assertEqual(context.owner.events, [])
        context.closed = True
        with self.assertRaisesRegex(HIAProgramRejected, 'closed module'):
            self.image(0).step(context)


class NominalModuleNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development fixture cannot override cold source custody')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-nominal-module-')
        cls.addClassCleanup(cls.temporary.cleanup); cls.folder = Path(cls.temporary.name)
        if development:
            supplied = Path(development); value = json.loads(supplied.read_bytes()); name = value['image_path']
            assert type(name) is str and Path(name).name == name
            shutil.copyfile(supplied.parent/name, cls.folder/name)
            cls.manifest = cls.folder/'manifest.json'; cls.manifest.write_bytes(supplied.read_bytes())
            cls.fixture_scope = 'DEVELOPMENT_ONLY'
        elif cold:
            from tools.build_hia_json_preflight import build
            report = json.loads(Path(cold).read_bytes()); nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder/'qualified', compiler, Path(cold), candidate='nominal-module')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder); source = SOURCE.with_name('selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            image, receipt = compile_stage(cls.folder, 'nominal-module', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder/'manifest.json'
            cls.manifest.write_text(json.dumps(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
                image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
            (cls.folder/'development-compile.json').write_text(json.dumps(receipt))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native = installed_nominal_module(str(cls.manifest))

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def test_actual_native_success_refusal_and_interruption_release_both_arenas(self):
        from hepta import hia_nominal_module_native as module
        error = KeyboardInterrupt('original second function interruption')
        class InterruptedOwner(HeldOwner):
            def function(self, raw):
                if raw['index'] == 1:
                    self.events.append('interrupted')
                    raise error
                return super().function(raw)
        for owner, expected in ((HeldOwner(), None),
                                (HeldOwner(block_count=4097), HIAProgramRejected),
                                (InterruptedOwner(), KeyboardInterrupt)):
            contexts, references = [], []
            class ObservedContext(ModuleContext):
                def __init__(self, owner):
                    super().__init__(owner)
                    contexts.append(self)
                    references.extend((weakref.ref(self.output), weakref.ref(self.workspace)))
            with self.subTest(expected=expected), patch.object(module, 'ModuleContext', ObservedContext):
                try:
                    value = self.native.lower(owner)
                except BaseException as actual:
                    held = (actual, actual.__traceback__)
                    self.assertIsNotNone(expected)
                    self.assertIsInstance(actual, expected)
                    if expected is KeyboardInterrupt:
                        self.assertIs(actual, error)
                else:
                    held = None
                    self.assertIsNone(expected)
                    self.assertIs(value['functions'][0], owner.produced[0])
                self.assertEqual(len(contexts), 1)
                context = contexts[0]
                self.assertTrue(context.closed)
                self.assertIsNone(context.pending)
                self.assertIsNone(context.output)
                self.assertIsNone(context.workspace)
                self.assertTrue(all(reference() is None for reference in references))
                if held is not None:
                    self.assertIsNotNone(held[1])

    def test_complete_original_modules_and_public_programs(self):
        makers = (scalar_edges, fixtures.stored_loan_program, partials.roundtrip_program, loans.pair_program)
        for maker in makers:
            document = maker(); before = deepcopy(document)
            left = composite._Elaborator(deepcopy(document)); right = composite._Elaborator(deepcopy(document))
            expected = left._reference_lower()
            with patch.object(composite._Elaborator, '_reference_lower', side_effect=AssertionError('host module')):
                actual = self.native.lower(right)
            self.assertEqual(actual, expected)
            self.assertEqual((right.serial, right.value_slots), (left.serial, left.value_slots))
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected_bytes = verify_core(document).canonical_bytes
            with self.selected(), patch.object(composite._Elaborator, '_reference_lower',
                                               side_effect=AssertionError('host module')):
                self.assertEqual(verify_core(document).canonical_bytes, expected_bytes)
            self.assertEqual(document, before)
        for version in (1, 2, 3, 4):
            document = scalar_edges(); document['schema'] = 'hepta.hia.composite.v' + str(version)
            owner = composite._Elaborator(document)
            self.assertEqual(self.native.lower(owner)['schema'], composite.composite_core_schema(document['schema']))

    def test_all_function_callbacks_precede_helper_inventory_and_exports(self):
        reference, native = HeldOwner(), HeldOwner()
        expected = composite._Elaborator._reference_lower(reference)
        actual = self.native.lower(native)
        self.assertEqual(actual, expected)
        self.assertEqual(native.events, [0, 1, 'signatures'])
        self.assertEqual(native.events, reference.events)
        self.assertEqual(actual['exports'], ['a', 'z'])
        self.assertIs(actual['functions'][0], native.produced[0])
        self.assertIs(actual['functions'][1], native.produced[1])
        self.assertIs(actual['functions'][2], native.helpers[0])
        self.assertIsNot(actual['functions'], native.helpers)
        native.helpers.append({'later': True})
        self.assertEqual(len(actual['functions']), 3)

    def test_inventory_refusal_is_late_and_never_queries_exports(self):
        for kwargs in ({'block_count': 4097}, {'helper_count': 1023}):
            reference, native = HeldOwner(**kwargs), HeldOwner(**kwargs)
            _, expected = outcome(lambda: composite._Elaborator._reference_lower(reference))
            _, actual = outcome(lambda: self.native.lower(native))
            self.assertEqual(actual, expected)
            self.assertEqual(actual[0], 'E_HIA_LIMIT')
            self.assertEqual(native.events, [0, 1])
            self.assertEqual(native.events, reference.events)
            self.assertEqual(native.helpers, reference.helpers)

    def test_function_exception_preserves_prefix_and_propagates_exact_error(self):
        class FailedOwner(HeldOwner):
            def function(self, raw):
                if raw['index'] == 1:
                    self.events.append('failed second')
                    self.helpers.append({'partial': True})
                    raise HIAProgramRejected('original callback refusal', 'E_HIA_RESOURCE')
                return super().function(raw)
        reference, native = FailedOwner(), FailedOwner()
        _, expected = outcome(lambda: composite._Elaborator._reference_lower(reference))
        _, actual = outcome(lambda: self.native.lower(native))
        self.assertEqual(actual, expected)
        self.assertEqual((native.events, native.helpers, native.produced),
                         (reference.events, reference.helpers, reference.produced))

    def test_scalar_export_filter_keeps_all_names_and_original_ascii_sort(self):
        owner = HeldOwner()
        from hepta.hia_opcodes import SCALARS
        owner.held_signatures = {}
        for name in ('z', 'A', 'a', 'Z'):
            owner.held_signatures[name] = ((), ())
        for index, key in enumerate(sorted(SCALARS)):
            typ = composite._Type(key, 'primitive', (key,))
            owner.held_signatures['scalar_' + str(index)] = ((('x', typ),), (typ,))
        for key in ('readbuf', 'mutbuf', 'buffer', 'chain'):
            typ = composite._Type(key, 'primitive', (key,))
            owner.held_signatures['excluded_' + key] = ((('x', typ),), ())
        empty = composite._Type('Empty<>', 'record', ())
        owner.held_signatures['excluded_empty'] = ((), (empty,))
        actual = self.native.lower(owner)['exports']
        self.assertEqual(actual, sorted(name for name in owner.held_signatures if not name.startswith('excluded_')))
        self.assertEqual(actual[:4], ['A', 'Z', 'a', 'scalar_0'])

    def test_full_function_and_export_capacity_without_earlier_limit(self):
        owner = HeldOwner(1024, helper_count=0)
        owner.held_signatures = {'f_' + str(i): ((), ()) for i in range(1024)}
        result = self.native.lower(owner)
        self.assertEqual(len(result['functions']), 1024)
        self.assertEqual(result['exports'], sorted(owner.held_signatures))
        self.assertEqual(owner.events, list(range(1024)) + ['signatures'])

    def test_wire_does_not_expand_complete_earlier_function_arrays(self):
        owner = HeldOwner(1, helper_count=0)
        original = owner.function
        held = ['argument_' + str(i) for i in range(512)] * 8193
        def produce(raw):
            result = original(raw); result['large_arguments'] = held
            return result
        owner.function = produce
        context = ModuleContext(owner); largest_source = largest_output = 0
        while True:
            result = self.native.step(context)
            largest_source = max(largest_source, len(context.wire))
            size, = struct.unpack_from('<Q', context.output, 40)
            largest_output = max(largest_output, size)
            result.admit()
            if not result.request:
                break
            context.invoke(result)
        self.assertLess(largest_source, 2048); self.assertLess(largest_output, 2048)
        self.assertIs(result.value['functions'][0]['large_arguments'], held)
        self.assertEqual(len(held), 8193 * 512)

    def test_native_continuations_match_independent_vm_complete_frames_and_state(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(SOURCE.read_bytes())
        workspace = _Owner(-3, bytearray(WORKSPACE_BYTES))
        context = ModuleContext(HeldOwner())
        frames = 0
        while True:
            wire = context.wire
            source = _Owner(-1, bytearray(wire))
            output = _Owner(-2, bytearray(ctypes.string_at(context.output, OUTPUT_BYTES)))
            vm = _Machine(checked, 20_000_000, 128 << 20, None, 256)
            extent = vm.invoke(checked.as_dict()['functions'][0],
                [_View(source, False), _View(output, True), _View(workspace, True)])[0]
            result = self.native.step(context)
            self.assertEqual(ctypes.string_at(context.output, extent), bytes(output.data[:extent]))
            self.assertEqual(ctypes.string_at(context.workspace, WORKSPACE_BYTES), bytes(workspace.data))
            self.assertEqual(bytes(source.data), wire)
            frames += 1
            if not result.request:
                break
            context.invoke(result)
        self.assertEqual(frames, 5)

    def test_replay_foreign_metadata_and_unsolicited_acknowledgements_refused(self):
        for mode in ('replay', 'metadata', 'pool', 'count', 'action', 'index'):
            context = ModuleContext(HeldOwner())
            result = self.native.step(context)
            context.invoke(result)
            if mode == 'replay':
                struct.pack_into('<Q', context.output, 8, 0)
            elif mode == 'metadata':
                changed = list(context.metadata); changed[3] = 'f' * 32
                context.wire = transport(changed)
            else:
                at = {'pool': 32, 'count': 48, 'action': 16, 'index': 24}[mode]
                struct.pack_into('<Q', context.output, at, 55)
            with self.subTest(mode=mode), self.assertRaises(HIAProgramRejected):
                self.native.step(context)

    def test_private_bounds_canaries_and_nonzero_unowned_scratch(self):
        frames = []
        for fill in (0, 165, 255):
            context = ModuleContext(HeldOwner())
            context.metadata[3] = 'a' * 32
            context.wire = transport(context.metadata)
            output = ctypes.create_string_buffer(OUTPUT_BYTES + 32)
            workspace = ctypes.create_string_buffer(WORKSPACE_BYTES + 32)
            ctypes.memmove(output, context.output, OUTPUT_BYTES)
            ctypes.memset(workspace, fill, WORKSPACE_BYTES)
            # Only the retained state's ownership word must initially be zero;
            # all remaining scratch bytes may be arbitrary.
            struct.pack_into('<Q', workspace, 8192, 0)
            ctypes.memset(ctypes.addressof(output) + OUTPUT_BYTES, 0xa7, 32)
            ctypes.memset(ctypes.addressof(workspace) + WORKSPACE_BYTES, 0xb9, 32)
            source = ctypes.create_string_buffer(context.wire)
            for oc, wc in ((OUTPUT_BYTES - 1, WORKSPACE_BYTES), (OUTPUT_BYTES, WORKSPACE_BYTES - 1)):
                self.assertEqual(self.native._entry(source, len(context.wire), output, oc, workspace, wc), 0xfffffff1)
            extent = self.native._entry(source, len(context.wire), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
            self.assertTrue(80 <= extent <= OUTPUT_BYTES)
            frames.append(ctypes.string_at(output, extent))
            self.assertEqual(ctypes.string_at(ctypes.addressof(output) + OUTPUT_BYTES, 32), b'\xa7' * 32)
            self.assertEqual(ctypes.string_at(ctypes.addressof(workspace) + WORKSPACE_BYTES, 32), b'\xb9' * 32)
            self.assertEqual(ctypes.string_at(source, len(context.wire)), context.wire)
        self.assertEqual(frames, [frames[0]] * 3)
        for wire in (b'', context.wire[:-1], context.wire + b'\0', transport(None),
                     transport(['bad', 'm', 1, 'a' * 32]),
                     transport(['hepta.hia.composite.v1', 'm', 1025, 'a' * 32])):
            fresh = ModuleContext(HeldOwner())
            source = ctypes.create_string_buffer(wire, max(1, len(wire)))
            self.assertEqual(self.native._entry(source, len(wire), fresh.output, OUTPUT_BYTES,
                                               fresh.workspace, WORKSPACE_BYTES), 0xfffffff1)

    def test_original_resource_and_loan_suites_without_host_module(self):
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(('tests.test_hia_program_composite',
            'tests.test_hia_partial_record', 'tests.test_hia_composite_returned_loans.CompositeReturnedLoans'))
        log = io.StringIO()
        with self.selected(), patch.object(composite._Elaborator, '_reference_lower',
                side_effect=AssertionError('host module used')):
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        self.assertEqual(loader.errors, [])
        self.assertTrue(result.wasSuccessful(), log.getvalue())
        self.assertEqual((result.testsRun, len(result.skipped), len(result.expectedFailures),
                          len(result.unexpectedSuccesses)), (75, 0, 0, 0), log.getvalue())


    def test_installed_wheel_without_authoring_or_host_module(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/nominal_module.hiaasm', NATIVE_SOURCE_FILES)
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
            raise AssertionError('installed module imported authoring tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_nominal_module_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('host module called')
composite._Elaborator._reference_lower=absent
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
        resource = installed / 'hepta/_data/examples/hia_bootstrap/nominal_module.hiaasm'
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
        with self.selected(), patch.object(composite._Elaborator, '_reference_lower',
                side_effect=AssertionError('host module called')):
            checked = verify_core(resource_program())
        obj = self.folder / 'module-effects.o'
        compile_program_machine(emit_program_machine(checked), program=checked, output=obj, kind='object', linker=cc)
        source, executable = self.folder / 'module-effects.c', self.folder / 'module-effects'
        source.write_text(driver)
        built = subprocess.run([cc, '-std=c11', '-O2', str(source), str(obj),
            '-Wl,--wrap=calloc', '-Wl,--wrap=free', '-o', str(executable)], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        ran = subprocess.run([str(executable)], capture_output=True, timeout=30)
        self.assertEqual((ran.returncode, ran.stdout, ran.stderr), (0, b'1 1 1\n', b''))

    def test_selected_manifest_image_and_source_hash_fail_closed(self):
        loaded = installed_nominal_module(str(self.manifest))
        self.assertIsNotNone(loaded)
        original = self.manifest.read_bytes()
        for field in ('source_sha256', 'image_sha256'):
            value = json.loads(original); value[field] = '0' * 64
            target = self.folder / ('bad-' + field + '.json'); target.write_text(json.dumps(value))
            with self.subTest(field=field), self.assertRaises((ValueError, OSError)):
                installed_nominal_module(str(target))
        value = json.loads(original); value['compiler_sha256'] = 'invalid'
        target = self.folder / 'bad-compiler-syntax.json'; target.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            installed_nominal_module(str(target))


if __name__ == '__main__':
    unittest.main()
