"""Complete HIA cache policy, native continuation custody and installation."""
from __future__ import annotations

import ast
from contextlib import ExitStack
from copy import deepcopy
import ctypes
from dataclasses import replace
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import weakref

from hepta import hia_program_composite as composite
from hepta.hia_composite_types_native import _NativeTypeIdentity, SELECTOR as TYPE_SELECTOR
from hepta.hia_instruction_policy_native import transport
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import execute_program
from hepta.hia_task_helper_cache_native import (MAGIC, SOURCE, SCHEMA, SELECTOR,
    INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES, HelperCacheContext, NativeTaskHelperCache,
    installed_task_helper_cache, selected_task_helper_cache)
from hepta.hia_task_helpers_native import SELECTOR as HELPER_SELECTOR
from tests import test_hia_program_composite as fixtures
from tests import test_hia_task_helpers_native as helpers

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_TASK_HELPER_CACHE_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_TASK_HELPER_CACHE_DEVELOPMENT_MANIFEST'
REFERENCE_AST_SHA256 = '9a2986d04df78f9c563504c9b9019808c8f728f3e22a5bfd71c300148af52947'
_reject = composite._reject


def reference_helper_cache(self, typ, operation, *, require_native=False):
    key = (typ.key, operation)
    if key in self.helper_names:
        return self.helper_names[key]
    from hepta.hia_task_helpers_native import selected_task_helpers
    selected = selected_task_helpers()
    if selected is None:
        if require_native:
            _reject("selected native function requires native task helper generation", "E_HIA_TYPE")
        return self._reference_helper(typ, operation)
    step = self.check_task(typ)
    result = selected.generate(typ, step, operation, self.serial,
        self.functions[typ.poll]["effects"], self.functions[typ.cancel]["effects"])
    self.serial = result.serial
    if result.name is not None:
        self.helper_names[key] = result.name
    result.admit()
    self.helpers.append(result.helper)
    return result.name


def reference_ast(function):
    body = ast.parse(textwrap.dedent(inspect.getsource(function))).body[0].body
    # The independent copy lives in tests, so its import is absolute. No
    # executable statement or branch differs from the captured old wrapper.
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.ImportFrom) and node.module == 'hepta.hia_task_helpers_native':
            node.module, node.level = 'hia_task_helpers_native', 1
    return sha256(ast.dump(ast.Module(body=body, type_ignores=[])).encode()).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def opaque_owner():
    nonce = object()
    typ = SimpleNamespace(key=_NativeTypeIdentity(nonce, 1))
    owner = SimpleNamespace(helper_names={}, helpers=[], serial=0, native_types=None)
    return owner, typ


def observed(owner, action):
    try:
        value, error = action(), None
    except HIAProgramRejected as exc:
        value, error = None, (type(exc).__name__, exc.code, str(exc))
    except KeyError as exc:
        value, error = None, (type(exc).__name__, exc.args)
    names = tuple((key.identifier, operation, name) for (key, operation), name in owner.helper_names.items())
    observations = owner.native_types.observations if hasattr(owner.native_types, 'observations') else None
    return value, error, owner.serial, names, deepcopy(owner.helpers), observations


class TaskHelperCacheSourceTests(unittest.TestCase):
    def test_generator_complete_ir_and_unchanged_compiler_profile(self):
        from tools import generate_hia_task_helper_cache as generator
        from hepta.hia_agent_assembly import render_assembly
        from tools.hia_selfhost_limits import MAX_FUNCTIONS, MAX_BLOCKS, MAX_INSTRUCTIONS
        doc = generator.document()
        self.assertEqual(render_assembly(doc).encode(), SOURCE.read_bytes())
        self.assertLessEqual(len(doc['functions']), MAX_FUNCTIONS)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in doc['functions']), MAX_BLOCKS)
        self.assertLessEqual(sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks']), MAX_INSTRUCTIONS)
        self.assertLessEqual(max(len(block['params']) for fn in doc['functions'] for block in fn['blocks']), 16)
        self.assertEqual((generator.MAGIC, generator.INPUT_BYTES, generator.OUTPUT_BYTES, generator.WORKSPACE_BYTES),
                         (MAGIC, INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES))
        verify_core(doc)

    def test_independent_original_wrapper_and_exact_type_identity_transport(self):
        self.assertEqual(reference_ast(reference_helper_cache), REFERENCE_AST_SHA256)
        if hasattr(composite._Elaborator, '_reference_helper_cache'):
            self.assertEqual(reference_ast(composite._Elaborator._reference_helper_cache), REFERENCE_AST_SHA256)
        owner, typ = opaque_owner()
        held = 'h2internal_7'
        owner.helper_names[(typ.key, 'start')] = held
        context = HelperCacheContext(owner, typ, 'start')
        try:
            self.assertIs(context.pool.get(0), held)
            self.assertEqual(context.metadata[3], [[1, 'start', held, 0]])
            self.assertIs(context.keys[1], typ.key)
        finally:
            context.close()
        owner.helper_names[(_NativeTypeIdentity(object(), 1), 'poll')] = held
        with self.assertRaisesRegex(HIAProgramRejected, 'outside the held HIA session'):
            HelperCacheContext(owner, typ, 'start')
        with self.assertRaisesRegex(HIAProgramRejected, 'HIA-issued'):
            HelperCacheContext(owner, SimpleNamespace(key='host structural key'), 'start')

    def test_selected_missing_manifest_is_explicit_refusal(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(selected_task_helper_cache())
        with patch.dict(os.environ, {SELECTOR: '/absent-task-helper-cache-manifest'}):
            with self.assertRaisesRegex(HIAProgramRejected, 'selected native task helper cache refused'):
                selected_task_helper_cache()


class TaskHelperCacheAdapterTests(unittest.TestCase):
    def context(self):
        owner, typ = opaque_owner()
        context = HelperCacheContext(owner, typ, 'start')
        self.addCleanup(context.close)
        return context

    def image(self, data, *, mutate=False):
        image = object.__new__(NativeTaskHelperCache)
        def entry(source, size, output, capacity, workspace, workspace_size):
            if mutate:
                ctypes.memmove(source, b'x', 1)
            if type(data) is int:
                return data
            ctypes.memmove(output, data, len(data))
            return len(data)
        image._entry = entry
        return image

    def frame(self, *, error=0, request=1, sequence=1, reserved=0, value=None):
        if value is None:
            value = {}
        encoded = transport(value)
        return struct.pack('<8Q', MAGIC, error, request, len(encoded), sequence, reserved, 0, 0) + encoded

    def test_frames_custody_and_complete_state_shapes_fail_closed(self):
        good = dict(serial=[], cache=[], helpers=[], name=None)
        malformed = [0, 0xfffffff1, self.frame(error=9), self.frame(error=1),
            self.frame(request=7), self.frame(sequence=0), self.frame(reserved=1), self.frame(value=[]),
            self.frame(request=0), self.frame(request=0, value=dict(good, serial=[True])),
            self.frame(request=0, value=dict(good, cache=[[2, 'start', 'h2internal_1']])),
            self.frame(error=1, request=0, value=dict(good, helpers=[{}]))]
        for data in malformed:
            with self.subTest(data=repr(data)[:70]):
                context = self.context()
                with self.assertRaises(HIAProgramRejected):
                    self.image(data).step(context)
                self.assertTrue(context.closed)
                self.assertEqual((context.owner.serial, context.owner.helpers, context.owner.helper_names), (0, [], {}))
                context.close()
        context = self.context()
        with self.assertRaisesRegex(HIAProgramRejected, 'input bytes changed'):
            self.image(self.frame(), mutate=True).step(context)
        context.close()
        context = self.context()
        context.metadata[1] = 'poll'
        with self.assertRaisesRegex(HIAProgramRejected, 'metadata changed'):
            context.data()

    def test_callback_permissions_are_consumed_before_external_work(self):
        context = self.context()
        image = self.image(self.frame())
        result = image.step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'not completed'):
            image.step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'current unexecuted'):
            context.service(result.request, dict(result.value))
        fault = KeyboardInterrupt('selector interrupted after native request')
        with patch('hepta.hia_task_helpers_native.selected_task_helpers', side_effect=fault) as selected:
            held = None
            try:
                context.service(result.request, result.value)
            except KeyboardInterrupt as error:
                held = error
            self.assertIs(held, fault)
            self.assertEqual(selected.call_count, 1)
            self.assertTrue(context.closed)
            self.assertEqual((context.executed, context.completed), (1, 0))
            with self.assertRaisesRegex(HIAProgramRejected, 'current unexecuted'):
                context.service(result.request, result.value)
            self.assertEqual(selected.call_count, 1)


    def test_terminal_commit_requires_the_exact_issued_result_and_cannot_replay(self):
        context = self.context()
        with self.assertRaisesRegex(HIAProgramRejected, 'current uncommitted'):
            context.commit(None)
        value = dict(serial=[7], cache=[[1, 'start', 'h2internal_7']],
                     helpers=[{'name': 'held-helper'}], name='h2internal_7')
        result = self.image(self.frame(request=0, value=value)).step(context)
        self.assertIs(context.terminal, result)
        with self.assertRaisesRegex(HIAProgramRejected, 'current uncommitted'):
            context.commit(replace(result))
        other = self.context()
        foreign = self.image(self.frame(request=0, value=value)).step(other)
        with self.assertRaisesRegex(HIAProgramRejected, 'current uncommitted'):
            context.commit(foreign)
        self.assertEqual((context.owner.serial, context.owner.helper_names, context.owner.helpers), (0, {}, []))
        self.assertIs(context.commit(result), result.value['name'])
        expected = (7, {(context.typ.key, 'start'): 'h2internal_7'}, [{'name': 'held-helper'}])
        self.assertEqual((context.owner.serial, context.owner.helper_names, context.owner.helpers), expected)
        with self.assertRaisesRegex(HIAProgramRejected, 'current uncommitted'):
            context.commit(result)
        self.assertEqual((context.owner.serial, context.owner.helper_names, context.owner.helpers), expected)
        other.close()
        with self.assertRaisesRegex(HIAProgramRejected, 'current uncommitted'):
            other.commit(foreign)
        self.assertEqual((other.owner.serial, other.owner.helper_names, other.owner.helpers), (0, {}, []))

        partial = self.context()
        fault = KeyboardInterrupt('terminal cache prefix interrupted after mutation')
        class InterruptedCache(dict):
            def __setitem__(self, key, name):
                super().__setitem__(key, name)
                raise fault
        partial.owner.helper_names = InterruptedCache()
        issued = self.image(self.frame(request=0, value=value)).step(partial)
        held = None
        try:
            partial.commit(issued)
        except KeyboardInterrupt as error:
            held = error
        self.assertIs(held, fault)
        self.assertTrue(partial.committed)
        self.assertTrue(partial.closed)
        self.assertTrue(partial.released)
        self.assertIsNone(partial.output)
        self.assertIsNone(partial.workspace)
        expected_prefix = (7, {(partial.typ.key, 'start'): 'h2internal_7'}, [])
        self.assertEqual((partial.owner.serial, partial.owner.helper_names, partial.owner.helpers), expected_prefix)
        with self.assertRaisesRegex(HIAProgramRejected, 'current uncommitted'):
            partial.commit(issued)
        self.assertEqual((partial.owner.serial, partial.owner.helper_names, partial.owner.helpers), expected_prefix)

    def test_partial_constructor_allocation_is_released_with_original_traceback(self):
        real = ctypes.create_string_buffer
        owner, typ = opaque_owner()
        refs, requests = [], []
        fault = MemoryError('controlled second cache arena refusal')
        def allocate(size, *args):
            requests.append(size)
            if len(requests) == 2:
                raise fault
            value = real(size, *args)
            refs.append(weakref.ref(value))
            return value
        held = None
        with patch('hepta.hia_task_helper_cache_native.ctypes.create_string_buffer', allocate):
            try:
                object.__new__(NativeTaskHelperCache).lower(owner, typ, 'start')
            except MemoryError as error:
                held = error
        self.assertIs(held, fault)
        self.assertEqual(requests, [OUTPUT_BYTES, WORKSPACE_BYTES])
        self.assertIsNone(refs[0]())
        traceback = held.__traceback__
        while traceback.tb_frame.f_code is not HelperCacheContext.__init__.__code__:
            traceback = traceback.tb_next
        context = traceback.tb_frame.f_locals['self']
        self.assertTrue(context.closed)
        self.assertIsNone(context.output)
        self.assertIsNone(context.workspace)


class TaskHelperCacheNativeTests(unittest.TestCase):
    def test_actual_issued_payload_changes_refuse_before_callback_or_commit(self):
        with self.selected():
            owner, typ = self.owner()
            owner.serial = 7
            owner.helper_names[(typ.key, 'start')] = 'h2internal_7'
            context = HelperCacheContext(owner, typ, 'start', require_native=True)
            try:
                result = self.native.step(context)
                self.assertEqual((result.request, result.error, result.value['serial']), (0, 0, []))
                result.value['serial'].append(99)
                with self.assertRaisesRegex(HIAProgramRejected, 'issued graph changed'):
                    context.commit(result)
                self.assertEqual((owner.serial, owner.helpers), (7, []))
                self.assertTrue(context.closed)
                self.assertIsNone(context._binding)
                self.assertIsNone(context.output)
                self.assertIsNone(context.workspace)
            finally:
                context.close()
            owner, typ = self.owner()
            context = HelperCacheContext(owner, typ, 'start', require_native=True)
            try:
                for _ in range(16):
                    result = self.native.step(context)
                    if result.request == 5:
                        break
                    self.assertTrue(result.request)
                    context.service(result.request, result.value)
                else:
                    self.fail('native generator continuation was not issued')
                self.assertEqual(result.value, {'serial': 0})
                result.value['serial'] = 77
                with patch.object(context.generator, 'generate',
                        side_effect=AssertionError('changed query reached the generator')):
                    with self.assertRaisesRegex(HIAProgramRejected, 'issued graph changed'):
                        context.service(result.request, result.value)
                self.assertEqual((owner.serial, owner.helper_names, owner.helpers), (0, {}, []))
                self.assertTrue(context.closed)
                self.assertIsNone(context._binding)
            finally:
                context.close()

    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development task helper cache cannot override cold qualification')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-task-helper-cache-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.folder = Path(cls.temporary.name)
        if development:
            supplied = Path(development)
            value = json.loads(supplied.read_bytes())
            name = value['image_path']
            assert type(name) is str and Path(name).name == name
            shutil.copyfile(supplied.parent / name, cls.folder / name)
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(supplied.read_bytes())
            cls.fixture_scope = 'DEVELOPMENT_ONLY'
        elif cold:
            from tools.build_hia_json_preflight import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold), candidate='task-helper-cache')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            image, receipt = compile_stage(cls.folder, 'task-helper-cache', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(wire(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
                image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
            (cls.folder / 'development-compile.json').write_bytes(wire(receipt))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native = installed_task_helper_cache(str(cls.manifest))
        from tests import test_hia_composite_types_native as types
        cls.support = {}
        for module, implementation in ((types, types.CompositeTypesNativeTests), (helpers, helpers.TaskHelpersNativeTests)):
            fixture = type('SupportingFixture', (unittest.TestCase,), {})
            cls.addClassCleanup(fixture.doClassCleanups)
            extra = {}
            if cold and not os.environ.get(module.COLD_REPORT):
                extra[module.COLD_REPORT] = cold
            with patch.dict(os.environ, extra):
                implementation.setUpClass.__func__(fixture)
            cls.support[module.SELECTOR] = str(fixture.manifest)

    def selected(self, *, cache=True):
        return patch.dict(os.environ, {**self.support, SELECTOR: str(self.manifest) if cache else ''})

    def owner(self, document=None):
        owner = composite._Elaborator(deepcopy(document if document is not None else fixtures.scalar_task_program()))
        self.addCleanup(owner.native_types.close)
        name = next(item['name'] for item in owner.document['types'] if item['kind'] == 'task')
        return owner, owner.types.resolve(name)

    def test_complete_five_operations_original_failures_and_cache_prefixes(self):
        with self.selected(cache=False):
            for factory in helpers.FACTORIES:
                old, ot = self.owner(factory())
                new, nt = self.owner(factory())
                try:
                    for operation in helpers.OPERATIONS:
                        for serial in (0, 8188, 8191, 8192):
                            for owner in (old, new):
                                owner.serial = serial
                                owner.helper_names.clear()
                                owner.helpers.clear()
                            with self.subTest(factory=factory.__name__, operation=operation, serial=serial):
                                expected = observed(old, lambda: reference_helper_cache(old, ot, operation, require_native=True))
                                with patch.object(composite._Elaborator, '_reference_helper', side_effect=AssertionError('host generator')):
                                    actual = observed(new, lambda: self.native.lower(new, nt, operation, require_native=True))
                                self.assertEqual(actual, expected)
                                if (nt.key, operation) in new.helper_names:
                                    prefix = (new.serial, deepcopy(new.helpers), dict(new.helper_names))
                                    with patch.dict(os.environ, {HELPER_SELECTOR: '/absent-generator'}), patch.object(
                                            new.native_types, 'check_task', side_effect=AssertionError('cached task rechecked')):
                                        name = self.native.lower(new, nt, operation, require_native=True)
                                    self.assertIs(name, new.helper_names[(nt.key, operation)])
                                    self.assertEqual(prefix, (new.serial, new.helpers, new.helper_names))
                    # Independent pure old generator control, in addition to
                    # the exact old cache wrapper around the native generator.
                    for owner in (old, new):
                        owner.serial = 0; owner.helper_names.clear(); owner.helpers.clear()
                    expected = observed(old, lambda: old._reference_helper(ot, 'poll'))
                    self.assertEqual(observed(new, lambda: self.native.lower(new, nt, 'poll')), expected)
                finally:
                    old.native_types.close(); new.native_types.close()

    def test_cache_is_shared_across_calls_and_generator_is_pinned_once(self):
        from hepta import hia_task_helpers_native as generated
        with self.selected():
            owner, typ = self.owner()
            generator = generated.selected_task_helpers()
            entry = generator._entry
            generate = generator.generate
            events, entered, produced = [], [], []
            original_check = owner.native_types.check_task
            def check(*args):
                events.append('check_task')
                return original_check(*args)
            def selected():
                events.append('select')
                os.environ[HELPER_SELECTOR] = '/rebound-after-real-admission'
                return generator
            def native_entry(*args):
                entered.append(True)
                return entry(*args)
            def invoke(*args):
                events.append('generate')
                value = generate(*args)
                produced.append(value)
                return value
            with patch.object(generated, 'selected_task_helpers', side_effect=selected), patch.object(
                    owner.native_types, 'check_task', side_effect=check), patch.object(generator, '_entry', side_effect=native_entry), patch.object(
                    generator, 'generate', side_effect=invoke):
                name = self.native.lower(owner, typ, 'start', require_native=True)
                self.assertEqual(events, ['select', 'check_task', 'generate'])
                self.assertEqual(len(entered), 1)
                self.assertIs(owner.helpers[0], produced[0].helper)
                self.assertIs(name, produced[0].name)
                prefix = (owner.serial, tuple(owner.helpers), dict(owner.helper_names))
                for _ in range(3):
                    self.assertIs(self.native.lower(owner, typ, 'start', require_native=True), name)
                self.assertEqual(events, ['select', 'check_task', 'generate'])
                self.assertEqual(prefix, (owner.serial, tuple(owner.helpers), owner.helper_names))

    def test_miss_guards_and_protocol_effect_lookup_error_order(self):
        with self.selected():
            owner, typ = self.owner()
            for required, message in ((True, 'selected native function requires native task helper generation'),
                                      (False, 'selected native task helper cache requires native task helper generation')):
                with patch.dict(os.environ, {HELPER_SELECTOR: ''}), patch.object(owner.native_types, 'check_task',
                        side_effect=AssertionError('guard moved after task check')):
                    with self.assertRaisesRegex(HIAProgramRejected, message):
                        self.native.lower(owner, typ, 'start', require_native=required)
                self.assertEqual((owner.serial, owner.helper_names, owner.helpers), (0, {}, []))
            for mode in ('poll_function', 'cancel_function', 'poll_effects', 'cancel_effects', 'poll_signature'):
                old, ot = self.owner(); new, nt = self.owner()
                try:
                    for current, typ in ((old, ot), (new, nt)):
                        if mode.endswith('_function'):
                            current.functions.pop(typ.poll if mode.startswith('poll') else typ.cancel)
                        elif mode.endswith('_effects'):
                            current.functions[typ.poll if mode.startswith('poll') else typ.cancel].pop('effects')
                        else:
                            params, _ = current.signatures[typ.poll]
                            current.signatures[typ.poll] = (params, ())
                    with self.subTest(mode=mode):
                        self.assertEqual(observed(new, lambda: self.native.lower(new, nt, 'poll', require_native=True)),
                            observed(old, lambda: reference_helper_cache(old, ot, 'poll', require_native=True)))
                finally:
                    old.native_types.close(); new.native_types.close()

    def test_private_unreachable_padding_refusals_keep_generated_names(self):
        # These are explicit private descriptor controls, not publicly admitted
        # loan-capturing tasks. The generator and cache images are real; the
        # protocol callback supplies the retained fixture's complete step.
        with self.selected():
            for state, result, operation in ((['readbuf'], [], 'join'), ([], ['readbuf'], 'poll'),
                                              (['readbuf'], [], 'cancel')):
                for serial in (0, 8191, 8192):
                    old, old_task = helpers.helper_owner(state, result, serial=serial)
                    new, new_task = helpers.helper_owner(state, result, serial=serial)
                    nonce = object()
                    old_task = replace(old_task, key=_NativeTypeIdentity(nonce, 1))
                    new_task = replace(new_task, key=old_task.key)
                    old_step, new_step = old.signatures['poll'][1][0], new.signatures['poll'][1][0]
                    old.check_task = lambda task: old_step
                    new.native_types = SimpleNamespace(_nonce=nonce, check_task=lambda task, signatures: new_step)
                    with self.subTest(state=state, result=result, operation=operation, serial=serial):
                        self.assertEqual(observed(new, lambda: self.native.lower(new, new_task, operation)),
                            observed(old, lambda: reference_helper_cache(old, old_task, operation)))

    def test_independent_vm_and_native_complete_frames_workspace_and_all_requests(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(SOURCE.read_bytes())
        requests = set()
        with self.selected():
            for mode in ('success', 'missing_function', 'generated_refusal', 'cached'):
                owner, typ = self.owner()
                if mode == 'missing_function': owner.functions.pop(typ.cancel)
                if mode == 'generated_refusal': owner.serial = 8191
                if mode == 'cached': owner.helper_names[(typ.key, 'start')] = 'h2internal_9'
                context = HelperCacheContext(owner, typ, 'start', require_native=True)
                workspace = _Owner(-3, bytearray(WORKSPACE_BYTES))
                output = _Owner(-2, bytearray(OUTPUT_BYTES))
                try:
                    for _ in range(16):
                        data = context.data()
                        source = _Owner(-1, bytearray(data))
                        machine = _Machine(checked, 20_000_000, 128 << 20, None, 256)
                        extent = machine.invoke(checked.as_dict()['functions'][0],
                            [_View(source, False), _View(output, True), _View(workspace, True)])[0]
                        result = self.native.step(context)
                        self.assertEqual(extent, 64 + struct.unpack_from('<Q', context.output, 24)[0])
                        self.assertEqual(bytes(output.data[:extent]), ctypes.string_at(context.output, extent))
                        self.assertEqual(bytes(workspace.data), ctypes.string_at(context.workspace, WORKSPACE_BYTES))
                        self.assertEqual(bytes(source.data), data)
                        if not result.request:
                            break
                        requests.add(result.request)
                        if result.request == 6:
                            with self.assertRaises(KeyError): context.service(result.request, result.value)
                            break
                        context.service(result.request, result.value)
                    else:
                        self.fail('native cache controller did not finish')
                finally:
                    context.close(); owner.native_types.close()
        self.assertEqual(requests, set(range(1, 7)))

    def test_private_node_byte_bounds_canaries_and_exact_inventory_custody(self):
        owner, typ = opaque_owner()
        context = HelperCacheContext(owner, typ, 'start')
        try:
            context.metadata[-1] = 'a' * 32
            context.metadata_bytes = transport(context.metadata)
            data = context.data()
            source = ctypes.create_string_buffer(data)
            output = ctypes.create_string_buffer(OUTPUT_BYTES + 32)
            workspace = ctypes.create_string_buffer(WORKSPACE_BYTES + 32)
            ctypes.memset(output, 0xa7, OUTPUT_BYTES + 32)
            ctypes.memset(ctypes.addressof(workspace) + WORKSPACE_BYTES, 0xb9, 32)
            for oc, wc in ((OUTPUT_BYTES - 1, WORKSPACE_BYTES), (OUTPUT_BYTES, WORKSPACE_BYTES - 1)):
                self.assertEqual(self.native._entry(source, len(data), output, oc, workspace, wc), 0xfffffff1)
                self.assertEqual(ctypes.string_at(output, OUTPUT_BYTES), b'\xa7' * OUTPUT_BYTES)
            extent = self.native._entry(source, len(data), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
            self.assertGreaterEqual(extent, 88)
            self.assertEqual(ctypes.string_at(ctypes.addressof(output) + OUTPUT_BYTES, 32), b'\xa7' * 32)
            self.assertEqual(ctypes.string_at(ctypes.addressof(workspace) + WORKSPACE_BYTES, 32), b'\xb9' * 32)
            too_many = transport([None] * 8192)
            bad_source = ctypes.create_string_buffer(too_many)
            before = ctypes.string_at(ctypes.addressof(workspace) + 4096, WORKSPACE_BYTES - 4096)
            self.assertEqual(self.native._entry(bad_source, len(too_many), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES), 0xfffffff1)
            self.assertEqual(ctypes.string_at(ctypes.addressof(workspace) + 4096, WORKSPACE_BYTES - 4096), before)
        finally:
            context.close()
        with self.selected():
            owner, typ = self.owner()
            context = HelperCacheContext(owner, typ, 'start')
            try:
                while True:
                    result = self.native.step(context)
                    if result.request == 4:
                        context.service(result.request, result.value)
                        break
                    context.service(result.request, result.value)
                context.inventory[2][0] = 'changed_native_inventory'
                with self.assertRaises(HIAProgramRejected): self.native.step(context)
                self.assertTrue(context.closed)
                self.assertEqual((owner.serial, owner.helper_names, owner.helpers), (0, {}, []))
            finally:
                context.close(); owner.native_types.close()

    def test_conservative_640_cache_rows_and_1024_function_names(self):
        with self.selected():
            owner, typ = self.owner(helpers.maximum_program())
            # The maximum private envelope is deliberately conservative:
            # these opaque cache IDs do not assert new public task admission.
            for i in range(128):
                for operation in helpers.OPERATIONS:
                    owner.helper_names[(_NativeTypeIdentity(typ.key.session, 1000 + i), operation)] = 'h' + 'a' * 127
            while len(owner.functions) < 1024:
                name = 'f' + str(len(owner.functions)).zfill(4) + 'a' * 123
                owner.functions[name] = {'effects': []}
            context = HelperCacheContext(owner, typ, 'start')
            largest = 0
            try:
                for _ in range(16):
                    largest = max(largest, len(context.data()))
                    result = self.native.step(context)
                    if result.request == 5:
                        break
                    context.service(result.request, result.value)
                else:
                    self.fail('maximum held inventory did not reach the generator continuation')
                self.assertLess(largest, 310000)
                self.assertLess(largest, INPUT_BYTES)
                self.assertEqual(len(context.metadata[3]), 640)
                self.assertEqual(len(context.inventory[2]), 1024)
            finally:
                context.close(); owner.native_types.close()

    def test_actual_callback_interruptions_and_prefix_failure_cannot_replay(self):
        from hepta import hia_task_helper_cache_native as cache_module
        from hepta import hia_task_helpers_native as generated
        with self.selected():
            for mode in ('protocol_return', 'generator_return', 'reply_assignment', 'cache_commit'):
                owner, typ = self.owner()
                generator = generated.selected_task_helpers()
                original_check, original_generate = owner.native_types.check_task, generator.generate
                fault = KeyboardInterrupt('actual cache continuation ' + mode)
                captured, calls, results = [], [], []
                original_init = HelperCacheContext.__init__
                def initialize(context, *args, **kwargs):
                    original_init(context, *args, **kwargs); captured.append(context)
                def check(*args):
                    value = original_check(*args)
                    calls.append('protocol')
                    if mode == 'protocol_return': raise fault
                    return value
                def generate(*args):
                    value = original_generate(*args)
                    calls.append('generator'); results.append(value)
                    if mode == 'generator_return': raise fault
                    return value
                class FailingCache(dict):
                    def __setitem__(self, key, value):
                        super().__setitem__(key, value)
                        raise fault
                if mode == 'cache_commit': owner.helper_names = FailingCache()
                class ReplyLoss(HelperCacheContext):
                    def __setattr__(self, name, value):
                        if name == 'reply' and getattr(self, 'generated', None) is not None:
                            raise fault
                        super().__setattr__(name, value)
                held = None
                with patch.object(HelperCacheContext, '__init__', initialize), patch.object(
                        cache_module, 'HelperCacheContext', ReplyLoss if mode == 'reply_assignment' else HelperCacheContext), patch.object(
                        owner.native_types, 'check_task', side_effect=check), patch.object(generator, 'generate', side_effect=generate), patch.object(
                        generated, 'selected_task_helpers', return_value=generator):
                    try:
                        self.native.lower(owner, typ, 'start', require_native=True)
                    except KeyboardInterrupt as error:
                        held = error
                with self.subTest(mode=mode):
                    self.assertIs(held, fault)
                    context, = captured
                    self.assertTrue(context.closed)
                    self.assertIsNone(context.output); self.assertIsNone(context.workspace)
                    prefix = (owner.serial, dict(owner.helper_names), deepcopy(owner.helpers), list(calls))
                    with self.assertRaises(HIAProgramRejected): context.data()
                    with self.assertRaises(HIAProgramRejected): self.native.step(context)
                    with self.assertRaises(HIAProgramRejected): context.service(5, {})
                    with self.assertRaises(HIAProgramRejected): context.commit(context.terminal)
                    self.assertEqual(prefix, (owner.serial, owner.helper_names, owner.helpers, calls))
                    if mode == 'cache_commit':
                        self.assertEqual(owner.serial, results[0].serial)
                        self.assertIs(owner.helper_names[(typ.key, 'start')], results[0].name)
                        self.assertEqual(owner.helpers, [])
                    else:
                        self.assertEqual((owner.serial, owner.helper_names, owner.helpers), (0, {}, []))
                owner.native_types.close()

    def test_public_profiles_runtime_and_complete_selected_cache_without_host_bodies(self):
        self.assertTrue(hasattr(composite._Elaborator, '_reference_helper_cache'), 'selected cache integration is required')
        for version in (1, 2, 3, 4):
            document = fixtures.scalar_task_program()
            document['schema'] = 'hepta.hia.composite.v' + str(version)
            with self.selected(cache=False):
                expected = verify_core(document)
            with self.selected(), patch.object(composite._Elaborator, '_reference_helper_cache',
                    side_effect=AssertionError('host cache policy')), patch.object(composite._Elaborator, '_reference_helper',
                    side_effect=AssertionError('host helper generation')):
                actual = verify_core(document)
                self.assertEqual(actual.canonical_bytes, expected.canonical_bytes)
                self.assertEqual(execute_program(actual, 'scalar_task', []),
                                 execute_program(expected, 'scalar_task', []))

    def test_retained_actual_machine_allocator_and_protocol_aborts_with_native_cache(self):
        with patch.object(composite._Elaborator, '_reference_helper_cache', side_effect=AssertionError('host cache policy')):
            helpers.TaskHelpersNativeTests.test_actual_native_task_state_machine_allocator_and_protocol_aborts(self)

    def test_installed_wheel_without_checkout_and_changed_source_refusals(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/task_helper_cache.hiaasm', NATIVE_SOURCE_FILES)
        source = self.folder / 'wheel-source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        names = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES
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
        data = self.folder / 'installed-input.json'
        child = '''import sys,importlib.abc
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):raise AssertionError('installed cache imported authoring tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_task_helper_cache_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('host cache/generator called')
composite._Elaborator._reference_helper_cache=absent
composite._Elaborator._reference_helper=absent
composite._Elaborator._reference_check_task=absent
composite._Types=absent
try:result=verify_core(Path(sys.argv[2]).read_bytes())
except HIAProgramRejected:
    assert sys.argv[3]=='refuse';print('REFUSED')
else:
    assert sys.argv[3]=='accept';sys.stdout.buffer.write(result.canonical_bytes)
'''
        def run(mode, manifest=None):
            return subprocess.run([sys.executable, '-I', '-S', '-B', '-c', child,
                str(installed), str(data), mode], cwd=self.folder, capture_output=True, timeout=30,
                env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', **self.support,
                     SELECTOR: str(self.manifest if manifest is None else manifest)})
        for factory in (fixtures.task_program, fixtures.scalar_task_program):
            document = factory(); data.write_bytes(wire(document))
            with self.selected(cache=False): expected = verify_core(document).canonical_bytes
            result = run('accept')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
        installed_source = installed / 'hepta' / '_data' / 'examples' / 'hia_bootstrap' / SOURCE.name
        self.assertTrue(installed_source.is_file())
        original = installed_source.read_bytes()
        for mode in ('changed', 'missing'):
            if mode == 'changed': installed_source.write_bytes(original + b'\n')
            else: installed_source.unlink()
            result = run('refuse')
            self.assertEqual((result.returncode, result.stdout), (0, b'REFUSED\n'), result.stderr)
            installed_source.write_bytes(original)
        bad = self.folder / 'invalid-cache-manifest.json'; bad.write_text('{}')
        result = run('refuse', bad)
        self.assertEqual((result.returncode, result.stdout), (0, b'REFUSED\n'), result.stderr)
