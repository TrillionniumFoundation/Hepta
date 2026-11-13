"""New recovery controls for the byte-exact ad640 native call owner.

The former test file (SHA abcba5da...c543da) was not recovered.  This is a
new suite, not a reproduction of its historical 17-test qualification.
The frozen generator, HIA source, bridge and original semantic branch are
unchanged.  Adapter-only synthetic frames are separate from real HIA tests.
"""
from __future__ import annotations

import ast
from contextlib import ExitStack
from copy import deepcopy
import ctypes
from hashlib import sha256
import inspect
import io
import json
import math
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_call_primitive_native import (SOURCE, SCHEMA, SELECTOR, MAGIC,
    INPUT_BYTES, OUTPUT_BYTES, WORKSPACE_BYTES, ERRORS, CallPrimitivePacket,
    NativeCallPrimitive, installed_call_primitive, selected_call_primitive)
from hepta.hia_instruction_policy_native import transport
from hepta.hia_native_value_graph import _index, decode_native_graph
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_runtime import execute_program
from tests import test_hia_program_composite as fixtures
from tests import test_hia_partial_record as partials
from tests import test_hia_composite_returned_loans as loans
from tests.test_hia_program import b, c, f, i, ret

ROOT = Path(__file__).resolve().parents[1]
COLD_REPORT = 'HEPTA_HIA_CALL_PRIMITIVE_COLD_REPORT'
DEVELOPMENT_MANIFEST = 'HEPTA_HIA_CALL_PRIMITIVE_DEVELOPMENT_MANIFEST'
ORIGINAL_BRANCH_AST_SHA256 = '3d7b6d0c4d014f0928ed6a15ac72319e963c26c9916dadf93ecde7f98d8f1ab1'


def wire(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(',', ':')).encode()


def outcome(call):
    try:
        return call(), None
    except HIAProgramRejected as error:
        return None, (error.code, str(error))


def constant_program():
    """New fixture preserving the known original first const u32=37 contract."""
    return fixtures.module([], f('constant', [], ['u32'], [], [
        b('entry', [], [c('answer', 'u32', 37)], ret('answer'))]))


def call_program():
    """Reconstructed valid nominal call fixture; not claimed old fixture bytes."""
    pair = fixtures.record('Pair', [('left', 'u32'), ('right', 'u32')])
    mix = f('mix', [('input', 'Pair')], ['u32', 'Pair'], ['trap'], [
        b('entry', [('input', 'Pair')], [
            i('record.unpack', ['input'], [('left', 'u32'), ('right', 'u32')]),
            i('int.add.checked', ['left', 'right'], [('sum', 'u32')]),
            i('int.add.checked', ['sum', 'left'], [('answer', 'u32')]),
            i('record.make', ['right', 'left'], [('swapped', 'Pair')]),
        ], ret('answer', 'swapped'))])
    caller = f('caller', [('left', 'u32'), ('right', 'u32')], ['u32'], ['trap'], [
        b('entry', [('left', 'u32'), ('right', 'u32')], [
            i('record.make', ['left', 'right'], [('pair', 'Pair')]),
            i('call', ['pair'], [('answer', 'u32'), ('swapped', 'Pair')], function='mix'),
            i('record.unpack', ['swapped'], [('ignored_left', 'u32'), ('ignored_right', 'u32')]),
        ], ret('answer'))])
    return fixtures.module([pair], mix, caller)


def duplicate_owner_program():
    caller = f('duplicate', [('owned', 'buffer')], [], ['alloc'], [
        b('entry', [('owned', 'buffer')], [
            i('call', ['owned', 'owned'], [], function='drop_pair'),
        ], ret())])
    callee = f('drop_pair', [('first', 'buffer'), ('second', 'buffer')], [], ['alloc'], [
        b('entry', [('first', 'buffer'), ('second', 'buffer')], [
            i('owner.drop', ['first']), i('owner.drop', ['second']),
        ], ret())])
    return fixtures.module([], caller, callee)


def resource_call_program():
    measure = f('measure', [('owned', 'buffer')], ['usize'], ['alloc'], [
        b('entry', [('owned', 'buffer')], [
            i('buffer.len', ['owned'], [('length', 'usize')]), i('owner.drop', ['owned']),
        ], ret('length'))])
    caller = f('call_resource', [('size', 'usize')], ['usize'], ['alloc', 'trap'], [
        b('entry', [('size', 'usize')], [
            i('buffer.try_new', ['size'], [('owned', 'buffer'), ('ok', 'bool')]),
            i('call', ['owned'], [('length', 'usize')], function='measure'),
        ], ret('length'))])
    return fixtures.module([], measure, caller)


def scalar_type(name='u32'):
    return composite._Type(name, 'primitive', (name,), linear=name in {'buffer', 'chain', 'readbuf', 'mutbuf'})


class CallPrimitiveSourceTests(unittest.TestCase):
    def test_exact_generator_and_unchanged_compiler_limits(self):
        from tools import generate_hia_call_primitive as generator
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

    def test_original_branch_ast_and_identity_only_transport(self):
        function = ast.parse(textwrap.dedent(inspect.getsource(
            composite._Elaborator._reference_call_primitive))).body[0]
        branch = next(node for node in function.body if isinstance(node, ast.If))
        from tests.hia_reference_ast import reference_ast_dump
        self.assertEqual(sha256(reference_ast_dump(branch).encode()).hexdigest(),
                         ORIGINAL_BRANCH_AST_SHA256)
        class ForbiddenKey:
            def __str__(self): raise AssertionError('transport displayed nominal identity')
            def __hash__(self): raise AssertionError('transport hashed nominal identity')
            def __eq__(self, other): raise AssertionError('transport compared nominal identity')
        typ = composite._Type(ForbiddenKey(), 'record', ())
        value = composite._Value(typ, ())
        packet = CallPrimitivePacket('call', ['a', 'z'], {'function': 'f'}, [value, value],
                                     [('out', typ)], 8192)
        self.assertIs(type(packet.data()), bytes)
        self.assertEqual((len(packet.types), len(packet.values), packet.arguments),
                         (1, 1, [['a', 0], ['z', 0]]))

    def test_missing_or_falsy_selected_owner_never_enters_reference(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIsNone(selected_call_primitive())
        with patch.dict(os.environ, {SELECTOR: '/missing-call-primitive'}), patch.object(
                composite._Elaborator, '_reference_call_primitive',
                side_effect=AssertionError('selected reference fallback')):
            with self.assertRaises(HIAProgramRejected):
                composite.elaborate_program(constant_program())
        marker = HIAProgramRejected('falsy selected owner was reached', 'E_HIA_TYPE')
        class FalsySelected:
            def __bool__(self): return False
            def lower(self, *args, **kwargs): raise marker
        with patch('hepta.hia_call_primitive_native.selected_call_primitive', return_value=FalsySelected()), patch.object(
                composite._Elaborator, '_reference_call_primitive',
                side_effect=AssertionError('falsy owner fell back')):
            with self.assertRaises(HIAProgramRejected) as caught:
                composite.elaborate_program(constant_program())
        self.assertIs(caught.exception, marker)

    def test_requested_cold_gate_cannot_be_overridden_before_fixture_work(self):
        with patch.dict(os.environ, {COLD_REPORT: '/unread-cold', DEVELOPMENT_MANIFEST: '/unread-development'}), patch(
                'tempfile.TemporaryDirectory', side_effect=AssertionError('fixture work preceded admission')):
            with self.assertRaisesRegex(AssertionError, 'development.*cold'):
                CallPrimitiveNativeTests.setUpClass()


class CallPrimitiveAdapterTests(unittest.TestCase):
    def image(self, replies, *, mutate=False):
        image = object.__new__(NativeCallPrimitive)
        pending = iter(replies)
        def entry(source, size, output, capacity, workspace, workspace_size):
            if mutate:
                ctypes.memmove(source, b'x', 1)
            reply = next(pending)
            if type(reply) is not bytes:
                return reply
            ctypes.memmove(output, reply, len(reply))
            return len(reply)
        image._entry = entry
        return image

    def frame(self, *, serial=7, error=0, request=0, payload=None,
              magic=MAGIC, reserved=0, size_delta=0):
        if payload is None:
            payload = {'ops': [] if error or request else [i('const', [], [('answer', 'u32')], value=37)],
                'consumed': [], 'values': [] if error or request else [['answer', 0, ['answer'], False, False]],
                'query': {} if request else None}
        body = transport(payload)
        return struct.pack('<8Q', magic, error, serial, request, len(body)+size_delta, reserved, 0, 0) + body

    def context(self, *, operation='const', phase=0):
        typ = scalar_type()
        context = CallPrimitivePacket(operation, [], {'value': 37} if operation == 'const' else {'function': 'f'},
                                      [], [('answer', typ)], 7)
        context.phase = phase
        if phase:
            context.signatures = [['f', [], [context.type_ref(typ)]]]
        if phase == 2:
            context.outputs = [['answer', context.type_ref(typ)]]
        return context

    def test_strict_extent_header_graph_and_original_input_admission(self):
        context = self.context()
        good = self.frame()
        result = self.image([good]).step(context)
        self.assertEqual((result.serial, result.error, result.request), (7, 0, 0))
        self.assertEqual(result.bindings[0][0], 'answer')
        malformed = [0, True, 0xfffffff1, good[:-1], self.frame(magic=0),
            self.frame(error=10), self.frame(serial=6), self.frame(serial=8),
            self.frame(reserved=1), self.frame(size_delta=1), self.frame(error=1),
            self.frame(request=1), self.frame(payload={'ops': [], 'consumed': [], 'values': [], 'query': None}),
            self.frame(payload={'ops': [i('const')], 'consumed': [],
                'values': [['answer', 1, ['answer'], False, False]], 'query': None}),
            self.frame(payload={'ops': [i('const')], 'consumed': [],
                'values': [['answer', 0, ['answer'], 0, False]], 'query': None})]
        for reply in malformed:
            with self.subTest(reply=repr(reply)[:80]), self.assertRaises(HIAProgramRejected):
                self.image([reply]).step(context)
        with self.assertRaisesRegex(HIAProgramRejected, 'input bytes changed'):
            self.image([good], mutate=True).step(context)
        for serial in (-1, True, 8193):
            context.serial = serial
            with self.subTest(serial=serial), self.assertRaises(HIAProgramRejected):
                self.image([]).step(context)

    def test_signature_and_output_queries_cannot_be_skipped_or_reordered(self):
        for phase, wrong in [(0, 0), (0, 2), (1, 0), (1, 1), (2, 1), (2, 2)]:
            with self.subTest(phase=phase, request=wrong), self.assertRaises(HIAProgramRejected):
                self.image([self.frame(request=wrong)]).step(self.context(operation='call', phase=phase))
        trace = []
        typ = scalar_type()
        class Inventory(dict):
            def items(self):
                trace.append('signatures')
                return super().items()
        inventory = Inventory(f=((), (typ,)))
        def outputs():
            trace.append('outputs')
            return [('answer', typ)]
        result = self.image([self.frame(request=1), self.frame(request=2), self.frame()]).lower(
            'call', [], {'function': 'f'}, [], [('answer', typ)], 7,
            signatures=inventory, reparse_outputs=outputs)
        self.assertEqual((trace, result.request, result.error), (['signatures', 'outputs'], 0, 0))
        trace.clear()
        result = self.image([self.frame(error=2)]).lower('call', [], {}, [], [], 7,
            signatures=inventory, reparse_outputs=outputs)
        self.assertEqual((result.error, trace), (2, []))

    def test_partial_name_budget_retains_only_complete_output_bindings(self):
        typ = scalar_type()
        pair = composite._Type('Pair<>', 'record', ('u32', 'u32'))
        context = CallPrimitivePacket('call', [], {'function': 'f'}, [], [('a', typ), ('pair', pair)], 8191)
        context.phase = 2
        context.signatures = [['f', [], [context.type_ref(typ), context.type_ref(pair)]]]
        context.outputs = [['a', context.type_ref(typ)], ['pair', context.type_ref(pair)]]
        payload = {'ops': [], 'consumed': [], 'values': [['a', 0, ['a'], False, False]], 'query': None}
        result = self.image([self.frame(serial=8192, error=1, payload=payload)]).step(context)
        self.assertEqual((result.serial, result.error, [name for name, _ in result.bindings]), (8192, 1, ['a']))
        with self.assertRaisesRegex(HIAProgramRejected, 'expansion budget exceeded'):
            result.admit()
        for changed in (dict(payload, ops=[i('call')]),
                        dict(payload, values=payload['values'] + [['pair', 1, ['x'], False, False]])):
            with self.assertRaises(HIAProgramRejected):
                self.image([self.frame(serial=8192, error=1, payload=changed)]).step(context)


class CallPrimitiveArenaTests(unittest.TestCase):
    def test_complete_private_extents_and_last_export_own_the_mapping(self):
        import weakref
        from hepta import hia_machine_transport as storage
        mappings = []
        real_mmap = storage.mmap
        class MmapObserver:
            def __getattr__(self, name): return getattr(real_mmap, name)
            def mmap(self, *args, **kwargs):
                value = real_mmap.mmap(*args, **kwargs)
                mappings.append(weakref.ref(value))
                return value
        for size in (OUTPUT_BYTES, WORKSPACE_BYTES):
            with self.subTest(bytes=size), patch.object(storage, 'mmap', MmapObserver()):
                value = storage._private_zeroed_buffer(size)
                view = weakref.ref(value)
                self.assertEqual(ctypes.sizeof(value), size)
                self.assertEqual(value.raw, bytes(size))
                value[0], value[size - 1] = b'A', b'Z'
                exported = memoryview(value)
                self.assertEqual((value[0], value[size - 1]), (b'A', b'Z'))
                del value
                self.assertIsNotNone(view())
                self.assertIsNotNone(mappings[-1]())
                self.assertFalse(mappings[-1]().closed)
                exported.release()
                del exported
                self.assertIsNone(view())
                self.assertIsNone(mappings[-1]())

    def test_failed_view_construction_keeps_only_real_external_exports(self):
        import weakref
        from hepta import hia_machine_transport as storage
        real_ctypes, real_mmap = ctypes, storage.mmap
        for keep_export in (False, True):
            for exception_type in (MemoryError, KeyboardInterrupt):
                with self.subTest(export=keep_export, error=exception_type.__name__):
                    mappings, exports = [], []
                    fault = exception_type('controlled ctypes view construction failure')
                    class MmapObserver:
                        def __getattr__(self, name): return getattr(real_mmap, name)
                        def mmap(self, *args, **kwargs):
                            value = real_mmap.mmap(*args, **kwargs)
                            mappings.append(weakref.ref(value))
                            return value
                    class Array:
                        @staticmethod
                        def from_buffer(mapped):
                            if keep_export:
                                exports.append((real_ctypes.c_char * OUTPUT_BYTES).from_buffer(mapped))
                            # Simulate the C constructor's error without adding
                            # a Python observer frame that owns its argument.
                            del mapped
                            raise fault
                    class Char:
                        def __mul__(self, size):
                            self_size.append(size)
                            return Array
                    class CtypesObserver:
                        c_char = Char()
                        def __getattr__(self, name): return getattr(real_ctypes, name)
                    self_size, held = [], None
                    with patch.object(storage, 'mmap', MmapObserver()), patch.object(storage, 'ctypes', CtypesObserver()):
                        try: storage._private_zeroed_buffer(OUTPUT_BYTES)
                        except BaseException as error: held = error
                    self.assertIs(held, fault)
                    self.assertEqual(self_size, [OUTPUT_BYTES])
                    self.assertEqual(len(mappings), 1)
                    if keep_export:
                        self.assertIsNotNone(mappings[0]())
                        self.assertFalse(mappings[0]().closed)
                        exports[0][-1] = b'Q'
                        self.assertEqual(exports[0][-1], b'Q')
                    else:
                        self.assertIsNone(mappings[0]())
                    exports.clear()
                    self.assertIsNone(mappings[0]())
                    # The original error and its traceback are still held.
                    self.assertIs(held, fault)

    def test_partial_step_allocation_refuses_before_any_native_entry(self):
        import weakref
        from hepta import hia_call_primitive_native as bridge
        real_allocate = bridge._private_zeroed_buffer
        for ordinal in (1, 2):
            for exception_type in (MemoryError, KeyboardInterrupt):
                with self.subTest(ordinal=ordinal, error=exception_type.__name__):
                    fault = exception_type('controlled private arena allocation refusal')
                    requests, views, entered = [], [], []
                    def allocate(size):
                        requests.append(size)
                        if len(requests) == ordinal: raise fault
                        value = real_allocate(size)
                        views.append(weakref.ref(value))
                        return value
                    image = object.__new__(NativeCallPrimitive)
                    image._entry = lambda *args: entered.append(args)
                    context = CallPrimitivePacket('const', [], {'value': 37}, [], [('out', scalar_type())], 0)
                    held = None
                    with patch.object(bridge, '_private_zeroed_buffer', allocate):
                        try: image.step(context)
                        except BaseException as error: held = error
                    self.assertIs(held, fault)
                    self.assertEqual(requests, [OUTPUT_BYTES, WORKSPACE_BYTES][:ordinal])
                    self.assertEqual(entered, [])
                    self.assertTrue(all(view() is None for view in views))

    def test_real_address_limit_preserves_original_MemoryError_chain(self):
        child = r'''
import ctypes, importlib.util, json, os, pathlib, resource, sys
spec = importlib.util.spec_from_file_location('arena_storage', sys.argv[1])
storage = importlib.util.module_from_spec(spec); spec.loader.exec_module(storage)
used = int(pathlib.Path('/proc/self/statm').read_text().split()[0]) * os.sysconf('SC_PAGE_SIZE')
before = resource.getrlimit(resource.RLIMIT_AS)
limit = used + (32 << 20)
assert before[1] == resource.RLIM_INFINITY or limit <= before[1]
resource.setrlimit(resource.RLIMIT_AS, (limit, before[1]))
observations = []
for name, allocate in [('original', ctypes.create_string_buffer), ('candidate', storage._private_zeroed_buffer)]:
    for outer in (False, True):
        def observe():
            try: allocate(64 << 20)
            except BaseException as error:
                return [type(error).__name__, error.args,
                        None if error.__context__ is None else [type(error.__context__).__name__, error.__context__.args],
                        None if error.__cause__ is None else [type(error.__cause__).__name__, error.__cause__.args],
                        error.__suppress_context__]
            raise AssertionError('actual address limit did not refuse the allocation')
        if outer:
            try: raise LookupError('outer handled exception')
            except LookupError: result = observe()
        else: result = observe()
        observations.append([name, outer, result])
assert observations[0][2] == observations[2][2]
assert observations[1][2] == observations[3][2]
assert all(item[2] == ['MemoryError', (), None, None, False] for item in observations)
print(json.dumps({'observations': observations, 'address_limit': limit, 'requested_bytes': 64 << 20}))
'''
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', child,
            str(ROOT / 'hepta/hia_machine_transport.py')], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(len(report['observations']), 4)
        self.assertEqual(report['requested_bytes'], OUTPUT_BYTES)


class CallPrimitiveNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT_MANIFEST), os.environ.get(COLD_REPORT)
        if development and cold:
            raise AssertionError('development call fixture cannot override cold qualification')
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-call-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.folder = Path(cls.temporary.name)
        if development:
            supplied = Path(development)
            raw = supplied.read_bytes(); value = json.loads(raw); name = value['image_path']
            if type(name) is not str or Path(name).name != name:
                raise AssertionError('development image must be a sibling basename')
            shutil.copyfile(supplied.parent / name, cls.folder / name)
            cls.manifest = cls.folder / 'manifest.json'; cls.manifest.write_bytes(raw)
            cls.fixture_scope = 'DEVELOPMENT_ONLY'
        elif cold:
            from tools.build_hia_json_preflight import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold), candidate='call-primitive')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            seed, _ = build_seed(cls.folder)
            source = SOURCE.with_name('selfhost.hepta').read_bytes()
            first, _ = compile_stage(cls.folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(cls.folder, 'B2', first, source)
            if first.read_bytes() != compiler.read_bytes():
                raise AssertionError('development compiler generations differ')
            image, receipt = compile_stage(cls.folder, 'call-primitive', compiler, SOURCE.read_bytes())
            cls.manifest = cls.folder / 'manifest.json'
            cls.manifest.write_bytes(wire(dict(schema=SCHEMA, source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
                image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
            (cls.folder / 'development-compile.json').write_bytes(wire(receipt))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.native = installed_call_primitive(str(cls.manifest))

    def selected(self):
        return patch.dict(os.environ, {SELECTOR: str(self.manifest)})

    def test_exact_core_profiles_and_runtime_without_hosted_call_erasure(self):
        factories = (constant_program, call_program, resource_call_program,
            fixtures.stored_loan_program, fixtures.enum_owner_program, fixtures.task_program,
            partials.roundtrip_program, loans.pair_program)
        for maker in factories:
            document = maker(); original = wire(document)
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = verify_core(document)
            with self.selected(), patch.object(composite._Elaborator, '_reference_call_primitive',
                    side_effect=AssertionError('selected hosted call/primitive fallback')):
                actual = verify_core(document)
            self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                             (expected.canonical_bytes, expected.structured_bytes), maker.__name__)
            self.assertEqual(wire(document), original)
        for version in range(1, 5):
            document = call_program(); document['schema'] = 'hepta.hia.composite.v' + str(version)
            with self.selected():
                checked = verify_core(document)
            self.assertEqual(execute_program(checked, 'caller', [7, 11])['result'], 25)
        with self.selected():
            self.assertEqual(execute_program(verify_core(constant_program()), 'constant', [])['result'], 37)

    def test_complete_reference_prefix_cache_callbacks_and_refusal_order(self):
        reference = composite._Elaborator._reference_call_primitive
        selected = composite._Elaborator.lower_call_primitive
        observations = []
        test = self
        def freeze(value):
            if isinstance(value, composite._Type):
                return {'key': str(value.key), 'kind': value.kind, 'flat': value.flat, 'linear': value.linear}
            if isinstance(value, dict):
                return {str(key): freeze(item) for key, item in value.items()}
            if isinstance(value, (tuple, list)):
                return [freeze(item) for item in value]
            return value
        def compare(owner, ins, actual, declared, env, ops, consume, outputs):
            initial_env, initial_ops, initial_serial = dict(env), deepcopy(ops), owner.serial
            held = {id(value): (value, value.consumed) for value in [*env.values(), *actual]}
            cache, active = dict(owner.types.cache), set(owner.types.active)
            loan_cache, steps = dict(owner.types.known_loan_cache), owner.types.partial_declaration_steps
            signatures = dict(owner.signatures)
            choices = [('unchanged', deepcopy(ins), list(actual), None)]
            if ins['op'] == 'call':
                for number, attrs in enumerate(({}, {'function': None}, {'function': 7}, {'function': False},
                        {'function': ''}, {'function': '0bad'}, {'function': '__hia_x'},
                        {'function': 'h2internal_3'}, {'function': 'missing'}, {'function': '汉'},
                        {'function': 'x'*129}, {'function': ins['attrs']['function'], 'extra': 0})):
                    changed = deepcopy(ins); changed['attrs'] = attrs
                    choices.append(('callee-' + str(number), changed, list(actual), None))
                for number, out in enumerate(([], [{'name': 'new_out', 'type': 'u64'}],
                        [{'name': 'new_out', 'type': 'Unknown'}], None,
                        [{'name': 'x', 'type': 'u32'}, {'name': 'x', 'type': 'u32'}])):
                    changed = deepcopy(ins); changed['out'] = out
                    choices.append(('outputs-' + str(number), changed, list(actual), None))
            else:
                for number, attrs in enumerate(({}, {'opaque': [None, True, False, 0, -1, -0.0,
                        5e-324, 1.7976931348623157e308, 'x\x00汉\ud800']},
                        {'nested': {'unicode': '汉', 'sequence': [[], {}, [1, 2, 3]]}}, None, [])):
                    changed = deepcopy(ins); changed['attrs'] = attrs
                    choices.append(('attrs-' + str(number), changed, list(actual), None))
                changed = deepcopy(ins); changed['op'] = 'unknown.primitive'
                choices.append(('unknown-primitive', changed, list(actual), None))
            if actual:
                for label, indices in [('empty', []), ('reverse', list(reversed(range(len(actual))))),
                        ('duplicate', list(range(len(actual)))*2), ('prefix', [0])]:
                    changed = deepcopy(ins); changed['args'] = [ins['args'][n] for n in indices]
                    choices.append(('arguments-' + label, changed, [actual[n] for n in indices], None))
                choices.append(('already-consumed', deepcopy(ins), list(actual), 0))
            def restore(serial):
                env.clear(); env.update(initial_env); ops[:] = deepcopy(initial_ops); owner.serial = serial
                for value, consumed in held.values(): value.consumed = consumed
                owner.types.cache.clear(); owner.types.cache.update(cache)
                owner.types.active.clear(); owner.types.active.update(active)
                owner.types.known_loan_cache.clear(); owner.types.known_loan_cache.update(loan_cache)
                owner.types.partial_declaration_steps = steps
                owner.signatures.clear(); owner.signatures.update(signatures)
            def observe(method, changed, values):
                trace = []; parameters, resolve = owner.parameters, owner.types.resolve
                def traced_parameters(raw):
                    trace.append(['parameters', freeze(raw), owner.serial]); return parameters(raw)
                def traced_resolve(*args, **kwargs):
                    trace.append(['resolve', freeze(args), freeze(kwargs), owner.serial]); return resolve(*args, **kwargs)
                with patch.object(owner, 'parameters', side_effect=traced_parameters), patch.object(
                        owner.types, 'resolve', side_effect=traced_resolve):
                    _, error = outcome(lambda: method(owner, changed, values, declared, env, ops, consume, outputs))
                return {'error': error, 'serial': owner.serial, 'ops': deepcopy(ops),
                    'bindings': {name: [freeze(v.typ), id(v.typ), v.names, v.external, v.consumed]
                                 for name, v in env.items()},
                    'consumed': [v.consumed for v, _ in held.values()], 'callbacks': trace,
                    'type_cache': freeze(owner.types.cache), 'loan_cache': freeze(owner.types.known_loan_cache),
                    'partial_steps': owner.types.partial_declaration_steps}
            for label, changed, values, consumed in choices:
                for serial in ((0, 8191, 8192) if ins['op'] == 'call' else (8192,)):
                    restore(serial)
                    if consumed is not None: actual[consumed].consumed = True
                    expected = observe(reference, changed, values)
                    restore(serial)
                    if consumed is not None: actual[consumed].consumed = True
                    got = observe(selected, changed, values)
                    test.assertEqual(wire(got), wire(expected), (label, serial, changed))
                    observations.append((label, serial, got['error']))
            restore(initial_serial)
            return selected(owner, ins, actual, declared, env, ops, consume, outputs)
        drop = fixtures.module([], f('drop_pair', [('first', 'buffer'), ('second', 'buffer')], [], ['alloc'], [
            b('entry', [('first', 'buffer'), ('second', 'buffer')],
              [i('owner.drop', ['first']), i('owner.drop', ['second'])], ret())]))
        for maker in (constant_program, call_program, duplicate_owner_program, lambda: drop):
            document = maker(); original = wire(document)
            with patch.dict(os.environ, {SELECTOR: ''}):
                expected = outcome(lambda: composite.elaborate_program(deepcopy(document)))
            with self.selected(), patch.object(composite._Elaborator, 'lower_call_primitive', compare), patch.object(
                    composite._Elaborator, '_reference_call_primitive', side_effect=AssertionError('native fell back')):
                actual = outcome(lambda: composite.elaborate_program(document))
            self.assertEqual(wire(actual), wire(expected)); self.assertEqual(wire(document), original)
        # This new fixture inventory deliberately retains all original mutation categories.
        self.assertGreaterEqual(len(observations), 193)
        self.assertTrue(any(error and error[0] == 'E_HIA_LIMIT' for _, _, error in observations))
        self.assertTrue(any(error and error[0] == 'E_HIA_RESOURCE' for _, _, error in observations))

    def test_signature_snapshot_and_callbacks_happen_only_at_native_requests(self):
        a = composite._Type('A<>', 'record', ('u32',)); z = composite._Type('Z<>', 'record', ('u32',))
        trace = []
        class Inventory(dict):
            def items(self):
                trace.append('signatures'); return super().items()
        signatures = Inventory(callee=((), (a,)))
        def reparse():
            trace.append('outputs'); signatures['callee'] = ((), (z,)); return [('out', z)]
        result = self.native.lower('call', [], {'function': 'callee'}, [], [('out', a)], 0,
                                  signatures=signatures, reparse_outputs=reparse)
        self.assertEqual((result.error, trace, result.bindings, result.ops), (7, ['signatures', 'outputs'], [], []))
        for attrs, expected, calls in [({}, 2, []), ({'function': '0bad'}, 3, []),
                ({'function': 'h2internal_x'}, 4, []), ({'function': 'absent'}, 5, ['signatures'])]:
            trace.clear()
            result = self.native.lower('call', [], attrs, [], [], 0,
                signatures=signatures, reparse_outputs=lambda: self.fail('premature output reparse'))
            self.assertEqual((result.error, trace), (expected, calls))

    def test_real_partial_consumption_and_completed_binding_prefix(self):
        owner_type = scalar_type('buffer'); scalar = scalar_type()
        item = composite._Value(owner_type, ('owned',))
        result = self.native.lower('owner.drop', ['a', 'a'], {}, [item, item], [], 0,
            signatures={}, reparse_outputs=lambda: self.fail('primitive queried outputs'))
        self.assertEqual((result.error, result.states, result.ops), (8, [(item, True)], []))
        self.assertFalse(item.consumed)
        pair = composite._Type('Pair<>', 'record', ('u32', 'u32'))
        declared = [('scalar', scalar), ('pair', pair)]
        result = self.native.lower('call', ['owned'], {'function': 'f'}, [item], declared, 8191,
            signatures={'f': ((('p', owner_type),), (scalar, pair))}, reparse_outputs=lambda: declared)
        self.assertEqual((result.error, result.serial, result.states, result.ops), (1, 8192, [(item, True)], []))
        self.assertEqual([name for name, _ in result.bindings], ['scalar'])
        self.assertFalse(item.consumed)
        with self.assertRaises(HIAProgramRejected): result.admit()

    def test_primitive_attributes_and_ordered_nominal_refusal(self):
        scalar = scalar_type(); pair = composite._Type('Pair<>', 'record', ('u32', 'u32'))
        attrs = {'raw': [None, True, False, -1, -0.0, 5e-324, 'x\x00汉\ud800', {'a': [1, 2]}]}
        result = self.native.lower('unknown.primitive', [], attrs, [], [('out', scalar)], 8192,
            signatures={}, reparse_outputs=lambda: self.fail('primitive queried outputs'))
        self.assertEqual(wire(result.ops[0]['attrs']), wire(attrs))
        self.assertEqual(math.copysign(1.0, result.ops[0]['attrs']['raw'][4]), -1.0)
        result.ops[0]['attrs']['raw'].append('detached')
        self.assertEqual(len(attrs['raw']), 8)
        value = composite._Value(pair, ('left', 'right'))
        result = self.native.lower('owner.drop', ['pair'], {}, [value], [], 8192,
            signatures={}, reparse_outputs=lambda: self.fail('primitive queried outputs'))
        self.assertEqual((result.error, result.states, result.ops), (9, [(value, False)], []))

    def test_independent_vm_and_native_complete_frames_workspace_and_prefix(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(SOURCE.read_bytes())
        scalar, owner_type = scalar_type(), scalar_type('buffer')
        pair = composite._Type('Pair<>', 'record', ('u32', 'u32'))
        owned = composite._Value(owner_type, ('owned',))
        contexts = [CallPrimitivePacket('const', [], {'value': 37}, [], [('out', scalar)], 0),
            CallPrimitivePacket('owner.drop', ['a', 'a'], {}, [owned, owned], [], 8192),
            CallPrimitivePacket('call', [], {}, [], [], 7)]
        for phase, serial in [(0, 8191), (1, 8191), (2, 8191), (2, 8190)]:
            context = CallPrimitivePacket('call', [], {'function': 'f'}, [], [('sum', scalar), ('pair', pair)], serial)
            context.phase = phase
            if phase: context.signatures = [['f', [], [context.type_ref(scalar), context.type_ref(pair)]]]
            if phase == 2: context.outputs = [['sum', context.type_ref(scalar)], ['pair', context.type_ref(pair)]]
            contexts.append(context)
        output, workspace = _Owner(-2, bytearray(OUTPUT_BYTES)), _Owner(-3, bytearray([165])*WORKSPACE_BYTES)
        native_output = ctypes.create_string_buffer(OUTPUT_BYTES)
        native_workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        ctypes.memset(native_workspace, 165, WORKSPACE_BYTES)
        observed_requests, observed_errors = set(), set()
        for context in contexts:
            data = context.data(); source = _Owner(-1, bytearray(data))
            machine = _Machine(checked, 20_000_000, 128 << 20, None, 256)
            extent = machine.invoke(checked.as_dict()['functions'][0],
                [_View(source, False), _View(output, True), _View(workspace, True)])[0]
            self.assertTrue(64 <= extent <= OUTPUT_BYTES)
            native_source = ctypes.create_string_buffer(data)
            actual_extent = self.native._entry(native_source, len(data), native_output, OUTPUT_BYTES,
                                                native_workspace, WORKSPACE_BYTES)
            self.assertEqual(actual_extent, extent)
            self.assertEqual(ctypes.string_at(native_output, extent), bytes(output.data[:extent]))
            self.assertEqual(native_workspace.raw, bytes(workspace.data))
            self.assertEqual(bytes(source.data), data)
            self.assertEqual(ctypes.string_at(native_source, len(data)), data)
            header = struct.unpack_from('<8Q', native_output)
            observed_errors.add(header[1]); observed_requests.add(header[3])
        self.assertEqual(observed_requests, {0, 1, 2})
        self.assertTrue({0, 1, 2, 8}.issubset(observed_errors))

    def test_original_1457_malformed_packet_mutations_have_bounded_effects(self):
        scalar = scalar_type(); pair = composite._Type('Pair<>', 'record', ('u32', 'u32'))
        item = composite._Value(pair, ('left', 'right')); cases = []
        for phase in range(3):
            context = CallPrimitivePacket('call', ['pair'], {'function': 'mix'}, [item],
                                          [('sum', scalar), ('swapped', pair)], 8191)
            context.data(); context.phase = phase
            if phase: context.signatures = [['mix', [context.type_ref(pair)], [context.type_ref(scalar), context.type_ref(pair)]]]
            if phase == 2: context.outputs = [['sum', context.type_ref(scalar)], ['swapped', context.type_ref(pair)]]
            data = context.data(); cases.append(data)
            for offset, (kind, size, end) in _index(data).items():
                for field, words in ((0, (0, 5, 7, 9, (1 << 64)-1)), (8, (0, 1, 7, 15, (1 << 64)-1))):
                    for word in words:
                        raw = bytearray(data); struct.pack_into('<Q', raw, offset+field, word); cases.append(bytes(raw))
                if kind in (5, 6):
                    for count in (0, 1, (1 << 64)-1):
                        raw = bytearray(data); struct.pack_into('<Q', raw, offset+16, count); cases.append(bytes(raw))
        cases = list(dict.fromkeys(cases))
        self.assertEqual(len(cases), 1457)
        output, workspace = ctypes.create_string_buffer(OUTPUT_BYTES+32), ctypes.create_string_buffer(WORKSPACE_BYTES+32)
        ctypes.memset(workspace, 165, WORKSPACE_BYTES)
        ctypes.memset(ctypes.addressof(output)+OUTPUT_BYTES, 183, 32)
        ctypes.memset(ctypes.addressof(workspace)+WORKSPACE_BYTES, 201, 32)
        for number, data in enumerate(cases):
            source = ctypes.create_string_buffer(data, len(data))
            extent = self.native._entry(source, len(data), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
            self.assertEqual(source.raw, data, number)
            self.assertEqual(ctypes.string_at(ctypes.addressof(output)+OUTPUT_BYTES, 32), bytes([183])*32, number)
            self.assertEqual(ctypes.string_at(ctypes.addressof(workspace)+WORKSPACE_BYTES, 32), bytes([201])*32, number)
            if extent == 0xfffffff1: continue
            self.assertTrue(64 <= extent <= OUTPUT_BYTES, (number, extent))
            header = struct.unpack_from('<8Q', output)
            self.assertEqual((header[0], header[4], header[5:]), (MAGIC, extent-64, (0, 0, 0)), number)
            self.assertTrue(0 <= header[1] <= 9 and 8191 <= header[2] <= 8192 and 0 <= header[3] <= 2, number)
            try: decode_native_graph(ctypes.string_at(ctypes.addressof(output)+64, extent-64), data)
            except ValueError: pass  # The ordinary adapter safely refuses malformed original input graphs.

    def test_private_capacities_nonzero_workspaces_canaries_and_concurrency(self):
        from concurrent.futures import ThreadPoolExecutor
        context = CallPrimitivePacket('const', [], {'value': 37}, [], [('out', scalar_type())], 8192)
        data = context.data(); source = ctypes.create_string_buffer(data)
        output, workspace = ctypes.create_string_buffer(OUTPUT_BYTES+32), ctypes.create_string_buffer(WORKSPACE_BYTES+32)
        ctypes.memset(ctypes.addressof(output)+OUTPUT_BYTES, 167, 32)
        ctypes.memset(ctypes.addressof(workspace)+WORKSPACE_BYTES, 185, 32)
        for oc, wc in ((OUTPUT_BYTES-1, WORKSPACE_BYTES), (OUTPUT_BYTES, WORKSPACE_BYTES-1)):
            self.assertEqual(self.native._entry(source, len(data), output, oc, workspace, wc), 0xfffffff1)
        frames = []
        for fill in (0, 165, 255):
            ctypes.memset(workspace, fill, WORKSPACE_BYTES)
            extent = self.native._entry(source, len(data), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
            self.assertTrue(64 <= extent <= OUTPUT_BYTES)
            frames.append(ctypes.string_at(output, extent))
        self.assertTrue(all(frame == frames[0] for frame in frames))
        self.assertEqual(ctypes.string_at(ctypes.addressof(output)+OUTPUT_BYTES, 32), bytes([167])*32)
        self.assertEqual(ctypes.string_at(ctypes.addressof(workspace)+WORKSPACE_BYTES, 32), bytes([185])*32)
        self.assertEqual(ctypes.string_at(source, len(data)), data)
        nested = None
        for _ in range(129): nested = [nested]
        malformed = [b'', data[:-1], data+b'\0', transport(nested), transport([0, 0, 'const'])]
        for raw in malformed:
            bad = ctypes.create_string_buffer(raw, max(1, len(raw)))
            self.assertEqual(self.native._entry(bad, len(raw), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES), 0xfffffff1)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.native.step(context), range(4)))
        self.assertTrue(all(result == results[0] for result in results))

    def test_8201_repeated_512_slot_arguments_preserve_complete_core_and_late_refusal(self):
        count = 8201
        types = [fixtures.record('Chunk', [('f'+str(n), 'u32') for n in range(64)]),
                 fixtures.record('Wide', [('c'+str(n), 'Chunk') for n in range(8)])]
        params = [('p'+str(n), 'Wide') for n in range(count)]
        caller = f('caller', [('input', 'Wide')], [], [], [
            b('entry', [('input', 'Wide')], [i('call', ['input']*count, function='sink')], ret())])
        document = fixtures.module(types, caller, f('sink', params, [], [], [b('entry', params, [], ret())]))
        original = wire(document); self.assertLess(len(original), 8 << 20)
        reference_owner = composite._Elaborator(document)
        expected = reference_owner.function(caller)
        owner = composite._Elaborator(document); extents = []; entry = self.native._entry
        def observe(*args):
            extent = entry(*args); extents.append(extent); return extent
        with self.selected(), patch.object(self.native, '_entry', side_effect=observe), patch.object(
                composite._Elaborator, '_reference_call_primitive', side_effect=AssertionError('large call fell back')):
            actual = owner.function(caller)
        self.assertEqual((actual, owner.serial), (expected, reference_owner.serial))
        self.assertEqual(len(actual['blocks'][0]['ops'][0]['args']), 4_198_912)
        self.assertLess(max(extents), 1 << 17)
        errors = []
        for selector in ('', str(self.manifest)):
            with patch.dict(os.environ, {SELECTOR: selector}):
                errors.append(outcome(lambda: verify_core(document))[1])
        self.assertEqual(errors, [('E_HIA_LIMIT', 'E_HIA_LIMIT: nominal elaborated value-slot budget exceeded')]*2)
        self.assertEqual(wire(document), original)

    def test_zero_width_returns_and_exact_output_slot_capacity(self):
        empty = composite._Type('Empty<>', 'record', ())
        outputs = [('empty_'+str(index), empty) for index in range(15000)]
        result = self.native.lower('call', [], {'function': 'f'}, [], outputs, 8192,
            signatures={'f': ((), (empty,)*len(outputs))}, reparse_outputs=lambda: outputs)
        self.assertEqual((result.error, result.serial, len(result.bindings)), (0, 8192, 15000))
        self.assertEqual(result.ops[0]['out'], [])
        self.assertTrue(all(value.typ is empty and value.names == () for _, value in result.bindings))
        scalar = scalar_type(); outputs = [('v'+str(index), scalar) for index in range(32768)]
        result = self.native.lower('call', [], {'function': 'f'}, [], outputs, 8192,
            signatures={'f': ((), (scalar,)*len(outputs))}, reparse_outputs=lambda: outputs)
        self.assertEqual((result.error, result.serial, len(result.bindings)), (0, 8192, 32768))
        too_many = outputs + [('one_more', scalar)]
        with self.assertRaises(HIAProgramRejected):
            self.native.lower('call', [], {'function': 'f'}, [], too_many, 8192,
                signatures={}, reparse_outputs=lambda: self.fail('invalid storage reached callback'))

    def test_original_75_nominal_resource_and_loan_cases_without_hosted_call(self):
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(('tests.test_hia_program_composite', 'tests.test_hia_partial_record',
                                          'tests.test_hia_composite_returned_loans.CompositeReturnedLoans'))
        self.assertEqual(loader.errors, [])
        self.assertEqual(suite.countTestCases(), 75)
        log = io.StringIO()
        with self.selected(), patch.object(composite._Elaborator, '_reference_call_primitive',
                side_effect=AssertionError('retained nominal suite entered hosted call owner')):
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
        self.assertTrue(result.wasSuccessful(), log.getvalue())
        self.assertEqual((result.testsRun, len(result.skipped), len(result.expectedFailures),
                          len(result.unexpectedSuccesses)), (75, 0, 0, 0), log.getvalue())

    def test_all_eight_native_nominal_owners_compose_without_reference_fallback(self):
        from tests import test_hia_composite_types_native as types_tests
        from tests import test_hia_task_helpers_native as helpers_tests
        from tests import test_hia_enum_match_native as match_tests
        from tests import test_hia_enum_operations_native as enum_tests
        from tests import test_hia_record_operations_native as record_tests
        from tests import test_hia_record_transitions_native as transition_tests
        from tests import test_hia_task_operations_native as task_tests
        prepared = {SELECTOR: str(self.manifest)}
        supports = [(types_tests, types_tests.CompositeTypesNativeTests),
            (helpers_tests, helpers_tests.TaskHelpersNativeTests),
            (match_tests, match_tests.EnumMatchNativeTests),
            (enum_tests, enum_tests.EnumOperationsNativeTests),
            (record_tests, record_tests.RecordOperationsNativeTests),
            (transition_tests, transition_tests.RecordTransitionsNativeTests),
            (task_tests, task_tests.TaskOperationsNativeTests)]
        for module, implementation in supports:
            fixture = type('CallSupport' + implementation.__name__, (unittest.TestCase,), {})
            self.addCleanup(fixture.doClassCleanups)
            extra = {}
            if os.environ.get(COLD_REPORT) and not os.environ.get(module.COLD_REPORT):
                extra[module.COLD_REPORT] = os.environ[COLD_REPORT]
            with patch.dict(os.environ, extra):
                implementation.setUpClass.__func__(fixture)
            prepared[module.SELECTOR] = str(fixture.manifest)
        methods = ('_reference_call_primitive', '_reference_helper', '_reference_match',
                   '_reference_enum_operation', '_reference_record_operation',
                   '_reference_record_transition', '_reference_task_operation')
        for maker in (call_program, fixtures.stored_loan_program, fixtures.enum_owner_program,
                      fixtures.task_program, partials.roundtrip_program, partials.task_partial_program):
            document = maker()
            with patch.dict(os.environ, {key: '' for key in prepared}):
                expected = verify_core(document)
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, prepared))
                stack.enter_context(patch.object(composite, '_Types',
                    side_effect=AssertionError('hosted nominal type owner')))
                for method in methods:
                    stack.enter_context(patch.object(composite._Elaborator, method,
                        side_effect=AssertionError('selected hosted owner: ' + method)))
                actual = verify_core(document)
            self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                             (expected.canonical_bytes, expected.structured_bytes), maker.__name__)
        with patch.dict(os.environ, prepared):
            checked = verify_core(call_program())
        self.assertEqual(execute_program(checked, 'caller', [7, 11])['result'], 25)

    def test_selected_hashes_and_warm_source_custody_fail_without_fallback(self):
        import hepta.hia_call_primitive_native as native_module
        original = json.loads(self.manifest.read_bytes())
        for field in ('source_sha256', 'image_sha256'):
            changed = dict(original); changed[field] = '0' * 64
            manifest = self.folder / ('bad-' + field + '.json')
            manifest.write_bytes(wire(changed))
            with self.subTest(field=field), patch.dict(os.environ, {SELECTOR: str(manifest)}), patch.object(
                    composite._Elaborator, '_reference_call_primitive',
                    side_effect=AssertionError('invalid selected manifest fell back')):
                with self.assertRaises(HIAProgramRejected):
                    composite.elaborate_program(constant_program())
        local_source = self.folder / 'observed-call-source.hiaasm'
        local_source.write_bytes(SOURCE.read_bytes())
        with patch.object(native_module, 'SOURCE', local_source):
            warm = installed_call_primitive(str(self.manifest))
            self.assertIs(installed_call_primitive(str(self.manifest)), warm)
            self.assertEqual(warm.image_sha256, self.native.image_sha256)
            local_source.write_bytes(local_source.read_bytes() + b'\n')
            with self.selected(), patch.object(composite._Elaborator, '_reference_call_primitive',
                    side_effect=AssertionError('warm stale source fell back')):
                with self.assertRaises(HIAProgramRejected):
                    composite.elaborate_program(constant_program())

    def test_actual_machine_allocator_refusal_and_call_owner_cleanup(self):
        from hepta.hia_program_native import emit_program_machine, compile_program_machine
        cc = shutil.which('cc'); self.assertIsNotNone(cc, 'actual C linker is required')
        with self.selected(), patch.object(composite._Elaborator, '_reference_call_primitive',
                side_effect=AssertionError('machine fixture entered hosted call owner')):
            checked = verify_core(resource_call_program())
        obj = self.folder / 'call-effects.o'
        compile_program_machine(emit_program_machine(checked), program=checked, output=obj, kind='object', linker=cc)
        source, executable = self.folder / 'call-effects.c', self.folder / 'call-effects'
        source.write_text(r'''
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
size_t call_resource(size_t);
int main(void){
  if(call_resource(7)!=7 || call_resource(0)!=0)return 82;
  refuse=true;if(call_resource(7)!=0 || refuse || live)return 83;
  printf("%zu %zu %zu\n",allocations,frees,refusals);
  return allocations!=1 || frees!=1 || refusals!=1;
}
''')
        built = subprocess.run([cc, '-std=c11', '-O2', str(source), str(obj),
            '-Wl,--wrap=calloc', '-Wl,--wrap=free', '-o', str(executable)], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stdout+built.stderr)
        ran = subprocess.run([str(executable)], capture_output=True, timeout=30)
        self.assertEqual((ran.returncode, ran.stdout, ran.stderr), (0, b'1 1 1\n', b''))

    def test_installed_wheel_no_authoring_reference_or_stale_source_custody(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES
        self.assertIn('examples/hia_bootstrap/call_primitive.hepta', NATIVE_SOURCE_FILES)
        source = self.folder / 'wheel-source'; source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        names = tuple('docs/'+name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES
        for name in (*names, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            destination = source / name; destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        wheels, installed = self.folder / 'wheels', self.folder / 'installed'
        built = subprocess.run([sys.executable, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
            '--wheel-dir', str(wheels), str(source)], cwd=source, capture_output=True, timeout=120,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(built.returncode, 0, built.stdout+built.stderr)
        wheel, = wheels.glob('*.whl')
        copied = subprocess.run([sys.executable, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
            '--target', str(installed), str(wheel)], cwd=self.folder, capture_output=True, timeout=120,
            env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        self.assertEqual(copied.returncode, 0, copied.stdout+copied.stderr)
        child = '''import sys,importlib.abc
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed call owner imported authoring tools')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as composite
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_call_primitive_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents
def absent(*args,**kwargs):raise AssertionError('installed call used hosted reference')
composite._Elaborator._reference_call_primitive=absent
try: result=verify_core(Path(sys.argv[2]).read_bytes())
except HIAProgramRejected:
    if sys.argv[3]=='refuse': print('REFUSED')
    else: raise
else:
    assert sys.argv[3]=='accept','invalid installed source custody accepted'
    sys.stdout.buffer.write(result.canonical_bytes)
'''
        data = self.folder / 'installed-input.json'
        def run(mode, manifest=self.manifest):
            return subprocess.run([sys.executable, '-I', '-S', '-B', '-c', child,
                str(installed), str(data), mode], cwd=self.folder, capture_output=True, timeout=30,
                env={'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', SELECTOR: str(manifest)})
        for maker in (constant_program, call_program, resource_call_program, partials.roundtrip_program):
            document = maker(); data.write_bytes(wire(document))
            with patch.dict(os.environ, {SELECTOR: ''}): expected = verify_core(document).canonical_bytes
            result = run('accept')
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
        resource = installed / 'hepta/_data/examples/hia_bootstrap/call_primitive.hepta'
        original = resource.read_bytes()
        for missing in (False, True):
            try:
                resource.unlink() if missing else resource.write_bytes(original+b'\n')
                result = run('refuse')
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))
            finally:
                resource.write_bytes(original)
        bad = self.folder / 'bad-installed-manifest.json'; bad.write_bytes(b'{}')
        result = run('refuse', bad)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'REFUSED\n', b''))


if __name__ == '__main__':
    unittest.main()
