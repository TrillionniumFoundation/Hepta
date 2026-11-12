"""Complete v2 Core lowering controls; old v1 twelve-test ABI stays archived."""
from __future__ import annotations
import ast
from collections import Counter
from contextlib import ExitStack
import ctypes
from dataclasses import fields
import dis
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
import types
import unittest
import weakref
from unittest.mock import patch

from hepta import hia_program_native as backend
from hepta import hia_machine_plan_control_native as protocol
from hepta.hia_core_lowering_native import NativeCoreLowering, LoweringSession, SOURCE, SCHEMA
from hepta.hia_core_lowering_selection import (
    SELECTOR, installed_core_lowering, native_core_lowering_scope, active_core_lowering)
from hepta.hia_json_preflight_native import _source_resource_path
ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = 'HEPTA_HIA_CORE_LOWERING_DEVELOPMENT_MANIFEST'
COLD = 'HEPTA_HIA_CORE_LOWERING_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_CORE_LOWERING_FIXTURE_EVIDENCE'
FIXTURE_SHA = '8f0be8c06e932fedbdd5973591310440a97e85a0c3b88ba9bc5ca95035810185'
HELPERS = ('_reject', '_words', '_bounds', '_normalize', '_prologue')

def recorded(function, *args):
    try:
        return {'value': function(*args)}
    except BaseException as exc:
        return {'exception_type': type(exc), 'exception_args': exc.args}


def comparable(machine):
    return {field.name: getattr(machine, field.name) for field in fields(machine)
            if field.name != 'implementation_sha256'}


def original_nodes():
    raw = (Path(__file__).with_name('fixtures') / 'hia_program_native_608.py.txt').read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA:
        raise AssertionError('complete original lowering fixture differs')
    return ast.parse(raw)


def selected_guard(manifest):
    stack = ExitStack()
    stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
    for name, method in backend._Function.__dict__.items():
        if inspect.isfunction(method) and name != '__new__':
            stack.enter_context(patch.object(backend._Function, name,
                side_effect=AssertionError('retained Function control entered: ' + name)))
    for name in HELPERS:
        legacy = '_reference' + name
        original = getattr(backend, legacy)
        def guard(*args, _name=legacy, _original=original, **kwargs):
            if active_core_lowering() is not None:
                raise AssertionError('retained helper entered captured lowering: ' + _name)
            return _original(*args, **kwargs)
        stack.enter_context(patch.object(backend, legacy, guard))
    return stack


class CoreLoweringSourceTests(unittest.TestCase):
    def test_global_nameerror_preserves_name_and_active_context(self):
        from tests.hia_native_name_resolution import assert_missing_global_port
        assert_missing_global_port(self, LoweringSession)

    def test_complete_original_Function_and_five_helpers_are_independent(self):
        original = original_nodes()
        current = ast.parse(inspect.getsource(backend))
        before = next(n for n in original.body if isinstance(n, ast.ClassDef) and n.name == '_Function')
        after = next(n for n in current.body if isinstance(n, ast.ClassDef) and n.name == '_Function')
        additions = [n for n in after.body if isinstance(n, ast.FunctionDef) and n.name == '__new__']
        self.assertEqual(len(additions), 1)
        after.body = [n for n in after.body if n not in additions]
        self.assertEqual(len([n for n in before.body if isinstance(n, ast.FunctionDef)]), 22)
        self.assertEqual(ast.dump(before), ast.dump(after))
        for name in HELPERS:
            wanted = next(n for n in original.body if isinstance(n, ast.FunctionDef) and n.name == name)
            retained = next(n for n in current.body if isinstance(n, ast.FunctionDef) and n.name == '_reference' + name)
            retained.name = name
            self.assertEqual(ast.dump(wanted), ast.dump(retained))
        import hepta.hia_core_lowering_native as primitive
        tree = ast.parse(inspect.getsource(primitive))
        imported = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        self.assertFalse(any(name and name.startswith('tools') for name in imported))


    def test_unqualified_cold_refuses_before_output_creation(self):
        from tools.build_hia_core_lowering import build
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compiler, cold = root / 'compiler', root / 'cold'
            compiler.write_bytes(b'explicitly-not-qualified')
            cold.write_text('{"status":"DEVELOPMENT_ONLY"}')
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build(root / 'must-not-create' / 'build', compiler, cold)
            self.assertFalse((root / 'must-not-create').exists())


    def test_unselected_constructor_subclass_and_early_target_errors_stay_original(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        program = verify_program(minimal_document())
        with patch.dict(os.environ, {SELECTOR: ''}):
            image = backend.emit_program_machine(program)
            emitter = backend._Emitter(program.as_dict(), set(image.exports))
            self.assertIs(type(backend._Function(emitter, program.as_dict()['functions'][0], 0)), backend._Function)
            wanted = recorded(backend.emit_program_machine, program)
        class Foreign(backend._Function):
            def __init__(self, parent, fn, index):
                self.marker = (parent, fn, index)
        with patch.dict(os.environ, {SELECTOR: '/missing/explicit-core-lowering-manifest'}):
            foreign = Foreign(None, None, 7)
            self.assertEqual(foreign.marker, (None, None, 7))
            with self.assertRaises(FileNotFoundError):
                backend.emit_program_machine(program)
            with self.assertRaisesRegex(backend.HIAProgramNativeRejected, 'E_HIA_PROGRAM_TARGET'):
                backend.emit_program_machine(program, target='not-the-accepted-target')
        self.assertIn('value', wanted)


    def test_complete_HIA_table_and_original_profile_match_independent_VM(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from tools.generate_hia_core_lowering import document, program, EMIT_MAGIC
        from tools.generate_hia_machine_plan_control import table
        expected = render_assembly(document()).encode()
        self.assertEqual(SOURCE.read_bytes(), expected)
        checked = assemble_program(expected)
        doc = checked.as_dict()
        functions = doc['functions']
        blocks = [b for f in functions for b in f['blocks']]
        self.assertLessEqual(len(expected), 1 << 20)
        self.assertLessEqual(len(expected.splitlines()), 16384)
        self.assertLessEqual(len(functions), 128)
        self.assertLessEqual(len(blocks), 1536)
        self.assertLessEqual(sum(len(b['ops']) + 1 for b in blocks), 8192)
        for function in functions:
            self.assertLessEqual(len(function['blocks']), 256)
            self.assertLessEqual(len(function['params']), 16)
            definitions = {p['name'] for p in function['params']}
            for block in function['blocks']:
                definitions.update(p['name'] for p in block['params'])
                for op in block['ops']:
                    definitions.update(p['name'] for p in op['out'])
                    self.assertLessEqual(len(op.get('args', ())), 16)
            self.assertLessEqual(len(definitions), 2048)
        policy = program()
        owners = [_Owner(-1, bytearray(struct.pack('<8Q', EMIT_MAGIC, *([0] * 7)))),
                  _Owner(-2, bytearray(1 << 20)), _Owner(-3, bytearray(96))]
        before = bytes(owners[0].data)
        vm = _Machine(checked, 20_000_000, 4 << 20, None, 128)
        size = vm.invoke(functions[0], [_View(owners[0], False), _View(owners[1], True),
                                      _View(owners[2], True)])[0]
        self.assertEqual(bytes(owners[0].data), before)
        self.assertEqual(size, len(table(policy)))
        self.assertEqual(bytes(owners[1].data[:size]), table(policy))
        self.assertEqual(len(policy.functions), 34)  # 28 roots and six lazy generators.
        self.assertEqual(vm.resources()['live_owners'], 0)


    def test_only_reviewed_CPython_frame_ABIs_are_observed(self):
        from types import SimpleNamespace
        from hepta import hia_machine_plan_control_native as bridge
        from hepta.hia_exception_delivery import ExceptionDeliveryUnavailable
        for version in ((3, 12), (3, 13), (3, 14)):
            observed = SimpleNamespace(implementation=SimpleNamespace(name='cpython'), version_info=version)
            with patch.object(bridge, 'sys', observed):
                self.assertEqual(bridge._runtime_profile(), version[0]*100+version[1])
        for family, version in (('cpython', (3, 11)), ('cpython', (3, 15)),
                                ('cpython', (4, 0)), ('pypy', (3, 14))):
            observed = SimpleNamespace(implementation=SimpleNamespace(name=family), version_info=version)
            with patch.object(bridge, 'sys', observed):
                with self.assertRaises(ExceptionDeliveryUnavailable):
                    bridge._runtime_profile()


class CoreLoweringNativeTests(unittest.TestCase):
    def test_global_helpers_observe_replacement_and_deletion_before_and_after_admission(self):
        from tests.hia_native_name_resolution import assert_helper_rebindings
        rows = assert_helper_rebindings(self, 'core', self.new_owner)
        (self.folder / 'global-helper-rebindings.json').write_text(json.dumps(rows, sort_keys=True, indent=2) + '\n')

    @classmethod
    def setUpClass(cls):
        development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
        if development and cold:
            raise AssertionError('development image cannot override requested cold')
        if cold:
            from tools.build_hia_json_preflight import admit_cold_build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            admit_cold_build(compiler.read_bytes(), Path(cold).read_bytes())
        if not cold and not development:
            raise unittest.SkipTest('requires matching cold report or explicit development manifest')
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).resolve()
            cls.folder.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='hia-core-lowering-v2-')
            cls.addClassCleanup(temporary.cleanup)
            cls.folder = Path(temporary.name)
        if cold:
            from tools.build_hia_core_lowering import build
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            cls.manifest = Path(development).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        cls.owner = installed_core_lowering(str(cls.manifest), vars(backend))

    def new_owner(self):
        spec = json.loads(self.manifest.read_bytes())
        return NativeCoreLowering((self.manifest.parent / spec['image_path']).read_bytes(),
                                  spec['image_sha256'], vars(backend))

    def test_ordinary_backend_is_native_with_complete_metadata_and_no_retained_Function(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        from tests.test_hia_program_native_review import _empty_memory_program
        from tools.qualify_hia_program import qualification_program
        documents = [minimal_document(), _empty_memory_program(), qualification_program()]
        with patch.dict(os.environ, {SELECTOR: ''}):
            expected = [backend.emit_program_machine(verify_program(doc)) for doc in documents]
        for doc, wanted in zip(documents, expected):
            with selected_guard(self.manifest):
                actual = backend.emit_program_machine(verify_program(doc))
            self.assertEqual(comparable(actual), comparable(wanted))
            self.assertNotEqual(actual.implementation_sha256, wanted.implementation_sha256)



    def test_five_helpers_and_native_literal_owner_keep_errors_and_values(self):
        for typ in (*backend.WIDTHS, 'bool', 'unit', 'buffer', 'readbuf', 'mutbuf', 'chain', 'missing', None, []):
            for name in ('_words', '_bounds'):
                with self.subTest(name=name, typ=typ):
                    wanted = recorded(getattr(backend, '_reference' + name), typ)
                    self.assertEqual(recorded(self.owner.invoke, name, (typ,)), wanted)
        self.assertEqual(recorded(self.owner.invoke, '_reject', ('message', 'E_NATIVE')),
                         recorded(backend._reference_reject, 'message', 'E_NATIVE'))
        literal = self.owner.invoke('_native_globals', ())
        self.assertEqual(literal, {name: getattr(backend, name) for name in (
            'WIDTHS', 'BYTE_RESOURCES', 'MAX_TEXT_BYTES', 'MAX_FRAME_BYTES')})
        class Recorder:
            def __init__(self):
                self.calls = []
            def __getattr__(self, name):
                def call(*args):
                    self.calls.append((name, args))
                return call
        for typ in ('i8', 'u32', 'u64', 'bool', 'unit', 'chain'):
            old, native = Recorder(), Recorder()
            backend._reference_normalize(old, 'rax', typ)
            self.owner.invoke('_normalize', (native, 'rax', typ))
            self.assertEqual(native.calls, old.calls)
        old, native = Recorder(), Recorder()
        backend._reference_prologue(old, 8193)
        self.owner.invoke('_prologue', (native, 8193))
        self.assertEqual(native.calls, old.calls)



    def test_exact_foreign_store_binding_and_nested_native_invocation_order(self):
        def observe(native, reenter):
            events = []
            class Code:
                def __getattribute__(self, name):
                    if name == 'store':
                        events.append(['bind-store'])
                    return object.__getattribute__(self, name)
                def store(self, *arguments):
                    events.append(['old-store', *arguments])
                    if reenter:
                        result = self_owner.invoke('_words', ('mutbuf',)) if native else backend._reference_words('mutbuf')
                        events.append(['nested', result])
            class Slots(dict):
                def __getitem__(self, key):
                    events.append(['slot', key])
                    return super().__getitem__(key)
            code = Code()
            class Word:
                def __mul__(self, value):
                    events.append(['multiply', value])
                    code.store = lambda *args: events.append(['new-store', *args])
                    return 8
            receiver = types.SimpleNamespace(c=code, value_registers={}, slots=Slots(x=-24))
            self_owner = self.owner
            if native:
                result = recorded(self.owner.invoke, '_Function.store', (receiver, 'x', 'rax', Word()))
            else:
                result = recorded(backend._Function.store, receiver, 'x', 'rax', Word())
            return result, events
        for nested in (False, True):
            self.assertEqual(observe(True, nested), observe(False, nested))



    def test_capture_identity_reentrancy_and_all_bridge_dependencies(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        program = verify_program(minimal_document())
        with selected_guard(self.manifest):
            wanted = backend.emit_program_machine(program)
            original = backend._Emitter.render
            def render(emitter):
                os.environ[SELECTOR] = '/missing/changed-after-capture'
                return original(emitter)
            with patch.object(backend._Emitter, 'render', render):
                actual = backend.emit_program_machine(program)
        self.assertEqual(actual, wanted)
        with patch.dict(os.environ, {SELECTOR: ''}), native_core_lowering_scope(vars(backend)):
            os.environ[SELECTOR] = str(self.manifest)
            self.assertIsNone(active_core_lowering())
            with native_core_lowering_scope(vars(backend)):
                self.assertIsNone(active_core_lowering())
        original_read = Path.read_bytes
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            initial = backend._implementation_hash()
            for name in ('hia_core_lowering_native.py', 'hia_core_lowering_selection.py'):
                def changed(path, _name=name):
                    raw = original_read(path)
                    return raw + b'\n# identity observation\n' if path == ROOT / 'hepta' / _name else raw
                with patch.object(Path, 'read_bytes', changed):
                    self.assertNotEqual(backend._implementation_hash(), initial)


    def test_original_four_lifetime_generator_and_error_observations(self):
        observations = _peer_observations(self.owner)
        self.assertEqual(len(observations), 4)
        for row in observations:
            self.assertEqual(row['native'], row['reference'], row['case'])
        (self.folder / 'original-peer-four-observations.json').write_text(
            json.dumps(observations, indent=2) + '\n')
        try:
            raise ValueError('outer handled exception')
        except ValueError:
            outer = _peer_observations(self.owner)
        for row in outer:
            self.assertEqual(row['native'], row['reference'], row['case'])
        (self.folder / 'original-peer-four-with-outer-handler.json').write_text(
            json.dumps(outer, indent=2) + '\n')

    def test_every_actual_frame_matches_independent_VM_and_canaries(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        checked = assemble_program(SOURCE.read_bytes())
        function = checked.as_dict()['functions'][0]
        owner = self.new_owner()
        actual_entry = owner._entry
        observations = []
        def entry(source, size, output, outsize, workspace, worksize):
            before = (ctypes.string_at(source, size), ctypes.string_at(output, outsize),
                      ctypes.string_at(workspace, worksize))
            guards = [ctypes.create_string_buffer(b'\xa5' * 16 + value + b'\x5a' * 16, len(value) + 32)
                      for value in before]
            actual = actual_entry(ctypes.byref(guards[0], 16), size,
                                  ctypes.byref(guards[1], 16), outsize,
                                  ctypes.byref(guards[2], 16), worksize)
            owners = [_Owner(-1 - i, bytearray(value)) for i, value in enumerate(before)]
            vm = _Machine(checked, 20_000_000, 4 << 20, None, 128)
            wanted = vm.invoke(function, [_View(owners[0], False), _View(owners[1], True),
                                         _View(owners[2], True)])[0]
            self.assertEqual(actual, wanted)
            for guard, expected in zip(guards, owners):
                self.assertEqual(guard.raw[:16], b'\xa5' * 16)
                self.assertEqual(guard.raw[-16:], b'\x5a' * 16)
                self.assertEqual(guard.raw[16:-16], bytes(expected.data))
            self.assertEqual(guards[0].raw[16:-16], before[0])
            ctypes.memmove(output, guards[1].raw[16:-16], outsize)
            ctypes.memmove(workspace, guards[2].raw[16:-16], worksize)
            observations.append({'return': actual,
                'command': struct.unpack_from('<Q', before[2])[0],
                'source_sha256': sha256(before[0]).hexdigest(),
                'output_sha256': sha256(guards[1].raw[16:-16]).hexdigest(),
                'workspace_sha256': sha256(guards[2].raw[16:-16]).hexdigest()})
            return actual
        owner._entry = entry
        owner._initialize_control()
        owner._bind_namespace(vars(backend))
        for name, args in (('_words', ('mutbuf',)), ('_bounds', ('i8',)),
                           ('_reject', ('actual refusal', 'E_TEST'))):
            self.assertEqual(recorded(owner.invoke, name, args),
                             recorded(getattr(backend, '_reference' + name), *args))
        receiver = types.SimpleNamespace(cursor=8)
        self.assertEqual(owner.invoke('_Function.allocate', (receiver, 3)), -32)
        self.assertEqual(receiver.cursor, 32)
        self.assertTrue(any(r['command'] == 2 for r in observations))
        self.assertTrue(any(r['command'] == 4 for r in observations))
        self.assertIn(3, [r['return'] for r in observations])
        (self.folder / 'all-native-VM-frames.json').write_text(json.dumps(observations, indent=2) + '\n')

    def test_actual_frame_nonce_identity_claim_ack_and_terminal_are_once_only(self):
        mode = self.owner.modes['_words']['number']
        frame = LoweringSession(self.owner, mode, ('readbuf',))
        self.assertEqual(frame.step(), 1)
        issued = frame.pending
        with self.assertRaises(RuntimeError):
            frame.service(protocol.Issued(issued.raw))
        with self.assertRaises(RuntimeError):
            frame.step()
        frame.service(issued)
        with self.assertRaises(RuntimeError):
            frame.service(issued)
        status = frame.step()
        while status == 1:
            frame.service(frame.pending)
            status = frame.step()
        self.assertEqual(status, 0)
        self.assertEqual(frame.take(), 2)
        with self.assertRaises(RuntimeError):
            frame.take()
        frame.close()
        second = LoweringSession(self.owner, mode, ('readbuf',))
        self.assertEqual(second.step(), 1)
        self.assertNotEqual(frame.nonce, second.nonce)
        with self.assertRaises(RuntimeError):
            second.service(issued)
        # Even a byte-for-byte late native claim cannot authorize this frame.
        old = struct.unpack_from('<10Q', issued.raw)
        struct.pack_into('<5Q', second.state, 0, 2, old[1], old[2], old[4], 0)
        self.assertNotEqual(self.owner._entry(self.owner._table_buffer, len(self.owner.table),
            second.output, len(second.output), second.state, len(second.state)), 4)
        second.service(second.pending)
        while second.step() == 1:
            second.service(second.pending)
        self.assertEqual(second.take(), 2)
        second.close()

    def test_actual_reply_STORE_interruption_keeps_unknown_and_forbids_replay(self):
        frame = LoweringSession(self.owner, self.owner.modes['_words']['number'], ('mutbuf',))
        self.assertEqual(frame.step(), 1)
        issued = frame.pending
        calls = []
        original = frame._effect
        def effect():
            calls.append(True)
            return original()
        frame._effect = effect
        offsets = {i.offset for i in dis.get_instructions(protocol.PlanFrame.service)
                   if i.opname == 'STORE_ATTR' and i.argval == 'reply'}
        self.assertTrue(offsets)
        failure = KeyboardInterrupt('after actual Core primitive, before stored ACK')
        fired = []
        def trace(current, event, arg):
            if current.f_code is protocol.PlanFrame.service.__code__:
                current.f_trace_opcodes = True
                if event == 'opcode' and current.f_lasti in offsets and calls and not fired:
                    fired.append(True)
                    raise failure
            return trace
        previous, arming = sys.gettrace(), sys._getframe()
        old_opcodes = arming.f_trace_opcodes
        held = None
        try:
            arming.f_trace_opcodes = True
            sys.settrace(trace)
            frame.service(issued)
        except KeyboardInterrupt as error:
            held = error
        finally:
            sys.settrace(previous)
            arming.f_trace_opcodes = old_opcodes
        self.assertIs(held, failure)
        self.assertEqual(calls, [True])
        self.assertEqual(fired, [True])
        self.assertTrue(frame.closed and frame._uncertain)
        for replay in (lambda: frame.service(issued), frame.step, frame.take):
            with self.assertRaises(RuntimeError):
                replay()
        frame.close()
        self.assertIs(protocol._UNCONFIRMED_RETIREMENTS[frame.nonce], frame)

    def test_partial_constructor_and_post_machine_return_failure_keep_custody(self):
        original = protocol._private_zeroed_buffer
        calls, refs = [], []
        failure = MemoryError('second owned Core arena allocation')
        def allocate(size):
            calls.append(size)
            if len(calls) == 2:
                raise failure
            value = original(size)
            refs.append(weakref.ref(value))
            return value
        held = None
        with patch.object(protocol, '_private_zeroed_buffer', side_effect=allocate):
            try:
                LoweringSession(self.owner, self.owner.modes['_words']['number'], ('mutbuf',))
            except MemoryError as error:
                held = error
        self.assertIs(held, failure)
        self.assertEqual(len(refs), 1)
        self.assertIsNone(refs[0]())
        actual = self.owner._entry
        for kind in (KeyboardInterrupt, SystemExit, MemoryError, RuntimeError):
            returned = []
            failure = kind('after actual HIA frame returned')
            def entry(*args):
                returned.append(actual(*args))
                raise failure
            frame = LoweringSession(self.owner, self.owner.modes['_words']['number'], ('mutbuf',))
            with patch.object(self.owner, '_entry', entry):
                with self.assertRaises(kind) as seen:
                    frame.step()
            self.assertIs(seen.exception, failure)
            self.assertEqual(len(returned), 1)
            self.assertTrue(frame.closed and frame._uncertain)
            with self.assertRaises(RuntimeError):
                frame.step()

    def test_private_packet_extent_and_wrong_issued_payload_are_rejected(self):
        from tools.generate_hia_machine_plan_control import ABI
        for size, outsize, worksize in ((63, 2048, self.owner.workspace_bytes),
                (len(self.owner.table), 2047, self.owner.workspace_bytes),
                (len(self.owner.table), 2048, self.owner.workspace_bytes - 1)):
            source = ctypes.create_string_buffer(self.owner.table)
            output = ctypes.create_string_buffer(b'\xa5' * (2048 + 32), 2048 + 32)
            workspace = ctypes.create_string_buffer(self.owner.workspace_bytes + 32)
            struct.pack_into('<4Q', workspace, 16, 0, 1, 0, self.owner.modes['_words']['number'])
            before = bytes(source)
            result = self.owner._entry(source, size, ctypes.byref(output, 16), outsize,
                                       ctypes.byref(workspace, 16), worksize)
            self.assertEqual(result, ABI)
            self.assertEqual(bytes(source), before)
            self.assertEqual(bytes(output)[:16] + bytes(output)[-16:], b'\xa5' * 32)
            self.assertEqual(bytes(workspace)[:16] + bytes(workspace)[-16:], bytes(32))
        frame = LoweringSession(self.owner, self.owner.modes['_words']['number'], ('mutbuf',))
        self.assertEqual(frame.step(), 1)
        issued = frame.pending
        before = self.owner.entries
        object.__setattr__(issued, 'raw', issued.raw[:-1] + bytes([issued.raw[-1] ^ 1]))
        with self.assertRaises(RuntimeError):
            frame.service(issued)
        self.assertEqual(self.owner.entries, before)
        object.__setattr__(issued, 'raw', frame.frame_bytes)
        frame.service(issued)
        while frame.step() == 1:
            frame.service(frame.pending)
        self.assertEqual(frame.take(), 2)
        frame.close()

    def test_warm_source_image_and_manifest_are_rebound_before_effects(self):
        import hepta.hia_core_lowering_selection as selection
        from tools.qualify_hia_core_lowering_callers import copy_bundle
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            alternate = root / 'source.hiaasm'
            alternate.write_bytes(SOURCE.read_bytes() + b'\n')
            with patch.object(selection, 'SOURCE', alternate):
                with self.assertRaises(ValueError):
                    installed_core_lowering(str(self.manifest), vars(backend))
                alternate.unlink()
                with self.assertRaises(FileNotFoundError):
                    installed_core_lowering(str(self.manifest), vars(backend))
            copied = copy_bundle(self.manifest, root / 'bundle')
            loaded = installed_core_lowering(str(copied), vars(backend))
            spec = json.loads(copied.read_bytes())
            image = copied.parent / spec['image_path']
            raw = image.read_bytes()
            image.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
            with self.assertRaises(ValueError):
                installed_core_lowering(str(copied), vars(backend))
            image.write_bytes(raw)
            self.assertIs(installed_core_lowering(str(copied), vars(backend)), loaded)
            copied.write_text(copied.read_text().replace(SCHEMA, SCHEMA + '-wrong'))
            with self.assertRaises(ValueError):
                installed_core_lowering(str(copied), vars(backend))


    def test_actual_installed_wheel_uses_complete_bundle_without_authoring(self):
        from hepta.hia_agent_contract import (DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES)
        from tests.test_hia_program_native import minimal_document
        case = self.folder / 'installed-control'
        case.mkdir()
        source = case / 'source'
        source.mkdir()
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = tuple('docs/' + n for n in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        expected = {'python': {p.relative_to(ROOT).as_posix(): sha256(p.read_bytes()).hexdigest()
                              for p in sorted((ROOT / 'hepta').rglob('*.py')) if '_data' not in p.parts},
                    'resources': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in resources},
                    'document': minimal_document()}
        request = case / 'expected.json'
        request.write_text(json.dumps(expected, sort_keys=True))
        packaging = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        wheels, installed = case / 'wheels', case / 'installed'
        processes = []
        def run(arguments, label, env=None):
            result = subprocess.run(arguments, cwd=case, env=env, capture_output=True, timeout=120)
            (case / (label + '.stdout')).write_bytes(result.stdout)
            (case / (label + '.stderr')).write_bytes(result.stderr)
            processes.append({'argv': arguments, 'returncode': result.returncode,
                              'stdout_sha256': sha256(result.stdout).hexdigest(),
                              'stderr_sha256': sha256(result.stderr).hexdigest()})
            (case / 'processes.json').write_text(json.dumps(processes, indent=2) + '\n')
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result
        run([packaging, '-B', '-m', 'pip', 'wheel', '--no-cache-dir', '--no-deps', '--no-index',
             '--no-build-isolation', '--wheel-dir', str(wheels), str(source)], 'wheel-build')
        wheel, = wheels.glob('*.whl')
        run([packaging, '-B', '-m', 'pip', 'install', '--no-cache-dir', '--no-deps', '--no-index',
             '--target', str(installed), str(wheel)], 'wheel-install')
        script = case / 'installed-child.py'
        script.write_text(INSTALLED_CHILD)
        env = {k: v for k, v in os.environ.items() if not k.startswith('HEPTA_HIA_') and k != 'PYTHONPATH'}
        env['PATH'] = ''
        result = run([sys.executable, '-I', '-S', '-B', str(script), str(installed),
                      str(self.manifest), str(request)], 'installed-execution', env)
        observed = json.loads(result.stdout)
        self.assertEqual(observed['status'], 'INSTALLED_CORE_LOWERING_PASS')
        self.assertEqual(observed['images'], 1)
        (case / 'report.json').write_text(json.dumps(observed, indent=2, sort_keys=True) + '\n')


    def test_actual_encoding_proof_binds_captured_and_fresh_Core_images(self):
        from hepta import hia_checker_identity as identity
        from hepta.hia_proof_contract import proof_result
        from hepta.hia_agent_store import AgentRejected
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        import hepta.hia_core_lowering_selection as selection
        from tools.qualify_hia_core_lowering_callers import copy_bundle
        checked = verify_program(minimal_document())
        report = {'scope': 'ACTUAL_CORE_REDERIVATION_AND_PROOF_CONSUMPTION',
                  'modified_image_is_identity_fault_control_not_qualified_compiler_output': True}
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            first = backend.emit_program_machine(checked)
            second = backend.emit_program_machine(checked)
            self.assertEqual(first.object_bytes, second.object_bytes)
            observed = identity.checker_native_selection()
            self.assertEqual(observed[SELECTOR]['images']['image']['image_sha256'], self.owner.image_sha256)
            evidence = {'method': 'complete_native_rederivation', 'actual_sha256': first.sha256,
                        'bytes_equal': True, 'object_identity_equal': True,
                        'native_checker_selection': observed}
            subject = {'kind': 'native_artifact', 'candidate_core_sha256': checked.sha256,
                       'base_core_sha256': None, 'native_artifact': {'sha256': first.sha256}}
            def consume():
                return proof_result(claim='encoding_check', status='proved',
                    domain='actual complete Core relocatable-object rederivation identity control',
                    subject=subject, profile={}, installation={}, evidence=evidence)
            proof = consume()
            self.assertFalse(proof['global_safety_proved'])
            self.assertFalse(proof['execution_authority_granted'])
            with native_core_lowering_scope(vars(backend)):
                captured = selection.captured_checker_owner()
                self.assertTrue(captured[0])
                os.environ[SELECTOR] = '/missing/changed-after-real-selection'
                self.assertEqual(identity.checker_native_selection(), observed)
                held_image = backend.emit_program_machine(checked)
                self.assertEqual(comparable(held_image), comparable(first))
                self.assertEqual(consume(), proof)
                with self.assertRaises(ValueError):
                    identity.checker_native_selection(held_owners=(captured[1],))
            self.assertEqual(selection.captured_checker_owner(), (False, None))
            with self.assertRaises(FileNotFoundError):
                identity.checker_native_selection()
        with patch.dict(os.environ, {SELECTOR: ''}), native_core_lowering_scope(vars(backend)):
            os.environ[SELECTOR] = str(self.manifest)
            self.assertIsNone(identity.checker_native_selection()[SELECTOR])
            self.assertIsNone(active_core_lowering())
        with tempfile.TemporaryDirectory() as temporary:
            path = copy_bundle(self.manifest, Path(temporary) / 'second')
            spec = json.loads(path.read_bytes())
            image_path = path.parent / spec['image_path']
            image_path.write_bytes(image_path.read_bytes() + b'\x90')
            spec['image_sha256'] = sha256(image_path.read_bytes()).hexdigest()
            path.write_text(json.dumps(spec, sort_keys=True) + '\n')
            with patch.dict(os.environ, {SELECTOR: str(path)}):
                alternative = installed_core_lowering(str(path), vars(backend))
                before = alternative.entries
                regenerated = backend.emit_program_machine(checked)
                self.assertGreater(alternative.entries, before)
                self.assertEqual(regenerated.object_bytes, first.object_bytes)
                self.assertNotEqual(regenerated.implementation_sha256, first.implementation_sha256)
                self.assertNotEqual(identity.checker_native_selection(), observed)
                with self.assertRaisesRegex(AgentRejected, 'native checker selection differs'):
                    consume()
                report.update(alternative_image_sha256=alternative.image_sha256,
                              alternative_actual_native_entries=alternative.entries - before,
                              stale_proof_refused=True)
        for malformed in ((1, None), (True, {}), (False, captured[1])):
            with patch.object(selection, 'captured_checker_owner', return_value=malformed):
                with self.assertRaises(ValueError):
                    identity.checker_native_selection()
        with patch.dict(identity.CAPTURED_NATIVE_OWNERS,
                {'HEPTA_HIA_UNKNOWN_MANIFEST': ('hia_core_lowering_selection', 'captured_checker_owner')}):
            with self.assertRaises(ValueError):
                identity.checker_native_selection()
        actual = self.owner._entry
        failure = KeyboardInterrupt('after actual native return inside captured emit')
        entered = []
        def interrupted(*args):
            entered.append(actual(*args))
            raise failure
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            with patch.object(self.owner, '_entry', interrupted):
                with self.assertRaises(KeyboardInterrupt) as seen:
                    backend.emit_program_machine(checked)
            self.assertIs(seen.exception, failure)
            self.assertEqual(len(entered), 1)
            self.assertEqual(selection.captured_checker_owner(), (False, None))
            self.assertEqual(identity.checker_native_selection(), observed)
            self.assertEqual(consume(), proof)
            self.assertEqual(comparable(backend.emit_program_machine(checked)), comparable(first))
        self.assertEqual(selection.captured_checker_owner(), (False, None))
        report.update(original_image_sha256=self.owner.image_sha256,
                      captured_selector_drift_kept_original=True, captured_none_kept_none=True,
                      malformed_and_duplicate_capture_refused=True,
                      actual_unknown_exit_scope_restored=True)
        (self.folder / 'encoding-proof-selection.json').write_text(json.dumps(report, indent=2) + '\n')


    def test_three_physical_profiles_and_complete_Core_retirement_frames(self):
        from hepta.hia_core_lowering_native import LoweringSession
        from tests.hia_machine_frame_profile_controls import profile_matrix
        spec = json.loads(self.manifest.read_bytes())
        owner = NativeCoreLowering((self.manifest.parent / spec['image_path']).read_bytes(),
                                   spec['image_sha256'], vars(backend))
        class Code:
            def __getattr__(self, name):
                return lambda *arguments: None
        report = profile_matrix(self, owner, LoweringSession, SOURCE,
                                owner.modes['_prologue']['number'], (Code(), 0), None)
        (self.folder / 'physical-frame-profile-matrix.json').write_text(json.dumps(report, indent=2) + '\n')

    def test_facade_argument_transfer_preserves_parameter_and_named_local_lifetimes(self):
        rows = _facade_observations(self.owner)
        (self.folder / 'facade-parameter-lifetime-traces.json').write_text(json.dumps(rows, indent=2) + '\n')
        for row in rows:
            with self.subTest(fail=row['fail'], outer=row['outer']):
                self.assertEqual(row['native'], row['reference'])
                self.assertGreater(row['actual_entries'], 0)

    def test_helper_facades_preserve_original_parameter_and_derived_local_lifetimes(self):
        rows = _helper_facade_observations(self.owner, self.manifest)
        (self.folder / 'helper-facade-lifetime-traces.json').write_text(json.dumps(rows, indent=2) + '\n')
        self.assertEqual(len(rows), 12)
        for row in rows:
            with self.subTest(route=row['route'], fail=row['fail'], outer=row['outer']):
                self.assertEqual(row['actual'], row['reference'])
                if row['route'] == 'default-public':
                    self.assertEqual(row['actual_native_entries'], 0)
                else:
                    self.assertGreater(row['actual_native_entries'], 0)


    def test_six_owner_emission_keeps_captured_plan_and_proof_identity(self):
        from tests.hia_core_lowering_composition import controls
        controls(self, self.manifest, self.folder)

    def test_original_label_retires_temporary_receiver_and_argument_at_the_actual_Call(self):
        from tests.hia_machine_frame_shared_fixtures import core_label_cases
        owner = self.new_owner()
        rows = core_label_cases(owner, backend)
        (self.folder / 'original-Core-label-Call-lifetimes.json').write_text(json.dumps({
            'runtime_profile': owner.runtime_profile, 'cases': rows}, indent=2) + '\n')
        self.assertEqual(len(rows), 4)
        for row in rows:
            with self.subTest(fails=row['fails'], outer=row['outer']):
                self.assertFalse(any(row['expected']['alive_after_release'].values()))
                self.assertGreater(row['native_entries'], 0)
                self.assertEqual(row['actual'], row['expected'])


def _facade_observations(owner):
    import gc
    Native = owner.function_class(backend._Function)
    def observe(selected,fail,outer):
     events=[];refs=[];held=None;value=None
     def mark(name):
      handled=sys.exception();events.append([name,None if handled is None else type(handled).__name__])
     class Code:
      def __del__(self):mark('code-del')
     class Receiver:
      @property
      def c(self):
       mark('c-get');obj=Code();refs.append(weakref.ref(obj));return obj
      def __del__(self):mark('receiver-del')
     class Opcode(str):
      def __del__(self):mark('opcode-del')
     class Arguments(list):
      def __del__(self):mark('args-del')
     class Input:
      def __getitem__(self,key):
       mark('input-'+key)
       if key=='op':return Opcode('loan.end')
       if key=='args':return Arguments()
       if key=='attrs':
        if fail:raise LookupError('held original attrs failure')
        return {}
       if key=='out':return []
       raise KeyError(key)
      def __del__(self):mark('input-del')
     def invoke():
      return (Native.operation if selected else backend._Function.operation)(Receiver(),Input())
     def capture():
      nonlocal held,value
      try:value=['value',invoke()]
      except BaseException as error:
       held=error;value=['error',type(error).__name__,str(error)]
     previous=gc.isenabled();gc.disable()
     try:
      if outer:
       try:raise TypeError('real outer handled exception')
       except TypeError:capture()
      else:capture()
      before=list(events);live=[r() is not None for r in refs]
      if held is not None:held.__traceback__=None
      return {'outcome':value,'with_original_error':before,'live_with_error':live,'after_traceback_detach':list(events),'live_after_detach':[r() is not None for r in refs]}
     finally:
      held=None
      if previous:gc.enable()
    rows=[]
    for fail in (False,True):
        for outer in (False,True):
            expected=observe(False,fail,outer); entries=owner.entries
            actual=observe(True,fail,outer)
            rows.append({"fail":fail,"outer":outer,"reference":expected,"native":actual,"actual_entries":owner.entries-entries})
    return rows


def describe(error):
    if error is None:
        return None
    return {'type': type(error).__name__, 'args_repr': repr(error.args),
            'cause_type': None if error.__cause__ is None else type(error.__cause__).__name__,
            'context_type': None if error.__context__ is None else type(error.__context__).__name__}


def _peer_observations(owner):
    import builtins
    NativeFunction = owner.function_class(backend._Function)
    report = {'observations': []}
    def prologue(native, fail):
        events = []
        sentinel = LookupError('original-effect-failure')
        class Result:
            def __del__(self):
                handled = sys.exception()
                events.append(['drop-result', None if handled is None else type(handled).__name__])
        class Method:
            def __init__(self, name):
                self.name = name
            def __call__(self, *arguments):
                events.append(['call', self.name, *arguments])
                if fail and self.name == 'mov_rr':
                    raise sentinel
                return Result()
            def __del__(self):
                handled = sys.exception()
                events.append(['drop-callable', self.name, None if handled is None else type(handled).__name__])
        class Code:
            def __getattr__(self, name):
                events.append(['bind', name])
                return Method(name)
        held = None
        try:
            if native:
                owner.invoke('_prologue', (Code(), 0))
            else:
                backend._prologue(Code(), 0)
        except BaseException as caught:
            held = caught
        observation = {'events_while_exception_retained': list(events),
                       'error': describe(held), 'error_is_original': held is sentinel if fail else held is None}
        # This is an explicitly labelled diagnostic release, after the actual
        # retained-exception observation above. It is not a GC workaround.
        if held is not None:
            held.__traceback__ = None
        observation['events_after_explicit_traceback_detach'] = list(events)
        return observation

    for fail in (False, True):
        reference, native = prologue(False, fail), prologue(True, fail)
        report['observations'].append({'case': 'prologue-temporary-error' if fail else 'prologue-temporary-success',
            'reference': reference, 'native': native,
            'equal': reference == native})

    def constructor(native, intercept):
        events = []
        def watched_max(*args, **kwargs):
            events.append(['max', len(args), sorted(kwargs)])
            return builtins.max(*args, **kwargs)
        def watched_sum(*args, **kwargs):
            events.append(['sum', len(args), sorted(kwargs)])
            return builtins.sum(*args, **kwargs)
        parent = types.SimpleNamespace(c=object(), machine_plan=None,
            label=lambda name: events.append(['label', name]) or name)
        fn = {'name': 'f0', 'params': [], 'returns': ['u32'], 'effects': [], 'entry': 'b0',
              'blocks': [{'id': 'b0', 'params': [], 'ops': [
                  {'op': 'const', 'args': [], 'out': [{'name': 'v', 'type': 'u32'}], 'attrs': {'value': 7}}],
                  'term': {'op': 'ret', 'values': ['v']}}]}
        with patch.object(backend, 'max', watched_max, create=True), patch.object(backend, 'sum', watched_sum, create=True):
            value = (NativeFunction if native else backend._Function)(parent, fn, 0)
        fields = {name: getattr(value, name) for name in ('cursor', 'slots', 'types', 'edge_words',
            'call_words', 'result_words', 'edge_slot', 'call_slot', 'result_slot', 'temporary',
            'saved_registers', 'frame', 'trap')}
        return {'events': events, 'fields': fields}
    reference, native = constructor(False, True), constructor(True, True)
    report['observations'].append({'case': 'constructor-original-generator-reduction-lookup-order',
                                  'reference': reference, 'native': native, 'equal': reference == native})

    def stop_iteration(native):
        events = []
        sentinel = StopIteration('operand-stopped')
        class Parameter(dict):
            def __getitem__(self, key):
                if key == 'type':
                    events.append('parameter-type')
                    if len(events) == 2:
                        raise sentinel
                return super().__getitem__(key)
        parent = types.SimpleNamespace(c=object(), machine_plan=None, label=lambda name: name)
        fn = {'name': 'f0', 'blocks': [{'id': 'b0', 'params': [Parameter(name='p', type='u32')], 'ops': []}]}
        held = None
        try:
            (NativeFunction if native else backend._Function)(parent, fn, 0)
        except BaseException as caught:
            held = caught
        row = {'events': list(events), 'error': describe(held),
               'error_is_operand': held is sentinel,
               'cause_is_operand': held is not None and held.__cause__ is sentinel}
        if held is not None:
            held.__traceback__ = None
        return row
    reference, native = stop_iteration(False), stop_iteration(True)
    report['observations'].append({'case': 'constructor-original-generator-StopIteration-channel',
                                  'reference': reference, 'native': native, 'equal': reference == native})
    return report['observations']


INSTALLED_CHILD = r'''
import importlib.abc,inspect,json,os,sys
from pathlib import Path
from hashlib import sha256
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed lowering imported authoring tools')
sys.meta_path.insert(0,NoTools())
root=Path(sys.argv[1])
expected=json.loads(Path(sys.argv[3]).read_bytes())
for name,identity in expected['python'].items():
    assert sha256((root/name).read_bytes()).hexdigest()==identity
actual={p.relative_to(root).as_posix() for p in (root/'hepta').rglob('*.py') if '_data' not in p.parts}
assert actual==set(expected['python'])
from hepta.hia_json_preflight_native import _source_resource_path
for name,identity in expected['resources'].items():
    path=_source_resource_path(name)
    assert root in path.parents and sha256(path.read_bytes()).hexdigest()==identity
from hepta import hia_program_native as backend
from hepta.hia_program import verify_program
from hepta.hia_core_lowering_selection import SELECTOR,installed_core_lowering,active_core_lowering
from hepta.hia_core_lowering_native import LoweringSession,SOURCE
entries=[]
real=LoweringSession._invoke
def entry(session,*args,**kwargs):
    value=real(session,*args,**kwargs);entries.append(value);return value
LoweringSession._invoke=entry
def forbidden(*args,**kwargs):
    raise AssertionError('retained Function control entered installed child')
for name,method in tuple(backend._Function.__dict__.items()):
    if inspect.isfunction(method) and name!='__new__':
        setattr(backend._Function,name,forbidden)
for name in ('_reject','_words','_bounds','_normalize','_prologue'):
    legacy='_reference'+name
    original=getattr(backend,legacy)
    def guard(*args,_old=original,**kwargs):
        if active_core_lowering() is not None:return forbidden()
        return _old(*args,**kwargs)
    setattr(backend,legacy,guard)
os.environ[SELECTOR]=sys.argv[2]
owner=installed_core_lowering(sys.argv[2],vars(backend))
machine=backend.emit_program_machine(verify_program(expected['document']))
assert machine.object_bytes.startswith(b'\x7fELF')
assert entries and 0 in entries and 1 in entries and 4 in entries and 5 in entries
raw=SOURCE.read_bytes()
SOURCE.write_bytes(raw+b'\n')
try:installed_core_lowering(sys.argv[2],vars(backend))
except ValueError:pass
else:raise AssertionError('warm HIA source change was ignored')
SOURCE.write_bytes(raw);SOURCE.unlink()
try:installed_core_lowering(sys.argv[2],vars(backend))
except FileNotFoundError:pass
else:raise AssertionError('missing installed source fell back to checkout')
SOURCE.write_bytes(raw)
assert sys.flags.isolated and sys.flags.no_site and os.environ['PATH']==''
print(json.dumps({'status':'INSTALLED_CORE_LOWERING_PASS','images':1,
 'source_sha256':owner.admitted_source_sha256,'image_sha256':owner.image_sha256,
 'object_sha256':machine.sha256,'python_files':len(expected['python']),
 'resource_files':len(expected['resources']),'actual_native_frames':len(entries),
 'retained_lowering_forbidden':True,'authoring_forbidden':True,'isolated_without_site':True,'empty_PATH':True}))
'''


if __name__ == '__main__':
    unittest.main()


def _helper_facade_observations(owner,manifest):
    import gc
    MANIFEST = manifest
    def observe(route,fail,outer):
     events=[];held=None;outcome=None
     def mark(name):
      active=sys.exception();events.append([name,None if active is None else type(active).__name__])
     class Remaining(int):
      def __bool__(self):
       if fail:raise LookupError('actual final while truth failure')
       return False
      def __del__(self):mark('remaining-del')
     class Count(int):
      def __sub__(self,other):return Remaining(0)
      def __del__(self):mark('count-del')
     class Code:
      def __getattr__(self,name):return lambda *args: None
      def __del__(self):mark('code-del')
     def invoke():
      if route=='reference':return backend._reference_prologue(Code(),Count(1))
      if route=='native-direct':return owner.invoke('_prologue',(Code(),Count(1)))
      with patch.dict(os.environ,{SELECTOR:str(MANIFEST) if route=='native-public' else ''}):
       with native_core_lowering_scope(vars(backend)):
        return backend._prologue(Code(),Count(1))
     def capture():
      nonlocal held,outcome
      try:outcome=['value',invoke()]
      except BaseException as error:held=error;outcome=['error',type(error).__name__,str(error)]
     old=gc.isenabled();gc.disable()
     try:
      if outer:
       try:raise TypeError('actual outer handled')
       except TypeError:capture()
      else:capture()
      before=list(events)
      if held is not None:held.__traceback__=None
      return {'outcome':outcome,'with_error':before,'after_detach':list(events)}
     finally:
      held=None
      if old:gc.enable()
    rows=[]
    for fail in (False,True):
     for outer in (False,True):
      expected=observe('reference',fail,outer)
      for route in ('native-direct','native-public','default-public'):
       entries=owner.entries;actual=observe(route,fail,outer)
       rows.append({'route':route,'fail':fail,'outer':outer,'reference':expected,'actual':actual,'equal':expected==actual,'actual_native_entries':owner.entries-entries})
    return rows
