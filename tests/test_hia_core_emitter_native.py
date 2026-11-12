"""Actual six-method Core emitter controls, including original lifetime oracles."""
from __future__ import annotations

import ast
from collections import Counter
from contextlib import ExitStack
from dataclasses import fields
import gc
import ctypes
import dis
import shutil
import struct
import subprocess
import tempfile
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
import weakref
from unittest.mock import patch

from hepta import hia_program_native as backend
from hepta.hia_core_emitter_native import NativeCoreEmitter, EmitterFrame, SOURCE, SCHEMA
from hepta.hia_core_emitter_selection import (
    SELECTOR, installed_core_emitter, native_core_emitter_scope, active_core_emitter)

ROOT = Path(__file__).resolve().parents[1]
METHODS = ('__init__', 'ordered_blocks', 'label', 'function_symbol', 'wrapper', 'render')
DEVELOPMENT = 'HEPTA_HIA_CORE_EMITTER_DEVELOPMENT_MANIFEST'
COLD = 'HEPTA_HIA_CORE_EMITTER_COLD_REPORT'
EVIDENCE = 'HEPTA_HIA_CORE_EMITTER_FIXTURE_EVIDENCE'
FIXTURE_SHA = '8fd7cd5b01b2501e6ff36cadaf6dee6662c57b01b30a2686455ec6e07b730e57'


def recorded(function, *arguments):
    try:
        return {'value': function(*arguments)}
    except BaseException as error:
        return {'exception_type': type(error), 'exception_args': error.args}


def comparable(machine):
    return {field.name: getattr(machine, field.name) for field in fields(machine)
            if field.name != 'implementation_sha256'}


def guard(manifest):
    stack = ExitStack()
    stack.enter_context(patch.dict(os.environ, {SELECTOR: str(manifest)}))
    for name in METHODS:
        stack.enter_context(patch.object(backend._Emitter, name,
            side_effect=AssertionError('retained emitter entered: ' + name)))
    return stack


def _handled():
    error = sys.exception()
    return None if error is None else [type(error).__name__, str(error)]


def keyword_observation(owner, case):
    """Execute the unchanged original body or its HIA counterpart once."""
    from hepta import hia_machine_plan
    events, refs = [], []
    held = None
    class Value:
        def __init__(self):
            refs.append(weakref.ref(self))
        def __del__(self):
            events.append(['value-del', _handled()])
    class Options(dict):
        def __del__(self):
            events.append(['options-del', _handled()])
    class Mapping:
        def __init__(self):
            self.value = Value()
        def keys(self):
            events.append(['keys', _handled()])
            if case == 'keys-attribute':
                raise AttributeError('original keys refused')
            if case == 'keys-runtime':
                raise RuntimeError('original keys failed')
            if case == 'keys-key-one':
                raise KeyError('x')
            if case == 'keys-key-empty':
                raise KeyError()
            if case == 'keys-key-two':
                raise KeyError('x', 'y')
            if case == 'keys-not-iterable':
                return 7
            return ['x', 'x'] if case == 'duplicate' else [7] if case == 'nonstring' else ['x']
        def __getitem__(self, key):
            events.append(['item', key, _handled()])
            if case == 'item-key':
                raise KeyError(key)
            if case == 'item-runtime':
                raise RuntimeError('original item failed')
            return self.value
        def __del__(self):
            events.append(['mapping-del', _handled()])
    def options(plan):
        events.append(['options-enter', _handled()])
        if case == 'empty':
            return Options()
        if case in ('dict', 'call-error', 'call-stop', 'call-exit', 'call-interrupt'):
            return Options(x=Value())
        if case == 'none':
            return None
        if case == 'integer':
            return 7
        if case == 'list':
            return [('x', 1)]
        return Mapping()
    def code(x=None, **kwargs):
        events.append(['code-enter', x is not None, list(kwargs), _handled()])
        if case in ('call-error', 'call-stop', 'call-exit', 'call-interrupt'):
            kind = {'call-error': RuntimeError, 'call-stop': StopIteration,
                    'call-exit': SystemExit, 'call-interrupt': KeyboardInterrupt}[case]
            raise kind('original callable failed')
        x = None
        kwargs.clear()
        events.append(['code-after-release', _handled()])
        return object()
    receiver = SimpleNamespace()
    error_record = None
    with patch.object(hia_machine_plan, 'code_options', options), patch.object(backend, 'Code', code):
        try:
            if owner is None:
                backend._Emitter.__init__(receiver, {'functions': []}, frozenset())
            else:
                owner.invoke('_Emitter.__init__', (receiver, {'functions': []}, frozenset(), None, (), None))
            events.append(['init-return', _handled()])
        except BaseException as error:
            held = error
            error_record = [type(error).__name__, list(error.args),
                None if error.__context__ is None else [type(error.__context__).__name__, list(error.__context__.args)],
                error.__suppress_context__]
    gc.collect()
    before = [ref() is not None for ref in refs]
    events.append(['before-traceback-release', before, _handled()])
    held = None
    gc.collect()
    after = [ref() is not None for ref in refs]
    events.append(['after-traceback-release', after, _handled()])
    return {'case': case, 'events': events, 'error': error_record, 'alive': after}


class CoreEmitterSourceTests(unittest.TestCase):
    def test_exact_six_original_methods_and_authoring_inventory(self):
        fixture = ROOT / 'tests/fixtures/hia_program_emitter_v76.py.txt'
        raw = fixture.read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), FIXTURE_SHA)
        original = next(n for n in ast.parse(raw).body if isinstance(n, ast.ClassDef) and n.name == '_Emitter')
        current = next(n for n in ast.parse(inspect.getsource(backend)).body if isinstance(n, ast.ClassDef) and n.name == '_Emitter')
        self.assertEqual(tuple(n.name for n in original.body), METHODS)
        current.body = [n for n in current.body if n.name != '__new__']
        self.assertEqual(ast.dump(original), ast.dump(current))
        policy = ast.parse((ROOT / 'tools/hia_core_emitter_policy.py').read_text())
        selected = next(n for n in policy.body if isinstance(n, ast.ClassDef))
        self.assertEqual(ast.dump(original), ast.dump(selected))
        import hepta.hia_core_emitter_native as bridge
        tree = ast.parse(inspect.getsource(bridge))
        self.assertFalse(any(isinstance(n, ast.ImportFrom) and n.module and n.module.startswith('tools') for n in ast.walk(tree)))
        self.assertFalse(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ('eval', 'exec', 'compile') for n in ast.walk(tree)))
        from tools.generate_hia_core_emitter import program
        from tools.hia_core_emitter_control import OPS
        calls = []
        for function in program().functions:
            for instruction in function.instructions:
                if instruction['kind'] != 'effect' or instruction['opcode'] != OPS['CALL']:
                    continue
                arguments, consumed = instruction['arguments'], instruction['consume']
                self.assertEqual(len(arguments), len({value.slot for value in arguments}))
                self.assertTrue(all(value.temporary for value in arguments))
                expected = arguments[1:] if instruction['raw'] == [0, 254] else arguments
                self.assertEqual([value.slot for value in consumed], [value.slot for value in expected])
                calls.append(instruction['raw'])
        self.assertTrue(calls)
        self.assertIn([0, 254], calls)
        self.assertIn([0, 255], calls)

    def test_unqualified_cold_refuses_before_output_creation(self):
        import tempfile
        from tools.build_hia_core_emitter import build
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            compiler, cold = directory / 'compiler', directory / 'cold'
            compiler.write_bytes(b'not-qualified')
            cold.write_text('{"status":"DEVELOPMENT_ONLY"}')
            with self.assertRaisesRegex(ValueError, 'completed matching native cold'):
                build(directory / 'must-not-create/build', compiler, cold)
            self.assertFalse((directory / 'must-not-create').exists())

    def test_unselected_subclasses_and_early_target_refusal_remain_original(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        program = verify_program(minimal_document())
        with patch.dict(os.environ, {SELECTOR: ''}):
            self.assertIs(type(backend._Emitter(program.as_dict(), {'answer'})), backend._Emitter)
            original = backend.emit_program_machine(program)
        class Foreign(backend._Emitter):
            def __init__(self, *args):
                self.arguments = args
        with patch.dict(os.environ, {SELECTOR: '/missing/native-emitter-manifest'}):
            self.assertEqual(Foreign(None, 7).arguments, (None, 7))
            with self.assertRaises(FileNotFoundError):
                backend.emit_program_machine(program)
            with self.assertRaisesRegex(backend.HIAProgramNativeRejected, 'E_HIA_PROGRAM_TARGET'):
                backend.emit_program_machine(program, target='unreviewed-target')
        self.assertTrue(original.object_bytes)


    def test_complete_HIA_table_and_original_profile_match_independent_VM(self):
        from hepta.hia_agent_assembly import assemble_program, render_assembly
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from tools.generate_hia_core_emitter import document, program, EMIT_MAGIC
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
        self.assertEqual(len(policy.functions), 12)  # Seven roots and five lazy generators.
        self.assertEqual(vm.resources()['live_owners'], 0)


class CoreEmitterNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile
        development, cold = os.environ.get(DEVELOPMENT), os.environ.get(COLD)
        if development and cold:
            raise AssertionError('development cannot override requested current cold')
        if not development and not cold:
            raise unittest.SkipTest('requires actual current cold or explicit development image')
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence).resolve()
            cls.folder.mkdir(parents=True, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='hia-core-emitter-')
            cls.addClassCleanup(temporary.cleanup)
            cls.folder = Path(temporary.name)
        if cold:
            from tools.build_hia_core_emitter import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build(cls.folder / 'qualified', compiler, Path(cold))
            cls.scope = 'MATCHING_SOURCE_COLD'
        else:
            cls.manifest = Path(development).resolve(strict=True)
            cls.scope = 'EXPLICIT_DEVELOPMENT_ONLY'
        cls.owner = installed_core_emitter(str(cls.manifest), vars(backend))

    def new_owner(self):
        spec = json.loads(self.manifest.read_bytes())
        return NativeCoreEmitter((self.manifest.parent / spec['image_path']).read_bytes(), spec['image_sha256'], vars(backend))

    def test_complete_native_frames_and_canaries_match_independent_VM(self):
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
            guards = [ctypes.create_string_buffer(b'\xa5'*16 + value + b'\x5a'*16, len(value)+32)
                      for value in before]
            actual = actual_entry(ctypes.byref(guards[0],16),size,
                ctypes.byref(guards[1],16),outsize,ctypes.byref(guards[2],16),worksize)
            owners = [_Owner(-1-i,bytearray(value)) for i,value in enumerate(before)]
            vm = _Machine(checked,20_000_000,4<<20,None,128)
            wanted = vm.invoke(function,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
            self.assertEqual(actual,wanted)
            for observed, expected in zip(guards,owners):
                self.assertEqual(observed.raw[:16],b'\xa5'*16)
                self.assertEqual(observed.raw[-16:],b'\x5a'*16)
                self.assertEqual(observed.raw[16:-16],bytes(expected.data))
            self.assertEqual(guards[0].raw[16:-16],before[0])
            ctypes.memmove(output,guards[1].raw[16:-16],outsize)
            ctypes.memmove(workspace,guards[2].raw[16:-16],worksize)
            observations.append({'return':actual,'command':struct.unpack_from('<Q',before[2])[0],
                'input_sha256':sha256(before[0]).hexdigest(),
                'output_sha256':sha256(guards[1].raw[16:-16]).hexdigest(),
                'workspace_sha256':sha256(guards[2].raw[16:-16]).hexdigest()})
            return actual
        owner._entry = entry
        owner._initialize_control()
        owner._bind_namespace(vars(backend))
        for name, factory in (
            ('label',lambda:(SimpleNamespace(serial=3),'edge')),
            ('function_symbol',lambda:(SimpleNamespace(indices={}), 'missing')),
            ('__init__',lambda:(SimpleNamespace(),{'functions':[]},frozenset(),None,(),None))):
            native_args,old_args=factory(),factory()
            self.assertEqual(recorded(owner.invoke,'_Emitter.'+name,native_args),
                             recorded(getattr(backend._Emitter,name),*old_args))
        self.assertIn(2,[row['command'] for row in observations])
        self.assertIn(4,[row['command'] for row in observations])
        self.assertIn(3,[row['return'] for row in observations])
        (self.folder/'all-native-VM-frames.json').write_text(json.dumps(observations,indent=2)+'\n')

    def test_claim_ack_and_mapping_handoff_cannot_replay_after_actual_call(self):
        from hepta import hia_machine_plan, hia_machine_plan_control_native as protocol
        owner=self.new_owner()
        frame=owner.prepare('_Emitter.__init__',(SimpleNamespace(),{'functions':[]},frozenset(),None,(),None))
        calls=[]
        def code(**kwargs):
            calls.append(tuple(kwargs))
            return object()
        with patch.object(hia_machine_plan,'code_options',return_value={}),patch.object(backend,'Code',code):
            while frame.step()==1:
                if frame._parts()[0]==9 and frame._parts()[3]==(0,255):
                    break
                frame.service(frame.pending)
            self.assertEqual(frame._parts()[3],(0,255))
            issued=frame.pending
            slots=frame._parts()[2]
            with self.assertRaises(RuntimeError):
                frame.service(protocol.Issued(issued.raw))
            with self.assertRaises(RuntimeError):
                frame.step()
            offsets={item.offset for item in dis.get_instructions(protocol.PlanFrame.service)
                     if item.opname=='STORE_ATTR' and item.argval=='reply'}
            self.assertTrue(offsets)
            fired=[]
            failure=KeyboardInterrupt('after actual emitter CALL, before stored acknowledgement')
            def trace(current,event,arg):
                if current.f_code is protocol.PlanFrame.service.__code__:
                    current.f_trace_opcodes=True
                    if event=='opcode' and current.f_lasti in offsets and calls and not fired:
                        fired.append(True)
                        raise failure
                return trace
            previous,arming=sys.gettrace(),sys._getframe()
            old_opcodes=arming.f_trace_opcodes
            try:
                arming.f_trace_opcodes=True
                sys.settrace(trace)
                with self.assertRaises(KeyboardInterrupt) as seen:
                    frame.service(issued)
            finally:
                sys.settrace(previous)
                arming.f_trace_opcodes=old_opcodes
            self.assertIs(seen.exception,failure)
        self.assertEqual(calls,[()])
        self.assertEqual(fired,[True])
        self.assertTrue(frame.closed and frame._uncertain)
        self.assertTrue(all(frame.values[slot] is protocol._EMPTY for slot in slots))
        for replay in (lambda:frame.service(issued),frame.step,frame.take):
            with self.assertRaises(RuntimeError):
                replay()
        frame.close()
        self.assertIs(protocol._UNCONFIRMED_RETIREMENTS[frame.nonce],frame)
        (self.folder/'mapping-handoff-unknown-ack.json').write_text(json.dumps({
            'actual_calls':len(calls),'replay_forbidden':True,'operands_transferred':True,
            'retirement_unknown_retained':True,'actual_native_entries':owner.entries},indent=2)+'\n')

    def test_original_escaped_generator_close_and_cross_thread_final_release(self):
        import threading
        def observe(native,close,threaded,outer):
            events=[]; refs=[]; held=[]
            class Param(dict):
                def __init__(self):
                    super().__init__(name='x',type='u64');refs.append(weakref.ref(self))
                def __del__(self):
                    events.append(['param-del',threading.current_thread().name,_handled()])
            def keep(generator):
                held.append(generator)
                return False
            receiver=SimpleNamespace(c=backend.Code(),foreign_buffer_exports={},allowed_exports={'f'},
                symbols=[],exports=[],function_symbol=lambda name:'private_f')
            def invoke():
                fn={'name':'f','params':[Param()],'returns':[]}
                with patch.object(backend,'any',keep,create=True):
                    if native:
                        self.owner.invoke('_Emitter.wrapper',(receiver,fn))
                    else:
                        backend._Emitter.wrapper(receiver,fn)
            def execute():
                invoke();gc.collect()
                self.assertEqual(len(held),2)
                events.append(['returned',*[ref() is not None for ref in refs]])
                if close:
                    for generator in held:generator.close()
                    generator=None
                if threaded:
                    failure=[]
                    def retire():
                        try:held.clear();gc.collect()
                        except BaseException as error:failure.append([type(error).__name__,str(error)])
                    thread=threading.Thread(target=retire,name='emitter-final-holder')
                    thread.start();thread.join(5)
                    self.assertFalse(thread.is_alive());self.assertFalse(failure)
                else:
                    held.clear();gc.collect()
                events.append(['released',*[ref() is not None for ref in refs]])
            if outer:
                try:raise LookupError('outer generator holder')
                except LookupError:execute()
            else:execute()
            self.assertTrue(all(ref() is None for ref in refs))
            return events
        rows=[]
        for close in (False,True):
            for threaded in (False,True):
                for outer in (False,True):
                    row={'close':close,'threaded':threaded,'outer':outer,
                         'reference':observe(False,close,threaded,outer),
                         'native':observe(True,close,threaded,outer)}
                    rows.append(row)
                    with self.subTest(close=close,threaded=threaded,outer=outer):
                        self.assertEqual(row['native'],row['reference'])
        (self.folder/'generator-close-cross-thread-eight.json').write_text(json.dumps(rows,indent=2)+'\n')

    def test_public_facade_parameter_temporaries_and_held_traceback_match_original(self):
        native_type=self.owner.emitter_class(backend._Emitter)
        def observe(native,fail,outer):
            events=[];held=None;value=None
            def mark(name):events.append([name,_handled()])
            class Name(str):
                def __del__(self):mark('name-del')
            class Blocks(list):
                def __del__(self):mark('blocks-del')
            class Order:
                def get(self,name):
                    mark('order-get')
                    if fail:raise LookupError('original order-get failure')
                    return None
                def __del__(self):mark('order-del')
            class Receiver:
                @property
                def block_order(self):mark('order-attribute');return Order()
                def __del__(self):mark('receiver-del')
            class Input:
                def __getitem__(self,key):
                    mark('input-'+key)
                    return Name('f') if key=='name' else Blocks()
                def __del__(self):mark('input-del')
            def invoke():
                return (native_type if native else backend._Emitter).ordered_blocks(Receiver(),Input())
            def capture():
                nonlocal value,held
                try:value=invoke()
                except BaseException as error:held=error
            if outer:
                try:raise RuntimeError('original outer facade handler')
                except RuntimeError:capture()
            else:capture()
            outcome=['value',list(value)] if held is None else ['error',type(held).__name__,str(held)]
            value=None;gc.collect();before=list(events)
            held=None;gc.collect()
            return {'outcome':outcome,'before':before,'after':events}
        rows=[]
        for fail in (False,True):
            for outer in (False,True):
                row={'fail':fail,'outer':outer,'reference':observe(False,fail,outer),
                     'native':observe(True,fail,outer)}
                rows.append(row)
                with self.subTest(fail=fail,outer=outer):self.assertEqual(row['native'],row['reference'])
        (self.folder/'facade-four-original-observations.json').write_text(json.dumps(rows,indent=2)+'\n')

    def test_complete_ordinary_output_and_all_six_native_entries(self):
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        from tests.test_hia_program_native_review import _empty_memory_program
        from tools.qualify_hia_program import qualification_program
        documents = [minimal_document(), _empty_memory_program(), qualification_program()]
        with patch.dict(os.environ, {SELECTOR: ''}):
            expected = [backend.emit_program_machine(verify_program(doc)) for doc in documents]
        counts = Counter()
        prepare = self.owner.prepare
        def selected(name, arguments):
            counts[name] += 1
            return prepare(name, arguments)
        before = self.owner.entries
        with patch.object(self.owner, 'prepare', selected), guard(self.manifest):
            actual = [backend.emit_program_machine(verify_program(doc)) for doc in documents]
        self.assertEqual([comparable(x) for x in actual], [comparable(x) for x in expected])
        self.assertGreater(self.owner.entries, before)
        self.assertTrue(all(counts['_Emitter.' + name] for name in METHODS))
        (self.folder / 'ordinary-six-methods.json').write_text(json.dumps({'counts': dict(counts), 'native_entries': self.owner.entries-before, 'scope': self.scope}, indent=2)+'\n')

    def test_original_mapping_protocol_lifetimes_and_full_errors(self):
        cases = ('empty', 'dict', 'mapping', 'duplicate', 'nonstring', 'none', 'integer', 'list',
                 'keys-attribute', 'keys-runtime', 'keys-key-one', 'keys-key-empty', 'keys-key-two',
                 'keys-not-iterable', 'item-key', 'item-runtime', 'call-error', 'call-stop', 'call-exit', 'call-interrupt')
        rows = []
        for outer in (False, True):
            def compare():
                for case in cases:
                    row = {'outer': outer, 'case': case, 'reference': keyword_observation(None, case),
                           'native': keyword_observation(self.owner, case)}
                    rows.append(row)
                    with self.subTest(outer=outer, case=case):
                        self.assertEqual(row['native'], row['reference'])
                        self.assertFalse(any(row['native']['alive']))
            if outer:
                try:
                    raise LookupError('outer original exception')
                except LookupError:
                    compare()
            else:
                compare()
        (self.folder / 'mapping-protocol-40-observations.json').write_text(json.dumps(rows, indent=2)+'\n')

    def test_all_simple_methods_and_rejection_branches_use_original_oracles(self):
        cases = [('_Emitter.label', lambda: (SimpleNamespace(serial=2), 'edge')),
                 ('_Emitter.function_symbol', lambda: (SimpleNamespace(indices={'f': 3}), 'f')),
                 ('_Emitter.function_symbol', lambda: (SimpleNamespace(indices={}), 'missing')),
                 ('_Emitter.ordered_blocks', lambda: (SimpleNamespace(block_order={}), {'name':'f','blocks':[{'id':'a'}]})),
                 ('_Emitter.ordered_blocks', lambda: (SimpleNamespace(block_order={'f':['b','a']}), {'name':'f','blocks':[{'id':'a'},{'id':'b'}]})),
                 ('_Emitter.ordered_blocks', lambda: (SimpleNamespace(block_order={'f':['missing']}), {'name':'f','blocks':[{'id':'a'}]})),
                 ('_Emitter.render', lambda: (SimpleNamespace(document={'schema':'unreviewed'}),))]
        for name, arguments in cases:
            with self.subTest(name=name, case=repr(arguments())):
                old_args, native_args = arguments(), arguments()
                original = getattr(backend._Emitter, name.split('.')[1])
                self.assertEqual(recorded(self.owner.invoke, name, native_args), recorded(original, *old_args))
                self.assertEqual(vars(native_args[0]), vars(old_args[0]))


    def test_warm_source_image_and_manifest_are_rebound_before_effects(self):
        import hepta.hia_core_emitter_selection as selection
        from tools.qualify_hia_core_emitter_callers import copy_bundle
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            alternate = root / 'source.hiaasm'
            alternate.write_bytes(SOURCE.read_bytes() + b'\n')
            with patch.object(selection, 'SOURCE', alternate):
                with self.assertRaises(ValueError):
                    installed_core_emitter(str(self.manifest), vars(backend))
                alternate.unlink()
                with self.assertRaises(FileNotFoundError):
                    installed_core_emitter(str(self.manifest), vars(backend))
            copied = copy_bundle(self.manifest, root / 'bundle')
            loaded = installed_core_emitter(str(copied), vars(backend))
            spec = json.loads(copied.read_bytes())
            image = copied.parent / spec['image_path']
            raw = image.read_bytes()
            image.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
            with self.assertRaises(ValueError):
                installed_core_emitter(str(copied), vars(backend))
            image.write_bytes(raw)
            self.assertIs(installed_core_emitter(str(copied), vars(backend)), loaded)
            copied.write_text(copied.read_text().replace(SCHEMA, SCHEMA + '-wrong'))
            with self.assertRaises(ValueError):
                installed_core_emitter(str(copied), vars(backend))


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
        self.assertEqual(observed['status'], 'INSTALLED_CORE_EMITTER_PASS')
        self.assertEqual(observed['images'], 1)
        (case / 'report.json').write_text(json.dumps(observed, indent=2, sort_keys=True) + '\n')


    def test_actual_encoding_proof_binds_captured_and_fresh_Core_images(self):
        from hepta import hia_checker_identity as identity
        from hepta.hia_proof_contract import proof_result
        from hepta.hia_agent_store import AgentRejected
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        import hepta.hia_core_emitter_selection as selection
        from tools.qualify_hia_core_emitter_callers import copy_bundle
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
            with native_core_emitter_scope(vars(backend)):
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
        with patch.dict(os.environ, {SELECTOR: ''}), native_core_emitter_scope(vars(backend)):
            os.environ[SELECTOR] = str(self.manifest)
            self.assertIsNone(identity.checker_native_selection()[SELECTOR])
            self.assertIsNone(active_core_emitter())
        with tempfile.TemporaryDirectory() as temporary:
            path = copy_bundle(self.manifest, Path(temporary) / 'second')
            spec = json.loads(path.read_bytes())
            image_path = path.parent / spec['image_path']
            image_path.write_bytes(image_path.read_bytes() + b'\x90')
            spec['image_sha256'] = sha256(image_path.read_bytes()).hexdigest()
            path.write_text(json.dumps(spec, sort_keys=True) + '\n')
            with patch.dict(os.environ, {SELECTOR: str(path)}):
                alternative = installed_core_emitter(str(path), vars(backend))
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
                {'HEPTA_HIA_UNKNOWN_MANIFEST': ('hia_core_emitter_selection', 'captured_checker_owner')}):
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
        from hepta.hia_core_emitter_native import EmitterFrame
        from tests.hia_machine_frame_profile_controls import profile_matrix
        spec = json.loads(self.manifest.read_bytes())
        owner = NativeCoreEmitter((self.manifest.parent / spec['image_path']).read_bytes(),
                                   spec['image_sha256'], vars(backend))
        class Code:
            def __getattr__(self, name):
                return lambda *arguments: None
        report = profile_matrix(self, owner, EmitterFrame, SOURCE,
                                owner.modes['_Emitter.__init__']['number'], (SimpleNamespace(), {'functions': []}, frozenset(), None, (), None), None)
        (self.folder / 'physical-frame-profile-matrix.json').write_text(json.dumps(report, indent=2) + '\n')


INSTALLED_CHILD = "\nimport importlib.abc,inspect,json,os,sys\nfrom pathlib import Path\nfrom hashlib import sha256\nsys.path.insert(0,sys.argv[1])\nclass NoTools(importlib.abc.MetaPathFinder):\n    def find_spec(self,fullname,path=None,target=None):\n        if fullname=='tools' or fullname.startswith('tools.'):\n            raise AssertionError('installed lowering imported authoring tools')\nsys.meta_path.insert(0,NoTools())\nroot=Path(sys.argv[1])\nexpected=json.loads(Path(sys.argv[3]).read_bytes())\nfor name,identity in expected['python'].items():\n    assert sha256((root/name).read_bytes()).hexdigest()==identity\nactual={p.relative_to(root).as_posix() for p in (root/'hepta').rglob('*.py') if '_data' not in p.parts}\nassert actual==set(expected['python'])\nfrom hepta.hia_json_preflight_native import _source_resource_path\nfor name,identity in expected['resources'].items():\n    path=_source_resource_path(name)\n    assert root in path.parents and sha256(path.read_bytes()).hexdigest()==identity\nfrom hepta import hia_program_native as backend\nfrom hepta.hia_program import verify_program\nfrom hepta.hia_core_emitter_selection import SELECTOR,installed_core_emitter,active_core_emitter\nfrom hepta.hia_core_emitter_native import EmitterFrame,SOURCE\nentries=[]\nreal=EmitterFrame._invoke\ndef entry(session,*args,**kwargs):\n    value=real(session,*args,**kwargs);entries.append(value);return value\nEmitterFrame._invoke=entry\ndef forbidden(*args,**kwargs):\n    raise AssertionError('retained Function control entered installed child')\nfor name,method in tuple(backend._Emitter.__dict__.items()):\n    if inspect.isfunction(method) and name!='__new__':\n        setattr(backend._Emitter,name,forbidden)\nos.environ[SELECTOR]=sys.argv[2]\nowner=installed_core_emitter(sys.argv[2],vars(backend))\nmachine=backend.emit_program_machine(verify_program(expected['document']))\nassert machine.object_bytes.startswith(b'\\x7fELF')\nassert entries and 0 in entries and 1 in entries and 4 in entries and 5 in entries\nraw=SOURCE.read_bytes()\nSOURCE.write_bytes(raw+b'\\n')\ntry:installed_core_emitter(sys.argv[2],vars(backend))\nexcept ValueError:pass\nelse:raise AssertionError('warm HIA source change was ignored')\nSOURCE.write_bytes(raw);SOURCE.unlink()\ntry:installed_core_emitter(sys.argv[2],vars(backend))\nexcept FileNotFoundError:pass\nelse:raise AssertionError('missing installed source fell back to checkout')\nSOURCE.write_bytes(raw)\nassert sys.flags.isolated and sys.flags.no_site and os.environ['PATH']==''\nprint(json.dumps({'status':'INSTALLED_CORE_EMITTER_PASS','images':1,\n 'source_sha256':owner.admitted_source_sha256,'image_sha256':owner.image_sha256,\n 'object_sha256':machine.sha256,'python_files':len(expected['python']),\n 'resource_files':len(expected['resources']),'actual_native_frames':len(entries),\n 'retained_lowering_forbidden':True,'authoring_forbidden':True,'isolated_without_site':True,'empty_PATH':True}))\n"

if __name__ == '__main__':
    unittest.main()
