"""Actual-image controls for complete Code composition and private custody.

The immutable whole Code fixture supplies the independent Python reference.
Native controls require an explicit development bundle or matching cold report;
they never treat the reference implementation as a selected-path fallback.
"""
from __future__ import annotations

import dis
from contextlib import ExitStack
from functools import lru_cache
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import struct
import sys
import types
import unittest
import weakref
from unittest.mock import patch

from hepta import hia_machine_x64 as reference
from hepta import hia_machine_encoding_native as byte_bridge
from hepta import hia_machine_state_native as state_bridge
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tests import test_hia_machine_instructions_native as instruction_tests

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/hia_machine_x64_e09.py.txt'
FIXTURE_SHA256 = '8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9'
EVIDENCE = 'HEPTA_HIA_MACHINE_CODE_COMPOSITION_EVIDENCE'

@lru_cache(maxsize=1)
def oracle():
    raw = FIXTURE.read_bytes()
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise AssertionError('immutable complete Code reference differs')
    module = types.ModuleType('hia_complete_code_original')
    exec(compile(raw, str(FIXTURE), 'exec'), module.__dict__)
    return module

def lifetime_observation(factory, case):
    events = []
    code = factory()
    failure = None
    try:
        if case == "emit-data-temporary":
            class Destination:
                def __init__(self, name):
                    self.name, self.buffer = name, bytearray()
                def extend(self, value):
                    events.append(["extend", self.name, bytes(value).hex()])
                    self.buffer.extend(value)
            class Before:
                def __len__(self):
                    events.append(["old-data-length"])
                    code.data = Destination("after-len")
                    return 0
                def __del__(self):
                    events.append(["old-data-del"])
                    code.data = Destination("after-del")
            code.data = Before()
            code.emit(b"X")
            state = {"data": code.data.buffer.hex(), "destination": code.data.name}
        elif case == "labels-membership-temporary":
            class Labels:
                def __contains__(self, name):
                    events.append(["contains", name])
                    code.labels = {"target": 8}
                    return True
                def __del__(self):
                    events.append(["labels-del"])
                    code.labels = {"target": 12}
            code.data = bytearray(4)
            code.fixups = [(0, "target")]
            code.labels = Labels()
            raw, rows = code.finalize()
            state = {"bytes": raw.hex(), "labels": dict(code.labels), "relocations": rows}
        elif case == "ignored-emit-result-and-reentry":
            saved_emit = code.emit
            count = [0]
            class Returned:
                def __init__(self, number):
                    self.number = number
                def __del__(self):
                    events.append(["returned-del", self.number, len(code.data)])
                    code.label("L" + str(self.number))
            def emit(raw):
                saved_emit(raw)
                count[0] += 1
                events.append(["emit-return", count[0], bytes(raw).hex()])
                return Returned(count[0])
            code.emit = emit
            code.jmp("destination")
            state = {"data": code.data.hex(), "labels": dict(code.labels),
                     "fixups": list(code.fixups)}
        elif case == "move-option-temporary":
            ready = [False]
            class Truth:
                def __bool__(self):
                    events.append(["truth", ready[0]])
                    return ready[0]
            class Option:
                def __eq__(self, other):
                    events.append(["option-equality", other])
                    code.move_immediate = "movabs"
                    return Truth()
                def __del__(self):
                    events.append(["option-del"])
                    ready[0] = True
            code.move_immediate = Option()
            code.mov_imm("r10", 1)
            state = {"data": code.data.hex(), "ready": ready[0]}
        elif case == "register-mapping-temporary":
            ready = [False]
            class Get:
                def __call__(self, key, default):
                    events.append(["get", key, default, ready[0]])
                    return "r11" if ready[0] else "r10"
            class Mapping:
                @property
                def get(self):
                    events.append(["bind-get"])
                    code.scratch_registers = {}
                    return Get()
                def __del__(self):
                    events.append(["mapping-del"])
                    ready[0] = True
            code.scratch_registers = Mapping()
            code.mov_imm("r10", 1)
            state = {"data": code.data.hex(), "ready": ready[0]}
        else:
            raise AssertionError("unknown case")
    except BaseException as exc:
        failure = {"type": type(exc).__name__, "message": str(exc)}
        state = {}
    return {"events": list(events), "state": state, "exception": failure}

def forbidden(*args, **kwargs):
    raise AssertionError("retained hosted Code policy was entered on the selected path")

def guarded_selection(reference, byte_bridge, selectors):
    stack = ExitStack()
    stack.enter_context(patch.dict(os.environ, selectors))
    for name, member in reference.Code.__dict__.items():
        if inspect.isfunction(member) and name != "__new__":
            stack.enter_context(patch.object(reference.Code, name, forbidden))
    stack.enter_context(patch.object(reference.Code, "offset", property(forbidden)))
    for name in ("_reg", "_condition", "_s32"):
        stack.enter_context(patch.object(reference, name, forbidden))
    for name, member in byte_bridge.NativeEncodedCode.__dict__.items():
        if inspect.isfunction(member) and name != "_bytes":
            stack.enter_context(patch.object(byte_bridge.NativeEncodedCode, name, forbidden))
    stack.enter_context(patch.object(byte_bridge, "_displacement", forbidden))
    return stack

def mutation_permission(state_bridge, native):
    receiver = types.SimpleNamespace(data=bytearray())
    session = state_bridge.MachineStateSession(native, receiver, 5)
    status = session.step()
    if status != 1:
        raise AssertionError("real native request was not issued")
    opcode, sequence = struct.unpack_from("<2Q", session.workspace, 8)
    before = bytes(session.workspace)
    receiver_handle = struct.unpack("<10Q", session.packet)[4]
    literal = b"violated"
    session.workspace[1024:1024 + len(literal)] = literal
    struct.pack_into("<Q", session.workspace, 8, 4)
    struct.pack_into("<4Q", session.workspace, 512,
                     receiver_handle, session.none, 1024, len(literal))
    error = None
    try:
        session.observe()
    except BaseException as exc:
        error = {"type": type(exc).__name__, "message": str(exc)}
    effect = hasattr(receiver, "violated")
    return {"scope": "PRIVATE_ISSUED_FRAME_TRANSPORT_DIAGNOSTIC_NOT_A_SANDBOX_CLAIM",
            "original_actual_request": {"opcode": opcode, "sequence": sequence},
            "native_entry_observed": True, "workspace_before_sha256": sha256(before).hexdigest(),
            "effect_occurred": effect, "error": error,
            "control_pass": not effect and error is not None,
            "finished": session.finished}

def acknowledgement_interruption(state_bridge, native):
    events = []
    class Data:
        def __len__(self):
            events.append(["length"])
            return 0
        def extend(self, value):
            events.append(["extend", bytes(value).hex()])
    receiver = types.SimpleNamespace(data=Data())
    session = state_bridge.MachineStateSession(native, receiver, 2, b"X")
    status = session.step()
    while status == 1:
        opcode, = struct.unpack_from("<Q", session.workspace, 8)
        handle, = struct.unpack_from("<Q", session.workspace, 512)
        if opcode == 2 and session.value(handle) is receiver.data:
            break
        session.observe()
        status = session.step()
    if status != 1:
        raise AssertionError("actual foreign length request not reached")
    offsets = {instruction.offset for instruction in dis.get_instructions(
        state_bridge.MachineStateSession.observe)
        if instruction.opname == "STORE_ATTR" and instruction.argval == "prepared"}
    if len(offsets) != 1:
        raise AssertionError("expected original exact prepared acknowledgement point")
    target, = offsets
    marker = KeyboardInterrupt("injected original ACK-store loss")
    seen = []
    def trace(frame, event, arg):
        if frame.f_code is state_bridge.MachineStateSession.observe.__code__:
            frame.f_trace_opcodes = True
            if event == "opcode" and frame.f_lasti == target:
                seen.append("actual-prepared-STORE_ATTR")
                raise marker
        return trace
    caught = None
    previous_trace = sys.gettrace()
    try:
        sys.settrace(trace)
        session.observe()
    except BaseException as exc:
        caught = exc
    finally:
        sys.settrace(previous_trace)
    after_failure = list(events)
    replay_error = None
    try:
        status = session.step(session.packet)
        while status == 1:
            session.observe()
            status = session.step()
    except BaseException as exc:
        replay_error = {"type": type(exc).__name__, "message": str(exc)}
    later_effects = events != after_failure
    return {"scope": "PRIVATE_CAPTURED_CONTEXT_AFTER_ACTUAL_ACK_STORE_INTERRUPTION",
            "injection_points": seen, "original_exception_identity_preserved": caught is marker,
            "events_when_original_exception_escaped": after_failure,
            "events_after_explicit_private_replay": list(events),
            "replay_error": replay_error, "later_effects": later_effects,
            "control_pass": caught is marker and bool(seen) and replay_error is not None and not later_effects,
            "finished": session.finished}

def alias_observation(factory,name):
    events=[];code=factory()
    if name=='equality-result-alias':
        class Option:
            def __eq__(self,other):
                events.append(['equality',other]);code.move_immediate='movabs';return self
            def __bool__(self):
                events.append(['truth']);return True
            def __del__(self):
                events.append(['del'])
        code.move_immediate=Option();code.mov_imm('r10',17)
        return {'events':events,'bytes':code.data.hex()}
    if name=='bound-callable-alias':
        class Mapping:
            @property
            def get(self):
                events.append(['getattr']);code.scratch_registers={};return self
            def __call__(self,key,default):
                events.append(['call',key,default]);return 'r11'
            def __del__(self):events.append(['del'])
        code.scratch_registers=Mapping();code.mov_imm('r10',17)
        return {'events':events,'bytes':code.data.hex()}
    if name=='ignored-return-alias':
        saved=code.emit
        class Emit:
            def __call__(self,value):
                saved(value);code.emit=saved;events.append(['call',value.hex()]);return self
            def __del__(self):
                events.append(['del',len(code.data)]);code.label('from-del')
        code.emit=Emit();code.jmp('target')
        return {'events':events,'bytes':code.data.hex(),'labels':code.labels}
    if name=='constant-byte-reference-reuse':
        rows=[]
        code.emit=rows.append
        result={}
        for name in ('cqo','ud2','ret','leave'):
            getattr(code,name)();getattr(code,name)()
            result[name]={'hex':rows[-1].hex(),'same_object':rows[-1] is rows[-2]}
        return result
    if name=='branch-call-constant-and-dynamic-identity':
        rows=[];code.emit=rows.append
        code.jmp('target');code.jcc('ne','target');code.call('external')
        zero=[value for value in rows if value==b'\0'*4]
        first=rows[2]
        code.jcc('ne','target')
        return {'zero_count':len(zero),'all_zero_shared':all(value is zero[0] for value in zero),
                'dynamic_prefix_equal':first==rows[-2],'dynamic_prefix_shared':first is rows[-2],
                'bytes':[value.hex() for value in rows]}
    raise AssertionError(name)

def binding_observation(factory):
    result=[]
    cases=[('constructor-positional',lambda:factory(1)),('constructor-keyword',lambda:factory(unknown=True)),
      ('mov_rr-missing',lambda:factory().mov_rr('rax')),('mov_rr-extra',lambda:factory().mov_rr('rax','rcx',0)),
      ('emit-missing',lambda:factory().emit()),('label-extra',lambda:factory().label('x','y')),
      ('finalize-extra',lambda:factory().finalize(0)),('alias-keyword',lambda:factory().shl('rax',count=1,extra=2))]
    for name,call in cases:
        try:call()
        except BaseException as exc:result.append({'case':name,'type':type(exc).__name__,'message':str(exc)})
        else:result.append({'case':name,'unexpected_success':True})
    return result

def error_release_observation(factory):
    code=factory();events=[];references=[]
    class Temporary(list):
        def __del__(self):
            current=sys.exception()
            events.append({'event':'temporary-del','handled_type':None if current is None else type(current).__name__,
                           'handled_message':None if current is None else str(current)})
    class Mapping:
        @property
        def get(self):
            code.scratch_registers={}
            value=Temporary()
            references.append(weakref.ref(value))
            return value.append
    code.scratch_registers=Mapping()
    retained=None
    try:
        code.mov_imm('rax',17)
    except BaseException as error:
        retained=error
    if retained is None:raise AssertionError('the original two-argument builtin call must refuse')
    result={'error':{'type':type(retained).__name__,'message':str(retained),
                    'cause':None if retained.__cause__ is None else type(retained.__cause__).__name__,
                    'context':None if retained.__context__ is None else type(retained.__context__).__name__},
            'while_error_retained':{'events':list(events),'alive':[r() is not None for r in references]}}
    retained=None
    result['after_error_released']={'events':list(events),'alive':[r() is not None for r in references]}
    return result


class MachineCodeCompositionSourceTests(unittest.TestCase):
    def test_complete_reference_fixture_is_immutable(self):
        self.assertEqual(sha256(FIXTURE.read_bytes()).hexdigest(), FIXTURE_SHA256)
        self.assertTrue(hasattr(oracle().Code, 'finalize'))

    def test_admitted_source_identity_is_read_only_and_cannot_be_rebound(self):
        image = object.__new__(NativeHiaJsonImage)
        image._admitted_source_sha256 = None
        digest = '1' * 64
        image._bind_manifest_source(digest)
        self.assertEqual(image.admitted_source_sha256, digest)
        image._bind_manifest_source(digest)
        with self.assertRaises(AttributeError):
            image.admitted_source_sha256 = '2' * 64
        with self.assertRaises((ValueError, RuntimeError)):
            image._bind_manifest_source('2' * 64)
        for invalid in (True, b'1' * 64, 'A' * 64, '1' * 63):
            with self.subTest(value=repr(invalid)):
                other = object.__new__(NativeHiaJsonImage)
                other._admitted_source_sha256 = None
                with self.assertRaises((TypeError, ValueError, RuntimeError)):
                    other._bind_manifest_source(invalid)


class MachineCodeCompositionNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse the original strict cold/development fixture, giving this
        # complete class its own output directory in full module discovery.
        evidence = os.environ.get(EVIDENCE)
        with patch.dict(os.environ):
            os.environ.pop(instruction_tests.EVIDENCE, None)
            if evidence:
                os.environ[instruction_tests.EVIDENCE] = evidence
            instruction_tests.MachineInstructionsNativeTests.setUpClass.__func__(cls)

    def selected(self):
        selectors = {
            instruction_tests.SELECTOR: str(self.manifest),
            instruction_tests.STATE_SELECTOR: str(self.state_manifest),
            instruction_tests.ENCODING_SELECTOR: str(self.encoding_manifest)}
        return guarded_selection(reference, byte_bridge, selectors)

    def save(self, name, rows):
        (self.folder / name).write_text(json.dumps(rows, indent=2, sort_keys=True) + '\n')

    def test_temporary_reference_release_and_reentry_match_complete_original(self):
        cases = ('emit-data-temporary', 'labels-membership-temporary',
                 'ignored-emit-result-and-reentry', 'move-option-temporary',
                 'register-mapping-temporary')
        rows = []
        for name in cases:
            with self.subTest(case=name):
                wanted = lifetime_observation(oracle().Code, name)
                with self.selected():
                    actual = lifetime_observation(reference.Code, name)
                rows.append({'case': name, 'expected': wanted, 'actual': actual})
                self.assertIsNone(wanted['exception'])
                self.assertEqual(actual, wanted)
        self.save('temporary-reference-lifetimes.json', rows)

    def test_aliases_preserve_separate_owning_operand_slots(self):
        rows = []
        for name in ('equality-result-alias', 'bound-callable-alias', 'ignored-return-alias'):
            with self.subTest(case=name):
                wanted = alias_observation(oracle().Code, name)
                with self.selected():
                    actual = alias_observation(reference.Code, name)
                rows.append({'case': name, 'expected': wanted, 'actual': actual})
                self.assertEqual(actual, wanted)
        self.save('owning-slot-aliases.json', rows)

    def test_constant_byte_identity_preserves_dynamic_byte_independence(self):
        rows = []
        for name in ('constant-byte-reference-reuse', 'branch-call-constant-and-dynamic-identity'):
            with self.subTest(case=name):
                wanted = alias_observation(oracle().Code, name)
                with self.selected():
                    actual = alias_observation(reference.Code, name)
                rows.append({'case': name, 'expected': wanted, 'actual': actual})
                self.assertEqual(actual, wanted)
        self.save('constant-and-dynamic-byte-identity.json', rows)

    def test_public_python_call_binding_errors_match_complete_original(self):
        wanted = binding_observation(oracle().Code)
        with self.selected():
            actual = binding_observation(reference.Code)
        self.save('public-call-binding.json', {'expected': wanted, 'actual': actual})
        self.assertEqual(len(wanted), 8)
        self.assertTrue(all(row['type'] == 'TypeError' for row in wanted))
        self.assertEqual(actual, wanted)

    def test_actual_issued_request_cannot_be_changed_into_another_effect(self):
        row = mutation_permission(state_bridge, self.state)
        self.save('issued-frame-mutation.json', row)
        self.assertTrue(row['native_entry_observed'])
        self.assertTrue(row['control_pass'], row)
        self.assertTrue(row['finished'])

    def test_actual_acknowledgement_store_interruption_cannot_resume_effects(self):
        outer = sys._getframe()
        previous = outer.f_trace_opcodes
        outer.f_trace_opcodes = True
        try:
            row = acknowledgement_interruption(state_bridge, self.state)
        finally:
            outer.f_trace_opcodes = previous
        self.save('acknowledgement-store-interruption.json', row)
        self.assertEqual(row['injection_points'], ['actual-prepared-STORE_ATTR'])
        self.assertTrue(row['control_pass'], row)
        self.assertTrue(row['finished'])

    def test_interrupted_context_pin_publication_restores_all_three_owners(self):
        variables = (reference._NATIVE_OWNER, reference._NATIVE_STATE_OWNER,
                     reference._NATIVE_INSTRUCTION_OWNER)
        before = tuple(variable.get() for variable in variables)
        function = reference.native_encoding_scope.__wrapped__
        instructions = list(dis.get_instructions(function))
        targets = []
        for n, instruction in enumerate(instructions):
            if instruction.opname in ('LOAD_ATTR', 'LOAD_METHOD') and instruction.argval == 'set':
                call = next(i for i in range(n + 1, len(instructions))
                            if instructions[i].opname == 'CALL')
                targets.append(instructions[call + 1].offset)
        targets = targets[:3]
        self.assertEqual(len(targets), 3)
        outer = sys._getframe()
        previous_opcodes, previous_trace = outer.f_trace_opcodes, sys.gettrace()
        outer.f_trace_opcodes = True
        rows = []
        try:
            with self.selected():
                for position, target in enumerate(targets):
                    marker = KeyboardInterrupt('native Code pin result interruption')
                    seen = []
                    def trace(frame, event, arg):
                        if frame.f_code is function.__code__:
                            frame.f_trace_opcodes = True
                            if event == 'opcode' and frame.f_lasti == target:
                                seen.append(target)
                                raise marker
                        return trace
                    caught = None
                    try:
                        sys.settrace(trace)
                        with reference.native_encoding_scope():
                            raise AssertionError('actual pin publication was not interrupted')
                    except BaseException as exc:
                        caught = exc
                    finally:
                        sys.settrace(previous_trace)
                    after = tuple(variable.get() for variable in variables)
                    row = {'position': position, 'target': target, 'seen': seen,
                           'same_exception': caught is marker,
                           'restored': [a is b for a, b in zip(before, after)]}
                    rows.append(row)
                    for variable, original in zip(variables, before):
                        variable.set(original)
                    self.assertEqual(seen, [target])
                    self.assertIs(caught, marker)
                    self.assertTrue(all(row['restored']), row)
        finally:
            sys.settrace(previous_trace)
            outer.f_trace_opcodes = previous_opcodes
            for variable, original in zip(variables, before):
                variable.set(original)
            self.save('pin-publication-interruption.json', rows)


    def test_error_operand_retirement_keeps_original_handled_exception(self):
        rows = []
        def compare(label):
            wanted = error_release_observation(oracle().Code)
            with self.selected():
                actual = error_release_observation(reference.Code)
            rows.append({'outer_handler': label, 'expected': wanted, 'actual': actual})
            self.assertEqual(actual, wanted)
        try:
            compare('none')
            try:
                raise LookupError('outer handler')
            except LookupError:
                compare('lookup-error')
        finally:
            self.save('error-operand-release-context.json', rows)

    def test_foreign_StopIteration_is_delivered_without_generator_conversion(self):
        def observe(factory):
            code = factory()
            original = StopIteration('foreign iteration stop')
            cause = ValueError('explicit cause')
            original.__cause__ = cause
            original.__suppress_context__ = True
            original.add_note('retained note')
            class Mapping:
                def get(self, key, default):
                    raise original
            code.scratch_registers = Mapping()
            held = None
            try:
                code.mov_imm('rax', 17)
            except BaseException as error:
                held = error
            self.assertIsNotNone(held)
            result = {'same_instance': held is original,
                      'type': type(held).__name__, 'args': held.args,
                      'same_cause': held.__cause__ is cause,
                      'context': None if held.__context__ is None else type(held.__context__).__name__,
                      'suppress_context': held.__suppress_context__,
                      'notes': list(held.__notes__)}
            held = None
            return result
        wanted = observe(oracle().Code)
        with self.selected():
            actual = observe(reference.Code)
        self.save('foreign-StopIteration-delivery.json', {'expected': wanted, 'actual': actual})
        self.assertTrue(wanted['same_instance'])
        self.assertEqual(wanted['type'], 'StopIteration')
        self.assertEqual(actual, wanted)



if __name__ == '__main__':
    unittest.main()
