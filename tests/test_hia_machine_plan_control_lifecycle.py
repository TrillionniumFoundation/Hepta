"""Authored successor controls; no execution or qualification is claimed."""
from contextlib import ExitStack
import ctypes
import dis
import gc
import json
import os
from pathlib import Path
import struct
import sys
import unittest
import weakref
from unittest.mock import patch

from hepta import hia_machine_plan as plans
from hepta import hia_machine_plan_control_native as bridge
from hepta.hia_program import VerifiedProgram, verify_program
from tests.test_hia_program_native import minimal_document
from tests import test_hia_machine_plan_control_native as native_fixture
from tests.test_hia_machine_plan_control_native import EVIDENCE


class MachinePlanControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        selected = os.environ.get(EVIDENCE)
        with patch.dict(os.environ, {EVIDENCE: str(Path(selected) / 'control')}
                        if selected else {}):
            native_fixture.MachinePlanNativeTests.setUpClass.__func__(cls)

    def new_owner(self):
        manifest = json.loads(self.manifest.read_bytes())
        image = (self.manifest.parent / manifest['image_path']).read_bytes()
        return bridge.NativeMachinePlanControl(image, manifest['image_sha256'])

    def test_identifier_literals_preserve_original_python_key_identity(self):
        def run(call):
            events = []
            class Plan:
                def __getitem__(self, key):
                    canonical = {'schema': 'schema', 'scratch_registers': 'scratch_registers',
                                 'instruction_selection': 'instruction_selection'}[key]
                    events.append((key, key is canonical))
                    return {'schema': plans.MACHINE_V2, 'scratch_registers': {},
                            'instruction_selection': {'move_immediate': 'movabs',
                                                      'alu_immediate': 'imm32'}}[key]
            result = call(Plan())
            return result, events
        expected = run(plans._reference_code_options)
        self.assertTrue(all(same for name, same in expected[1]))
        self.assertEqual(run(self.native.code_options), expected)

    def test_partial_constructor_releases_only_its_real_owned_arenas(self):
        original = bridge._private_zeroed_buffer
        saved, calls = [], []
        failure = MemoryError('controlled second private arena allocation')
        def allocate(size):
            calls.append(size)
            if len(calls) == 2:
                raise failure
            value = original(size)
            saved.append(weakref.ref(value))
            return value
        held = None
        with patch.object(bridge, '_private_zeroed_buffer', side_effect=allocate):
            try:
                bridge.PlanFrame(self.native, 3, (None,))
            except MemoryError as error:
                held = error
        self.assertIs(held, failure)
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(saved), 1)
        # Keep the exact error and original traceback throughout this check.
        self.assertIsNone(saved[0]())

    def test_wrong_handled_exception_delivery_cannot_execute_the_claimed_effect(self):
        owner = self.new_owner()
        checked = verify_program(minimal_document())
        plan = {}; plan['cycle'] = plan
        frame = bridge.PlanFrame(owner, 1, (checked, plan))
        while frame.step() == 1:
            if frame.handled is not None:
                break
            frame.service(frame.pending)
        self.assertIsNotNone(frame.handled)
        self.assertIsNotNone(frame.pending)
        owner._delivery.close()
        calls = []
        original = frame._effect
        def effect():
            calls.append(True)
            return original()
        frame._effect = effect
        with self.assertRaises(RuntimeError):
            frame.service(frame.pending)
        self.assertEqual(calls, [])
        self.assertTrue(frame.closed)
        self.assertTrue(frame._uncertain)
        with self.assertRaises(RuntimeError):
            frame.step()

    def test_exact_issued_identity_and_native_claim_prevent_duplicate_effects(self):
        frame = bridge.PlanFrame(self.native, 3, (None,))
        self.assertEqual(frame.step(), 1)
        issued = frame.pending
        count = self.native.entries
        with self.assertRaises(RuntimeError):
            frame.service(bridge.Issued(issued.raw))
        self.assertEqual(self.native.entries, count)
        frame.service(issued)
        count = self.native.entries
        with self.assertRaises(RuntimeError):
            frame.service(issued)
        self.assertEqual(self.native.entries, count)
        status = frame.step()
        while status == 1:
            frame.service(frame.pending)
            status = frame.step()
        self.assertEqual(status, 0)
        self.assertEqual(frame.take(), {})
        with self.assertRaises(RuntimeError):
            frame.take()
        frame.close()
        self.assertTrue(frame._retired)

    def test_actual_reply_store_interruption_cannot_replay_the_callback(self):
        frame = bridge.PlanFrame(self.native, 3, (None,))
        self.assertEqual(frame.step(), 1)
        issued = frame.pending
        calls = []
        original = frame._effect
        def effect():
            calls.append(True)
            return original()
        frame._effect = effect
        offsets = {instruction.offset for instruction in dis.get_instructions(bridge.PlanFrame.service)
                   if instruction.opname == 'STORE_ATTR' and instruction.argval == 'reply'}
        self.assertTrue(offsets)
        failure = KeyboardInterrupt('controlled loss after the actual primitive result')
        fired = []
        def trace(current, event, arg):
            if current.f_code is bridge.PlanFrame.service.__code__:
                current.f_trace_opcodes = True
                if event == 'opcode' and current.f_lasti in offsets and calls and not fired:
                    fired.append(True)
                    raise failure
            return trace
        previous = sys.gettrace()
        arming_frame = sys._getframe()
        previous_opcodes = arming_frame.f_trace_opcodes
        observed = None
        try:
            # CPython 3.12 must enable the opcode event at tracing admission;
            # setting it only in the later target-frame callback is too late.
            arming_frame.f_trace_opcodes = True
            sys.settrace(trace)
            frame.service(issued)
        except KeyboardInterrupt as error:
            observed = error
        finally:
            sys.settrace(previous)
            arming_frame.f_trace_opcodes = previous_opcodes
        self.assertIs(observed, failure)
        self.assertEqual(calls, [True])
        self.assertEqual(fired, [True])
        self.assertTrue(frame.closed)
        self.assertTrue(frame._uncertain)
        for replay in (lambda: frame.service(issued), frame.step, frame.take):
            with self.assertRaises(RuntimeError):
                replay()
        self.assertEqual(calls, [True])
        frame.close()
        self.assertIs(bridge._UNCONFIRMED_RETIREMENTS[frame.nonce], frame)


    def test_generator_and_operand_lifetimes_match_with_held_original_errors(self):
        from tests.test_hia_program_native import minimal_document

        def observe(case, selected, outer):
            events, refs = [], []
            checked = verify_program(minimal_document())
            def mark(label):
                active = sys.exception()
                events.append((label, None if active is None else type(active).__name__))
            class Parameter:
                def __getitem__(self, key):
                    mark('parameter-read')
                    if case == 'generator-error':
                        raise TypeError('actual generator parameter refusal')
                    return 'unit'
                def __del__(self):
                    mark('parameter-del')
            class Iterator:
                def __init__(self): self.done = False
                def __iter__(self): return self
                def __next__(self):
                    if self.done: raise StopIteration
                    self.done = True
                    value = Parameter()
                    refs.append(weakref.ref(value))
                    return value
                def __del__(self): mark('iterator-del')
            class Parameters:
                def __iter__(self):
                    mark('parameters-iter')
                    value = Iterator()
                    refs.append(weakref.ref(value))
                    return value
            class Checked(VerifiedProgram):
                def as_dict(self):
                    document = super().as_dict()
                    document['functions'][0]['params'] = Parameters()
                    return document
            class Value:
                def __del__(self): mark('value-del')
            class Mapping(dict):
                def __del__(self): mark('mapping-del')
            class Choices:
                def __getitem__(self, key):
                    mark('choices-' + key)
                    if key == 'move_immediate': return Value()
                    raise KeyError('actual second choice refusal')
                def __del__(self): mark('choices-del')
            class Plan:
                def __getitem__(self, key):
                    mark('plan-' + key)
                    if key == 'schema': return plans.MACHINE_V2
                    if key == 'scratch_registers': return Mapping(r10='r10', r11='r11')
                    return Choices()
            held = None
            result = None
            def invoke():
                if case == 'code-options-error':
                    return (self.native.code_options if selected else
                            plans._reference_code_options)(Plan())
                return (self.native.witness if selected else
                        plans._reference_register_assignment_witness)(
                            Checked(checked.canonical_bytes), {'answer': {'x': 'r8'}},
                            allow_leaf_registers=True)
            def capture():
                nonlocal held, result
                try:
                    result = ('value', invoke())
                except BaseException as error:
                    held = error
                    result = ('error', type(error).__name__, str(error),
                              type(error.__cause__).__name__ if error.__cause__ else None)
            enabled = gc.isenabled()
            gc.disable()
            try:
                if outer:
                    try: raise LookupError('actual outer handled exception')
                    except LookupError: capture()
                else:
                    capture()
                before_release = list(events)
                live_with_traceback = [ref() is not None for ref in refs]
                # Keep the actual raised object while only its traceback is
                # detached. No GC or replacement exception is used.
                if held is not None: held.__traceback__ = None
                after_release = list(events)
                live_after_release = [ref() is not None for ref in refs]
                return {'result': result, 'with_traceback': before_release,
                        'live_with_traceback': live_with_traceback,
                        'after_traceback_release': after_release,
                        'live_after_release': live_after_release}
            finally:
                held = None
                if enabled: gc.enable()
        rows = []
        for case in ('code-options-error', 'generator-short', 'generator-error'):
            for outer in (False, True):
                expected = observe(case, False, outer)
                actual = observe(case, True, outer)
                rows.append({'case': case, 'outer': outer,
                             'expected': expected, 'actual': actual})
        (self.folder / 'actual-lifetime-traces.json').write_text(json.dumps(rows, indent=2))
        for row in rows:
            with self.subTest(case=row['case'], outer=row['outer']):
                self.assertEqual(row['actual'], row['expected'])

    def test_complete_native_frames_and_canaries_equal_independent_Core_VM(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_machine_plan_control_selection import SOURCE
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        from collections import Counter
        from hashlib import sha256
        program = assemble_program(SOURCE.read_bytes())
        function = program.as_dict()['functions'][0]
        owner = self.new_owner()
        native_entry = owner._entry
        frames = []
        def guarded(value):
            return ctypes.create_string_buffer(b'Z' * 16 + value + b'Y' * 16,
                                               len(value) + 32)
        def entry(source, source_size, output, output_size, workspace, workspace_size):
            before = [ctypes.string_at(ptr, size) for ptr, size in
                      ((source, source_size), (output, output_size),
                       (workspace, workspace_size))]
            guards = [guarded(value) for value in before]
            actual = native_entry(ctypes.addressof(guards[0]) + 16, source_size,
                                  ctypes.addressof(guards[1]) + 16, output_size,
                                  ctypes.addressof(guards[2]) + 16, workspace_size)
            memory = [_Owner(-1-i, bytearray(value)) for i, value in enumerate(before)]
            vm = _Machine(program, 12_000_000, 64 << 20, None, 128)
            expected = vm.invoke(function, [_View(memory[0], False),
                _View(memory[1], True), _View(memory[2], True)])[0]
            self.assertEqual(actual, expected)
            self.assertEqual(bytes(memory[0].data), before[0])
            for guard, value in zip(guards, memory):
                self.assertEqual(guard.raw[:16], b'Z' * 16)
                self.assertEqual(guard.raw[-16:], b'Y' * 16)
                self.assertEqual(guard.raw[16:-16], bytes(value.data))
            self.assertEqual(guards[0].raw[16:-16], before[0])
            ctypes.memmove(output, guards[1].raw[16:-16], output_size)
            ctypes.memmove(workspace, guards[2].raw[16:-16], workspace_size)
            frames.append({'source_bytes': source_size, 'output_bytes': output_size,
                           'workspace_bytes': workspace_size, 'return': actual,
                           'output_sha256': sha256(guards[1].raw[16:-16]).hexdigest(),
                           'workspace_sha256': sha256(guards[2].raw[16:-16]).hexdigest(),
                           'command': struct.unpack_from('<Q', before[2])[0]})
            return actual
        owner._entry = entry
        owner._initialize_control()  # Independent VM also checks both emissions.
        self.assertEqual(owner.code_options(None), {})
        self.assertEqual(owner.code_options({'schema': plans.LAYOUT_V1}), {})
        self.assertEqual(owner.preservation_checks({'schema': plans.LAYOUT_V1}),
                         plans._reference_preservation_checks({'schema': plans.LAYOUT_V1}))
        checked = verify_program(minimal_document())
        with self.assertRaises(plans.MachinePlanRejected):
            owner.validate(checked, {})
        counts = Counter(row['command'] for row in frames)
        self.assertGreater(counts[2], 0)
        self.assertGreater(counts[4], 0)
        self.assertIn(3, [row['return'] for row in frames])
        (self.folder / 'all-frame-VM-native.json').write_text(json.dumps(frames, indent=2))

    def test_original_peer_failures_keep_complete_foreign_observation_tapes(self):
        from tests.test_hia_machine_plan import explicit_plan
        from hashlib import sha256
        checked = verify_program(minimal_document())
        def run(kind, selected):
            events, changes = [], []
            if kind == 'ordinary':
                value = checked
            elif kind == 'hash-subclass':
                class Identity(str):
                    def __eq__(self, other):
                        events.append(['identity-equal', str(other)])
                        return str.__eq__(self, other)
                    __hash__ = str.__hash__
                class WithIdentity(VerifiedProgram):
                    @property
                    def sha256(self):
                        events.append(['sha256-get'])
                        return Identity(super().sha256)
                value = WithIdentity(checked.canonical_bytes)
            else:
                class TemporaryRoot(dict):
                    def __del__(self):
                        events.append(['root-del'])
                        for function in self['functions']:
                            for parameter in function['params']:
                                if parameter['type'] == 'u64': parameter['type'] = 'u32'
                            function['returns'][:] = ['u32' if t == 'u64' else t
                                                      for t in function['returns']]
                            for block in function['blocks']:
                                for parameter in block['params']:
                                    if parameter['type'] == 'u64': parameter['type'] = 'u32'
                                for operation in block['ops']:
                                    for output in operation['out']:
                                        if output['type'] == 'u64': output['type'] = 'u32'
                        changes.append(dict(self))
                class WithRoot(VerifiedProgram):
                    def as_dict(self):
                        events.append(['as_dict'])
                        return TemporaryRoot(super().as_dict())
                value = WithRoot(checked.canonical_bytes)
            try:
                if kind == 'hash-subclass':
                    result = (self.native.validate if selected else
                              plans._reference_validate_plan)(value, explicit_plan(checked))
                else:
                    result = (self.native.witness if selected else
                              plans._reference_register_assignment_witness)(
                                  value, {'answer': {'x': 'r12'}})
                result = {'value': result}
            except BaseException as error:
                result = {'exception': type(error).__name__, 'message': str(error),
                          'cause_type': type(error.__cause__).__name__ if error.__cause__ else None,
                          'context_type': type(error.__context__).__name__ if error.__context__ else None,
                          'suppress_context': error.__suppress_context__}
            return {'result': result, 'events': events,
                    'post_release_Core_reverified': [verify_program(item).sha256 for item in changes]}
        rows = []
        for kind in ('ordinary', 'hash-subclass', 'asdict-root-retirement'):
            expected = run(kind, False)
            start = self.native.entries
            actual = run(kind, True)
            rows.append({'kind': kind, 'expected': expected, 'actual': actual,
                         'native_entries': self.native.entries - start})
        (self.folder / 'three-original-peer-witnesses.json').write_text(json.dumps(rows, indent=2))
        for row in rows:
            with self.subTest(kind=row['kind']):
                self.assertEqual(row['actual'], row['expected'])
                self.assertGreater(row['native_entries'], 0)

    def test_closed_session_nonce_and_pending_retirement_do_not_authorize_an_effect(self):
        owner = self.new_owner()
        first = bridge.PlanFrame(owner, 3, (None,))
        first.step()
        old = first.pending
        first.service(old)
        status = first.step()
        while status == 1:
            first.service(first.pending)
            status = first.step()
        first.take()
        first.close()
        next_frame = bridge.PlanFrame(owner, 3, (None,))
        next_frame.step()
        self.assertNotEqual(first.nonce, next_frame.nonce)
        entries = owner.entries
        with self.assertRaises(RuntimeError): next_frame.service(old)
        self.assertEqual(owner.entries, entries)
        # Exercise the actual HIA claim and retirement guards on independent
        # copies of the real pending state; do not rewind the active owner.
        original = bytes(next_frame.state)
        output = ctypes.create_string_buffer(2048)
        for command, nonce in ((2, first.nonce), (4, next_frame.nonce)):
            state = ctypes.create_string_buffer(original, len(original))
            operation = struct.unpack_from('<Q', next_frame.pending.raw, 32)[0]
            sequence = struct.unpack_from('<Q', original, 144)[0]
            struct.pack_into('<5Q', state, 0, command, nonce, sequence,
                             operation if command == 2 else 0, 0)
            result = owner._entry(owner._table_buffer, len(owner.table), output,
                                  len(output), state, len(state))
            self.assertEqual(result, 0xfffffffd)
            self.assertEqual(bytes(state)[128:], original[128:])
        self.assertEqual(bytes(next_frame.state), original)
        next_frame.service(next_frame.pending)
        status = next_frame.step()
        while status == 1:
            next_frame.service(next_frame.pending)
            status = next_frame.step()
        self.assertEqual(next_frame.take(), {})
        next_frame.close()


    def test_three_physical_profiles_and_empty_slot_retirement_match_complete_VM(self):
        from hepta.hia_machine_plan_control_selection import SOURCE
        from tests.hia_machine_frame_profile_controls import profile_matrix
        plan = {'schema': plans.LAYOUT_V1}
        report = profile_matrix(self, self.new_owner(), bridge.PlanFrame,
                                SOURCE, 4, (plan, None), plans._reference_preservation_checks(plan))
        (self.folder / 'physical-frame-profile-matrix.json').write_text(json.dumps(report, indent=2) + '\n')

    def test_public_and_direct_facades_transfer_original_parameter_lifetimes(self):
        rows = _plan_facade_observations(self.native, self.manifest)
        (self.folder / 'facade-parameter-lifetime-traces.json').write_text(json.dumps(rows, indent=2) + '\n')
        self.assertEqual(len(rows), 12)
        for row in rows:
            with self.subTest(route=row['route'], fail=row['fail'], outer=row['outer']):
                self.assertEqual(row['actual'], row['reference'])
                if row['route'] == 'default-public':
                    self.assertEqual(row['actual_native_entries'], 0)
                else:
                    self.assertGreater(row['actual_native_entries'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)


def _plan_facade_observations(owner,manifest):
    base = verify_program(minimal_document())
    MANIFEST = manifest
    from hepta.hia_machine_plan_control_selection import SELECTOR
    def observe(route,fail,outer):
     events=[];refs=[];held=None;outcome=None
     def mark(name):
      handled=sys.exception();events.append([name,None if handled is None else type(handled).__name__])
     class Function(dict):
      def __del__(self):mark('function-del')
     class Checked(VerifiedProgram):
      def as_dict(self):
       mark('as_dict');doc=super().as_dict()
       for index,fn in enumerate(doc['functions']):
        value=Function(fn);refs.append(weakref.ref(value));doc['functions'][index]=value
       return doc
      def __del__(self):mark('checked-del')
     def invoke():
      if route=='reference':return plans._reference_register_assignment_witness(Checked(base.canonical_bytes), {'missing':{}} if fail else {})
      if route=='native-direct':return owner.witness(Checked(base.canonical_bytes), {'missing':{}} if fail else {})
      with patch.dict(os.environ,{SELECTOR:str(MANIFEST) if route=='native-public' else ''}):
       return plans.register_assignment_witness(Checked(base.canonical_bytes), {'missing':{}} if fail else {})
     def capture():
      nonlocal held,outcome
      try:outcome=['value',invoke()]
      except BaseException as error:held=error;outcome=['error',type(error).__name__,str(error)]
     previous=gc.isenabled();gc.disable()
     try:
      if outer:
       try:raise LookupError('actual outer handled')
       except LookupError:capture()
      else:capture()
      before=list(events);live=[r() is not None for r in refs]
      if held is not None:held.__traceback__=None
      return {'outcome':outcome,'with_error':before,'live_with_error':live,'after_detach':list(events),'live_after_detach':[r() is not None for r in refs]}
     finally:
      held=None
      if previous:gc.enable()
    rows=[]
    for fail in (False,True):
     for outer in (False,True):
      expected=observe('reference',fail,outer)
      for route in ('native-direct','native-public','default-public'):
       entries=owner.entries;actual=observe(route,fail,outer)
       rows.append({'route':route,'fail':fail,'outer':outer,'reference':expected,'actual':actual,'equal':expected==actual,'actual_native_entries':owner.entries-entries})
    return rows
