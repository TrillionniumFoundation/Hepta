"""Actual new-image patch policy controls; no mock owner or positive fallback.

The frozen runner configures explicit manifests and a new evidence directory.
Native frames are saved on both sides of every real mapped entry, including
the actual returned call underneath an injected lost-return fault.
"""
from __future__ import annotations

import builtins
from contextlib import ExitStack
import copy
import ctypes
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.hia_patch_result_support import (
    FrameJournal, context, exception_value, observed_admission, publish, require,
)


class LostPatchReturn(BaseException):
    pass


def _functions(names):
    return [{'name': name, 'params': [], 'returns': [], 'effects': [], 'return_loans': []}
            for name in names]


class DictionaryProgram:
    def __init__(self, functions):
        self.functions = functions

    def as_dict(self):
        return {'functions': self.functions}


class PatchResultNativeTests(unittest.TestCase):
    def setUp(self):
        from hepta import hia_program_tools as public
        from hepta.hia_patch_result_native import NativePatchResult, admit_patch_result
        cfg = context()
        self.directory = Path(cfg['evidence']).absolute() / self._testMethodName
        self.directory.mkdir(mode=0o700)
        self.admission = observed_admission(NativePatchResult, self.directory / 'admission',
                                             admit_patch_result, cfg['manifest'])
        self.owner = self.admission.owner
        self.public = public
        self.apply = self.owner._definitions['apply_program_patch'].function
        self.interface = self.owner._definitions['_check_patch_interface'].function
        self.journal = FrameJournal(self.owner, self.directory / 'machine')
        self.journal.tag = self._testMethodName
        self.observations = []

    def tearDown(self):
        try:
            self.journal.close()
        finally:
            publish(self.directory / 'OBSERVATIONS.json', self.observations)

    def actual_apply(self, document, request):
        before = self.journal.started
        try:
            return self.owner.invoke_bound_apply(self.apply, document, request)
        finally:
            self.assertGreater(self.journal.started, before, 'selected route did not enter the actual new HIA image')

    def actual_interface(self, original, verified, policy):
        before = self.journal.started
        try:
            return self.owner.invoke_bound_interface(self.interface, original, verified, policy)
        finally:
            self.assertGreater(self.journal.started, before, 'selected interface route did not enter HIA')

    def test_real_v1_v2_four_edit_kinds_and_unchanged_business_receipts(self):
        from tests.test_hia_core_patch_native import four_kinds
        program, requests = four_kinds()
        requests.append({**copy.deepcopy(requests[0]), 'schema': 'hepta.hia.patch.v2',
                         'interface_policy': 'preserve'})
        for index, request in enumerate(requests):
            with self.subTest(index=index):
                before = copy.deepcopy(program)
                expected, expected_receipt = self.apply(program, copy.deepcopy(request))
                self.journal.tag = 'real-patch-' + str(index)
                actual, receipt = self.actual_apply(program, copy.deepcopy(request))
                self.observations.append({'case': self.journal.tag, 'receipt': receipt,
                                          'expected_receipt': expected_receipt,
                                          'candidate_sha256': actual.sha256})
                self.assertEqual(actual.canonical_bytes, expected.canonical_bytes)
                self.assertEqual(receipt, expected_receipt)
                self.assertEqual(program, before)
                self.assertIs(receipt['claims']['native_executed'], False)
                self.assertIs(receipt['claims']['behavior_equivalence_proved'], False)
                self.assertEqual(receipt['status'], 'verified_unpublished')
                self.assertNotIn('publication', receipt)

    def test_imported_verifier_is_captured_once_and_prepare_observes_late_global(self):
        from hepta import hia_program
        results = []
        for selected in (False, True):
            events, document, request, candidate = [], object(), object(), object()
            class Verified(DictionaryProgram):
                def __init__(self, name):
                    super().__init__([])
                    self.name = name
                @property
                def sha256(self):
                    events.append(self.name + '.sha256')
                    return self.name + '-sha'
                @property
                def input_sha256(self):
                    events.append(self.name + '.input_sha256')
                    return self.name + '-input'
                def as_dict(self):
                    events.append(self.name + '.as_dict')
                    return super().as_dict()
            original, revised = Verified('original'), Verified('revised')
            def forbidden(value):
                raise AssertionError('second public verifier lookup was synthesized')
            def late_prepare(actual_original, actual_request):
                self.assertIs(actual_original, original)
                self.assertIs(actual_request, request)
                events.append('late-prepare')
                return candidate, self.public.PATCH_SCHEMA_V2, 'preserve', 7
            def first_prepare(*args):
                raise AssertionError('prepare was captured before verification')
            def verify(value):
                if value is document:
                    events.append('verify-original')
                    hia_program.verify_program = forbidden
                    self.public._prepare_program_patch = late_prepare
                    return original
                self.assertIs(value, candidate)
                events.append('verify-candidate-with-captured-provider')
                return revised
            with patch.object(hia_program, 'verify_program', verify), \
                    patch.object(self.public, '_prepare_program_patch', first_prepare):
                returned, receipt = (self.actual_apply if selected else self.apply)(document, request)
                self.assertIs(returned, revised)
            results.append((events, receipt))
        self.observations.append({'case': 'captured-verifier-late-prepare', 'old': results[0], 'new': results[1]})
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[1][0][:3],
                         ['verify-original', 'late-prepare', 'verify-candidate-with-captured-provider'])
        self.assertEqual(results[1][0][-4:],
                         ['original.sha256', 'revised.sha256', 'original.sha256', 'original.input_sha256'])

    def test_original_import_operands_and_import_failure_precede_all_business_calls(self):
        original_import = builtins.__import__
        results = []
        for selected in (False, True):
            events, fault = [], ImportError('actual patch import refusal')
            def importing(name, globals=None, locals=None, fromlist=(), level=0):
                if name == 'hia_program' and level == 1 and fromlist == ('verify_program',):
                    events.append((name, fromlist, level, globals is vars(self.public), locals is None))
                    raise fault
                return original_import(name, globals, locals, fromlist, level)
            with patch.dict(builtins.__dict__, {'__import__': importing}):
                with self.assertRaises(ImportError) as caught:
                    (self.actual_apply(object(), object())
                     if selected else self.apply(object(), object()))
            self.assertIs(caught.exception, fault)
            results.append((events, exception_value(caught.exception)))
        self.observations.append({'case': 'import-exception', 'old': results[0], 'new': results[1]})
        self.assertEqual(results[0], results[1])
        self.assertEqual(len(results[1][0]), 1)

    def test_interface_loans_sorted_union_and_first_eight_rejection_names(self):
        before = DictionaryProgram(_functions(['same', 'zeta'] + ['n%02d' % i for i in range(10)]))
        after_data = copy.deepcopy(before.functions)
        for fn in after_data:
            if fn['name'] != 'same':
                fn['return_loans'] = [None]
        after_data.append(_functions(['alpha'])[0])
        after = DictionaryProgram(after_data)
        expected = self.interface(before, after, 'migrate')
        actual = self.actual_interface(before, after, 'migrate')
        self.assertEqual(actual, expected)
        self.assertEqual(actual, sorted(['alpha', 'zeta'] + ['n%02d' % i for i in range(10)]))
        errors = []
        for selected in (False, True):
            try:
                (self.actual_interface if selected else self.interface)(before, after, 'preserve')
            except self.public.HIAEditRejected as error:
                errors.append(exception_value(error))
            else:
                self.fail('actual interface mutation was accepted without migrate')
        self.observations.append({'case': 'interface-union', 'changes': actual, 'errors': errors})
        self.assertEqual(errors[0], errors[1])
        self.assertTrue(errors[1]['text'].endswith(', '.join(expected[:8])))

    def test_captured_foreign_alias_and_changed_exact_function_are_called_once(self):
        events, marker, document, request = [], object(), object(), object()
        class Foreign:
            def __getattribute__(self, name):
                raise AssertionError('unrequested provider attribute: ' + name)
            def __call__(self, left, right):
                events.append((left is document, right is request))
                return marker
        count = self.journal.started
        self.assertIs(self.owner.invoke_bound_apply(Foreign(), document, request), marker)
        self.assertEqual(self.journal.started, count)
        self.assertEqual(events, [(True, True)])
        def replacement(document, request):
            return request
        code = self.apply.__code__
        try:
            self.apply.__code__ = replacement.__code__
            self.assertIs(self.owner.invoke_bound_apply(self.apply, document, request), request)
            self.assertEqual(self.journal.started, count)
        finally:
            self.apply.__code__ = code
        from tests.test_hia_program_tools import scalar_program, add_two_patch
        data = scalar_program()
        with patch.object(self.public, 'apply_program_patch', Foreign()):
            self.actual_apply(data, add_two_patch(data))
        self.assertEqual(events, [(True, True)])

    def test_receipt_keeps_eager_default_reads_and_schema_comparison_order(self):
        from hepta import hia_program
        results = []
        for selected in (False, True):
            events, document, request, candidate = [], object(), object(), object()
            class Schema:
                def __eq__(self, other):
                    events.append(('schema-eq', other))
                    return True
            class Verified(DictionaryProgram):
                def __init__(self, name):
                    super().__init__([])
                    self.name = name
                @property
                def sha256(self):
                    events.append(self.name + '.sha256')
                    return self.name
                @property
                def input_sha256(self):
                    events.append(self.name + '.input_sha256')
                    raise AttributeError('intentionally absent input digest')
            original, revised = Verified('original'), Verified('candidate')
            def verify(value):
                events.append('verify-original' if value is document else 'verify-candidate')
                return original if value is document else revised
            def prepare(value, actual_request):
                events.append('prepare')
                return candidate, Schema(), 'preserve', 0
            with patch.object(hia_program, 'verify_program', verify), \
                    patch.object(self.public, '_prepare_program_patch', prepare):
                returned, receipt = (self.actual_apply if selected else self.apply)(document, request)
            self.assertIs(returned, revised)
            self.assertEqual(receipt['original_input_sha256'], 'original')
            self.assertIs(receipt['claims']['native_executed'], False)
            self.assertIs(receipt['claims']['external_callers_revalidated'], False)
            results.append((events, receipt))
        self.observations.append({'case': 'receipt-order', 'old': results[0], 'new': results[1]})
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[1][0][-5:], ['original.sha256', 'candidate.sha256',
                         'original.sha256', 'original.input_sha256',
                         ('schema-eq', self.public.PATCH_SCHEMA_V2)])

    def test_four_item_unpack_preserves_iteration_exceptions_and_fifth_probe(self):
        from hepta import hia_program
        for extent in (0, 1, 3, 4, 5):
            results = []
            for selected in (False, True):
                events, candidate, document = [], object(), object()
                original, revised = DictionaryProgram([]), DictionaryProgram([])
                original.sha256 = 'old'; revised.sha256 = 'new'
                payload = [candidate, self.public.PATCH_SCHEMA, 'preserve', 0, object()][:extent]
                class Values:
                    def __iter__(self):
                        events.append('iter')
                        self.index = 0
                        return self
                    def __next__(self):
                        events.append(('next', self.index))
                        if self.index == len(payload):
                            raise StopIteration
                        value = payload[self.index]
                        self.index += 1
                        return value
                def verify(value):
                    events.append('verify-original' if value is document else 'verify-candidate')
                    return original if value is document else revised
                def prepare(*args):
                    events.append('prepare')
                    return Values()
                with patch.object(hia_program, 'verify_program', verify), \
                        patch.object(self.public, '_prepare_program_patch', prepare):
                    try:
                        result = ((self.actual_apply if selected else self.apply)(document, object()))
                    except BaseException as error:
                        result = {'exception': exception_value(error)}
                    else:
                        result = {'receipt': result[1], 'same_verified': result[0] is revised}
                results.append((events, result))
            self.observations.append({'case': 'unpack-' + str(extent), 'old': results[0], 'new': results[1]})
            with self.subTest(extent=extent):
                self.assertEqual(results[0], results[1])
                self.assertEqual(('exception' in results[1][1]), extent != 4)
                if extent == 4:
                    self.assertIn(('next', 4), results[1][0])

    def test_independently_admitted_signature_has_real_hia_positive_and_late_foreign(self):
        from hepta.hia_inspect_program_native import NativeInspectProgram, admit_inspect_program
        from hepta.hia_patch_result_native import NativePatchResult, admit_patch_result
        cfg = context()
        self.assertIn('inspect_manifest', cfg, 'positive dependency gate requires a real explicit Inspect artifact')
        inspect_admission = observed_admission(NativeInspectProgram,
            self.directory / 'signature-admission', admit_inspect_program, cfg['inspect_manifest'])
        inspect_owner = inspect_admission.owner
        inspect_journal = FrameJournal(inspect_owner, self.directory / 'signature-machine')
        inspect_journal.tag = 'independent-signature'
        # Real admission returns its actual cached mapping. Journal before
        # the patch admission takes that entry snapshot; never replace it later.
        combined = observed_admission(NativePatchResult, self.directory / 'combined-admission',
            admit_patch_result, cfg['manifest'], inspect_manifest=cfg['inspect_manifest'])
        combined_journal = FrameJournal(combined.owner, self.directory / 'combined-machine')
        combined_journal.tag = 'combined-signature'
        try:
            self.assertIs(combined.owner._signature.admission.owner, inspect_owner)
            self.assertIs(combined.owner._signature.entry, inspect_journal.entry)
            left, right = DictionaryProgram(_functions(['f'])), DictionaryProgram(_functions(['f', 'g']))
            expected = self.interface(left, right, 'migrate')
            result = combined.owner.invoke_bound_interface(self.interface, left, right, 'migrate')
            self.assertEqual(result, expected)
            self.assertGreater(combined_journal.started, 0)
            self.assertGreater(inspect_journal.started, 0)
            signature = inspect_owner._definitions['function_signature'][0]
            original_keywords = dict(signature.__kwdefaults__)
            before = inspect_journal.started
            try:
                signature.__kwdefaults__['include_return_loans'] = True
                result = combined.owner.invoke_bound_interface(self.interface, left, right, 'migrate')
                self.assertEqual(result, expected)
                self.assertEqual(inspect_journal.started, before)
            finally:
                signature.__kwdefaults__.clear(); signature.__kwdefaults__.update(original_keywords)
            events = []
            class Foreign:
                def __getattribute__(self, name):
                    raise AssertionError('foreign signature attribute probe: ' + name)
                def __call__(self, function, *, include_return_loans):
                    events.append((function['name'], include_return_loans))
                    return signature(function, include_return_loans=include_return_loans)
            with patch.object(self.public, 'function_signature', Foreign()):
                result = combined.owner.invoke_bound_interface(self.interface, left, right, 'migrate')
            self.assertEqual(result, expected)
            self.assertEqual(inspect_journal.started, before)
            self.assertEqual(events, [('f', True), ('f', True), ('g', True)])
            self.observations.append({'case': 'independent-signature', 'changes': result,
                                      'native_signature_calls': before, 'foreign_events': events,
                                      'same_actual_cached_owner': True})
        finally:
            combined_journal.close()
            inspect_journal.close()

    def test_same_frame_physical_reentry_refuses_before_changes_other_frame_can_run(self):
        from hepta.hia_front_runtime import FrontUnknown
        original = DictionaryProgram([])
        first = self.owner.prepare('_check_patch_interface', (original, original, 'preserve'))
        second = self.owner.prepare('_check_patch_interface', (original, original, 'preserve'))
        observed = []
        outer = self.journal.entry
        entered = False
        def callback(source, source_size, output, output_size, workspace, workspace_size):
            nonlocal entered
            if workspace is first.state and not entered:
                entered = True
                self.assertIs(first._machine_busy, True)
                for label, call in (('drive', first.drive), ('step', first.step),
                                    ('service', lambda: first.service(first.pending)),
                                    ('take', first.take), ('close', first.close),
                                    ('retire', first._retire), ('invoke', lambda: first._invoke(0))):
                    before = (bytes(first.state), bytes(first.output), self.owner.entries,
                              first.pending, first.closed, first._uncertain)
                    with self.assertRaises(FrontUnknown):
                        call()
                    self.assertEqual((bytes(first.state), bytes(first.output), self.owner.entries,
                                      first.pending, first.closed, first._uncertain), before)
                    observed.append(label)
                self.assertEqual(self.owner.finish(second), [])
                self.assertIs(first._machine_busy, True)
            return outer(source, source_size, output, output_size, workspace, workspace_size)
        self.owner._entry = callback
        try:
            self.assertEqual(self.owner.finish(first), [])
        finally:
            self.owner._entry = self.journal.entry
        self.assertEqual(observed, ['drive', 'step', 'service', 'take', 'close', 'retire', 'invoke'])
        self.assertTrue(first._retired and second._retired)
        self.observations.append({'case': 'physical-reentry', 'refused_routes': observed,
                                  'independent_frame_completed': second._retired})

    def test_real_pending_drive_claim_ack_and_terminal_permissions_are_single_use(self):
        original = DictionaryProgram([])
        frame = self.owner.prepare('_check_patch_interface', (original, original, 'preserve'))
        self.assertEqual(frame.step(), 1)
        issued = frame.pending
        before = (bytes(frame.state), bytes(frame.output), self.owner.entries)
        with self.assertRaises(RuntimeError):
            frame.step()
        self.assertEqual((bytes(frame.state), bytes(frame.output), self.owner.entries), before)
        self.assertFalse(frame._uncertain)
        self.assertEqual(frame.drive(), 0)
        self.assertEqual(frame.take(), [])
        with self.assertRaises(RuntimeError):
            frame.take()
        with self.assertRaises(RuntimeError):
            frame.service(issued)
        frame.close()
        self.assertTrue(frame._retired)
        self.observations.append({'case': 'pending-drive', 'retired': frame._retired})

    def test_real_lost_claim_return_is_quarantined_without_effect_or_replay(self):
        from hepta.hia_front_continuation import _UNCONFIRMED_RETIREMENTS
        original = DictionaryProgram([])
        frame = self.owner.prepare('_check_patch_interface', (original, original, 'preserve'))
        self.journal.tag = 'lost-claim'
        self.assertEqual(frame.step(), 1)
        fault, injected = LostPatchReturn('actual claim return lost'), []
        actual_entry = self.journal.entry
        def lose(source, source_size, output, output_size, workspace, workspace_size):
            command = struct.unpack_from('<Q', workspace)[0]
            result = actual_entry(source, source_size, output, output_size, workspace, workspace_size)
            if command == 2 and not injected:
                self.assertEqual(result, 4)
                injected.append(self.journal.rows[-1]['index'])
                raise fault
            return result
        self.owner._entry = lose
        try:
            with self.assertRaises(LostPatchReturn) as caught:
                frame.service(frame.pending)
            self.assertIs(caught.exception, fault)
        finally:
            self.owner._entry = self.journal.entry
        self.assertEqual(len(injected), 1)
        self.assertTrue(frame.closed and frame._uncertain and frame.executed and not frame.completed)
        before = self.journal.started
        for call in (frame.drive, frame.step, frame.take):
            with self.assertRaises(RuntimeError):
                call()
        frame._retire()
        self.assertEqual(self.journal.started, before)
        self.assertIs(_UNCONFIRMED_RETIREMENTS[frame.nonce], frame)
        self.observations.append({'case': 'lost-claim', 'frame_index': injected[0],
                                  'nonce': frame.nonce, 'quarantined_until_child_exit': True,
                                  'replayed': False})

    def test_real_impact_consumer_keeps_native_false_and_original_postconditions(self):
        from hepta import hia_patch_impact
        from tests.test_hia_patch_impact import move_program, patch_packet, patch_initial_byte
        original = move_program()
        packet = patch_packet(original, patch_initial_byte(original))
        expected = hia_patch_impact.analyze_patch_impact(original, packet)
        captured = hia_patch_impact.apply_program_patch
        count = self.journal.started
        def selected(document, request):
            return self.owner.invoke_bound_apply(captured,
                (document, (document := None))[0], (request, (request := None))[0])
        with patch.object(hia_patch_impact, 'apply_program_patch', selected):
            actual = hia_patch_impact.analyze_patch_impact(original, packet)
        self.assertGreater(self.journal.started, count)
        self.assertEqual(actual[0].canonical_bytes, expected[0].canonical_bytes)
        self.assertEqual(actual[1:], expected[1:])
        self.assertIs(actual[1]['claims']['native_executed'], False)
        self.assertIs(actual[2]['claims']['functional_equivalence_proved'], False)
        self.observations.append({'case': 'actual-impact-consumer',
                                  'receipt': actual[1], 'impact': actual[2],
                                  'default_alias_after_scope_is_original':
                                      hia_patch_impact.apply_program_patch is captured})


if __name__ == '__main__':
    unittest.main()
