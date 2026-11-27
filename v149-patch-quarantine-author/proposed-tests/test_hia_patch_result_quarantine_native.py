"""New actual-frame terminal custody controls; authored, never executed yet.

These require a newly generated compatibility file and newly built/admitted
Patch image. They do not replace or rewrite any original Source/Native test.
"""
from __future__ import annotations

import struct
import unittest

from tests import test_hia_patch_result_native as _retained


class PatchTerminalQuarantineNativeTests(unittest.TestCase):
    setUp = _retained.PatchResultNativeTests.setUp
    tearDown = _retained.PatchResultNativeTests.tearDown

    def assert_inert_unknown(self, frame):
        from hepta.hia_front_continuation import _UNCONFIRMED_RETIREMENTS
        self.assertIs(_UNCONFIRMED_RETIREMENTS.get(frame.nonce), frame)
        self.assertIs(frame.image, self.owner)
        self.assertTrue(frame.closed and frame._uncertain)
        self.assertFalse(frame._retired)
        before = self.journal.started
        for name, call in (('step', frame.step), ('drive', frame.drive),
                           ('take', frame.take),
                           ('service', lambda: frame.service(frame.pending))):
            with self.subTest(refused=name), self.assertRaises(RuntimeError):
                call()
            self.assertEqual(self.journal.started, before)

    def test_root_start_claim_ack_and_retire_loss_are_quarantined_at_finish(self):
        from hepta.hia_front_continuation import _UNCONFIRMED_RETIREMENTS
        original = _retained.DictionaryProgram([])
        for command in (0, 2, 1, 4):
            with self.subTest(lost_command=command):
                before_keys = set(_UNCONFIRMED_RETIREMENTS)
                frame = self.owner.prepare('_check_patch_interface',
                                            (original, original, 'preserve'))
                fault = _retained.LostPatchReturn('root terminal return lost: ' + str(command))
                lost = []
                actual_entry = self.journal.entry

                def lose(source, source_size, output, output_size, workspace, workspace_size):
                    sent, nonce = struct.unpack_from('<2Q', workspace)
                    result = actual_entry(source, source_size, output, output_size,
                                          workspace, workspace_size)
                    if nonce == frame.nonce and sent == command and not lost:
                        lost.append({'index': self.journal.rows[-1]['index'],
                                     'calls_at_loss': self.journal.started,
                                     'nonce': nonce, 'command': sent, 'actual_return': result})
                        raise fault
                    return result

                self.journal.tag = 'root-loss-' + str(command)
                self.owner._entry = lose
                caught = None
                try:
                    try:
                        self.owner.finish(frame)
                    except BaseException as error:
                        caught = error
                finally:
                    self.owner._entry = actual_entry
                self.assertIs(caught, fault)
                self.assertEqual(len(lost), 1)
                self.assertIsNotNone(fault.__traceback__)
                self.assertEqual(self.journal.started, lost[0]['calls_at_loss'])
                self.assertEqual(set(_UNCONFIRMED_RETIREMENTS) - before_keys, {frame.nonce})
                self.assert_inert_unknown(frame)
                self.observations.append({'case': self.journal.tag, 'loss': lost[0],
                                          'exception_is_original': caught is fault,
                                          'original_traceback_kept': fault.__traceback__ is not None,
                                          'immediate_unknown': True, 'extra_native_after_loss': 0,
                                          'all_frames_retired': False})
        independent = self.owner.prepare('_check_patch_interface',
                                          (original, original, 'preserve'))
        self.journal.tag = 'independent-normal-after-four-unknowns'
        before_calls = self.journal.started
        self.assertEqual(self.owner.finish(independent), [])
        self.assertGreater(self.journal.started, before_calls)
        self.assertTrue(independent._retired and not independent._uncertain)

    def test_lazy_child_loss_is_registered_before_outer_error_returns(self):
        from hepta.hia_front_continuation import _UNCONFIRMED_RETIREMENTS
        original = _retained.DictionaryProgram(_retained._functions(('left', 'right')))
        root = self.owner.prepare('_check_patch_interface', (original, original, 'preserve'))
        fault = _retained.LostPatchReturn('lazy child claim return lost')
        actual_entry = self.journal.entry
        before_keys = set(_UNCONFIRMED_RETIREMENTS)
        lost, calls = [], []

        def lose(source, source_size, output, output_size, workspace, workspace_size):
            command, nonce = struct.unpack_from('<2Q', workspace)
            result = actual_entry(source, source_size, output, output_size,
                                  workspace, workspace_size)
            calls.append((nonce, command, result, self.journal.rows[-1]['index']))
            if nonce != root.nonce and command == 2 and not lost:
                self.assertEqual(result, 4)
                lost.append({'nonce': nonce, 'call_position': len(calls) - 1,
                             'index': self.journal.rows[-1]['index'], 'actual_return': result})
                raise fault
            return result

        self.journal.tag = 'lazy-child-lost-claim'
        self.owner._entry = lose
        caught = None
        try:
            try:
                self.owner.finish(root)
            except BaseException as error:
                caught = error
        finally:
            self.owner._entry = actual_entry
        self.assertIs(caught, fault)
        self.assertEqual(len(lost), 1)
        nonce = lost[0]['nonce']
        self.assertEqual(set(_UNCONFIRMED_RETIREMENTS) - before_keys, {nonce})
        child = _UNCONFIRMED_RETIREMENTS[nonce]
        self.assertIsNot(child, root)
        self.assertFalse(root._uncertain)
        self.assertFalse(any(row[0] == nonce for row in calls[lost[0]['call_position'] + 1:]))
        self.assert_inert_unknown(child)
        self.assertIsNotNone(fault.__traceback__)
        self.observations.append({'case': self.journal.tag, 'root_nonce': root.nonce,
                                  'child_nonce': nonce, 'loss': lost[0], 'calls': calls,
                                  'exception_is_original': caught is fault,
                                  'parent_certain': not root._uncertain,
                                  'lost_child_reentered': False, 'all_frames_retired': False})

    def test_known_error_and_later_independent_success_keep_original_lifetime(self):
        from hepta.hia_front_continuation import _UNCONFIRMED_RETIREMENTS
        before_keys = set(_UNCONFIRMED_RETIREMENTS)
        fault = RuntimeError('known actual foreign provider failure')
        class BrokenProgram:
            def as_dict(self):
                raise fault
        broken = BrokenProgram()
        frame = self.owner.prepare('_check_patch_interface', (broken, broken, 'preserve'))
        self.journal.tag = 'known-foreign-error'
        caught = None
        try:
            self.owner.finish(frame)
        except BaseException as error:
            caught = error
        self.assertIs(caught, fault)
        self.assertTrue(frame.closed)
        self.assertFalse(frame._uncertain)
        self.assertEqual(set(_UNCONFIRMED_RETIREMENTS), before_keys)
        original = _retained.DictionaryProgram([])
        independent = self.owner.prepare('_check_patch_interface',
                                          (original, original, 'preserve'))
        before_calls = self.journal.started
        self.journal.tag = 'independent-normal-after-known-error'
        self.assertEqual(self.owner.finish(independent), [])
        self.assertGreater(self.journal.started, before_calls)
        self.assertTrue(independent.closed and independent._retired)
        self.assertFalse(independent._uncertain)
        self.assertEqual(set(_UNCONFIRMED_RETIREMENTS), before_keys)
        self.observations.append({'case': 'known-error-and-independent-success',
                                  'original_exception': caught is fault,
                                  'known_error_not_quarantined': True,
                                  'independent_frame_retired': independent._retired})
