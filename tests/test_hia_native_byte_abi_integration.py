"""Actual whole-emission Byte selection and subject-bound proof consumption.

These are component controls. Alternative executable bytes below are an
identity fault control, not independently qualified compiler output.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta import hia_checker_identity as identity
from hepta import hia_native_byte_abi as public
from hepta import hia_native_byte_abi_selection as selection
from hepta import hia_program_native as backend
from hepta.hia_agent_store import AgentRejected
from hepta.hia_native_byte_abi_native import SELECTOR
from hepta.hia_program import verify_program
from hepta.hia_proof_contract import proof_result
from tests import test_hia_native_byte_abi_native as component
from tests.test_hia_native_byte_abi import byte_program


def _comparable(image):
    return (image.object_bytes, image.text_bytes, image.exports,
            image.implementation_sha256, image.foreign_buffer_exports)


class NativeByteABIIntegrationTests(component._Fixture, unittest.TestCase):
    def setUp(self):
        self.checked = verify_program(byte_program())
        self.exports = (('copy_bytes', 4096),)
        self.owner = selection.installed_native_byte_abi(self.manifest)

    def _emit(self):
        return backend.emit_program_machine(self.checked,
                                            foreign_buffer_exports=self.exports)

    def _proof(self, image, observed):
        evidence = {'method': 'complete_native_rederivation',
                    'actual_sha256': image.sha256, 'bytes_equal': True,
                    'object_identity_equal': True,
                    'native_checker_selection': observed}
        subject = {'kind': 'native_artifact',
                   'candidate_core_sha256': self.checked.sha256,
                   'base_core_sha256': None,
                   'native_artifact': {'sha256': image.sha256}}
        def consume():
            return proof_result(claim='encoding_check', status='proved',
                domain='actual complete borrowed-byte object rederivation identity control',
                subject=subject, profile={}, installation={}, evidence=evidence)
        return consume

    def test_whole_emission_retains_one_owner_and_proof_during_selector_change(self):
        calls, observed = Counter(), []
        prepare = self.owner.prepare
        def counted(name, arguments, captures=(), *, witness=None):
            calls[name] += 1
            return prepare(name, arguments, captures, witness=witness)
        def forbidden(*args, **kwargs):
            raise AssertionError('retained Byte policy entered selected whole emission')
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), \
                patch.object(self.owner, 'prepare', counted), \
                patch.object(public, '_reference_normalize_exports', forbidden), \
                patch.object(public, '_reference_emit_wrapper', forbidden):
            first = self._emit()
            selected = identity.checker_native_selection()
            consume = self._proof(first, selected)
            accepted = consume()
            self.assertFalse(accepted['global_safety_proved'])
            self.assertFalse(accepted['execution_authority_granted'])
            render = backend._Emitter.render
            def change_and_render(emitter):
                active = selection.active_native_byte_abi()
                self.assertIs(active, self.owner)
                capture = selection.captured_checker_owner()
                self.assertTrue(capture[0])
                os.environ[SELECTOR] = '/missing/byte-owner-after-admission'
                self.assertEqual(identity.checker_native_selection(), selected)
                self.assertEqual(consume(), accepted)
                observed.append({'held_image_sha256': active.image_sha256,
                                 'captured_proof_unchanged': True})
                return render(emitter)
            with patch.object(backend._Emitter, 'render', change_and_render):
                second = self._emit()
            self.assertEqual(_comparable(first), _comparable(second))
            self.assertEqual(selection.captured_checker_owner(), (False, None))
            self.assertIsNone(selection.active_native_byte_abi())
            with self.assertRaises(FileNotFoundError): self._emit()
            with self.assertRaises(FileNotFoundError): identity.checker_native_selection()
        self.assertEqual(len(observed), 1)
        self.assertEqual(calls['normalize_exports'], 2)
        self.assertEqual(calls['emit_wrapper'], 2)
        self.assertGreater(calls['_normalize'], 0)
        self.assertGreater(calls['_prologue'], 0)
        (self.folder / 'whole-emission-held-owner.json').write_text(json.dumps(
            {'observations': observed, 'actual_mode_counts': dict(calls),
             'fresh_bad_selection_refused': True}, indent=2) + '\n')

    def test_explicit_absence_and_original_target_check_precede_new_admission(self):
        with patch.dict(os.environ, {SELECTOR: ''}):
            reference = self._emit()
            with selection.native_byte_abi_scope():
                with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), \
                        patch.object(self.owner, 'prepare', side_effect=AssertionError('captured absence replaced')):
                    actual = self._emit()
                    self.assertEqual(_comparable(actual), _comparable(reference))
                    self.assertIsNone(identity.checker_native_selection()[SELECTOR])
                    self.assertEqual(selection.captured_checker_owner(), (True, None))
        with patch.dict(os.environ, {SELECTOR: '/missing/invalid-byte-selection'}), \
                patch.object(selection, '_admit', side_effect=AssertionError('target check moved after selection')):
            with self.assertRaisesRegex(backend.HIAProgramNativeRejected, 'E_HIA_PROGRAM_TARGET'):
                backend.emit_program_machine(self.checked, target='not-the-original-target')
        self.assertEqual(selection.captured_checker_owner(), (False, None))

    def test_actual_encoding_proof_refuses_a_different_fresh_Byte_image(self):
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            first = self._emit()
            selected = identity.checker_native_selection()
            consume = self._proof(first, selected)
            accepted = consume()
            self.assertEqual(selected[SELECTOR]['images']['image']['image_sha256'],
                             self.owner.image_sha256)
        folder = self.folder / 'alternative-identity-control'
        folder.mkdir()
        spec = json.loads(self.manifest.read_bytes())
        image_path = folder / spec['image_path']
        image_path.write_bytes((self.manifest.parent / spec['image_path']).read_bytes() + b'\x90')
        spec['image_sha256'] = sha256(image_path.read_bytes()).hexdigest()
        manifest = folder / 'manifest.json'
        manifest.write_text(json.dumps(spec, sort_keys=True) + '\n')
        with patch.dict(os.environ, {SELECTOR: str(manifest)}):
            other = selection.installed_native_byte_abi(manifest)
            before = other.entries
            actual = self._emit()
            self.assertGreater(other.entries, before)
            self.assertEqual(actual.object_bytes, first.object_bytes)
            self.assertEqual(actual.text_bytes, first.text_bytes)
            self.assertNotEqual(actual.implementation_sha256, first.implementation_sha256)
            self.assertNotEqual(identity.checker_native_selection(), selected)
            with self.assertRaisesRegex(AgentRejected, 'native checker selection differs'):
                consume()
        (self.folder / 'actual-encoding-proof-selection.json').write_text(json.dumps({
            'scope': 'ACTUAL_EMISSION_AND_PROOF_CONSUMPTION',
            'first_image_sha256': self.owner.image_sha256,
            'alternative_image_sha256': other.image_sha256,
            'alternative_actual_native_entries': other.entries - before,
            'alternative_is_identity_fault_control_not_qualified_output': True,
            'old_proof_refused': True,
            'proof_grants_execution_authority': accepted['execution_authority_granted'],
        }, indent=2) + '\n')

    def test_unknown_native_entry_unwinds_whole_emit_scope_without_replay(self):
        actual = self.owner._entry
        error = KeyboardInterrupt('after real Byte native entry before acknowledgement')
        returned = []
        def interrupted(*args):
            returned.append(actual(*args))
            raise error
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            before = identity.checker_native_selection()
            with patch.object(self.owner, '_entry', interrupted):
                with self.assertRaises(KeyboardInterrupt) as seen: self._emit()
            self.assertIs(seen.exception, error)
            self.assertEqual(len(returned), 1)
            self.assertEqual(selection.captured_checker_owner(), (False, None))
            self.assertIsNone(selection.active_native_byte_abi())
            self.assertEqual(identity.checker_native_selection(), before)
            # This is a new public invocation and frame, never a retry of the
            # interrupted frame's unknown native result or foreign effect.
            resumed = self._emit()
            self.assertEqual(resumed.exports, ('copy_bytes',))
        self.assertEqual(selection.captured_checker_owner(), (False, None))


if __name__ == '__main__': unittest.main()
