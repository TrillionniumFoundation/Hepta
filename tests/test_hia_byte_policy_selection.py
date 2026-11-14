"""Selection and lifetime transport controls; no machine-code pass is inferred."""
import os
import unittest
import weakref
from unittest.mock import patch

from hepta import hia_native_byte_abi as api
from hepta import hia_byte_policy_selection as policy
from hepta import hia_byte_wrapper_selection as bundle
from hepta import hia_native_byte_abi_selection as control


class BytePolicySelectionTests(unittest.TestCase):
    def setUp(self):
        self.bundle_token = bundle._OWNER.set(bundle._UNSELECTED)
        self.control_token = control._OWNER.set(control._UNSELECTED)
        self.environment = patch.dict(os.environ, {
            bundle.SELECTOR: '', control.SELECTOR: ''})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        control._OWNER.reset(self.control_token)
        bundle._OWNER.reset(self.bundle_token)

    def test_unselected_route_does_not_admit_either_native_family(self):
        with patch.object(bundle, 'selected_byte_wrapper', side_effect=AssertionError('bundle admission')), \
             patch.object(control, 'selected_native_byte_abi', side_effect=AssertionError('control admission')):
            self.assertEqual(policy.selected_byte_policy({}), (None, None))

    def test_bundle_choice_never_probes_the_control_manifest(self):
        owner = object()
        with patch.dict(os.environ, {bundle.SELECTOR: '/bundle'}), \
             patch.object(bundle, 'selected_byte_wrapper', return_value=owner) as selected, \
             patch.object(control, 'selected_native_byte_abi', side_effect=AssertionError('control admission')):
            namespace = {}
            self.assertEqual(policy.selected_byte_policy(namespace), ('bundle', owner))
            selected.assert_called_once_with(namespace)

    def test_control_choice_never_probes_the_bundle_manifest(self):
        owner = object()
        with patch.dict(os.environ, {control.SELECTOR: '/control'}), \
             patch.object(bundle, 'selected_byte_wrapper', side_effect=AssertionError('bundle admission')), \
             patch.object(control, 'selected_native_byte_abi', return_value=owner) as selected:
            namespace = {}
            self.assertEqual(policy.selected_byte_policy(namespace), ('control', owner))
            selected.assert_called_once_with(namespace)

    def test_two_choices_refuse_before_either_manifest_or_image_is_admitted(self):
        with patch.dict(os.environ, {bundle.SELECTOR: '/bundle', control.SELECTOR: '/control'}), \
             patch.object(bundle, 'selected_byte_wrapper', side_effect=AssertionError('bundle admission')) as left, \
             patch.object(control, 'selected_native_byte_abi', side_effect=AssertionError('control admission')) as right:
            with self.assertRaisesRegex(ValueError, 'cannot both be selected'):
                policy.selected_byte_policy({})
            left.assert_not_called()
            right.assert_not_called()

    def test_selected_admission_failure_is_not_retried_or_replaced(self):
        failure = ValueError('original selected refusal')
        with patch.dict(os.environ, {control.SELECTOR: '/control'}), \
             patch.object(control, 'selected_native_byte_abi', side_effect=failure) as selected, \
             patch.object(bundle, 'selected_byte_wrapper', side_effect=AssertionError('fallback')):
            with self.assertRaises(ValueError) as caught:
                policy.selected_byte_policy({})
            self.assertIs(caught.exception, failure)
            self.assertEqual(selected.call_count, 1)

    def test_disappearing_choice_does_not_enter_the_reference_route(self):
        with patch.dict(os.environ, {control.SELECTOR: '/control'}), \
             patch.object(control, 'selected_native_byte_abi', return_value=None), \
             patch.object(api, '_reference_normalize_exports', side_effect=AssertionError('reference')):
            with self.assertRaisesRegex(ValueError, 'selection changed'):
                api.normalize_exports((), object())

    def test_captured_absence_masks_later_environment_selection(self):
        with policy.native_byte_policy_scope(vars(api)):
            with patch.dict(os.environ, {bundle.SELECTOR: '/bundle', control.SELECTOR: '/control'}):
                self.assertFalse(bundle.byte_wrapper_selection_requested())
                self.assertFalse(control.native_byte_abi_selection_requested())
                self.assertEqual(policy.selected_byte_policy(vars(api)), (None, None))
        with patch.dict(os.environ, {bundle.SELECTOR: '/bundle', control.SELECTOR: '/control'}):
            with self.assertRaisesRegex(ValueError, 'cannot both be selected'):
                policy.selected_byte_policy(vars(api))

    def test_control_entry_releases_public_argument_references_before_finish(self):
        events = []
        class Argument:
            def __del__(self):
                events.append('released')
        class Owner:
            def prepare(self, name, arguments):
                self_name = name
                return self_name, tuple(weakref.ref(value) for value in arguments)
            def finish(self, frame):
                name, references = frame
                if any(reference() is not None for reference in references):
                    raise AssertionError('public facade retained an argument after prepare')
                return name, len(references)
        owner = Owner()
        with patch.object(policy, 'selected_byte_policy', return_value=('control', owner)):
            self.assertEqual(api.normalize_exports(Argument(), Argument()), ('normalize_exports', 2))
            self.assertEqual(len(events), 2)
            self.assertEqual(api.emit_wrapper(Argument(), Argument(), Argument()), ('emit_wrapper', 3))
            self.assertEqual(len(events), 5)

    def test_bundle_entry_preserves_the_original_invoke_protocol(self):
        calls = []
        class Owner:
            def invoke(self, name, arguments):
                calls.append((name, arguments))
                return 'observed'
        owner = Owner()
        first, second, third = object(), object(), object()
        with patch.object(policy, 'selected_byte_policy', return_value=('bundle', owner)):
            self.assertEqual(api.normalize_exports(first, second), 'observed')
            self.assertEqual(api.emit_wrapper(first, second, third), 'observed')
        self.assertEqual(calls, [
            ('normalize_exports', (first, second)),
            ('emit_wrapper', (first, second, third))])


    def test_original_whole_emission_scope_captures_absence_of_both_families(self):
        with control.native_byte_abi_scope():
            with patch.dict(os.environ, {bundle.SELECTOR: '/bundle', control.SELECTOR: '/control'}):
                self.assertFalse(bundle.byte_wrapper_selection_requested())
                self.assertFalse(control.native_byte_abi_selection_requested())
                self.assertEqual(policy.selected_byte_policy(vars(api)), (None, None))

    def test_original_whole_emission_scope_rejects_dual_selection_before_admission(self):
        with patch.dict(os.environ, {bundle.SELECTOR: '/bundle', control.SELECTOR: '/control'}), \
             patch.object(bundle, 'installed_byte_wrapper', side_effect=AssertionError('bundle admission')) as left, \
             patch.object(control, '_admit', side_effect=AssertionError('control admission')) as right:
            with self.assertRaisesRegex(ValueError, 'cannot both be selected'):
                with control.native_byte_abi_scope():
                    self.fail('ambiguous whole-emission scope entered')
            left.assert_not_called()
            right.assert_not_called()


if __name__ == '__main__':
    unittest.main()
