"""Real installed-image and first-admission tests for native Agent metadata."""
from __future__ import annotations
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_agent_native_metadata_native import (
    REFUSALS, SELECTOR, SOURCE, NativeAgentMetadata, call_admitted_metadata_image,
    installed_agent_metadata, prepare_native_metadata, selected_agent_metadata,
)
from hepta.hia_program import verify_program
from tests.test_hia_agent_native_metadata import (
    AgentMetadataFixture, clean_environment, function, loan_program,
    no_hosted_metadata, no_reference_metadata, object_cases, observe_entry,
    original_metadata, original_object_metadata, program, record,
)

class AgentMetadataIntegrationTests(AgentMetadataFixture, unittest.TestCase):
    def test_original_full_verifier_precedes_any_native_call(self):
        invalid = program(function('broken'))
        invalid['functions'][0]['blocks'][0]['term']['values'] = ['undefined_value']
        with patch.dict(os.environ, clean_environment(), clear=True), observe_entry(self.native) as calls:
            with self.assertRaises(ValueError):
                prepare_native_metadata(invalid, native=self.native, manifest_wire=b'[]')
        self.assertEqual(len(calls), 0)

    def test_actual_installed_factory_and_present_selector(self):
        document = loan_program()
        checked = verify_program(document)
        raw = b'[["alpha",33]]'
        expected = original_metadata(checked, raw)
        with patch.dict(os.environ, clean_environment(), clear=True):
            self.assertIsNone(selected_agent_metadata())
            with patch.dict(os.environ, {SELECTOR: ''}):
                with self.assertRaises(ValueError):
                    selected_agent_metadata()
            with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
                selected = selected_agent_metadata()
                with no_hosted_metadata(), observe_entry(selected) as calls:
                    actual = call_admitted_metadata_image(selected, checked, raw)
                self.assertEqual(len(calls), 1)
                self.assertEqual(actual, expected)
        record(self.directory() / 'selection.json', {
            'actual_installed_factory_executed': True, 'native_invocations': len(calls),
            'default_absence_selected': False, 'empty_selector_refused': True})

    def test_installed_source_schema_and_image_drift_refuse(self):
        from hepta import hia_agent_native_metadata_native as adapter
        root = self.directory()
        original = json.loads(self.manifest.read_bytes())
        with patch.dict(os.environ, clean_environment(), clear=True):
            self.assertIsNotNone(installed_agent_metadata(str(self.manifest)))
            for mode in ('schema', 'image', 'source'):
                with self.subTest(mode=mode):
                    folder = root / mode
                    folder.mkdir(mode=0o700)
                    image = self.image_path.read_bytes()
                    if mode == 'image':
                        image = bytes([image[0] ^ 1]) + image[1:]
                    (folder / 'image.bin').write_bytes(image)
                    manifest = dict(original, image_path='image.bin')
                    if mode == 'schema':
                        manifest['schema'] += '.wrong'
                    path = folder / 'manifest.json'
                    record(path, manifest)
                    changed_source = folder / 'source.hepta'
                    changed_source.write_bytes(SOURCE.read_bytes() + b'\n')
                    with patch.object(adapter, 'SOURCE', changed_source if mode == 'source' else SOURCE):
                        with self.assertRaises(ValueError):
                            installed_agent_metadata(str(path))

    def test_real_native_call_has_no_hosted_signature_fallback(self):
        document = loan_program()
        checked = verify_program(document)
        raw = b'[["zeta",16],["alpha",32]]'
        expected = original_metadata(checked, raw)
        with no_hosted_metadata(), observe_entry(self.native) as calls:
            actual = prepare_native_metadata(document, native=self.native, manifest_wire=raw)
            with self.assertRaises(ValueError) as refused:
                prepare_native_metadata(document, native=self.native,
                                        manifest_wire=b'[["alpha",0]]')
        self.assertEqual(actual, expected)
        self.assertEqual(len(calls), 2)
        self.assertIn('E_HIA_BYTE_ABI', str(refused.exception))
        self.assertIn(REFUSALS[0xfffffffa], str(refused.exception))
        self.assertTrue(all(row['input'] == row['input_after'] for row in calls))
        record(self.directory() / 'actual-policy-owner.json', {
            'native_invocations': len(calls), 'hosted_policy_poisoned': True,
            'success_and_public_refusal_observed': True,
            'full_core_verifier_preceded_invocations': True})

    def test_ordinary_signatures_entry_uses_actual_admitted_native_owner(self):
        from hepta.hia_agent_service import _signatures
        checked = verify_program(loan_program())
        exports = (('zeta', 17), ('alpha', 31))
        expected = original_object_metadata(checked, exports)['signatures']
        real_transition = NativeAgentMetadata.transition
        observations = []
        def observed(instance, request):
            result = real_transition(instance, request)
            observations.append({'input_version': int.from_bytes(request[8:16], 'little'),
                                 'status': result.status})
            return result
        with patch.dict(os.environ, clean_environment(), clear=True):
            self.assertEqual(_signatures(checked, exports), expected)
            with patch.dict(os.environ, {SELECTOR: ''}), no_reference_metadata():
                with self.assertRaises(ValueError):
                    _signatures(checked, exports)
            with patch.dict(os.environ, {SELECTOR: str(self.manifest)}), no_reference_metadata():
                with patch.object(NativeAgentMetadata, 'transition', observed):
                    self.assertEqual(_signatures(checked, exports), expected)
                    with self.assertRaises(ValueError) as error:
                        _signatures(checked, (('alpha', 0),))
        self.assertIn(REFUSALS[0xfffffffa], str(error.exception))
        self.assertEqual(observations, [{'input_version': 2, 'status': 0},
                                       {'input_version': 2, 'status': 0xfffffffa}])
        record(self.directory() / 'ordinary-entry.json', {
            'actual_original_entry': 'hepta.hia_agent_service._signatures',
            'actual_installed_factory_used': True, 'reference_policy_poisoned': True,
            'transitions': observations, 'absence_retains_reference_default': True})

    def test_ordinary_signatures_exact_object_refusal_matrix(self):
        from hepta.hia_agent_service import _signatures
        checked = verify_program(loan_program())
        observations = []
        with patch.dict(os.environ, clean_environment(), clear=True):
            for label, exports in object_cases():
                error = None
                try:
                    expected = original_object_metadata(checked, exports)['signatures']
                except ValueError as exc:
                    error = str(exc)
                with self.subTest(label=label), patch.dict(os.environ, {SELECTOR: str(self.manifest)}), no_reference_metadata():
                    if error is None:
                        self.assertEqual(_signatures(checked, exports), expected)
                    else:
                        with self.assertRaises(ValueError) as actual:
                            _signatures(checked, exports)
                        self.assertEqual(str(actual.exception), error)
                observations.append({'case': label, 'reference_error': error,
                                     'selected_original_entry_matched': True})
        record(self.directory() / 'ordinary-object-domain.json', observations)


if __name__ == '__main__':
    unittest.main()
