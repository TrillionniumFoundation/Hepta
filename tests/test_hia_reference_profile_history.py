"""Source, default-profile, and refusal controls for reference QA adapters."""
import ast
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import hia_reference_profile_history as history
from tests.hia_distribution_fixture import reference_build_settings, reference_fixture_environment

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    'tests/test_hia_cli_native.py',
    'tests/test_hia_json_wire_native.py',
    'tests/test_hia_continuation_native.py',
    'tests/hia_distribution_fixture.py',
    'tests/test_hia_agent_installed_resources.py',
    'tests/test_hia_bounded_memory_native.py',
    'tests/test_hia_candidate_budget_native.py',
    'tests/test_hia_composite_functions_native.py',
    'tests/test_hia_composite_outer_integration.py',
    'tests/test_hia_execution_budget_native.py',
    'tests/test_hia_generation_retention_native.py',
    'tests/test_hia_native_mapping_native.py',
    'tests/test_hia_publication_measurement_native.py',
    'tests/test_hia_scalar_profile_native.py',
    'tests/test_hia_slot_ledger_native_integration.py',
    'tests/test_hia_store_native_delivery.py',
}


class ReferenceProfileContinuityTests(unittest.TestCase):
    def test_complete_original_sources_and_forward_replay_keep_all_assertions_and_budgets(self):
        records = history.records()
        self.assertEqual(set(records), EXPECTED)
        for name, record in records.items():
            with self.subTest(name=name):
                current = (ROOT / name).read_bytes()
                original = history.predecessor(name, current)
                self.assertEqual(history._pin(original), record['original'])
                self.assertEqual(history._pin(current), record['current'])
                def controls(raw):
                    tree = ast.parse(raw)
                    return [ast.dump(node, include_attributes=False) for node in ast.walk(tree)
                            if isinstance(node, ast.Assert)
                            or isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and node.func.attr.startswith('assert')
                            or isinstance(node, ast.keyword) and node.arg in ('timeout', 'wall_seconds')]
                self.assertEqual(controls(original), controls(current))
                for damaged in (current + b'\n', current[:-1], b'!' + current[1:]):
                    self.assertEqual(history.predecessor(name, damaged), damaged)
                    with self.assertRaises(ValueError):
                        history.restore(damaged, record)

    def test_explicit_reference_selection_does_not_change_production_default(self):
        from tools.hia_wheel_backend import _reference_distribution
        self.assertFalse(_reference_distribution(None))
        self.assertFalse(_reference_distribution({}))
        settings = reference_build_settings()
        self.assertEqual(settings, ('--config-settings', 'hia.reference-wheel=true'))
        name, value = settings[1].split('=', 1)
        self.assertTrue(_reference_distribution({name: value}))
        with self.assertRaises(ValueError):
            _reference_distribution({name: 'TRUE'})

    def test_clean_reference_child_preserves_only_complete_packaging_inputs(self):
        from tests.test_hia_store_native_delivery import clean_environment
        selected = {'HEPTA_HIA_TEST_PACKAGING_PYTHON': '/qa/python',
                    'HEPTA_HIA_TEST_DISTRIBUTION_WHEEL': '/qa/reference.whl',
                    'HEPTA_HIA_TEST_DISTRIBUTION_SHA256': 'a' * 64}
        ambient = dict(selected, HEPTA_HIA_AGENT_STORE_MANIFEST='/forbidden/provider',
                       HEPTA_HIA_SELFHOST_BUILD_DEVELOPMENT_COMPILER='/forbidden/compiler',
                       PYTHONPATH='/forbidden/imports', PYTHONHOME='/forbidden/home', PATH='/normal')
        self.assertEqual(reference_fixture_environment(ambient), selected)
        with patch.dict(os.environ, ambient, clear=True):
            self.assertEqual(clean_environment(), dict(selected, PATH='/normal'))
        for missing in ('HEPTA_HIA_TEST_DISTRIBUTION_WHEEL', 'HEPTA_HIA_TEST_DISTRIBUTION_SHA256'):
            invalid = dict(ambient); del invalid[missing]
            with self.assertRaises(ValueError):
                reference_fixture_environment(invalid)


if __name__ == '__main__':
    unittest.main()
