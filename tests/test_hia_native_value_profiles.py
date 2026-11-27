"""Release admission refuses a partial or unbound current Value image."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from tools.hia_native_value_profiles import (
    qualified_value_profile, qualified_value_sources, value_profile,
)

ROOT = Path(__file__).resolve().parents[1]


class NativeValueProfileTests(unittest.TestCase):
    def setUp(self):
        self.receipt = json.loads(
            (ROOT / 'docs/HIA_NATIVE_VALUE_RESOURCE_QUALIFICATION.json').read_bytes())

    def test_current_receipt_binds_all_sixteen_roles_and_native_sources(self):
        profile = qualified_value_profile(self.receipt)
        self.assertEqual(profile.protocol, 'HIABVP09')
        self.assertEqual(len(profile.roles), 16)
        self.assertEqual(profile.roles[-4:], (
            'result_value_protocols', 'result_value_callables',
            'result_value_invocations', 'result_value_platform'))
        self.assertEqual(qualified_value_sources(self.receipt),
                         self.receipt['construction']['source_files'])

    def test_older_layouts_remain_distinct(self):
        self.assertEqual(len(value_profile('HIABVP04').roles), 11)
        self.assertEqual(len(value_profile('HIABVP05').roles), 12)
        self.assertNotEqual(value_profile('HIABVP05').packer,
                            value_profile('HIABVP09').packer)

    def test_unregistered_layouts_cannot_select_a_partial_packer(self):
        for protocol in ('HIABVP06', 'HIABVP07', 'HIABVP08', 'HIABVP10', '', None):
            with self.subTest(protocol=protocol), self.assertRaises(ValueError):
                value_profile(protocol)

    def test_role_loss_duplication_or_reordering_is_refused(self):
        roles = self.receipt['value_roles']
        for changed in (roles[:12], roles[:-1] + [roles[0]], roles[::-1]):
            receipt = deepcopy(self.receipt)
            receipt['value_roles'] = changed
            with self.subTest(roles=changed), self.assertRaises(ValueError):
                qualified_value_profile(receipt)

    def test_unqualified_original_campaigns_cannot_be_inherited(self):
        self.receipt['original_six_campaigns_qualified'] = False
        with self.assertRaises(ValueError):
            qualified_value_profile(self.receipt)

    def test_legacy_packer_cannot_be_substituted_for_platform_packer(self):
        self.receipt['value_packer'] = 'examples/hia_bootstrap/result_value_resources_packer.hepta'
        with self.assertRaises(ValueError):
            qualified_value_profile(self.receipt)

    def test_missing_or_unrecognized_schema_does_not_fall_back_to_other_pins(self):
        self.receipt['source_files'] = self.receipt['construction']['source_files']
        for schema in (None, 'hia.native-value-deferred-info.component.v2'):
            self.receipt['schema'] = schema
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                qualified_value_sources(self.receipt)

    def test_construction_must_be_frozen_qualified_and_match_all_roles(self):
        for key, value in (('component_qualified', False), ('source_frozen', False),
                           ('value_protocol', 'HIABVP05'), ('value_roles', [])):
            receipt = deepcopy(self.receipt)
            receipt['construction'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                qualified_value_sources(receipt)

    def test_changed_or_incomplete_source_audit_is_refused(self):
        for change in ('pin', 'missing', 'unfrozen'):
            receipt = deepcopy(self.receipt)
            audit = receipt['source_audit']
            if change == 'pin':
                next(iter(audit['native_inputs'].values()))['sha256'] = '0' * 64
            elif change == 'missing':
                audit['native_inputs'].pop(next(iter(audit['native_inputs'])))
            else:
                audit['frozen_before_and_after'] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                qualified_value_sources(receipt)

    def test_bridge_and_independent_reference_cannot_change_layout(self):
        for key, value in (('value_bridge_source', 'tools/hia_result_value_resources_bridge.S'),
                           ('value_packer_module', 'tools.generate_hia_result_value_resources_packer')):
            receipt = deepcopy(self.receipt)
            receipt[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                qualified_value_sources(receipt)


if __name__ == '__main__':
    unittest.main()
