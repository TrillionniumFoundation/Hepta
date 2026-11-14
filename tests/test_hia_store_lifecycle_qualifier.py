"""Caller denominator and anomaly gates, with no product/native execution."""
from __future__ import annotations

from types import SimpleNamespace
import unittest

from tools import qualify_hia_store_lifecycle as qualifier
from tools import qualify_hia_service_requests as original


class StoreLifecycleQualifierTests(unittest.TestCase):
    def tearDown(self):
        qualifier.configure_group('agent')
        original.configure_group('agent')

    def test_three_original_groups_keep_all_original_ids_and_budgets(self):
        for name, count in (('agent', 48), ('namespace', 35), ('ledger', 48)):
            with self.subTest(name=name):
                qualifier.configure_group(name); original.configure_group(name)
                self.assertEqual(qualifier.EXPECTED_COUNT, 48 if name == 'agent' else 1)
                self.assertEqual(len(qualifier.original_ids()), qualifier.EXPECTED_COUNT)
                self.assertEqual(len(qualifier.nested_ids()), 0 if name == 'agent' else count)
                self.assertEqual(qualifier.GROUPS[name]['nested'], None if name == 'agent' else count)
                self.assertEqual(qualifier.original_ids(), original.original_ids())
                self.assertEqual(qualifier.execution_ids(), original.execution_ids())
                self.assertEqual(qualifier.nested_ids(), original.nested_ids())
                self.assertEqual(qualifier.caller_id_map(), original.caller_id_map())
                self.assertEqual(qualifier.GROUP_SECONDS, 1800)

    def test_original_result_requires_exact_execution_and_all_anomalies_empty(self):
        qualifier.configure_group('agent')
        loaded = qualifier.execution_ids()
        good = dict(testsRun=48, failures=[], errors=[], skipped=[], expectedFailures=[], unexpectedSuccesses=[])
        self.assertTrue(qualifier._strict_result(SimpleNamespace(**good), loaded, loaded, [], {1: 1, 2: 1}, {1: 1, 2: 1}))
        for key in ('failures', 'errors', 'skipped', 'expectedFailures', 'unexpectedSuccesses'):
            with self.subTest(key=key):
                changed = dict(good); changed[key] = ['anomaly']
                self.assertFalse(qualifier._strict_result(SimpleNamespace(**changed), loaded, loaded, [], {1: 1, 2: 1}, {1: 1, 2: 1}))
        for changed in (loaded[:-1], list(reversed(loaded)), loaded + loaded[:1]):
            self.assertFalse(qualifier._strict_result(SimpleNamespace(**good), loaded, changed, [], {1: 1, 2: 1}, {1: 1, 2: 1}))
        self.assertFalse(qualifier._strict_result(SimpleNamespace(**good), loaded, loaded, ['reference'], {1: 1, 2: 1}, {1: 1, 2: 1}))

    def test_two_actual_policy_modes_are_both_required_with_exact_integer_counts(self):
        qualifier.configure_group('agent')
        self.assertTrue(qualifier.valid_modes({1: 3, 2: 2}))
        for counts in ({}, {1: 1}, {2: 1}, {1: True, 2: 1}, {1: 0, 2: 1}, {1: 1, 2: 1.0}, {1: 1, 2: 1, 3: 1}):
            with self.subTest(counts=counts):
                self.assertFalse(qualifier.valid_modes(counts))
