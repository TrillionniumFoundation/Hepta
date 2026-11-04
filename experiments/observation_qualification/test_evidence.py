"""Negative capability evidence, never convergence acceptance tests."""
import json
from pathlib import Path
import tempfile
import unittest

from experiments.frontend_lock_revalidation.owner import Owner
from experiments.frontend_lock_revalidation.cli import envelope
from .reproduce import alternating, current_route, fixture, torn_stream


class ObservationEvidenceTests(unittest.TestCase):
    def test_current_route_accepts_lock_changed_during_graph(self):
        result = current_route()
        self.assertTrue(result['mutated'])
        self.assertTrue(result['ok'])
        self.assertTrue(result['lock_bad'])
        self.assertEqual(result['qualification'], 'post_analysis_observed')
        self.assertEqual(result['fresh_code'], 'E_LOCK_INVALID')

    def assert_alternating(self, rounds):
        result = alternating(rounds)
        self.assertEqual(result['outcomes'], [True] * rounds)
        self.assertEqual(result['transitions'], ['lock', 'graph'] * rounds)
        self.assertNotIn((True, True), result['states'])
        self.assertIn((False, False), result['states'])
        self.assertTrue(result['source_good'])
        self.assertFalse(result['lock_good'])
        self.assertIsNone(result['failure'])
        return result

    def test_one_round_without_joint_good_state(self):
        self.assert_alternating(1)

    def test_eight_rounds_without_joint_good_state(self):
        result = self.assert_alternating(8)
        # Same context, cumulative observations, no budget resets.
        first = alternating(1)
        self.assertGreater(result['reads'], first['reads'])
        self.assertGreater(result['metadata_parses'], first['metadata_parses'])

    def test_hypothetical_final_lock_bracket_leaves_graph_changed(self):
        result = alternating(8, final_lock=True)
        self.assertEqual(result['outcomes'], [True] * 8)
        self.assertTrue(result['bracket_equal'])
        self.assertFalse(result['source_good'])
        self.assertTrue(result['lock_good'])
        self.assertNotIn((True, True), result['states'])
        self.assertIsNone(result['failure'])

    def test_harness_rounds_are_bounded_not_runtime_configuration(self):
        for invalid in (0, 9, -1, True, 1.0):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                alternating(invalid)

    def test_real_reader_accepts_never_present_stream(self):
        result = torn_stream()
        self.assertTrue(result['matches'])
        self.assertTrue(result['mutated'])
        self.assertEqual(result['states'], [b'AAAAXXXX', b'ZZZZXXXX', b'ZZZZBBBB'])
        self.assertNotIn(b'AAAABBBB', result['states'])
        self.assertEqual((result['reads'], result['bytes_read']), (1, 8))

    def test_digest_does_not_repair_torn_stream(self):
        result = torn_stream(digest=True)
        self.assertTrue(result['matches'])
        self.assertTrue(result['mutated'])
        self.assertNotIn(b'AAAABBBB', result['states'])
        self.assertEqual((result['reads'], result['bytes_read']), (1, 8))

    def test_existing_qualifiers_stay_nonatomic_and_nonnative(self):
        result = envelope('success', lock_revalidation='post_analysis_observed')
        self.assertFalse(result['atomic_snapshot'])
        self.assertFalse(result['native_qualified'])
        self.assertTrue(result['frontend_only'])
        self.assertEqual(result['lock_revalidation'], 'post_analysis_observed')

    def test_lock_semantics_are_not_raw_byte_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            entry, lock, original = fixture(Path(tmp))
            owner = Owner()
            handle = owner.load(entry, locked=True)
            lock.write_text(json.dumps(json.loads(original), indent=4))
            self.assertNotEqual(lock.read_bytes(), original)
            self.assertTrue(owner.revalidate(handle))
            self.assertIsNone(owner.context.failure)


if __name__ == '__main__':
    unittest.main()
