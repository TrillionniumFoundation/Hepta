"""Finite P0 falsification of laundering a frozen native release cohort.

These call only the registration checker. They are NOT native performance,
whole-language proof, Rust parity, or permission to deploy.
"""
from __future__ import annotations

import unittest

from tools.qualify_hia_release_parity import specification, _validate_release_registration


class FrozenReleaseAxesTests(unittest.TestCase):
    def assert_refused(self, mutate):
        spec = specification("verified-reduction-release-v1")
        mutate(spec)
        with self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
            _validate_release_registration(spec)

    def test_replacing_a_registered_training_size_refuses(self):
        self.assert_refused(lambda spec: spec.update(training_sizes=[128, 4096, 65536]))

    def test_replacing_an_unseen_holdout_seed_refuses(self):
        self.assert_refused(lambda spec: spec.update(holdout_seeds=[383, 659, 2003]))

    def test_shrinking_actual_release_sample_budget_refuses(self):
        self.assert_refused(lambda spec: spec.update(samples=1))

    def test_stripping_schema_cannot_downgrade_a_release_registration(self):
        self.assert_refused(lambda spec: spec.pop("schema"))

    def test_unregistered_release_build_profile_refuses(self):
        self.assert_refused(lambda spec: spec.update(build_profile="unregistered-release-v1"))

    def test_exact_both_frozen_profiles_and_stricter_limits_survive(self):
        for profile in ("optimized-release-v1", "verified-reduction-release-v1"):
            with self.subTest(profile=profile):
                spec = specification(profile)
                _validate_release_registration(spec)
                spec["performance_gate"]["hia_tail_ratio_maximum"] = 1.05
                _validate_release_registration(spec)


if __name__ == "__main__":
    unittest.main()
