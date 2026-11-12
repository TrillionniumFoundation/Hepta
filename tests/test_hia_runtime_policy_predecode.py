"""P0/P7: reject caller policy objects before native runtime JSON normalization.

These tests deliberately do not need Z3/Clang. The actual native path is
covered by a second exact-source job with the project's pinned toolchain.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from hepta.hia_adaptive import AdaptiveRuntime
from hepta.hia_optimization import DEFAULT_POLICY, OptimizationRejected


class PolicyPredecodeAdmissionTests(unittest.TestCase):
    def reject_before_side_effects(self, supplied, code):
        with tempfile.TemporaryDirectory(prefix="hia-policy-predecode-") as directory:
            target = Path(directory) / "runtime-must-not-be-created"
            with self.assertRaisesRegex(OptimizationRejected, code):
                AdaptiveRuntime(None, target, policy=supplied)
            self.assertFalse(target.exists(), "invalid policy created runtime files")

    def test_mapping_subclass_is_not_laundered_into_trusted_dict(self):
        class ForeignPolicy(dict):
            pass

        self.reject_before_side_effects(
            ForeignPolicy(DEFAULT_POLICY), "E_HIA_OPT_POLICY")

    def test_mapping_subclass_hooks_are_never_executed(self):
        class HostilePolicy(dict):
            def items(self):
                raise AssertionError("untrusted mapping.items was invoked")

        self.reject_before_side_effects(
            HostilePolicy(DEFAULT_POLICY), "E_HIA_OPT_POLICY")

    def test_schema_subclass_with_identical_value_is_not_laundered(self):
        class ForeignString(str):
            pass

        supplied = dict(DEFAULT_POLICY)
        supplied["schema"] = ForeignString(DEFAULT_POLICY["schema"])
        self.reject_before_side_effects(supplied, "E_HIA_OPT_POLICY")

    def test_target_subclass_with_identical_value_is_not_laundered(self):
        class ForeignString(str):
            pass

        supplied = dict(DEFAULT_POLICY)
        supplied["target"] = ForeignString(DEFAULT_POLICY["target"])
        self.reject_before_side_effects(supplied, "E_HIA_OPT_TARGET")

    def test_empty_list_subclass_cannot_erase_provenance(self):
        class ForeignList(list):
            pass

        supplied = dict(DEFAULT_POLICY)
        supplied["preconditions"] = ForeignList()
        self.reject_before_side_effects(supplied, "E_HIA_OPT_PRECONDITION")

    def test_nonempty_unproved_preconditions_fail_before_build(self):
        supplied = dict(DEFAULT_POLICY)
        supplied["preconditions"] = [{"assume": "any input is safe"}]
        self.reject_before_side_effects(supplied, "E_HIA_OPT_PRECONDITION")

    def test_invalid_boolean_budget_fails_before_native_allocation(self):
        supplied = dict(DEFAULT_POLICY)
        supplied["timeout_ms"] = True
        self.reject_before_side_effects(supplied, "E_HIA_OPT_POLICY")

    def test_valid_policy_is_detached_before_source_profile_check(self):
        class ProfileReached(Exception):
            pass

        class CaptureRuntime(AdaptiveRuntime):
            def _admit_profile(self, document):
                raise ProfileReached

        with tempfile.TemporaryDirectory(prefix="hia-policy-valid-") as directory:
            supplied = dict(DEFAULT_POLICY)
            supplied["preconditions"] = []
            runtime = CaptureRuntime.__new__(CaptureRuntime)
            with self.assertRaises(ProfileReached):
                runtime.__init__(
                    None, Path(directory) / "profile-only", policy=supplied)
            normalized = runtime._policy
            self.assertEqual(normalized, DEFAULT_POLICY)
            self.assertIsNot(normalized, supplied)
            self.assertIsNot(normalized["preconditions"], supplied["preconditions"])
            supplied["preconditions"].append("producer changed after admission")
            supplied["schema"] = "untrusted"
            self.assertEqual(normalized, DEFAULT_POLICY)


if __name__ == "__main__":
    unittest.main()
