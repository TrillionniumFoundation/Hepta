"""Cached admission follows the actual extracted ownership implementation."""
from dataclasses import make_dataclass
import unittest
from unittest.mock import patch

from hepta import hia_capability_flow as flow
from hepta import hia_program as core
from hepta.hia_incremental import IncrementalVerifier
from tests.test_hia_program import joined_loan_program


def reject_renaming(*args):
    raise flow.CapabilityFlowRejected("changed ownership policy rejects the edge", "E_HIA_LOAN")


class IncrementalCapabilityPolicyTests(unittest.TestCase):
    def assert_rejected_like_full(self, session, source):
        before = session.base_sha256
        with self.assertRaises(core.HIAProgramRejected) as expected:
            core.verify_program(source)
        with self.assertRaises(core.HIAProgramRejected) as actual:
            session.verify(source)
        self.assertEqual(actual.exception.code, expected.exception.code)
        self.assertEqual(str(actual.exception), str(expected.exception))
        self.assertEqual(session.base_sha256, before)
        self.assertEqual(session.last_report["mode"], "full")
        self.assertEqual(session.last_report["functions_body_reused"], [])

    def test_rebound_imported_renamer_cannot_reuse_old_ownership_admission(self):
        source = joined_loan_program()
        session = IncrementalVerifier(source)
        with patch.object(core, "rename_capabilities", reject_renaming):
            self.assert_rejected_like_full(session, source)
        # A failed policy transition did not corrupt the original cache.
        _, report = session.verify(source)
        self.assertEqual(report["mode"], "incremental")
        self.assertEqual(report["functions_body_reused"], ["join"])

    def test_in_place_renamer_code_change_invalidates_the_same_function_object(self):
        source = joined_loan_program()
        session = IncrementalVerifier(source)
        original = core.rename_capabilities.__code__
        # This replacement executes in the helper's module globals.
        def changed(*args):
            raise CapabilityFlowRejected("changed helper code", "E_HIA_LOAN")
        try:
            core.rename_capabilities.__code__ = changed.__code__
            self.assert_rejected_like_full(session, source)
        finally:
            core.rename_capabilities.__code__ = original

    def test_reloaded_helper_class_is_bound_even_when_core_aliases_are_unchanged(self):
        source = joined_loan_program()
        session = IncrementalVerifier(source)
        changed = make_dataclass("Capability", [("typ", str), ("root", str)])
        with patch.object(flow, "Capability", changed):
            self.assert_rejected_like_full(session, source)

    def test_changed_capability_equality_cannot_preserve_cached_cfg_join_result(self):
        source = joined_loan_program()
        session = IncrementalVerifier(source)
        with patch.object(core._Capability, "__eq__", lambda self, other: False):
            self.assert_rejected_like_full(session, source)


if __name__ == "__main__":
    unittest.main()
