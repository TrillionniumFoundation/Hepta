"""Live interface equality cannot hide a changed returned-loan dependency."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from hepta import hia_program as core
from hepta.hia_incremental import IncrementalVerifier
from tests.test_hia_program import joined_loan_program
from tests.test_hia_incremental_v8 import early_release_other_owner
from tests.test_hia_returned_loan_interfaces import migration


def always_equal(self, other):
    return True


class IncrementalInterfacePolicyTests(unittest.TestCase):
    def source_and_candidate(self):
        source = early_release_other_owner()
        changed = deepcopy(source)
        changed["functions"][1] = migration(source)["edits"][0]["definition"]
        return source, changed

    def assert_rejected_like_full(self, session, changed):
        before = session.base_sha256
        with self.assertRaises(core.HIAProgramRejected) as expected:
            core.verify_program(changed)
        self.assertEqual(expected.exception.code, "E_HIA_LOAN")
        with self.assertRaises(core.HIAProgramRejected) as actual:
            session.verify(changed)
        self.assertEqual(str(actual.exception), str(expected.exception))
        self.assertEqual(session.base_sha256, before)
        self.assertEqual(session.last_report["mode"], "full")
        self.assertEqual(session.last_report["functions_body_reused"], [])

    def test_rebound_interface_equality_cannot_hide_changed_returned_origin(self):
        source, changed = self.source_and_candidate()
        session = IncrementalVerifier(source)
        with patch.object(core._FunctionInterface, "__eq__", always_equal):
            self.assert_rejected_like_full(session, changed)
        _, report = session.verify(source)
        self.assertEqual(report["mode"], "incremental")
        self.assertEqual(report["functions_body_reused"], ["entrypoint", "pick"])

    def test_in_place_interface_equality_code_cannot_keep_cached_caller(self):
        source, changed = self.source_and_candidate()
        session = IncrementalVerifier(source)
        equality = core._FunctionInterface.__eq__
        original = equality.__code__
        try:
            equality.__code__ = always_equal.__code__
            self.assert_rejected_like_full(session, changed)
        finally:
            equality.__code__ = original

    def test_added_interface_inequality_cannot_hide_changed_returned_origin(self):
        source, changed = self.source_and_candidate()
        session = IncrementalVerifier(source)
        with patch.object(core._FunctionInterface, "__ne__", lambda self, other: False,
                          create=True):
            self.assert_rejected_like_full(session, changed)

    def test_in_place_equality_property_getter_cannot_hide_returned_origin(self):
        source, changed = self.source_and_candidate()
        equality = core._FunctionInterface.__eq__

        def original_getter(self):
            return equality.__get__(self, type(self))

        def changed_getter(self):
            assert equality is not None
            return always_equal.__get__(self, type(self))

        # A non-callable descriptor can supply the special equality method.
        # Its identity stays fixed while the getter's implementation changes.
        with patch.object(core._FunctionInterface, "__eq__", property(original_getter)):
            session = IncrementalVerifier(source)
            original_getter.__code__ = changed_getter.__code__
            self.assert_rejected_like_full(session, changed)

    def test_changed_capability_constructor_defaults_cannot_reuse_local_loans(self):
        source = joined_loan_program()
        session = IncrementalVerifier(source)
        # New local loans now default to external, making loan.end illegal.
        # The class, constructor function and code objects all stay identical.
        with patch.object(core._Capability.__init__, "__defaults__", (None, True, None)):
            self.assert_rejected_like_full(session, source)

    def test_in_place_borrow_keyword_default_change_cannot_reuse_buffer_check(self):
        source = joined_loan_program()
        session = IncrementalVerifier(source)
        # An existing dict changes in place; retaining its reference is not a
        # snapshot of the keyword-only default actually used by the checker.
        with patch.dict(core._BlockCheck.borrow.__kwdefaults__, chain_head=True):
            self.assert_rejected_like_full(session, source)


if __name__ == "__main__":
    unittest.main()
