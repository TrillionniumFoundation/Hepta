"""Hostile HIA function-container checks for the isolated kernel privilege profile.

A bad JSON container must never escape with an untyped Python exception.
These checks strengthen verifier failure semantics; they do not authenticate
CPL0, CR3 or page-table ownership and must not be treated as Linux closure.
"""
from copy import deepcopy
import unittest

from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_schema import KERNEL_TLB_SCHEMA
from tests.test_hia_kernel_invlpg_core import sample


class KernelPrivilegeShapeGuardTests(unittest.TestCase):
    def test_malformed_function_containers_are_typed_rejections(self):
        valid = sample()
        self.assertEqual(verify_program(valid).as_dict()["schema"], KERNEL_TLB_SCHEMA)
        for malformed in (None, [], {}, "function", 9, True,
                          {"effects": ["privilege"]}, {"effects": []}):
            doc = deepcopy(valid)
            doc["functions"][0] = malformed
            with self.subTest(malformed=repr(malformed)):
                with self.assertRaises(HIAProgramRejected):
                    verify_program(doc)

    def test_malformed_effect_lists_refuse_before_kernel_permission_check(self):
        valid = sample()
        for malformed in (None, "privilege", {"privilege": True}, 0, True,
                          [["privilege"]], [None], ["privilege", "privilege"]):
            doc = deepcopy(valid)
            doc["functions"][0]["effects"] = malformed
            with self.subTest(effects=repr(malformed)):
                with self.assertRaises(HIAProgramRejected):
                    verify_program(doc)

    def test_legacy_profile_cannot_obtain_privilege_by_declaring_effect(self):
        doc = sample()
        doc["schema"] = "hepta.hia.program.v8"
        doc["functions"][0]["blocks"][0]["ops"] = []
        with self.assertRaisesRegex(HIAProgramRejected, "privilege"):
            verify_program(doc)


if __name__ == "__main__":
    unittest.main()
