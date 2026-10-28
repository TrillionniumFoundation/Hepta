"""A reduced test selection must not inherit the reviewed safety qualification."""
from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from tools import qualify_hia_safety_contract as safety


class ReviewedSafetyProtocolTests(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(safety.CONTRACT.read_bytes())

    def refuse(self, changed):
        with self.assertRaisesRegex(ValueError, "E_SAFETY_PROTOCOL"):
            safety.validate_contract(changed)

    def test_reviewed_protocol_resolves_every_distinct_test(self):
        expected = sorted({selector for row in self.contract["capabilities"]
                           for selector in row["regression_selectors"]})
        self.assertGreaterEqual(len(expected), 37)
        self.assertEqual(safety.validate_contract(self.contract), expected)

    def test_json_formatting_and_object_key_order_do_not_change_protocol(self):
        reordered = {key: self.contract[key] for key in reversed(self.contract)}
        self.assertEqual(safety.validate_contract(json.loads(json.dumps(reordered, indent=4))),
                         safety.validate_contract(self.contract))

    def test_stateful_python_containers_cannot_reduce_the_hashed_selection(self):
        class ChangingSelectors(list):
            def __init__(self, values):
                super().__init__(values)
                self.reads = 0

            def __iter__(self):
                self.reads += 1
                if self.reads == 1:
                    return super().__iter__()
                return iter([self[0]])

        expected = safety.validate_contract(self.contract)
        changed = deepcopy(self.contract)
        for row in changed["capabilities"]:
            row["regression_selectors"] = ChangingSelectors(row["regression_selectors"])
        self.assertEqual(safety.validate_contract(changed), expected)

    def test_removing_each_reviewed_capability_is_refused(self):
        for index, row in enumerate(self.contract["capabilities"]):
            with self.subTest(capability=row["id"]):
                changed = deepcopy(self.contract)
                del changed["capabilities"][index]
                self.refuse(changed)

    def test_removing_each_boundary_regression_is_refused(self):
        for row_index, row in enumerate(self.contract["capabilities"]):
            for test_index, selector in enumerate(row["regression_selectors"]):
                with self.subTest(capability=row["id"], selector=selector):
                    changed = deepcopy(self.contract)
                    del changed["capabilities"][row_index]["regression_selectors"][test_index]
                    self.refuse(changed)

    def test_replacing_a_regression_with_another_valid_test_is_refused(self):
        changed = deepcopy(self.contract)
        selectors = changed["capabilities"][0]["regression_selectors"]
        selectors[0] = selectors[1]
        self.refuse(changed)

    def test_changed_scope_exclusions_or_trust_assumptions_are_refused(self):
        for field in ("scope", "guarantee", "exclusions"):
            with self.subTest(field=field):
                changed = deepcopy(self.contract)
                changed["capabilities"][0][field] = (
                    ["none"] if field == "exclusions" else "unbounded")
                self.refuse(changed)
        changed = deepcopy(self.contract)
        changed["trusted_computing_base"] = self.contract["trusted_computing_base"][:1]
        self.refuse(changed)

    def test_changed_entrypoint_refuses_before_dynamic_resolution(self):
        changed = deepcopy(self.contract)
        changed["capabilities"][0]["entrypoints"] = ["os.system"]
        with patch.object(safety.importlib, "import_module",
                          side_effect=AssertionError("unreviewed dynamic import")):
            self.refuse(changed)

    def test_forged_identity_and_numeric_boolean_substitutions_are_refused(self):
        changed = deepcopy(self.contract)
        changed["reviewed_contract_sha256"] = safety.REVIEWED_CONTRACT_SHA256
        self.refuse(changed)
        for key in self.contract["unproved_claims"]:
            with self.subTest(claim=key):
                changed = deepcopy(self.contract)
                changed["unproved_claims"][key] = 0  # Python equality treats 0 == False.
                self.refuse(changed)

    def test_non_json_and_nonfinite_contract_values_are_controlled_refusals(self):
        for value in (object(), float("nan"), float("inf")):
            with self.subTest(type=type(value).__name__):
                changed = deepcopy(self.contract)
                changed["extra"] = value
                self.refuse(changed)

    def test_live_registry_is_still_checked_after_protocol_identity(self):
        registry = deepcopy(self.contract["registry"])
        with patch.object(safety, "schema_registry", return_value={"unreviewed": registry}):
            with self.assertRaisesRegex(ValueError, "E_SAFETY_REGISTRY"):
                safety.validate_contract(self.contract)


if __name__ == "__main__":
    unittest.main()
