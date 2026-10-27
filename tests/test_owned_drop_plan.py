"""Verifier-derived Drop decisions for finite concrete owned types."""
import unittest

from hepta.owned_drop_plan import DropPlanRejected, derive_resource_drop_plan


TYPES = {
    'u8': {'kind': 'scalar', 'name': 'u8'},
    'u64': {'kind': 'scalar', 'name': 'u64'},
    'Buffer<u8>': {'kind': 'buffer', 'element': 'u8'},
    'Pair': {'kind': 'struct', 'name': 'Pair', 'args': [], 'fields': [
        {'name': 'data', 'type': 'Buffer<u8>'}, {'name': 'tag', 'type': 'u64'}]},
    'Choice': {'kind': 'enum', 'name': 'Choice', 'args': [], 'variants': [
        {'name': 'None', 'fields': []},
        {'name': 'Some', 'fields': ['Pair']},
        {'name': 'PairOf', 'fields': ['Pair', 'Pair']}]},
}


class DropPlanTests(unittest.TestCase):
    def test_verified_resource_type_drives_owned_child_dispatch(self):
        plan = derive_resource_drop_plan(TYPES, 'Pair')
        self.assertEqual(plan.kind, 'struct')
        self.assertEqual(plan.fields, (('data', 'Buffer<u8>', True), ('tag', 'u64', False)))
        choice = derive_resource_drop_plan(TYPES, 'Choice')
        self.assertEqual(choice.variants[0], ('None', ()))
        self.assertEqual(choice.variants[1], ('Some', (('Pair', True),)))
        self.assertEqual(choice.variants[2][1], (('Pair', True), ('Pair', True)))
        self.assertEqual(derive_resource_drop_plan(TYPES, 'Buffer<u8>').kind, 'buffer')

    def test_missing_instantiation_is_not_implicitly_qualified(self):
        self.assertIsNone(derive_resource_drop_plan(TYPES, 'Pair<Buffer<u8>>'))

    def test_missing_dependency_and_recursive_types_refused(self):
        forged = dict(TYPES)
        forged['Pair'] = {'kind': 'struct', 'fields': [{'name': 'data', 'type': 'missing'}]}
        with self.assertRaisesRegex(DropPlanRejected, 'E_DROP_PLAN'):
            derive_resource_drop_plan(forged, 'Pair')
        forged['Pair'] = {'kind': 'struct', 'fields': [{'name': 'self', 'type': 'Pair'}]}
        with self.assertRaisesRegex(DropPlanRejected, 'E_DROP_PLAN'):
            derive_resource_drop_plan(forged, 'Pair')

    def test_owned_array_and_unsupported_view_refused(self):
        forged = dict(TYPES)
        forged['[Buffer<u8>; 1]'] = {'kind': 'array', 'element': 'Buffer<u8>', 'length': 1}
        forged['List'] = {'kind': 'struct', 'fields': [{'name': 'xs', 'type': '[Buffer<u8>; 1]'}]}
        with self.assertRaisesRegex(DropPlanRejected, 'E_DROP_PLAN'):
            derive_resource_drop_plan(forged, 'List')
        forged['Loan'] = {'kind': 'view', 'name': 'Loan'}
        with self.assertRaisesRegex(DropPlanRejected, 'E_DROP_PLAN'):
            derive_resource_drop_plan(forged, 'Loan')

    def test_boolean_identity_and_input_budgets(self):
        for value in (None, [], 'wrong'):
            with self.assertRaises(DropPlanRejected):
                derive_resource_drop_plan(value, 'Pair')
        with self.assertRaises(DropPlanRejected):
            derive_resource_drop_plan(TYPES, True)


    def test_malformed_type_identity_cannot_change_native_drop_plan(self):
        cases = [
            ("u64", {"kind": "scalar", "name": "u8"}),
            ("Buffer<u8>", {"kind": "scalar", "name": "Buffer<u8>"}),
            ("Buffer<u8>", {"kind": "buffer", "element": "u8", "proved": True}),
            ("Buffer<u8>", {"kind": "buffer", "element": "u64"}),
            ("Pair", {**TYPES["Pair"], "args": ["forged"]}),
            ("Pair", {**TYPES["Pair"], "fields": [
                {"name": "data", "type": "Buffer<u8>", "safe": True}]}),
            ("Choice", {**TYPES["Choice"], "variants": [
                {"name": "Some", "fields": ["Pair"], "proved": True}]}),
        ]
        for name, entry in cases:
            with self.subTest(name=name):
                forged = dict(TYPES)
                forged[name] = entry
                target = "Choice" if name in {"Choice", "u64"} else "Pair"
                with self.assertRaisesRegex(DropPlanRejected, "E_DROP_PLAN"):
                    derive_resource_drop_plan(forged, target)

if __name__ == '__main__':
    unittest.main()
