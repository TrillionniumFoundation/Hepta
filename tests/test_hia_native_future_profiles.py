"""A current Future cannot be released with the obsolete raw cleanup role."""
from copy import deepcopy
import unittest

from tools.hia_native_future_profiles import admitted_truth_capsule, truth_capsule_record


class NativeFutureProfileTests(unittest.TestCase):
    def setUp(self):
        self.receipt = {'value_protocol': 'HIABVP09',
                        'public_cleanup_capsule': truth_capsule_record(
                            {'bytes': 700000, 'sha256': '1' * 64})}

    def test_current_profile_requires_its_truth_continuation(self):
        self.receipt.pop('public_cleanup_capsule')
        with self.assertRaisesRegex(ValueError, 'truth continuation'):
            admitted_truth_capsule(self.receipt)

    def test_exact_two_role_native_capsule_is_admitted(self):
        self.assertEqual(admitted_truth_capsule(self.receipt),
                         self.receipt['public_cleanup_capsule'])

    def test_legacy_receipts_do_not_synthesize_current_qualification(self):
        self.assertIsNone(admitted_truth_capsule({'value_protocol': 'HIABVP05'}))

    def test_missing_reordered_or_duplicated_role_is_rejected(self):
        for roles in (['cleanup'], ['truth', 'cleanup'], ['cleanup', 'cleanup']):
            receipt = deepcopy(self.receipt)
            receipt['public_cleanup_capsule']['roles'] = roles
            with self.subTest(roles=roles), self.assertRaises(ValueError):
                admitted_truth_capsule(receipt)

    def test_unknown_schema_or_hosted_build_cannot_claim_native(self):
        for key, value in (('protocol', 'HIABFT02'), ('packer', 'raw_cleanup'),
                           ('native_pack', False), ('native_pack', 1),
                           ('independent_byte_comparison', False), ('independent_byte_comparison', 1)):
            receipt = deepcopy(self.receipt)
            receipt['public_cleanup_capsule'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                admitted_truth_capsule(receipt)

    def test_product_pin_and_original_four_mib_limit_are_required(self):
        for product in ({'bytes': 0, 'sha256': '1' * 64},
                        {'bytes': 4194305, 'sha256': '1' * 64},
                        {'bytes': True, 'sha256': '1' * 64},
                        {'bytes': 7, 'sha256': 'x' * 64},
                        {'bytes': 7}, {'bytes': 7, 'sha256': '1' * 64, 'skip': True}):
            receipt = deepcopy(self.receipt)
            receipt['public_cleanup_capsule']['product'] = product
            with self.subTest(product=product), self.assertRaises(ValueError):
                admitted_truth_capsule(receipt)


if __name__ == '__main__':
    unittest.main()
