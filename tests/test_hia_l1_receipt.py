"""Pure L1 metadata adversarial tests, no simulated native success claims."""
import copy
import unittest

from hepta.hia_l1_receipt import HIAL1ReceiptRejected, validate_migration_receipt


SRC, OUT, SRC_SHA, OUT_SHA = "/tmp/input.c", "/tmp/native.hepta", "a" * 64, "b" * 64
BASE = {
    "ok": True, "status": "frontend_checked_not_native_qualified",
    "source": SRC, "output": OUT, "source_sha256": SRC_SHA,
    "output_sha256": OUT_SHA, "native_validation": "not_run",
    "converted": [{"name": "compute"}], "rejected": [],
    "target_model": {"pointer_bits": 64},
}


def specimen(language):
    base = copy.deepcopy(BASE)
    if language == "c":
        base.update(schema="hepta.migrate-c.v0", profile="strict_scalar_pilot",
                    source_equivalence_proved=False, whole_language_soundness_proved=False,
                    preprocessed_sha256="c" * 64, frontend="passed")
    else:
        base.update(schema="hepta.migrate-cpp-l1.v0", tier="L1",
                    profile="cpp20-noexcept-i32-free-functions-canonical-c-scalar-l1",
                    cpp_abi_preserved=False, behavioral_equivalence_proved=False,
                    whole_language_memory_safety_proved=False,
                    foreign_cpp_memory_safe=False, differential_validation="not_run")
    return base


def check(item, language):
    return validate_migration_receipt(item, language=language,
                                      source=SRC, output=OUT,
                                      source_sha256=SRC_SHA, output_sha256=OUT_SHA)


class SchemaTests(unittest.TestCase):
    def test_both_original_receipt_shapes_admitted_with_no_safety_proof(self):
        for language in ("c", "cpp"):
            self.assertIsNone(check(specimen(language), language))

    def test_missing_unknown_or_relabelled_fields_rejected(self):
        for language in ("c", "cpp"):
            for mutation in (lambda x: x.update(extra_passed=False),
                             lambda x: x.pop("converted"),
                             lambda x: x.update(schema="hepta.migrate-cpp-l1.v999"),
                             lambda x: x.update(status="checked"),
                             lambda x: x.update(ok=1)):
                item = specimen(language)
                mutation(item)
                with self.subTest(language=language, fields=list(item)), self.assertRaises(HIAL1ReceiptRejected):
                    check(item, language)

    def test_declared_safety_and_abi_claim_promotion_rejected_even_if_zero(self):
        for language, field in (("c", "source_equivalence_proved"),
                                ("c", "whole_language_soundness_proved"),
                                ("cpp", "cpp_abi_preserved"),
                                ("cpp", "behavioral_equivalence_proved"),
                                ("cpp", "whole_language_memory_safety_proved"),
                                ("cpp", "foreign_cpp_memory_safe")):
            for bad in (True, 1, 0):
                item = specimen(language)
                item[field] = bad
                with self.subTest(language=language, field=field, bad=bad), self.assertRaises(HIAL1ReceiptRejected):
                    check(item, language)

    def test_source_output_preprocess_and_inventory_spoof_rejected(self):
        for language in ("c", "cpp"):
            for key, bad in (("source", "other.c"), ("output", "other.hepta"),
                             ("source_sha256", "f" * 64), ("output_sha256", "X" * 64),
                             ("converted", []), ("converted", [{"name": "f"}, {"name": "f"}]),
                             ("converted", ["f"]), ("rejected", [{"code": "bad"}])):
                item = specimen(language)
                item[key] = bad
                with self.subTest(language=language, field=key), self.assertRaises(HIAL1ReceiptRejected):
                    check(item, language)
        item = specimen("c")
        item["preprocessed_sha256"] = None
        with self.assertRaises(HIAL1ReceiptRejected):
            check(item, "c")
        item = specimen("cpp")
        item["differential_validation"] = "passed"
        with self.assertRaises(HIAL1ReceiptRejected):
            check(item, "cpp")


if __name__ == '__main__':
    unittest.main()
