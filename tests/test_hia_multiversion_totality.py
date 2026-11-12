"""Actual native admission requires normal return separately from equivalence."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_multiversion import (MultiversionRejected, PROFILE, PROVED_TOTAL_PROFILE,
                                   PublicationCancellation, ScalarMultiversionRuntime)
from hepta.hia_scalar_state import ScalarStateSession
from hepta.hia_scalar_totality import validate_scalar_totality
from hepta.hia_specialization import propose_guarded_specializations
from hepta.hia_translation_validation import validate_translation
from tests.test_hia_multiversion import _CLANG, _NATIVE, scalar_program
from tests.test_hia_program import arithmetic
from tests.test_hia_scalar_totality import total_division


def specialized(source):
    return propose_guarded_specializations(source, function="calculate",
        assumptions=[{"parameter": "denominator", "value": 16}])[0]["program"]


@unittest.skipUnless(_NATIVE, "actual Clang, Z3 and Linux sealed memfd are required")
class ProvedTotalNativeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-proved-total-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def runtime(self, source, **options):
        runtime = ScalarMultiversionRuntime(source, self.root, clang=_CLANG,
                                           prove_total=True, **options)
        self.addCleanup(runtime.close)
        return runtime

    def test_original_profile_still_rejects_even_semantically_total_division(self):
        with patch("hepta.hia_multiversion.build_program_native") as build:
            with self.assertRaises(MultiversionRejected):
                ScalarMultiversionRuntime(total_division(), self.root, clang=_CLANG)
            build.assert_not_called()
        with ScalarMultiversionRuntime(scalar_program(), self.root, clang=_CLANG) as runtime:
            self.assertEqual(runtime.snapshot()["schema"], PROFILE)
            self.assertEqual(runtime.snapshot()["generations"][0]["totality_proofs"], 0)

    def test_explicit_profile_flag_does_not_coerce_truthy_values(self):
        for flag in (1, 0, "true", None, []):
            with self.subTest(flag=flag), self.assertRaisesRegex(MultiversionRejected, "Boolean"):
                ScalarMultiversionRuntime(total_division(), self.root, clang=_CLANG, prove_total=flag)

    def test_all_u8_input_pairs_match_independent_integer_spec_before_and_after_publish(self):
        source = total_division()
        runtime = self.runtime(source)
        for version in range(2):
            if version:
                generation = runtime.publish(specialized(source))
                self.assertEqual(generation.totality_proofs, 1)
                self.assertEqual(generation.translation_proofs, 1)
            with runtime.lease() as lease:
                for value in range(256):
                    for divisor in range(256):
                        expected = value if divisor == 0 else (value // divisor + value % divisor) & 255
                        self.assertEqual(lease.call("calculate", [value, divisor]), expected)
        self.assertEqual(runtime.snapshot()["schema"], PROVED_TOTAL_PROFILE)

    def test_u16_edges_generic_fallback_and_conditional_publication(self):
        source = total_division("u16")
        runtime = self.runtime(source)
        token = PublicationCancellation()
        report = runtime.publish_if_current(specialized(source), 0, expected_epoch=0,
                                            max_prepare_ns=30_000_000_000, cancellation=token)
        self.assertTrue(token.committed())
        self.assertEqual(report["generation"]["admission_profile"], PROVED_TOTAL_PROFILE)
        with runtime.lease() as lease:
            for value in (0, 1, 15, 16, 32767, 32768, 65535):
                for divisor in (0, 1, 3, 10, 16, 32768, 65535):
                    expected = value if divisor == 0 else (value // divisor + value % divisor) & 65535
                    self.assertEqual(lease.call("calculate", [value, divisor]), expected)

    def test_self_equivalence_does_not_admit_a_trapping_baseline(self):
        source = arithmetic("int.div.checked", "u8")
        self.assertEqual(validate_translation(source, source)["status"], "proved")
        with patch("hepta.hia_multiversion.build_program_native") as build:
            with self.assertRaisesRegex(MultiversionRejected, "totality"):
                self.runtime(source)
            build.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_wrong_guard_does_not_build_or_replace_the_incumbent(self):
        source = total_division()
        runtime = self.runtime(source)
        wrong = copy.deepcopy(source)
        wrong["functions"][0]["blocks"][0]["ops"][1]["op"] = "compare.ne"
        with patch("hepta.hia_multiversion.build_program_native") as build:
            with self.assertRaisesRegex(MultiversionRejected, "totality"):
                runtime.publish(wrong)
            build.assert_not_called()
        self.assertEqual(runtime.snapshot()["current_generation"], 0)
        self.assertEqual(runtime.call("calculate", [9, 0]), 9)

    def test_total_but_behavior_changing_candidate_still_needs_equivalence(self):
        source = total_division()
        runtime = self.runtime(source)
        wrong = copy.deepcopy(source)
        wrong["functions"][0]["blocks"][2]["ops"][2]["op"] = "int.sub.wrap"
        self.assertEqual(validate_scalar_totality(wrong)["status"], "proved")
        with patch("hepta.hia_multiversion.build_program_native") as build:
            with self.assertRaisesRegex(MultiversionRejected, "disproved"):
                runtime.publish(wrong)
            build.assert_not_called()
        self.assertEqual(runtime.snapshot()["selection_epoch"], 0)

    def test_unknown_unbound_and_malformed_fresh_totality_results_reject(self):
        source = total_division()
        runtime = self.runtime(source)
        candidate = specialized(source)
        stale = validate_scalar_totality(source)
        good = validate_scalar_totality(candidate)
        controls = [stale]
        for field, value in (("status", "unknown"), ("validator_sha256", "0" * 64),
                             ("encoder_sha256", "0" * 64), ("structural_verification", 1)):
            row = copy.deepcopy(good); row[field] = value; controls.append(row)
        row = copy.deepcopy(good); row["solver"]["result"] = "sat"; controls.append(row)
        row = copy.deepcopy(good); row["claims"]["all_inputs_return_normally_proved"] = 1; controls.append(row)
        for receipt in controls:
            with self.subTest(receipt=receipt), \
                 patch("hepta.hia_scalar_totality.validate_scalar_totality", return_value=receipt), \
                 patch("hepta.hia_multiversion.build_program_native") as build:
                with self.assertRaisesRegex(MultiversionRejected, "totality"):
                    runtime.publish(candidate)
                build.assert_not_called()
        self.assertEqual(runtime.snapshot()["current_generation"], 0)

    def test_unused_trapping_export_cannot_hide_behind_a_total_entry(self):
        source = total_division()
        helper = arithmetic("int.div.checked", "u8")["functions"][0]
        helper["name"] = "unused_trapping_export"
        source["functions"].append(helper)
        with patch("hepta.hia_multiversion.build_program_native") as build:
            with self.assertRaisesRegex(MultiversionRejected, "totality"):
                self.runtime(source)
            build.assert_not_called()

    def test_signed_wide_and_other_checked_operations_remain_outside_runtime_profile(self):
        for source in (total_division("u32"), total_division("i8"),
                       scalar_program("int.add.checked", typ="u8")):
            if source["functions"][0]["effects"] == []:
                source["functions"][0]["effects"] = ["trap"]
            with self.subTest(source=source), patch("hepta.hia_multiversion.build_program_native") as build:
                with self.assertRaises(MultiversionRejected): self.runtime(source)
                build.assert_not_called()

    def test_proof_snapshots_are_detached_and_explicit_state_survives_code_rollback(self):
        source = total_division()
        runtime = self.runtime(source)
        with ScalarStateSession(runtime, "calculate", 250) as session:
            self.assertEqual(session.step([16], expected_revision=0)["state_after"], 25)
            runtime.publish(specialized(source))
            self.assertEqual(session.step([16], expected_revision=1)["state_after"], 10)
            runtime.rollback()
            self.assertEqual(session.step([0], expected_revision=2)["state_after"], 10)
        snapshot = runtime.snapshot()
        snapshot["generations"][0]["totality_evidence"][0]["status"] = "disproved"
        self.assertEqual(runtime.snapshot()["generations"][0]["totality_evidence"][0]["status"], "proved")


if __name__ == "__main__": unittest.main()
