"""Public SMT proof scope must survive failures and reject broader receipts."""
from __future__ import annotations

import copy
from hashlib import sha256
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_bounded_unroll import validate_bounded_translation, verify_bounded_translation_receipt
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_scalar_call_validation import validate_scalar_calls
from hepta.hia_scalar_proof_contract import FIELDS, SCHEMA, _source_identity
from hepta.hia_scalar_totality import validate_scalar_totality, validate_scalar_call_totality
from hepta.hia_translation_validation import validate_translation, verify_translation_receipt
from tests.test_hia_bounded_unroll import counted, candidate
from tests.test_hia_program import arithmetic
from tests.test_hia_scalar_call_validation import signed_calls
from tests.test_hia_scalar_totality import total_division, guarded_call_division
from tests.test_hia_translation_validation import identity


class ScalarProofScopeTests(unittest.TestCase):
    def public_checks(self, **kwargs):
        primitive, calls, loop = identity("u8"), signed_calls(), counted(1)
        unrolled = candidate(loop, 1)
        return {
            "primitive_equivalence": lambda: validate_translation(primitive, primitive, **kwargs),
            "call_equivalence": lambda: validate_scalar_calls(calls, calls, function="calculate", **kwargs),
            "bounded_equivalence": lambda: validate_bounded_translation(
                loop, unrolled, function="calculate", max_backedges=1, **kwargs),
            "primitive_totality": lambda: validate_scalar_totality(total_division(), **kwargs),
            "call_totality": lambda: validate_scalar_call_totality(
                guarded_call_division(), function="calculate", **kwargs),
        }

    def assert_scope(self, result):
        self.assertEqual(result["proof_scope_schema"], SCHEMA)
        self.assertTrue(all(name in result for name in FIELDS), result)
        self.assertIs(result["execution_authority"], False)
        self.assertIs(result["checker"]["machine_checked_implementation"], False)
        self.assertIn("global safety", result["proved_meaning"])
        self.assertTrue(result["property"]["id"])
        self.assertTrue(result["property"]["statement"])
        self.assertTrue(result["profile"])
        for field in ("assumptions", "unproved_obligations"):
            self.assertTrue(result[field])
            self.assertTrue(all(row["id"] and row["statement"] for row in result[field]))
        obligations = {row["id"] for row in result["unproved_obligations"]}
        self.assertTrue({"core_to_machine", "abi_ffi_loading", "resources", "checker_soundness"} <= obligations)
        self.assertEqual("requested_property" in obligations, result["status"] != "proved")
        # The published record is inert, ordinary serializable JSON.
        json.dumps(result, allow_nan=False)

    def test_all_five_real_smt_proofs_identify_exact_subject_checker_and_property(self):
        properties = set()
        for name, check in self.public_checks().items():
            with self.subTest(producer=name):
                result = check()
                self.assertEqual(result["status"], "proved", result)
                self.assert_scope(result)
                properties.add(result["property"]["id"])
                checker = result["checker"]
                self.assertEqual(checker["kind"], "trusted_executable_smt_checker")
                self.assertEqual(checker["solver"]["version"], "4.15.4")
                self.assertEqual(len(checker["solver"]["library_sha256"]), 64)
                for path, digest in checker["source_identity"].items():
                    self.assertEqual(digest, sha256((Path(__file__).parents[1] / "hepta" / path).read_bytes()).hexdigest())
                keys = ("program_sha256", "input_sha256") if "totality" in name else (
                    "before_sha256", "after_sha256", "before_input_sha256", "after_input_sha256")
                for key in keys:
                    self.assertEqual(result["subject"][key], result[key])
                    self.assertEqual(len(result["subject"][key]), 64)
        self.assertEqual(len(properties), 5)

    def test_bad_timeout_is_scoped_unknown_for_every_entrypoint(self):
        for name, check in self.public_checks(timeout_ms=0).items():
            with self.subTest(producer=name):
                result = check()
                self.assertEqual(result["status"], "unknown", result)
                self.assert_scope(result)
                self.assertIsNone(result["checker"]["solver"])

    def test_missing_solver_stays_scoped_unknown_for_every_entrypoint(self):
        targets = ("hepta.hia_translation_validation._z3_module",
                   "hepta.hia_scalar_call_validation._z3_module",
                   "hepta.hia_bounded_unroll._z3_module")
        from contextlib import ExitStack
        with ExitStack() as stack:
            for target in targets:
                stack.enter_context(patch(target, side_effect=ImportError("solver unavailable")))
            for name, check in self.public_checks().items():
                with self.subTest(producer=name):
                    result = check()
                    self.assertEqual(result["status"], "unknown", result)
                    self.assert_scope(result)
                    self.assertIsNone(result["checker"]["solver"])

    def test_replayed_counterexamples_keep_their_proof_scope(self):
        calls = signed_calls()
        changed = copy.deepcopy(calls)
        changed["functions"][0]["blocks"][0]["ops"][-1]["op"] = "int.add.checked"
        loop = counted(2)
        results = [
            validate_translation(arithmetic("int.add.wrap", "u8"), arithmetic("int.sub.wrap", "u8")),
            validate_scalar_calls(calls, changed, function="calculate"),
            validate_bounded_translation(loop, candidate(loop, 1), function="calculate", max_backedges=1),
            validate_scalar_totality(arithmetic("int.div.checked", "u8")),
            validate_scalar_call_totality(calls, function="calculate"),
        ]
        for result in results:
            with self.subTest(checker=result["checker"]["name"]):
                self.assertEqual(result["status"], "disproved", result)
                self.assertTrue(result["counterexample"])
                self.assert_scope(result)

    def test_equivalence_of_a_trapping_program_never_claims_totality(self):
        program = arithmetic("int.div.checked", "u8")
        equivalent = validate_translation(program, program)
        total = validate_scalar_totality(program)
        self.assertEqual(equivalent["status"], "proved")
        self.assertEqual(total["status"], "disproved")
        self.assertNotEqual(equivalent["property"]["id"], total["property"]["id"])
        self.assertIn("normal_return_totality", {x["id"] for x in equivalent["unproved_obligations"]})
        self.assertNotIn("normal_return_totality", {x["id"] for x in total["unproved_obligations"]})

    def test_canonical_input_identity_and_transitive_callee_are_bound(self):
        source = signed_calls()
        first = validate_scalar_calls(source, source, function="calculate")
        changed = copy.deepcopy(source)
        # Primitive input identity is canonical JSON; whitespace is not a new Core.
        raw_a, raw_b = json.dumps(source).encode(), json.dumps(source, indent=2).encode()
        a, b = (validate_scalar_calls(raw, raw, function="calculate") for raw in (raw_a, raw_b))
        self.assertEqual(a["subject"]["before_sha256"], b["subject"]["before_sha256"])
        self.assertEqual(a["subject"]["before_input_sha256"], b["subject"]["before_input_sha256"])
        self.assertEqual(a["subject"]["before_input_sha256"], verify_program(source).input_sha256)
        self.assertIn("helper", first["subject"]["call_closures"][0])
        changed["functions"][1]["blocks"][2]["term"] = {"op": "ret", "values": ["p"]}
        second = validate_scalar_calls(changed, changed, function="calculate")
        self.assertEqual(second["status"], "proved", second)
        self.assertNotEqual(first["subject"]["before_sha256"], second["subject"]["before_sha256"])

    def test_bound_is_a_proved_obligation_and_nested_equivalence_has_its_own_scope(self):
        loop = counted(1)
        result = validate_bounded_translation(loop, candidate(loop, 1), function="calculate", max_backedges=1)
        self.assertEqual(result["status"], "proved", result)
        self.assertEqual(result["subject"]["max_backedges"], 1)
        self.assertEqual(result["subject"]["feedback_edge"], result["feedback_edge"])
        self.assertIn("checked obligation", result["property"]["statement"])
        self.assert_scope(result["equivalence"])
        self.assertEqual(result["equivalence"]["subject"]["before_sha256"], result["reference_sha256"])

    def test_scope_drift_or_absence_cannot_keep_proof_claims(self):
        original = _source_identity("validate_translation")
        changed = dict(original, **{"hia_schema.py": "0" * 64})
        cases = ([original, changed], [OSError("unreadable"), original])
        for observations in cases:
            with self.subTest(observations=observations), patch(
                    "hepta.hia_scalar_proof_contract._source_identity", side_effect=observations):
                result = validate_translation(identity(), identity())
            self.assertEqual(result["status"], "unknown", result)
            self.assertFalse(any(result["claims"].values()))
            self.assert_scope(result)

    def test_missing_actual_solver_identity_cannot_leave_a_proved_status(self):
        with patch("hepta.hia_optimization._solver_identity", return_value=None):
            result = validate_translation(identity(), identity())
        self.assertEqual(result["status"], "unknown", result)
        self.assertEqual(result["reason"], "scope_solver_identity_unavailable")
        self.assert_scope(result)

    def test_unscoped_or_broadened_primitive_receipts_are_rejected_at_use(self):
        program = identity("u8")
        receipt = validate_translation(program, program)
        self.assertEqual(verify_translation_receipt(program, program, receipt)["status"], "proved")
        for key in FIELDS:
            for mutation in ("remove", "replace"):
                forged = copy.deepcopy(receipt)
                if mutation == "remove":
                    del forged[key]
                elif key in {"assumptions", "unproved_obligations"}:
                    forged[key] = []
                elif key == "profile":
                    forged[key] = "all_programs"
                else:
                    forged[key] = {"id": "global_safety"}
                with self.subTest(field=key, mutation=mutation), self.assertRaises(HIAProgramRejected):
                    verify_translation_receipt(program, program, forged)

    def test_python_equality_spoof_cannot_weaken_scope(self):
        class EqualToAnything(list):
            def __eq__(self, _other):
                return True
        program = identity()
        forged = validate_translation(program, program)
        forged["assumptions"] = EqualToAnything()
        with self.assertRaises(HIAProgramRejected):
            verify_translation_receipt(program, program, forged)

    def test_bounded_receipt_rejects_missing_and_nested_broadened_scope(self):
        loop = counted(1)
        after = candidate(loop, 1)
        receipt = validate_bounded_translation(loop, after, function="calculate", max_backedges=1)
        self.assertEqual(verify_bounded_translation_receipt(loop, after, receipt,
                         function="calculate", max_backedges=1)["status"], "proved")
        for nested in (False, True):
            forged = copy.deepcopy(receipt)
            (forged["equivalence"] if nested else forged)["unproved_obligations"] = []
            with self.subTest(nested=nested), self.assertRaises(HIAProgramRejected):
                verify_bounded_translation_receipt(loop, after, forged, function="calculate", max_backedges=1)

    def test_unsupported_core_version_is_not_promoted_by_scope(self):
        program = identity()
        program["schema"] = "hepta.hia.program.v8"
        loop = counted(1)
        after = candidate(loop, 1)
        loop["schema"] = "hepta.hia.program.v8"
        for result in (validate_translation(program, program), validate_scalar_totality(program),
                       validate_scalar_calls(program, program, function="calculate"),
                       validate_scalar_call_totality(program, function="calculate"),
                       validate_bounded_translation(loop, after, function="calculate", max_backedges=1)):
            self.assertEqual(result["status"], "unknown", result)
            self.assert_scope(result)


if __name__ == "__main__":
    unittest.main()
