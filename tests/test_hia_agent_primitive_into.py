"""Opt-in conversion admission and public-only feedback; no model answers."""
import copy
import json
import unittest

from experiments.hia_agent_factorial_v4_20261028 import calibration, evaluator, fixtures
from experiments.hia_agent_factorial_v6_20261028.prompts import public_feedback, prompt
from tools.provider_adapter.llama_cpp_engine import canonical


class PrimitiveIntoTests(unittest.TestCase):
    def setUp(self):
        self.task = calibration.problems()[0]
        self.files = copy.deepcopy(self.task["correct_rust"])
        self.files["client.rs"] = "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::span(a,b).wrapping_add(c.into()) }"

    def admit(self, files=None, *, new=True):
        return evaluator.parse_files(self.task, "rust", canonical({"files": files or self.files}).decode(), primitive_parameter_into=new)

    def test_default_legacy_profile_still_refuses_into(self):
        with self.assertRaisesRegex(ValueError, "RUST_METHOD: into"):
            self.admit(new=False)

    def test_declared_scalar_parameter_preserves_exact_source(self):
        accepted, receipt = self.admit()
        self.assertEqual(accepted, self.files)
        self.assertEqual(receipt["rust_conversion_profile"], "unshadowed_declared_scalar_parameter_into_v1")

    def test_container_and_expression_receivers_are_not_admitted(self):
        for receiver in ("(c)", "(a+b)", "api::span(a,b)", "[c][0]", "unknown"):
            files = copy.deepcopy(self.files)
            files["client.rs"] = files["client.rs"].replace("c.into()", receiver + ".into()")
            with self.assertRaises(ValueError):
                self.admit(files)
        owner = calibration.problems()[2]
        files = copy.deepcopy(owner["correct_rust"])
        files["api.rs"] = "pub fn touch(mut buf:Vec<u8>,x:u8)->Vec<u8> { buf[0]=x.wrapping_add(1); buf.into() }"
        with self.assertRaisesRegex(ValueError, "declared scalar parameter"):
            evaluator.parse_files(owner, "rust", canonical({"files": files}).decode(), primitive_parameter_into=True)

    def test_shadowing_and_binding_patterns_refuse(self):
        for declaration in ("let c=0u32;", "let mut c=0u32;", "let(c,)=(0u32,);", "let ref c=0u32;", "let [c]=[0u32];"):
            files = copy.deepcopy(self.files)
            files["client.rs"] = files["client.rs"].replace("{ api::", "{ " + declaration + " api::")
            with self.assertRaises(ValueError):
                self.admit(files)

    def test_closure_and_method_arguments_refuse(self):
        for replacement in ("c.into(1)", "c.into(a)"):
            files = copy.deepcopy(self.files)
            files["client.rs"] = files["client.rs"].replace("c.into()", replacement)
            with self.assertRaisesRegex(ValueError, "into takes no arguments"):
                self.admit(files)
        files = copy.deepcopy(self.files)
        files["client.rs"] = files["client.rs"].replace("{ api::", "{ let f=|c:u32|->u64 {c.into()}; api::")
        with self.assertRaises(ValueError):
            self.admit(files)

    def test_custom_trait_and_arbitrary_method_remain_forbidden(self):
        for text in ("trait Into {}", "impl Into for u32 {}"):
            files = copy.deepcopy(self.files)
            files["client.rs"] = text + files["client.rs"]
            with self.assertRaises(ValueError):
                self.admit(files)
        files = copy.deepcopy(self.files)
        files["client.rs"] = files["client.rs"].replace("c.into()", "c.into_iter()")
        with self.assertRaises(ValueError):
            self.admit(files)

    def test_qualified_field_receiver_is_not_a_parameter(self):
        with self.assertRaisesRegex(ValueError, "declared scalar parameter"):
            evaluator._primitive_parameter_into("pub fn f(c:u32)->u64 { thing. c.into() }")

    def test_macro_expansion_cannot_substitute_a_container_receiver(self):
        owner = calibration.problems()[2]
        files = copy.deepcopy(owner["correct_rust"])
        files["api.rs"] = "pub fn touch(mut buf:Vec<u8>,x:u8)->Vec<u8> { macro_rules! vec { ($x:ident) => { $x.into() }; } buf[0]=x.wrapping_add(1); vec![buf] }"
        with self.assertRaisesRegex(ValueError, "macro definitions and metavariables"):
            evaluator.parse_files(owner, "rust", canonical({"files": files}).decode(), primitive_parameter_into=True)
        files["api.rs"] = "pub fn touch(mut buf:Vec<u8>,x:u8)->Vec<u8> { macro_rules! vec { ($len:ident) => { buf.$len() }; } buf[0]=x.wrapping_add(1); vec![into] }"
        with self.assertRaisesRegex(ValueError, "macro definitions and metavariables"):
            evaluator.parse_files(owner, "rust", canonical({"files": files}).decode(), primitive_parameter_into=True)
        # Exclude definitions before looking for literal .into sites: expansion
        # must not manufacture a conversion whose receiver escaped admission.
        for body in ("macro_rules! m { () => { c }; } c", "$c"):
            with self.assertRaisesRegex(ValueError, "macro definitions and metavariables"):
                evaluator._primitive_parameter_into("pub fn f(c:u32)->u32 { " + body + " }")

    def test_feedback_only_pairs_already_public_values(self):
        observed = {"status": "observable_wrong", "observations": [[16, 16], [73, 73]],
                    "expected": [[17, 17], [74, 74]], "resource_contract_passed": True, "vm_contract_passed": True}
        task = calibration.problems()[2]
        value = public_feedback(task, {"status": "compiled"}, observed)
        self.assertEqual([r["arguments"] for r in value["public_cases"]], task["public_cases"])
        self.assertEqual(value["public_cases"][0]["entrypoint"], {"expected": 17, "observed": 16})
        text = json.dumps(value)
        for forbidden in ("hidden", "correct_rust", "wrapping_add", "buf[0]"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(value["diagnostic"], "")

    def test_no_public_execution_has_no_invented_counterexample(self):
        value = public_feedback(self.task, {"status": "compile_rejected", "error": {"message": "real diagnostic"}}, None)
        self.assertEqual(value["public_cases"], [])
        self.assertEqual(value["diagnostic"], {"message": "real diagnostic"})

    def test_both_rust_interfaces_disclose_same_primitive_profile(self):
        task = fixtures.make_fixtures()[0]
        for arm in ("rust_full", "rust_query", "calibration"):
            text = prompt(self.task if arm == "calibration" else task, arm)
            self.assertIn("len,into", text)
            self.assertIn("declared scalar function parameter", text)
        for arm in ("hia_full", "hia_query"):
            self.assertNotIn("declared scalar function parameter", prompt(task, arm))


if __name__ == "__main__":
    unittest.main()
