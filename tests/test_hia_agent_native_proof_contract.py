"""Proof scopes are preserved at the real Agent receipt-consumer boundary.

Corrupted retained-record fixtures model storage/producer mistakes; they do not
grant ordinary artifact writers the private verification-receipt authority.
"""
from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import platform
import unittest
from unittest.mock import patch

from hepta.hia_agent_store import AgentRejected, wire
from tests.test_hia_agent_native_tools import AgentToolCase
from tools.hia_agent_native_qualification import add_program, branch_program


class ProofContractTests(AgentToolCase):
    def prepare(self, *, objective=None, typ="u8"):
        workload = {"schema": "hepta.hia.agent.workload.v1",
            "cases": [{"function": "transform", "arguments": [0]}],
            "warmup_iterations": 0, "repetitions": 1}
        self.session.freeze(workload, objective=objective)
        return self.session.import_program(add_program(typ=typ))

    def assert_scope(self, check, candidate, *, base=None, kind="core"):
        self.assertEqual(check["schema"], "hepta.hia.agent.proof-result.v1")
        for field in ("subject", "property", "profile", "assumptions", "checker",
                      "unproved_obligations"):
            self.assertIn(field, check)
        self.assertEqual(check["subject"]["kind"], kind)
        self.assertEqual(check["subject"]["candidate"], candidate)
        self.assertEqual(check["subject"]["candidate_core_sha256"], candidate["sha256"])
        self.assertEqual(check["subject"]["base_program"], base)
        self.assertEqual(check["subject"]["base_core_sha256"], None if base is None else base["sha256"])
        self.assertEqual(check["subject"]["context"], self.session.context)
        self.assertEqual(check["subject"]["target_profile"], self.session.profiles["target"])
        self.assertEqual(check["property"]["id"], check["claim"])
        self.assertTrue(check["property"]["statement"])
        self.assertEqual(check["profile"], self.session.profiles["validation"])
        self.assertEqual(check["validator"], check["profile"])
        self.assertEqual(check["checker"]["installation"], self.service.identities)
        self.assertEqual(check["checker"]["python"]["version"], platform.python_version())
        self.assertTrue(check["assumptions"])
        self.assertTrue({"whole_language_soundness", "core_to_machine_refinement",
                         "abi_ffi_loading", "native_resources"} <=
                        {item["id"] for item in check["unproved_obligations"]})
        self.assertFalse(check["global_safety_proved"])
        self.assertFalse(check["execution_authority_granted"])
        assumptions = self.session.read_json(check["assumptions_artifact"])
        self.assertEqual(assumptions["assumptions"], check["assumptions"])
        self.assertEqual(assumptions["subject"], check["subject"])
        self.assertEqual(assumptions["checker"], check["checker"])
        self.assertFalse(assumptions["assumptions_proved_here"])
        evidence = self.session.read_json(check["evidence_artifact"])
        scoped = {key: value for key, value in check.items()
                  if key not in {"assumptions_artifact", "evidence_artifact"}}
        self.assertEqual(evidence["proof_binding"], scoped)

    def retained_record(self, result):
        return self.session.read_json(result["verification_receipt"])

    def corrupt_receipt(self, record):
        return self.service.store.json(record, "verification-receipt")

    def reject_emit(self, candidate, receipt, *, codegen=None):
        args = self.session.arguments(candidate=candidate, backend_profile=self.session.backend,
            output_kind="object", codegen=codegen or {
                "kind": "canonical", "lowering_profile": self.session.profiles["lowering"]},
            verification_receipts=[receipt])
        result = self.reject("hia_emit", args)
        self.assertEqual(result["error"]["code"], "E_HIA_PROOF_SCOPE", result)

    def test_discovery_teaches_scope_before_verification(self):
        contract = self.session.read_json(self.session.manifest["resources"]["proof_contract"])
        self.assertEqual(contract["schema"], "hepta.hia.agent.proof-result.v1")
        self.assertTrue(contract["all_statuses_require_scope"])
        self.assertFalse(contract["unscoped_legacy_receipts_accepted"])
        self.assertFalse(contract["sample_tests_are_proofs"])
        guide = self.session.read(self.session.manifest["resources"]["proof_contract_guide"]).decode()
        self.assertIn("same-implementation", guide)
        self.assertIn("unproved_obligations", guide)
        profile = self.session.read_json(self.session.manifest["profile_manifests"]["validation"])
        self.assertEqual(profile["proof_result_schema"], contract["schema"])
        self.assertEqual(profile["proved_meaning"], contract["proved_meaning"])

    def test_admission_is_self_contained_even_when_detached_from_response(self):
        candidate = self.prepare()
        result = self.session.verify(candidate)
        check = json.loads(json.dumps(result["checks"][0]))
        self.assertEqual(check["status"], "proved")
        self.assert_scope(check, candidate)
        self.assertEqual(check["checker"]["name"], "hepta.hia_program.verify_program")
        self.assertIn("admission predicate", check["property"]["statement"])
        self.assertIsNone(check["checker"]["solver"])
        self.assertEqual(self.retained_record(result)["checks"], result["checks"])
        self.service._verification(result["verification_receipt"], self.session.context, candidate)

    def test_reflexivity_retains_both_exact_program_references(self):
        base = self.prepare()
        candidate = self.session.import_program(add_program())
        result = self.session.verify(candidate, base=base, claims=["behavior_equivalence"])
        check = result["checks"][0]
        self.assertEqual(check["status"], "proved")
        self.assertEqual(check["checker"]["method"], "canonical_core_identity")
        self.assert_scope(check, candidate, base=base)
        self.service._verification(result["verification_receipt"], self.session.context, candidate)

    def test_finite_domain_is_complete_despite_single_case_workload(self):
        base = self.prepare()
        candidate = self.session.import_program(add_program(optimized=True))
        result = self.session.verify(candidate, base=base, claims=["behavior_equivalence"])
        check = result["checks"][0]
        self.assertEqual(check["status"], "proved")
        self.assertEqual(check["checker"]["method"], "finite_domain")
        evidence = self.session.read_json(check["evidence_artifact"])
        self.assertEqual((evidence["checked"], evidence["required"]), (256, 256))
        self.assertTrue(evidence["complete"])
        self.assert_scope(check, candidate, base=base)
        self.service._verification(result["verification_receipt"], self.session.context, candidate)

    def test_a_matching_workload_example_does_not_hide_a_counterexample(self):
        base = self.prepare()
        changed = add_program(optimized=True)
        block = changed["functions"][0]["blocks"][0]
        block["ops"].extend([
            {"op": "const", "args": [], "out": [{"name": "maximum", "type": "u8"}], "attrs": {"value": 255}},
            {"op": "const", "args": [], "out": [{"name": "zero", "type": "u8"}], "attrs": {"value": 0}},
            {"op": "compare.eq", "args": ["x", "maximum"], "out": [{"name": "edge", "type": "bool"}], "attrs": {}},
            {"op": "select", "args": ["edge", "zero", "answer"], "out": [{"name": "selected", "type": "u8"}], "attrs": {}},
        ])
        block["term"]["values"] = ["selected"]
        candidate = self.session.import_program(changed)
        result = self.session.verify(candidate, base=base, claims=["behavior_equivalence"])
        check = result["checks"][0]
        self.assertEqual(check["status"], "refuted")
        evidence = self.session.read_json(check["evidence_artifact"])
        self.assertEqual(evidence["counterexample"]["arguments"], [255])
        self.assertEqual(evidence["checked"], 256)
        self.assert_scope(check, candidate, base=base)
        self.assertIn("requested_property", {x["id"] for x in check["unproved_obligations"]})

    def test_incomplete_reference_enumeration_remains_unknown_with_full_scope(self):
        base = self.prepare()
        candidate = self.session.import_program(add_program(optimized=True))
        with patch("hepta.hia_agent_service._vm_observation", return_value={"status": "budget_exceeded"}):
            result = self.session.verify(candidate, base=base, claims=["behavior_equivalence"])
        check = result["checks"][0]
        self.assertEqual(check["status"], "unknown")
        self.assertEqual(check["checker"]["method"], "finite_domain")
        self.assert_scope(check, candidate, base=base)
        self.service._verification(result["verification_receipt"], self.session.context, candidate)

    @unittest.skipUnless(importlib.util.find_spec("z3"), "optional pinned Z3 is not installed")
    def test_compositional_proof_names_the_actual_solver_and_excluded_vm_ticks(self):
        base = self.prepare(typ="u32")
        candidate = self.session.import_program(add_program(optimized=True, typ="u32"))
        result = self.session.verify(candidate, base=base, claims=["behavior_equivalence"])
        check = result["checks"][0]
        self.assertEqual(check["status"], "proved", check)
        self.assertEqual(check["checker"]["method"], "compositional_scalar_effect")
        self.assertEqual(check["checker"]["solver"]["name"], "Z3")
        self.assertEqual(check["checker"]["solver"]["version"], "4.15.4")
        for field in ("binding_sha256", "library_sha256"):
            self.assertRegex(check["checker"]["solver"][field], r"^[0-9a-f]{64}$")
        self.assertRegex(check["checker"]["auxiliary_checker_sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("vm_tick_preservation", {x["id"] for x in check["unproved_obligations"]})
        self.assert_scope(check, candidate, base=base)
        self.service._verification(result["verification_receipt"], self.session.context, candidate)

    def test_canonical_lowering_unsupported_keeps_explicit_open_obligations(self):
        candidate = self.prepare()
        result = self.session.verify(candidate, claims=["lowering_refinement"], subject={
            "kind": "canonical_lowering", "backend_profile": self.session.backend,
            "lowering_profile": self.session.profiles["lowering"]})
        check = result["checks"][0]
        self.assertEqual(check["status"], "unsupported")
        self.assert_scope(check, candidate, kind="canonical_lowering")
        self.assertIn("requested_property", {x["id"] for x in check["unproved_obligations"]})
        self.service._verification(result["verification_receipt"], self.session.context, candidate)

    def test_missing_scope_fields_and_legacy_receipts_are_rejected_by_emission(self):
        candidate = self.prepare()
        result = self.session.verify(candidate)
        record = self.retained_record(result)
        for field in ("schema", "subject", "property", "profile", "assumptions",
                      "checker", "unproved_obligations"):
            with self.subTest(field=field):
                changed = deepcopy(record)
                del changed["checks"][0][field]
                self.reject_emit(candidate, self.corrupt_receipt(changed))
        legacy = deepcopy(record)
        keep = {"claim", "status", "domain", "validator", "assumptions_artifact", "evidence_artifact"}
        legacy["checks"][0] = {key: value for key, value in legacy["checks"][0].items() if key in keep}
        self.reject_emit(candidate, self.corrupt_receipt(legacy))

    def test_changed_subject_profile_checker_assumptions_and_obligations_are_rejected(self):
        candidate = self.prepare()
        record = self.retained_record(self.session.verify(candidate))
        mutations = [
            lambda check: check["subject"].update(candidate_core_sha256="0" * 64),
            lambda check: check["subject"]["context"].update(sha256="0" * 64),
            lambda check: check["subject"]["target_profile"].update(sha256="0" * 64),
            lambda check: check["profile"].update(sha256="0" * 64),
            lambda check: check["validator"].update(sha256="0" * 64),
            lambda check: check["checker"]["installation"].update(worker_sha256="0" * 64),
            lambda check: check["property"].update(statement="All native executions are globally safe."),
            lambda check: check.update(domain="Every program and every environment"),
            lambda check: check["assumptions"][0].update(statement="No premise is required."),
            lambda check: check["unproved_obligations"].pop(),
            lambda check: check.update(global_safety_proved=True),
            lambda check: check.update(execution_authority_granted=True),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                changed = deepcopy(record)
                mutate(changed["checks"][0])
                self.reject_emit(candidate, self.corrupt_receipt(changed))

    def test_rebound_assumptions_or_evidence_cannot_be_substituted(self):
        candidate = self.prepare()
        record = self.retained_record(self.session.verify(candidate))
        other = self.session.import_program(add_program(increment=8))
        other_check = self.session.verify(other)["checks"][0]
        for field in ("assumptions_artifact", "evidence_artifact"):
            with self.subTest(field=field):
                changed = deepcopy(record)
                changed["checks"][0][field] = other_check[field]
                self.reject_emit(candidate, self.corrupt_receipt(changed))

    def test_restamping_metadata_cannot_upgrade_incomplete_evidence(self):
        base = self.prepare()
        candidate = self.session.import_program(add_program(optimized=True))
        with patch("hepta.hia_agent_service._vm_observation", return_value={"status": "budget_exceeded"}):
            result = self.session.verify(candidate, base=base, claims=["behavior_equivalence"])
        record = self.retained_record(result)
        check = record["checks"][0]
        evidence = self.session.read_json(check["evidence_artifact"])
        check["status"] = evidence["proof_binding"]["status"] = "proved"
        check["evidence_artifact"] = self.service.store.json(evidence, "verification-evidence")
        self.reject_emit(candidate, self.corrupt_receipt(record))

    def test_restamping_metadata_cannot_turn_unsupported_lowering_into_a_proof(self):
        candidate = self.prepare()
        result = self.session.verify(candidate, claims=["lowering_refinement"], subject={
            "kind": "canonical_lowering", "backend_profile": self.session.backend,
            "lowering_profile": self.session.profiles["lowering"]})
        record = self.retained_record(result)
        check = record["checks"][0]
        evidence = self.session.read_json(check["evidence_artifact"])
        check["status"] = evidence["proof_binding"]["status"] = "proved"
        check["evidence_artifact"] = self.service.store.json(evidence, "verification-evidence")
        self.reject_emit(candidate, self.corrupt_receipt(record))

    def test_conditional_machine_plan_preserves_scope_at_emission(self):
        self.prepare()
        candidate = self.session.import_program(branch_program())
        plan = {"schema": "hepta.hia.agent.block-layout.v1", "core_sha256": candidate["sha256"],
                "block_order": {"select_value": ["entry", "no", "yes"]}}
        plan_ref = self.session.artifact(plan)
        result = self.session.verify(candidate, claims=["lowering_refinement"], subject={
            "kind": "agent_machine_plan", "backend_profile": self.session.backend,
            "plan_profile": self.session.profiles["plan"], "plan": plan_ref})
        check = result["checks"][0]
        self.assertEqual(check["status"], "proved")
        self.assert_scope(check, candidate, kind="agent_machine_plan")
        self.assertTrue({"canonical_lowering_correctness", "encoder_and_relocation_correctness"} <=
                        {item["id"] for item in check["assumptions"]})
        codegen = {"kind": "agent_plan", "plan_profile": self.session.profiles["plan"],
                   "plan": plan_ref, "verification_receipt": result["verification_receipt"]}
        emitted = self.session.emit(candidate, kind="object", codegen=codegen)
        self.assertFalse(emitted["native_execution_observed"])
        changed = self.retained_record(result)
        changed["checks"][0]["assumptions"] = changed["checks"][0]["assumptions"][:1]
        bad = self.corrupt_receipt(changed)
        self.reject_emit(candidate, bad, codegen={**codegen, "verification_receipt": bad})

    def test_actual_object_encoding_proof_exposes_same_implementation_limit(self):
        candidate = self.prepare()
        core = self.session.verify(candidate)
        built = self.session.emit(candidate, kind="object", receipts=[core["verification_receipt"]])
        result = self.session.encoding(candidate, built)
        check = result["checks"][0]
        self.assertEqual(check["status"], "proved")
        self.assert_scope(check, candidate, kind="native_artifact")
        self.assertEqual(check["subject"]["native_artifact"], built["native_artifact"])
        self.assertEqual(check["subject"]["build_receipt"], built["build_receipt"])
        self.assertIn("same installed implementation", check["property"]["statement"])
        self.assertIn("independent_encoding_semantics",
                      {item["id"] for item in check["unproved_obligations"]})
        self.service._verification(result["verification_receipt"], self.session.context, candidate)
        context = self.service._context(self.session.context)
        self.service._required_claims(context, built["native_artifact"],
            [core["verification_receipt"], result["verification_receipt"]])

    def test_changed_reemitted_bytes_are_refuted_without_a_semantic_safety_claim(self):
        candidate = self.prepare()
        built = self.session.emit(candidate, kind="object")
        original_compile = self.service._compile

        def changed_compile(*args):
            data, metadata = original_compile(*args)
            return data[:-1] + bytes([data[-1] ^ 1]), metadata

        with patch.object(self.service, "_compile", side_effect=changed_compile):
            result = self.session.encoding(candidate, built)
        check = result["checks"][0]
        self.assertEqual(check["status"], "refuted")
        self.assert_scope(check, candidate, kind="native_artifact")
        self.assertFalse(self.session.read_json(check["evidence_artifact"])["bytes_equal"])

    def test_required_acceptance_claims_reject_valid_status_with_missing_scope(self):
        candidate = self.prepare()
        core = self.session.verify(candidate)
        built = self.session.emit(candidate, kind="object")
        encoded = self.session.encoding(candidate, built)
        record = self.retained_record(core)
        del record["checks"][0]["unproved_obligations"]
        with self.assertRaises(AgentRejected) as caught:
            self.service._required_claims(self.service._context(self.session.context),
                built["native_artifact"],
                [self.corrupt_receipt(record), encoded["verification_receipt"]])
        self.assertEqual(caught.exception.code, "E_HIA_PROOF_SCOPE")

    def test_unsupported_scope_cannot_satisfy_a_required_lowering_property(self):
        objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
            "required_claims": ["core_admission", "lowering_refinement"],
            "allow_unchanged": True, "min_improvement_ratio": 0.0}
        candidate = self.prepare(objective=objective)
        core = self.session.verify(candidate)
        lowering = self.session.verify(candidate, claims=["lowering_refinement"], subject={
            "kind": "canonical_lowering", "backend_profile": self.session.backend,
            "lowering_profile": self.session.profiles["lowering"]})
        built = self.session.emit(candidate, kind="object")
        with self.assertRaises(AgentRejected) as caught:
            self.service._required_claims(self.service._context(self.session.context),
                built["native_artifact"],
                [core["verification_receipt"], lowering["verification_receipt"]])
        self.assertEqual(caught.exception.code, "E_HIA_CLAIM_REQUIRED")


    def last_verification_call(self):
        return next(row for row in reversed(self.client.records) if row["tool"] == "hia_verify")

    def replace_cached_response(self, response):
        count = self.service.store.db.execute(
            "UPDATE requests SET response=? WHERE tool='hia_verify'",
            (wire(response).decode(),)).rowcount
        self.assertEqual(count, 1)

    def test_exact_verification_replay_preserves_the_original_scoped_result(self):
        candidate = self.prepare()
        self.session.verify(candidate)
        recorded = self.last_verification_call()
        replayed = self.client.call("hia_verify", recorded["arguments"])
        self.assertEqual(replayed, recorded["response"])
        self.assert_scope(replayed["result"]["checks"][0], candidate)

    def test_cached_legacy_result_cannot_bypass_the_current_output_contract(self):
        candidate = self.prepare()
        self.session.verify(candidate)
        recorded = self.last_verification_call()
        changed = deepcopy(recorded["response"])
        del changed["result"]["checks"][0]["checker"]
        self.replace_cached_response(changed)
        result = self.reject("hia_verify", recorded["arguments"])
        self.assertEqual(result["error"]["code"], "E_HIA_PROOF_SCOPE")

    def test_cached_valid_shape_cannot_change_the_retained_checker_conclusion(self):
        base = self.prepare()
        candidate = self.session.import_program(add_program(optimized=True))
        with patch("hepta.hia_agent_service._vm_observation", return_value={"status": "budget_exceeded"}):
            self.session.verify(candidate, base=base, claims=["behavior_equivalence"])
        recorded = self.last_verification_call()
        changed = deepcopy(recorded["response"])
        self.assertEqual(changed["result"]["checks"][0]["status"], "unknown")
        changed["result"]["checks"][0]["status"] = "proved"
        self.replace_cached_response(changed)
        result = self.reject("hia_verify", recorded["arguments"])
        self.assertEqual(result["error"]["code"], "E_HIA_PROOF_SCOPE")



    def test_verification_replay_rejects_changed_installed_checker_source(self):
        candidate = self.prepare()
        self.session.verify(candidate)
        recorded = self.last_verification_call()
        changed = {**self.service.identities, "worker_sha256": "0" * 64}
        with patch("hepta.hia_agent_service.installation_manifest", return_value=changed):
            result = self.reject("hia_verify", recorded["arguments"])
        self.assertEqual(result["error"]["code"], "E_HIA_IMPLEMENTATION_STALE")


if __name__ == "__main__":
    unittest.main()
