"""Exercise independent machine validation at the Agent tool boundary.

These tests compile and validate real retained ELF bytes on Linux. Private-store
corruption fixtures are not a claim that public artifact writers can mint
verification/build receipts. No negative-control image is executed.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import importlib.util
import platform
import shutil
import unittest
from unittest.mock import patch

from hepta.hia_agent_store import AgentRejected, digest
from hepta.hia_machine_x64 import Code
from tests.test_hia_agent_native_tools import AgentToolCase
from tools.hia_agent_native_qualification import add_program


AVAILABLE = (platform.system() == "Linux"
             and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None
             and importlib.util.find_spec("z3") is not None)
METHOD = "independent_safe_core_machine_validation"
PROFILE = "hia.safe-core.unsigned-acyclic-single-borrow.supplied-elf.x86_64.v1"
OBLIGATIONS = [
    ("caller_contract_nonvacuous", "sat"),
    ("machine_memory_access_bounds", "unsat"),
    ("sysv_stack_alignment_and_preservation", "unsat"),
    ("all_inputs_reach_a_terminal_model_outcome", "unsat"),
    ("core_to_final_image_return_abort_and_caller_bytes", "unsat"),
]


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class AgentNativeMachineValidationTests(AgentToolCase):
    def prepare(self, *, document=None, kind="shared"):
        workload = {"schema": "hepta.hia.agent.workload.v1",
            "cases": [{"function": "transform", "arguments": [0],
                       "expected": {"status": "returned", "values": [7]}}],
            "warmup_iterations": 0, "repetitions": 1}
        objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
            "required_claims": ["core_admission", "lowering_refinement"],
            "allow_unchanged": True, "min_improvement_ratio": 0.0}
        self.session.freeze(workload, objective=objective)
        candidate = self.session.import_program(document or add_program(optimized=True, typ="u32"))
        admitted = self.session.verify(candidate)
        built = self.session.emit(candidate, kind=kind, receipts=[admitted["verification_receipt"]])
        return candidate, admitted, built

    def native_arguments(self, candidate, built):
        return self.session.arguments(candidate=candidate, base_program=None,
            validation_profile=self.session.profiles["validation"],
            claims=["lowering_refinement"],
            subject={"kind": "native_artifact", "backend_profile": self.session.backend,
                     "native_artifact": built["native_artifact"], "build_receipt": built["build_receipt"]})

    def native_verify(self, candidate, built):
        return self.client.result("hia_verify", self.native_arguments(candidate, built))

    def read_proof(self, result):
        record = self.session.read_json(result["verification_receipt"])
        check = record["checks"][0]
        evidence = self.session.read_json(check["evidence_artifact"])
        assumptions = self.session.read_json(check["assumptions_artifact"])
        return record, evidence, assumptions

    def rewritten_receipt(self, record, evidence, assumptions=None):
        record = deepcopy(record)
        check = record["checks"][0]
        if assumptions is not None:
            check["assumptions_artifact"] = self.service.store.json(assumptions, "verification-assumptions")
        # Restamp the duplicate binding to ensure rejection does not rely only
        # on an unchanged copy of metadata. The actual theorem still matters.
        evidence = deepcopy(evidence)
        evidence["proof_binding"] = {key: value for key, value in check.items()
                                     if key not in {"assumptions_artifact", "evidence_artifact"}}
        check["evidence_artifact"] = self.service.store.json(evidence, "verification-evidence")
        return self.service.store.json(record, "verification-receipt")

    def reject_consumption(self, built, admitted, proof):
        return self.reject("hia_evaluate", self.session.arguments(
            baseline_artifact=built["native_artifact"], candidate_artifact=built["native_artifact"],
            build_receipt=built["build_receipt"],
            verification_receipts=[admitted["verification_receipt"], proof]))

    def corrupt_artifact_bytes(self, ref):
        path = self.state_root / "artifacts" / ref["sha256"]
        original = path.read_bytes()
        self.assertTrue(original)
        path.chmod(0o600)
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))

    def assert_adoption_identity(self, adopted, candidate, built, receipts):
        adoption = self.session.read_json(adopted["adoption_receipt"])
        identity = adoption["artifact_identity"]
        build = self.session.read_json(built["build_receipt"])
        self.assertEqual(identity["schema"], "hepta.hia.agent.adopted-artifact-identity.v1")
        self.assertEqual(identity["candidate"], candidate)
        self.assertEqual(identity["core_sha256"], candidate["sha256"])
        self.assertEqual(identity["input_sha256"], build["native_build"]["input_sha256"])
        self.assertEqual(identity["context"], self.session.context)
        for field in ("codegen", "object_artifact", "object_sha256", "output_kind",
                      "target_profile", "backend_profile", "installation"):
            self.assertEqual(identity[field], build[field])
        self.assertEqual(identity["machine_plan_sha256"], build["native_build"]["machine_plan_sha256"])
        self.assertEqual(identity["object_sha256"], sha256(self.session.read(identity["object_artifact"])).hexdigest())
        self.assertEqual(identity["native_artifact"], built["native_artifact"])
        self.assertEqual(identity["final_image_sha256"], sha256(self.session.read(built["native_artifact"])).hexdigest())
        self.assertEqual(identity["build_receipt"], built["build_receipt"])
        self.assertEqual(identity["abi_signatures"], build["signatures"])
        self.assertEqual(identity["abi_sha256"], digest(build["signatures"]))
        self.assertEqual(identity["target_slot"], adopted["target_slot"])
        self.assertEqual(identity["current"], adopted["current"])
        self.assertFalse(identity["projection_is_execution_authority"])
        self.assertEqual([row["verification_receipt"] for row in identity["proofs"]], receipts)
        for row, ref in zip(identity["proofs"], receipts):
            checks = self.session.read_json(ref)["checks"]
            self.assertEqual(row["checks"], [{name: check[name] for name in (
                "claim", "status", "subject", "profile", "evidence_artifact", "assumptions_artifact")}
                for check in checks])
        return identity

    def test_shared_scalar_proof_binds_the_actual_core_object_final_and_solver(self):
        candidate, _admitted, built = self.prepare()
        build = self.session.read_json(built["build_receipt"])
        object_bytes, metadata = self.service.store.get(build["object_artifact"], kind="build-object")
        self.assertEqual(metadata["schema"], "hepta.hia.agent.build-object.v1")
        self.assertEqual(metadata["core_sha256"], candidate["sha256"])
        self.assertEqual(metadata["installation"], self.service.identities)
        self.assertIsNone(metadata["machine_plan_sha256"])
        self.assertEqual(build["object_sha256"], sha256(object_bytes).hexdigest())
        self.assertEqual(build["native_build"]["object_artifact"], build["object_artifact"])

        result = self.native_verify(candidate, built)
        record, evidence, _assumptions = self.read_proof(result)
        check = record["checks"][0]
        self.assertEqual(check["status"], "proved")
        self.assertEqual(check["checker"]["method"], METHOD)
        self.assertEqual(check["checker"]["name"], "hepta.hia_safe_core.validate_safe_core_artifact")
        self.assertEqual(check["subject"]["kind"], "native_artifact")
        self.assertFalse(check["global_safety_proved"])
        self.assertFalse(check["execution_authority_granted"])
        self.assertEqual(evidence["method"], METHOD)
        self.assertEqual(evidence["profile"], PROFILE)
        binding = evidence["artifact_binding"]
        self.assertEqual(binding["candidate_core_sha256"], candidate["sha256"])
        self.assertEqual(binding["native_artifact"], built["native_artifact"])
        self.assertEqual(binding["build_receipt"], built["build_receipt"])
        self.assertEqual(binding["object_artifact"], build["object_artifact"])
        self.assertEqual(binding["object_sha256"], sha256(object_bytes).hexdigest())
        self.assertEqual(binding["final_image_sha256"], built["native_artifact"]["sha256"])
        self.assertEqual(binding["output_kind"], "shared")
        self.assertEqual(binding["foreign_buffer_exports"], [])
        self.assertIn("transform", binding["entry_symbols"])
        validation = evidence["validation"]
        self.assertEqual(validation["profile"], PROFILE)
        self.assertFalse(validation["checker"]["producer_reemission_used"])
        self.assertEqual([(row["name"], row["expected"]) for row in validation["obligations"]], OBLIGATIONS)
        self.assertEqual([row["result"] for row in validation["obligations"]],
                         [expected for _name, expected in OBLIGATIONS])
        self.assertTrue(validation["claims"]["all_input_refinement_in_independent_model"])
        self.assertFalse(validation["claims"]["machine_checked_isa_refinement_proved"])
        self.assertFalse(validation["claims"]["python_checker_soundness_proved"])
        self.assertFalse(validation["claims"]["whole_language_soundness_proved"])
        self.assertEqual(check["checker"]["solver"], evidence["solver"])
        self.assertEqual(evidence["solver"], validation["solver"])
        self.assertEqual(evidence["solver"]["version"], "4.15.4")
        for key in ("binding_sha256", "library_sha256"):
            self.assertRegex(evidence["solver"][key], r"^[0-9a-f]{64}$")
        self.assertEqual(len(evidence["queries"]), 5)
        premise_ids = {row["id"] for row in check["assumptions"]}
        self.assertNotIn("canonical_lowering_correctness", premise_ids)
        self.assertNotIn("encoder_and_relocation_correctness", premise_ids)

    def test_reverification_and_consumption_do_not_call_the_emitter_or_linker(self):
        candidate, admitted, built = self.prepare()
        with patch("hepta.hia_program_native.emit_program_machine",
                   side_effect=AssertionError("independent verification invoked the emitter")), \
             patch("hepta.hia_program_native.compile_program_machine",
                   side_effect=AssertionError("independent verification invoked the linker")):
            result = self.native_verify(candidate, built)
            self.assertEqual(result["checks"][0]["status"], "proved")
            self.service._verification(result["verification_receipt"], self.session.context, candidate)
            self.service._required_claims(self.service._context(self.session.context),
                built["native_artifact"],
                [admitted["verification_receipt"], result["verification_receipt"]])

    def test_native_proof_flows_through_evaluation_adoption_and_a_consumer_lease(self):
        candidate, admitted, built = self.prepare()
        result = self.native_verify(candidate, built)
        receipts = [admitted["verification_receipt"], result["verification_receipt"]]
        evaluated = self.session.evaluate(built, built, receipts=receipts)
        self.assertEqual(evaluated["outcome"], "unchanged")
        self.assertTrue(evaluated["planned_workload_complete"])
        adopted = self.client.result("hia_adopt", self.session.arguments(
            target_slot="machine-proof-consumer", expected_current={"generation": "0", "epoch": "0"},
            candidate_artifact=built["native_artifact"],
            evaluation_receipt=evaluated["evaluation_receipt"], verification_receipts=receipts))
        identity = self.assert_adoption_identity(adopted, candidate, built, receipts)
        self.assertEqual(identity["codegen"], {"kind": "canonical", "lowering_profile": self.session.profiles["lowering"]})
        self.assertIsNone(identity["machine_plan_sha256"])
        lease = self.service.acquire_slot("machine-proof-consumer")
        try:
            observation = self.service.invoke_lease(lease, "transform", [35])
            self.assertEqual(observation["status"], "returned")
            self.assertEqual(observation.get("values", observation.get("result")), [42])
            self.assertEqual(observation["artifact"], built["native_artifact"])
            self.assertEqual(observation["generation"], adopted["current"]["generation"])
        finally:
            self.service.release_slot(lease)

    def test_planned_native_adoption_projects_the_exact_plan_and_proof_subject(self):
        candidate, admitted, canonical = self.prepare()
        plan = {"schema": "hepta.hia.agent.block-layout.v1", "core_sha256": candidate["sha256"],
                "block_order": {"transform": ["entry"]}}
        plan_ref = self.session.artifact(plan)
        checked = self.session.verify(candidate, claims=["lowering_refinement"], subject={
            "kind": "agent_machine_plan", "backend_profile": self.session.backend,
            "plan_profile": self.session.profiles["plan"], "plan": plan_ref})
        self.assertEqual(checked["checks"][0]["status"], "proved")
        built = self.session.emit(candidate, codegen={"kind": "agent_plan",
            "plan_profile": self.session.profiles["plan"], "plan": plan_ref,
            "verification_receipt": checked["verification_receipt"]})
        native = self.native_verify(candidate, built)
        self.assertEqual(native["checks"][0]["status"], "proved")
        receipts = [admitted["verification_receipt"], checked["verification_receipt"], native["verification_receipt"]]
        evaluated = self.session.evaluate(canonical, built, receipts=receipts)
        with patch("hepta.hia_program_native.emit_program_machine", side_effect=AssertionError("adoption reemitted code")), \
             patch("hepta.hia_program_native.compile_program_machine", side_effect=AssertionError("adoption relinked code")):
            adopted = self.client.result("hia_adopt", self.session.arguments(
                target_slot="planned-machine-proof-consumer", expected_current={"generation": "0", "epoch": "0"},
                candidate_artifact=built["native_artifact"],
                evaluation_receipt=evaluated["evaluation_receipt"], verification_receipts=receipts))
        identity = self.assert_adoption_identity(adopted, candidate, built, receipts)
        self.assertEqual(identity["codegen"]["plan"], plan_ref)
        self.assertEqual(identity["machine_plan_sha256"], digest(plan))
        self.assertEqual(identity["proofs"][1]["checks"][0]["subject"]["plan"], plan_ref)

    def test_a_self_consistent_wrong_backend_passes_encoding_but_fails_native_semantics(self):
        with patch.object(Code, "add", Code.sub):
            candidate, _admitted, built = self.prepare()
            encoded = self.session.encoding(candidate, built)
            self.assertEqual(encoded["checks"][0]["status"], "proved")
        result = self.native_verify(candidate, built)
        self.assertEqual(result["checks"][0]["status"], "refuted", result)
        _record, evidence, _assumptions = self.read_proof(result)
        self.assertIsNotNone(evidence["validation"])
        self.assertTrue(any(row["result"] == "sat" and row["expected"] == "unsat"
                            for row in evidence["validation"]["obligations"]))

    def test_object_output_is_unsupported_by_the_shared_image_proof_profile(self):
        candidate, _admitted, built = self.prepare(kind="object")
        result = self.native_verify(candidate, built)
        self.assertEqual(result["checks"][0]["status"], "unsupported")
        self.assertFalse(result["checks"][0]["global_safety_proved"])

    def test_multiple_functions_remain_outside_the_native_proof_profile(self):
        document = add_program(optimized=True, typ="u32")
        helper = deepcopy(document["functions"][0])
        helper["name"] = "other"
        document["functions"].append(helper)
        candidate, _admitted, built = self.prepare(document=document)
        result = self.native_verify(candidate, built)
        self.assertEqual(result["checks"][0]["status"], "unsupported")

    def test_less_than_minimum_budget_does_not_start_a_machine_proof(self):
        candidate, admitted, built = self.prepare()
        with patch.object(self.service, "_remaining_ms", return_value=99), \
             patch("hepta.hia_safe_core.validate_safe_core_artifact",
                   side_effect=AssertionError("insufficient budget must not start the solver")):
            result = self.native_verify(candidate, built)
        self.assertEqual(result["checks"][0]["status"], "unknown")
        _record, evidence, _assumptions = self.read_proof(result)
        self.assertIsNone(evidence["validation"])
        self.assertIsNone(evidence["solver"])
        self.assertFalse(evidence["deadline_met"])
        self.reject_consumption(built, admitted, result["verification_receipt"])

    def test_completed_queries_cannot_be_published_after_the_frozen_deadline(self):
        candidate, admitted, built = self.prepare()
        with patch.object(self.service, "_remaining_ms", side_effect=[60000, 0]):
            result = self.native_verify(candidate, built)
        self.assertEqual(result["checks"][0]["status"], "unknown")
        _record, evidence, _assumptions = self.read_proof(result)
        self.assertTrue(evidence["validation"]["complete"])
        self.assertTrue(all(row["result"] == row["expected"]
                            for row in evidence["validation"]["obligations"]))
        self.assertFalse(evidence["deadline_met"])
        self.reject_consumption(built, admitted, result["verification_receipt"])

    def test_missing_or_rebound_retained_object_identity_is_rejected(self):
        candidate, _admitted, built = self.prepare()
        record = self.session.read_json(built["build_receipt"])
        mutations = [
            lambda row: row.pop("object_artifact"),
            lambda row: row.pop("object_sha256"),
            lambda row: row["native_build"].pop("object_artifact"),
            lambda row: row.update(object_sha256="0" * 64),
            lambda row: row.update(core_sha256="0" * 64),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                changed = deepcopy(record)
                mutate(changed)
                fake = self.service.store.json(changed, "build-receipt")
                self.reject("hia_verify", self.native_arguments(candidate, {**built, "build_receipt": fake}))

    def test_changed_retained_object_bytes_are_not_replaced_by_reemission(self):
        candidate, _admitted, built = self.prepare()
        record = self.session.read_json(built["build_receipt"])
        self.corrupt_artifact_bytes(record["object_artifact"])
        self.reject("hia_verify", self.native_arguments(candidate, built))

    def test_changed_final_image_bytes_are_rejected_before_a_proof_is_issued(self):
        candidate, _admitted, built = self.prepare()
        self.corrupt_artifact_bytes(built["native_artifact"])
        self.reject("hia_verify", self.native_arguments(candidate, built))

    def test_changed_candidate_core_bytes_are_rejected_before_a_proof_is_issued(self):
        candidate, _admitted, built = self.prepare()
        self.corrupt_artifact_bytes(candidate)
        self.reject("hia_verify", self.native_arguments(candidate, built))

    def test_incomplete_duplicate_or_wrong_solver_obligations_cannot_be_restamped(self):
        candidate, admitted, built = self.prepare()
        result = self.native_verify(candidate, built)
        original, raw, _assumptions = self.read_proof(result)

        def duplicate(rows):
            rows[1] = deepcopy(rows[0])

        def reordered(rows):
            rows[1], rows[2] = rows[2], rows[1]

        changes = [
            lambda rows: rows.pop(),
            duplicate,
            reordered,
            lambda rows: rows[0].update(result="unsat"),
            lambda rows: rows[1].update(result="sat"),
            lambda rows: rows[-1].update(result="unknown"),
            lambda rows: rows[-1].update(expected="sat", result="sat"),
        ]
        for index, mutate in enumerate(changes):
            with self.subTest(mutation=index):
                evidence = deepcopy(raw)
                mutate(evidence["validation"]["obligations"])
                evidence["validation"].update(ok=True, status="smt_validated")
                forged = self.rewritten_receipt(original, evidence)
                self.reject_consumption(built, admitted, forged)

    def test_raw_proof_artifact_binding_cannot_be_transplanted_or_weakened(self):
        candidate, admitted, built = self.prepare()
        result = self.native_verify(candidate, built)
        original, raw, _assumptions = self.read_proof(result)
        mutations = [
            lambda row: row["artifact_binding"].update(candidate_core_sha256="0" * 64),
            lambda row: row["artifact_binding"].update(object_sha256="0" * 64),
            lambda row: row["artifact_binding"].update(final_image_sha256="0" * 64),
            lambda row: row["artifact_binding"].pop("object_artifact"),
            lambda row: row["artifact_binding"].update(foreign_buffer_exports=[["transform", 4096]]),
            lambda row: row["validation"]["subject"].update(core_sha256="0" * 64),
            lambda row: row["validation"]["subject"].update(object_sha256="0" * 64),
            lambda row: row["validation"]["subject"].update(final_image_sha256="0" * 64),
            lambda row: row["validation"]["image_binding"].update(final_image_sha256="0" * 64),
            lambda row: row["validation"]["subject"].update(entry_symbol="other"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                evidence = deepcopy(raw)
                mutate(evidence)
                self.reject_consumption(built, admitted, self.rewritten_receipt(original, evidence))

    def test_true_solver_version_with_false_library_or_bindings_is_not_a_checker_identity(self):
        candidate, admitted, built = self.prepare()
        result = self.native_verify(candidate, built)
        original, raw, old_assumptions = self.read_proof(result)
        for field in ("library_sha256", "binding_sha256"):
            with self.subTest(field=field):
                record, evidence, assumptions = deepcopy(original), deepcopy(raw), deepcopy(old_assumptions)
                fake = {**evidence["solver"], field: "0" * 64}
                evidence["solver"] = fake
                evidence["validation"]["solver"] = deepcopy(fake)
                evidence["validation"]["checker"]["solver"] = deepcopy(fake)
                record["checks"][0]["checker"]["solver"] = deepcopy(fake)
                assumptions["checker"]["solver"] = deepcopy(fake)
                self.reject_consumption(built, admitted,
                    self.rewritten_receipt(record, evidence, assumptions))

    def test_restamped_consumer_source_digest_must_match_current_checker_files(self):
        candidate, admitted, built = self.prepare()
        result = self.native_verify(candidate, built)
        record, evidence, assumptions = self.read_proof(result)
        source = deepcopy(evidence["source_identity"])
        self.assertIn("hia_safe_core.py", source)
        source["hia_safe_core.py"] = "0" * 64
        evidence["source_identity"] = source
        evidence["checker_sha256"] = digest(source)
        evidence["validation"]["source_identity"] = deepcopy(source)
        evidence["validation"]["checker"]["source_identity"] = deepcopy(source)
        record["checks"][0]["checker"]["auxiliary_checker_sha256"] = digest(source)
        assumptions["checker"]["auxiliary_checker_sha256"] = digest(source)
        self.reject_consumption(built, admitted, self.rewritten_receipt(record, evidence, assumptions))

    def test_a_proof_for_another_issued_native_artifact_does_not_satisfy_the_gate(self):
        candidate, admitted, built = self.prepare()
        result = self.native_verify(candidate, built)
        # Repeated identical emissions are correctly deduplicated by the store.
        # This private fixture issues another authority-bound reference to the
        # same bytes so the gate must compare the complete artifact identity.
        data, metadata = self.service.store.get(built["native_artifact"], kind="native")
        metadata = {**metadata, "test_issued_identity": "another"}
        artifact = self.service.store.put(data, "native", metadata)
        record = {**self.session.read_json(built["build_receipt"]), **metadata,
                  "native_artifact": artifact}
        another = {**built, "native_artifact": artifact,
                   "build_receipt": self.service.store.json(record, "build-receipt")}
        self.assertNotEqual(another["native_artifact"], built["native_artifact"])
        self.reject_consumption(another, admitted, result["verification_receipt"])

    def test_refuted_machine_evidence_cannot_be_relabelled_as_proved(self):
        with patch.object(Code, "add", Code.sub):
            candidate, admitted, built = self.prepare()
        result = self.native_verify(candidate, built)
        self.assertEqual(result["checks"][0]["status"], "refuted")
        record, evidence, assumptions = self.read_proof(result)
        record["checks"][0]["status"] = "proved"
        record["checks"][0]["unproved_obligations"] = [
            row for row in record["checks"][0]["unproved_obligations"] if row["id"] != "requested_property"]
        evidence["outcome"] = "proved"
        evidence["validation"].update(ok=True, status="smt_validated")
        forged = self.rewritten_receipt(record, evidence, assumptions)
        # Exercise the acceptance gate without ever launching the faulty image,
        # even if a regression were to make this assertion fail.
        with self.assertRaises(AgentRejected):
            self.service._required_claims(self.service._context(self.session.context),
                built["native_artifact"], [admitted["verification_receipt"], forged])


if __name__ == "__main__":
    unittest.main()
