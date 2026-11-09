"""HIA tool qualification from an independent client boundary.

These tests exercise records, actual direct code, native calls and conditional
publication. A successful checker invocation is never assumed to prove another
claim, an unrelated artifact, or an unbounded input domain.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from hashlib import sha256
import builtins
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from hepta.hia_agent_service import HIAAgentService
from tools.hia_agent_native_qualification import (
    CATALOG_PATH, Session, ToolClient, add_program, branch_program,
    exhaustive_u8_workload, json_bytes, scripted_loop,
)


class AgentToolCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-agent-test-")
        self.root = Path(self.temporary.name)
        self.state_root = self.root / "state"
        self.files_root = self.root / "files"
        self.files_root.mkdir()
        self.service = HIAAgentService(self.state_root, artifact_roots=(self.files_root,))
        self.client = ToolClient(self.service.call)
        self.session = Session(self.client, prefix=self._testMethodName)

    def tearDown(self):
        self.service.close()
        self.temporary.cleanup()

    def reject(self, tool, arguments):
        """Send malformed input through the server, bypassing client validation."""
        result = self.service.call(tool, deepcopy(arguments))
        Draft202012Validator(self.client.tools[tool]["outputSchema"]).validate(result)
        self.assertEqual(result["status"], "rejected", result)
        self.assertIn("error", result)
        self.assertNotIn("result", result)
        return result

    def build_pair(self, *, document=None, candidate=None, workload=None, budget=None,
                   objective=None):
        session = self.session
        document = document or add_program()
        candidate = candidate or add_program(optimized=True)
        workload = workload or exhaustive_u8_workload()
        session.freeze(workload, budget=budget, objective=objective)
        base = session.import_program(document)
        session.freeze(workload, baseline=base, budget=budget, objective=objective)
        revised = session.import_program(candidate)
        base_check = session.verify(base)
        check = session.verify(revised)
        baseline_build = session.emit(base, receipts=[base_check["verification_receipt"]])
        build = session.emit(revised, receipts=[check["verification_receipt"]])
        encoding = session.encoding(revised, build)
        receipts = [check["verification_receipt"], encoding["verification_receipt"]]
        return base, revised, baseline_build, build, receipts


class ArtifactContractTests(AgentToolCase):
    def test_discovery_is_readable_and_source_bound(self):
        session = self.session
        self.assertEqual(session.catalog_sha256, sha256(CATALOG_PATH.read_bytes()).hexdigest())
        self.assertTrue(set(("compiler", "target", "artifact", "validation", "lowering", "plan"))
                        <= set(session.profiles))
        for section in ("language", "backend", "examples", "diagnostics", "plans"):
            result = self.client.result("hia_describe", {"section": section})
            self.assertEqual(result["catalog_sha256"], session.catalog_sha256)
            for artifact in result["resources"]:
                self.assertTrue(session.read(artifact))
        support = json.loads(session.read(self.service.resources["self_hosting_core_support"]))
        self.assertEqual(support["schema"], "hepta.hia.selfhost-core-support.v1")
        self.assertEqual(support["profile"], "selfhost-core-linux-x86_64-v14")
        self.assertEqual(support["limits"]["tail_self_call_additional_frames"], 0)
        backend = self.client.result("hia_describe", {"section": "backend"})
        self.assertIn(self.service.resources["self_hosting_core_support"], backend["resources"])

    def test_utf8_pagination_preserves_bytes_and_rejects_cross_artifact_cursor(self):
        content = "x" * 511 + "雪🧪" * 1200 + "end"
        artifact = self.session.artifact(content)
        self.assertEqual(self.session.read(artifact, max_bytes=512), content.encode("utf-8"))
        first = self.client.result("hia_read", {
            "catalog_sha256": self.session.catalog_sha256, "artifact": artifact, "max_bytes": 512})
        self.assertIsNotNone(first["next_cursor"])
        another = self.session.artifact("unrelated content" * 100)
        self.reject("hia_read", {"catalog_sha256": self.session.catalog_sha256,
            "artifact": another, "cursor": first["next_cursor"], "max_bytes": 512})

    def test_high_escape_pages_obey_serialized_response_bound(self):
        content = "\0" * 65536
        artifact = self.session.artifact(content)
        self.assertEqual(self.session.read(artifact), content.encode())
        pages = [row["response"] for row in self.client.records
                 if row["tool"] == "hia_read" and row["arguments"]["artifact"] == artifact]
        self.assertTrue(pages)
        self.assertTrue(all(len(json_bytes(page)) < 512 * 1024 for page in pages))

    def test_issued_reference_fields_and_actual_bytes_are_verified(self):
        artifact = self.session.artifact("untrusted source data")
        for field, value in (("id", "../../escape"), ("sha256", "0" * 64),
                             ("uri", "hia://artifacts/not-the-issued-uri")):
            forged = {**artifact, field: value}
            with self.subTest(field=field):
                self.reject("hia_read", {"catalog_sha256": self.session.catalog_sha256,
                                         "artifact": forged})
        stored = self.state_root / "artifacts" / artifact["sha256"]
        self.assertTrue(stored.is_file())
        stored.chmod(0o600)
        stored.write_bytes(b"changed behind the artifact reference")
        self.reject("hia_read", {"catalog_sha256": self.session.catalog_sha256,
                                 "artifact": artifact})

    def test_file_capture_enforces_roots_regular_identity_and_expected_hash(self):
        target = self.files_root / "input.json"
        target.write_text("bounded file contents")
        payload = {"kind": "path", "path": str(target),
                   "expected_sha256": sha256(target.read_bytes()).hexdigest(), "max_bytes": 4096}
        args = self.session.arguments(context=False,
            artifact_profile=self.session.profiles["artifact"], source=payload)
        result = self.client.result("hia_artifact", args)
        self.assertEqual(self.session.read(result["artifact"]), target.read_bytes())
        self.assertFalse(result["content_admitted_as_program"])
        self.assertFalse(result["execution_authority_granted"])
        outside = self.root / "not-authorized.txt"
        outside.write_text("outside capture roots")
        link = self.files_root / "symlink"
        link.symlink_to(outside)
        for path, digest, limit in ((outside, None, 4096), (link, None, 4096),
                                    (target, "0" * 64, 4096), (target, None, 4)):
            with self.subTest(path=path, digest=digest, limit=limit):
                self.reject("hia_artifact", self.session.arguments(context=False,
                    artifact_profile=self.session.profiles["artifact"], source={
                        "kind": "path", "path": str(path), "expected_sha256": digest,
                        "max_bytes": limit}))

    def test_exact_request_replay_survives_restart_and_changed_body_rejects(self):
        args = self.session.arguments(context=False,
            artifact_profile=self.session.profiles["artifact"],
            source={"kind": "utf8", "text": "one durable effect"})
        first = self.client.call("hia_artifact", args)
        second = self.client.call("hia_artifact", args)
        self.assertEqual(first, second)
        restarted = HIAAgentService(self.state_root, artifact_roots=(self.files_root,))
        self.assertEqual(restarted.call("hia_artifact", args), first)
        changed = deepcopy(args)
        changed["source"]["text"] = "different effect under same key"
        self.reject("hia_artifact", changed)
        self.assertEqual(restarted.call("hia_artifact", args), first)
        restarted.close()

    def test_unknown_fields_stale_catalog_and_profile_do_not_gain_admission(self):
        self.reject("hia_describe", {"section": "manifest", "verified": True})
        self.reject("hia_describe", {"section": "manifest", "max_bytes": 10 ** 400})
        for change in ({"catalog_sha256": "0" * 64},
                       {"artifact_profile": {"id": "invented", "sha256": "0" * 64}},
                       {"principal": "administrator"}):
            args = self.session.arguments(context=False,
                artifact_profile=self.session.profiles["artifact"],
                source={"kind": "utf8", "text": "does not grant authority"})
            args.update(change)
            self.reject("hia_artifact", args)

    def test_process_killed_after_effect_leaves_unknown_intent_and_never_replays(self):
        """Interrupt the real process between retained artifact and result commit."""
        args = self.session.arguments(context=False,
            artifact_profile=self.session.profiles["artifact"],
            source={"kind": "utf8", "text": "durably stored before interrupted report"})
        marker = self.root / "effect-visible"
        script = r'''
import json,pathlib,sys,time
from hepta.hia_agent_service import HIAAgentService
service=HIAAgentService(sys.argv[1],artifact_roots=(sys.argv[2],))
original=service._hia_artifact
def stop_after_effect(arguments):
    result=original(arguments)
    pathlib.Path(sys.argv[3]).write_text(json.dumps(result))
    time.sleep(300)
    return result
service._hia_artifact=stop_after_effect
print(json.dumps(service.call("hia_artifact",json.loads(sys.argv[4]))),flush=True)
'''
        child = subprocess.Popen([sys.executable, "-c", script, str(self.state_root),
            str(self.files_root), str(marker), json.dumps(args)],
            cwd=CATALOG_PATH.parents[1], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and child.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists(), "fault injection did not reach the post-effect checkpoint")
            child.kill()
            child.communicate(timeout=5)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=5)
        retained = json.loads(marker.read_text())["artifact"]
        self.assertEqual(self.session.read(retained), args["source"]["text"].encode())
        first = self.reject("hia_artifact", args)
        self.assertEqual(first["error"]["code"], "E_HIA_REQUEST_UNKNOWN")
        self.assertEqual(first["error"]["retry_action"], "observe_original")
        second = self.reject("hia_artifact", args)
        self.assertEqual(second["error"]["code"], "E_HIA_REQUEST_UNKNOWN")
        changed = deepcopy(args)
        changed["source"]["text"] = "attempt to replace interrupted request"
        conflict = self.reject("hia_artifact", changed)
        self.assertEqual(conflict["error"]["code"], "E_HIA_REQUEST_CONFLICT")


class CandidateAndVerificationTests(AgentToolCase):
    def test_invalid_candidate_is_repaired_with_an_explicit_new_request(self):
        session = self.session
        session.freeze(exhaustive_u8_workload())
        invalid = add_program()
        invalid["functions"][0]["blocks"][0]["ops"][-1]["args"] = ["x", "undefined"]
        source = session.artifact(invalid)
        args = session.arguments(change={"kind": "import", "format": "core-json", "source": source})
        rejection = self.reject("hia_candidate", args)
        self.assertEqual(self.service.call("hia_candidate", args), rejection)
        candidate = session.import_program(add_program())
        result = session.verify(candidate)
        self.assertEqual(result["checks"][0]["claim"], "core_admission")
        self.assertEqual(result["checks"][0]["status"], "proved")
        self.assertFalse(result["adopted"])

    def test_patch_binds_canonical_base_and_whole_candidate_is_rechecked(self):
        session = self.session
        session.freeze(exhaustive_u8_workload())
        original = session.import_program(add_program())
        operation = deepcopy(add_program()["functions"][0]["blocks"][0]["ops"][0])
        operation["attrs"]["value"] = 7
        patch = {"schema": "hepta.hia.patch.v1", "expected_sha256": original["sha256"],
            "edits": [{"action": "replace_operation", "function": "transform", "block": "entry",
                       "index": 0, "operation": operation}]}
        patch_ref = session.artifact(patch)
        args = session.arguments(change={"kind": "patch", "base_program": original,
            "patch_schema": patch["schema"], "patch": patch_ref})
        result = self.client.result("hia_candidate", args)
        self.assertNotEqual(result["candidate"]["sha256"], original["sha256"])
        self.assertFalse(result["behavior_equivalence_proved"])
        self.assertEqual(result["base_program"], original)
        stale = session.arguments(change={"kind": "patch", "base_program": result["candidate"],
            "patch_schema": patch["schema"], "patch": patch_ref})
        self.reject("hia_candidate", stale)
        self.assertEqual(session.read_json(original)["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"], 6)

    def test_stale_context_and_foreign_validation_profile_are_rejected(self):
        session = self.session
        session.freeze(exhaustive_u8_workload())
        candidate = session.import_program(add_program())
        for field, value in (("context", {**session.context, "sha256": "0" * 64}),
                             ("validation_profile", {**session.profiles["validation"], "sha256": "0" * 64})):
            args = session.arguments(candidate=candidate, base_program=None,
                validation_profile=session.profiles["validation"], subject={"kind": "core"},
                claims=["core_admission"])
            args[field] = value
            self.reject("hia_verify", args)

    def test_unknown_or_refuted_equivalence_cannot_be_reported_as_core_admission(self):
        session = self.session
        session.freeze(exhaustive_u8_workload())
        base = session.import_program(add_program())
        changed = session.import_program(add_program(optimized=True, increment=8))
        result = session.verify(changed, base=base, claims=["core_admission", "behavior_equivalence"])
        checks = {check["claim"]: check for check in result["checks"]}
        self.assertEqual(checks["core_admission"]["status"], "proved")
        self.assertIn(checks["behavior_equivalence"]["status"], ("refuted", "unknown", "unsupported"))
        self.assertTrue(checks["behavior_equivalence"]["domain"])

    def test_matching_return_values_do_not_hide_different_first_trap(self):
        session = self.session
        session.freeze(exhaustive_u8_workload())
        original = add_program(optimized=True)
        fn = original["functions"][0]
        fn["effects"] = ["trap"]
        fn["blocks"][0]["ops"] = [
            {"op": "const", "args": [], "out": [{"name": "one", "type": "u8"}], "attrs": {"value": 1}},
            {"op": "const", "args": [], "out": [{"name": "zero", "type": "u8"}], "attrs": {"value": 0}},
            {"op": "int.add.checked", "args": ["x", "one"],
             "out": [{"name": "sum", "type": "u8"}], "attrs": {}},
            {"op": "int.div.checked", "args": ["x", "zero"],
             "out": [{"name": "answer", "type": "u8"}], "attrs": {}},
        ]
        reordered = deepcopy(original)
        operations = reordered["functions"][0]["blocks"][0]["ops"]
        operations[2], operations[3] = operations[3], operations[2]
        base = session.import_program(original)
        candidate = session.import_program(reordered)
        result = session.verify(candidate, base=base, claims=["behavior_equivalence"])
        check = result["checks"][0]
        self.assertIn(check["status"], ("refuted", "unknown", "unsupported"), check)

    def test_allocation_resource_trace_difference_is_not_value_equivalence(self):
        session = self.session
        session.freeze(exhaustive_u8_workload())
        original = add_program(optimized=True)
        original["functions"][0]["effects"] = ["alloc", "trap"]
        operations = original["functions"][0]["blocks"][0]["ops"]
        operations[0:0] = [
            {"op": "const", "args": [], "out": [{"name": "size", "type": "usize"}], "attrs": {"value": 1}},
            {"op": "buffer.new", "args": ["size"], "out": [{"name": "owner", "type": "buffer"}], "attrs": {}},
            {"op": "owner.drop", "args": ["owner"], "out": [], "attrs": {}},
        ]
        removed = add_program(optimized=True)
        removed["functions"][0]["effects"] = ["alloc", "trap"]
        base = session.import_program(original)
        candidate = session.import_program(removed)
        result = session.verify(candidate, base=base, claims=["behavior_equivalence"])
        self.assertIn(result["checks"][0]["status"], ("refuted", "unknown", "unsupported"))

    def test_changed_cfg_and_alpha_names_do_not_implicitly_expand_validator_domain(self):
        session = self.session
        workload = {"schema": "hepta.hia.agent.workload.v1", "cases": [
            {"function": "select_value", "arguments": [True]}],
            "warmup_iterations": 0, "repetitions": 1}
        session.freeze(workload)
        original = branch_program()
        # Rename one block and its reference; this is legal Core. A supported
        # exhaustive bool profile may prove it. A structural-only validator
        # must report its narrower domain instead of trusting matching names.
        renamed = deepcopy(original)
        renamed["functions"][0]["blocks"][1]["id"] = "renamed_yes"
        renamed["functions"][0]["blocks"][0]["term"]["then"]["target"] = "renamed_yes"
        base = session.import_program(original)
        candidate = session.import_program(renamed)
        result = session.verify(candidate, base=base, claims=["behavior_equivalence"])
        check = result["checks"][0]
        if check["status"] == "proved":
            self.assertTrue(check["domain"])
            self.assertIsNotNone(check["evidence_artifact"])
        else:
            self.assertIn(check["status"], ("unknown", "unsupported"))
        diverged = deepcopy(renamed)
        diverged["functions"][0]["blocks"][0]["term"]["else"]["target"] = "renamed_yes"
        # The no block is now unreachable and may be rejected at Core admission;
        # if admitted, the False input refutes behavioral equivalence.
        source = session.artifact(diverged)
        response = self.client.call("hia_candidate", session.arguments(change={
            "kind": "import", "format": "core-json", "source": source}), expected_status=None)
        if response["status"] == "completed":
            candidate = response["result"]["candidate"]
            checked = session.verify(candidate, base=base, claims=["behavior_equivalence"])
            self.assertIn(checked["checks"][0]["status"], ("refuted", "unknown", "unsupported"))
        else:
            self.assertEqual(response["status"], "rejected")

    def test_encoding_receipt_for_another_candidate_does_not_authorize_evaluation(self):
        base, candidate, baseline_build, build, receipts = self.build_pair()
        encoded_base = self.session.encoding(base, baseline_build)
        args = self.session.arguments(baseline_artifact=baseline_build["native_artifact"],
            candidate_artifact=build["native_artifact"], build_receipt=build["build_receipt"],
            verification_receipts=[receipts[0], encoded_base["verification_receipt"]])
        self.reject("hia_evaluate", args)

    def test_equivalence_search_uses_remaining_frozen_context_budget(self):
        session = self.session
        frozen = session.freeze(exhaustive_u8_workload(),
            budget={"max_total_wall_ms": 3000, "max_native_wall_ms": 1000})
        original = session.import_program(add_program(redundant_additions=128))
        candidate = session.import_program(add_program(optimized=True))
        deadline = datetime.fromisoformat(frozen["sampled_at"]).timestamp() + 3.0
        remaining = deadline - time.time() - 0.100
        self.assertGreater(remaining, 0)
        time.sleep(remaining)
        started = time.monotonic()
        response = self.client.call("hia_verify", session.arguments(candidate=candidate,
            base_program=original, validation_profile=session.profiles["validation"],
            subject={"kind": "core"}, claims=["behavior_equivalence"]), expected_status=None)
        self.assertLess(time.monotonic() - started, 0.75)
        if response["status"] == "completed":
            self.assertEqual(response["result"]["checks"][0]["status"], "unknown")
        else:
            self.assertEqual(response["status"], "rejected")
            self.assertEqual(response["error"]["code"], "E_HIA_BUDGET")


class MachinePlanTests(AgentToolCase):
    def prepare(self):
        session = self.session
        workload = {"schema": "hepta.hia.agent.workload.v1", "cases": [
            {"function": "select_value", "arguments": [True],
             "expected": {"status": "returned", "values": [19]}},
            {"function": "select_value", "arguments": [False],
             "expected": {"status": "returned", "values": [83]}}],
            "warmup_iterations": 0, "repetitions": 1}
        session.freeze(workload)
        program = session.import_program(branch_program())
        plan = {"schema": "hepta.hia.agent.block-layout.v1", "core_sha256": program["sha256"],
                "block_order": {"select_value": ["entry", "no", "yes"]}}
        return program, plan

    def plan_verify(self, program, plan):
        plan_ref = self.session.artifact(plan)
        subject = {"kind": "agent_machine_plan", "backend_profile": self.session.backend,
                   "plan_profile": self.session.profiles["plan"], "plan": plan_ref}
        result = self.session.verify(program, subject=subject, claims=["lowering_refinement"])
        return plan_ref, result

    def test_explicit_layout_changes_bytes_preserves_observations_and_core_anchor(self):
        program, plan = self.prepare()
        session = self.session
        plan_ref, checked = self.plan_verify(program, plan)
        self.assertEqual(checked["subject"]["plan"], plan_ref)
        self.assertEqual(checked["checks"][0]["status"], "proved")
        canonical = session.emit(program)
        planned = session.emit(program, codegen={"kind": "agent_plan",
            "plan_profile": session.profiles["plan"], "plan": plan_ref,
            "verification_receipt": checked["verification_receipt"]})
        self.assertNotEqual(canonical["native_artifact"]["sha256"], planned["native_artifact"]["sha256"])
        self.assertEqual(planned["candidate"], program)
        core = session.verify(program)
        encoded = session.encoding(program, planned)
        evaluated = session.evaluate(canonical, planned,
            receipts=[core["verification_receipt"], encoded["verification_receipt"]])
        self.assertTrue(evaluated["planned_workload_complete"])
        self.assertNotEqual(evaluated["outcome"], "incorrect")
        self.assertFalse(planned["llvm_codegen_used"])
        self.assertFalse(planned["external_assembler_used"])

    def test_plan_with_duplicate_missing_unknown_blocks_and_machine_bytes_is_refused(self):
        program, plan = self.prepare()
        variants = []
        for blocks in (["entry", "yes", "yes"], ["entry", "yes"], ["entry", "no", "foreign"]):
            bad = deepcopy(plan)
            bad["block_order"]["select_value"] = blocks
            variants.append(bad)
        variants.append({**plan, "bytes": "4831c0c3"})
        variants.append({**plan, "core_sha256": "0" * 64})
        for bad in variants:
            with self.subTest(plan=bad):
                ref = self.session.artifact(bad)
                result = self.client.call("hia_verify", self.session.arguments(candidate=program,
                    base_program=None, validation_profile=self.session.profiles["validation"],
                    subject={"kind": "agent_machine_plan", "backend_profile": self.session.backend,
                        "plan_profile": self.session.profiles["plan"], "plan": ref},
                    claims=["lowering_refinement"]), expected_status=None)
                if result["status"] == "completed":
                    self.assertTrue(all(check["status"] != "proved" for check in result["result"]["checks"]))
                else:
                    self.assertEqual(result["status"], "rejected")

    def test_one_plan_receipt_cannot_authorize_different_layout(self):
        program, plan = self.prepare()
        original_ref, checked = self.plan_verify(program, plan)
        alternate = deepcopy(plan)
        alternate["block_order"]["select_value"] = ["entry", "yes", "no"]
        alternate_ref = self.session.artifact(alternate)
        self.assertNotEqual(original_ref, alternate_ref)
        self.reject("hia_emit", self.session.arguments(candidate=program,
            backend_profile=self.session.backend, output_kind="object",
            codegen={"kind": "agent_plan", "plan_profile": self.session.profiles["plan"],
                "plan": alternate_ref, "verification_receipt": checked["verification_receipt"]},
            verification_receipts=[]))


class NativeLifecycleTests(AgentToolCase):
    def test_tool_object_emission_needs_no_llvm_import_or_external_process(self):
        session = self.session
        session.freeze(exhaustive_u8_workload())
        candidate = session.import_program(add_program(optimized=True))
        original_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if "llvm" in name.lower():
                raise AssertionError("native tool imported LLVM: " + name)
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", guarded_import), \
                patch("subprocess.Popen", side_effect=AssertionError("object emission launched a subprocess")):
            build = session.emit(candidate, kind="object")
        self.assertFalse(build["linker_used"])
        self.assertFalse(build["llvm_codegen_used"])
        self.assertFalse(build["external_assembler_used"])
        self.assertTrue(session.read(build["native_artifact"]).startswith(b"\x7fELF\x02\x01"))

    def test_all_eleven_tools_and_full_u8_native_workload(self):
        result = scripted_loop(self.session)
        self.assertEqual(set(self.client.tools), {row["tool"] for row in self.client.records})
        self.assertTrue(result["evaluation"]["termination_confirmed"])
        self.assertTrue(result["evaluation"]["planned_workload_complete"])
        self.assertEqual(result["evaluation"]["outcome"], "improved")
        self.assertTrue(result["adoption"]["future_calls_only"])
        self.assertFalse(result["rollback"]["past_effects_reversed"])
        for name in ("baseline_build", "candidate_build"):
            build = result[name]
            self.assertEqual(build["codegen_backend"], "hia-direct")
            self.assertFalse(build["native_execution_observed"])
            self.assertFalse(build["llvm_codegen_used"])
            self.assertFalse(build["external_assembler_used"])

    def test_real_native_wrong_answer_is_incorrect_and_cannot_be_adopted(self):
        _base, _candidate, baseline, build, receipts = self.build_pair(
            candidate=add_program(optimized=True, increment=8))
        evaluation = self.session.evaluate(baseline, build, receipts=receipts)
        self.assertEqual(evaluation["outcome"], "incorrect")
        self.reject("hia_adopt", self.session.arguments(target_slot="wrong-answer",
            expected_current={"generation": "0", "epoch": "0"},
            candidate_artifact=build["native_artifact"],
            evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts))

    def test_published_version_lease_survives_rollback_and_release_is_checked(self):
        _base, _candidate, baseline, build, receipts = self.build_pair()
        evaluation = self.session.evaluate(baseline, build, receipts=receipts)
        adopted = self.client.result("hia_adopt", self.session.arguments(target_slot="leased",
            expected_current={"generation": "0", "epoch": "0"},
            candidate_artifact=build["native_artifact"],
            evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts))
        lease = self.service.acquire_slot("leased")
        rolled_back = self.client.result("hia_rollback", self.session.arguments(target_slot="leased",
            expected_current=adopted["current"], retained_generation=adopted["previous"]["generation"],
            reason="retain in-flight candidate lease"))
        self.assertNotEqual(rolled_back["active_artifact"], build["native_artifact"])
        observation = self.service.invoke_lease(lease, "transform", [250])
        self.assertEqual(observation["status"], "returned")
        self.assertEqual(observation.get("values", observation.get("result")), [1])
        self.assertEqual(observation["artifact"], build["native_artifact"])
        self.assertEqual(observation["generation"], adopted["current"]["generation"])
        new_lease = self.service.acquire_slot("leased")
        restored = self.service.invoke_lease(new_lease, "transform", [250])
        self.assertEqual(restored["artifact"], baseline["native_artifact"])
        forged_lease = {**lease, "artifact": baseline["native_artifact"]}
        with self.assertRaises(ValueError):
            self.service.invoke_lease(forged_lease, "transform", [0])
        self.service.release_slot(lease)
        self.service.release_slot(new_lease)
        with self.assertRaises(ValueError):
            self.service.invoke_lease(lease, "transform", [0])

    def test_native_timeout_is_incomplete_terminated_and_not_adoptable(self):
        _base, _candidate, baseline, build, receipts = self.build_pair(
            budget={"max_native_wall_ms": 1})
        started = time.monotonic()
        evaluation = self.session.evaluate(baseline, build, receipts=receipts)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(evaluation["outcome"], "budget_exceeded")
        self.assertTrue(evaluation["report_complete"])
        self.assertTrue(evaluation["termination_confirmed"])
        self.assertFalse(evaluation["planned_workload_complete"])
        self.reject("hia_adopt", self.session.arguments(target_slot="timed-out",
            expected_current={"generation": "0", "epoch": "0"},
            candidate_artifact=build["native_artifact"],
            evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts))

    def test_reference_loop_cannot_restart_or_overrun_frozen_context_deadline(self):
        looping = {"schema": "hepta.hia.program.v1", "module": "budget_loop", "functions": [{
            "name": "spin", "params": [], "returns": ["u8"], "effects": [], "entry": "entry",
            "blocks": [
                {"id": "entry", "params": [], "ops": [], "term": {"op": "jump", "target": "loop", "args": []}},
                {"id": "loop", "params": [], "ops": [], "term": {"op": "jump", "target": "loop", "args": []}},
            ]}]}
        workload = {"schema": "hepta.hia.agent.workload.v1", "cases": [
            {"function": "spin", "arguments": []}], "warmup_iterations": 0, "repetitions": 1}
        _base, _candidate, baseline, build, receipts = self.build_pair(
            document=looping, candidate=looping, workload=workload,
            budget={"max_total_wall_ms": 3000, "max_native_wall_ms": 1000})
        frozen = next(row["response"]["result"] for row in reversed(self.client.records)
                      if row["tool"] == "hia_context")
        deadline = datetime.fromisoformat(frozen["sampled_at"]).timestamp() + 3.0
        context_row = self.service.store.db.execute("SELECT created_ns FROM contexts WHERE id=?",
            (self.session.context["id"],)).fetchone()
        context_deadline_ns = int(context_row["created_ns"]) + 3_000_000_000
        from hepta.hia_agent_runner import run_reference_batch
        references, wall_reads, entered_evaluation = [], [], []
        real_time_ns = time.time_ns
        required_claims = self.service._required_claims

        def observe_wall_time():
            observed = real_time_ns()
            wall_reads.append(observed)
            return observed

        def wait_inside_evaluation(*arguments):
            result = required_claims(*arguments)
            entered_evaluation.append(True)
            # Admission and the real retained-artifact/claim checks have now
            # completed. Wait inside that admitted evaluation, not in front of
            # request validation. This also makes the wall limit win over the
            # VM's independent instruction-count limit.
            remaining = deadline - time.time() - 0.100
            self.assertGreater(remaining, 0, "fixture preparation exhausted the original context budget")
            time.sleep(remaining)
            return result

        def observe_reference(program, cases, **options):
            # Record actual clock reads without changing them. The last read
            # supplied the remaining_total_ms argument at this exact boundary.
            # Compare the same integer-millisecond rounding with no tolerance.
            self.assertTrue(wall_reads)
            remaining_ms = max(0, (context_deadline_ns - wall_reads[-1]) // 1_000_000)
            self.assertEqual(options["timeout_ms"], remaining_ms)
            self.assertGreater(options["timeout_ms"], 0)
            observed = run_reference_batch(program, cases, **options)
            references.append(observed)
            return observed

        # Start while admission still has the original context budget. Waiting
        # before dispatch left only 100ms for schema, source-identity and
        # context I/O, so a valid rejection could bypass the reference test.
        with patch("hepta.hia_agent_service.time.time_ns", side_effect=observe_wall_time), \
             patch.object(self.service, "_required_claims", side_effect=wait_inside_evaluation), \
             patch("hepta.hia_agent_runner.run_reference_batch", side_effect=observe_reference):
            evaluation = self.session.evaluate(baseline, build, receipts=receipts)
        # The old bound was 0.75s after a start at deadline-0.100s. Keep that
        # same absolute deadline+0.650s bound without the admission race.
        self.assertLess(time.time(), deadline + 0.650)
        self.assertEqual(entered_evaluation, [True])
        self.assertEqual(len(references), 1)
        self.assertTrue(references[0]["started"])
        self.assertEqual(references[0]["status"], "budget_exceeded")
        self.assertTrue(references[0]["termination_confirmed"])
        self.assertEqual(evaluation["outcome"], "budget_exceeded")
        self.assertFalse(evaluation["planned_workload_complete"])
        self.assertTrue(evaluation["termination_confirmed"])
        measurements = self.session.read_json(evaluation["measurements"])
        self.assertEqual(measurements["reference_runs"]["baseline"]["status"], "budget_exceeded")
        self.assertTrue(all(run["normal"] is None for run in measurements["native_runs"].values()))

    def test_expired_evaluation_is_rejected_before_any_reference_or_native_runner(self):
        _base, _candidate, baseline, build, receipts = self.build_pair(
            budget={"max_total_wall_ms": 3000, "max_native_wall_ms": 1000})
        context = dict(self.session.context)
        context_row = self.service.store.db.execute("SELECT created_ns FROM contexts WHERE id=?",
            (context["id"],)).fetchone()
        created_ns = context_row["created_ns"]
        deadline_ns = int(created_ns) + 3_000_000_000
        time.sleep(max(0, (deadline_ns - time.time_ns()) / 1_000_000_000 + 0.010))
        with patch("hepta.hia_agent_runner.run_reference_batch", side_effect=AssertionError("expired reference started")), \
             patch("hepta.hia_agent_runner.run_native_batch", side_effect=AssertionError("expired native started")):
            response = self.reject("hia_evaluate", self.session.arguments(
                baseline_artifact=baseline["native_artifact"], candidate_artifact=build["native_artifact"],
                build_receipt=build["build_receipt"], verification_receipts=receipts))
        self.assertEqual(response["error"]["code"], "E_HIA_BUDGET")
        self.assertEqual(response["error"]["phase"], "context")
        self.assertEqual(self.session.context, context)
        self.assertEqual(self.service.store.db.execute("SELECT created_ns FROM contexts WHERE id=?",
            (context["id"],)).fetchone()["created_ns"], created_ns)
        execution = self.service.store.db.execute("SELECT used_native_ns,owner FROM execution_budgets WHERE context_id=?",
            (context["id"],)).fetchone()
        self.assertEqual(execution["used_native_ns"], "0")
        self.assertIsNone(execution["owner"])

    def test_fresh_context_can_advance_existing_slot_and_stale_error_is_readable(self):
        _base, previous_core, baseline, build, receipts = self.build_pair()
        evaluation = self.session.evaluate(baseline, build, receipts=receipts)
        adopted = self.client.result("hia_adopt", self.session.arguments(target_slot="continued",
            expected_current={"generation": "0", "epoch": "0"},
            candidate_artifact=build["native_artifact"],
            evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts))
        previous_context = self.session.context
        self.session.freeze(exhaustive_u8_workload(), baseline=previous_core)
        self.assertNotEqual(previous_context, self.session.context)
        check = self.session.verify(previous_core)
        new_build = self.session.emit(previous_core, receipts=[check["verification_receipt"]])
        encoded = self.session.encoding(previous_core, new_build)
        new_receipts = [check["verification_receipt"], encoded["verification_receipt"]]
        measured = self.session.evaluate(new_build, new_build, receipts=new_receipts)
        args = self.session.arguments(target_slot="continued", expected_current=adopted["current"],
            candidate_artifact=new_build["native_artifact"],
            evaluation_receipt=measured["evaluation_receipt"], verification_receipts=new_receipts)
        revised = self.client.result("hia_adopt", args)
        self.assertNotEqual(revised["current"], adopted["current"])
        stale_args = {**args, "request_key": self.session.key("stale")}
        stale = self.reject("hia_adopt", stale_args)
        self.assertEqual(stale["error"]["code"], "E_HIA_GENERATION_STALE")
        details = self.session.read_json(stale["error"]["details_artifact"])
        self.assertEqual(details["current"], revised["current"])
        self.assertEqual(details["active_artifact"], new_build["native_artifact"])
        self.assertFalse(details["snapshot_is_adoption_authority"])

    def test_u64_generation_boundary_rejects_out_of_range_strings(self):
        self.session.freeze(exhaustive_u8_workload())
        for invalid in ("18446744073709551616", "99999999999999999999"):
            self.reject("hia_rollback", self.session.arguments(target_slot="does-not-exist",
                expected_current={"generation": invalid, "epoch": "0"},
                retained_generation="0", reason="integer range must be checked"))


if __name__ == "__main__":
    unittest.main()


class AgentStoreDirectoryPermissionTests(unittest.TestCase):
    def test_preexisting_world_writable_artifact_directory_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="hia-store-permission-") as directory:
            root = Path(directory) / "state"
            root.mkdir(mode=0o700)
            artifacts = root / "artifacts"
            artifacts.mkdir(mode=0o700)
            artifacts.chmod(0o777)

            # A pre-existing shared artifact directory lets another local user
            # unlink or replace content-addressed files despite the private
            # state-root check. Store initialization must fail closed.
            with self.assertRaisesRegex(ValueError, "artifact directory"):
                HIAAgentService(root)

