"""Actual copied-byte lifecycle and fail-closed adoption observations."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import unittest
from unittest.mock import patch

from hepta.hia_agent_byte_abi import byte_value, byte_observations, decode_arguments, decode_bytes
from tests.test_hia_agent_native_tools import AgentToolCase
from tests.test_hia_native_byte_abi import byte_program
from tests.test_hia_program import b, c, f, i, ret


def workload(cases=None, exports=None, *, warmup=1, repetitions=3):
    return {"schema": "hepta.hia.agent.workload.v2",
        "foreign_buffer_exports": exports or [{"function": "copy_bytes", "maximum_bytes": 4096}],
        "cases": cases or [{"function": "copy_bytes", "arguments": [byte_value(b"\x00\xffbytes"), byte_value(b"_" * 9)]},
                            {"function": "copy_bytes", "arguments": [byte_value(b""), byte_value(b"tail")]},
                            {"function": "copy_bytes", "arguments": [byte_value(b"too large"), byte_value(b"short")]}],
        "warmup_iterations": warmup, "repetitions": repetitions}


class AgentNativeBytesTests(AgentToolCase):
    def pair(self, *, source=None, candidate=None, cases=None, objective=None, budget=None):
        source = source or byte_program()
        return self.build_pair(document=source, candidate=candidate or deepcopy(source),
                               workload=cases or workload(), objective=objective, budget=budget)

    def adopt(self, build, evaluation, receipts, slot="copied-bytes"):
        return self.client.result("hia_adopt", self.session.arguments(target_slot=slot,
            expected_current={"generation": "0", "epoch": "0"}, candidate_artifact=build["native_artifact"],
            evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts))

    def test_complete_byte_pipeline_binds_vm_native_outputs_and_real_leased_consumer(self):
        base, revised, baseline, build, receipts = self.pair()
        built = self.session.read_json(build["build_receipt"])
        self.assertEqual(built["foreign_buffer_exports"], [["copy_bytes", 4096]])
        self.assertEqual(built["native_build"]["foreign_buffer_exports"], built["foreign_buffer_exports"])
        self.assertEqual(set(built["signatures"]), {"copy_bytes"})
        identity = self.session.verify(revised, base=base, claims=["behavior_equivalence"])
        self.assertEqual(identity["checks"][0]["status"], "proved")
        evaluation = self.session.evaluate(baseline, build, receipts=receipts)
        self.assertEqual(evaluation["outcome"], "unchanged")
        self.assertTrue(evaluation["planned_workload_complete"])
        measured = self.session.read_json(evaluation["measurements"])
        self.assertEqual(measured["planned_cases"], 3)
        for row in measured["observations"]:
            self.assertEqual(row["baseline_vm"]["buffers"], row["candidate_native"]["buffers"])
            self.assertEqual(row["candidate_vm"]["values"], row["candidate_native"]["values"])
            self.assertFalse(row["candidate_native"]["mismatch"])
            self.assertEqual(row["candidate_vm"]["ledger"]["resources"]["live_owners"], 0)
            self.assertEqual(row["candidate_vm"]["ledger"]["external_input_copies"]["ranges"], 2)
        for native in measured["native_runs"].values():
            self.assertEqual(native["normal"]["report"]["measured_calls"], 9)
        adopted = self.adopt(build, evaluation, receipts)
        lease = self.service.acquire_slot("copied-bytes")
        arguments = [byte_value(b"consumer"), byte_value(b"..........")]
        original = deepcopy(arguments)
        observation = self.service.invoke_lease(lease, "copy_bytes", arguments)
        self.assertEqual(arguments, original)
        self.assertEqual(observation["values"], [0])
        self.assertEqual(decode_bytes(observation["arguments"][0]), b"consumer")
        self.assertEqual(decode_bytes(observation["arguments"][1]), b"consumer..")
        self.assertEqual(observation["artifact"], build["native_artifact"])
        self.client.result("hia_rollback", self.session.arguments(target_slot="copied-bytes",
            expected_current=adopted["current"], retained_generation="0", reason="check retained lease"))
        self.assertEqual(self.service.invoke_lease(lease, "copy_bytes", arguments)["generation"], "1")
        new_lease = self.service.acquire_slot("copied-bytes")
        self.assertEqual(self.service.invoke_lease(new_lease, "copy_bytes", arguments)["generation"], "0")
        self.service.release_slot(lease)
        self.service.release_slot(new_lease)
        with self.assertRaisesRegex(ValueError, "lease"):
            self.service.invoke_lease(lease, "copy_bytes", arguments)

    def test_matching_scalar_result_with_wrong_mutable_bytes_cannot_be_adopted(self):
        wrong = byte_program()
        wrong["functions"][1]["blocks"][0]["ops"][0] = c("v", "u8", 0)
        _base, _revised, baseline, build, receipts = self.pair(candidate=wrong)
        evaluated = self.session.evaluate(baseline, build, receipts=receipts)
        self.assertEqual(evaluated["outcome"], "incorrect")
        measured = self.session.read_json(evaluated["measurements"])
        row = measured["observations"][0]
        self.assertEqual(row["baseline_native"]["values"], row["candidate_native"]["values"])
        self.assertNotEqual(row["baseline_native"]["buffers"], row["candidate_native"]["buffers"])
        denied = self.reject("hia_adopt", self.session.arguments(target_slot="wrong-bytes",
            expected_current={"generation": "0", "epoch": "0"}, candidate_artifact=build["native_artifact"],
            evaluation_receipt=evaluated["evaluation_receipt"], verification_receipts=receipts))
        self.assertEqual(denied["error"]["code"], "E_HIA_EVALUATION_REQUIRED")
        self.assertIsNone(self.service.inspect_slot("wrong-bytes")["active_artifact"])

    def test_every_warmup_and_repetition_starts_from_original_mutable_bytes(self):
        params = [("bytes", "mutbuf")]
        document = {"schema": "hepta.hia.program.v8", "module": "increment_once", "functions": [
            f("increment", params, ["u32"], ["read", "write", "trap"], [b("entry", params, [
                c("zero", "usize", 0), i("buffer.load", ["bytes", "zero"], [("before", "u8")]),
                c("one", "u8", 1), i("int.add.wrap", ["before", "one"], [("after", "u8")]),
                i("buffer.store", ["bytes", "zero", "after"]), c("ok", "u32", 0)], ret("ok"))])]}
        cases = workload([{"function": "increment", "arguments": [byte_value(b"\xff")]},
                          {"function": "increment", "arguments": [byte_value(b"\x01")]}],
                         [{"function": "increment", "maximum_bytes": 8}], warmup=2, repetitions=5)
        _base, _revised, baseline, build, receipts = self.pair(source=document, cases=cases)
        evaluated = self.session.evaluate(baseline, build, receipts=receipts)
        self.assertEqual(evaluated["outcome"], "unchanged")
        measured = self.session.read_json(evaluated["measurements"])
        self.assertEqual(measured["observations"][0]["candidate_native"]["buffers"][0]["sha256"], sha256(b"\0").hexdigest())

    def test_mixed_register_and_stack_arguments_keep_exact_scalar_types(self):
        cases = workload([{"function": "mixed", "arguments": [3, -4, 9, True,
            byte_value(b"source"), 255, byte_value(b"_"), 11]}], [{"function": "mixed", "maximum_bytes": 32}])
        _base, _revised, baseline, build, receipts = self.pair(cases=cases)
        evaluated = self.session.evaluate(baseline, build, receipts=receipts)
        self.assertEqual(evaluated["outcome"], "unchanged")
        self.adopt(build, evaluated, receipts)
        lease = self.service.acquire_slot("copied-bytes")
        arguments = cases["cases"][0]["arguments"]
        result = self.service.invoke_lease(lease, "mixed", arguments)
        self.assertEqual(result["values"], [19])
        self.assertEqual(decode_bytes(result["arguments"][6]), b"\xff")
        for index, value in ((0, 256), (1, True), (3, 1), (7, -1)):
            invalid = deepcopy(arguments)
            invalid[index] = value
            with self.subTest(index=index), self.assertRaises(ValueError) as error, \
                    patch("hepta.hia_agent_runner.run_native_batch", side_effect=AssertionError("must reject before launch")):
                self.service.invoke_lease(lease, "mixed", invalid)
            self.assertEqual(error.exception.code, "E_HIA_ARGUMENTS")
        self.service.release_slot(lease)

    def test_out_of_bounds_core_trap_stays_a_trap_with_no_completed_byte_copy(self):
        cases = workload([{"function": "mixed", "arguments": [3, -4, 9, True,
            byte_value(b"source"), 255, byte_value(b""), 11], "expected": {"status": "trapped"}}],
            [{"function": "mixed", "maximum_bytes": 32}], warmup=0, repetitions=1)
        _base, _revised, baseline, build, receipts = self.pair(cases=cases)
        evaluated = self.session.evaluate(baseline, build, receipts=receipts)
        self.assertEqual(evaluated["outcome"], "unchanged")
        observed = self.session.read_json(evaluated["measurements"])["observations"][0]
        self.assertEqual(observed["candidate_vm"]["trap_code"], "bounds")
        self.assertEqual(observed["candidate_native"]["status"], "trapped")
        self.assertNotIn("buffers", observed["candidate_vm"])

    def test_invalid_byte_wires_and_duplicate_exports_fail_at_context_admission(self):
        invalid = []
        for value in ({"kind": "bytes", "base64": "AB=="}, {"kind": "bytes", "base64": "@@"},
                      {"kind": "bytes", "base64": "AA==", "address": 4096},
                      {"kind": "bytes", "base64": "é"}):
            case = workload()
            case["cases"][0]["arguments"][0] = value
            invalid.append(case)
        repeated = workload()
        repeated["foreign_buffer_exports"] *= 2
        invalid.append(repeated)
        fraction = workload()
        fraction["foreign_buffer_exports"][0]["maximum_bytes"] = 4096.0
        invalid.append(fraction)
        self.session.freeze(workload())
        template = deepcopy(next(row["arguments"] for row in reversed(self.client.records) if row["tool"] == "hia_context"))
        for case in invalid:
            with self.subTest(case=case["foreign_buffer_exports"]):
                arguments = {**template, "request_key": self.session.key("invalid-byte-context"),
                             "workload": self.session.artifact(case)}
                denied = self.reject("hia_context", arguments)
                self.assertIn(denied["error"]["code"], {"E_HIA_ARGUMENTS", "E_HIA_SCHEMA", "E_HIA_ABI"})

    def test_excess_extent_and_unexported_entry_reject_before_reference_or_native_launch(self):
        for cases in (workload([{"function": "copy_bytes", "arguments": [byte_value(b"large"), byte_value(b"x")]}],
                              [{"function": "copy_bytes", "maximum_bytes": 4}]),
                      workload([{"function": "readonly", "arguments": [byte_value(b""), byte_value(b"")]}])):
            with self.subTest(cases=cases):
                _base, _revised, baseline, build, receipts = self.pair(cases=cases)
                with patch("hepta.hia_agent_runner.run_reference_batch", side_effect=AssertionError("must reject before reference")), \
                     patch("hepta.hia_agent_runner.run_native_batch", side_effect=AssertionError("must reject before native")):
                    denied = self.reject("hia_evaluate", self.session.arguments(
                        baseline_artifact=baseline["native_artifact"], candidate_artifact=build["native_artifact"],
                        build_receipt=build["build_receipt"], verification_receipts=receipts))
                self.assertEqual(denied["error"]["code"], "E_HIA_ARGUMENTS")

    def test_frozen_extent_is_part_of_retained_build_identity(self):
        _base, _revised, _baseline, build, _receipts = self.pair()
        row = self.service.store.db.execute("SELECT metadata FROM artifacts WHERE id=?", (build["native_artifact"]["id"],)).fetchone()
        metadata = json.loads(row["metadata"])
        metadata["foreign_buffer_exports"][0][1] += 1
        self.service.store.db.execute("UPDATE artifacts SET metadata=? WHERE id=?", (json.dumps(metadata), build["native_artifact"]["id"]))
        with self.assertRaisesRegex(ValueError, "admitted Core identity"):
            self.service._native(build["native_artifact"], self.session.context)

    def test_aggregate_byte_and_frozen_reference_budgets_fail_before_any_context_is_created(self):
        self.session.freeze(workload())
        template = deepcopy(next(row["arguments"] for row in reversed(self.client.records) if row["tool"] == "hia_context"))
        count = self.service.store.db.execute("SELECT count(*) FROM contexts").fetchone()[0]
        cases = workload([{"function": "copy_bytes", "arguments": [byte_value(bytes(1 << 20)), byte_value(b"")]}
                          for _ in range(5)], [{"function": "copy_bytes", "maximum_bytes": 1 << 20}])
        path = self.files_root / "excess-workload.json"
        raw = json.dumps(cases).encode()
        path.write_bytes(raw)
        artifact = self.client.result("hia_artifact", self.session.arguments(context=False,
            artifact_profile=self.session.profiles["artifact"], source={"kind": "path", "path": str(path),
                "expected_sha256": sha256(raw).hexdigest(), "max_bytes": len(raw)}))["artifact"]
        rejected = self.reject("hia_context", {**template, "request_key": self.session.key("excess-bytes"), "workload": artifact})
        self.assertEqual(rejected["error"]["code"], "E_HIA_BUDGET")
        for steps in (0, 10000001, True, 1000000.0):
            invalid = workload()
            invalid["reference_max_steps"] = steps
            with self.subTest(steps=steps):
                denied = self.reject("hia_context", {**template, "request_key": self.session.key("bad-steps"),
                    "workload": self.session.artifact(invalid)})
                self.assertIn(denied["error"]["code"], {"E_HIA_BUDGET", "E_HIA_SCHEMA"})
        self.assertEqual(self.service.store.db.execute("SELECT count(*) FROM contexts").fetchone()[0], count)

    def test_byte_native_refinement_remains_unsupported_and_required_claim_cannot_be_bypassed(self):
        objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
            "required_claims": ["core_admission", "encoding_check", "lowering_refinement"],
            "allow_unchanged": True, "min_improvement_ratio": 0.0}
        _base, candidate, baseline, build, receipts = self.pair(objective=objective)
        proof = self.session.verify(candidate, subject={"kind": "native_artifact",
            "backend_profile": self.session.backend, "native_artifact": build["native_artifact"],
            "build_receipt": build["build_receipt"]}, claims=["lowering_refinement"])
        self.assertEqual(proof["checks"][0]["status"], "unsupported")
        denied = self.reject("hia_evaluate", self.session.arguments(baseline_artifact=baseline["native_artifact"],
            candidate_artifact=build["native_artifact"], build_receipt=build["build_receipt"],
            verification_receipts=receipts + [proof["verification_receipt"]]))
        self.assertEqual(denied["error"]["code"], "E_HIA_CLAIM_REQUIRED")

    def test_real_byte_timeout_does_not_publish_an_adoptable_evaluation(self):
        _base, _revised, baseline, build, receipts = self.pair(budget={"max_native_wall_ms": 1})
        evaluated = self.session.evaluate(baseline, build, receipts=receipts)
        self.assertEqual(evaluated["outcome"], "budget_exceeded")
        self.assertFalse(evaluated["planned_workload_complete"])
        denied = self.reject("hia_adopt", self.session.arguments(target_slot="timeout",
            expected_current={"generation": "0", "epoch": "0"}, candidate_artifact=build["native_artifact"],
            evaluation_receipt=evaluated["evaluation_receipt"], verification_receipts=receipts))
        self.assertEqual(denied["error"]["code"], "E_HIA_EVALUATION_REQUIRED")

    def test_consumer_rejects_changed_input_or_extent_even_with_consistent_output_hashes(self):
        from hepta.hia_agent_runner import run_native_batch
        cases = workload([{"function": "mixed", "arguments": [3, -4, 9, True,
            byte_value(b"source"), 255, byte_value(b"_"), 11]}], [{"function": "mixed", "maximum_bytes": 32}])
        _base, _revised, baseline, build, receipts = self.pair(cases=cases)
        evaluated = self.session.evaluate(baseline, build, receipts=receipts)
        self.adopt(build, evaluated, receipts)
        lease = self.service.acquire_slot("copied-bytes")
        data, metadata, _program = self.service._native(build["native_artifact"])
        observed = run_native_batch(data, metadata["signatures"], cases["cases"], include_buffers=True)
        signature = metadata["signatures"]["mixed"]
        for index, replacement in ((4, byte_value(b"change")), (6, byte_value(b"")), (0, 4)):
            forged = deepcopy(observed)
            row = forged["report"]["observations"][0]
            row["arguments"][index] = replacement
            row["buffers"] = byte_observations(signature["params"], decode_arguments(signature, row["arguments"]))
            with self.subTest(index=index), patch("hepta.hia_agent_runner.run_native_batch", return_value=forged), \
                    self.assertRaises(ValueError) as error:
                self.service.invoke_lease(lease, "mixed", cases["cases"][0]["arguments"])
            self.assertEqual(error.exception.code, "E_HIA_NATIVE_REPORT")
        self.service.release_slot(lease)


if __name__ == "__main__":
    unittest.main()
