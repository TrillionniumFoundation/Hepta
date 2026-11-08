"""Real bounded buffer calls through retained verification and generation leases."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import platform
import shutil
import unittest
from unittest.mock import patch

from hepta.hia_agent_buffers import PROFILE, buffer_observation
from hepta.hia_agent_runner import run_native_batch
from hepta.hia_agent_store import AgentRejected
from tests.test_hia_agent_native_tools import AgentToolCase
from tests.test_hia_native_byte_abi import byte_program
from tests.test_hia_program import b, c, f, i, jump, ret


NATIVE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
          and shutil.which("ld") is not None)


def workload(cases=None, *, function="copy_bytes", extent=4096, repetitions=1, warmup=0):
    return {"schema": "hepta.hia.agent.workload.v2",
        "foreign_buffer_exports": [{"function": function, "max_buffer_bytes": extent}],
        "cases": cases or [{"function": function,
            "arguments": [{"bytes_hex": "0061ff"}, {"byte_length": 5, "fill_byte": 165}],
            "expected": {"status": "returned", "values": [0]}}],
        "warmup_iterations": warmup, "repetitions": repetitions}


def trap_program(value=91):
    params = [("output", "mutbuf")]
    return {"schema": "hepta.hia.program.v8", "module": "trap_writes",
        "functions": [f("write_then_trap", params, ["u32"], ["write", "trap"], [
            b("entry", params, [c("index", "usize", 0), c("byte", "u8", value),
                i("buffer.store", ["output", "index", "byte"])],
              {"op": "trap", "code": "bounds"})])]}


@unittest.skipUnless(NATIVE, "Linux x86-64 and GNU ld are required")
class BufferLifecycleTests(AgentToolCase):
    def pair(self, document=None, candidate=None, *, work=None, objective=None):
        self.session.freeze(work or workload(), objective=objective)
        original = self.session.import_program(document or byte_program())
        revised = self.session.import_program(candidate or document or byte_program())
        admitted = self.session.verify(revised)
        base_build = self.session.emit(original)
        built = self.session.emit(revised, receipts=[admitted["verification_receipt"]])
        encoded = self.session.encoding(revised, built)
        self.assertEqual(encoded["checks"][0]["status"], "proved")
        receipts = [admitted["verification_receipt"], encoded["verification_receipt"]]
        return original, revised, base_build, built, receipts

    def adopt(self, built, evaluation, receipts, *, expected=None):
        return self.client.result("hia_adopt", self.session.arguments(target_slot="byte-lifecycle",
            expected_current=expected or {"generation": "0", "epoch": "0"},
            candidate_artifact=built["native_artifact"],
            evaluation_receipt=evaluation["evaluation_receipt"], verification_receipts=receipts))

    def test_explicit_profile_exports_real_bytes_and_retains_abi_in_build(self):
        _original, _revised, base, built, receipts = self.pair()
        record = self.session.read_json(built["build_receipt"])
        self.assertEqual(record["foreign_buffer_exports"], [["copy_bytes", 4096]])
        self.assertEqual(record["native_build"]["foreign_buffer_exports"], record["foreign_buffer_exports"])
        self.assertEqual(record["signatures"]["copy_bytes"]["abi"], PROFILE)
        self.assertNotIn("read_byte", record["signatures"])
        result = self.session.evaluate(base, built, receipts=receipts)
        self.assertEqual(result["outcome"], "unchanged")
        self.assertTrue(result["planned_workload_complete"])
        row = self.session.read_json(result["measurements"])["observations"][0]
        expected = [buffer_observation(0, "readbuf", b"\0a\xff"),
                    buffer_observation(1, "mutbuf", b"\0a\xff\xa5\xa5")]
        for name in ("baseline_vm", "candidate_vm", "baseline_native", "candidate_native"):
            self.assertEqual(row[name]["buffers"], expected)
        self.assertEqual(row["baseline_vm"]["ledger"]["resources"]["allocations"], 0)
        self.assertEqual(row["baseline_vm"]["ledger"]["external_buffers"]["byte_length"], 8)

    def test_adoption_consumer_bytes_survive_rollback_and_release_fences(self):
        _original, _revised, base, built, receipts = self.pair()
        evaluation = self.session.evaluate(base, built, receipts=receipts)
        adopted = self.adopt(built, evaluation, receipts)
        lease = self.service.acquire_slot("byte-lifecycle")
        rolled = self.client.result("hia_rollback", self.session.arguments(target_slot="byte-lifecycle",
            expected_current=adopted["current"], retained_generation="0", reason="test future acquisition rollback"))
        self.assertEqual(rolled["current"], {"generation": "0", "epoch": "2"})
        result = self.service.invoke_lease(lease, "copy_bytes",
            [{"bytes_hex": "0102fe"}, {"byte_length": 4, "fill_byte": 3}])
        self.assertEqual(result["status"], "returned")
        self.assertEqual(result["generation"], "1")
        self.assertEqual(self.session.read(result["buffers"][1]["artifact"]), b"\x01\x02\xfe\x03")
        for row in result["buffers"]:
            self.assertEqual(row["sha256"], row["artifact"]["sha256"])
        current_lease = self.service.acquire_slot("byte-lifecycle")
        self.assertEqual(current_lease["generation"], "0")
        self.service.release_slot(lease)
        self.service.release_slot(current_lease)
        with self.assertRaisesRegex(AgentRejected, "released"):
            self.service.invoke_lease(lease, "copy_bytes", [{"bytes_hex": ""}, {"bytes_hex": ""}])

    def test_same_output_status_cannot_hide_changed_buffer_bytes(self):
        original = byte_program()
        changed = deepcopy(original)
        body = next(block for block in changed["functions"][0]["blocks"] if block["id"] == "body")
        body["ops"].insert(1, c("wrong", "u8", 99))
        body["ops"][2]["args"][2] = "wrong"
        _original, _revised, base, built, receipts = self.pair(original, changed)
        result = self.session.evaluate(base, built, receipts=receipts)
        self.assertEqual(result["outcome"], "incorrect")
        rejection = self.reject("hia_adopt", self.session.arguments(target_slot="byte-lifecycle",
            expected_current={"generation": "0", "epoch": "0"}, candidate_artifact=built["native_artifact"],
            evaluation_receipt=result["evaluation_receipt"], verification_receipts=receipts))
        self.assertEqual(rejection["error"]["code"], "E_HIA_EVALUATION_REQUIRED")

    def test_abort_snapshot_preserves_writes_and_detects_a_changed_prefix(self):
        work = workload([{"function": "write_then_trap", "arguments": [{"bytes_hex": "010203"}],
                          "expected": {"status": "trapped"}}], function="write_then_trap")
        _original, _revised, base, built, receipts = self.pair(trap_program(), work=work)
        result = self.session.evaluate(base, built, receipts=receipts)
        self.assertEqual(result["outcome"], "unchanged")
        self.assertTrue(result["termination_confirmed"])
        observed = self.session.read_json(result["measurements"])["observations"][0]
        expected = [buffer_observation(0, "mutbuf", b"[\x02\x03")]
        for label in ("baseline_vm", "candidate_vm", "baseline_native", "candidate_native"):
            self.assertEqual(observed[label]["buffers"], expected)
        _original, _revised, base, built, receipts = self.pair(trap_program(), trap_program(92), work=work)
        result = self.session.evaluate(base, built, receipts=receipts)
        self.assertEqual(result["outcome"], "incorrect")

    def test_every_warmup_and_repetition_starts_with_fresh_owned_bytes(self):
        params = [("output", "mutbuf")]
        doc = {"schema": "hepta.hia.program.v8", "module": "fresh_input",
            "functions": [f("increment", params, ["u32"], ["read", "write", "trap"], [b("entry", params,
                [c("at", "usize", 0), c("one", "u8", 1), i("buffer.load", ["output", "at"], [("before", "u8")]),
                 i("int.add.wrap", ["before", "one"], [("after", "u8")]), i("buffer.store", ["output", "at", "after"]),
                 i("int.cast", ["after"], [("result", "u32")], mode="wrap")], ret("result"))])]}
        work = workload([{"function": "increment", "arguments": [{"bytes_hex": "07"}],
                          "expected": {"status": "returned", "values": [8]}}],
                        function="increment", repetitions=5, warmup=3)
        _original, _revised, base, built, receipts = self.pair(doc, work=work)
        result = self.session.evaluate(base, built, receipts=receipts)
        self.assertEqual(result["outcome"], "unchanged")
        measurements = self.session.read_json(result["measurements"])
        for label in ("baseline", "candidate"):
            report = measurements["native_runs"][label]["normal"]["report"]
            self.assertEqual(report["measured_calls"], 5)
            self.assertFalse(report["observations"][0]["mismatch"])
            self.assertEqual(report["observations"][0]["buffers"][0]["sha256"], sha256(b"\x08").hexdigest())

    def test_mixed_register_stack_scalars_and_empty_buffers_are_exact(self):
        mixed = workload([{"function": "mixed", "arguments": [255, -7, 17, True,
            {"bytes_hex": ""}, 231, {"bytes_hex": "00"}, 99],
            "expected": {"status": "returned", "values": [364]}}], function="mixed", extent=8)
        _original, _revised, base, built, receipts = self.pair(work=mixed)
        result = self.session.evaluate(base, built, receipts=receipts)
        self.assertEqual(result["outcome"], "unchanged")
        row = self.session.read_json(result["measurements"])["observations"][0]
        self.assertEqual(row["candidate_native"]["buffers"],
            [buffer_observation(4, "readbuf", b""), buffer_observation(6, "mutbuf", b"\xe7")])

    def test_invalid_byte_shapes_and_extent_never_enter_native_execution(self):
        _original, _revised, base, built, receipts = self.pair(work=workload(extent=8))
        evaluation = self.session.evaluate(base, built, receipts=receipts)
        self.adopt(built, evaluation, receipts)
        lease = self.service.acquire_slot("byte-lifecycle")
        malformed = [{"pointer": 1, "length": 1}, {"bytes_hex": "ff "}, {"bytes_hex": "FF"},
                     {"bytes_hex": "0"}, {"byte_length": True, "fill_byte": 0},
                     {"byte_length": 9, "fill_byte": 0}]
        with patch("hepta.hia_agent_runner.run_native_batch", side_effect=AssertionError("native execution")):
            for value in malformed:
                with self.subTest(value=value), self.assertRaises(AgentRejected):
                    self.service.invoke_lease(lease, "copy_bytes", [value, {"bytes_hex": ""}])
        self.service.release_slot(lease)

    def test_workload_byte_budget_and_duplicate_exports_are_rejected_at_context(self):
        duplicate = workload()
        duplicate["foreign_buffer_exports"].append({"function": "copy_bytes", "max_buffer_bytes": 9})
        oversized = workload([{"function": "copy_bytes", "arguments": [
            {"byte_length": 1048576, "fill_byte": 0}, {"byte_length": 1048576, "fill_byte": 0}]}
            for _ in range(17)], extent=1048576)
        for work, code in [(duplicate, "E_HIA_BYTE_ABI"), (oversized, "E_HIA_BUFFER_BUDGET")]:
            self.session.freeze(workload())
            args = self.session.arguments(context=False, compiler_profile=self.session.profiles["compiler"],
                target_profile=self.session.profiles["target"], baseline_program=None,
                workload=self.session.artifact(work), objective=self.service._context(self.session.context)["objective"],
                budget=self.service._context(self.session.context)["budget"])
            self.assertEqual(self.reject("hia_context", args)["error"]["code"], code)

    def test_refinement_stays_unsupported_and_required_proof_blocks_adoption(self):
        objective = {"schema": "hepta.hia.agent.objective.v1", "metric": "artifact_bytes",
            "required_claims": ["core_admission", "lowering_refinement"],
            "allow_unchanged": True, "min_improvement_ratio": 0}
        _original, revised, base, built, receipts = self.pair(objective=objective)
        proof = self.session.verify(revised, claims=["lowering_refinement"], subject={
            "kind": "native_artifact", "backend_profile": self.session.backend,
            "native_artifact": built["native_artifact"], "build_receipt": built["build_receipt"]})
        self.assertEqual(proof["checks"][0]["status"], "unsupported")
        self.assertFalse(proof["checks"][0]["global_safety_proved"])
        refused = self.reject("hia_evaluate", self.session.arguments(
            baseline_artifact=base["native_artifact"], candidate_artifact=built["native_artifact"],
            build_receipt=built["build_receipt"], verification_receipts=receipts + [proof["verification_receipt"]]))
        self.assertEqual(refused["error"]["code"], "E_HIA_CLAIM_REQUIRED")

    def test_normal_scalar_workload_does_not_opt_into_buffer_exports(self):
        scalar = {"schema": "hepta.hia.agent.workload.v1", "cases": [{"function": "copy_bytes", "arguments": [0, 0]}],
                  "warmup_iterations": 0, "repetitions": 1}
        self.session.freeze(scalar)
        candidate = self.session.import_program(byte_program())
        error = self.reject("hia_emit", self.session.arguments(candidate=candidate, backend_profile=self.session.backend,
            output_kind="shared", codegen={"kind": "canonical", "lowering_profile": self.session.profiles["lowering"]},
            verification_receipts=[]))
        self.assertIn("entrypoints", error["error"]["message"])

    def test_timeout_retains_partial_external_write_but_never_success(self):
        params = [("output", "mutbuf")]
        doc = {"schema": "hepta.hia.program.v8", "module": "bounded_infinite",
            "functions": [f("loop_forever", params, ["u32"], ["write", "trap"], [
                b("entry", params, [c("at", "usize", 0), c("v", "u8", 73),
                    i("buffer.store", ["output", "at", "v"])], jump("loop")),
                b("loop", [], [], jump("loop"))])]}
        self.session.freeze(workload([{"function": "loop_forever", "arguments": [{"bytes_hex": "00"}]}],
                                     function="loop_forever", extent=1))
        program = self.session.import_program(doc)
        built = self.session.emit(program)
        data, metadata, _ = self.service._native(built["native_artifact"])
        result = run_native_batch(data, metadata["signatures"],
            [{"function": "loop_forever", "arguments": [{"bytes_hex": "00"}]}], timeout_ms=1000)
        self.assertEqual(result["status"], "budget_exceeded")
        self.assertTrue(result["termination_confirmed"])
        self.assertEqual(result["buffer_snapshots"][0]["buffers"], [buffer_observation(0, "mutbuf", b"I")])


if __name__ == "__main__":
    unittest.main()
