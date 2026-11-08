"""Stopped borrowed calls retain external bytes without inventing Core owners.

These are finite VM/native observations and deliberately corrupted report
controls. They do not prove the dynamic view graph or compiler refinement.
"""
from copy import deepcopy
import platform
import shutil
import unittest
from unittest.mock import patch

from hepta.hia_agent_buffers import PROFILE, buffer_observation, reference_observation
from hepta.hia_opcodes import ExecutionObservationRejected, validate_execution_observation
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta import hia_program_runtime as runtime
from tests.test_hia_agent_native_tools import AgentToolCase
from tests.test_hia_program import b, c, f, i, ret


CALL = {"function": "entry", "arguments": [{"bytes_hex": "0000"}]}
EXPORTS = (("entry", 64),)
NATIVE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
          and shutil.which("ld") is not None)


def stopped_program(*, returned=False):
    params = [("input", "mutbuf")]
    ops = [i("borrow.mut", ["input"], [("child", "mutbuf")]),
           c("offset", "usize", 0), c("value", "u8", 171),
           i("buffer.store", ["child", "offset", "value"])]
    term = {"op": "trap", "code": "bounds"}
    if returned:
        ops += [i("loan.end", ["child"]), c("result", "u32", 7)]
        term = ret("result")
    return {"schema": "hepta.hia.program.v8", "module": "external_root_regression",
            "functions": [f("entry", params, ["u32"], ["read", "write", "trap"],
                            [b("b0", params, ops, term)])]}


def stopped_machine():
    machine = runtime._Machine(verify_program(stopped_program()), 100, 0, None, 256)
    root = runtime._Owner(-1, bytearray(b"\0\0"))
    view = runtime._View(root, True)
    try:
        machine.invoke(machine.functions["entry"], [view])
    except runtime.HIAProgramTrap as error:
        return machine, root, view, error
    raise AssertionError("fixture did not trap")


class ExternalRootReportTests(unittest.TestCase):
    def assert_external_stop(self, result, status, code, *, live_loans=1, byte_data=b"\xab\0"):
        self.assertEqual(result["status"], status)
        self.assertEqual(result["trap_code" if status == "trapped" else "budget_code"], code)
        self.assertEqual(result["buffers"], [buffer_observation(0, "mutbuf", byte_data)])
        ledger = result["ledger"]
        self.assertEqual(ledger["steps"], 6)
        self.assertEqual(ledger["resources"]["live_local_loans"], live_loans)
        self.assertEqual(ledger["resources"]["loans_started"], live_loans)
        self.assertEqual(ledger["resources"]["loans_ended"], 0)
        for name, count in ledger["resources"].items():
            if name not in {"loans_started", "live_local_loans"}:
                self.assertEqual(count, 0, name)
        self.assertEqual(ledger["external_buffers"], {"profile": PROFILE, "byte_length": 2,
            "distinct_roots": 1, "included_in_core_heap_ledger": False})
        self.assertFalse(ledger["claims"]["whole_language_soundness_proved"])
        self.assertFalse(ledger["claims"]["backend_refinement_proved"])

    def test_same_frozen_core_trap_and_budget_keep_real_external_write_and_local_loan(self):
        subjects = ((False, 100, "trapped", "bounds",
                     "a753045d796c1f28f2e858773b4fcf704e37be507c0ed360e023e7a415dcdb4c"),
                    (True, 5, "budget_exceeded", "steps",
                     "a6f1f2ca8c7eb918006c377104448beed839882488de600e2993ba4a932d4d4e"))
        for returned, steps, status, code, digest in subjects:
            with self.subTest(status=status):
                program = verify_program(stopped_program(returned=returned))
                self.assertEqual(program.sha256, digest)
                result = reference_observation(program, CALL, EXPORTS, steps=steps, heap=0)
                self.assert_external_stop(result, status, code)
                self.assertEqual(result["ledger"]["program_sha256"], digest)

    def test_normal_return_still_ends_local_loans_and_keeps_caller_storage(self):
        result = reference_observation(stopped_program(returned=True), CALL, EXPORTS, steps=100, heap=0)
        self.assertEqual(result["status"], "returned")
        self.assertEqual(result["values"], [7])
        self.assertEqual(result["buffers"], [buffer_observation(0, "mutbuf", b"\xab\0")])
        resources = result["ledger"]["resources"]
        self.assertEqual((resources["loans_started"], resources["loans_ended"],
                          resources["live_local_loans"]), (1, 1, 0))
        self.assertEqual((resources["owners_created"], resources["live_bytes"]), (0, 0))

    def test_read_only_nested_loans_and_empty_external_root_can_stop(self):
        params = [("input", "readbuf")]
        program = {"schema": "hepta.hia.program.v8", "module": "read_stop", "functions": [
            f("entry", params, ["u32"], ["read", "trap"], [b("b0", params, [
                i("borrow.read", ["input"], [("outer", "readbuf")]),
                i("borrow.read", ["outer"], [("inner", "readbuf")]),
                c("zero", "usize", 0), i("buffer.load", ["inner", "zero"], [("value", "u8")]),
            ], {"op": "trap", "code": "bounds"})])]}
        call = {"function": "entry", "arguments": [{"bytes_hex": ""}]}
        result = reference_observation(program, call, EXPORTS, steps=100, heap=0)
        self.assertEqual((result["status"], result["trap_code"]), ("trapped", "bounds"))
        self.assertEqual(result["buffers"], [buffer_observation(0, "readbuf", b"")])
        self.assertEqual(result["ledger"]["resources"]["live_local_loans"], 2)
        self.assertEqual(result["ledger"]["resources"]["live_owners"], 0)

    def test_default_raw_report_still_rejects_ownerless_live_loan(self):
        machine, root, _view, error = stopped_machine()
        with self.assertRaisesRegex(HIAProgramRejected, "no live byte owner"):
            machine.report("entry", "trapped", error=error)
        common = {"steps": machine.steps, "max_steps": 100, "max_heap_bytes": 0,
                  "error_code": "bounds", "with_chains": True}
        with self.assertRaisesRegex(ExecutionObservationRejected, "no live byte owner"):
            validate_execution_observation("trapped", machine.resources(), **common)
        accepted = machine.report("entry", "trapped", error=error, external_roots=(root,))
        self.assertEqual(accepted["resources"], machine.resources())

    def test_external_backing_does_not_relax_counter_heap_chain_or_return_contract(self):
        machine, _root, _view, _error = stopped_machine()
        common = {"steps": 6, "max_steps": 100, "max_heap_bytes": 0,
                  "with_chains": True, "live_external_roots": 1}
        mutations = [{"live_local_loans": 0}, {"loans_ended": 2}, {"owners_created": 1},
                     {"allocations": 1}, {"live_bytes": 1}, {"peak_bytes": 1},
                     {"chain_nodes_created": 1, "live_chain_nodes": 1}, {"future_resource": 0}]
        for change in mutations:
            with self.subTest(change=change), self.assertRaises(ExecutionObservationRejected):
                validate_execution_observation("trapped", {**machine.resources(), **change},
                                               error_code="bounds", **common)
        with self.assertRaisesRegex(ExecutionObservationRejected, "return retains resources"):
            validate_execution_observation("returned", machine.resources(), **common)
        for value in (True, 1.0, -1, 1 << 64):
            with self.subTest(value=value), self.assertRaises(ExecutionObservationRejected):
                validate_execution_observation("trapped", machine.resources(), error_code="bounds",
                                               **{**common, "live_external_roots": value})

    def test_external_root_context_is_actual_distinct_active_storage_outside_vm_heap(self):
        corruptions = {
            "not_tuple": lambda m, r: [r],
            "not_owner": lambda m, r: (object(),),
            "duplicate_object": lambda m, r: (r, r),
            "duplicate_identity": lambda m, r: (r, runtime._Owner(-1, bytearray())),
            "shared_storage": lambda m, r: (r, runtime._Owner(-2, r.data)),
            "zero_identity": lambda m, r: (runtime._Owner(0, bytearray()),),
            "positive_identity": lambda m, r: (runtime._Owner(1, bytearray()),),
            "boolean_identity": lambda m, r: (runtime._Owner(False, bytearray()),),
            "dead": lambda m, r: (runtime._Owner(-1, bytearray(), False),),
            "nonexact_active": lambda m, r: (runtime._Owner(-1, bytearray(), 1),),
            "immutable_storage": lambda m, r: (runtime._Owner(-1, b""),),
        }
        for name, corrupt in corruptions.items():
            machine, root, _view, error = stopped_machine()
            with self.subTest(name=name), self.assertRaisesRegex(HIAProgramRejected, "invalid external"):
                machine.report("entry", "trapped", error=error, external_roots=corrupt(machine, root))
        for key, same_object in ((1, True), (-1, False)):
            machine, root, _view, error = stopped_machine()
            machine.owners[key] = root if same_object else runtime._Owner(key, bytearray())
            with self.subTest(key=key), self.assertRaisesRegex(HIAProgramRejected, "invalid external"):
                machine.report("entry", "trapped", error=error, external_roots=(root,))

    def test_broken_caller_views_are_rejected_even_after_a_real_trap(self):
        original = runtime._Machine.invoke
        for field, value in (("active", False), ("active", 1), ("mutable", False),
                             ("mutable", 1), ("parent", runtime._Owner(-2, bytearray(2)))):
            def corrupt(machine, fn, args, depth=0):
                try:
                    return original(machine, fn, args, depth)
                except runtime.HIAProgramTrap:
                    setattr(args[0], field, value)
                    raise
            with self.subTest(field=field, value=value), patch.object(runtime._Machine, "invoke", corrupt):
                with self.assertRaisesRegex(HIAProgramRejected, "invalid external runtime views"):
                    reference_observation(stopped_program(), CALL, EXPORTS, steps=100, heap=0)


@unittest.skipUnless(NATIVE, "Linux x86-64 and GNU ld are required")
class ExternalRootLifecycleTests(AgentToolCase):
    def test_self_evaluation_reborrow_trap_matches_native_stopped_bytes(self):
        work = {"schema": "hepta.hia.agent.workload.v2", "foreign_buffer_exports": [
            {"function": "entry", "max_buffer_bytes": 64}],
            "cases": [{**deepcopy(CALL), "expected": {"status": "trapped"}}],
            "warmup_iterations": 0, "repetitions": 1}
        self.session.freeze(work)
        subject = self.session.import_program(stopped_program())
        admitted = self.session.verify(subject)
        built = self.session.emit(subject, receipts=[admitted["verification_receipt"]])
        encoded = self.session.encoding(subject, built)
        receipts = [admitted["verification_receipt"], encoded["verification_receipt"]]
        evaluation = self.session.evaluate(built, built, receipts=receipts)
        self.assertEqual(evaluation["outcome"], "unchanged")
        self.assertTrue(evaluation["planned_workload_complete"])
        self.assertTrue(evaluation["termination_confirmed"])
        row = self.session.read_json(evaluation["measurements"])["observations"][0]
        for name in ("baseline_vm", "candidate_vm", "baseline_native", "candidate_native"):
            self.assertEqual(row[name]["status"], "trapped")
            self.assertEqual(row[name]["buffers"], [buffer_observation(0, "mutbuf", b"\xab\0")])
        for name in ("baseline_vm", "candidate_vm"):
            self.assertEqual(row[name]["trap_code"], "bounds")
            self.assertEqual(row[name]["ledger"]["resources"]["live_local_loans"], 1)
            self.assertEqual(row[name]["ledger"]["resources"]["live_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
