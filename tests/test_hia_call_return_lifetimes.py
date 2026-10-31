"""Return-boundary loans survive independent leaf expansion and native lowering.

The semantic oracle is the existing non-expanded interpreter, plus independent
arithmetic answers. A well-typed numerical equivalent that erases a loan is not
accepted as an ordered resource-preserving expansion.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.hia_call_expansion import (
    build_expanded_native, propose_leaf_call_expansion, verify_leaf_call_expansion,
)
from hepta.hia_optimization_contract import POLICY_SCHEMA, qualify_expansion_contract
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from hepta.hia_program_source import lower_program
from hepta.hia_schema import SCHEMA_V8
from hepta.hia_static_budget import HIAStaticBudgetRejected
from hepta.modules import load_project
from tests.test_hia_program import b, branch, c, f, i, jump, ret
from tests.test_hia_returned_loans import (
    fallible_return_program, helper, loan_program, multiple_shared, swapped_mutable,
)


def cross_module_source():
    entry = Path(__file__).resolve().parents[1] / "examples/hia_call_return_lifetimes/client.hepta"
    return lower_program(load_project(entry).program, core_schema=SCHEMA_V8)


def loop_returned_loan():
    """Each iteration borrows from the same parent, then restores that parent."""
    forward = helper("read", "forward")
    run = f("repeat", [("n", "usize"), ("byte", "u8")], ["u64"],
            ["alloc", "read", "write", "trap"], [
        b("entry", [("n", "usize"), ("byte", "u8")], [
            c("size", "usize", 1), c("zero", "usize", 0), c("sum", "u64", 0),
            i("buffer.new", ["size"], [("owner", "buffer")]),
            i("borrow.mut", ["owner"], [("writer", "mutbuf")]),
            i("buffer.store", ["writer", "zero", "byte"]), i("loan.end", ["writer"]),
            i("borrow.read", ["owner"], [("parent", "readbuf")]),
        ], jump("head", "n", "owner", "parent", "zero", "sum")),
        b("head", [("hn", "usize"), ("ho", "buffer"), ("hp", "readbuf"),
                   ("hi", "usize"), ("hs", "u64")], [
            i("compare.lt", ["hi", "hn"], [("more", "bool")]),
        ], branch("more", ("body", "hn", "ho", "hp", "hi", "hs"), ("done", "ho", "hp", "hs"))),
        b("body", [("bn", "usize"), ("bo", "buffer"), ("bp", "readbuf"),
                   ("bi", "usize"), ("bs", "u64")], [
            i("call", ["bp"], [("child", "readbuf")], function=forward["name"]),
            c("index", "usize", 0), i("buffer.load", ["child", "index"], [("observed", "u8")]),
            i("loan.end", ["child"]), i("int.cast", ["observed"], [("wide", "u64")], mode="wrap"),
            i("int.add.wrap", ["bs", "wide"], [("next_sum", "u64")]), c("one", "usize", 1),
            i("int.add.checked", ["bi", "one"], [("next_index", "usize")]),
        ], jump("head", "bn", "bo", "bp", "next_index", "next_sum")),
        b("done", [("do", "buffer"), ("dp", "readbuf"), ("answer", "u64")], [
            i("loan.end", ["dp"]), i("owner.drop", ["do"]),
        ], ret("answer")),
    ])
    return {"schema": SCHEMA_V8, "module": "returned_loop", "exports": ["repeat"],
            "functions": [forward, run]}


def trap_after_returned_loan(mode="read"):
    source = loan_program(mode, "forward")
    operations = source["functions"][1]["blocks"][0]["ops"]
    position = next(n for n, op in enumerate(operations)
                    if op["op"] == "buffer.load" and op["args"][0] == "returned")
    operations.insert(position, c("bad_index", "usize", 1))
    operations[position + 1]["args"][1] = "bad_index"
    return source


def observe(program, function, arguments, **limits):
    try:
        report = execute_program(program, function, arguments, **limits)
    except (HIAProgramTrap, HIAProgramBudgetExceeded) as error:
        report = error.report
    return report


def comparable(report):
    return {"status": report["status"], "values": report.get("values"),
            "error": report.get("error", {}).get("code"), "resources": report["resources"]}


class ReturnedLoanExpansionTests(unittest.TestCase):
    def expansion(self, base):
        original = verify_program(base)
        proposal = propose_leaf_call_expansion(original)
        proof = verify_leaf_call_expansion(original, proposal)
        self.assertEqual(proof["status"], "verified", proof)
        self.assertFalse(proof["claims"]["vm_budget_failures_preserved"])
        return original, proposal, verify_program(proposal["candidate_core"])

    def test_shared_and_mutable_forwarding_preserve_parent_reuse(self):
        for mode in ("read", "mut"):
            original, _, candidate = self.expansion(loan_program(mode, "forward"))
            for length in (1, 3):
                for byte in (0, 1, 43, 251, 255):
                    with self.subTest(mode=mode, length=length, byte=byte):
                        before, after = [observe(core, "entry_" + mode + "_forward", [length, byte])
                                         for core in (original, candidate)]
                        self.assertEqual(comparable(before), comparable(after))
                        self.assertEqual(after["result"], byte if mode == "read" else (byte + 5) % 256)
                        self.assertEqual(after["resources"]["loans_started"], 3)
                        self.assertEqual(after["resources"]["loans_ended"], 3)

    def test_aliased_shared_formals_and_mixed_return_construction(self):
        for construction in ("forward", "mixed", "children"):
            original, _, candidate = self.expansion(multiple_shared(construction))
            for byte in (0, 43, 127, 128, 255):
                with self.subTest(construction=construction, byte=byte):
                    before, after = [observe(core, "shared", [byte]) for core in (original, candidate)]
                    self.assertEqual(comparable(before), comparable(after))
                    self.assertEqual(after["result"], 2 * byte % 256)
                    self.assertEqual(after["resources"]["loans_started"], 3)

    def test_distinct_mutable_result_origins_survive_reversed_return_order(self):
        original, _, candidate = self.expansion(swapped_mutable())
        before, after = [observe(core, "swapped", []) for core in (original, candidate)]
        self.assertEqual(comparable(before), comparable(after))
        self.assertEqual(after["result"], 71 - 43)
        self.assertEqual(after["resources"]["loans_started"], 4)

    def test_call_loop_keeps_owner_and_parent_through_all_edges(self):
        original, _, candidate = self.expansion(loop_returned_loan())
        for count in (0, 1, 2, 17):
            for byte in (0, 71, 255):
                with self.subTest(count=count, byte=byte):
                    before, after = [observe(core, "repeat", [count, byte]) for core in (original, candidate)]
                    self.assertEqual(comparable(before), comparable(after))
                    self.assertEqual(after["result"], count * byte)
                    self.assertEqual(after["resources"]["loans_started"], count + 2)

    def test_fallible_callee_and_post_return_trap_keep_exact_resource_prefixes(self):
        cases = [(fallible_return_program(), "fallible_entry", [], (None, 1, 2, 3))]
        cases += [(trap_after_returned_loan(mode), "entry_" + mode + "_forward", [1, 71], (None, 1))
                  for mode in ("read", "mut")]
        for source, entry, args, failures in cases:
            original, _, candidate = self.expansion(source)
            for fail_at in failures:
                with self.subTest(entry=entry, failure=fail_at):
                    before, after = [observe(core, entry, args, allocation_fail_at=fail_at)
                                     for core in (original, candidate)]
                    self.assertEqual(comparable(before), comparable(after))
                    if entry == "fallible_entry" and fail_at == 2:
                        self.assertEqual(after["result"], 0)
                    if entry != "fallible_entry" and fail_at is None:
                        self.assertEqual(after["error"]["code"], "bounds")
                        self.assertEqual(after["resources"]["live_local_loans"], 2)
                        self.assertEqual(after["resources"]["live_owners"], 1)

    def test_safe_numerical_equivalent_cannot_erase_return_boundary_loan(self):
        original, proposal, _ = self.expansion(loan_program("read", "forward"))
        operations = proposal["candidate_core"]["functions"][1]["blocks"][0]["ops"]
        boundary = next(op for op in operations if op["op"] == "borrow.read" and op["args"] == ["parent"])
        child = boundary["out"][0]["name"]
        operations[:] = [op for op in operations
                         if op is not boundary and not (op["op"] == "loan.end" and op["args"] == [child])]
        for op in operations:
            op["args"] = ["parent" if name == child else name for name in op["args"]]
        candidate = verify_program(proposal["candidate_core"])
        before, after = [observe(core, "entry_read_forward", [1, 71]) for core in (original, candidate)]
        self.assertEqual(before["result"], after["result"])
        self.assertNotEqual(before["resources"]["loans_started"], after["resources"]["loans_started"])
        self.assertEqual(verify_leaf_call_expansion(original, proposal)["status"], "rejected")

    def test_wrong_but_linear_return_origins_do_not_receive_equivalence_receipt(self):
        original, proposal, _ = self.expansion(swapped_mutable())
        operations = proposal["candidate_core"]["functions"][1]["blocks"][0]["ops"]
        boundaries = [op for op in operations if op["op"] == "borrow.mut" and op["args"][0] in {"left", "right"}]
        self.assertEqual(len(boundaries), 2)
        boundaries[0]["args"], boundaries[1]["args"] = boundaries[1]["args"], boundaries[0]["args"]
        candidate = verify_program(proposal["candidate_core"])
        self.assertNotEqual(execute_program(original, "swapped", [])["result"],
                            execute_program(candidate, "swapped", [])["result"])
        self.assertEqual(verify_leaf_call_expansion(original, proposal)["status"], "rejected")

    def test_fresh_resource_contract_is_bound_to_actual_forwarding_candidate(self):
        original, proposal, candidate = self.expansion(loan_program("read", "forward"))
        policy = {"schema": POLICY_SCHEMA, "budget_mode": "both_fit_same_quotas",
                  "max_allocator_interactions": 2, "max_vm_ticks": 64,
                  "max_call_depth": 2, "max_live_heap_bytes": 1}
        receipt = qualify_expansion_contract(original, proposal,
            function="entry_read_forward", arguments=[1, 71], policy=policy)
        self.assertEqual(receipt["candidate_sha256"], candidate.sha256)
        self.assertTrue(receipt["claims"]["actual_candidate_resource_limits_recomputed"])
        self.assertFalse(receipt["claims"]["exact_budget_stop_behavior_preserved"])

    def test_source_file_boundary_preserves_return_origins_and_cooperative_cancel(self):
        original, proposal, candidate = self.expansion(cross_module_source())
        self.assertEqual(len(proposal["sites"]), 2)
        callees = {row["callee"] for row in proposal["sites"]}
        self.assertTrue(all(fn.get("return_loans") for fn in original.as_dict()["functions"]
                            if fn["name"] in callees))
        for size in (0, 1, 3):
            for byte in (0, 71, 255):
                for cancel in (0, 1):
                    with self.subTest(size=size, byte=byte, cancel=cancel):
                        before, after = [observe(core, "cross_module", [size, byte, cancel])
                                         for core in (original, candidate)]
                        self.assertEqual(comparable(before), comparable(after))
                        if cancel or size:
                            self.assertEqual(after["result"], 0 if cancel else byte ^ 90)
                            self.assertEqual(after["resources"]["live_owners"], 0)
                            self.assertEqual(after["resources"]["live_local_loans"], 0)
                        else:
                            self.assertEqual(after["error"]["code"], "bounds")

    def test_finite_loop_observations_do_not_grant_an_unproved_static_quota(self):
        original, proposal, _ = self.expansion(loop_returned_loan())
        policy = {"schema": POLICY_SCHEMA, "budget_mode": "both_fit_same_quotas",
                  "max_allocator_interactions": 64, "max_vm_ticks": 4096,
                  "max_call_depth": 2, "max_live_heap_bytes": 4}
        with self.assertRaisesRegex(HIAStaticBudgetRejected, "E_HIA_BUDGET_UNBOUNDED"):
            qualify_expansion_contract(original, proposal, function="repeat", arguments=[17, 71], policy=policy)


@unittest.skipUnless(shutil.which(os.environ.get("CLANG", "clang")), "real Clang required")
class ReturnedLoanExpansionNativeTests(unittest.TestCase):
    def test_proof_bound_native_shared_mutable_alias_and_failure_result_paths(self):
        cases = [(loan_program("read", "forward"), "entry_read_forward", [ctypes.c_uint64, ctypes.c_uint8],
                  [[1, value] for value in (0, 71, 255)], [0, 71, 255]),
                 (loan_program("mut", "forward"), "entry_mut_forward", [ctypes.c_uint64, ctypes.c_uint8],
                  [[1, value] for value in (0, 71, 255)], [5, 76, 4]),
                 (multiple_shared("mixed"), "shared", [ctypes.c_uint8], [[0], [71], [255]], [0, 142, 254]),
                 (swapped_mutable(), "swapped", [], [[]], [28]),
                 (fallible_return_program(), "fallible_entry", [], [[]], [1]),
                 (cross_module_source(), "cross_module", [ctypes.c_uint64, ctypes.c_uint8, ctypes.c_uint8],
                  [[1, 0, 0], [1, 71, 0], [3, 255, 0], [0, 255, 1]], [90, 29, 165, 0])]
        for source, entry, argument_types, arguments, expected in cases:
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as directory:
                proposal = propose_leaf_call_expansion(source)
                target = Path(directory) / "expanded.so"
                build_expanded_native(source, proposal, target, clang=os.environ.get("CLANG", "clang"))
                library = ctypes.CDLL(str(target))
                function = getattr(library, entry)
                function.argtypes = argument_types
                function.restype = ctypes.c_uint8
                self.assertEqual([function(*args) for args in arguments], expected)


if __name__ == "__main__":
    unittest.main()
