"""Independent behavioral and adversarial controls for resolved leaf expansion."""
from __future__ import annotations

import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_call_expansion import (propose_leaf_call_expansion,
    verify_leaf_call_expansion, build_expanded_native, expansion_checker_identity,
    propose_expanded_guarded, verify_expanded_guarded, expanded_guarded_program,
    build_expanded_guarded_native)
from hepta.hia_optimization import OptimizationRejected, DEFAULT_POLICY
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program, HIAProgramTrap, HIAProgramBudgetExceeded
from tests.test_hia_program import m, f, b, i, c, ret, jump, branch
from tests.test_hia_program_composite import module, record


def loop_resources():
    """Two owners cross a resolved call and loop edge; the callee mutates both."""
    effects = ["alloc", "read", "write", "trap"]
    step = f("owned_step", [("a", "buffer"), ("z", "buffer"), ("value", "u8")],
             ["buffer", "buffer", "u8"], effects, [
        b("entry", [("a", "buffer"), ("z", "buffer"), ("value", "u8")], [
            c("zero", "usize", 0),
            i("borrow.mut", ["a"], [("av", "mutbuf")]),
            i("buffer.store", ["av", "zero", "value"]), i("loan.end", ["av"]),
            i("borrow.mut", ["z"], [("zv", "mutbuf")]),
            i("buffer.store", ["zv", "zero", "value"]), i("loan.end", ["zv"]),
            i("borrow.read", ["a"], [("reader", "readbuf")]),
            i("buffer.load", ["reader", "zero"], [("observed", "u8")]),
            i("loan.end", ["reader"]),
            i("owner.move", ["a"], [("an", "buffer")]),
            i("owner.move", ["z"], [("zn", "buffer")]),
        ], ret("an", "zn", "observed"))])
    run = f("run", [("n", "usize")], ["u64"], effects, [
        b("entry", [("n", "usize")], [
            c("size", "usize", 1), c("zero_index", "usize", 0), c("zero_sum", "u64", 0),
            i("buffer.new", ["size"], [("first", "buffer")]),
            i("buffer.new", ["size"], [("second", "buffer")]),
        ], jump("head", "n", "zero_index", "first", "second", "zero_sum")),
        b("head", [("hn", "usize"), ("hi", "usize"), ("ha", "buffer"),
                   ("hz", "buffer"), ("hs", "u64")], [
            i("compare.lt", ["hi", "hn"], [("more", "bool")]),
        ], branch("more", ("body", "hn", "hi", "ha", "hz", "hs"), ("done", "ha", "hz", "hs"))),
        b("body", [("bn", "usize"), ("bi", "usize"), ("ba", "buffer"),
                   ("bz", "buffer"), ("bs", "u64")], [
            i("int.cast", ["bi"], [("byte", "u8")], mode="wrap"),
            i("call", ["ba", "bz", "byte"], [("after_a", "buffer"), ("after_z", "buffer"),
                                               ("observed_byte", "u8")], function="owned_step"),
            i("int.cast", ["observed_byte"], [("wide", "u64")], mode="checked"),
            i("int.add.wrap", ["bs", "wide"], [("next_sum", "u64")]),
            c("one", "usize", 1), i("int.add.checked", ["bi", "one"], [("next_index", "usize")]),
        ], jump("head", "bn", "next_index", "after_a", "after_z", "next_sum")),
        b("done", [("da", "buffer"), ("dz", "buffer"), ("answer", "u64")], [
            i("owner.drop", ["da"]), i("owner.drop", ["dz"]),
        ], ret("answer")),
    ])
    data = m(step, run)
    data["exports"] = ["run"]
    return data


def loan_call():
    read = f("read", [("view", "readbuf"), ("index", "usize")], ["u8"], ["read", "trap"], [
        b("entry", [("view", "readbuf"), ("index", "usize")], [
            i("buffer.load", ["view", "index"], [("value", "u8")]),
        ], ret("value"))])
    use = f("use", [("index", "usize")], ["u8"], ["alloc", "read", "trap"], [
        b("entry", [("index", "usize")], [
            c("size", "usize", 1), i("buffer.new", ["size"], [("owner", "buffer")]),
            i("borrow.read", ["owner"], [("reader", "readbuf")]),
            i("call", ["reader", "index"], [("value", "u8")], function="read"),
            i("loan.end", ["reader"]), i("owner.drop", ["owner"]),
        ], ret("value"))])
    return m(read, use)


def bundle_call():
    pair = record("Owners", [("first", "buffer"), ("second", "buffer")])
    dispose = f("dispose", [("pair", "Owners")], ["usize"], ["alloc", "trap"], [
        b("entry", [("pair", "Owners")], [
            i("record.unpack", ["pair"], [("a", "buffer"), ("z", "buffer")]),
            i("buffer.len", ["a"], [("al", "usize")]),
            i("buffer.len", ["z"], [("zl", "usize")]),
            i("int.add.checked", ["al", "zl"], [("length", "usize")]),
            i("owner.drop", ["z"]), i("owner.drop", ["a"]),
        ], ret("length"))])
    use = f("bundle", [("n", "usize")], ["usize"], ["alloc", "trap"], [
        b("entry", [("n", "usize")], [
            i("buffer.new", ["n"], [("a", "buffer")]),
            i("buffer.new", ["n"], [("z", "buffer")]),
            i("record.make", ["a", "z"], [("pair", "Owners")]),
            i("call", ["pair"], [("length", "usize")], function="dispose"),
        ], ret("length"))])
    return module([pair], dispose, use)


def checked_loop_resources():
    core = loop_resources()
    core["functions"][1]["blocks"][2]["ops"][3]["op"] = "int.add.checked"
    return core


class ExpansionProofTests(unittest.TestCase):
    def test_loop_with_two_transferred_owners_and_multiple_returns(self):
        base = loop_resources()
        proposal = propose_leaf_call_expansion(base)
        proof = verify_leaf_call_expansion(base, proposal)
        self.assertEqual(proof["status"], "verified", proof)
        self.assertEqual(proof["call_sites"], 1)
        for n in (0, 1, 2, 17, 255, 256, 257, 1025):
            left, right = [execute_program(p, "run", [n]) for p in (base, proposal["candidate_core"])]
            self.assertEqual(left["result"], sum(k % 256 for k in range(n)))
            self.assertEqual(left["result"], right["result"])
            self.assertEqual(left["resources"], right["resources"])
            self.assertEqual(right["resources"]["allocations"], 2)
            self.assertEqual(right["resources"]["frees"], 2)
            self.assertEqual(right["resources"]["live_owners"], 0)

    def test_borrowed_call_trap_order_and_live_resource_observation(self):
        base = loan_call()
        proposal = propose_leaf_call_expansion(base)
        self.assertEqual(verify_leaf_call_expansion(base, proposal)["status"], "verified")
        for index in (0, 1, 2**64 - 1):
            records = []
            for core in (base, proposal["candidate_core"]):
                try:
                    value = execute_program(core, "use", [index])
                    records.append((value["status"], value["result"], value["resources"]))
                except HIAProgramTrap as error:
                    records.append((error.code, error.report["resources"]))
            self.assertEqual(records[0], records[1])
            if index:
                self.assertEqual(records[0][1]["live_owners"], 1)

    def test_nominal_composite_elaborates_before_leaf_proof(self):
        base = bundle_call()
        proposal = propose_leaf_call_expansion(base)
        self.assertEqual(verify_leaf_call_expansion(base, proposal)["status"], "verified")
        for n in (0, 1, 31):
            reports = [execute_program(p, "bundle", [n]) for p in (base, proposal["candidate_core"])]
            self.assertEqual(reports[0]["result"], 2 * n)
            self.assertEqual(reports[0]["resources"], reports[1]["resources"])

    def test_harmful_reordering_is_rejected_even_when_ordinary_core_is_valid(self):
        base = loop_resources()
        for attack in ("drop_order", "value", "trap", "callee", "loop_exit", "effect_order"):
            proposal = propose_leaf_call_expansion(base)
            candidate = proposal["candidate_core"]
            body = candidate["functions"][1]["blocks"][2]
            if attack == "drop_order":
                candidate["functions"][1]["blocks"][3]["ops"].reverse()
            elif attack == "value":
                body["ops"][0]["attrs"]["mode"] = "checked"
            elif attack == "trap":
                body["ops"][-1]["op"] = "int.add.wrap"
            elif attack == "callee":
                candidate["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 1
            elif attack == "loop_exit":
                candidate["functions"][1]["blocks"][1]["term"]["then"], candidate["functions"][1]["blocks"][1]["term"]["else"] = (
                    candidate["functions"][1]["blocks"][1]["term"]["else"], candidate["functions"][1]["blocks"][1]["term"]["then"])
            else:
                # Two complete, nonaliasing write/loan groups are statically
                # safe to exchange, but ordered resource equivalence forbids it.
                body["ops"][2:8] = body["ops"][5:8] + body["ops"][2:5]
            verify_program(candidate)
            self.assertEqual(verify_leaf_call_expansion(base, proposal)["status"], "rejected", attack)

    def test_missing_duplicated_forged_sites_and_unsafe_candidate_fail_closed(self):
        base = loop_resources()
        for attack in ("absent", "duplicate", "wrong_callee", "wrong_index", "wrong_source", "drop", "alias"):
            proposal = propose_leaf_call_expansion(base)
            if attack == "absent": proposal["sites"] = []
            elif attack == "duplicate": proposal["sites"] *= 2
            elif attack == "wrong_callee": proposal["sites"][0]["callee"] = "run"
            elif attack == "wrong_index": proposal["sites"][0]["operation"] = 999
            elif attack == "wrong_source": proposal["base_sha256"] = "0" * 64
            elif attack == "drop": proposal["candidate_core"]["functions"][1]["blocks"][3]["ops"].pop()
            else:
                term = proposal["candidate_core"]["functions"][1]["blocks"][2]["term"]
                term["args"][3] = term["args"][2]
            self.assertEqual(verify_leaf_call_expansion(base, proposal)["status"], "rejected", attack)

    def test_fresh_names_are_unique_across_caller_branches(self):
        leaf = f("leaf", [("a", "u32")], ["u32"], [], [
            b("entry", [("a", "u32")], [c("one", "u32", 1),
                i("int.add.wrap", ["a", "one"], [("sum", "u32")])], ret("sum"))])
        caller = f("caller", [("flag", "bool"), ("x", "u32")], ["u32"], [], [
            b("entry", [("flag", "bool"), ("x", "u32")], [], branch("flag", ("yes", "x"), ("no", "x"))),
            b("yes", [("inline_1", "u32")], [i("call", ["inline_1"], [("y", "u32")], function="leaf")], ret("y")),
            b("no", [("z", "u32")], [i("call", ["z"], [("n", "u32")], function="leaf")], ret("n")),
        ])
        base = m(leaf, caller)
        proposal = propose_leaf_call_expansion(base)
        self.assertEqual(verify_leaf_call_expansion(base, proposal)["status"], "verified")
        for flag in (False, True):
            self.assertEqual(execute_program(proposal["candidate_core"], "caller", [flag, 41])["result"], 42)

    def test_direct_parameter_return_and_nonleaf_exclusion(self):
        identity = f("identity", [("a", "u32")], ["u32"], [], [b("entry", [("a", "u32")], [], ret("a"))])
        outer = f("outer", [("x", "u32")], ["u32"], [], [b("entry", [("x", "u32")], [
            i("call", ["x"], [("y", "u32")], function="identity")], ret("y"))])
        base = m(identity, outer)
        proposal = propose_leaf_call_expansion(base)
        self.assertEqual(verify_leaf_call_expansion(base, proposal)["status"], "verified")
        self.assertEqual(execute_program(proposal["candidate_core"], "outer", [42])["result"], 42)
        with self.assertRaises(OptimizationRejected):
            propose_leaf_call_expansion(base, callees=["outer"])
        with self.assertRaises(OptimizationRejected):
            propose_leaf_call_expansion(base, callees=["identity", "identity"])

    def test_budget_difference_is_explicit_and_never_a_preserved_trap_claim(self):
        base = loan_call()
        proposal = propose_leaf_call_expansion(base)
        proof = verify_leaf_call_expansion(base, proposal)
        self.assertFalse(proof["claims"]["vm_budget_failures_preserved"])
        with self.assertRaises(HIAProgramBudgetExceeded):
            execute_program(base, "use", [0], max_call_depth=1)
        self.assertEqual(execute_program(proposal["candidate_core"], "use", [0], max_call_depth=1)["result"], 0)


@unittest.skipUnless(shutil.which(os.environ.get("CLANG", "clang")), "real Clang required")
class ExpansionNativeTests(unittest.TestCase):
    def test_proof_binds_actual_native_bytes_and_loop_result(self):
        base = loop_resources()
        proposal = propose_leaf_call_expansion(base)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "expanded.so"
            receipt = build_expanded_native(base, proposal, path, clang=os.environ.get("CLANG", "clang"))
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), receipt["native"]["artifact_sha256"])
            self.assertEqual(receipt["native"]["core_sha256"], receipt["verification"]["candidate_sha256"])
            function = ctypes.CDLL(str(path)).run
            function.argtypes, function.restype = [ctypes.c_uint64], ctypes.c_uint64
            for n in (0, 1, 257, 1025):
                self.assertEqual(function(n), sum(k % 256 for k in range(n)))
            with self.assertRaises(OptimizationRejected):
                build_expanded_native(base, proposal, path, clang=os.environ.get("CLANG", "clang"))

    def test_forged_native_work_is_not_started(self):
        base = loop_resources()
        proposal = propose_leaf_call_expansion(base)
        proposal["candidate_core"]["functions"][1]["blocks"][3]["ops"].reverse()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "never.so"
            with patch("hepta.hia_program_llvm.build_program_native", side_effect=AssertionError("compiled")):
                with self.assertRaises(OptimizationRejected):
                    build_expanded_native(base, proposal, path)
            self.assertFalse(path.exists())

    def test_checker_drift_after_real_compile_withdraws_artifact(self):
        from hepta.hia_program_llvm import build_program_native
        base = loop_resources()
        proposal = propose_leaf_call_expansion(base)
        identity, state = expansion_checker_identity(), {"built": False}
        def compile_then_change(*args, **kwargs):
            result = build_program_native(*args, **kwargs)
            state["built"] = True
            return result
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "never.so"
            with patch("hepta.hia_program_llvm.build_program_native", side_effect=compile_then_change), patch(
                "hepta.hia_call_expansion.expansion_checker_identity", side_effect=lambda: "f" * 64 if state["built"] else identity):
                with self.assertRaises(OptimizationRejected):
                    build_expanded_native(base, proposal, path, clang=os.environ.get("CLANG", "clang"))
            self.assertTrue(state["built"])
            self.assertFalse(path.exists())
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_real_compilation_of_wrong_core_cannot_launder_artifact_binding(self):
        from hepta.hia_program_llvm import build_program_native
        base = loop_resources()
        proposal = propose_leaf_call_expansion(base)
        def build_wrong_core(program, output, **kwargs):
            wrong = program.as_dict()
            done = wrong["functions"][1]["blocks"][3]
            done["ops"].append(c("wrong_answer", "u64", 1234))
            done["term"] = ret("wrong_answer")
            return build_program_native(wrong, output, **kwargs)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "never.so"
            with patch("hepta.hia_program_llvm.build_program_native", side_effect=build_wrong_core):
                with self.assertRaisesRegex(OptimizationRejected, "different Core"):
                    build_expanded_native(base, proposal, path, clang=os.environ.get("CLANG", "clang"))
            self.assertFalse(path.exists())
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_missing_receipt_identity_cannot_leave_a_published_artifact(self):
        from hepta.hia_program_llvm import build_program_native
        base = loop_resources()
        proposal = propose_leaf_call_expansion(base)
        def incomplete_receipt(*args, **kwargs):
            receipt = build_program_native(*args, **kwargs)
            receipt.pop("toolchain")
            return receipt
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "never.so"
            with patch("hepta.hia_program_llvm.build_program_native", side_effect=incomplete_receipt):
                with self.assertRaisesRegex(OptimizationRejected, "compiler identity"):
                    build_expanded_native(base, proposal, path, clang=os.environ.get("CLANG", "clang"))
            self.assertFalse(path.exists())
            self.assertEqual(list(Path(tmp).iterdir()), [])


try:
    import z3
except ImportError:
    z3 = None


@unittest.skipUnless(z3 is not None, "pinned Z3 required")
class ExpandedGuardTests(unittest.TestCase):
    def test_expansion_exposes_previously_unsupported_producer_to_inductive_proof(self):
        from hepta.hia_guarded_optimization import propose_guarded_reduction
        base = checked_loop_resources()
        with self.assertRaisesRegex(OptimizationRejected, "NO_CANDIDATE"):
            propose_guarded_reduction(base)
        proposal = propose_expanded_guarded(base, maximum=16)
        report = verify_expanded_guarded(base, proposal)
        self.assertEqual(report["status"], "verified", report)
        self.assertEqual(report["stages"][0]["candidate_sha256"], report["stages"][1]["base_sha256"])
        self.assertTrue(all(row["result"] == "unsat" for row in report["stages"][1]["obligations"]))
        final = expanded_guarded_program(base, proposal)
        for n in (0, 1, 15, 16, 17, 257):
            for fail_at in (None, 1, 2):
                observations = []
                for core in (base, final):
                    try:
                        value = execute_program(core, "run", [n], allocation_fail_at=fail_at)
                        observations.append((value["result"], value["resources"]))
                    except HIAProgramTrap as error:
                        observations.append((error.code, error.report["resources"]))
                self.assertEqual(observations[0], observations[1], (n, fail_at))

    def test_stale_intermediate_unlisted_change_and_unsafe_invariants_reject(self):
        base = checked_loop_resources()
        for attack in ("stale", "unlisted", "invariant", "guard"):
            proposal = propose_expanded_guarded(base, maximum=16)
            if attack == "stale":
                proposal["guarded"]["base_sha256"] = verify_program(base).sha256
            elif attack == "unlisted":
                proposal["expansion"]["candidate_core"]["functions"][1]["blocks"][3]["ops"].reverse()
            elif attack == "invariant":
                for row in proposal["guarded"]["invariants"]["run"]["body"]:
                    if row["op"] == "scaled_le": row["factor"] = 254
            else:
                proposal["guarded"]["guards"][0]["maximum"] = 2**64 - 1
                for constraints in proposal["guarded"]["invariants"]["run"].values():
                    for row in constraints:
                        if row["op"] == "le_const": row["limit"] = 2**64 - 1
            report = verify_expanded_guarded(base, proposal)
            self.assertEqual(report["status"], "rejected", (attack, report))

    def test_unknown_and_timeout_cannot_build_a_partial_chain(self):
        base = checked_loop_resources()
        proposal = propose_expanded_guarded(base)
        for settings, status in (({"timeout_ms": 0}, "timeout"), ({"max_obligations": 0}, "unknown")):
            policy = {**DEFAULT_POLICY, **settings}
            report = verify_expanded_guarded(base, proposal, policy)
            self.assertEqual(report["status"], status)
            with tempfile.TemporaryDirectory() as tmp, patch(
                    "hepta.hia_program_llvm.build_program_native", side_effect=AssertionError("compiled")):
                path = Path(tmp) / "never.so"
                with self.assertRaises(OptimizationRejected):
                    build_expanded_guarded_native(base, proposal, path, policy=policy)
                self.assertFalse(path.exists())

    def test_cross_target_chain_is_not_silently_admitted(self):
        base = checked_loop_resources()
        report = verify_expanded_guarded(base, propose_expanded_guarded(base),
            {**DEFAULT_POLICY, "target": "aarch64-unknown-linux-gnu"})
        self.assertEqual(report["status"], "rejected")
        self.assertIn("different targets", report["reason"])

    @unittest.skipUnless(shutil.which(os.environ.get("CLANG", "clang")), "real Clang required")
    def test_solver_identity_drift_after_real_compilation_refuses_publication(self):
        from hepta.hia_program_llvm import build_program_native
        from hepta.hia_optimization import _solver_identity
        base = checked_loop_resources()
        proposal = propose_expanded_guarded(base)
        identity, state = _solver_identity(z3), {"built": False}
        def build_then_drift(*args, **kwargs):
            result = build_program_native(*args, **kwargs)
            state["built"] = True
            return result
        def actual_identity(module):
            return {**identity, "library_sha256": "0" * 64} if state["built"] else identity
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "never.so"
            with patch("hepta.hia_program_llvm.build_program_native", side_effect=build_then_drift), patch(
                "hepta.hia_optimization._solver_identity", side_effect=actual_identity):
                with self.assertRaisesRegex(OptimizationRejected, "solver identity changed"):
                    build_expanded_guarded_native(base, proposal, path, clang=os.environ.get("CLANG", "clang"))
            self.assertTrue(state["built"])
            self.assertFalse(path.exists())
            self.assertEqual(list(Path(tmp).iterdir()), [])

    @unittest.skipUnless(shutil.which(os.environ.get("CLANG", "clang")), "real Clang required")
    def test_composed_proof_binds_final_executed_artifact(self):
        base = checked_loop_resources()
        proposal = propose_expanded_guarded(base, maximum=16)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "chain.so"
            receipt = build_expanded_guarded_native(base, proposal, path, clang=os.environ.get("CLANG", "clang"))
            proof = receipt["verification"]
            self.assertEqual(receipt["native"]["core_sha256"], proof["candidate_sha256"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), receipt["native"]["artifact_sha256"])
            self.assertNotEqual(proof["intermediate_sha256"], proof["candidate_sha256"])
            from hepta.hia_native_differential import _pin_native_artifact
            original, identity, descriptor = _pin_native_artifact(path)
            try:
                self.assertEqual(hashlib.sha256(original).hexdigest(), receipt["native"]["artifact_sha256"])
                cases = [0, 16, 17, 1025]
                worker = ("import ctypes,json,resource,sys\n"
                    "resource.setrlimit(resource.RLIMIT_CORE,(0,0))\n"
                    "resource.setrlimit(resource.RLIMIT_CPU,(2,2))\n"
                    "resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2))\n"
                    "f=ctypes.CDLL(sys.argv[1]).run\n"
                    "f.argtypes=[ctypes.c_uint64];f.restype=ctypes.c_uint64\n"
                    "print(json.dumps([f(n) for n in json.loads(sys.argv[2])]))\n")
                observed = subprocess.run([sys.executable, "-I", "-S", "-c", worker,
                    "/proc/self/fd/" + str(descriptor), json.dumps(cases)], pass_fds=(descriptor,),
                    env={"LC_ALL": "C"}, capture_output=True, timeout=5)
                self.assertEqual(observed.returncode, 0, observed.stderr)
                self.assertFalse(observed.stderr)
                self.assertEqual(json.loads(observed.stdout), [sum(k % 256 for k in range(n)) for n in cases])
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
