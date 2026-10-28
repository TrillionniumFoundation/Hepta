"""Guard discharge, inductive counterexamples, original fallback and native bytes."""
from __future__ import annotations

import copy
import contextlib
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program_source import lower_source
from hepta.hia_program_runtime import execute_program
from hepta.hia_optimization import DEFAULT_POLICY, OptimizationRejected, _digest, verify_optimization
from hepta.hia_guarded_optimization import (propose_guarded_reduction, guarded_program,
    verify_guarded_optimization, build_guarded_native, BYTE_SUM_LIMIT)

try:
    import z3
except ImportError:
    z3 = None

SOURCE = Path(__file__).resolve().parents[1] / "experiments/hia_optimizer_eval/kernels.hepta"


@unittest.skipUnless(z3 is not None, "pinned Z3 is required")
class GuardedProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = lower_source(SOURCE.read_text())
        cls.proposal = propose_guarded_reduction(cls.base)

    def test_inductive_guards_are_actually_discharged(self):
        r = verify_guarded_optimization(self.base, self.proposal)
        self.assertEqual(r["status"], "verified", r["reason"])
        self.assertEqual(len(r["changes"]), 2)
        self.assertTrue(all(o["result"] == "unsat" for o in r["obligations"]))
        self.assertEqual({o["kind"] for o in r["obligations"]},
                         {"guard_establishes_entry", "inductive_edge", "removed_check_cannot_trap"})
        self.assertEqual(r["resource_delta"]["peak_live_bytes_change_under_core_model"], 0)
        self.assertNotEqual(r["candidate_sha256"], r["fast_core_sha256"])
        self.assertFalse(r["claims"]["backend_refinement_proved"])

    def test_the_unprotected_fast_body_does_not_get_universal_authority(self):
        r = verify_optimization(self.base, self.proposal["fast_core"])
        self.assertEqual(r["status"], "rejected", r["reason"])
        self.assertIn("counterexample", r["obligations"][-1])

    def test_fast_slow_and_allocator_refusals_preserve_real_vm_resources(self):
        proposal = propose_guarded_reduction(self.base, maximum=16)
        guarded = guarded_program(self.base, proposal)
        for name in ("full_lifecycle", "packet_xor"):
            for n in (0, 1, 15, 16, 17, 33):
                for fail_at in (None, 1, 2):
                    a = execute_program(self.base, name, [n, 2**32 - 1], allocation_fail_at=fail_at)
                    b = execute_program(guarded, name, [n, 2**32 - 1], allocation_fail_at=fail_at)
                    self.assertEqual(a["result"], b["result"], (name, n, fail_at))
                    self.assertEqual(a["resources"], b["resources"], (name, n, fail_at))

    def test_forged_strong_entry_invariant_is_rejected(self):
        proposed = copy.deepcopy(self.proposal)
        function = self.base.as_dict()["functions"][0]
        for constraint in proposed["invariants"][function["name"]][function["entry"]]:
            constraint["limit"] = 0
        r = verify_guarded_optimization(self.base, proposed)
        self.assertEqual(r["status"], "rejected")
        self.assertEqual(r["obligations"][-1]["kind"], "guard_establishes_entry")
        self.assertFalse(r["resource_delta"]["allocation_failure_sequence_preserved"])

    def test_header_to_body_must_establish_the_proposed_bound(self):
        proposed = copy.deepcopy(self.proposal)
        change = proposed["changes"][0]
        constraints = proposed["invariants"][change["function"]][change["block"]]
        for c in constraints:
            if c["op"] == "scaled_le":
                c["factor"] = 254
        r = verify_guarded_optimization(self.base, proposed)
        self.assertEqual(r["status"], "rejected", r["reason"])
        self.assertEqual(r["obligations"][-1]["kind"], "inductive_edge")

    def test_larger_guard_cannot_hide_a_possible_overflow(self):
        proposed = copy.deepcopy(self.proposal)
        for g in proposed["guards"]:
            g["maximum"] = 2**64 - 1
        for blocks in proposed["invariants"].values():
            for constraints in blocks.values():
                for c in constraints:
                    if c["op"] == "le_const":
                        c["limit"] = 2**64 - 1
        r = verify_guarded_optimization(self.base, proposed)
        self.assertEqual(r["status"], "rejected", r["reason"])
        self.assertEqual(r["obligations"][-1]["kind"], "removed_check_cannot_trap")

    def test_the_proposer_does_not_prove_an_incorrect_initial_accumulator(self):
        source = SOURCE.read_text().replace("let mut total:u64=0;", "let mut total:u64=1;")
        base = lower_source(source)
        proposed = propose_guarded_reduction(base)
        r = verify_guarded_optimization(base, proposed)
        self.assertEqual(r["status"], "rejected", r["reason"])
        self.assertEqual(r["obligations"][-1]["kind"], "inductive_edge")

    def test_unlisted_semantic_change_is_rejected_before_solving(self):
        proposed = copy.deepcopy(self.proposal)
        for block in proposed["fast_core"]["functions"][0]["blocks"]:
            for op in block["ops"]:
                if op["op"] == "const" and op["attrs"]["value"] == 1000:
                    op["attrs"]["value"] = 999
        r = verify_guarded_optimization(self.base, proposed)
        self.assertEqual(r["status"], "rejected")
        self.assertEqual(r["obligations"], [])

    def test_timeout_and_unknown_never_publish(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "never.so"
            for settings, status in (({"timeout_ms": 0}, "timeout"),
                                     ({"max_obligations": 0}, "unknown"),
                                     ({"max_scalar_operations": 0}, "unknown")):
                policy = {**DEFAULT_POLICY, **settings}
                r = verify_guarded_optimization(self.base, self.proposal, policy)
                self.assertEqual(r["status"], status)
                with patch("hepta.hia_program_llvm.build_program_native", side_effect=AssertionError("compiled")):
                    with self.assertRaises(OptimizationRejected):
                        build_guarded_native(self.base, self.proposal, path, policy=policy)
                self.assertFalse(path.exists())
            with patch.object(z3.Solver, "check", return_value=z3.unknown), \
                    patch.object(z3.Solver, "reason_unknown", return_value="incomplete"):
                r = verify_guarded_optimization(self.base, self.proposal)
                self.assertEqual(r["status"], "unknown")
                with self.assertRaises(OptimizationRejected):
                    build_guarded_native(self.base, self.proposal, path)
            self.assertFalse(path.exists())

    def test_proof_metadata_cannot_replace_actual_guard_inputs(self):
        for mutation in ("argument", "inventory", "predicate", "base"):
            proposed = copy.deepcopy(self.proposal)
            if mutation == "argument":
                proposed["guards"][0]["argument"] = "not_a_parameter"
            elif mutation == "inventory":
                proposed["changes"].pop()
            elif mutation == "predicate":
                first = next(iter(proposed["invariants"].values()))
                first[next(iter(first))].append({"op": "assume_true"})
            else:
                proposed["base_sha256"] = "0" * 64
            self.assertEqual(verify_guarded_optimization(self.base, proposed)["status"], "rejected", mutation)

    def test_cli_guarded_proposal_and_fresh_verification_preserve_command_boundaries(self):
        from hepta.cli import main
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, proposal = root / "base.json", root / "guarded.json"
            source.write_text(json.dumps(self.base.as_dict()))
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = main(["hia", "optimize-guarded", str(source), "--maximum", "16",
                             "--output", str(proposal)])
            self.assertEqual(code, 0, stream.getvalue())
            created = json.loads(stream.getvalue())
            self.assertEqual(created["verification"]["status"], "verified")
            self.assertEqual(json.loads(proposal.read_text())["schema"],
                             "hepta.hia.guarded-reduction-proposal.v1")
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = main(["hia", "verify-guarded", str(source), "--candidate", str(proposal)])
            self.assertEqual(code, 0, stream.getvalue())
            self.assertEqual(json.loads(stream.getvalue())["status"], "verified")
            # A proof receipt is not the proposal containing actual operations.
            receipt = root / "receipt.json"
            receipt.write_text(json.dumps(created["verification"]))
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                code = main(["hia", "verify-guarded", str(source), "--candidate", str(receipt)])
            self.assertNotEqual(code, 0)
            self.assertNotEqual(json.loads(stream.getvalue()).get("status"), "verified")

    def test_cli_unproved_guarded_candidate_never_publishes_proposal_or_native(self):
        from hepta.cli import main
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, policy = root / "base.json", root / "timeout.json"
            proposed, native = root / "never.json", root / "never.so"
            candidate = root / "candidate.json"
            source.write_text(json.dumps(self.base.as_dict()))
            candidate.write_text(json.dumps(self.proposal))
            policy.write_text(json.dumps({**DEFAULT_POLICY, "timeout_ms": 0}))
            for argv in (["hia", "optimize-guarded", str(source), "--policy", str(policy),
                          "--output", str(proposed)],
                         ["hia", "build-guarded", str(source), "--policy", str(policy),
                          "--candidate", str(candidate), "--output", str(native)]):
                with self.subTest(action=argv[1]), contextlib.redirect_stdout(io.StringIO()):
                    with patch("hepta.hia_program_llvm.build_program_native",
                               side_effect=AssertionError("unproved candidate compiled")):
                        self.assertNotEqual(main(argv), 0)
                self.assertFalse(proposed.exists())
                self.assertFalse(native.exists())


@unittest.skipUnless(z3 is not None and shutil.which(os.environ.get("CLANG", "clang")),
                     "pinned Z3 and native Clang required")
class GuardedNativeTests(unittest.TestCase):
    def test_real_native_fast_slow_bytes_and_mutable_producer(self):
        from hepta.hia_program_llvm import build_program_native
        from hepta.hia_native_differential import _pin_native_artifact
        base = lower_source(SOURCE.read_text())
        proposal = propose_guarded_reduction(base, maximum=32)
        original_proposal_hash = _digest(copy.deepcopy(proposal))

        def build_frozen(program, output, **kwargs):
            proposal["fast_core"]["functions"][0]["blocks"][-1]["term"]["values"] = []
            return build_program_native(program, output, **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "guarded.so"
            with patch("hepta.hia_program_llvm.build_program_native", side_effect=build_frozen):
                report = build_guarded_native(base, proposal, path, clang=os.environ.get("CLANG", "clang"))
            self.assertEqual(report["verification"]["proposal_sha256"], original_proposal_hash)
            self.assertEqual(report["verification"]["candidate_sha256"], report["native"]["core_sha256"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), report["native"]["artifact_sha256"])
            _, _, descriptor = _pin_native_artifact(path)
            library = None
            try:
                library = ctypes.CDLL(f"/proc/self/fd/{descriptor}")
                for name in ("full_lifecycle", "packet_xor"):
                    call = getattr(library, name)
                    call.argtypes, call.restype = [ctypes.c_uint64, ctypes.c_uint32], ctypes.c_uint64
                    for n in (0, 1, 31, 32, 33, 65):
                        for seed in (0, 255, 2**32 - 1):
                            self.assertEqual(call(n, seed), execute_program(base, name, [n, seed])["result"])
            finally:
                if library is not None:
                    import _ctypes
                    _ctypes.dlclose(library._handle)
                os.close(descriptor)

    def test_checker_drift_during_build_cannot_publish(self):
        import hepta.hia_guarded_optimization as guarded
        from hepta.hia_program_llvm import build_program_native
        base = lower_source(SOURCE.read_text())
        proposal = propose_guarded_reduction(base)
        real_identity = guarded.guarded_checker_identity
        changed = False

        def identity():
            return "0" * 64 if changed else real_identity()

        def compiler(program, output, **kwargs):
            nonlocal changed
            result = build_program_native(program, output, **kwargs)
            changed = True
            return result

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "never.so"
            with patch.object(guarded, "guarded_checker_identity", side_effect=identity), \
                    patch("hepta.hia_program_llvm.build_program_native", side_effect=compiler):
                with self.assertRaisesRegex(OptimizationRejected, "STALE"):
                    build_guarded_native(base, proposal, path, clang=os.environ.get("CLANG", "clang"))
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
