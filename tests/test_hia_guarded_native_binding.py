"""Adversarial proof/artifact boundary tests and separately gated native tests.

Boundary unit tests replace the prover and native compiler deliberately.  They
exercise real Core verification, LLVM emission, byte reads and file publication;
their fixtures are not machine code and are not native qualification evidence.
The native class uses the actual pinned solver and actual Clang backend.
"""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_guarded_optimization as guarded
from hepta.hia_optimization import OptimizationRejected, _digest
from hepta.hia_program import SCHEMA, verify_program
from hepta.hia_program_llvm import emit_program_llvm


def scalar_guard_fixture():
    params = [{"name": "n", "type": "u64"}]
    base = {"schema": SCHEMA, "module": "guarded_binding", "functions": [{
        "name": "increment", "params": params, "returns": ["u64"],
        "effects": ["trap"], "entry": "entry", "blocks": [{
            "id": "entry", "params": deepcopy(params), "ops": [
                {"op": "const", "args": [], "out": [{"name": "one", "type": "u64"}],
                 "attrs": {"value": 1}},
                {"op": "int.add.checked", "args": ["n", "one"],
                 "out": [{"name": "answer", "type": "u64"}], "attrs": {}},
            ], "term": {"op": "ret", "values": ["answer"]},
        }],
    }]}
    fast = deepcopy(base)
    fast["functions"][0]["blocks"][0]["ops"][1]["op"] = "int.add.wrap"
    proposal = {
        "schema": guarded.SCHEMA, "base_sha256": verify_program(base).sha256,
        "fast_core": fast,
        "guards": [{"function": "increment", "argument": "n", "maximum": 10}],
        "invariants": {"increment": {"entry": [{"op": "le_const", "left": "n", "limit": 10}]}},
        "changes": [{"function": "increment", "block": "entry", "operation": 1}],
    }
    return base, proposal


class GuardedArtifactBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / "output.so"
        self.compiler = self.root / "boundary-fixture-compiler"
        self.compiler.write_bytes(b"test fixture only; this is not a native compiler")
        self.base, self.proposal = scalar_guard_fixture()
        original, fast, frozen = guarded._freeze(self.base, self.proposal)
        self.program = guarded._compose(original, fast, frozen)
        self.solver = {"name": "boundary test fixture, not solver evidence"}
        self.proof = {
            "status": "verified", "target": "x86_64-unknown-linux-gnu",
            "base_sha256": original.sha256, "candidate_sha256": self.program.sha256,
            "checker_sha256": guarded.guarded_checker_identity(), "solver": self.solver,
            "verification_sha256": "b" * 64,
        }
        self.payload = b"boundary fixture artifact; not executable machine code"
        self.built = 0

    def backend(self, program, output, *, clang, kind, target):
        self.built += 1
        ir = emit_program_llvm(program, target=target)
        Path(output).write_bytes(self.payload)
        return {
            "schema": "hepta.hia.program.native.v1", "ok": True,
            "status": "native_compiled_not_executed", "kind": kind,
            "target": target, "core_sha256": program.sha256,
            "input_sha256": program.input_sha256, "output": str(output),
            "llvm_ir_sha256": ir.sha256, "implementation_sha256": ir.implementation_sha256,
            "profile": ir.profile, "exports": list(ir.exports),
            "artifact_sha256": sha256(self.payload).hexdigest(), "artifact_bytes": len(self.payload),
            "toolchain": {"path": str(self.compiler),
                          "sha256": sha256(self.compiler.read_bytes()).hexdigest(),
                          "version": "boundary fixture, not Clang",
                          "default_target": target},
        }

    def build(self, backend=None, extra_patches=()):
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {"z3": SimpleNamespace()}))
            stack.enter_context(patch.object(guarded, "verify_guarded_optimization", return_value=self.proof))
            stack.enter_context(patch("hepta.hia_optimization._solver_identity", return_value=self.solver))
            stack.enter_context(patch.object(guarded, "_solver_identity", return_value=self.solver))
            stack.enter_context(patch("hepta.hia_program_llvm.build_program_native",
                                      side_effect=backend or self.backend))
            for context in extra_patches:
                stack.enter_context(context)
            return guarded.build_guarded_native(self.base, self.proposal, self.output)

    def assert_not_published(self):
        self.assertFalse(self.output.exists())
        self.assertFalse(self.output.is_symlink())
        self.assertEqual(list(self.root.glob(".hia-*")), [])

    def test_valid_boundary_receipt_binds_exact_snapshot_and_bytes(self):
        receipt = self.build()
        self.assertEqual(self.output.read_bytes(), self.payload)
        self.assertEqual(receipt["native"]["core_sha256"], receipt["verification"]["candidate_sha256"])
        self.assertEqual(receipt["binding_sha256"], _digest({
            "base": self.proof["base_sha256"], "candidate": self.program.sha256,
            "verification": self.proof["verification_sha256"],
            "artifact": sha256(self.payload).hexdigest(),
            "compiler": sha256(self.compiler.read_bytes()).hexdigest(), "target": self.proof["target"],
        }))
        self.assertFalse(receipt["claims"]["backend_refinement_proved"])
        self.assertFalse(receipt["claims"]["performance_qualified"])

    def test_wrong_core_ir_target_interface_and_output_receipts_never_publish(self):
        mutations = {
            "schema": "forged.v1", "ok": 1, "status": "executed",
            "kind": "object", "target": "aarch64-unknown-linux-gnu",
            "core_sha256": "a" * 64, "input_sha256": "c" * 64,
            "llvm_ir_sha256": "d" * 64, "implementation_sha256": "e" * 64,
            "profile": "different-profile", "exports": ["wrong_export"],
            "output": str(self.root / "other.so"),
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                def altered(*args, **kwargs):
                    receipt = self.backend(*args, **kwargs)
                    receipt[field] = value
                    return receipt
                with self.assertRaisesRegex(OptimizationRejected, "different Core, IR"):
                    self.build(altered)
                self.assert_not_published()

    def test_missing_or_malformed_toolchain_never_fails_after_publication(self):
        for mutation in ("toolchain", "sha256", "path", "version", "default_target", "zero", "relative"):
            with self.subTest(mutation=mutation):
                def incomplete(*args, **kwargs):
                    receipt = self.backend(*args, **kwargs)
                    if mutation == "toolchain":
                        receipt.pop("toolchain")
                    elif mutation == "zero":
                        receipt["toolchain"]["sha256"] = "0" * 64
                    elif mutation == "relative":
                        receipt["toolchain"]["path"] = "relative-compiler"
                    else:
                        receipt["toolchain"].pop(mutation)
                    return receipt
                with self.assertRaisesRegex(OptimizationRejected, "compiler identity"):
                    self.build(incomplete)
                self.assert_not_published()

    def test_incorrect_byte_length_digest_and_changed_stage_are_rejected(self):
        for attack in ("length", "boolean_length", "digest", "bytes"):
            with self.subTest(attack=attack):
                def altered(program, output, **kwargs):
                    receipt = self.backend(program, output, **kwargs)
                    if attack == "length": receipt["artifact_bytes"] += 1
                    elif attack == "boolean_length": receipt["artifact_bytes"] = True
                    elif attack == "digest": receipt["artifact_sha256"] = "f" * 64
                    else: Path(output).write_bytes(b"replacement")
                    return receipt
                with self.assertRaisesRegex(OptimizationRejected, "native bytes or length"):
                    self.build(altered)
                self.assert_not_published()

    def test_changed_actual_compiler_bytes_are_rejected(self):
        def changed(*args, **kwargs):
            receipt = self.backend(*args, **kwargs)
            self.compiler.write_bytes(b"different compiler bytes")
            return receipt
        with self.assertRaisesRegex(OptimizationRejected, "compiler identity changed"):
            self.build(changed)
        self.assert_not_published()

    def test_producer_mutation_cannot_change_frozen_proof_or_program(self):
        digest = self.program.sha256
        def mutate(*args, **kwargs):
            receipt = self.backend(*args, **kwargs)
            self.proof["candidate_sha256"] = "a" * 64
            self.proposal["fast_core"]["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 17
            return receipt
        receipt = self.build(mutate)
        self.assertEqual(receipt["verification"]["candidate_sha256"], digest)
        self.assertEqual(receipt["native"]["core_sha256"], digest)

    def test_unknown_or_rejected_proof_never_starts_backend(self):
        for status in ("unknown", "timeout", "rejected"):
            with self.subTest(status=status):
                self.proof.update(status=status, reason="injected non-admission")
                with self.assertRaisesRegex(OptimizationRejected, "NOT_VERIFIED"):
                    self.build()
                self.assertEqual(self.built, 0)
                self.assert_not_published()

    def test_interrupt_inside_publication_withdraws_own_link(self):
        def interrupt(stage, destination, expected):
            os.link(stage, destination)
            raise KeyboardInterrupt("interrupted after link creation")
        with self.assertRaises(KeyboardInterrupt):
            self.build(extra_patches=[patch("hepta.artifact_publication.publish_verified", side_effect=interrupt)])
        self.assert_not_published()

    def test_post_publication_compiler_drift_withdraws_own_link(self):
        from hepta.artifact_publication import publish_verified
        def change(stage, destination, expected):
            result = publish_verified(stage, destination, expected)
            self.compiler.write_bytes(b"changed after publication")
            return result
        with self.assertRaisesRegex(OptimizationRejected, "compiler identity changed"):
            self.build(extra_patches=[patch("hepta.artifact_publication.publish_verified", side_effect=change)])
        self.assert_not_published()

    def test_withdrawal_preserves_competing_writer_replacement(self):
        def replace_then_interrupt(stage, destination, expected):
            os.link(stage, destination)
            destination.unlink()
            destination.write_bytes(b"competing writer")
            raise KeyboardInterrupt("replacement won pathname")
        with self.assertRaises(KeyboardInterrupt):
            self.build(extra_patches=[patch("hepta.artifact_publication.publish_verified",
                                           side_effect=replace_then_interrupt)])
        self.assertEqual(self.output.read_bytes(), b"competing writer")
        self.assertEqual(list(self.root.glob(".hia-*")), [])

    def test_existing_output_never_gets_overwritten(self):
        self.output.write_bytes(b"existing")
        with self.assertRaisesRegex(OptimizationRejected, "new path"):
            self.build()
        self.assertEqual(self.built, 0)
        self.assertEqual(self.output.read_bytes(), b"existing")


try:
    import z3
except ImportError:
    z3 = None


RESOURCE_SOURCE = """module guarded_binding_native;
export "C" fn sum_bytes(size:usize,seed:u32)->u64 effects {alloc,block,panic,write} {
    match try_buffer(size) {
        Result::Err(code)=>{return 1000+(code as u64);},
        Result::Ok(initial)=>{
            let mut bytes=move initial;
            for i in 0..size {bytes[i]=wrapping_add(i as u32,seed) as u8;}
            let mut total:u64=0;
            for i in 0..size {total=total+(bytes[i] as u64);}
            drop(move bytes);
            return total;
        },
    }
}
"""


@unittest.skipUnless(z3 is not None and shutil.which(os.environ.get("CLANG", "clang")),
                     "real pinned Z3 and native Clang required; not a passed native qualification")
class GuardedNativeBindingQualificationTests(unittest.TestCase):
    def base_and_proposal(self):
        from hepta.hia_program_source import lower_source
        base = lower_source(RESOURCE_SOURCE)
        return base, guarded.propose_guarded_reduction(base, maximum=16)

    def test_actual_guarded_loop_artifact_runs_fast_and_fallback_paths(self):
        from hepta.hia_program_runtime import execute_program
        from hepta.hia_native_differential import _pin_native_artifact
        base, proposal = self.base_and_proposal()
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "guarded.so"
            receipt = guarded.build_guarded_native(base, proposal, destination,
                                                   clang=os.environ.get("CLANG", "clang"))
            self.assertEqual(sha256(destination.read_bytes()).hexdigest(), receipt["native"]["artifact_sha256"])
            self.assertEqual(receipt["verification"]["candidate_sha256"], receipt["native"]["core_sha256"])
            cases = [[count, seed] for count in (0, 1, 15, 16, 17, 257)
                     for seed in (0, 255, 2**32 - 1)]
            exact_bytes, _, descriptor = _pin_native_artifact(destination)
            try:
                self.assertEqual(sha256(exact_bytes).hexdigest(), receipt["native"]["artifact_sha256"])
                worker = ("import ctypes,json,resource,sys\n"
                          "resource.setrlimit(resource.RLIMIT_CORE,(0,0))\n"
                          "resource.setrlimit(resource.RLIMIT_CPU,(2,2))\n"
                          "resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2))\n"
                          "f=ctypes.CDLL(sys.argv[1]).sum_bytes\n"
                          "f.argtypes=[ctypes.c_uint64,ctypes.c_uint32];f.restype=ctypes.c_uint64\n"
                          "print(json.dumps([f(*v) for v in json.loads(sys.argv[2])]))\n")
                observed = subprocess.run(
                    [sys.executable, "-I", "-S", "-c", worker,
                     "/proc/self/fd/" + str(descriptor), json.dumps(cases)],
                    pass_fds=(descriptor,), env={"LC_ALL": "C"}, capture_output=True, timeout=5)
                self.assertEqual(observed.returncode, 0, observed.stderr)
                self.assertFalse(observed.stderr)
                self.assertEqual(json.loads(observed.stdout),
                                 [execute_program(base, "sum_bytes", args)["result"] for args in cases])
            finally:
                os.close(descriptor)

    def test_real_wrong_core_compilation_cannot_launder_guarded_proof(self):
        from hepta.hia_program_llvm import build_program_native
        base, proposal = self.base_and_proposal()
        actual = []
        def compile_other(program, output, **kwargs):
            wrong = program.as_dict()
            function = next(f for f in wrong["functions"] if f["name"] == "sum_bytes")
            function["entry"] = "wrong_entry"
            function["blocks"] = [{"id": "wrong_entry", "params": deepcopy(function["params"]),
                "ops": [{"op": "const", "args": [], "out": [{"name": "wrong", "type": "u64"}],
                         "attrs": {"value": 1234}}], "term": {"op": "ret", "values": ["wrong"]}}]
            receipt = build_program_native(wrong, output, **kwargs)
            actual.append(receipt)
            return receipt
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "must_not_exist.so"
            with patch("hepta.hia_program_llvm.build_program_native", side_effect=compile_other):
                with self.assertRaisesRegex(OptimizationRejected, "different Core, IR"):
                    guarded.build_guarded_native(base, proposal, destination,
                                                  clang=os.environ.get("CLANG", "clang"))
            self.assertEqual(len(actual), 1, "the adversarial control must actually compile wrong Core")
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
