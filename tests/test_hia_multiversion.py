"""Real native generation admission, rejection and concurrent retirement."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import copy
import errno
import importlib.util
import os
from pathlib import Path
import platform
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta.hia_multiversion import (MultiversionRejected, ScalarMultiversionRuntime,
                                   _admissible)
from hepta.hia_program import SCHEMA, verify_program
from hepta.hia_program_llvm import build_program_native


def scalar_program(operation="int.add.wrap", value=0, typ="u64"):
    params = [{"name": "x", "type": typ}]
    operations = [] if operation is None else [
        {"op": "const", "args": [], "out": [{"name": "k", "type": typ}],
         "attrs": {"value": value}},
        {"op": operation, "args": ["x", "k"], "out": [{"name": "answer", "type": typ}], "attrs": {}},
    ]
    return {"schema": SCHEMA, "module": "multiversion_test", "functions": [
        {"name": "calculate", "params": params, "returns": [typ], "effects": [], "entry": "entry",
         "blocks": [{"id": "entry", "params": copy.deepcopy(params), "ops": operations,
                     "term": {"op": "ret", "values": ["x" if operation is None else "answer"]}}]}]}


def cyclic_program():
    result = scalar_program(None)
    fn = result["functions"][0]
    fn["blocks"][0]["term"] = {"op": "jump", "target": "loop", "args": ["x"]}
    fn["blocks"].append({"id": "loop", "params": [{"name": "again", "type": "u64"}], "ops": [],
                         "term": {"op": "jump", "target": "loop", "args": ["again"]}})
    return result


class MultiversionProfileTests(unittest.TestCase):
    def test_cycles_are_rejected_even_when_canonical_resource_verification_passes(self):
        program = verify_program(cyclic_program())
        with self.assertRaisesRegex(MultiversionRejected, "cyclic"):
            _admissible(program)

    def test_checked_operations_and_resource_effects_are_not_live_callable(self):
        checked = scalar_program("int.add.checked")
        checked["functions"][0]["effects"] = ["trap"]
        verify_program(checked)
        with self.assertRaisesRegex(MultiversionRejected, "effect-free"):
            _admissible(checked)
        allocation = scalar_program(None)
        allocation["functions"][0]["effects"] = ["alloc"]
        with self.assertRaises(MultiversionRejected):
            _admissible(allocation)

    def test_forged_verified_program_bytes_do_not_admit_bad_ssa(self):
        from hepta.hia_program import HIAProgramRejected, VerifiedProgram
        import json
        bad = scalar_program(None)
        bad["functions"][0]["blocks"][0]["term"]["values"] = ["missing"]
        with self.assertRaises(HIAProgramRejected):
            _admissible(VerifiedProgram(json.dumps(bad).encode()))


_CLANG = os.environ.get("HEPTA_CLANG") or os.environ.get("CLANG") or "clang"
_NATIVE = (platform.system() == "Linux" and platform.machine() in {"x86_64", "amd64"}
           and hasattr(os, "memfd_create") and shutil.which(_CLANG)
           and importlib.util.find_spec("z3") is not None)


@unittest.skipUnless(_NATIVE, "actual Clang 20+, Z3 and Linux sealed memfd are required")
class MultiversionNativeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-multiversion-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runtime = ScalarMultiversionRuntime(scalar_program(), self.root, clang=_CLANG)
        self.addCleanup(self.runtime.close)

    def test_actual_baseline_and_proved_candidate_execute_exact_u64_edges(self):
        for value in (0, 1, 2**63, 2**64 - 1):
            self.assertEqual(self.runtime.call("calculate", [value]), value)
        candidate = self.runtime.publish(scalar_program("bit.xor"))
        self.assertNotEqual(candidate.program_sha256, self.runtime._states[0].info.program_sha256)
        self.assertEqual(candidate.translation_proofs, 1)
        self.assertGreater(candidate.native_probe_calls, 5)
        for value in (0, 1, 2**63, 2**64 - 1):
            self.assertEqual(self.runtime.call("calculate", [value]), value)
        snapshot = self.runtime.snapshot()
        self.assertEqual(snapshot["current_generation"], candidate.generation)
        self.assertFalse(snapshot["claims"]["backend_refinement_proved"])

    def test_different_behavior_rejects_before_native_build_and_preserves_selection(self):
        before = self.runtime.snapshot()
        with patch("hepta.hia_multiversion.build_program_native") as build:
            with self.assertRaisesRegex(MultiversionRejected, "disproved"):
                self.runtime.publish(scalar_program(value=1))
            build.assert_not_called()
        after = self.runtime.snapshot()
        self.assertEqual(after["current_generation"], before["current_generation"])
        self.assertEqual(after["selection_epoch"], before["selection_epoch"])
        self.assertEqual(self.runtime.call("calculate", [73]), 73)

    def test_changed_abi_rejects_before_native_build(self):
        with patch("hepta.hia_multiversion.build_program_native") as build:
            with self.assertRaisesRegex(MultiversionRejected, "ABI differs"):
                self.runtime.publish(scalar_program(typ="i64"))
            build.assert_not_called()
        self.assertEqual(self.runtime.call("calculate", [2**64 - 1]), 2**64 - 1)

    def test_unknown_or_unbound_fresh_validator_results_fail_closed(self):
        for proof in ({"status": "unknown"}, {"status": "proved", "ok": True}):
            with self.subTest(proof=proof), patch("hepta.hia_translation_validation.validate_translation", return_value=proof):
                with self.assertRaises(MultiversionRejected):
                    self.runtime.publish(scalar_program(None))
        self.assertEqual(self.runtime.snapshot()["current_generation"], 0)

    def test_otherwise_matching_proof_with_wrong_schema_profile_or_scope_rejects(self):
        from hepta.hia_translation_validation import validate_translation
        candidate = scalar_program(None)
        proof = validate_translation(scalar_program(), candidate, function="calculate")
        self.assertEqual(proof["status"], "proved")
        for field in ("schema", "profile", "scope"):
            changed = {**proof, field: "unrelated"}
            with self.subTest(field=field), patch("hepta.hia_translation_validation.validate_translation", return_value=changed):
                with self.assertRaises(MultiversionRejected):
                    self.runtime.publish(candidate)
        self.assertEqual(self.runtime.snapshot()["current_generation"], 0)

    def test_compiled_bytes_are_rechecked_instead_of_trusting_ok_flag(self):
        def corrupt(*args, **kwargs):
            receipt = build_program_native(*args, **kwargs)
            Path(args[1]).write_bytes(b"not the compiled program")
            receipt["ok"] = True
            return receipt
        with patch("hepta.hia_multiversion.build_program_native", side_effect=corrupt):
            with self.assertRaises(MultiversionRejected):
                self.runtime.publish(scalar_program(None))
        self.assertEqual(self.runtime.snapshot()["current_generation"], 0)
        self.assertEqual(self.runtime.call("calculate", [19]), 19)
        self.assertEqual(sorted(p.name for p in self.runtime._directory.iterdir()), ["generation-0.so"])

    def test_every_export_requires_independent_equivalence(self):
        baseline = scalar_program()
        extra = copy.deepcopy(baseline["functions"][0])
        extra["name"] = "second"
        baseline["functions"].append(extra)
        changed = copy.deepcopy(baseline)
        changed["functions"][1]["blocks"][0]["ops"][0]["attrs"]["value"] = 1
        with ScalarMultiversionRuntime(baseline, self.root, clang=_CLANG) as runtime:
            with self.assertRaisesRegex(MultiversionRejected, "disproved"):
                runtime.publish(changed)
            self.assertEqual(runtime.call("second", [113]), 113)

    def test_native_signed_narrow_and_boolean_abis_have_exact_values(self):
        baseline = scalar_program(typ="i8")
        unsigned = scalar_program(typ="u32")["functions"][0]
        unsigned["name"] = "unsigned_value"
        boolean = scalar_program(None, typ="bool")["functions"][0]
        boolean["name"] = "boolean_value"
        baseline["functions"].extend([unsigned, boolean])
        candidate = copy.deepcopy(baseline)
        fn = candidate["functions"][0]
        fn["blocks"][0]["ops"] = []
        fn["blocks"][0]["term"]["values"] = ["x"]
        with ScalarMultiversionRuntime(baseline, self.root, clang=_CLANG) as runtime:
            info = runtime.publish(candidate)
            self.assertEqual(info.translation_proofs, 3)
            for value in (-128, -1, 0, 1, 127):
                self.assertEqual(runtime.call("calculate", [value]), value)
            self.assertEqual(runtime.call("unsigned_value", [2**32 - 1]), 2**32 - 1)
            self.assertIs(runtime.call("boolean_value", [False]), False)
            self.assertIs(runtime.call("boolean_value", [True]), True)

    def test_sealing_failure_preserves_old_generation_and_removes_unpublished_candidate(self):
        previous = self.runtime.snapshot()
        with patch("hepta.hia_multiversion._sealed_fd", side_effect=OSError("injected sealing failure")):
            with self.assertRaisesRegex(OSError, "sealing failure"):
                self.runtime.publish(scalar_program(None))
        self.assertEqual(self.runtime.snapshot()["current_generation"], previous["current_generation"])
        self.assertEqual(self.runtime.snapshot()["selection_epoch"], previous["selection_epoch"])
        self.assertEqual(sorted(p.name for p in self.runtime._directory.iterdir()), ["generation-0.so"])
        self.assertEqual(self.runtime.call("calculate", [31]), 31)

    def test_live_calls_use_sealed_bytes_after_disk_copy_is_modified(self):
        info = self.runtime.publish(scalar_program(None))
        state = self.runtime._states[info.generation]
        with self.assertRaises(OSError) as blocked:
            os.pwrite(state.fd, b"x", 0)
        self.assertEqual(blocked.exception.errno, errno.EPERM)
        state.artifact.write_bytes(b"changed external disk copy")
        self.assertEqual(self.runtime.call("calculate", [2**64 - 1]), 2**64 - 1)
        self.assertEqual(self.runtime.snapshot()["generations"][-1]["artifact_sha256"], info.artifact_sha256)

    def test_old_generation_is_retained_across_concurrent_publication_until_lease_exit(self):
        first = self.runtime.publish(scalar_program(None))
        state = self.runtime._states[first.generation]
        entered, release = threading.Event(), threading.Event()
        def caller():
            with self.runtime.lease() as lease:
                self.assertEqual(lease.info.generation, first.generation)
                self.assertEqual(lease.call("calculate", [41]), 41)
                entered.set()
                if not release.wait(10):
                    raise AssertionError("publication did not release the old caller")
                self.assertEqual(lease.call("calculate", [43]), 43)
                return lease.info.generation
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(caller)
            try:
                self.assertTrue(entered.wait(10))
                second = self.runtime.publish(scalar_program("bit.or"))
                self.assertNotEqual(first.generation, second.generation)
                retained = {s["generation"]: s for s in self.runtime.snapshot()["generations"]}
                self.assertTrue(retained[first.generation]["retired"])
                self.assertEqual(retained[first.generation]["active_leases"], 1)
                self.assertTrue(state.artifact.is_file())
                os.fstat(state.fd)
                with self.runtime.lease() as current:
                    self.assertEqual(current.info.generation, second.generation)
                    self.assertEqual(current.call("calculate", [47]), 47)
            finally:
                release.set()
            self.assertEqual(future.result(timeout=10), first.generation)
        self.assertNotIn(first.generation, self.runtime._states)
        self.assertFalse(state.artifact.exists())
        with self.assertRaises(OSError):
            os.fstat(state.fd)

    def test_rollback_changes_future_calls_and_retains_old_lease(self):
        info = self.runtime.publish(scalar_program("bit.xor"))
        lease = self.runtime.lease()
        self.addCleanup(lease.close)
        epoch = lease.selection_epoch
        self.assertEqual(self.runtime.rollback().generation, 0)
        self.assertGreater(self.runtime.snapshot()["selection_epoch"], epoch)
        self.assertEqual(lease.info.generation, info.generation)
        self.assertEqual(lease.call("calculate", [101]), 101)
        with self.runtime.lease() as baseline:
            self.assertEqual(baseline.info.generation, 0)
            self.assertEqual(baseline.call("calculate", [103]), 103)
        lease.close()
        self.assertNotIn(info.generation, self.runtime._states)

    def test_close_blocks_new_calls_but_existing_lease_completes(self):
        lease = self.runtime.lease()
        self.runtime.close()
        with self.assertRaisesRegex(MultiversionRejected, "closed"):
            self.runtime.call("calculate", [1])
        self.assertEqual(lease.call("calculate", [107]), 107)
        lease.close()
        with self.assertRaisesRegex(MultiversionRejected, "closed"):
            lease.call("calculate", [1])
        self.assertEqual(self.runtime.snapshot()["generations"], [])
        self.assertFalse(self.runtime._directory.exists())

    def test_arguments_are_checked_before_ctypes_can_coerce_or_wrap_them(self):
        for arguments in ([True], [-1], [2**64], [], [1, 2], [1.0]):
            with self.subTest(arguments=arguments), self.assertRaises(MultiversionRejected):
                self.runtime.call("calculate", arguments)
        with self.assertRaises(MultiversionRejected):
            self.runtime.call("not_exported", [1])

    def test_copying_cannot_create_an_extra_close_owner_for_one_lease(self):
        with self.runtime.lease() as lease:
            for operation in (copy.copy, copy.deepcopy):
                with self.assertRaises(MultiversionRejected):
                    operation(lease)
                with self.assertRaises(MultiversionRejected):
                    operation(self.runtime)
            self.assertEqual(self.runtime.snapshot()["generations"][0]["active_leases"], 1)
            self.assertEqual(lease.call("calculate", [127]), 127)

    def test_live_budget_never_reclaims_a_leased_generation_to_admit_candidate(self):
        with ScalarMultiversionRuntime(scalar_program(), self.root, clang=_CLANG, max_live_generations=2) as runtime:
            info = runtime.publish(scalar_program(None))
            with runtime.lease() as lease:
                with self.assertRaisesRegex(MultiversionRejected, "budget exhausted"):
                    runtime.publish(scalar_program("bit.or"))
                self.assertEqual(runtime.snapshot()["current_generation"], info.generation)
                self.assertEqual(lease.call("calculate", [109]), 109)


if __name__ == "__main__":
    unittest.main()
