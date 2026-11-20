"""Selection fallback precedes proof; proof failures never select another path."""
from __future__ import annotations

import ctypes
from hashlib import sha256
import importlib.util
import json
import platform
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hepta.hia_machine_x64 import Code
from hepta.hia_program import verify_program
from hepta.hia_safe_core import SafeCoreRejected
from hepta.hia_verified_kernel import build_verified_kernel, select_verified_kernel
from hepta.hia_verified_scalar import emit_verified_scalar
from hepta.hia_verified_simd import simd_kernel_program
from tests.test_hia_program import arithmetic, b, jump, ret
from tests.test_hia_verified_scalar import multiply_add
from tools.build_hia_verified_kernel import build as build_attempt


AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class VerifiedKernelIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-verified-kernel-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_multiblock_checked_arithmetic_auto_fallback_occurs_before_linking_or_proof(self):
        core = arithmetic("int.add.checked", "u64")
        core["functions"][0]["blocks"][0]["term"] = jump("done", "r")
        core["functions"][0]["blocks"].append(b("done", [("result", "u64")], [], ret("result")))
        with patch("hepta.hia_safe_core.validate_safe_core_artifact", side_effect=AssertionError("unexpected proof")):
            _, selected, image, refusals = select_verified_kernel(core)
        self.assertEqual(selected, "checked")
        self.assertIsNone(image)
        self.assertEqual({row["strategy"] for row in refusals}, {"scalar", "simd"})
        result = build_verified_kernel(core, self.root / "checked.so")
        self.assertEqual(result["selected_strategy"], "checked")
        self.assertTrue(result["validation"]["ok"])
        self.assertEqual(result["runtime_solver_calls"], 0)
        fn = ctypes.CDLL(result["output"]).calculate
        fn.argtypes, fn.restype = [ctypes.c_uint64] * 2, ctypes.c_uint64
        self.assertEqual(fn(7, 11), 18)

    def test_selected_scalar_proof_failure_never_falls_back_or_publishes(self):
        output = self.root / "failed.so"
        with patch.object(Code, "add", Code.sub), \
                patch("hepta.hia_verified_kernel.build_safe_core", side_effect=AssertionError("fallback after proof")):
            with self.assertRaises(SafeCoreRejected) as caught:
                build_verified_kernel(multiply_add(), output, query_directory=self.root / "queries")
        self.assertEqual(caught.exception.counterexample["obligation"],
                         "core_to_final_image_return_abort_and_caller_bytes")
        self.assertFalse(output.exists())
        self.assertTrue(list((self.root / "queries").glob("*.smt2")))

    def test_existing_output_is_never_replaced(self):
        for strategy, core in (("scalar", multiply_add()),
                               ("checked", arithmetic("int.add.checked", "u64")),
                               ("simd", simd_kernel_program("sum_u8"))):
            with self.subTest(strategy=strategy):
                output = self.root / (strategy + ".so")
                output.write_bytes(b"existing user content")
                with self.assertRaises(ValueError):
                    build_verified_kernel(core, output, strategy=strategy)
                self.assertEqual(output.read_bytes(), b"existing user content")

    def test_source_dictionary_changes_after_selection_do_not_change_checked_snapshot(self):
        source = multiply_add()
        expected = verify_program(source)
        original = emit_verified_scalar

        def mutate_caller(document):
            image = original(document)
            source["functions"][0]["blocks"][0]["ops"][1]["op"] = "int.sub.wrap"
            return image

        with patch("hepta.hia_verified_scalar.emit_verified_scalar", side_effect=mutate_caller):
            result = build_verified_kernel(source, self.root / "snapshot.so")
        self.assertEqual(result["core_sha256"], expected.sha256)
        self.assertEqual(result["validation"]["subject"]["core_sha256"], expected.sha256)
        self.assertNotEqual(verify_program(source).sha256, expected.sha256)
        fn = ctypes.CDLL(result["output"]).multiply_add
        fn.argtypes, fn.restype = [ctypes.c_uint64] * 3, ctypes.c_uint64
        self.assertEqual(fn(3, 5, 7), 22)

    def test_cli_attempt_preserves_source_object_queries_and_success(self):
        core = simd_kernel_program("sum_u8")
        source = self.root / "sum.hepta"
        original = core.canonical_bytes
        source.write_bytes(original)
        directory = self.root / "attempt"
        report = build_attempt(source, directory, strategy="simd")
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["selected_strategy"], "simd")
        self.assertEqual(report["source_sha256"], sha256(original).hexdigest())
        self.assertEqual((directory / "source.core.hepta").read_bytes(), original)
        self.assertEqual((directory / "core.core.hepta").read_bytes(), core.canonical_bytes)
        self.assertTrue((directory / "candidate.o").is_file())
        self.assertTrue((directory / "candidate.text.bin").is_file())
        self.assertTrue((directory / "program.so").is_file())
        self.assertTrue(list((directory / "queries").glob("*.smt2")))
        self.assertFalse(report["native_execution_observed"])
        self.assertFalse(report["adopted"])
        self.assertEqual(json.loads((directory / "attempt.json").read_bytes()), report)

    def test_cli_failed_proof_retains_original_source_and_counterexample(self):
        source = self.root / "multiply.hepta"
        original = verify_program(multiply_add()).canonical_bytes
        source.write_bytes(original)
        directory = self.root / "failed-attempt"
        with patch.object(Code, "add", Code.sub):
            report = build_attempt(source, directory)
        self.assertFalse(report["ok"])
        self.assertFalse(report["final_image_published"])
        self.assertEqual(report["status"], "rejected")
        self.assertEqual(report["selected_strategy"], "scalar")
        self.assertIsNotNone(report["error"]["counterexample"])
        self.assertFalse((directory / "program.so").exists())
        self.assertEqual((directory / "source.core.hepta").read_bytes(), original)
        self.assertTrue((directory / "candidate.o").exists())
        self.assertTrue(report["partial_validation"]["obligations"])

    def test_selected_object_is_emitted_once_and_matches_the_proof(self):
        source = self.root / "once.hepta"
        source.write_bytes(verify_program(multiply_add()).canonical_bytes)
        directory = self.root / "once-attempt"
        with patch("hepta.hia_verified_scalar.emit_verified_scalar", wraps=emit_verified_scalar) as emit:
            report = build_attempt(source, directory, strategy="scalar")
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(emit.call_count, 1)
        retained = sha256((directory / "candidate.o").read_bytes()).hexdigest()
        self.assertEqual(retained, report["result"]["object_sha256"])
        self.assertEqual(retained, report["result"]["validation"]["subject"]["object_sha256"])
