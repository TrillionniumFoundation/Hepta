"""Compatibility tables are checked against real verifier/emitter boundaries.

These tests do not invoke Clang or assert native target execution. Independent
ABI expectations intentionally do not call the emitter's extension helper.
"""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import tempfile
import shutil
import unittest
from unittest.mock import patch

from hepta.hia_opcodes import opcode_catalog
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_llvm import (
    HIAProgramLLVMRejected, TARGET, TARGET_AARCH64, TARGET_RISCV64,
    compile_program_llvm, emit_program_llvm, native_compatibility,
)
from hepta.hia_program_runtime import execute_program
from hepta.hia_schema import (
    COMPOSITE_PROFILES, COMPOSITE_SCHEMA_V3, COMPOSITE_SCHEMA_V4,
    PRIMITIVE_PROFILES, SCHEMA, SCHEMA_V7, SCHEMA_V8,
    compatibility_registry, composite_core_schema,
)
from tools.check_hia_compatibility import (
    JSON_PATH, MARKDOWN_PATH, PROGRAM_PATH, ROOT, WIRE_BEGIN,
    expected_files, main,
)

TYPES = ("bool", "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "isize", "usize")
TARGETS = (TARGET, TARGET_AARCH64, TARGET_RISCV64)
LLVM_TYPES = {"bool": "i1", "i8": "i8", "u8": "i8", "i16": "i16", "u16": "i16",
              "i32": "i32", "u32": "i32", "i64": "i64", "u64": "i64",
              "isize": "i64", "usize": "i64"}
EXTENSIONS = {
    TARGET: {"bool": "zeroext", "i8": "signext", "u8": "zeroext", "i16": "signext", "u16": "zeroext"},
    TARGET_AARCH64: {},
    TARGET_RISCV64: {"bool": "zeroext", "i8": "signext", "u8": "zeroext", "i16": "signext", "u16": "zeroext",
                     "i32": "signext", "u32": "signext"},
}


def function(name, params, returns, *, ops=(), values=None, effects=()):
    return {"name": name, "params": [{"name": n, "type": t} for n, t in params],
            "returns": list(returns), "effects": list(effects), "entry": "entry", "blocks": [{
                "id": "entry", "params": [{"name": n, "type": t} for n, t in params],
                "ops": list(ops), "term": {"op": "ret", "values": list(values if values is not None else [n for n, _ in params])},
            }]}


def scalar_module(schema=SCHEMA, types=("i32",)):
    return {"schema": schema, "module": "compatibility", "functions": [
        function("echo_" + typ, [("value", typ)], [typ]) for typ in types
    ]}


def header(typ, target):
    llvm = LLVM_TYPES[typ]
    extension = EXTENSIONS[target].get(typ, "")
    prefix = extension + " " if extension else ""
    return "define " + prefix + llvm + " @echo_" + typ + "(" + llvm + " " + prefix + "%a0) {"


class HIACompatibilityTests(unittest.TestCase):
    def test_all_declared_primitive_versions_keep_identity_and_emit_every_listed_target(self):
        registry = compatibility_registry()
        targets = {row["target"]: row for row in registry["native"]["targets"]}
        self.assertEqual(tuple(targets), TARGETS)
        self.assertEqual([row["schema"] for row in registry["primitive"]], list(PRIMITIVE_PROFILES))
        for row in registry["primitive"]:
            with self.subTest(schema=row["schema"]):
                verified = verify_core(scalar_module(row["schema"], TYPES))
                self.assertEqual(verified.as_dict()["schema"], row["schema"])
                self.assertEqual(verify_core(verified.canonical_bytes).canonical_bytes, verified.canonical_bytes)
                self.assertEqual(execute_program(verified, "echo_u32", [0xFFFFFFFF])["result"], 0xFFFFFFFF)
                self.assertEqual(execute_program(verified, "echo_i32", [-2147483648])["result"], -2147483648)
                self.assertEqual(row["llvm_targets"], list(TARGETS))
                for target in row["llvm_targets"]:
                    with self.subTest(target=target):
                        ir = emit_program_llvm(verified, target=target)
                        self.assertEqual(ir.profile, targets[target]["profiles"][row["schema"]])
                        self.assertEqual(ir.core_sha256, verified.sha256)
                        self.assertEqual(ir.exports, tuple(sorted("echo_" + typ for typ in TYPES)))
                        self.assertIn('target triple = "' + target + '"', ir.text)
                        for typ in TYPES:
                            self.assertIn(header(typ, target), ir.text)

    def test_nominal_versions_use_their_exact_core_mapping(self):
        for row in compatibility_registry()["composite"]:
            with self.subTest(schema=row["schema"]):
                document = scalar_module(row["schema"])
                document["types"] = []
                verified = verify_core(document)
                self.assertEqual(verified.as_dict()["schema"], composite_core_schema(row["schema"]))
                self.assertEqual(row["normalizes_to"], composite_core_schema(row["schema"]))
                self.assertIsNotNone(verified.structured_bytes)
                self.assertEqual(execute_program(verified, "echo_i32", [-7])["result"], -7)
                for target in row["llvm_targets"]:
                    ir = emit_program_llvm(verified, target=target)
                    self.assertIn(header("i32", target), ir.text)
        self.assertEqual(len(COMPOSITE_PROFILES), 4)

    def test_returned_loans_v8_emit_on_all_targets_without_public_resource_wrappers(self):
        document = json.loads((ROOT / "examples/hia_program/returned_loans_cross_target_v8.hia").read_text())
        verified = verify_core(document)
        borrowed = [fn["name"] for fn in document["functions"] if fn.get("return_loans")]
        self.assertTrue(borrowed)
        for target in TARGETS:
            with self.subTest(target=target):
                ir = emit_program_llvm(verified, target=target)
                self.assertIn("call %hia.buffer @__hia_fn_", ir.text)
                self.assertTrue(set(borrowed).isdisjoint(ir.exports))
                self.assertIn("loan_entry_read_forward", ir.exports)
                self.assertTrue(ir.profile.endswith(".v8"))
        old = deepcopy(document)
        old["schema"] = SCHEMA_V7
        with self.assertRaises(HIAProgramRejected):
            verify_core(old)

    def test_composite_v4_field_origins_normalize_and_emit_but_v3_does_not_admit_them(self):
        from tests.test_hia_composite_returned_loans import pair_program
        document = pair_program()
        self.assertEqual(document["schema"], COMPOSITE_SCHEMA_V4)
        verified = verify_core(document)
        self.assertEqual(verified.as_dict()["schema"], SCHEMA_V8)
        self.assertTrue(any(fn.get("return_loans") for fn in verified.as_dict()["functions"]))
        for target in TARGETS:
            with self.subTest(target=target):
                self.assertTrue(emit_program_llvm(verified, target=target).exports)
        old = deepcopy(document)
        old["schema"] = COMPOSITE_SCHEMA_V3
        with self.assertRaises(HIAProgramRejected):
            verify_core(old)

    def test_scalar_abi_metadata_matches_independent_signedness_and_width_expectations(self):
        native = native_compatibility()
        self.assertEqual(set(native["public_entry"]["argument_types"]), set(TYPES))
        self.assertFalse(native["public_entry"]["unit_argument_admitted"])
        for target in native["targets"]:
            self.assertEqual(set(target["profiles"]), set(PRIMITIVE_PROFILES))
            for row in target["scalar_abi"]:
                with self.subTest(target=target["target"], typ=row["type"]):
                    self.assertEqual(row["llvm_type"], LLVM_TYPES[row["type"]])
                    expected = EXTENSIONS[target["target"]].get(row["type"], "none")
                    self.assertEqual(row["argument_extension"], expected)
                    self.assertEqual(row["result_extension"], expected)
        self.assertFalse(native["native_compilation_evidence"])
        self.assertFalse(native["target_execution_evidence"])

    def test_native_empty_or_unit_results_are_void(self):
        doc = scalar_module()
        doc["functions"] += [function("no_result", [], [], values=[]),
            function("unit_result", [], ["unit"], values=["u"], ops=[
                {"op": "const", "args": [], "out": [{"name": "u", "type": "unit"}], "attrs": {"value": None}}
            ])]
        verified = verify_core(doc)
        for target in TARGETS:
            ir = emit_program_llvm(verified, target=target)
            self.assertIn("define void @no_result() {", ir.text)
            self.assertIn("define void @unit_result() {", ir.text)

    def test_implicit_scalar_signatures_outside_native_abi_are_omitted_and_explicit_rejected(self):
        unsupported = [function("unit_input", [("u", "unit")], [], values=[]),
                       function("two_results", [("a", "u8"), ("b", "i32")], ["u8", "i32"])]
        for fn in unsupported:
            with self.subTest(signature=fn["name"]):
                document = scalar_module()
                document["functions"].append(fn)
                verified = verify_core(document)
                for target in TARGETS:
                    self.assertEqual(emit_program_llvm(verified, target=target).exports, ("echo_i32",))
                document["exports"] = ["echo_i32", fn["name"]]
                verified = verify_core(document)
                for target in TARGETS:
                    with self.assertRaisesRegex(HIAProgramLLVMRejected, "E_HIA_PROGRAM_ABI"):
                        emit_program_llvm(verified, target=target)

    def test_resources_are_private_and_explicit_public_resource_exports_reject_in_core(self):
        document = scalar_module()
        document["functions"].append(function("consume", [("owner", "buffer")], [], values=[], effects=["alloc"], ops=[
            {"op": "owner.drop", "args": ["owner"], "out": [], "attrs": {}}
        ]))
        verified = verify_core(document)
        for target in TARGETS:
            self.assertEqual(emit_program_llvm(verified, target=target).exports, ("echo_i32",))
        document["exports"] = ["echo_i32", "consume"]
        with self.assertRaisesRegex(HIAProgramRejected, "public exports cannot carry resource descriptors"):
            verify_core(document)

    def test_unsupported_target_and_shared_cross_target_requests_reject_before_compiler(self):
        verified = verify_core(scalar_module(SCHEMA_V8))
        for target in ("i686-unknown-linux-gnu", "aarch64-apple-darwin", "wasm32-unknown-unknown"):
            with self.subTest(target=target), self.assertRaisesRegex(HIAProgramLLVMRejected, "unsupported 64-bit native target"):
                emit_program_llvm(verified, target=target)
        with tempfile.TemporaryDirectory() as directory:
            for target in (TARGET_AARCH64, TARGET_RISCV64):
                ir = emit_program_llvm(verified, target=target)
                output = Path(directory) / "must-not-exist.so"
                with self.subTest(target=target), patch("hepta.hia_program_llvm.run_bounded") as invoked:
                    with self.assertRaisesRegex(HIAProgramLLVMRejected, "relocatable objects"):
                        compile_program_llvm(ir, program=verified, output=output, kind="shared")
                    invoked.assert_not_called()
                    self.assertFalse(output.exists())
        targets = {row["target"]: row for row in native_compatibility()["targets"]}
        self.assertEqual(targets[TARGET]["publication_kinds"], ["shared", "object"])
        self.assertEqual(targets[TARGET_AARCH64]["publication_kinds"], ["object"])
        self.assertEqual(targets[TARGET_RISCV64]["publication_kinds"], ["object"])
        self.assertEqual(targets[TARGET_RISCV64]["compiler_flags"], ["-march=rv64gc", "-mabi=lp64d"])

    def test_opcode_catalog_contract_hashes_and_version_gates_are_preserved(self):
        rows = compatibility_registry()["primitive"]
        for row in rows:
            catalog = opcode_catalog(row["schema"])
            self.assertEqual(row["opcode_catalog_sha256"], catalog["catalog_sha256"])
            self.assertEqual(row["instructions"], [op["name"] for op in catalog["instructions"]])
            self.assertEqual(row["function_contract"], catalog["function_contract"])
            self.assertEqual(row["types"], catalog["types"])
        self.assertNotIn("buffer.fill", rows[0]["instructions"])
        self.assertIn("buffer.fill", rows[1]["instructions"])
        self.assertNotIn("chain", rows[5]["types"])
        self.assertIn("chain", rows[6]["types"])
        self.assertEqual(rows[6]["instructions"], rows[7]["instructions"])
        self.assertNotEqual(rows[6]["function_contract"], rows[7]["function_contract"])

    def test_registry_is_detached_and_digest_covers_full_contract(self):
        first = compatibility_registry()
        second = compatibility_registry()
        self.assertEqual(first, second)
        expected = second.pop("compatibility_sha256")
        self.assertEqual(expected, sha256(json.dumps(second, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest())
        first["primitive"][0]["instructions"].append("forged.opcode")
        first["native"]["targets"][0]["scalar_abi"][0]["argument_extension"] = "forged"
        first["native"]["targets"][0]["profiles"][SCHEMA] = "forged"
        self.assertNotEqual(first, compatibility_registry())
        self.assertEqual(second["native"], compatibility_registry()["native"])
        self.assertFalse(second["is_verification_receipt"])
        self.assertFalse(second["is_native_qualification_receipt"])

    def test_committed_generated_contract_is_current(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--check"]), 0)

    def test_check_detects_json_markdown_and_primary_spec_drift_without_rewriting(self):
        original = expected_files()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "docs").mkdir()
            for relative, content in original.items():
                (root / relative).write_text(content, encoding="utf-8")
            for relative in (JSON_PATH, MARKDOWN_PATH, PROGRAM_PATH):
                path = root / relative
                if relative == PROGRAM_PATH:
                    corrupt = original[relative].replace("| `hepta.hia.composite.v4`", "| `hepta.hia.composite.v99`", 1)
                else:
                    corrupt = original[relative] + "DRIFT\n"
                path.write_text(corrupt, encoding="utf-8")
                stderr = io.StringIO()
                with self.subTest(path=relative), redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                    self.assertEqual(main(["--check"], root=root), 1)
                    self.assertIn(relative.as_posix(), stderr.getvalue())
                    self.assertEqual(path.read_text(encoding="utf-8"), corrupt)
                path.write_text(original[relative], encoding="utf-8")
            path = root / PROGRAM_PATH
            path.write_text(original[PROGRAM_PATH].replace(WIRE_BEGIN, ""), encoding="utf-8")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--check"], root=root), 1)


class HIACompatibilityNativeTests(unittest.TestCase):
    """Optional actual object builds; require explicitly in native CI jobs."""

    @classmethod
    def setUpClass(cls):
        cls.clang = os.environ.get("CLANG", "/usr/lib/llvm-20/bin/clang")
        if shutil.which(cls.clang) is None:
            if os.environ.get("HIA_COMPATIBILITY_REQUIRE_NATIVE") == "1":
                raise AssertionError("HIA compatibility native gate requires actual Clang 20+")
            raise unittest.SkipTest("actual Clang 20+ native toolchain required")

    def test_v8_objects_match_target_elf_and_scalar_export_contracts(self):
        document = json.loads((ROOT / "examples/hia_program/returned_loans_cross_target_v8.hia").read_text())
        verified = verify_core(document)
        machine_ids = {TARGET: 62, TARGET_AARCH64: 183, TARGET_RISCV64: 243}
        with tempfile.TemporaryDirectory(prefix="hia-compatibility-native-") as directory:
            for target in TARGETS:
                with self.subTest(target=target):
                    ir = emit_program_llvm(verified, target=target)
                    path = Path(directory) / (target + ".o")
                    commands = []
                    receipt = compile_program_llvm(ir, program=verified, output=path,
                                                   clang=self.clang, kind="object", command_log=commands)
                    data = path.read_bytes()
                    self.assertEqual(data[:6], b"\x7fELF\x02\x01")
                    self.assertEqual(int.from_bytes(data[16:18], "little"), 1)
                    self.assertEqual(int.from_bytes(data[18:20], "little"), machine_ids[target])
                    if target == TARGET_RISCV64:
                        self.assertEqual(int.from_bytes(data[48:52], "little"), 5)
                        self.assertIn("-march=rv64gc", receipt["flags"])
                        self.assertIn("-mabi=lp64d", receipt["flags"])
                    self.assertEqual(receipt["artifact_sha256"], sha256(data).hexdigest())
                    self.assertEqual(receipt["status"], "native_compiled_not_executed")
                    self.assertEqual(receipt["target"], target)
                    self.assertEqual(receipt["profile"], ir.profile)
                    self.assertEqual(receipt["binary_inventory"]["defined"], list(ir.exports))
                    self.assertFalse(receipt["claims"]["native_execution_qualified"])
                    self.assertFalse(receipt["claims"]["cross_target_execution_qualified"])
                    self.assertTrue(commands)


if __name__ == "__main__":
    unittest.main()
