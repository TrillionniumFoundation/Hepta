"""Caller contracts are bounded, single-meaning input before C migration."""
from __future__ import annotations

import contextlib
import ctypes
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.c_contracts import (MAX_CONTRACT_BYTES, MAX_CONTRACT_DEPTH,
                               MAX_CONTRACT_NODES, contract_identity,
                               decode_contracts, load_contracts, snapshot_contracts)
from hepta.c_migrate import MigrationRejected, migrate_c_project
from hepta.c_project import capture_project


CONTRACT = {"schema": "hepta.c-contracts.v1", "functions": {
    "write_one": {"slices": {"p": {"length": 1, "access": "mut"}}}}}
DUPLICATE = ('{"schema":"hepta.c-contracts.v1","functions":{"write_one":'
             '{"slices":{"p":{"length":1,"access":"read","access":"mut"}}}}}')


class CContractIntakeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hepta-c-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def reject(self, raw, code="E_C_CONTRACT_JSON"):
        with self.assertRaises(MigrationRejected) as caught:
            decode_contracts(raw)
        self.assertEqual(caught.exception.code, code)

    def test_duplicate_obligations_and_escaped_duplicate_keys_fail_before_decode(self):
        original_loads = json.loads

        def key_tokens_only(source, *args, **kwargs):
            if type(source) is not str or not source.startswith('"'):
                raise AssertionError("JSON value graph decoded")
            return original_loads(source, *args, **kwargs)

        for raw in (DUPLICATE,
                    DUPLICATE.replace('"access":"mut"', '"acce\\u0073s":"mut"'),
                    '{"schema":"wrong","schema":"hepta.c-contracts.v1","functions":{}}',
                    '{"schema":"hepta.c-contracts.v1","functions":{},"functions":{}}',
                    DUPLICATE.replace('"access":"read","access":"mut"', '"access":"mut","length":1')):
            with self.subTest(raw=raw):
                # Only the preflight can inspect the ambiguous source spelling.
                # Patching the graph decoder also proves the rejection precedes it.
                with patch("hepta.c_contracts.json.loads", side_effect=key_tokens_only):
                    self.reject(raw)

    def test_nonfinite_fractional_null_and_invalid_unicode_reject(self):
        for raw in ('null', '[]', '{"schema":"hepta.c-contracts.v1","functions":NaN}',
                    '{"schema":"hepta.c-contracts.v1","functions":Infinity}',
                    '{"schema":"hepta.c-contracts.v1","functions":1.0}',
                    '{"schema":"hepta.c-contracts.v1","functions":{},"x":"\\ud800"}',
                    b"\xff"):
            with self.subTest(raw=raw):
                self.reject(raw)

    def test_depth_nodes_and_bytes_are_rejected_before_graph_materialization(self):
        payloads = [(b" " * (MAX_CONTRACT_BYTES + 1), "E_C_CONTRACT_LIMIT"),
                    ("[" * (MAX_CONTRACT_DEPTH + 2) + "0" + "]" * (MAX_CONTRACT_DEPTH + 2), "E_C_CONTRACT_LIMIT"),
                    ("[" + ",".join("0" for _ in range(MAX_CONTRACT_NODES + 1)) + "]", "E_C_CONTRACT_LIMIT")]
        for raw, code in payloads:
            with self.subTest(code=code, size=len(raw)):
                with patch("hepta.c_contracts.json.loads", side_effect=AssertionError("graph decoded")):
                    self.reject(raw, code)

    def test_explicit_empty_or_unknown_envelope_is_not_omission(self):
        self.assertEqual(snapshot_contracts(None), {"schema": "hepta.c-contracts.v1", "functions": {}})
        for value in ({}, {"schema": "hepta.c-contracts.v1", "functions": {}, "proof": True},
                      {"schema": "hepta.c-contracts.v1", "functions": []}):
            with self.subTest(value=value), self.assertRaises(MigrationRejected):
                snapshot_contracts(value)

    def test_api_graph_rejects_subclasses_cycles_nonfinite_and_oversized_integers(self):
        class CustomMap(dict):
            def items(self):
                raise AssertionError("custom map executed")
        class CustomString(str):
            def encode(self, *args, **kwargs):
                raise AssertionError("custom string executed")
        cyclic = {"schema": "hepta.c-contracts.v1", "functions": {}}
        cyclic["functions"]["cycle"] = cyclic
        for value in (CustomMap(CONTRACT),
                      {"schema": "hepta.c-contracts.v1", "functions": CustomMap()},
                      {"schema": CustomString("hepta.c-contracts.v1"), "functions": {}},
                      {"schema": "hepta.c-contracts.v1", "functions": {"bad": float("nan")}},
                      {"schema": "hepta.c-contracts.v1", "functions": {"bad": 1 << 65}}, cyclic):
            with self.subTest(kind=type(value)), self.assertRaises(MigrationRejected):
                snapshot_contracts(value)

    def test_custom_metaclass_equality_cannot_impersonate_builtin_json_types(self):
        class Impersonator(type):
            def __eq__(cls, other):
                raise AssertionError("custom metaclass equality was invoked")

        class Object(metaclass=Impersonator):
            pass

        class CustomText(str, metaclass=Impersonator):
            pass

        for value in (Object(), CustomText("{}")):
            for operation in (lambda: decode_contracts(value),
                              lambda: snapshot_contracts(value),
                              lambda: snapshot_contracts({"schema": "hepta.c-contracts.v1", "functions": {"bad": value}})):
                with self.assertRaises(MigrationRejected):
                    operation()

    def test_snapshot_has_no_shared_nested_state_and_canonical_identity_is_order_independent(self):
        original = json.loads(json.dumps(CONTRACT))
        snapshot = snapshot_contracts(original)
        before = contract_identity(snapshot)
        original["functions"]["write_one"]["slices"]["p"]["access"] = "read"
        self.assertEqual(snapshot["functions"]["write_one"]["slices"]["p"]["access"], "mut")
        self.assertEqual(before, contract_identity(decode_contracts(json.dumps(CONTRACT, indent=4))))
        self.assertNotEqual(before["canonical_sha256"], contract_identity(original)["canonical_sha256"])

    def test_serialization_cannot_revisit_original_graph_after_its_nodes_were_checked(self):
        from hepta.c_contracts import _envelope
        original = json.loads(json.dumps(CONTRACT))

        class LateCustomMap(dict):
            def items(self):
                raise AssertionError("unchecked custom mapping invoked during serialization")

        def mutate_original_after_copy(detached):
            self.assertIsNot(detached, original)
            _envelope(detached)
            original["functions"] = LateCustomMap({"unchecked": float("nan")})

        with patch("hepta.c_contracts._envelope", side_effect=mutate_original_after_copy):
            snapshot = snapshot_contracts(original)
        self.assertEqual(snapshot, CONTRACT)

    def test_ordinary_file_gate_rejects_symlink_fifo_and_oversized_file(self):
        ordinary = self.root / "contract.json"
        ordinary.write_text(json.dumps(CONTRACT))
        self.assertEqual(load_contracts(ordinary), CONTRACT)
        link = self.root / "link.json"
        link.symlink_to(ordinary)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        oversized = self.root / "large.json"
        with oversized.open("wb") as stream:
            stream.truncate(MAX_CONTRACT_BYTES + 1)
        for path in (link, fifo, oversized):
            with self.subTest(path=path), self.assertRaises(MigrationRejected) as caught:
                load_contracts(path)
            self.assertEqual(caught.exception.code, "E_C_CONTRACT_INPUT")

    def test_api_invalid_contract_is_rejected_before_build_capture(self):
        for contract in ({}, [], {"schema": "hepta.c-contracts.v1", "functions": float("nan")}):
            with self.subTest(contract=contract), patch("hepta.c_migration_project.capture_project", side_effect=AssertionError("compiler launched")):
                report = migrate_c_project(self.root / "missing.json", self.root / "output", contracts=contract)
                self.assertFalse(report["ok"])
                self.assertTrue(report["diagnostics"][0]["code"].startswith("E_C_CONTRACT"))
                self.assertFalse((self.root / "output").exists())

    def test_both_cli_entrypoints_reject_ambiguous_contract_before_compiler(self):
        from hepta.cli import main as public_main
        from tools.migrate_c_project import main as tool_main
        path = self.root / "contract.json"
        path.write_text(DUPLICATE)
        arguments = [str(self.root / "missing.json"), "--output", str(self.root / "output"), "--contracts", str(path), "--clang", "must-not-execute"]
        for entry in ("public", "tool"):
            buffer = io.StringIO()
            with self.subTest(entry=entry), contextlib.redirect_stdout(buffer), patch("hepta.c_migration_project.capture_project", side_effect=AssertionError("compiler launched")):
                if entry == "public":
                    code = public_main(["migrate-c-project", *arguments, "--frontend-only"])
                else:
                    with patch("sys.argv", ["migrate_c_project.py", *arguments]):
                        code = tool_main()
            report = json.loads(buffer.getvalue())
            self.assertEqual(code, 1)
            self.assertEqual(report["diagnostics"][0]["code"], "E_C_CONTRACT_JSON")
            self.assertFalse((self.root / "output").exists())

    def test_record_view_value_contracts_are_also_detached_from_caller(self):
        from hepta.c_record_views import CRecordViewTranslator
        from tools.qualify_c_ring_buffer import FIXTURE
        original = load_contracts(FIXTURE / "contracts.json")
        translator = CRecordViewTranslator({}, original)
        original["functions"]["ring_buffer_init"]["slices"]["buf"]["access"] = "read"
        self.assertEqual(translator.contracts["functions"]["ring_buffer_init"]["slices"]["buf"]["access"], "mut")
        self.assertEqual(translator.value_contracts["functions"]["ring_buffer_init"]["slices"]["buf"]["access"], "mut")

    def test_real_native_translation_uses_frozen_contract_and_matches_original_c_write(self):
        clang = shutil.which("clang") or shutil.which("clang-20")
        self.assertIsNotNone(clang, "Real Clang required")
        source = self.root / "input.c"
        source.write_text("void write_one(unsigned int *p) { *p = 7u; }\n")
        database = self.root / "compile_commands.json"
        database.write_text(json.dumps([{"directory": str(self.root), "file": "input.c",
                                         "arguments": ["clang", "-std=c11", "-O2", "-c", "input.c"]}]))
        authored = json.loads(json.dumps(CONTRACT))
        expected_identity = contract_identity(authored)

        def capture_and_mutate(*args, **kwargs):
            authored["functions"]["write_one"]["slices"]["p"]["access"] = "read"
            return capture_project(*args, **kwargs)

        with patch("hepta.c_migration_project.capture_project", side_effect=capture_and_mutate):
            report = migrate_c_project(database, self.root / "translated", contracts=authored,
                                       clang=clang, rustc=os.environ.get("RUSTC"), verify_native=True)
        self.assertTrue(report["ok"], report["diagnostics"])
        self.assertEqual(report["contract_identity"], expected_identity)
        self.assertEqual(report["contracts"], CONTRACT)
        original = self.root / "original.so"
        compiled = subprocess.run(["gcc", "-std=c11", "-O2", "-shared", "-fPIC", str(source), "-o", str(original)], capture_output=True, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        c, h = ctypes.CDLL(str(original)), ctypes.CDLL(str(self.root / "translated/libtranslated.so"))
        for lib in (c, h):
            lib.write_one.argtypes = [ctypes.POINTER(ctypes.c_uint32)]
            lib.write_one.restype = None
        for initial in (0, 1, 7, (1 << 32) - 1):
            cv, hv = ctypes.c_uint32(initial), ctypes.c_uint32(initial)
            c.write_one(ctypes.byref(cv))
            h.write_one(ctypes.byref(hv))
            self.assertEqual((cv.value, hv.value), (7, 7))
        refused = migrate_c_project(database, self.root / "read-only", contracts=authored, clang=clang)
        self.assertFalse(refused["ok"])
        self.assertIn("E_C_READ_ONLY", [entry["code"] for entry in refused["diagnostics"]])


if __name__ == "__main__":
    unittest.main()
