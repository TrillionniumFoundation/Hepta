"""Current physical-source checks plus four unchanged original admission methods.

The complete six-method historical source gate remains byte-for-byte in its
fixed fixture. Current regenerated HIA and the source suffix migration receive
separate explicit checks; historical bytes never authorize current compilation.
"""
from __future__ import annotations
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / "tests/fixtures/hia_legacy_byte_components_ff636"

def literal_assignment(path, name):
    nodes = ast.parse(path.read_bytes()).body
    values = [node.value for node in nodes if isinstance(node, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == name for t in node.targets)]
    if len(values) != 1:
        raise AssertionError("one fixed assignment required: " + name)
    return ast.literal_eval(values[0])

class BoundedReadCurrentSourceTests(unittest.TestCase):
    def test_current_generated_program_and_original_abi_limits(self):
        from hepta.hia_agent_assembly import assemble_program
        from tools.generate_hia_bounded_read import generated_files, document, SOURCE_PATH, ABI_PATH
        generated = generated_files()
        for name, raw in generated.items():
            self.assertEqual((ROOT / name).read_bytes(), raw)
        assembly = generated[SOURCE_PATH]
        self.assertEqual((len(assembly), sha256(assembly).hexdigest()),
                         (57752, "ae9172bc1a794e9a377652415e66fe672d643352c5ca6d964a352f04d2fc437e"))
        self.assertEqual(assemble_program(assembly).as_dict(), document())
        abi = json.loads(generated[ABI_PATH])
        self.assertEqual(abi["function"], "f0")
        self.assertEqual([p["type"] for p in abi["parameters"]], ["readbuf", "mutbuf", "mutbuf"])
        self.assertEqual([p["bytes"] for p in abi["parameters"]], [64, 24, 1024])
        self.assertEqual(abi["returns"], ["u32"])
        self.assertEqual(abi["source_sha256"], sha256(assembly).hexdigest())
        self.assertEqual(len(document()["functions"]), 14)
        self.assertLessEqual(len(assembly), 1 << 20)
        self.assertLessEqual(len(assembly.splitlines()), 16384)
        self.assertLessEqual(sum(len(f["blocks"]) for f in document()["functions"]), 1536)
        self.assertLessEqual(sum(len(b["ops"]) for f in document()["functions"] for b in f["blocks"]), 8192)

    def test_original_caller_whole_bytes_and_read_function_are_preserved(self):
        historical = ORIGINAL / "tests/test_hia_program_tools.py.txt"
        old = historical.read_bytes()
        self.assertEqual(sha256(old).hexdigest(),
                         "8e885163d57ec41e869d5b8cb206de1b9942e0c636bcacf3b362bd5e669317c6")
        current = (ROOT / "tests/test_hia_program_tools.py").read_bytes()
        self.assertEqual(current.replace(b'.hepta"', b'.hia"'), old)
        reference = (ROOT / "tests/fixtures/hia_program_tools_acffa.py.txt").read_bytes()
        self.assertEqual(sha256(reference).hexdigest(),
                         "953bcc57375f34210c319852091ce5a3a5a1479a723e388a4c989898911bf99c")
        def definitions(raw):
            return {n.name: ast.dump(n, include_attributes=False)
                    for n in ast.parse(raw).body
                    if isinstance(n, (ast.FunctionDef, ast.ClassDef))
                    and n.name in {"HIAEditRejected", "_reject", "read_bounded"}}
        self.assertEqual(definitions((ROOT / "hepta/hia_program_tools.py").read_bytes()),
                         definitions(reference))
        from hepta import hia_program_tools as public
        from hepta import hia_bounded_read_native as bridge
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(bridge.selected_bounded_read())
            with patch.object(public, "_RETAINED_READ_BOUNDED") as retained:
                retained.return_value = object()
                self.assertIs(public.read_bounded("test-only-path"), retained.return_value)
                retained.assert_called_once_with("test-only-path", 8 << 20)
        with patch.dict(os.environ, {bridge.SELECTOR: ""}, clear=True):
            with self.assertRaises((ValueError, OSError)):
                bridge.selected_bounded_read()

    def test_complete_historical_source_gate_is_immutable(self):
        path = ORIGINAL / "tests/test_hia_bounded_read_source.py.txt"
        self.assertEqual(sha256(path.read_bytes()).hexdigest(),
                         "8ad3941525165af4fbb8feff4ed70ce7ae4f40e740d4abb0bfce31630e38ed89")
        methods = [m for n in ast.parse(path.read_bytes()).body if isinstance(n, ast.ClassDef)
                   for m in n.body if isinstance(m, ast.FunctionDef) and m.name.startswith("test_")]
        self.assertEqual(len(methods), 6)

    def test_all_55_cases_and_original_eight_ids_and_deadlines_remain_explicit(self):
            from tools.qualify_hia_bounded_read import population
            groups = population()
            self.assertEqual([g["method_count"] for g in groups], [12, 24, 10, 9, 8])
            self.assertEqual([g["qualification_seconds"] for g in groups], [30, 30, 30, 30, 180])
            directory = ROOT / "tools/hia_bounded_read_checks"
            for group in groups:
                if group["name"] == "reject":
                    actual = [row[0] for row in literal_assignment(directory / group["script"], "CASES")]
                else:
                    actual = list(literal_assignment(directory / group["script"], "EXPECTED_IDS"))
                self.assertEqual(actual, group["expected_ids"])
            module = ast.parse((ROOT / "tests/test_hia_program_tools.py").read_bytes())
            names = sorted("tests.test_hia_program_tools.HIAProgramToolsTests." + method.name
                           for cls in module.body if isinstance(cls, ast.ClassDef)
                           and cls.name == "HIAProgramToolsTests"
                           for method in cls.body if isinstance(method, ast.FunctionDef)
                           and method.name.startswith("test_"))
            self.assertEqual(names, groups[-1]["expected_ids"])

    def test_component_resource_and_full_source_membership_are_declared(self):
            from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
            from tools.build_hia_bounded_read import ABI, SOURCE, OWNED_SOURCE_FILES, current_sources
            sources = current_sources()
            self.assertTrue(set(OWNED_SOURCE_FILES) <= set(sources))
            for name in OWNED_SOURCE_FILES:
                self.assertEqual(sources[name], sha256((ROOT / name).read_bytes()).hexdigest())
            manifest = (ROOT / "MANIFEST.in").read_text().splitlines()
            for name in (SOURCE, ABI):
                self.assertEqual(NATIVE_SOURCE_FILES.count(name), 1)
                self.assertEqual(manifest.count("include " + name), 1)

    def test_matching_cold_refusal_precedes_output_or_compiler_invocation(self):
            from tools import build_hia_bounded_read as builder
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                compiler, report, output = directory / "compiler", directory / "cold.json", directory / "out"
                compiler.write_bytes(b"not-a-qualified-compiler")
                report.write_text("{}")
                with patch.object(builder, "compile_stage") as compile_native:
                    with self.assertRaises(ValueError):
                        builder.build(output, compiler, report)
                    compile_native.assert_not_called()
                self.assertFalse(output.exists())
                with patch.object(builder, "current_sources", return_value={}):
                    with patch.object(builder, "compile_stage") as compile_native:
                        with self.assertRaises(ValueError):
                            builder.build_development(output, compiler)
                        compile_native.assert_not_called()
                self.assertFalse(output.exists())

    def test_actual_manifest_source_admission_rechecks_warm_source_without_native_mapping(self):
            from hepta import hia_bounded_read_native as bridge
            from hepta.hia_json_preflight_native import _load_manifest
            calls = []
            def observe_factory(image, digest):
                calls.append((image, digest))
                return object()
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                source, image, manifest = directory / "source", directory / "image", directory / "manifest.json"
                source.write_bytes(b"source-one")
                image.write_bytes(b"not-executable-observer-input")
                value = {"schema": bridge.SCHEMA, "source_sha256": sha256(source.read_bytes()).hexdigest(),
                         "image_path": image.name, "image_sha256": sha256(image.read_bytes()).hexdigest(),
                         "compiler_sha256": "0" * 64}
                manifest.write_text(json.dumps(value))
                _load_manifest.cache_clear()
                try:
                    with patch.object(bridge, "SOURCE", source), patch.object(bridge, "NativeBoundedRead", observe_factory):
                        first = bridge.installed_bounded_read(manifest)
                        self.assertIs(bridge.installed_bounded_read(manifest), first)
                        self.assertEqual(len(calls), 1)
                        source.write_bytes(b"source-two")
                        with self.assertRaises(ValueError):
                            bridge.installed_bounded_read(manifest)
                        self.assertEqual(len(calls), 1)
                        source.write_bytes(b"source-one")
                        self.assertIs(bridge.installed_bounded_read(manifest), first)
                        source.unlink()
                        with self.assertRaises(FileNotFoundError):
                            bridge.installed_bounded_read(manifest)
                finally:
                    _load_manifest.cache_clear()

if __name__ == "__main__":
    unittest.main()
