"""Real Agent roundtrips with the removed frontend and foreign backends absent."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CHILD = r'''
import importlib.abc, json, sys
blocked = {
    'hepta.backend', 'hepta.pipeline', 'hepta.protocol', 'hepta.lexer',
    'hepta.parser', 'hepta.checker', 'hepta.modules', 'hepta.packages',
    'hepta.c_backend', 'hepta.llvm_owned_backend', 'hepta.hia_program_source',
    'hepta.hia_program_llvm', 'hepta.hia_rust_crosscheck',
}
class NoFrozenFrontend(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in blocked:
            raise AssertionError('removed or foreign dependency: ' + fullname)
sys.meta_path.insert(0, NoFrozenFrontend())
from hepta.cli import hia_main
args = json.loads(sys.argv[1])
try:
    result = hia_main(args)
finally:
    assert not blocked.intersection(sys.modules), blocked.intersection(sys.modules)
raise SystemExit(result)
'''


def fixture():
    def value(name):
        return {"name": name, "type": "u32"}
    return {"schema": "hepta.hia.program.v8", "module": "agent_entry", "functions": [
        {"name": "calculate", "params": [value("x")], "returns": ["u32"],
         "effects": [], "entry": "entry", "blocks": [
             {"id": "entry", "params": [value("x")], "ops": [
                 {"op": "const", "args": [], "out": [value("one")], "attrs": {"value": 1}},
                 {"op": "int.add.wrap", "args": ["x", "one"], "out": [value("y")], "attrs": {}}],
              "term": {"op": "ret", "values": ["y"]}}]},
        {"name": "caller", "params": [value("input")], "returns": ["u32"],
         "effects": [], "entry": "entry", "blocks": [
             {"id": "entry", "params": [value("input")], "ops": [
                 {"op": "call", "args": ["input"], "out": [value("answer")],
                  "attrs": {"function": "calculate"}}],
              "term": {"op": "ret", "values": ["answer"]}}]},
    ]}


class AgentEntryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-agent-entry-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "program.hepta"
        self.source.write_text(json.dumps(fixture()))

    def invoke(self, *args, compat=False):
        # The object builder cannot accidentally find rustc/clang/ld via PATH.
        environment = {k: v for k, v in os.environ.items()
                       if not k.startswith("HEPTA_") and k != "PYTHONPATH"}
        environment.update(PATH="", PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([sys.executable, "-B", "-c", CHILD,
                               json.dumps(list(map(str, args))), "compat" if compat else "agent"],
                              cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)

    def accepted(self, *args, compat=False):
        result = self.invoke(*args, compat=compat)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        return json.loads(result.stdout)

    def query(self):
        target = self.root / "query.json"
        self.accepted("edit-query", self.source, "--function", "calculate", "--block", "entry",
                      "--value", "y", "--fields", "op", "-o", target)
        return target

    def test_capabilities_help_and_verify_do_not_load_frozen_frontend(self):
        result = self.accepted("capabilities")
        self.assertFalse(result["native_only_delivery_qualified"])
        self.assertFalse(result["high_level_source_required"])
        self.assertEqual(result["implementation"], "python_host_bridge")
        help_result = self.invoke("--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertNotIn("import-executable", help_result.stdout)
        self.assertNotIn("lower", help_result.stdout)
        version = self.invoke("--version")
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertTrue(version.stdout.startswith("hia "))
        self.assertTrue(self.accepted("verify", self.source)["ok"])
        self.assertTrue(self.accepted("verify", self.source, compat=True)["ok"])
        self.accepted("catalog", "--schema", "hepta.hia.program.v8")

    def test_assembly_roundtrip_uses_only_core(self):
        from hepta.hia_agent_assembly import render_assembly
        assembly = self.root / "program.hepta"
        assembly.write_text(render_assembly(fixture()))
        self.assertTrue(self.accepted("check-assembly", assembly)["accepted"])
        imported = self.root / "imported.hepta"
        self.accepted("import-assembly", assembly, "-o", imported)
        self.assertTrue(self.accepted("verify", imported)["ok"])
        self.accepted("inspect", imported)

    def test_local_edit_executes_changed_result_and_preserves_caller(self):
        from hepta.hia_program_runtime import execute_program
        query = self.query()
        response, target = self.root / "response.json", self.root / "changed.hepta"
        response.write_text('{"op":"int.sub.wrap"}')
        report = self.accepted("edit-apply", self.source, "--query", query,
                               "--response", response, "-o", target)
        self.assertTrue(report["edit_query"]["entire_module_reverified"])
        self.assertEqual(execute_program(self.source.read_bytes(), "caller", [9])["result"], 10)
        self.assertEqual(execute_program(target.read_bytes(), "caller", [9])["result"], 8)
        revised = json.loads(target.read_bytes())
        self.assertEqual(revised["functions"][1], fixture()["functions"][1])
        original = target.read_bytes()
        self.assertNotEqual(self.invoke("edit-apply", self.source, "--query", query,
                                       "--response", response, "-o", target).returncode, 0)
        self.assertEqual(target.read_bytes(), original)

    def test_stale_and_invalid_edits_publish_nothing(self):
        query = self.query()
        response, target = self.root / "response.json", self.root / "forbidden.hepta"
        response.write_text('{"op":"owner.drop"}')
        result = self.invoke("edit-apply", self.source, "--query", query,
                             "--response", response, "-o", target)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(target.exists())
        response.write_text('{"op":"int.sub.wrap"}')
        changed = fixture()
        changed["functions"][0]["blocks"][0]["ops"][0]["attrs"]["value"] = 2
        self.source.write_text(json.dumps(changed))
        result = self.invoke("edit-apply", self.source, "--query", query,
                             "--response", response, "-o", target)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(target.exists())

    def test_real_native_object_without_external_compiler_or_fallback(self):
        from hepta.object_symbols import inspect_object_symbols
        target = self.root / "program.o"
        self.accepted("build", self.source, "-o", target)
        self.assertEqual(target.read_bytes()[:4], b"\x7fELF")
        self.assertIn("calculate", inspect_object_symbols(target.read_bytes(), "ELF64", 62)["defined"])
        original = target.read_bytes()
        self.assertNotEqual(self.invoke("build", self.source, "-o", target).returncode, 0)
        self.assertEqual(target.read_bytes(), original)
        self.assertFalse(list(self.root.glob(".hia-direct-*")))

    def test_source_routes_and_foreign_backend_switches_refuse_before_output(self):
        target = self.root / "forbidden.o"
        for args in (("lower", self.source), ("run", self.source),
                     ("build", self.source, "--backend", "llvm", "-o", target),
                     ("build", self.source, "--kind", "shared", "-o", target),
                     ("verify", self.source, "--rust-shadow-bin", "/absent")):
            with self.subTest(args=args):
                self.assertEqual(self.invoke(*args).returncode, 2)
                self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
