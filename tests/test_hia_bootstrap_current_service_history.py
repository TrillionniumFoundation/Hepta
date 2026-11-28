"""Current Bootstrap source preparation, distinct from the fixed old controls."""
from __future__ import annotations
import ast
import base64
import gzip
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest

from tools import hia_bootstrap_source_history as history

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/hia_bootstrap_current_service_composition_v1.json"
FIXTURE_PIN = {"bytes": 23192, "sha256": "6b880851a9aab37a16731fd3aeec6cbae527342e6babe9f09573b22668f51858"}


def prior_files():
    raw = FIXTURE.read_bytes()
    if {"bytes": len(raw), "sha256": sha256(raw).hexdigest()} != FIXTURE_PIN:
        raise ValueError("Bootstrap source preparation originals changed")
    value = json.loads(raw)
    result = {}
    for name, record in value["files"].items():
        data = gzip.decompress(base64.b64decode(record["gzip_base64"], validate=True))
        if history.identity(data) != {k: record[k] for k in ("bytes", "sha256", "git_blob")}:
            raise ValueError("Bootstrap complete prior file changed")
        result[name] = data
    if FIXTURE.read_bytes() != raw:
        raise ValueError("Bootstrap preparation original fixture changed during read")
    return result


class BootstrapCurrentServiceTests(unittest.TestCase):
    def stage(self):
        original, proof, saved = history.capture(ROOT)
        directory = TemporaryDirectory(prefix="hia-bootstrap-current-group-")
        self.addCleanup(directory.cleanup)
        target = Path(directory.name).resolve()
        for name, raw in saved.items():
            p = target / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(raw)
            p.chmod(stat.S_IMODE((ROOT / name).stat().st_mode))
        history.unchanged(ROOT, saved)
        return target

    def test_complete_current_group_actual_capture_and_distinct_prior_view(self):
        observed = []
        def take(path):
            raw = path.read_bytes()
            observed.append((path, raw))
            return raw
        original, proof, saved = history.capture(ROOT, take=take)
        self.assertEqual(history.identity(saved[history.SOURCE]), history.CURRENT_SERVICE)
        self.assertEqual(history.identity(original), history.HISTORICAL)
        self.assertEqual(history.identity(history.current_service_predecessor(saved)), history.LIVE_CURRENT)
        self.assertNotEqual(saved[history.SOURCE], history.current_service_predecessor(saved))
        layer = proof["current_source_preparation"]
        self.assertEqual(layer["complete_group_scope"], "EXPLICIT_PREDECESSOR_446_PORT_9_METHOD_DOMAIN")
        self.assertEqual(len(layer["complete_group_entries"]), 12)
        self.assertGreater(len(layer["physical_group"]), 470)
        self.assertEqual(layer["prior_service"], history.LIVE_CURRENT)
        self.assertFalse(layer["current_semantics_qualified"])
        self.assertFalse(layer["whole_native_stack_qualified"])
        self.assertEqual(proof["physical_source"], {"path": history.SOURCE, **history.CURRENT_SERVICE})
        self.assertEqual(proof["captured_files"],
                         {name: history.identity(raw) for name, raw in sorted(saved.items())})
        self.assertTrue(all(p.is_relative_to(ROOT) and p.read_bytes() == raw for p, raw in observed))
        binding = history.graph_bindings(saved[history.SOURCE], original)
        self.assertEqual(binding["import_port_count"], 40)
        self.assertEqual(set(binding["current_code"]["public_complete"]), set(history.METHODS))
        history.unchanged(ROOT, saved, take=take)

    def test_complete_original_thirteen_methods_and_fixtures_are_preserved(self):
        old = prior_files()
        name = "tests/test_hia_bootstrap_source_history.py"
        def methods(raw):
            tree = ast.parse(raw)
            cls = next(n for n in tree.body if isinstance(n, ast.ClassDef)
                       and n.name == "BootstrapSourceHistoryTests")
            return {n.name: ast.dump(n, include_attributes=False) for n in cls.body
                    if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")}
        self.assertEqual(len(methods(old[name])), 13)
        self.assertEqual(methods(old[name]), methods((ROOT / name).read_bytes()))
        self.assertEqual(history.identity((ROOT / history.FIXTURE).read_bytes()), history.FIXTURE_PIN)
        self.assertEqual(history.identity((ROOT / history.SUCCESSOR_FIXTURE).read_bytes()), history.SUCCESSOR_PIN)
        # The complete original inversion and forward replay remain exact.
        old_tree = ast.parse(old[history.HELPER])
        new_tree = ast.parse((ROOT / history.HELPER).read_bytes())
        for name in ("_record", "_restore_relation", "restore", "_code",
                     "_code_value", "complete_code_digest", "code_bindings"):
            a = next(n for n in old_tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
            b = next(n for n in new_tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertEqual(ast.dump(a, include_attributes=False), ast.dump(b, include_attributes=False))

    def test_component_input_declaration_contains_every_actual_history_dependency(self):
        from tests import hia_service_bootstrap_support as support
        old = prior_files()
        name = "tools/build_hia_service_bootstrap.py"
        def inputs(raw):
            tree = ast.parse(raw)
            node = next(n for n in tree.body if isinstance(n, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == "INPUTS" for t in n.targets))
            return ast.literal_eval(node.value)
        before, after = inputs(old[name]), inputs((ROOT / name).read_bytes())
        self.assertEqual(after[:len(before)], before)
        self.assertEqual(len(after), len(set(after)))
        original, proof, saved = history.capture(ROOT)
        declared = support.source_snapshot()
        self.assertFalse(set(saved) - set(after))
        for name, raw in saved.items():
            self.assertEqual(declared[name], {"bytes": len(raw), "sha256": sha256(raw).hexdigest()})
        history.unchanged(ROOT, saved)

    def test_missing_and_corrupt_current_group_are_refused_without_ambient_fallback(self):
        root = self.stage()
        selected = (history.HELPER, history.BEHAVIOR_READER, history.BEHAVIOR_FIXTURE,
                    history.SOURCE, history.FIXTURE, history.SUCCESSOR_FIXTURE,
                    "hepta/hia_behavior_inputs.py", "hepta/hia_program_runtime.py",
                    "examples/hia_bootstrap/service_verification.hepta")
        for name in selected:
            path = root / name
            raw, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            try:
                path.unlink()
                with self.subTest(path=name, action="missing"), self.assertRaises((ValueError, FileNotFoundError)):
                    history.capture(root)
                path.write_bytes(raw + b"\n")
                path.chmod(mode)
                with self.subTest(path=name, action="changed"), self.assertRaises(ValueError):
                    history.capture(root)
            finally:
                path.write_bytes(raw)
                path.chmod(mode)
        history.capture(root)

    def test_all_twelve_current_members_and_mode_changes_are_refused_at_terminal(self):
        root = self.stage()
        original, proof, saved = history.capture(root)
        names = proof["current_source_preparation"]["complete_group_entries"]
        for name in names:
            path = root / name
            raw, mode = path.read_bytes(), stat.S_IMODE(path.stat().st_mode)
            try:
                path.write_bytes(raw + b"\n")
                with self.subTest(path=name, action="late-bytes"), self.assertRaises(ValueError):
                    history.unchanged(root, saved)
                with self.subTest(path=name, action="cached-take"), self.assertRaises(ValueError):
                    history.unchanged(root, saved, take=lambda p: saved[p.relative_to(root).as_posix()])
                path.write_bytes(raw)
                path.chmod(mode ^ 0o100)
                with self.subTest(path=name, action="late-mode"), self.assertRaises(ValueError):
                    history.unchanged(root, saved)
            finally:
                path.write_bytes(raw)
                path.chmod(mode)
        history.unchanged(root, saved)

    def test_imported_reader_and_terminal_capture_cannot_be_replaced_or_truncated(self):
        root = self.stage()
        spec = importlib.util.spec_from_file_location("bootstrap_current_tamper", root / history.HELPER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        path = root / history.HELPER
        raw = path.read_bytes()
        path.write_bytes(raw + b"\n# changed after import\n")
        try:
            with self.assertRaisesRegex(ValueError, "after import"):
                module.capture(root)
        finally:
            path.write_bytes(raw)
        original, proof, saved = module.capture(root)
        with self.assertRaises(ValueError):
            module.unchanged(root, dict(saved))
        for name in (module.HELPER, module.SOURCE, module.BEHAVIOR_FIXTURE):
            raw = saved.pop(name)
            try:
                with self.assertRaises((ValueError, KeyError)):
                    module.unchanged(root, saved)
            finally:
                saved[name] = raw
        module.unchanged(root, saved)

    def test_first_capture_and_terminal_late_physical_changes_cannot_be_rebound(self):
        root = self.stage()
        target = root / "hepta/hia_program_runtime.py"
        raw = target.read_bytes()
        changed = False
        def take(path):
            nonlocal changed
            value = path.read_bytes()
            if path == target and not changed:
                changed = True
                path.write_bytes(value + b"\n")
            return value
        try:
            with self.assertRaises(ValueError):
                history.capture(root, take=take)
            self.assertTrue(changed)
        finally:
            target.write_bytes(raw)
        original, proof, saved = history.capture(root)
        path = root / history.SOURCE
        physical = path.read_bytes()
        try:
            path.write_bytes(history.current_service_predecessor(saved))
            with self.assertRaises(ValueError):
                history.unchanged(root, saved)
        finally:
            path.write_bytes(physical)
        history.unchanged(root, saved)

    def test_current_static_prefix_uses_complete_original_and_rejects_modified_input(self):
        from tests.hia_store_delivery_successor import retained_bootstrap_service
        raw = (ROOT / history.SOURCE).read_bytes()
        actual = retained_bootstrap_service(raw)
        self.assertEqual(history.identity(actual), history.HISTORICAL)
        self.assertEqual(history.identity(actual[:history.PREFIX["bytes"]]), history.PREFIX)
        for offset in (0, len(raw) // 2, len(raw) - 1):
            changed = bytearray(raw)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                retained_bootstrap_service(bytes(changed))


if __name__ == "__main__":
    unittest.main()
