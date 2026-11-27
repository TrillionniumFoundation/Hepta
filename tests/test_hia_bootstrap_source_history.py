"""Independent physical-source and executed-reader refusal controls."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
from types import CodeType
import unittest

from tools import hia_bootstrap_source_history as history

ROOT = Path(__file__).resolve().parents[1]
NAMES = (history.HELPER, history.SOURCE, history.FIXTURE, history.SUCCESSOR_FIXTURE)


class BootstrapSourceHistoryTests(unittest.TestCase):
    def stage(self, *, legacy=False):
        directory = tempfile.TemporaryDirectory(prefix="hia-bootstrap-source-history-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name).resolve()
        for name in NAMES:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        if legacy:
            relation = json.loads((root / history.SUCCESSOR_FIXTURE).read_bytes())["record"]
            raw = (root / history.SOURCE).read_bytes()
            for hunk in reversed(relation["hunks"]):
                offset = hunk["new_offset"]
                new = bytes.fromhex(hunk["new_hex"])
                old = bytes.fromhex(hunk["old_hex"])
                self.assertEqual(raw[offset:offset + len(new)], new)
                raw = raw[:offset] + old + raw[offset + len(new):]
            self.assertEqual(history.identity(raw), history.CURRENT)
            (root / history.SOURCE).write_bytes(raw)
            (root / history.SUCCESSOR_FIXTURE).unlink()
        spec = importlib.util.spec_from_file_location(
            "bootstrap_history_" + root.name.replace("-", "_"),
            root / history.HELPER,
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return root, module

    def test_current_complete_inverse_uses_actual_four_file_capture(self):
        root, module = self.stage()
        captured = []
        def take(path):
            raw = path.read_bytes()
            captured.append((path, raw))
            return raw
        original, proof, saved = module.capture(root, take=take)
        self.assertEqual(module.identity(original), module.HISTORICAL)
        self.assertEqual(set(saved), set(NAMES))
        self.assertEqual(proof["physical_source"], {"path": module.SOURCE, **module.LIVE_CURRENT})
        self.assertEqual(proof["physical_predecessor"]["prior"], module.CURRENT)
        self.assertEqual(proof["physical_predecessor"]["qualification_granted"], False)
        self.assertEqual(proof["reader"], {"path": module.HELPER, **module.identity(saved[module.HELPER])})
        self.assertEqual(proof["captured_files"], {name: module.identity(raw) for name, raw in saved.items()})
        self.assertTrue(all(path.is_relative_to(root) and path.read_bytes() == raw for path, raw in captured))
        module.unchanged(root, saved, take=take)
        binding = module.graph_bindings(saved[module.SOURCE], original)
        self.assertEqual(binding["import_port_count"], 40)
        self.assertEqual(set(binding["current_code"]["public_complete"]), set(module.METHODS))
        self.assertFalse(proof["current_semantics_qualified"])
        self.assertFalse(proof["whole_native_stack_qualified"])

    def test_exact_legacy_domain_keeps_original_ten_layer_fixture(self):
        root, module = self.stage(legacy=True)
        original, proof, saved = module.capture(root)
        self.assertEqual(module.identity(original), module.HISTORICAL)
        self.assertEqual(set(saved), {module.HELPER, module.SOURCE, module.FIXTURE})
        self.assertEqual(proof["relation_layers"], 10)
        self.assertNotIn("physical_predecessor", proof)
        self.assertEqual(proof["fixture"], {"path": module.FIXTURE, **module.FIXTURE_PIN})
        module.unchanged(root, saved)

    def test_import_then_physical_reader_change_is_refused(self):
        root, module = self.stage()
        path = root / module.HELPER
        path.write_bytes(path.read_bytes() + b"\n# changed after import, before first capture\n")
        with self.assertRaisesRegex(ValueError, "after import"):
            module.capture(root)

    def test_imported_reader_and_distinct_capture_root_must_match(self):
        first, module = self.stage()
        second, _ = self.stage()
        path = second / module.HELPER
        path.write_bytes(path.read_bytes() + b"\n# different physical reader\n")
        with self.assertRaisesRegex(ValueError, "executed implementation"):
            module.capture(second)
        self.assertEqual((first / module.HELPER).read_bytes(), module._EXECUTED_SOURCE)

    def test_imported_reader_late_change_is_refused_even_with_unchanged_copy(self):
        first, module = self.stage()
        second, _ = self.stage()
        _, _, saved = module.capture(second)
        path = first / module.HELPER
        path.write_bytes(path.read_bytes() + b"\n# executing module changed\n")
        with self.assertRaisesRegex(ValueError, "after import"):
            module.unchanged(second, saved)

    def test_current_source_requires_its_exact_new_relation(self):
        for action in ("missing", "changed"):
            with self.subTest(action=action):
                root, module = self.stage()
                path = root / module.SUCCESSOR_FIXTURE
                if action == "missing":
                    path.unlink()
                else:
                    value = json.loads(path.read_bytes())
                    value["qualification_granted"] = True
                    path.write_text(json.dumps(value))
                with self.assertRaises((ValueError, FileNotFoundError)):
                    module.capture(root)

    def test_distinct_root_missing_source_never_uses_ambient_root(self):
        root, module = self.stage()
        (root / module.SOURCE).unlink()
        with self.assertRaises(FileNotFoundError):
            module.capture(root)

    def test_every_captured_input_late_change_is_refused(self):
        for name in NAMES:
            with self.subTest(name=name):
                root, module = self.stage()
                _, _, saved = module.capture(root)
                path = root / name
                path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaises(ValueError):
                    module.unchanged(root, saved)

    def test_initial_capture_to_terminal_boundary_changes_are_refused(self):
        for name in NAMES:
            with self.subTest(name=name):
                root, module = self.stage()
                changed = False
                def take(path):
                    nonlocal changed
                    raw = path.read_bytes()
                    if path == root / module.SUCCESSOR_FIXTURE and not changed:
                        changed = True
                        target = root / name
                        target.write_bytes(target.read_bytes() + b"\n")
                    return raw
                with self.assertRaises(ValueError):
                    module.capture(root, take=take)
                self.assertTrue(changed)

    def test_cached_take_cannot_hide_actual_physical_changes(self):
        for name in NAMES:
            with self.subTest(name=name):
                root, module = self.stage()
                _, _, saved = module.capture(root)
                path = root / name
                path.write_bytes(path.read_bytes() + b"\n")
                with self.assertRaisesRegex(ValueError, "after import|actual physical bytes|source changed"):
                    module.unchanged(root, saved, take=lambda path: saved[path.relative_to(root).as_posix()])

    def test_first_middle_last_source_and_relation_tampering_is_refused(self):
        for name in (history.SOURCE, history.FIXTURE, history.SUCCESSOR_FIXTURE):
            for position in ("first", "middle", "last"):
                with self.subTest(name=name, position=position):
                    root, module = self.stage()
                    path = root / name
                    raw = bytearray(path.read_bytes())
                    offset = {"first": 0, "middle": len(raw) // 2, "last": len(raw) - 1}[position]
                    raw[offset] ^= 1
                    path.write_bytes(raw)
                    with self.assertRaises(ValueError):
                        module.capture(root)

    def test_terminal_capture_cannot_drop_reader_or_dependency(self):
        root, module = self.stage()
        _, _, saved = module.capture(root)
        for name in NAMES:
            changed = dict(saved)
            del changed[name]
            with self.subTest(name=name), self.assertRaises(ValueError):
                module.unchanged(root, changed)
        changed = dict(saved)
        changed[module.SOURCE] = bytearray(changed[module.SOURCE])
        with self.assertRaises(ValueError):
            module.unchanged(root, changed)

    def test_full_code_binding_distinguishes_constants_names_and_types(self):
        def body(source):
            code = compile(source, history.SOURCE, "exec")
            return next(item for item in code.co_consts if type(item) is CodeType)
        one = body("def sample():\n    return 1\n")
        two = one.replace(co_consts=(None, 2))
        boolean = one.replace(co_consts=(None, True))
        self.assertEqual(one.co_code, two.co_code)
        self.assertEqual(one.co_code, boolean.co_code)
        self.assertNotEqual(history.complete_code_digest(one), history.complete_code_digest(two))
        self.assertNotEqual(history.complete_code_digest(one), history.complete_code_digest(boolean))
        answer = body("def sample():\n    return answer\n")
        changed = answer.replace(co_names=("replacement",))
        self.assertEqual(answer.co_code, changed.co_code)
        self.assertNotEqual(history.complete_code_digest(answer), history.complete_code_digest(changed))
        nested = body("def sample():\n    def inner():\n        return 1\n    return inner\n")
        child = next(item for item in nested.co_consts if type(item) is CodeType)
        revised = nested.replace(co_consts=tuple(child.replace(co_consts=(None, 2)) if item is child else item for item in nested.co_consts))
        self.assertEqual(nested.co_code, revised.co_code)
        self.assertNotEqual(history.complete_code_digest(nested), history.complete_code_digest(revised))


if __name__ == "__main__":
    unittest.main()
