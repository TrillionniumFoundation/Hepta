"""Immutable whole-file history controls for the original Slot15 migration."""
from __future__ import annotations

import ast
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_slot_cold_selection_history as history

ROOT = Path(__file__).resolve().parents[1]


class SlotColdSelectionHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current = {name: (ROOT / name).read_bytes() for name in history.EXPECTED}
        cls.previous = {
            name: subprocess.check_output(
                ["git", "-C", str(ROOT), "show", history.PREDECESSOR + ":" + name],
                timeout=60)
            for name in history.EXPECTED
        }
        cls.frozen = (ROOT / history.FIXTURE).read_bytes()
        for name, expected in history.EXPECTED.items():
            if history.pin(cls.current[name]) != expected["new"] or history.pin(cls.previous[name]) != expected["old"]:
                raise AssertionError("actual complete Git source does not match fixed history: " + name)

    def copied(self, folder, files):
        root = Path(folder).resolve()
        for name, raw in {**files, history.FIXTURE: self.frozen}.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        return root

    def test_complete_successor_restores_independent_git_predecessors(self):
        for name, raw in self.current.items():
            captured = []
            def take(path):
                captured.append(path.relative_to(ROOT).as_posix())
                return path.read_bytes()
            old, proof = history.reviewed(name, raw, root=ROOT, take=take)
            self.assertEqual(old, self.previous[name])
            self.assertIs(proof["complete_predecessors_restored"], True)
            self.assertIs(proof["complete_successors_replayed"], True)
            self.assertIs(proof["whole_native_delivery_qualified"], False)
            self.assertEqual(Counter(captured), Counter({path: 2 for path in (*history.EXPECTED, history.FIXTURE)}))

    def test_complete_predecessor_remains_unchanged(self):
        with tempfile.TemporaryDirectory(prefix="hia-slot-history-old-") as folder:
            root = self.copied(folder, self.previous)
            for name, raw in self.previous.items():
                self.assertEqual(history.reviewed(name, raw, root=root), (raw, None))

    def test_only_original_slot_setup_changes(self):
        name = "tests/test_hia_slot_ledger_native.py"
        old, new = (ast.parse(value[name]) for value in (self.previous, self.current))
        def methods(tree):
            return [ast.dump(node, include_attributes=False) for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name != "setUpClass"]
        self.assertEqual(methods(old), methods(new))
        self.assertEqual(sum(isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
                             for node in ast.walk(new)), 15)
        q = "tools/qualify_hia_slot_operations_callers.py"
        def assignments(raw):
            return {node.targets[0].id: ast.literal_eval(node.value)
                    for node in ast.parse(raw).body
                    if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id in {"ORIGINAL_MODULE", "ORIGINAL_FILE", "ORIGINAL_SHA256",
                                              "ORIGINAL_IDS", "OWNER_MODES"}}
        self.assertEqual(assignments(self.previous[q]), assignments(self.current[q]))
        self.assertEqual(assignments(self.current[q])["ORIGINAL_SHA256"],
                         "cfd2224fa96ef8c6a08a5aeb44f9d7576bf7fbaa611813ee0233edac7d5dcef8")
        self.assertEqual(len(assignments(self.current[q])["ORIGINAL_IDS"]), 15)
        for name in self.current:
            def budgets(raw):
                return [ast.dump(node, include_attributes=False) for node in ast.walk(ast.parse(raw))
                        if isinstance(node, ast.keyword) and node.arg in {"timeout", "deadline"}]
            self.assertEqual(budgets(self.previous[name]), budgets(self.current[name]))
        self.assertIn(b"and sum(entries.values()) > 0 and elapsed < 1800)", self.current[q])

    def test_unknown_and_partially_restored_source_groups_refuse(self):
        first = next(iter(self.current))
        with tempfile.TemporaryDirectory(prefix="hia-slot-history-mixed-") as folder:
            root = self.copied(folder, self.current)
            for basis, other in ((self.current, self.previous), (self.previous, self.current)):
                self.copied(folder, basis)
                for name in basis:
                    path = root / name
                    path.write_bytes(other[name])
                    try:
                        with self.subTest(basis="new" if basis is self.current else "old", name=name):
                            with self.assertRaisesRegex(ValueError, "group"):
                                history.reviewed(first, (root / first).read_bytes(), root=root)
                    finally:
                        path.write_bytes(basis[name])
            self.copied(folder, self.current)
            for name in self.current:
                path = root / name
                path.write_bytes(self.current[name] + b"\n# unknown source\n")
                try:
                    with self.subTest(unknown=name), self.assertRaisesRegex(ValueError, "group"):
                        history.reviewed(first, (root / first).read_bytes(), root=root)
                finally:
                    path.write_bytes(self.current[name])
            with self.assertRaisesRegex(ValueError, "provided bytes"):
                history.reviewed(first, self.previous[first], root=root)

    def test_explicit_root_and_capture_are_used_for_every_input(self):
        first = next(iter(self.current))
        with tempfile.TemporaryDirectory(prefix="hia-slot-history-root-") as folder:
            root = self.copied(folder, self.current)
            captured = []
            def take(path):
                self.assertTrue(path.is_relative_to(root))
                captured.append(path.relative_to(root).as_posix())
                return path.read_bytes()
            with patch.object(history, "ROOT", root / "nonexistent-default"):
                old, proof = history.reviewed(first, self.current[first], root=root, take=take)
            self.assertEqual(old, self.previous[first])
            self.assertIsNotNone(proof)
            self.assertEqual(Counter(captured), Counter({path: 2 for path in (*history.EXPECTED, history.FIXTURE)}))

    def test_terminal_reread_rejects_each_actual_input_mutation(self):
        first = next(iter(self.current))
        with tempfile.TemporaryDirectory(prefix="hia-slot-history-terminal-") as folder:
            root = self.copied(folder, self.current)
            for target in (*self.current, history.FIXTURE):
                path = root / target
                before = path.read_bytes()
                mutated = False
                def take(candidate):
                    nonlocal mutated
                    raw = candidate.read_bytes()
                    if candidate == path and not mutated:
                        candidate.write_bytes(raw + b"\n# late mutation\n")
                        mutated = True
                    return raw
                try:
                    with self.subTest(target=target), self.assertRaisesRegex(ValueError, "during review"):
                        history.reviewed(first, self.current[first], root=root, take=take)
                    self.assertTrue(mutated)
                finally:
                    path.write_bytes(before)

    def test_immutable_fixture_and_rebound_internal_mutations_refuse(self):
        first = next(iter(self.current))
        with tempfile.TemporaryDirectory(prefix="hia-slot-history-fixture-") as folder:
            root = self.copied(folder, self.current)
            path = root / history.FIXTURE
            path.write_bytes(self.frozen + b" ")
            with self.assertRaisesRegex(ValueError, "immutable fixture"):
                history.reviewed(first, self.current[first], root=root)
            original = json.loads(self.frozen)
            mutations = (
                ("scope", lambda v: v.__setitem__("whole_native_delivery_qualified", 0)),
                ("predecessor", lambda v: v.__setitem__("predecessor_commit", "0" * 40)),
                ("missing-file", lambda v: v["files"].pop(first)),
                ("new-pin", lambda v: v["files"][first]["new"].__setitem__("sha256", "0" * 64)),
                ("bool-offset", lambda v: v["files"][first]["hunks"][0].__setitem__("old_offset", True)),
                ("negative-offset", lambda v: v["files"][first]["hunks"][0].__setitem__("new_offset", -1)),
                ("changed-old-splice", lambda v: v["files"][first]["hunks"][0].__setitem__("old_hex", "00")),
                ("invalid-hex", lambda v: v["files"][first]["hunks"][0].__setitem__("new_hex", "gg")),
            )
            for label, change in mutations:
                value = json.loads(self.frozen)
                change(value)
                raw = (json.dumps(value, sort_keys=True) + "\n").encode()
                path.write_bytes(raw)
                with self.subTest(label=label), patch.object(history, "FIXTURE_SHA256", sha256(raw).hexdigest()):
                    with self.assertRaises(ValueError):
                        history.reviewed(first, self.current[first], root=root)
            duplicate = b'{"schema": "duplicate",' + self.frozen.lstrip()[1:]
            path.write_bytes(duplicate)
            with patch.object(history, "FIXTURE_SHA256", sha256(duplicate).hexdigest()):
                with self.assertRaisesRegex(ValueError, "duplicate"):
                    history.reviewed(first, self.current[first], root=root)

    def test_missing_nonbytes_and_unknown_inputs_refuse(self):
        first = next(iter(self.current))
        with tempfile.TemporaryDirectory(prefix="hia-slot-history-missing-") as folder:
            root = self.copied(folder, self.current)
            for name, raw in self.current.items():
                path = root / name
                path.unlink()
                try:
                    with self.subTest(name=name), self.assertRaisesRegex(ValueError, "missing captured"):
                        history.reviewed(first, self.current[first], root=root)
                finally:
                    path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "exact bytes"):
                history.reviewed(first, self.current[first].decode(), root=root)
            with self.assertRaisesRegex(ValueError, "unknown source path"):
                history.reviewed("unknown", b"", root=root)
            with self.assertRaisesRegex(ValueError, "capture did not return exact bytes"):
                history.reviewed(first, self.current[first], root=root,
                                 take=lambda path: path.read_text() if path.name.endswith(".py") else path.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
