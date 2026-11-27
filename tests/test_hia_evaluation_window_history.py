"""Complete physical/projection custody tests for the Evaluation successor."""
from pathlib import Path
from hashlib import sha256
import ast
import builtins
import json
import tempfile
import unittest

from tools import hia_evaluation_window_history as window
from tools import hia_frozen_component_sources as retained

ROOT = Path(__file__).resolve().parents[1]


def forward(raw, record):
    pieces, end = [], 0
    for hunk in record["hunks"]:
        at = hunk["old_offset"]
        before, after = bytes.fromhex(hunk["old_hex"]), bytes.fromhex(hunk["new_hex"])
        if raw[at:at + len(before)] != before:
            raise ValueError("test fixture cannot replay the complete predecessor")
        pieces.extend((raw[end:at], after))
        end = at + len(before)
    pieces.append(raw[end:])
    result = b"".join(pieces)
    if window.pin(result) != record["current"]:
        raise ValueError("test fixture complete successor differs")
    return result


class EvaluationWindowHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = (ROOT / window.FIXTURE).read_bytes()
        cls.relation = json.loads(cls.fixture)
        cls.old, cls.new = {}, {}
        for name, expected in window.ORIGINAL.items():
            raw = (ROOT / name).read_bytes()
            if window.pin(raw) == window.CURRENT[name]:
                raw = window._inverse(raw, cls.relation["files"][name], expected)
            if window.pin(raw) != expected:
                raise ValueError("test repository is not an exact reviewed composition member: " + name)
            cls.old[name] = raw
            cls.new[name] = forward(raw, cls.relation["files"][name])
        cls.support = {}
        names = [*window.UNCHANGED, window.FIXTURE, window.ENGINE,
                 retained.SOURCE_HISTORY_FIXTURE, retained.HOST_SUPPORT,
                 retained.EVALUATION_QUALIFIER, retained.FIXTURE]
        for name in names:
            cls.support[name] = (ROOT / name).read_bytes()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hia-evaluation-history-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.write({**self.support, **self.new})

    def write(self, values):
        for name, raw in values.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def prepare(self, name="tests/test_hia_evaluation_native.py"):
        return window.prepare(self.root, {name: (self.root / name).read_bytes()})

    def consume(self, name="tests/test_hia_evaluation_native.py"):
        projected, history = self.prepare(name)
        restored, previous = retained.restore(
            projected, root=self.root, take=history["prior_take"])
        retained.verify_unchanged(previous)
        window.verify_unchanged(history)
        self.assertEqual(set(restored), set(retained.PREDECESSORS))
        for path, expected in retained.PREDECESSORS.items():
            self.assertEqual(window.pin(restored[path]), expected)
        return projected, history, restored

    def test_current_complete_three_files_recover_all_five_prior_members(self):
        for name in window.ORIGINAL:
            with self.subTest(name=name):
                projected, history, _ = self.consume(name)
                self.assertEqual(projected[name], self.old[name])
                self.assertEqual(history["captures"][name], self.new[name])
                self.assertTrue(history["review"]["successor_applied"])
                self.assertFalse(history["review"]["physical_capture_rewritten"])
                self.assertFalse(history["review"]["prior_projection_is_physical_source"])
                self.assertTrue(history["review"]["terminal_reread_identical"])

    def test_complete_original_composition_uses_unchanged_engine(self):
        self.write(self.old)
        _, history, _ = self.consume()
        self.assertFalse(history["review"]["successor_applied"])

    def test_each_partially_reverted_successor_is_rejected(self):
        for name in window.ORIGINAL:
            with self.subTest(name=name):
                self.write(self.new)
                self.write({name: self.old[name]})
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_each_unchanged_composition_member_is_bound(self):
        for name in window.UNCHANGED:
            with self.subTest(name=name):
                self.write(self.support)
                self.write({name: self.support[name] + b" "})
                with self.assertRaises(ValueError):
                    self.prepare()
                (self.root / name).unlink()
                with self.assertRaises(FileNotFoundError):
                    self.prepare()
        self.write(self.support)

    def test_argument_cannot_substitute_historical_bytes_for_physical_capture(self):
        name = "tests/test_hia_evaluation_native.py"
        with self.assertRaises(ValueError):
            window.prepare(self.root, {name: self.old[name]})

    def test_independent_root_missing_fixed_relation_is_rejected(self):
        (self.root / window.FIXTURE).unlink()
        with self.assertRaises(FileNotFoundError):
            self.prepare()
        self.assertEqual((ROOT / window.FIXTURE).read_bytes(), self.fixture)

    def test_independent_root_altered_fixed_relation_is_rejected(self):
        self.write({window.FIXTURE: self.fixture + b" "})
        with self.assertRaises(ValueError):
            self.prepare()

    def test_retained_engine_complete_file_is_bound(self):
        self.write({window.ENGINE: self.support[window.ENGINE] + b"\n"})
        with self.assertRaises(ValueError):
            self.prepare()

    def test_physical_source_change_during_prior_consumer_is_rejected(self):
        projected, history = self.prepare()
        name = "hepta/hia_agent_service.py"
        self.write({name: self.new[name] + b"\n"})
        with self.assertRaises(ValueError):
            retained.restore(projected, root=self.root, take=history["prior_take"])

    def test_each_physical_source_late_change_is_rejected(self):
        for name in window.PATHS:
            with self.subTest(name=name):
                self.write({**self.support, **self.new})
                _, history, _ = self.consume()
                self.write({name: (self.root / name).read_bytes() + b"\n"})
                with self.assertRaises(ValueError):
                    window.verify_unchanged(history)

    def test_each_consumed_fixed_relation_late_change_is_rejected(self):
        for name in (window.FIXTURE, window.ENGINE, retained.SOURCE_HISTORY_FIXTURE,
                     retained.HOST_SUPPORT, retained.EVALUATION_QUALIFIER):
            with self.subTest(name=name):
                self.write({**self.support, **self.new})
                _, history, _ = self.consume()
                self.assertIn(name, history["captures"])
                self.write({name: (self.root / name).read_bytes() + b" "})
                with self.assertRaises(ValueError):
                    window.verify_unchanged(history)

    def test_unknown_complete_source_is_not_admitted(self):
        for name in window.ORIGINAL:
            with self.subTest(name=name):
                self.write(self.new)
                self.write({name: self.new[name] + b"# unknown\n"})
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_source_root_escape_and_nonphysical_arguments_are_rejected(self):
        for name in ("../outside", "/outside", ".git/config"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    window.prepare(self.root, {name: b""})
        with self.assertRaises(ValueError):
            window.prepare(self.root, {})
        name = "tests/test_hia_evaluation_native.py"
        with self.assertRaises(ValueError):
            window.prepare(self.root, {name: self.new[name].decode()})

    def test_fixed_reader_relation_composes_without_executing_product_code(self):
        actual_import = builtins.__import__
        attempted = []
        def guarded(name, *args, **kwargs):
            if (name == "hepta" or name.startswith(("hepta.", "tests.", "tools.build_",
                                                   "tools.generate_", "tools.qualify_"))
                    or "oracle" in name):
                attempted.append(name)
                raise AssertionError("data-only history attempted product import: " + name)
            return actual_import(name, *args, **kwargs)
        builtins.__import__ = guarded
        try:
            name = "tests/test_hia_evaluation_native.py"
            projected, history = self.prepare(name)
            result = retained.reviewed_source(
                self.root, name, projected[name], take=history["prior_take"])
            window.verify_unchanged(history)
        finally:
            builtins.__import__ = actual_import
        expected = json.loads(self.support[retained.FIXTURE])["files"][name]["reviewed_sha256"]
        self.assertEqual(sha256(result).hexdigest(), expected)
        self.assertEqual(attempted, [])
        tree = ast.parse((ROOT / "tools/hia_evaluation_window_history.py").read_bytes())
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.extend(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.append((node.module or "").split(".")[0])
        self.assertLessEqual(set(names), {"hashlib", "json", "pathlib", "re"})


if __name__ == "__main__":
    unittest.main()
