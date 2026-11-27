"""Independent controls for current Core inputs and explicit historical metadata."""
from __future__ import annotations
import ast
import base64
from contextlib import contextmanager
import importlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_core_three_current_preparation as prep
from tools import hia_core_three_source_history as history

ROOT = Path(__file__).resolve().parents[1]


class CurrentCorePreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = prep.CapturedInputs(ROOT)
        cls.temporary = tempfile.TemporaryDirectory(prefix="core-three-independent-controls-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name).resolve() / "source"
        for name, raw in cls.actual.saved.items():
            path = cls.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    @contextmanager
    def changed(self, name, raw):
        path = self.root / name
        old = path.read_bytes()
        try:
            if raw is None:
                path.unlink()
            else:
                path.write_bytes(raw)
            yield path
        finally:
            path.write_bytes(old)

    def test_original_methods_and_limits_are_exact(self):
        for family, name in prep.TESTS.items():
            old = self.actual.old[name]
            current = self.actual.saved[name]
            self.assertEqual(current, old.replace(
                prep.MARKER, prep.insertion(family) + prep.MARKER, 1))
            for kind in (ast.ClassDef,):
                before = [ast.dump(n) for n in ast.parse(old).body if isinstance(n, kind)]
                after = [ast.dump(n) for n in ast.parse(current).body if isinstance(n, kind)]
                self.assertEqual(after, before)

    def test_current_integer_is_physical_and_history_is_separate(self):
        state = prep.CapturedInputs(self.root, materialize=True)
        try:
            current = (state.integer_current_root /
                       "integration/hepta/hia_core_lowering_native.py").read_bytes()
            old = (state.historical_root /
                   "tests/fixtures/hia_core_integer/integration/hepta/hia_core_lowering_native.py").read_bytes()
            self.assertEqual(current, (self.root / "hepta/hia_core_lowering_native.py").read_bytes())
            self.assertNotEqual(current, old)
            self.assertFalse(state.proof()["native_executed"])
            self.assertFalse(state.proof()["whole_Core_qualification_granted"])
            state.verify_views()
        finally:
            state.temporary.cleanup()

    def test_current_authoring_is_canonical_and_original_algorithms_are_retained(self):
        from hepta.hia_agent_assembly import render_assembly
        from hepta.hia_program import verify_program
        for family in prep.TESTS:
            author = importlib.import_module("tools.generate_hia_core_" + family)
            original = ast.parse(self.actual.old["tools/generate_hia_core_" + family + ".py"])
            class CurrentSuffix(ast.NodeTransformer):
                def visit_Constant(self, node):
                    if type(node.value) is str:
                        node.value = node.value.replace(".hiaasm", ".hepta")
                    return node
            expected = CurrentSuffix().visit(original)
            current_author = ast.parse((ROOT / ("tools/generate_hia_core_" + family + ".py")).read_bytes())
            self.assertEqual(ast.dump(current_author), ast.dump(expected))
            document = author.document()
            verify_program(document)
            actual = (self.root / ("examples/hia_bootstrap/core_" + family + ".hepta")).read_bytes()
            self.assertEqual(actual, render_assembly(document).encode())

    def test_selected_root_missing_and_bad_fixture_cannot_fall_back(self):
        name = next(iter(prep.CORPORA))
        for replacement in (None, b"not the fixed source corpus"):
            with self.subTest(replacement=replacement), self.changed(name, replacement):
                with self.assertRaises((ValueError, FileNotFoundError)):
                    prep.CapturedInputs(self.root)

    def test_late_physical_source_and_forged_take_are_refused(self):
        state = prep.CapturedInputs(self.root)
        name = "hepta/hia_core_integer_native.py"
        before = (self.root / name).read_bytes()
        with self.changed(name, before + b"\n# independent late mutation\n"):
            with self.assertRaises(ValueError):
                state.unchanged()
            def forged(path):
                return before if Path(path) == self.root / name else Path(path).read_bytes()
            with self.assertRaises(ValueError):
                prep.CapturedInputs(self.root, take=forged)
        state.unchanged()

    def test_imported_preparation_and_history_bind_executed_self(self):
        for name, member in ((prep.SELF, "CapturedInputs"), (history.SELF, "prepare")):
            path = self.root / name
            spec = importlib.util.spec_from_file_location("independent_core_history", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            with self.changed(name, path.read_bytes() + b"\n# after import before admission\n"):
                with self.assertRaises(ValueError):
                    if member == "CapturedInputs":
                        module.CapturedInputs(self.root)
                    else:
                        module.prepare(self.root, {})

    def test_exact_history_keeps_actual_captures_and_rechecks_terminal(self):
        name = next(iter(history.CURRENT))
        actual = (self.root / name).read_bytes()
        projected, receipt = history.prepare(self.root, {name: actual})
        self.assertEqual(projected[name], self.actual.base[name])
        self.assertEqual(receipt["captures"][name], actual)
        other = "hepta/hia_core_integer_native.py"
        self.assertEqual(receipt["prior_take"](self.root / other),
                         (self.root / other).read_bytes())
        history.verify_unchanged(receipt)
        fixture = self.root / history.FIXTURE
        with self.changed(history.FIXTURE, fixture.read_bytes() + b" "):
            with self.assertRaises(ValueError):
                history.verify_unchanged(receipt)
        history.verify_unchanged(receipt)
        receipt["review"]["qualification_granted"] = 0
        with self.assertRaises(ValueError):
            history.verify_unchanged(receipt)

    def test_partial_reversion_and_unknown_current_composition_refuse(self):
        relation = json.loads((self.root / history.FIXTURE).read_bytes())
        for name in history.CURRENT:
            prior = base64.b64decode(relation["sources"][name]["prior"]["data_b64"])
            current = (self.root / name).read_bytes()
            for replacement in (prior, current + b"\n# unknown current\n"):
                with self.subTest(name=name), self.changed(name, replacement):
                    with self.assertRaises(ValueError):
                        history.prepare(self.root, {name: replacement})
        projected, receipt = history.prepare(self.root, {})
        self.assertEqual(projected, {})
        history.verify_unchanged(receipt)

    def test_historical_view_late_mutation_is_not_admitted(self):
        state = prep.CapturedInputs(self.root, materialize=True)
        path = state.historical_root / "hepta/hia_core_lowering_abi.json"
        raw = path.read_bytes()
        try:
            path.chmod(0o600)
            path.write_bytes(raw + b" ")
            with self.assertRaises(ValueError):
                state.verify_views()
            path.write_bytes(raw)
            path.chmod(0o400)
            state.verify_views()
        finally:
            state.temporary.cleanup()

    def test_warm_current_companion_source_and_selector_identity_are_bound(self):
        for family in prep.TESTS:
            selection = importlib.import_module("hepta.hia_core_" + family + "_selection")
            with (
                patch.object(selection, "_source_resource_path",
                             side_effect=lambda name: self.root / name),
                patch.object(selection, "__file__", str(self.root / selection.SELECTION_SOURCE)),
                patch.object(selection.primitive, "__file__", str(self.root / selection.BRIDGE_SOURCE)),
            ):
                initial = selection.current_inputs()
                for name in (selection.BRIDGE_SOURCE, selection.SELECTION_SOURCE):
                    with self.subTest(family=family, name=name):
                        with self.changed(name, (self.root / name).read_bytes() + b"\n# late\n"):
                            with self.assertRaises(ValueError):
                                selection.current_inputs()
                self.assertEqual(selection.current_inputs(), initial)


if __name__ == "__main__":
    unittest.main()
