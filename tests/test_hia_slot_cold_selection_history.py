"""Immutable whole-file history controls for the original Slot15 migration."""
from __future__ import annotations

import ast
import base64
from collections import Counter
from hashlib import sha256
import gzip
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_slot_cold_selection_history as history

ROOT = Path(__file__).resolve().parents[1]

# Exact predecessor bytes were independently read from the original Git objects.
# The controls remain executable in a normal depth-one CI checkout.
PREDECESSORS_SHA256 = '938f6879bc908ec509df1d547865a9dea2e90ae2df47d77412e186f3db5baaea'
PREDECESSORS_BASE64 = (
    'H4sIAAAAAAAC/819WXfqyLLme/+Mer59rgRm19Zd6z6YQYAA2QwSQi+1jGQGIwS1ATP06v/eEZGZUqYGPFTV6ftQtW2MlFNkzPHF'
    '//ltsY5eD7/91//57fh6OB7+c7V++eMQ7Y5/7Pavv16O6118+CPYbfe7+DU+/rFYX46nX6//2l9/+6/fuuvu2qmsVsHW3XQ7dhR2'
    '3HO37b8H67r20naW861b7bbt97lXP/jeKOqa9mFeHS5nFeMUdqz3efsSwXcv4dQ8vEz9/axiai9T49Rt6+9+xz3444deIxrt/HH9'
    'PdhG8cu0tpo36jffq8OYpgafn+CzqO9ZUVAx9GBrRzRePLrOK5dbt22e/Iby7GTeNrTBxFnCnI+zaQRjRaewbb6FjYee217tg2t9'
    '++KttBDe2W1b+sv0soHPaD2Zea/m2+ESxtl026NoVolubO4RvDeMup1wH7aX8PdaxP5+oX1qbGk/9vO2e+1XbD2IrWgeD4/w7gPM'
    '9QxzuvbXdSts1DfzigtrqL3Dz/DOmu5vYZ4d9wrr3sJ64P3O0vdWZ39qazNvtIexbv3lDk6l2/NjmOe4vvAqvk7PuMYC5xa0jSu8'
    'D+YO722z/Q7O+22wNY7dNpxlZQVn0V2+TPXzvGppcK672aSr28v9Hub9HsTD5UsMa5B+n1cHYrwzzGM3b0draawhftbYJr9rPrzb'
    '30YHf7jrORvj2W08Gl2zvoL92nm6AWu7RJ7+c9+P6VwP4dbZ9cY1eDfu1eg2vZlhI6qPR45vTfHZRtgduXVn6BrdsWMuHO3y7JrG'
    's9Nyx0N3ZE202sS7Br3Gcr/xp7OlV9nf5pWHXYDrb5yX4dY8hFNn/7TcLbuNxyX7vFYFutFg3zTYY63XpmdOQJfHoDPY8WcO3bZ7'
    'Cqq0v7B39v5lojtB7EZ9oFPcP69yjF69geF2LN0fn2FfazCHmvY86R4a60ca7+P/4Lzal/dQN06z6YMxgrGDirPvNg5LS7+crOsG'
    '1/Y2b5s3oNXmvAJnB3QHe9UWtCzWNmzbh5ln3+ZTF2ja2LA51GlfgoqruR48T+9Zvc07g2RP6L+2D/dKW4Zt4x3+dprFLtDxaPHS'
    'jlZeFe/2aDGv1iO8m0RX13pCI2OnNnTd0QT2ZR1O4ewfv/jetrvxK+5Voiv2HtgbGAfmb++DSvQ+j4yvvZ9oobYIOlbkby97v7LS'
    '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'
    'u1xPT2tJMr3J6mc+PuLCA82YV7/Karp6jeDYn1KuxTGthzkvKRYDhkySf0dnZOX6U4i1Y68frHcFm09n+ePLuD/WhQ71lblS/xvS'
    'WcW7Y7YnbN6pzhSgLwr2JcmRp34+tUQPTPPXSednfXUyufmpTXhe8ufztoEHz3R86nv+Rfs+b9P/eXqJ1otratXv9q+/Xo7rXXz4'
    'I3iJotdfB8nClyxzvLE+dqOdnlnkqNnSu+2QomdgIV+Bo8WIoPSCiOApUvXhdVxfw99O3KpP0cDQ+lhjkLP2jpqc4FAgDVgmS4O6'
    '2XM06vNS6kQkda4VlWM1Vrk4ZQhLVLFEiJdotRpXtDCB8rB6OWKZLYkGht2+Mt1FBAJSmi3FUMuiw7whrNSkkmgH3Ooqz7+x/aBq'
    'inUzwS5uMB/0Rl5qoDXoAf3ubu5VVfXX9XE4fWBdx857vNlX2F+dIvjrZO8RARTRJ7EzDVge+g0z2qiKrBpSJZpfIRTEW+jViVti'
    'dLa/3MGJd4XXYIFRVNp75o1IvCqEctrmFTjn1GsicR7xDqRkQsxk1Tqp9Q90pROCM1bntl2GQMA6K/YkC5xubOJh+Jr3Jvl9Xh2I'
    '+ZBmB3S5ltZDHEbyGoloVsa7k74P6AAsXOl3FjWWvu+eKLMZpBxwbGYZp1UuuK/kVQCOq3IIkSnfIc9/74WhB5K3lDRr/SdDGxLd'
    'XBpBiuiMc7zWmOaKCADo6W8szwKdlHmmNvvGxhiPnRDRCwaepj+PTHcwYh4BjVWq1rjH/25Hqlh9D2mBlP0ZMnT4dx7Bv4u6COut'
    'Wef9s7OJOmOnVp+YxmTcIuue3jWr+JvBW/dqt/3V0wS0o7fVm71tnZ/aLX02ddd2c7R9mg6r9iSozLazqr+1VrPJ7AI0fxlU3GjQ'
    '7N7g381sOqj6Tfi34m6fGkFvolvWSIuehs5lAVruBM+m97X1n5TI+UZ0SyGE3Vs/Zki7IvNE7T4HGk7bwHtfkzPf8hlv5EFGzxRq'
    'yti97MY6hKhjcAR2xVuTaqS1ewj+p1ym0Ja0bpBiNpyRge8mxJ9X13hD/o1nCDS+Fx0GeLfgE2oHYK28eVUH0SUwc5Z5KP7RPRXW'
    'pohuU6cDzDhZ4F1/hXvkJRkuFInahtMLPAfvqdhX1Prhrv7jezoX2VyuwT3fGA1zsftcLYeoWvWPJPUpC4ftcZLVglbO+J/eU33F'
    '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'
    'QoGOLaoNs0jYK41iVMnfM8jWZA9hHNfSeEcP0eWQbO6iajqe9RchSjdHmcSx9n6jsKMuvRvzgJKOACxvCO7KMINYIRAD3DPbjxo7'
    'A5N1IGLjZNCuWXfF94B/h1V8nfmcCqpTCaUc5/Hd+Rhnvk9sfwrQXhl9uYggQXkWFIfETuZjnZ6xzkoF6Bs/04TWkyoBrI6rRD/w'
    'XxHLxMoTmPcK0aNf0+o5spXCNqG6ZvUvhqiYuU9/cQzVJ+QFCroD09tqsVcxtfw4OSRQ6lyB3SR5BUIal9m4I+wmB/pQYwq6p3Ot'
    's8462GmaKgiS2CzoqyO01QVqxFdRvBKkFM7vVB9cy2yMx2lXScWvoHQ4BB7OOmncrdintWZRzjoh5nXc6E6paxuPXBM2wgZ9T6+P'
    'tKjJfJ7oE328dJtnI33WDen3Zku/g1xe59WQKFdTfUOgN5kM9TGjfySVvJKPpVbkx1P5nj2nirlkfmbYc7Vl76YtB8r3GW+cVgkt'
    'rIpoZIF+0L1xBHtxwPXINJPyT/Mo3TU9zDx/KXleOke4G2o1NsaKQZ5hVvTDrrdN/edot/XWe0RXYe/P+bFcDTNByX7GDqdyBxTR'
    'AS7XKfX+mcjdsAvpsi1ibajXtaQ5wPc7lD9ySnM9JR8YIQWwCpP071RJLctSCc0HK8UiRPVF/bsUoSjQj+Qn8hi/wdyg/UzoLY2V'
    'vLd7rr9gTGQn/He9cdq9FuS36NQgEOLk59VKr8jgeZrMfid5SnFa2Ks40Se4HMI4C/koNOwI1d/q7xgXoG6RaZWclu1qzvbsGL3y'
    'bnwfoE0zu1m3TKdljN1GcDcO98G7Cm1D9EE66++81xiOXAsrUZ4nkb2YOObT2PFNRx/GRbI+g7QNevTjDitv+jwek+8GwWxptcJk'
    '+HHnY0VXq82/tr8h6SHEa4rHv2e/fwpVXdmH6PBBh46R6W5c+Kxus25W5D+x4O9jtBeZfOhKiO8qasnXxnKnY2dkTja2qbw753cl'
    '9DspNqOzmE2lRmi5qh4zWI6S/PJhiuzH7xucsY53GmPXr5TjbFWoA9JVif28UZz8jcUSha8puD7Ie/vWbWEXjNG7L+ijbW6oI0e8'
    'Efr+u+CDGD8L2z9hPg/M3zatYR422oioF6zh3m8Q6byg63CxDYu52h51srzKvo4exdBpbEMgoRXIU9YRL4l3Sgj11DWY549sL+/+'
    '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'
)



class SlotColdSelectionHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current = {name: (ROOT / name).read_bytes() for name in history.EXPECTED}
        packed = base64.b64decode(PREDECESSORS_BASE64, validate=True)
        if sha256(packed).hexdigest() != PREDECESSORS_SHA256:
            raise AssertionError("immutable independent predecessor corpus changed")
        value = json.loads(gzip.decompress(packed))
        if (set(value) != {"schema", "source_commit", "files"}
                or value["schema"] != "hepta.hia.slot-cold-control-predecessors.v1"
                or value["source_commit"] != history.PREDECESSOR
                or set(value["files"]) != set(history.EXPECTED)):
            raise AssertionError("independent predecessor corpus scope changed")
        cls.previous = {name: base64.b64decode(raw, validate=True)
                        for name, raw in value["files"].items()}
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

    def test_complete_successor_restores_independent_frozen_predecessors(self):
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

    def test_qualifier_binds_history_and_loading_to_the_same_physical_sources(self):
        from tools import qualify_hia_slot_operations_callers as caller
        from tools import run_hia_unittest_gate as unittest_gate
        from tools import hia_selfhost_contract, build_hia_slot_operations
        import sys

        required = {*history.EXPECTED, history.FIXTURE,
                    "tools/hia_cold_compiler.py", "tests/hia_slot_cold_selection_history.py",
                    "tests/test_hia_slot_cold_selection_history.py"}
        with tempfile.TemporaryDirectory(prefix="hia-slot-caller-source-boundary-") as folder:
            root = Path(folder).resolve()
            for name in required:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / name).read_bytes())
            reviewed = history.reviewed
            loader = unittest_gate.load_declared_suite
            for boundary in ("review", "load"):
                for name in (*history.EXPECTED, history.FIXTURE):
                    target = root / name
                    before = target.read_bytes()
                    reached = False
                    def checked_review(*args, **kwargs):
                        nonlocal reached
                        value = reviewed(*args, **kwargs)
                        if boundary == "review":
                            target.write_bytes(before + b"\n# changed after source-history capture\n")
                            reached = True
                        return value
                    def checked_load(*args, **kwargs):
                        nonlocal reached
                        value = loader(*args, **kwargs)
                        if boundary == "load":
                            target.write_bytes(before + b"\n# changed after real suite loading\n")
                            reached = True
                        return value
                    try:
                        with self.subTest(boundary=boundary, path=name), \
                                patch.object(caller, "ROOT", root), \
                                patch.object(hia_selfhost_contract, "file_digests", return_value={}), \
                                patch.object(build_hia_slot_operations, "INPUTS", tuple(history.EXPECTED)), \
                                patch.object(build_hia_slot_operations, "build") as build, \
                                patch.object(history, "reviewed", side_effect=checked_review), \
                                patch.object(unittest_gate, "load_declared_suite", side_effect=checked_load) as load, \
                                patch.object(sys, "argv", ["slot15-source-boundary",
                                    "--cold-report", str(root / "not-read.json"),
                                    "--evidence", str(root / "must-not-exist")]):
                            expected = "initial source pins" if boundary == "review" else "loading the original suite"
                            with self.assertRaisesRegex(ValueError, expected):
                                caller.main()
                            self.assertTrue(reached)
                            self.assertNotEqual(target.read_bytes(), before)
                            build.assert_not_called()
                            if boundary == "review":
                                load.assert_not_called()
                            else:
                                load.assert_called_once()
                            self.assertFalse((root / "must-not-exist").exists())
                    finally:
                        target.write_bytes(before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
