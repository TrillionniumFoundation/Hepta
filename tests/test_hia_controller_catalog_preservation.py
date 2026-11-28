"""Source-only custody controls for Controller stage catalog regeneration."""
from pathlib import Path
from hashlib import sha256
import ast
import json
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

from tools import generate_hia_native_controller_release as author
from tools.generate_hia_release_extension_catalog import generated_table
from tools.hia_native_release_dependencies import read_source_table

ROOT = Path(__file__).resolve().parents[1]
TABLE = "examples/hia_bootstrap/release_stage_sources.tsv"
FIXTURE = "tests/fixtures/hia_controller_catalog_author_original_v1.json"
ORIGINAL_SHA256 = "d30c5a2f129a8e5f4604ac8c1ec4087bad33bbb5bfe55e6efb6d8b51fab7dace"


def original_author():
    value = json.loads((ROOT / FIXTURE).read_bytes())
    raw = value["source"].encode("utf-8")
    if value["sha256"] != ORIGINAL_SHA256 or len(raw) != 18324 or sha256(raw).hexdigest() != ORIGINAL_SHA256:
        raise ValueError("original Controller author whole source differs")
    return raw


def subset(raw, maximum):
    rows = [row for row in raw.decode("ascii").splitlines()[1:]
            if int(row.split("\t")[1]) <= maximum]
    count = sum(row.startswith("output\t") for row in rows)
    return ("\n".join([f"stage\t{maximum}\t{count}", *rows]) + "\n").encode("ascii")


class ControllerCatalogPreservationTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / TABLE).read_bytes()
        self.rows = self.raw.decode("ascii").splitlines()
        self.group = [row for row in self.rows[1:] if row.split("\t")[1] == "11"]

    def test_complete_original_author_is_fixed_and_only_main_changes(self):
        original = ast.parse(original_author())
        actual = ast.parse((ROOT / "tools/generate_hia_native_controller_release.py").read_bytes())
        old = {n.name: ast.dump(n, include_attributes=False) for n in original.body
               if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name != "main"}
        new = {n.name: ast.dump(n, include_attributes=False) for n in actual.body
               if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in old}
        self.assertEqual(new, old)

    def test_real_current_catalog_is_exact_registered_native_dags(self):
        expected, record = generated_table(ROOT, source_table=self.raw)
        self.assertEqual(expected, self.raw)
        admitted = author._admit_controller_catalog(self.raw, ROOT)
        self.assertEqual(admitted["stages"], record["stages"])
        self.assertEqual(admitted["publications"], read_source_table(expected)["publications"])

    def test_old_numeric_guard_rejects_this_actual_current_catalog(self):
        tree = ast.parse(original_author())
        candidates = [n for n in ast.walk(tree) if isinstance(n, ast.Assert)
                      and "len(header)" in ast.unparse(n.test)
                      and "int(header[1])" in ast.unparse(n.test)]
        self.assertEqual(len(candidates), 1)
        guard = compile(ast.Expression(candidates[0].test), "<fixed-original-guard>", "eval")
        self.assertGreater(int(self.rows[0].split("\t")[1]), 16)
        self.assertFalse(eval(guard, {"header": self.rows[0].split("\t")}))

    def test_old_row_reassembly_moves_real_registered_extensions(self):
        # This is the exact old row-selection relation, isolated from its
        # already-refusing numeric guard; no old author PASS is claimed.
        old = [row for row in self.rows[1:] if int(row.split("\t")[1]) < 11]
        old += self.group
        old += [row for row in self.rows[1:] if int(row.split("\t")[1]) > 11]
        self.assertNotEqual(old, self.rows[1:])
        first_11 = next(i for i, row in enumerate(self.rows) if row.startswith("stage\t11\t"))
        self.assertTrue(any(row.startswith("stage\t15\t") for row in self.rows[:first_11]))

    def test_current_replacement_preserves_every_other_row_and_position(self):
        changed = list(self.group)
        where = next(i for i, row in enumerate(changed) if row.startswith("framing\t"))
        changed[where] += "-source-control"
        value = author._replace_controller_group(self.raw, changed)
        expected = list(self.rows)
        for i, row in enumerate(expected):
            if row == self.group[where]:
                expected[i] = changed[where]
        self.assertEqual(value, ("\n".join(expected) + "\n").encode("ascii"))
        self.assertEqual(author._replace_controller_group(self.raw, self.group), self.raw)

    def test_original_ten_stage_aggregate_appends_complete_eleven(self):
        before = subset(self.raw, 10)
        self.assertEqual(author._admit_controller_catalog(before, ROOT)["stages"], 10)
        value = author._replace_controller_group(before, self.group)
        self.assertEqual(read_source_table(value)["stages"], 11)
        self.assertEqual(value.decode("ascii").splitlines()[1:],
                         before.decode("ascii").splitlines()[1:] + self.group)

    def test_original_fourteen_stage_aggregate_preserves_whole_rows(self):
        before = subset(self.raw, 14)
        self.assertEqual(author._admit_controller_catalog(before, ROOT)["stages"], 14)
        self.assertEqual(author._replace_controller_group(before, self.group), before)

    def test_unknown_extension_is_rejected_before_any_author_or_product_write(self):
        rows = list(self.rows)
        stages, count = map(int, rows[0].split("\t")[1:])
        rows[0] = f"stage\t{stages + 1}\t{count + 1}"
        rows += [f"stage\t{stages + 1}\tnative-release-dag-unregistered",
                 f"output\t{stages + 1}\tunregistered-output"]
        bad = ("\n".join(rows) + "\n").encode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._copy_current_inputs(root)
            table = root / TABLE
            table.write_bytes(bad)
            with mock.patch.object(author, "ROOT", root), mock.patch.object(
                    author, "specifications", side_effect=AssertionError("author must not run")):
                with self.assertRaisesRegex(ValueError, "unrecognized stage"):
                    author.main()
            self.assertEqual(table.read_bytes(), bad)
            self.assertEqual({str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()},
                             set(paths))
            for name in paths:
                if name != TABLE:
                    self.assertEqual((root / name).read_bytes(), (ROOT / name).read_bytes())

    def test_declared_count_cannot_omit_registered_current_extension(self):
        maximum = int(self.rows[0].split("\t")[1])
        bad = subset(self.raw, maximum - 1)
        with self.assertRaisesRegex(ValueError, "registered current DAGs"):
            author._admit_controller_catalog(bad, ROOT)

    def test_unknown_marker_and_noncanonical_lines_are_refused(self):
        bad = self.raw.replace(b"native-release-dag-helper_extensions",
                               b"native-release-dag-foreign", 1)
        with self.assertRaisesRegex(ValueError, "unrecognized stage"):
            author._admit_controller_catalog(bad, ROOT)
        with self.assertRaisesRegex(ValueError, "canonical whole lines"):
            author._admit_controller_catalog(self.raw.replace(b"\n", b"\r\n"), ROOT)

    def test_split_controller_group_cannot_discard_or_move_another_stage(self):
        rows = list(self.rows)
        at = next(i for i, row in enumerate(rows) if row == self.group[1])
        rows.insert(at, rows.pop(next(i for i, row in enumerate(rows)
                                     if row.startswith("need\t10\t"))))
        bad = ("\n".join(rows) + "\n").encode("ascii")
        with self.assertRaisesRegex(ValueError, "contiguous"):
            author._replace_controller_group(bad, self.group)

    def test_late_table_change_is_rejected_before_product_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            table = root / TABLE
            table.parent.mkdir(parents=True)
            before = subset(self.raw, 10)
            table.write_bytes(before)
            original_replace = author._replace_controller_group
            def changed(raw, rows):
                result = original_replace(raw, rows)
                table.write_bytes(before + b"\n")
                return result
            recipe = SimpleNamespace(binary=lambda: b"source-only-test-recipe",
                                     published=["hia-source-contract"])
            document = {"functions": []}
            with mock.patch.object(author, "ROOT", root), \
                    mock.patch.object(author, "specifications", return_value=[]), \
                    mock.patch.object(author, "filter_policy", return_value="source-only"), \
                    mock.patch.object(author.filters, "source_program", return_value="source-only"), \
                    mock.patch.object(author, "delivery_source", return_value="source-only"), \
                    mock.patch.object(author, "document", return_value=document), \
                    mock.patch.object(author, "render_assembly", return_value="source-only"), \
                    mock.patch.object(author, "build_recipe", return_value=(recipe, [])), \
                    mock.patch.object(author, "_replace_controller_group", side_effect=changed):
                with self.assertRaisesRegex(ValueError, "changed during authoring"):
                    author.main()
            self.assertEqual({str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()},
                             {TABLE})


    def _copy_current_inputs(self, root):
        from tools.hia_native_release_dependencies import PROGRAMS, registered_dags
        paths = [TABLE, "tools/generate_hia_release_owner.py"]
        paths += [PROGRAMS + "release_stage_" + name + ".hiastd" for name in registered_dags(ROOT)]
        for name in paths:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        return paths

    def test_current_catalog_parsers_use_exact_captured_bytes(self):
        import tools.generate_hia_release_extension_catalog as catalog
        real = catalog.generated_table
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._copy_current_inputs(root)
            path = root / "examples/hia_bootstrap/release_stage_helper_extensions.hiastd"
            initial = path.read_bytes()
            def changed(view, **kwargs):
                self.assertNotEqual(Path(view), root)
                self.assertEqual((Path(view) / path.relative_to(root)).read_bytes(), initial)
                path.write_bytes(initial + b"\x00")
                return real(view, **kwargs)
            with mock.patch.object(catalog, "generated_table", side_effect=changed):
                with self.assertRaisesRegex(ValueError, "inputs changed during capture"):
                    author._admit_controller_catalog(self.raw, root)

    def test_late_native_graph_change_is_rejected_before_product_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = self._copy_current_inputs(root)
            path = root / "examples/hia_bootstrap/release_stage_helper_extensions.hiastd"
            initial = path.read_bytes()
            def changed():
                path.write_bytes(initial + b"\x00")
                return []
            names = [row.split("\t")[2] for row in self.group if row.startswith("output\t")]
            recipe = SimpleNamespace(binary=lambda: b"source-only-test-recipe", published=names)
            with mock.patch.object(author, "ROOT", root), \
                    mock.patch.object(author, "specifications", side_effect=changed), \
                    mock.patch.object(author, "filter_policy", return_value="source-only"), \
                    mock.patch.object(author.filters, "source_program", return_value="source-only"), \
                    mock.patch.object(author, "delivery_source", return_value="source-only"), \
                    mock.patch.object(author, "document", return_value={"functions": []}), \
                    mock.patch.object(author, "render_assembly", return_value="source-only"), \
                    mock.patch.object(author, "build_recipe", return_value=(recipe, [])):
                with self.assertRaisesRegex(ValueError, "inputs changed during authoring"):
                    author.main()
            self.assertEqual({str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()},
                             set(paths))
            for name in paths:
                if root / name != path:
                    self.assertEqual((root / name).read_bytes(), (ROOT / name).read_bytes())



if __name__ == "__main__":
    unittest.main()
