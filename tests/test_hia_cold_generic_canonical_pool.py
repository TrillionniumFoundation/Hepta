"""Physical restoration and refusal controls for the deduplicated generic corpus."""
from __future__ import annotations

import ast
import copy
import hashlib
import importlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from tools import restore_hia_cold_generic_corpus as h

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / h.MANIFEST).read_bytes())


class CanonicalGenericCorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hia-generic-canonical-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        self.root.mkdir()
        names = [h.SELF, h.MANIFEST, *MANIFEST["pools"], *MANIFEST["metadata"]]
        for name in names:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        self.output = self.base / "restored"

    def test_full_original_corpus_and_all_thirteen_pools_reconstruct_exactly(self):
        from tools.hia_cold_cases_generic_plan import source_pool
        report = h.restore(self.root, self.output)
        self.assertEqual(report["restored_files"], 1615)
        self.assertEqual(report["payload_files"], 1601)
        self.assertEqual(report["payload_bytes"], 25259234)
        self.assertFalse(report["product_executed"])
        self.assertFalse(report["cold_qualification_claimed"])
        for name, row in {**MANIFEST["metadata"], **MANIFEST["files"]}.items():
            p = self.output / name[len(h.PREFIX):]
            raw = p.read_bytes()
            self.assertEqual(len(raw), row["bytes"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row["sha256"])
            self.assertEqual(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(), row["git_blob"])
            self.assertEqual(p.stat().st_mode & 0o777, 0o644)
        for path, pin in MANIFEST["pools"].items():
            family = Path(path).stem
            index = source_pool(self.output, self.base / ("repacked-" + family), families=(family,))
            raw = Path(index["source"]).read_bytes()
            self.assertEqual(index["bytes"], pin["bytes"])
            self.assertEqual(index["sha256"], pin["sha256"])
            self.assertEqual(raw, (self.root / path).read_bytes())

    def test_missing_or_modified_authority_and_inputs_refuse_before_output(self):
        names = [h.SELF, h.MANIFEST, next(iter(MANIFEST["pools"])), next(iter(MANIFEST["metadata"]))]
        for name in names:
            p = self.root / name
            original = p.read_bytes()
            for mutation in ("missing", "changed"):
                with self.subTest(name=name, mutation=mutation):
                    if mutation == "missing":
                        p.unlink()
                    else:
                        p.write_bytes(original + b"x")
                    with self.assertRaises((ValueError, OSError)):
                        h.restore(self.root, self.output)
                    self.assertFalse(self.output.exists())
                    p.write_bytes(original)

    def test_linked_pool_is_rejected(self):
        name = next(iter(MANIFEST["pools"]))
        p = self.root / name
        raw = p.read_bytes()
        target = self.base / "external-pool"
        target.write_bytes(raw)
        p.unlink()
        p.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "linked"):
            h.restore(self.root, self.output)
        self.assertFalse(self.output.exists())

    def test_input_change_after_complete_restoration_is_rejected(self):
        name = next(iter(MANIFEST["pools"]))
        original_verify = h._verify
        calls = 0
        def late(root, captures):
            nonlocal calls
            original_verify(root, captures)
            calls += 1
            if calls == 1:
                p = root / name
                raw = p.read_bytes()
                p.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with patch.object(h, "_verify", late):
            with self.assertRaises(ValueError):
                h.restore(self.root, self.output)
        self.assertTrue(self.output.is_dir())
        self.assertEqual(calls, 1)

    def test_restored_output_change_before_completion_is_rejected(self):
        original_verify = h._verify
        changed = False
        def late(root, captures):
            nonlocal changed
            original_verify(root, captures)
            if not changed:
                changed = True
                name = next(iter(MANIFEST["files"]))
                p = self.output / name[len(h.PREFIX):]
                p.write_bytes(p.read_bytes() + b"x")
        with patch.object(h, "_verify", late):
            with self.assertRaises(ValueError):
                h.restore(self.root, self.output)
        self.assertTrue(changed)

    def test_existing_or_source_tree_output_is_never_overwritten(self):
        existing = self.base / "existing"
        existing.mkdir()
        marker = existing / "owned"
        marker.write_bytes(b"keep")
        with self.assertRaises(ValueError):
            h.restore(self.root, existing)
        self.assertEqual(marker.read_bytes(), b"keep")
        with self.assertRaises(ValueError):
            h.restore(self.root, self.root / "new")
        self.assertFalse((self.root / "new").exists())

    def test_author_import_has_no_source_writes_or_product_monkey_patches(self):
        from hepta import hia_agent_assembly, hia_program
        before_assembly = hia_agent_assembly.assemble_program
        before_execute = hia_program.execute_program
        before = {p.relative_to(ROOT).as_posix() for p in (ROOT / h.PREFIX).rglob("*")}
        for name in ("tools.generate_hia_cold_cases_generic", "tools.generate_hia_cold_cases_native"):
            module = importlib.import_module(name)
            self.assertIsNone(module.DATA)
        after = {p.relative_to(ROOT).as_posix() for p in (ROOT / h.PREFIX).rglob("*")}
        self.assertEqual(before, after)
        self.assertIs(before_assembly, hia_agent_assembly.assemble_program)
        self.assertIs(before_execute, hia_program.execute_program)

    def test_complete_original_author_assertions_and_loops_are_preserved(self):
        fixture = json.loads((ROOT / "tests/fixtures/hia_cold_generic_original_authors_v1.json").read_bytes())
        for name, record in fixture["authors"].items():
            old = record["old"].encode()
            current = (ROOT / name).read_bytes()
            self.assertEqual(hashlib.sha256(old).hexdigest(), record["old_sha256"])
            self.assertEqual(hashlib.sha256(current).hexdigest(), record["new_sha256"])
            previous = {x.name: x for x in ast.parse(old).body if isinstance(x, ast.FunctionDef)}
            changed = {x.name: x for x in ast.parse(current).body if isinstance(x, ast.FunctionDef)}
            self.assertEqual(previous.keys(), changed.keys())
            for function in previous:
                if function not in ("generate", "normalize"):
                    self.assertEqual(ast.dump(previous[function]), ast.dump(changed[function]))
            if "generate" in previous:
                a = next(x for x in previous["generate"].body if isinstance(x, ast.Try))
                b = copy.deepcopy(next(x for x in changed["generate"].body if isinstance(x, ast.Try)))
                self.assertEqual(len(a.finalbody), 1)
                self.assertEqual(len(b.finalbody), 3)
                b.finalbody = b.finalbody[-1:]
                self.assertEqual(ast.dump(a), ast.dump(b))
            else:
                a = previous["normalize"].body
                b = changed["normalize"].body
                a = a[next(i for i, x in enumerate(a) if isinstance(x, ast.For)):]
                b = b[next(i for i, x in enumerate(b) if isinstance(x, ast.For)):]
                self.assertEqual([ast.dump(x) for x in a], [ast.dump(x) for x in b])


if __name__ == "__main__":
    unittest.main()
