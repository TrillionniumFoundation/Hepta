"""Whole original controller bodies and ordered native word-store guards."""
import ast
from hashlib import sha256
from pathlib import Path
import unittest

from hepta.hia_agent_assembly import render_assembly
from tools import generate_hia_cold_master as master
from tools import generate_hia_cold_build_entry as constructor
from tools import generate_hia_cold_source_bootstrap_entry as bootstrap
from tools.generate_hia_cold_document import bulk_document as original_bulk_document
from tools.hia_cold_guarded_write import guarded_controller_stores

ROOT = Path(__file__).resolve().parents[1]
ROLES = (
    ("cold_master", master),
    ("cold_build_entry", constructor),
    ("cold_source_bootstrap_entry", bootstrap),
)
PACKERS = {
    "cold_master": "4d9bb7d277979cd7fe9e2aa73ab9942486b461432b1abcfcc43695deb65f9455",
    "cold_build_entry": "13fbecda8df44d6baa0524e7cf200ad9d3da9c481f48cbc86c6e26834d428326",
    "cold_source_bootstrap_entry": "9f81a2b07e0aa89c9725e70eb967c7171ab26ea6e9e4d64a7882b321ec77b2a1",
}


class GuardedControllerWriteTests(unittest.TestCase):
    def test_original_fallbacks_and_every_other_function_remain_complete(self):
        for name, author in ROLES:
            with self.subTest(policy=name):
                original = ast.parse(author.source())
                updated = ast.parse(guarded_controller_stores(author.source()))
                self.assertEqual([n.name for n in updated.body],
                                 [n.name for n in original.body])
                for before, after in zip(original.body, updated.body):
                    if before.name in ("put", "call"):
                        self.assertIsInstance(after.body[0], ast.If)
                        self.assertFalse(after.body[0].orelse)
                        self.assertEqual([ast.dump(n) for n in after.body[1:]],
                                         [ast.dump(n) for n in before.body])
                        after.body = after.body[1:]
                    self.assertEqual(ast.dump(after), ast.dump(before))
                self.assertEqual(ast.dump(updated), ast.dump(original))

    def test_complete_bounds_and_all_nine_alias_sensitive_stores_keep_order(self):
        for name, author in ROLES:
            with self.subTest(policy=name):
                nodes = {n.name: n for n in
                         ast.parse(guarded_controller_stores(author.source())).body}
                put = nodes["put"].body[0]
                self.assertEqual(ast.dump(put.test), ast.dump(ast.parse(
                    "at <= length(w) and 8 <= length(w) - at", mode="eval").body))
                self.assertEqual([ast.unparse(n) for n in put.body],
                                 ["word_store(w, at, value)", "return 0"])
                call = nodes["call"].body[0]
                self.assertEqual(ast.dump(call.test), ast.dump(ast.parse(
                    "length(w) >= 8 and length(o) >= 64", mode="eval").body))
                self.assertEqual([ast.unparse(n) for n in call.body], [
                    "word_store(w, 0, phase)", "word_store(o, 0, number)",
                    "word_store(o, 8, a)", "word_store(o, 16, b)",
                    "word_store(o, 24, c)", "word_store(o, 32, d)",
                    "word_store(o, 40, e)", "word_store(o, 48, f)",
                    "word_store(o, 56, mask)", "return 1"])

    def test_changed_missing_duplicate_and_reapplied_helpers_are_refused(self):
        source = master.source()
        parts = {n.name: ast.get_source_segment(source, n) for n in ast.parse(source).body}
        cases = [
            source.replace(parts["put"], parts["put"].replace("i * 8", "i * 7")),
            source.replace(parts["put"], ""),
            source.replace(parts["call"], ""),
            source + "\n" + parts["put"],
            source + "\n" + parts["call"],
            source.replace(parts["call"], parts["call"].replace("put(o, 8, a)", "put(o, 8, b)")),
            guarded_controller_stores(source),
        ]
        for index, changed in enumerate(cases):
            with self.subTest(case=index):
                self.assertNotEqual(changed, source)
                with self.assertRaises(ValueError):
                    guarded_controller_stores(changed)

    def test_native_policies_preserve_other_emitted_functions_and_exact_packers(self):
        for name, author in ROLES:
            with self.subTest(policy=name):
                source = author.source()
                nodes = ast.parse(source).body
                selected = {"f" + str(i) for i, n in enumerate(nodes)
                            if n.name in ("put", "call")}
                if name == "cold_master":
                    before = master.packer_document(source)
                    after = master.document(source)
                else:
                    before = original_bulk_document(source, name)
                    after = author.bulk_document(source, name)
                self.assertEqual(len(after["functions"]), len(before["functions"]))
                for old, new in zip(before["functions"], after["functions"]):
                    if old["name"] not in selected:
                        self.assertEqual(new, old)
                raw = render_assembly(after).encode()
                self.assertEqual(raw, (ROOT / "examples/hia_bootstrap" /
                                       (name + ".hepta")).read_bytes())
                self.assertIn(b"buffer.store.u64.le", raw)
                self.assertNotIn(b"int.div", raw)
                self.assertNotIn(b"int.rem", raw)
                packer = (ROOT / "examples/hia_bootstrap" /
                          (name + "_packer.hepta")).read_bytes()
                self.assertEqual(sha256(packer).hexdigest(), PACKERS[name])


if __name__ == "__main__":
    unittest.main()
