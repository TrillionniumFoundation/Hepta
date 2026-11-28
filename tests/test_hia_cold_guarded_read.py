"""Exact original controller bodies and read/trap fallback for guarded loads."""
import ast
import copy
from hashlib import sha256
from pathlib import Path
import unittest

from hepta.hia_agent_assembly import render_assembly
from tools.hia_cold_guarded_read import guarded_u64_read
from tools import generate_hia_cold_master as master
from tools import generate_hia_cold_build_entry as constructor
from tools import generate_hia_cold_source_bootstrap_entry as bootstrap

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = 'def uint(s:readbuf,at:u64,count:u64) -> u64:\n    value = 0\n    i = 0\n    while i < count:\n        value = value | (byte(s,at+i) << (i*8))\n        i = i+1\n    return value'
ORIGINAL_POLICY_AST = {'cold_master': 'c6ee6b890efd53f796729497c3d0bf36a47ada7935a78ad76df1bfcb970ab9ac', 'cold_build_entry': 'acd3d7ac09f03e65b77c69ba32023808cc2fbf1a7e26b5a027c5f258df5c2638', 'cold_source_bootstrap_entry': '9aa56c5c6e6bcbbce3e03de103b8221d59bec33f7f713c49494ede0b12e486b6'}


class GuardedControllerReadTests(unittest.TestCase):
    def test_only_guarded_uint_changes_in_all_three_complete_policy_bodies(self):
        for name, author in [("cold_master", master), ("cold_build_entry", constructor),
                             ("cold_source_bootstrap_entry", bootstrap)]:
            with self.subTest(policy=name):
                tree = ast.parse(author.source())
                node = next(n for n in tree.body if n.name == "uint")
                first, *fallback = node.body
                self.assertEqual(ast.dump(first.test),
                    ast.dump(ast.parse(
                        "count == 8 and at <= length(s) and 8 <= length(s) - at",
                        mode="eval").body))
                self.assertEqual([ast.unparse(n) for n in first.body],
                    ["return word_load(s, at)"])
                self.assertEqual([ast.dump(n) for n in fallback],
                    [ast.dump(n) for n in ast.parse(ORIGINAL).body[0].body])
                node.body = fallback
                self.assertEqual(sha256(ast.dump(tree).encode()).hexdigest(),
                    ORIGINAL_POLICY_AST[name])

    def test_changed_duplicate_absent_and_reapplied_helpers_refuse(self):
        changed = [
            ORIGINAL.replace("readbuf", "mutbuf"),
            ORIGINAL.replace("i*8", "i*7"),
            ORIGINAL.replace("def uint(", "def another("),
            ORIGINAL + "\n\n" + ORIGINAL,
            guarded_u64_read(ORIGINAL),
        ]
        for source in changed:
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    guarded_u64_read(source)

    def test_generated_native_policies_match_current_authors(self):
        for name, author, document in [
                ("cold_master", master, lambda text, ignored: master.document(text)),
                ("cold_build_entry", constructor, constructor.bulk_document),
                ("cold_source_bootstrap_entry", bootstrap, bootstrap.bulk_document)]:
            with self.subTest(policy=name):
                self.assertEqual(render_assembly(document(author.source(), name)).encode(),
                    (ROOT / "examples/hia_bootstrap" / (name + ".hepta")).read_bytes())


if __name__ == "__main__":
    unittest.main()
