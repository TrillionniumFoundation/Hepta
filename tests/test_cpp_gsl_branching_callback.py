"""Source-level callback alternatives and unsupported side-effect boundaries."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.cpp_gsl_final_action import capture_and_lower, documents, translate_captured, walk, MigrationError
from hepta.hia_program_source import lower_source
from tools.qualify_migration_resource_profiles import callback_oracle

ROOT = Path(__file__).resolve().parents[1]
CLANG = os.environ.get("HEPTA_CLANG") or shutil.which("clang-20")


class CallbackModelTests(unittest.TestCase):
    def test_nested_cleanup_is_reverse_order_and_budget_failure_is_visible(self):
        self.assertEqual(callback_oracle(10, 4, 5, "budget_release"), (1, 3, 2005))


@unittest.skipUnless(CLANG, "Actual GSL instantiation requires Clang 20")
class GslBranchingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hepta-gsl-branches-")
        cls.root = Path(cls.temporary.name)
        cls.examples = cls.root / "source"
        shutil.copytree(ROOT / "examples/cpp/gsl_final_action", cls.examples)
        shutil.copyfile(ROOT / "examples/cpp/gsl_branching_callbacks/masked_release.cpp", cls.examples / "callback.cpp")
        cls.migration = capture_and_lower(ROOT, "4.0.0", cls.root / "capture", clang=CLANG, examples=cls.examples)
        cls.upstream = documents((cls.root / "capture/upstream.ast.json").read_text())
        cls.callback = documents((cls.root / "capture/callback.ast.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_nested_branch_source_lowers_to_independently_verified_core(self):
        lower_source(self.migration["source"])
        stats = self.migration["report"]["statistics"]
        self.assertEqual(stats["callback_branches_translated"], 2)
        self.assertEqual(stats["callback_const_locals_translated"], 2)

    def test_const_local_reference_is_declaration_bound(self):
        callback = copy.deepcopy(self.callback)
        reference = next(n for root in callback for n in walk(root) if n.get("kind") == "DeclRefExpr"
                         and n.get("referencedDecl", {}).get("name") == "parity")
        reference["referencedDecl"]["id"] = "unrelated-local"
        with self.assertRaisesRegex(MigrationError, "in-scope"):
            translate_captured(self.upstream, callback)

    def test_condition_with_hidden_initializer_is_not_accepted(self):
        callback = copy.deepcopy(self.callback)
        branch = next(n for root in callback for n in walk(root) if n.get("kind") == "IfStmt")
        branch["hasInit"] = True
        with self.assertRaisesRegex(MigrationError, "initializer"):
            translate_captured(self.upstream, callback)


if __name__ == "__main__":
    unittest.main()
