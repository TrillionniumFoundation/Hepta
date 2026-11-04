"""Pinned GSL 5.0.1 constructors and factories, from real Clang ASTs."""
import copy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from hepta.cpp_gsl_final_action import (capture_and_lower, documents, children, walk, qual,
                                       Translator, MigrationError, translate_captured,
                                       REFERENCE_CTOR_PROFILE)
from hepta.hia_program_source import lower_source
from hepta.pipeline import analyze

ROOT = Path(__file__).resolve().parents[1]


class CurrentGslReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clang = os.environ.get("HEPTA_CLANG") or shutil.which("clang-20")
        if not cls.clang:
            raise unittest.SkipTest("Real GSL capture requires Clang 20; set HEPTA_CLANG")
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-gsl-5-")
        output = Path(cls.temporary.name)
        cls.migration = capture_and_lower(ROOT, "5.0.1", output, clang=cls.clang)
        cls.upstream = documents((output / "upstream.ast.json").read_text())
        cls.callback = documents((output / "callback.ast.json").read_text())
        cls.factory = documents((output / "factory.ast.json").read_text())

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    def test_actual_latest_upstream_has_complete_four_body_translation(self):
        report = self.migration["report"]
        self.assertEqual(report["upstream"]["commit"], "fbd20b8e8c52cba04dbc869cc9068a7800a5665d")
        self.assertEqual(report["profile"], REFERENCE_CTOR_PROFILE)
        self.assertEqual(report["statistics"]["upstream_method_bodies_translated"], 4)
        self.assertEqual(report["statistics"]["upstream_factory_instantiations_translated"], 3)
        self.assertEqual(report["factory_categories"], ["const_lvalue", "nonconst_lvalue", "rvalue"])
        transfers = {r["callback"] for r in report["lowered_operations"] if r["operation"] == "construct"}
        self.assertEqual(transfers, {"trivial_move_from_rvalue", "trivial_copy_from_const_lvalue"})
        self.assertTrue(analyze(self.migration["source"], backend="c", native=False).report["ok"])
        lower_source(self.migration["source"])

    def test_copy_constructor_must_use_actual_parameter(self):
        upstream = copy.deepcopy(self.upstream)
        owner = Translator(upstream, self.callback).owner
        method = next(n for n in children(owner) if n.get("kind") == "CXXConstructorDecl"
                      and qual(n) == "void (const GslCallback &) noexcept")
        use = next(n for n in walk(method) if n.get("kind") == "DeclRefExpr")
        use["referencedDecl"]["id"] = "wrong-captured-parameter"
        with self.assertRaisesRegex(MigrationError, "actual captured callback"):
            translate_captured(upstream, self.callback, self.factory)

    def test_renamed_member_must_still_match_actual_declaration(self):
        upstream = copy.deepcopy(self.upstream)
        owner = Translator(upstream, self.callback).owner
        member = next(n for n in walk(owner)
                      if n.get("kind") == "MemberExpr" and n.get("name") == "invoke"
                      and n.get("referencedMemberDecl"))
        member["referencedMemberDecl"] = "same-name-but-different-owner-field"
        with self.assertRaisesRegex(MigrationError, "captured declaration"):
            translate_captured(upstream, self.callback, self.factory)

    def test_moved_from_owner_cannot_stay_active(self):
        upstream = copy.deepcopy(self.upstream)
        owner = Translator(upstream, self.callback).owner
        method = next(n for n in children(owner) if n.get("kind") == "CXXConstructorDecl"
                      and any(c.get("name") == "other" for c in children(n)))
        reset = next(n for n in walk(method) if n.get("kind") == "CXXBoolLiteralExpr"
                     and n.get("value") is False)
        reset["value"] = True
        with self.assertRaisesRegex(MigrationError, "inactive"):
            translate_captured(upstream, self.callback, self.factory)

    def test_factory_cannot_route_rvalue_to_unmatched_constructor(self):
        factory = copy.deepcopy(self.factory)
        owner = next(n for r in factory for n in walk(r)
                     if n.get("kind") == "CXXTemporaryObjectExpr"
                     and n.get("ctorType", {}).get("qualType") == "void (GslCallback &&) noexcept")
        owner["ctorType"]["qualType"] = "void (GslCallback) noexcept"
        with self.assertRaisesRegex(MigrationError, "constructor contract"):
            translate_captured(self.upstream, self.callback, factory)


if __name__ == "__main__":
    unittest.main()
