"""Boundary tests start from compiler-produced ASTs of pinned real GSL code."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import hepta.cpp_gsl_final_action as migration_module

from hepta.cpp_gsl_final_action import (
    MigrationError, Translator, capture_and_lower, children, documents,
    translate_captured, walk,
)
from hepta.hia_program_source import lower_source
from hepta.pipeline import analyze

ROOT = Path(__file__).resolve().parents[1]


class RealGslMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clang = os.environ.get("HEPTA_CLANG") or shutil.which("clang-20")
        if not cls.clang:
            raise unittest.SkipTest("Real GSL capture requires Clang 20; set HEPTA_CLANG")
        cls.temporary = tempfile.TemporaryDirectory(prefix="hepta-real-gsl-")
        cls.output = Path(cls.temporary.name)
        cls.migration = capture_and_lower(ROOT, "4.0.0", cls.output / "capture", clang=cls.clang)
        cls.upstream = documents((cls.output / "capture/upstream.ast.json").read_text())
        cls.callback = documents((cls.output / "capture/callback.ast.json").read_text())
        cls.factory = documents((cls.output / "capture/factory.ast.json").read_text())

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temporary"):
            cls.temporary.cleanup()

    def test_actual_method_bodies_generate_checked_standalone_program(self):
        source = self.migration["source"]
        statistics = self.migration["report"]["statistics"]
        self.assertEqual(statistics["upstream_method_bodies_translated"], 3)
        self.assertEqual(statistics["authored_callback_bodies_translated"], 1)
        self.assertEqual(statistics["upstream_factory_instantiations_translated"], 3)
        self.assertEqual(self.migration["report"]["factory_categories"],
                         ["const_lvalue", "nonconst_lvalue", "rvalue"])
        self.assertTrue(analyze(source, native=False, backend="c").report["ok"])
        lower_source(source)
        self.assertIn("wrapping_mul(state.trace, 31)", source)
        self.assertNotIn('extern "C" fn', source)

    def test_move_that_keeps_source_active_is_rejected(self):
        upstream = copy.deepcopy(self.upstream)
        translator = Translator(upstream, self.callback)
        moves = [n for n in children(translator.owner) if n.get("kind") == "CXXConstructorDecl"
                 and any(c.get("kind") == "ParmVarDecl" and c.get("name") == "other"
                         for c in children(n))]
        self.assertEqual(len(moves), 1)
        false_nodes = [n for n in walk(moves[0]) if n.get("kind") == "CXXBoolLiteralExpr"
                       and n.get("value") is False]
        self.assertEqual(len(false_nodes), 1)
        false_nodes[0]["value"] = True
        with self.assertRaisesRegex(MigrationError, "inactive"):
            translate_captured(upstream, self.callback)

    def test_unconditional_destructor_is_rejected(self):
        upstream = copy.deepcopy(self.upstream)
        translator = Translator(upstream, self.callback)
        destructor = next(n for n in children(translator.owner) if n.get("kind") == "CXXDestructorDecl")
        body = next(n for n in children(destructor) if n.get("kind") == "CompoundStmt")
        body["inner"] = [children(children(body)[0])[1]]
        with self.assertRaisesRegex(MigrationError, "conditionally"):
            translate_captured(upstream, self.callback)

    def test_extra_destructor_side_effect_is_rejected(self):
        upstream = copy.deepcopy(self.upstream)
        translator = Translator(upstream, self.callback)
        destructor = next(n for n in children(translator.owner) if n.get("kind") == "CXXDestructorDecl")
        body = next(n for n in children(destructor) if n.get("kind") == "CompoundStmt")
        body["inner"].append(copy.deepcopy(children(body)[0]))
        with self.assertRaisesRegex(MigrationError, "side effect"):
            translate_captured(upstream, self.callback)

    def test_callback_unknown_operator_is_rejected(self):
        callback = copy.deepcopy(self.callback)
        multiplication = next(n for root in callback for n in walk(root)
                              if n.get("kind") == "BinaryOperator" and n.get("opcode") == "*")
        multiplication["opcode"] = "/"
        with self.assertRaisesRegex(MigrationError, "scalar operation"):
            translate_captured(self.upstream, callback)

    def test_factory_extra_statement_is_rejected(self):
        factory = copy.deepcopy(self.factory)
        function = next(n for root in factory for n in walk(root)
                        if n.get("kind") == "FunctionDecl" and n.get("isUsed"))
        body = next(n for n in children(function) if n.get("kind") == "CompoundStmt")
        body["inner"].append(copy.deepcopy(children(body)[0]))
        with self.assertRaisesRegex(MigrationError, "directly return"):
            translate_captured(self.upstream, self.callback, factory)

    def test_lvalue_factory_nontrivial_transfer_is_rejected(self):
        factory = copy.deepcopy(self.factory)
        copy_constructor = next(n for root in factory for n in walk(root)
                                if n.get("kind") == "CXXConstructExpr"
                                and n.get("ctorType", {}).get("qualType") == "void (const GslCallback &) noexcept")
        copy_constructor["ctorType"]["qualType"] = "void (const GslCallback &)"
        with self.assertRaisesRegex(MigrationError, "trivial callback move/copy"):
            translate_captured(self.upstream, self.callback, factory)

    def test_actual_const_factory_is_translated_on_both_upstream_releases(self):
        old = capture_and_lower(ROOT, "3.1.0", self.output / "old-const-factory", clang=self.clang)
        self.assertEqual(old["report"]["factory_categories"], ["const_lvalue", "rvalue"])
        self.assertEqual(old["report"]["statistics"]["upstream_factory_instantiations_translated"], 2)
        for migration, binding in ((old, "direct_const_copy"), (self.migration, "std_forward")):
            operations = [row for row in migration["report"]["lowered_operations"]
                          if row.get("category") == "const_lvalue"]
            self.assertEqual(len(operations), 1)
            self.assertEqual(operations[0]["parameter_binding"], binding)
            self.assertEqual(operations[0]["callback_transfer"], "trivial_copy")
            source = migration["component_source"] + (ROOT / "examples/cpp/gsl_final_action/factory_const_client.hepta").read_text()
            self.assertTrue(analyze(source, native=False, backend="c").report["ok"])
            lower_source(source)

    def test_const_factory_cannot_claim_a_different_template_reference(self):
        factory = copy.deepcopy(self.factory)
        function = next(n for root in factory for n in walk(root)
                        if n.get("kind") == "FunctionDecl" and n.get("isUsed")
                        and any(c.get("kind") == "ParmVarDecl"
                                and c.get("type", {}).get("qualType") == "const GslCallback &"
                                for c in children(n)))
        argument = next(n for n in children(function) if n.get("kind") == "TemplateArgument")
        argument["type"]["qualType"] = "volatile GslCallback &"
        with self.assertRaisesRegex(MigrationError, "template argument"):
            translate_captured(self.upstream, self.callback, factory)

    def test_const_factory_copy_must_use_its_actual_parameter(self):
        factory = copy.deepcopy(self.factory)
        function = next(n for root in factory for n in walk(root)
                        if n.get("kind") == "FunctionDecl" and n.get("isUsed")
                        and any(c.get("kind") == "ParmVarDecl"
                                and c.get("type", {}).get("qualType") == "const GslCallback &"
                                for c in children(n)))
        reference = next(n for n in walk(function) if n.get("kind") == "DeclRefExpr"
                         and n.get("referencedDecl", {}).get("kind") == "ParmVarDecl")
        reference["referencedDecl"]["id"] = "unrelated-parameter"
        with self.assertRaisesRegex(MigrationError, "captured parameter"):
            translate_captured(self.upstream, self.callback, factory)

    def test_source_pointer_rebinding_is_rejected(self):
        examples = self.output / "rebinding-source"
        shutil.copytree(ROOT / "examples/cpp/gsl_final_action", examples)
        source = examples / "callback.cpp"
        source.write_text(source.read_text().replace("state->calls = state->calls + 1ULL;", "state = nullptr;"))
        with self.assertRaisesRegex(MigrationError, "pointer or tag"):
            capture_and_lower(ROOT, "4.0.0", self.output / "rebinding", clang=self.clang, examples=examples)

    def test_unmodeled_translation_unit_global_is_rejected(self):
        examples = self.output / "global-source"
        shutil.copytree(ROOT / "examples/cpp/gsl_final_action", examples)
        source = examples / "callback.cpp"
        source.write_text(source.read_text() + "\nint unmodeled_global = 1;\n")
        with self.assertRaisesRegex(MigrationError, "translation-unit declaration"):
            capture_and_lower(ROOT, "4.0.0", self.output / "global", clang=self.clang, examples=examples)

    def test_client_cannot_replace_type_contract(self):
        examples = self.output / "contract-source"
        shutil.copytree(ROOT / "examples/cpp/gsl_final_action", examples)
        source = examples / "contract.cpp"
        source.write_text(source.read_text().replace("static_assert(CHAR_BIT == 8 && sizeof(unsigned long long) == 8);", ""))
        with self.assertRaisesRegex(MigrationError, "compiler-owned probe"):
            capture_and_lower(ROOT, "4.0.0", self.output / "contract", clang=self.clang, examples=examples)

    def test_dependency_change_between_captures_is_rejected(self):
        examples = self.output / "changing-dependency-source"
        shutil.copytree(ROOT / "examples/cpp/gsl_final_action", examples)
        original_run = migration_module._run
        changed = []

        def change_after_first_ast(argv, **kwargs):
            result = original_run(argv, **kwargs)
            if "-ast-dump-filter=gsl::final_action" in argv:
                header = examples / "callback.hpp"
                header.write_text(header.read_text() + "\n// Changed between actual captures.\n")
                changed.append(True)
            return result

        with patch.object(migration_module, "_run", side_effect=change_after_first_ast):
            with self.assertRaisesRegex(MigrationError, "Dependency changed between captures"):
                capture_and_lower(ROOT, "4.0.0", self.output / "changing-dependency", clang=self.clang, examples=examples)
        self.assertEqual(changed, [True])


if __name__ == "__main__":
    unittest.main()
