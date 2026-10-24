"""Inventory the active Clang TU without banning legitimate typedef headers."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_migrate import migrate_c


class ActiveTranslationUnitTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(shutil.which("clang"), "Real Clang is required")
        self.work = tempfile.TemporaryDirectory(prefix="hepta-active-tu-")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.src = self.root / "input.c"
        self.out = self.root / "output.hepta"

    def convert(self, source, headers=None):
        for name, content in (headers or {}).items():
            (self.root / name).write_text(content, encoding="utf-8")
        self.src.write_text(source, encoding="utf-8")
        return migrate_c(self.src, self.out)

    def rejected(self, source, code="E_C_TOPLEVEL", headers=None):
        result = self.convert(source, headers)
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["converted"], [], result)
        self.assertIn(code, [d["code"] for d in result["rejected"]], result)
        self.assertFalse(self.out.exists())
        self.assertEqual(list(self.root.glob(".hepta-migrate-*")), [])

    def accepted(self, source, headers=None):
        result = self.convert(source, headers)
        self.assertTrue(result["ok"], result)
        self.assertEqual([d["name"] for d in result["converted"]], ["pure"])
        self.assertTrue(self.out.is_file())
        return result

    def test_macro_global_after_function_cannot_disappear(self):
        self.rejected("int pure(int x){return x;}\n#define G int hidden=7;\nG\n", code="E_C_MACRO")

    def test_first_macro_global_cannot_disappear(self):
        self.rejected("#define G int hidden=7;\nG\nint pure(int x){return x;}\n", code="E_C_MACRO")

    def test_nested_macro_global_cannot_disappear(self):
        self.rejected("int pure(int x){return x;}\n#define G(n) int n=7;\n#define OUTER G(hidden)\nOUTER\n", code="E_C_MACRO")

    def test_header_global_before_function_cannot_disappear(self):
        self.rejected('#include "state.h"\nint pure(int x){return x;}\n',
                      headers={"state.h": "int hidden=7;\n"})

    def test_header_global_after_function_cannot_disappear(self):
        self.rejected('int pure(int x){return x;}\n#include "state.h"\n',
                      headers={"state.h": "int hidden=7;\n"})

    def test_nested_header_global_cannot_disappear(self):
        self.rejected('#include "outer.h"\nint pure(int x){return x;}\n',
                      headers={"outer.h": '#include "inner.h"\n',
                               "inner.h": "int hidden=7;\n"})

    def test_macro_defined_in_header_and_expanded_in_main_is_rejected(self):
        self.rejected('#include "types.h"\nint pure(int x){return x;}\nG\n',
                      headers={"types.h": "#define G int hidden=7;\n"}, code="E_C_MACRO")

    def test_header_prototype_is_not_silently_omitted(self):
        self.rejected('#include "api.h"\nint pure(int x){return x;}\n',
                      headers={"api.h": "int external(int);\n"})

    def test_header_function_body_is_not_silently_omitted(self):
        self.rejected('#include "api.h"\nint pure(int x){return x;}\n',
                      headers={"api.h": "int hidden(int x){return x;}\n"})

    def test_macro_function_definition_is_rejected_not_omitted(self):
        self.rejected("int pure(int x){return x;}\n#define FN int hidden(int x){return x;}\nFN\n",
                      code="E_C_MACRO")

    def test_active_macro_expression_has_explicit_unsupported_diagnostic(self):
        self.rejected("#define INC(x) ((x)+1)\nint pure(int x){return INC(x);}\n",
                      code="E_C_MACRO")

    def test_main_macro_typedef_does_not_masquerade_as_header_context(self):
        self.rejected('#include "types.h"\nTYPE\nint pure(int x){return x;}\n',
                      headers={"types.h": "#define TYPE typedef int Number;\n"}, code="E_C_MACRO")

    def test_inactive_main_global_and_unused_macro_remain_allowed(self):
        self.accepted("#define UNUSED int hidden=7;\n#if 0\nUNUSED\n#endif\nint pure(int x){return x;}\n")

    def test_inactive_header_global_and_guarded_typedef_remain_allowed(self):
        result = self.accepted('#include "types.h"\nuint32_t pure(uint32_t x){return x;}\n',
            headers={"types.h": "#ifndef TYPES_H\n#define TYPES_H\n#if 0\nint hidden=7;\n#endif\ntypedef signed int uint32_t;\n#endif\n"})
        self.assertEqual(result["converted"][0]["params"], {"x": "i32"})

    def test_transitive_typedef_headers_preserve_canonical_type(self):
        result = self.accepted('#include "outer.h"\nuint32_t pure(uint32_t x){return x;}\n',
            headers={"outer.h": '#include "inner.h"\ntypedef Base uint32_t;\n',
                     "inner.h": "typedef signed int Base;\n"})
        self.assertEqual(result["converted"][0]["returns"], "i32")

    def test_standard_integer_header_still_works(self):
        self.accepted("#include <stdint.h>\nint32_t pure(int32_t x){return x;}\n")

    def test_line_directive_cannot_hide_active_main_global(self):
        self.rejected('#line 1 "pretend-header.h"\nint hidden=7;\nint pure(int x){return x;}\n')

    def test_include_with_no_active_declarations_remains_allowed(self):
        self.accepted('#include "empty.h"\nint pure(int x){return x;}\n',
            headers={"empty.h": "#ifndef EMPTY_H\n#define EMPTY_H\n#endif\n"})

    def test_included_function_body_requires_explicit_provenance(self):
        self.rejected('int pure(int x)\n#include "body.h"\n', code="E_C_LOCATION",
                      headers={"body.h": "{return x;}\n"})

    def test_included_statement_requires_explicit_provenance(self):
        self.rejected('int pure(int x){\n#include "body.h"\n}\n', code="E_C_LOCATION",
                      headers={"body.h": "return x;\n"})

    def test_header_macro_in_function_has_explicit_rejection(self):
        self.rejected('#include "macro.h"\nint pure(int x){return INC(x);}\n',
                      code="E_C_MACRO", headers={"macro.h": "#define INC(x) ((x)+1)\n"})

    def test_utf8_comments_use_clang_byte_offsets_not_character_counts(self):
        result = self.accepted("/* 雪とé */\nint pure(int x){ /* 雪 */ return x; }\n")
        self.assertFalse(result["preprocessing_inputs_frozen"])

    def test_linemarker_cannot_exempt_a_physical_main_file_typedef(self):
        self.rejected('# 1 "pretend.h" 1\ntypedef int Number;\n'
                      '# 1 "input.c" 2\nint pure(int x){return x;}\n')

    def test_nested_location_file_elision_cannot_exempt_main_typedef(self):
        result = self.convert('#include "start.h"\nint x;\n};\n'
                              '# 1 "pretend.h" 1\ntypedef int Hidden;\n'
                              '# 1 "input.c" 2\nint pure(int x){return x;}\n',
                              {"start.h": "struct X {\n"})
        self.assertFalse(result["ok"], result)
        self.assertEqual(result["converted"], [])
        self.assertFalse(self.out.exists())
        self.assertIn("Hidden", result["rejected"][0]["message"])
        self.assertEqual(result["rejected"][0]["code"], "E_C_TOPLEVEL")

    def test_real_header_type_keeps_physical_identity_despite_line_directive(self):
        result = self.accepted('#include "types.h"\nuint32_t pure(uint32_t x){return x;}\n',
            headers={"types.h": '#line 1 "input.c"\ntypedef signed int uint32_t;\n'})
        self.assertEqual(result["converted"][0]["params"], {"x": "i32"})

    def test_ast_lowered_operator_tokens_match_defined_native_inputs(self):
        # Clang JSON need not expose origins of operator/punctuation tokens.
        # Historical #20 accepted all three and demonstrated these finite C
        # semantics. The composed policy now rejects the active OP macro while
        # retaining its exact fixture and original-C oracle, not a miscompile
        # claim. Include-only operator/punctuation positives remain unchanged.
        from hepta.c_backend import emit_c
        from hepta.checker import check
        from hepta.parser import parse
        self.assertIsNotNone(shutil.which("gcc"))
        sources = [
            ("#define OP +\nint pure(int x,int y){return x OP y;}\n", {}),
            ('int pure(int x,int y){return x\n#include "op.h"\ny;}\n', {"op.h": "+\n"}),
            ('int pure(int x,int y){return x+y\n#include "semi.h"\n}\n', {"semi.h": ";\n"}),
        ]
        pairs = [(-7, 3), (0, 0), (20, 3), (100, -40), (2147483640, 7), (-2147483640, -7)]
        checks = "".join(f"if(pure({x},{y})!={x+y}) return 1;" for x, y in pairs)
        driver = "\nint main(void){" + checks + "return 0;}\n"
        for source, headers in sources:
            with self.subTest(source=source):
                self.out.unlink(missing_ok=True)
                if source.startswith("#define OP"):
                    self.rejected(source, code="E_C_MACRO", headers=headers)
                    # Preserve the historical defined-input original C oracle.
                    unit = self.root / "original-macro.c"
                    binary = self.root / "original-macro"
                    unit.write_text(source + driver)
                    build = subprocess.run(["gcc", "-std=c11", "-O2", str(unit), "-o", str(binary)],
                                           capture_output=True, text=True, timeout=30)
                    self.assertEqual(build.returncode, 0, build.stderr)
                    self.assertEqual(subprocess.run([str(binary)], timeout=10).returncode, 0)
                    continue
                result = self.accepted(source, headers)
                self.assertFalse(result["preprocessing_inputs_frozen"])
                self.assertFalse(result["source_equivalence_proved"])
                program = parse(self.out.read_text())
                generated = emit_c(program, check(program), crate_type="obj")
                for label, code, expected in [
                        ("original", source, 0), ("generated", generated, 0),
                        ("wrong-result", "int pure(int x,int y){return x-y;}", 1)]:
                    unit = self.root / (label + ".c")
                    binary = self.root / label
                    unit.write_text(code + driver)
                    build = subprocess.run(["gcc", "-std=c11", "-O2", str(unit), "-o", str(binary)],
                                           capture_output=True, text=True, timeout=30)
                    self.assertEqual(build.returncode, 0, build.stderr)
                    self.assertEqual(subprocess.run([str(binary)], timeout=10).returncode, expected)


class ActiveTranslationUnitShapeTests(unittest.TestCase):
    def test_missing_explicit_function_location_fails_closed(self):
        # Deliberately synthetic malformed AST; this is not a native result.
        from hepta.c_migrate import MigrationRejected, _active_declarations
        root = {"inner": [{"kind": "FunctionDecl", "name": "pure", "loc": {},
                          "range": {"begin": {"offset": 0}, "end": {"offset": 9}},
                          "inner": [{"kind": "CompoundStmt"}]}]}
        with self.assertRaises(MigrationRejected) as caught:
            _active_declarations(root, Path("/input.c"), 10)
        self.assertEqual(caught.exception.code, "E_C_LOCATION")


if __name__ == "__main__":
    unittest.main()
