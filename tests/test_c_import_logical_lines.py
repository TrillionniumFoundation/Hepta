"""C11 logical lines must be formed before the subset comment inventory."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.c_backend import compile_c, emit_c
from hepta.c_import import import_header, preprocess_subset
from hepta.checker import check
from hepta.parser import parse


@unittest.skipUnless(shutil.which("gcc"), "Real GCC C11 probes required")
class LogicalHeaderLineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-logical-header-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.header = self.root / "api.h"

    def source(self, text):
        self.header.write_bytes(text.encode("utf-8"))
        return self.header

    def gcc_declarations(self, text):
        self.source(text)
        result = subprocess.run(["gcc", "-std=c11", "-Werror", "-E", "-P",
                                 "-x", "c", str(self.header)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def imported_names(self, text):
        result = import_header(self.source(text))
        return [function["name"] for function in result.manifest["functions"]]

    def assert_rejected(self, text, code):
        with self.assertRaises(HeptaError) as caught:
            import_header(self.source(text))
        self.assertEqual(caught.exception.diagnostic.code, code)

    def test_cr_comment_does_not_omit_following_prototype(self):
        text = "int before(void); // license\rint after(void);\r"
        self.assertEqual(self.gcc_declarations(text).split(),
                         "int before(void); int after(void);".split())
        self.assertEqual(self.imported_names(text), ["before", "after"])

    def test_cr_comment_does_not_omit_typedef_record_or_constant(self):
        text = ("// license\r#define COUNT 3\rtypedef int Count;\r"
                "typedef struct Item { Count values[COUNT]; } Item;\r"
                "Item echo(Item value);\r")
        result = import_header(self.source(text))
        self.assertEqual(result.manifest["typedefs"], {"Count": "i32"})
        self.assertEqual(result.manifest["constants"]["COUNT"]["value"], 3)
        self.assertEqual(result.manifest["layouts"]["Item"]["fields"]["values"]["size"], 12)
        self.assertEqual([x["name"] for x in result.manifest["functions"]], ["echo"])

    def test_cr_cannot_hide_unsupported_active_declarations(self):
        for declaration, code in [
            ("int variadic(int count, ...);", "E_C_IMPORT_SYNTAX"),
            ("#define APPLY(x) (x)", "E_C_IMPORT_MACRO"),
            ("#if 1\rint conditional(void);\r#endif", "E_C_IMPORT_PREPROCESSOR"),
            ("struct Bits { unsigned value: 3; };", "E_C_IMPORT_SYNTAX"),
        ]:
            with self.subTest(declaration=declaration):
                text = "int before(void); // comment\r" + declaration + "\r"
                self.gcc_declarations(text)
                self.assert_rejected(text, code)

    def test_line_endings_and_mixed_endings_preserve_inventory(self):
        for ends in [("\n",) * 3, ("\r",) * 3, ("\r\n",) * 3,
                     ("\n\r",) * 3, ("\r", "\n", "\r\n")]:
            with self.subTest(ends=ends):
                text = ("// license" + ends[0] + "int first(void); // middle"
                        + ends[1] + "int second(void);" + ends[2])
                self.assertEqual(self.gcc_declarations(text).split(),
                                 "int first(void); int second(void);".split())
                self.assertEqual(self.imported_names(text), ["first", "second"])

    def test_non_c_line_separators_cannot_invent_guarded_declarations(self):
        for separator in ("\v", "\f", "\x85", "\u2028", "\u2029", "\x1c", "\x1d", "\x1e"):
            with self.subTest(separator=separator):
                text = "#ifndef API_H\n#define API_H " + separator + "int getchar(void);\n#endif\n"
                self.assertEqual(self.gcc_declarations(text).strip(), "")
                self.assert_rejected(text, "E_C_IMPORT_MACRO")

    def test_horizontal_control_whitespace_does_not_split_integer_macro(self):
        text = "#define VALUE (1\v+\f2)\nint kept(void);\n"
        result = import_header(self.source(text))
        self.assertEqual(result.manifest["constants"]["VALUE"]["value"], 3)
        self.assertEqual([x["name"] for x in result.manifest["functions"]], ["kept"])

    def test_spliced_comment_cannot_mint_preincluded_stdio_function(self):
        for newline in ("\n", "\r", "\r\n"):
            with self.subTest(newline=newline):
                text = ("// disabled declaration \\" + newline + "int getchar(void);"
                        + newline + "int kept(void);" + newline)
                self.assertEqual(self.gcc_declarations(text).split(), "int kept(void);".split())
                self.assert_rejected(text, "E_C_IMPORT_PREPROCESSOR")

    def test_spliced_comment_delimiters_cannot_omit_active_prototypes(self):
        text = "// continued \\\n/*\nint lost(void);\n// */\nint kept(void);\n"
        self.assertEqual(self.gcc_declarations(text).split(),
                         "int lost(void); int kept(void);".split())
        self.assert_rejected(text, "E_C_IMPORT_PREPROCESSOR")

    def test_splicing_cannot_hide_unsupported_active_declarations(self):
        text = "// continued \\\n/*\nint variadic(int count, ...);\n// */\nint kept(void);\n"
        self.assertIn("variadic", self.gcc_declarations(text))
        self.assert_rejected(text, "E_C_IMPORT_PREPROCESSOR")

    def test_split_tokens_and_delimiters_are_explicitly_rejected(self):
        text = ("/\\\n* removed *\\\n/\ntype\\\ndef int Count;\n"
                "int na\\\nme(Count value); /\\\n/ ignored\n")
        self.assertEqual(self.gcc_declarations(text).split(),
                         "typedef int Count; int name(Count value);".split())
        self.assert_rejected(text, "E_C_IMPORT_PREPROCESSOR")

    def test_continued_integer_macro_is_explicitly_rejected(self):
        text = "#define VALUE (1 + \\\n2)\nint kept(void);\n"
        self.assert_rejected(text, "E_C_IMPORT_PREPROCESSOR")

    def test_trigraph_comment_continuations_are_explicitly_rejected(self):
        text = "// disabled ??/\nint getchar(void);\nint kept(void);\n"
        self.assertEqual(self.gcc_declarations(text).split(), "int kept(void);".split())
        self.assert_rejected(text, "E_C_IMPORT_PREPROCESSOR")

    def test_gcc_whitespace_continuations_cannot_bypass_rejection(self):
        for backslash in ("\\", "??/"):
            for whitespace in (" ", "\t", "\v", "\f", " \t\v\f"):
                with self.subTest(backslash=backslash, whitespace=whitespace):
                    text = ("// continued " + backslash + whitespace
                            + "\n/*\nint lost(void);\n// */\nint kept(void);\n")
                    self.assertEqual(self.gcc_declarations(text).split(),
                                     "int lost(void); int kept(void);".split())
                    self.assert_rejected(text, "E_C_IMPORT_PREPROCESSOR")

    def test_nul_continuations_cannot_mint_preincluded_stdio_function(self):
        for backslash in ("\\", "??/"):
            with self.subTest(backslash=backslash):
                text = "// disabled " + backslash + "\x00\nint getchar(void);\nint kept(void);\n"
                self.assertEqual(self.gcc_declarations(text).split(), "int kept(void);".split())
                self.assert_rejected(text, "E_C_IMPORT_SYNTAX")

    def test_nul_anywhere_refuses_before_any_native_probe(self):
        for text in ("\x00int kept(void);\n", "// ordinary\x00comment\nint kept(void);\n",
                     "/* block\x00comment */\nint kept(void);\n", "int kept(void);\x00"):
            with self.subTest(text=text):
                self.source(text)
                with patch("hepta.c_import._native_process") as probe:
                    with self.assertRaises(HeptaError) as caught:
                        import_header(self.header)
                self.assertEqual(caught.exception.diagnostic.code, "E_C_IMPORT_SYNTAX")
                probe.assert_not_called()

    def test_splicing_rejection_does_not_depend_on_resulting_tokens(self):
        # Phase two cannot retroactively create a phase-one backslash.
        text = "// comment ?\\\n?/\nint kept(void);\n"
        self.assertEqual(self.gcc_declarations(text).split(), "int kept(void);".split())
        self.assert_rejected(text, "E_C_IMPORT_PREPROCESSOR")

    def test_lf_cr_continuation_is_also_explicitly_rejected(self):
        text = "// comment \\\n\rint kept(void);\n"
        self.assertEqual(self.gcc_declarations(text).split(), "int kept(void);".split())
        self.assert_rejected(text, "E_C_IMPORT_PREPROCESSOR")

    def test_multiline_block_comments_keep_existing_directive_semantics(self):
        text = "#define VALUE (1 /* comment\nsecond line */ + 2)\nint kept(void);\n"
        result = import_header(self.source(text))
        self.assertEqual(result.manifest["constants"]["VALUE"]["value"], 3)
        self.assertEqual([x["name"] for x in result.manifest["functions"]], ["kept"])
        self.assertEqual(preprocess_subset(text)[1]["VALUE"], "(1   + 2)")

    def test_comment_backslashes_without_continuations_remain_supported(self):
        text = "// C:\\include\\api.h and ??/ followed by text\nint kept(void);\n"
        self.assertEqual(self.imported_names(text), ["kept"])

    def test_continuations_refuse_before_any_native_probe(self):
        self.source("// continued \\\nint getchar(void);\n")
        with patch("hepta.c_import._native_process") as probe:
            with self.assertRaises(HeptaError) as caught:
                import_header(self.header)
        self.assertEqual(caught.exception.diagnostic.code, "E_C_IMPORT_PREPROCESSOR")
        probe.assert_not_called()

    def test_public_cli_refusal_does_not_publish_partial_bindings(self):
        self.source("// continued \\\n/*\nint lost(void);\n// */\nint kept(void);\n")
        output = self.root / "rejected.hepta"
        run = subprocess.run([sys.executable, "-B", "-m", "hepta", "import-c",
                              str(self.header), "--output", str(output)],
                             capture_output=True, text=True, timeout=60)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("E_C_IMPORT_PREPROCESSOR", run.stdout + run.stderr)
        self.assertFalse(output.exists())
        self.assertFalse(output.with_suffix(".hepta.imports.json").exists())

    def test_original_header_bytes_remain_the_hashed_probe_input(self):
        results = []
        for newline in ("\n", "\r", "\r\n"):
            text = "// license" + newline + "int kept(void);" + newline
            result = import_header(self.source(text))
            self.assertEqual(self.header.read_bytes(), text.encode())
            self.assertEqual(result.manifest["header_sha256"], hashlib.sha256(text.encode()).hexdigest())
            results.append(result)
        self.assertEqual(len({r.source for r in results}), 1)
        self.assertEqual(len({r.manifest["header_sha256"] for r in results}), 3)

    def test_public_cli_preserves_complete_cr_header_inventory(self):
        self.source("// license\rint before(void);\rint after(void);\r")
        output = self.root / "api.hepta"
        run = subprocess.run([sys.executable, "-B", "-m", "hepta", "import-c",
                              str(self.header), "--output", str(output)],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
        report = json.loads(run.stdout)
        self.assertTrue(report["ok"])
        manifest = json.loads(output.with_suffix(".hepta.imports.json").read_text())
        self.assertEqual([x["name"] for x in manifest["functions"]], ["before", "after"])
        self.assertEqual(manifest["source_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())

    def test_imported_functions_link_and_execute_against_original_header(self):
        self.source("// license\rint lost(void);\rint kept(void); // tail\rint after(void);\r")
        imported = import_header(self.header, contracts={name: {"ffi", "unsafe"}
                                                       for name in ("lost", "kept", "after")})
        source = imported.source + """
        fn main() -> Unit effects { ffi, unsafe, panic } {
            unsafe { assert(lost() == 11); assert(kept() == 22); assert(after() == 33); }
        }
        """
        program = parse(source)
        checked = check(program)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        implementation = self.root / "api.c"
        implementation.write_text('#include "api.h"\nint lost(void) { return 11; }\n'
                                  'int kept(void) { return 22; }\nint after(void) { return 33; }\n')
        obj = self.root / "api.o"
        compile_result = subprocess.run(["gcc", "-std=c11", "-Werror", "-c",
                                         str(implementation), "-o", str(obj)],
                                        capture_output=True, text=True, timeout=30)
        self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
        report = compile_c(emit_c(program, checked), output=self.root / "consumer", link_args=[str(obj)])
        self.assertTrue(report["ok"], report["diagnostics"])
        run = subprocess.run([report["artifact"]], capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
