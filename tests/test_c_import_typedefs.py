"""C tag namespaces and typedef qualification must survive ABI import."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import emit_header
from hepta.c_import import import_header
from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse


@unittest.skipUnless(shutil.which("gcc"), "GCC required for native C import probes")
class TypedefABIImportTests(unittest.TestCase):
    def import_checked(self, header, signature):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "api.h"
            path.write_text(header)
            probe = header + '\n_Static_assert(__builtin_types_compatible_p(__typeof__(inspect), ' + signature + '), "C signature");\n'
            result = subprocess.run(["gcc", "-std=c11", "-Werror", "-fsyntax-only", "-xc", "-"],
                                    input=probe, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            imported = import_header(path)
            # Compile declarations together, without calling any possibly
            # mismatched foreign ABI. Record types have generated names, so
            # compare the scalar/pointer cases directly; layouts have their
            # existing native importer integration test.
            if "struct" not in signature:
                generated = emit_header(parse(imported.source))
                compatibility = subprocess.run(
                    ["gcc", "-std=c11", "-Werror", "-fsyntax-only", "-xc", "-"],
                    input=header + "\n" + generated, text=True, capture_output=True)
                self.assertEqual(compatibility.returncode, 0, compatibility.stderr)
            return imported

    def test_scalar_typedef_and_struct_tag_have_separate_namespaces(self):
        for declarations in [
            "typedef int Token; struct Token { double x; };",
            "struct Token { double x; }; typedef int Token;",
        ]:
            with self.subTest(declarations=declarations):
                result = self.import_checked(declarations + " Token inspect(Token value);", "int(int)")
                self.assertIn('fn inspect(arg0: i32) -> i32', result.source)

    def test_scalar_typedef_binding_links_to_real_c_function(self):
        header = "typedef int Token; struct Token { double x; }; Token inspect(Token value);"
        imported = self.import_checked(header, "int(int)")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native = root / "api.c"
            native.write_text(header + "\nToken inspect(Token value) { return value + 7; }\n")
            obj = root / "api.o"
            subprocess.run(["gcc", "-std=c11", "-Werror", "-c", str(native), "-o", str(obj)],
                           check=True, capture_output=True)
            program = parse(imported.source + """
                fn main() -> Unit effects { alloc, block, ffi, io, panic, spawn, unsafe, write } {
                    unsafe { assert(inspect(35) == 42); }
                }
            """)
            checked = check(program)
            self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
            report = compile_c(emit_c(program, checked), output=root / "consumer",
                               link_args=[str(obj)], sanitize=True)
            self.assertTrue(report["ok"], report["diagnostics"])
            self.assertEqual(subprocess.run([report["artifact"]], capture_output=True).returncode, 0)

    def test_tag_is_not_a_bare_type_name(self):
        # The header itself is invalid C, so it must not produce a binding.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "api.h"
            path.write_text("struct Tag { int x; }; Tag inspect(Tag value);")
            with self.assertRaises(HeptaError):
                import_header(path)

    def test_struct_tag_and_distinct_typedef_alias(self):
        result = self.import_checked(
            "typedef struct Tag { int x; } Alias; Alias inspect(struct Tag value);",
            "Alias(struct Tag)")
        self.assertIn('fn inspect(arg0: Alias) -> Alias', result.source)

    def test_typedef_qualification_at_each_pointer_layer(self):
        cases = [
            ("typedef const int Value;", "Value *", "const int *", "raw const i32"),
            ("typedef int const Value;", "Value *", "const int *", "raw const i32"),
            ("typedef const int Base; typedef Base Value;", "Value *", "const int *", "raw const i32"),
            ("typedef const int * Value;", "Value *", "const int **", "raw mut raw const i32"),
            ("typedef int * const Value;", "Value *", "int * const *", "raw const raw mut i32"),
            ("typedef int * Value;", "const Value *", "int * const *", "raw const raw mut i32"),
            ("typedef const int * Value;", "const Value *", "const int * const *", "raw const raw const i32"),
            ("typedef int Value;", "Value *", "int *", "raw mut i32"),
        ]
        for declaration, spelling, native, expected in cases:
            with self.subTest(declaration=declaration, spelling=spelling):
                result = self.import_checked(declaration + f" int inspect({spelling} value);", f"int({native})")
                self.assertEqual(str(parse(result.source).functions[0].params[0].type), expected)


if __name__ == "__main__":
    unittest.main()
