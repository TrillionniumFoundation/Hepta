"""C ABI shape checking follows complete-layout edges, not traversal history."""
from itertools import permutations, product
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import Type
from hepta.backend import compile_rust, emit_header, emit_rust
from hepta.checker import _Checker, check
from hepta.parser import parse
from hepta.pipeline import analyze

RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")
ROOT = Path(__file__).resolve().parents[1]

MIXED = '''
repr(C) struct Parent { child: raw const Child, value: i32 }
repr(C) struct Child { parent: Parent, marker: i32 }
export "C" fn echo_parent(value: Parent) -> Parent effects {} { return value; }
export "C" fn echo_child(value: Child) -> Child effects {} { return value; }
'''


def predicate(source, name="A", position="field"):
    program = parse(source)
    checker = _Checker(program)
    checker.structs = {s.name: s for s in program.structs}
    return checker.c_type(Type(name), position=position)


class ABITypeGraphTests(unittest.TestCase):
    def accept(self, source):
        result = check(parse(source))
        self.assertTrue(result.ok, [d.to_dict() for d in result.diagnostics])
        return result

    def reject(self, source, code="E_C_ABI"):
        result = check(parse(source))
        self.assertFalse(result.ok)
        self.assertIn(code, [d.code for d in result.diagnostics])

    def test_pointer_broken_value_cycle_is_valid_in_both_orders(self):
        rows = ["repr(C) struct A { b: raw const B }", "repr(C) struct B { a: A }"]
        for order in permutations(rows):
            with self.subTest(order=order):
                self.accept(" ".join(order))
                self.assertTrue(predicate(" ".join(order)))

    def test_each_pointer_break_in_three_record_cycles_is_valid(self):
        for modes in product(("", "raw const ", "raw mut "), repeat=3):
            if not any(modes):
                continue
            rows = [f"repr(C) struct {a} {{ next: {mode}{b} }}"
                    for a, b, mode in zip("ABC", "BCA", modes)]
            for order in (rows, list(reversed(rows))):
                with self.subTest(modes=modes, reverse=order != rows):
                    self.accept(" ".join(order))

    def test_fixed_arrays_preserve_value_edges_after_pointer_break(self):
        self.accept("repr(C) struct A { b:raw mut B } repr(C) struct B { values:[A;2] }")
        self.accept("repr(C) struct A { b:raw const B } repr(C) struct B { c:C } "
                    "repr(C) struct C { values:[A;2] }")

    def test_actual_value_cycles_remain_rejected_by_both_checks(self):
        for source in (
            "repr(C) struct A { value:A }",
            "repr(C) struct A { b:B } repr(C) struct B { a:A }",
            "repr(C) struct A { b:[B;2] } repr(C) struct B { a:A }",
        ):
            with self.subTest(source=source):
                self.assertFalse(predicate(source))
                self.reject(source)
                self.reject(source, "E_RECURSIVE_LAYOUT")

    def test_pointer_cannot_hide_a_separate_invalid_value_cycle(self):
        source = "repr(C) struct A { b:raw const B } repr(C) struct B { c:C } repr(C) struct C { b:B }"
        self.assertFalse(predicate(source))
        self.reject(source)

    def test_pointer_to_array_requires_complete_elements(self):
        for source in (
            "repr(C) struct A { next:raw const [A;1] }",
            "repr(C) struct A { next:raw const [B;1] } repr(C) struct B { a:A }",
            "repr(C) struct A { next:raw const raw mut [B;1] } repr(C) struct B { a:A }",
        ):
            with self.subTest(source=source):
                self.assertFalse(predicate(source))
                self.reject(source)
        self.accept("repr(C) struct A { next:raw const [raw const A;1] }")
        self.accept("repr(C) struct A { next:raw const [B;1] } repr(C) struct B { a:raw const A }")

    def test_unsupported_fields_remain_visible_after_recursive_edges(self):
        for bad in ("bool", "i128", "u128", "Buffer<u8>", "Unit", "[i32;0]", "raw const bool"):
            for fields in (f"a:A, invalid:{bad}", f"invalid:{bad}, a:A"):
                source = f"repr(C) struct A {{ b:raw const B }} repr(C) struct B {{ {fields} }}"
                with self.subTest(bad=bad, fields=fields):
                    self.assertFalse(predicate(source))
                    self.reject(source)
        for declaration in ("struct B { a:A }", "repr(C) struct B {}",
                            "repr(C) struct B<T> { a:A, value:T }"):
            source = "repr(C) struct A { b:raw const B } " + declaration
            self.assertFalse(predicate(source))
            self.reject(source)

    def test_revisited_nominal_with_malformed_arguments_is_rejected(self):
        source = "repr(C) struct A { good:raw const B, invalid:raw const B<i32> } repr(C) struct B { a:A }"
        self.assertFalse(predicate(source))
        self.reject(source)

    def test_position_sensitive_unit_array_and_scalar_rules_are_unchanged(self):
        checker = _Checker(parse(""))
        for position in ("field", "parameter", "return", "pointee"):
            with self.subTest(position=position):
                self.assertEqual(checker.c_type(Type("Unit"), position=position), position in {"return", "pointee"})
                self.assertEqual(checker.c_type(Type("array", (Type("u8"),), 1), position=position), position in {"field", "pointee"})
                self.assertTrue(checker.c_type(Type("i32"), position=position))
                self.assertFalse(checker.c_type(Type("bool"), position=position))
        self.assertTrue(checker.c_type(Type("raw_const", (Type("Unit"),)), position="parameter"))
        self.assertFalse(checker.c_type(Type("array", (Type("Unit"),), 1), position="pointee"))

    def test_diamond_expands_each_nominal_once_per_predicate(self):
        source = "repr(C) struct T0 { value:u8 } " + " ".join(
            f"repr(C) struct T{i} {{ left:T{i-1}, right:T{i-1} }}" for i in range(1, 16))
        program = parse(source)
        class Counted(dict):
            reads = 0
            def __getitem__(self, key):
                self.reads += 1
                if self.reads > 100:
                    raise AssertionError("ABI type graph re-expanded more than 100 nominal occurrences")
                return super().__getitem__(key)
        checker = _Checker(program)
        checker.structs = Counted({s.name:s for s in program.structs})
        self.assertTrue(checker.c_type(Type("T15"), position="field"))
        self.assertLessEqual(checker.structs.reads, 31)

    def test_long_nominal_chain_uses_no_python_recursion(self):
        source = "repr(C) struct T0 { value:u8 } " + " ".join(
            f"repr(C) struct T{i} {{ value:T{i-1} }}" for i in range(1, 1200))
        self.assertTrue(predicate(source, "T1199"))

    def test_no_persistent_cache_survives_changed_record_definition(self):
        program = parse("repr(C) struct A { value:i32 }")
        checker = _Checker(program)
        checker.structs = {s.name:s for s in program.structs}
        self.assertTrue(checker.c_type(Type("A"), position="field"))
        program.structs[0].fields[0].type = Type("bool")
        self.assertFalse(checker.c_type(Type("A"), position="field"))

    def test_frontend_analysis_accepts_mixed_ffi_signatures(self):
        result = analyze(MIXED, native=False, crate_type="obj")
        self.assertTrue(result.report["ok"], result.report)
        self.assertIn("pub extern", result.rust)
        self.assertEqual(result.report["status"], "frontend_only")
        self.assertEqual(result.report["checks"]["rust_borrows_types"], "not_run")

    def test_public_cli_accepts_mixed_ffi_signatures(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "mixed.hepta"
            source.write_text(MIXED)
            result = subprocess.run([sys.executable, "-m", "hepta", "check", str(source),
                                     "--frontend-only", "--json"], cwd=ROOT,
                                    text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["status"], "frontend_only")


class ABITypeGraphNativeTests(unittest.TestCase):
    def test_complete_edges_match_independent_c_and_cpp_declarators(self):
        if not shutil.which("gcc") or not shutil.which("g++"):
            self.skipTest("real GCC and G++ required")
        # Hand-written declarators are an oracle independent of emit_header.
        fields = (("B", "hepta_B next;"),
                  ("raw const B", "const hepta_B *next;"),
                  ("[B;1]", "hepta_B next[1];"),
                  ("raw const [B;1]", "const hepta_B (*next)[1];"),
                  ("[raw const B;1]", "const hepta_B *next[1];"),
                  ("raw const [raw const B;1]", "const hepta_B *const (*next)[1];"),
                  ("[raw const [B;1];1]", "const hepta_B (*next[1])[1];"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oracle.h"
            for typ, declaration in fields:
                for back_type, back_declaration in (("A", "hepta_A back;"),
                                                    ("raw const A", "const hepta_A *back;")):
                    source = f"repr(C) struct A {{ next:{typ} }} repr(C) struct B {{ back:{back_type} }}"
                    actual = predicate(source)
                    rows = ("struct hepta_A { " + declaration + " };",
                            "struct hepta_B { " + back_declaration + " };")
                    accepted_languages = []
                    for compiler, language, standard in (("gcc", "c", "c11"), ("g++", "c++", "c++17")):
                        accepted_orders = []
                        for order in permutations(rows):
                            path.write_text("typedef struct hepta_A hepta_A;\ntypedef struct hepta_B hepta_B;\n"
                                            + "\n".join(order) + "\n")
                            built = subprocess.run([compiler, "-x", language, "-std=" + standard,
                                                    "-Werror", "-pedantic-errors", "-fsyntax-only", str(path)],
                                                   capture_output=True, text=True, timeout=20)
                            accepted_orders.append(built.returncode == 0)
                        accepted_languages.append(any(accepted_orders))
                    # C++ accepts some incomplete array pointees that C11
                    # rejects. The shared boundary must work in both languages.
                    with self.subTest(typ=typ, back_type=back_type):
                        self.assertEqual(actual, all(accepted_languages))

    def test_generated_headers_match_actual_c_and_cpp_complete_layouts(self):
        if not shutil.which("gcc") or not shutil.which("g++"):
            self.skipTest("real GCC and G++ required")
        cases = [MIXED,
                 "repr(C) struct A { b:raw mut B } repr(C) struct B { values:[A;2] }",
                 "repr(C) struct A { next:raw const [raw const A;1] }",
                 "repr(C) struct A { next:raw const [B;1] } repr(C) struct B { a:raw const A }"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for source in cases:
                checked = check(parse(source))
                self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
                generated = root / "api.h"
                generated.write_text(emit_header(parse(source)))
                for compiler, language, standard in (("gcc", "c", "c11"), ("g++", "c++", "c++17")):
                    with self.subTest(source=source, compiler=compiler):
                        built = subprocess.run([compiler, "-x", language, "-std="+standard,
                                                "-Werror", "-pedantic-errors", "-fsyntax-only", str(generated)],
                                               capture_output=True, text=True, timeout=20)
                        self.assertEqual(built.returncode, 0, built.stderr)

    @unittest.skipUnless(RUSTC and shutil.which("gcc") and shutil.which("g++"), "real pinned Rust and GCC/G++ required")
    def test_real_rust_objects_roundtrip_mixed_records_in_c_and_cpp(self):
        program = parse(MIXED)
        checked = check(program)
        self.assertTrue(checked.ok, [d.to_dict() for d in checked.diagnostics])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "api.h").write_text(emit_header(program))
            built = compile_rust(emit_rust(program, checked, crate_type="obj"), rustc=RUSTC,
                                 crate_type="obj", output=root/"api.o")
            self.assertTrue(built["ok"], built)
            client = '''#include "api.h"
int main(void) {
    hepta_Child child = {{NULL, 17}, 23};
    hepta_Parent parent = {&child, 41};
    hepta_Parent got = echo_parent(parent);
    if (got.child != &child || got.value != 41) return 1;
    hepta_Child copied = echo_child(child);
    if (copied.parent.child != NULL || copied.parent.value != 17 || copied.marker != 23) return 2;
    return 0;
}
'''
            for compiler, extension, standard in (("gcc", "c", "c11"), ("g++", "cpp", "c++17")):
                path=root/("client."+extension); path.write_text(client)
                compiled=subprocess.run([compiler,"-std="+standard,"-Werror","-pedantic-errors",str(path),str(root/"api.o"),"-o",str(root/"client")],capture_output=True,text=True,timeout=20)
                self.assertEqual(compiled.returncode,0,compiled.stderr)
                ran=subprocess.run([str(root/"client")],capture_output=True,text=True,timeout=10)
                self.assertEqual(ran.returncode,0,ran.stderr)


if __name__ == "__main__":
    unittest.main()
