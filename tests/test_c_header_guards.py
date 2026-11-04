"""Exact module identities must not corrupt or suppress generated C headers."""
from itertools import product
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.backend import compile_rust, emit_header, emit_rust
from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse

ROOT = Path(__file__).resolve().parents[1]
RUSTC = os.environ.get("RUSTC") or shutil.which("rustc")


def source(module, index=0):
    return (f"module {module};\n"
            f"repr(C) struct Record{index} {{ value: i32 }}\n"
            f'export "C" fn entry{index}(value: Record{index}) -> Record{index} '
            "effects {} { return value; }\n")


def checked_program(module, index=0):
    program = parse(source(module, index))
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return program, checked


def header(module, index=0):
    return emit_header(checked_program(module, index)[0])


def guard(text):
    return text.splitlines()[1].removeprefix("#ifndef ")


class HeaderGuardIdentityTests(unittest.TestCase):
    def test_qualified_names_are_single_valid_preprocessor_identifiers(self):
        for name in ("pkg::left", "pkg::nested::right", "_private::m0"):
            with self.subTest(module=name):
                self.assertRegex(guard(header(name)), r"^[A-Za-z][A-Za-z0-9_]*$")

    def test_case_sensitive_modules_have_distinct_guards(self):
        names = ("App", "app", "APP", "pkg::Left", "pkg::left")
        self.assertEqual(len({guard(header(n)) for n in names}), len(names))

    def test_namespaces_cannot_collide_with_underscore_spellings(self):
        names = ("a::b", "a_b", "a__b", "a::b_c", "a_b::c", "a::b::c")
        self.assertEqual(len({guard(header(n)) for n in names}), len(names))

    def test_guard_preserves_exact_module_bytes(self):
        names = ["".join(chars) for chars in product("aA_0", repeat=3)
                 if chars[0] != "0"]
        names += [f"{left}::{right}" for left in names[:12] for right in names[:12]]
        identities = []
        for name in names:
            actual = guard(header(name))
            self.assertTrue(actual.startswith("HEPTA_MODULE_"))
            self.assertTrue(actual.endswith("_H"))
            self.assertEqual(bytes.fromhex(actual[13:-2]).decode("utf-8"), name)
            identities.append(actual)
        self.assertEqual(len(set(identities)), len(names))

    def test_same_module_keeps_guard_across_declaration_changes(self):
        first = header("pkg::stable", 0)
        second = header("pkg::stable", 1)
        self.assertNotEqual(first, second)
        self.assertEqual(guard(first), guard(second))
        self.assertEqual(first, header("pkg::stable", 0))

    def test_only_guard_lines_change_and_default_module_is_supported(self):
        program = parse('repr(C) struct Record { value: i32 } '
                        'export "C" fn entry(value: Record)->Record effects {} {return value;}')
        checked = check(program)
        self.assertTrue(checked.ok)
        actual = emit_header(program)
        self.assertEqual(actual.splitlines()[3:-1], [
            '#include <stdint.h>', '#include <stddef.h>', '#ifdef __cplusplus',
            'extern "C" {', '#endif',
            'typedef struct hepta_Record hepta_Record;',
            'struct hepta_Record {', '    int32_t value;', '};',
            'hepta_Record entry(hepta_Record value);',
            '#ifdef __cplusplus', '}', '#endif',
        ])
        value = guard(actual)
        self.assertEqual(actual.splitlines()[2], "#define " + value)
        self.assertEqual(actual.splitlines()[-1], "#endif /* " + value + " */")
        self.assertEqual(value, "HEPTA_MODULE_6D61696E_H")


class HeaderNativeMixin:
    def native_headers(self, modules, *, cpp=False, rust=False):
        compiler = shutil.which("g++" if cpp else "gcc")
        if compiler is None:
            self.skipTest("real G++ required" if cpp else "real GCC required")
        if rust and not RUSTC:
            self.skipTest("real pinned rustc required")
        with tempfile.TemporaryDirectory(prefix="hepta-header-guards-") as tmp:
            root = Path(tmp)
            objects = []
            for index, name in enumerate(modules):
                program, checked = checked_program(name, index)
                (root / f"header{index}.h").write_text(emit_header(program))
                obj = root / f"object{index}.o"
                if rust:
                    built = compile_rust(emit_rust(program, checked, crate_type="obj"),
                                         rustc=RUSTC, crate_type="obj", output=obj)
                else:
                    built = compile_c(emit_c(program, checked, crate_type="obj"),
                                      crate_type="obj", output=obj)
                self.assertTrue(built["ok"], built)
                objects.append(str(obj))
            for order in (list(range(len(modules))), list(reversed(range(len(modules))))):
                with self.subTest(order=order, cpp=cpp, rust=rust):
                    # Struct definitions make failure to honor repeated inclusion
                    # an error, while all symbols/record types must survive.
                    includes = [f'#include "header{i}.h"' for i in order + order]
                    body = []
                    for i in range(len(modules)):
                        body += [f"hepta_Record{i} value{i} = {{{100 + i}}};",
                                 f"hepta_Record{i} (*fn{i})(hepta_Record{i}) = entry{i};",
                                 f"if (fn{i}(value{i}).value != {100 + i}) return {i + 1};"]
                    client = root / ("client.cpp" if cpp else "client.c")
                    client.write_text("\n".join(includes) + "\nint main(void) {\n" +
                                      "\n".join(body) + "\nreturn 0;\n}\n")
                    executable = root / "client"
                    command = [compiler, "-std=c++17" if cpp else "-std=c11",
                               "-Wall", "-Wextra", "-Werror", "-pedantic-errors",
                               str(client), *objects, "-o", str(executable)]
                    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    ran = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
                    self.assertEqual(ran.returncode, 0, ran.stderr)


class HeaderNativeTests(HeaderNativeMixin, unittest.TestCase):
    def test_c_qualified_headers_compile_link_and_repeat_in_both_orders(self):
        self.native_headers(("pkg::left", "pkg::right"))

    def test_cpp_qualified_headers_compile_link_and_repeat_in_both_orders(self):
        self.native_headers(("pkg::left", "pkg::right"), cpp=True)

    def test_c_case_distinct_headers_preserve_both_apis(self):
        self.native_headers(("App", "app"))

    def test_cpp_case_distinct_headers_preserve_both_apis(self):
        self.native_headers(("App", "app"), cpp=True)

    def test_c_underscores_do_not_alias_namespaces(self):
        self.native_headers(("a::b", "a_b", "a__b"))

    def test_cpp_underscores_do_not_alias_namespaces(self):
        self.native_headers(("a::b", "a_b", "a__b"), cpp=True)

    def test_long_module_identities_remain_distinct(self):
        prefix = "shared" * 20
        self.native_headers((prefix + "::left", prefix + "::right"))

    def test_cli_c_headers_preserve_qualified_module_identity(self):
        if not shutil.which("gcc"):
            self.skipTest("real GCC required")
        with tempfile.TemporaryDirectory(prefix="hepta-header-cli-") as tmp:
            root = Path(tmp)
            for index, name in enumerate(("pkg::left", "pkg::right")):
                input_path = root / f"input{index}.hepta"
                output_path = root / f"output{index}.h"
                input_path.write_text(source(name, index))
                result = subprocess.run(
                    [sys.executable, "-m", "hepta", "header", str(input_path),
                     "--backend", "c", "--crate-type", "obj", "-o", str(output_path)],
                    cwd=ROOT, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                receipt = json.loads(result.stdout)
                self.assertTrue(receipt["ok"], receipt)
                self.assertEqual(output_path.read_text(), header(name, index))
            client = root / "client.c"
            client.write_text('#include "output0.h"\n#include "output1.h"\n'
                              'hepta_Record0 (*a)(hepta_Record0) = entry0;\n'
                              'hepta_Record1 (*b)(hepta_Record1) = entry1;\n')
            result = subprocess.run(["gcc", "-std=c11", "-Werror", "-pedantic-errors",
                                     "-fsyntax-only", str(client)], capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)


class HeaderRustNativeTests(HeaderNativeMixin, unittest.TestCase):
    def test_c_headers_link_actual_rust_objects_for_all_identity_variants(self):
        self.native_headers(("pkg::left", "pkg::right", "App", "app", "pkg_left"), rust=True)

    def test_cpp_headers_link_actual_rust_objects_for_all_identity_variants(self):
        self.native_headers(("pkg::left", "pkg::right", "App", "app", "pkg_left"), cpp=True, rust=True)


if __name__ == "__main__":
    unittest.main()
