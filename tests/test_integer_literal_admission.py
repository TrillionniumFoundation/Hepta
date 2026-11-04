"""Source integers are bounded before hashing, diagnostics, or emission."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.checker import check
from hepta.lexer import tokenize
from hepta.modules import load_project
from hepta.parser import parse
from hepta.pipeline import analyze, interface_hash


MAX_INTEGER = (1 << 128) - 1
ROOT = Path(__file__).resolve().parents[1]


def spellings(value):
    return (str(value), hex(value), oct(value), bin(value))


def contexts(literal):
    return {
        "array_parameter": f"fn f(x: read [u8; {literal}]) -> Unit effects {{}} {{}}",
        "array_field": f"struct S {{ x: [u8; {literal}] }}",
        "nested_array": f"struct S {{ x: [[u8; {literal}]; 1] }}",
        "resource": f"fn f() -> Unit effects {{}} resources {{ heap_allocations = {literal}; }} {{}}",
        "unknown_resource": f"fn f() -> Unit effects {{}} resources {{ other = {literal}; }} {{}}",
        "usize": f"fn f() -> usize effects {{}} {{ return {literal}; }}",
        "isize": f"fn f() -> isize effects {{}} {{ return {literal}; }}",
        "u128": f"fn f() -> u128 effects {{}} {{ return {literal}; }}",
        "negative": f"fn f() -> i128 effects {{panic}} {{ return -{literal}; }}",
        "unused_generic": f"fn f<T>(x: T) -> usize effects {{}} {{ return {literal}; }}",
    }


class IntegerLiteralAdmissionTests(unittest.TestCase):
    def test_maximum_and_signed_minimum_magnitude_in_every_base(self):
        for value in (0, 1, 1 << 127, MAX_INTEGER):
            for literal in spellings(value):
                with self.subTest(value=value, base=literal[:2]):
                    self.assertEqual(tokenize(literal)[0].value, value)

    def test_one_above_maximum_rejected_in_every_base_with_exact_span(self):
        prefix = "/* π */\r\n  "
        for literal in spellings(MAX_INTEGER + 1):
            with self.subTest(base=literal[:2]), self.assertRaises(HeptaError) as caught:
                tokenize(prefix + literal + ";", "boundary.hepta")
            diagnostic = caught.exception.diagnostic
            self.assertEqual((diagnostic.phase, diagnostic.code), ("lex", "E_LEX_NUMBER"))
            self.assertIn("128-bit", diagnostic.message)
            self.assertEqual(diagnostic.span.path, "boundary.hepta")
            self.assertEqual((diagnostic.span.start, diagnostic.span.end),
                             (len(prefix), len(prefix) + len(literal)))
            self.assertEqual((diagnostic.span.line, diagnostic.span.column), (2, 3))

    def test_leading_zeroes_and_separators_preserve_values(self):
        for value in (0, 1, MAX_INTEGER):
            for literal in spellings(value):
                prefix, digits = (literal[:2], literal[2:]) if literal.startswith("0x") or literal.startswith("0o") or literal.startswith("0b") else ("", literal)
                for padded in (prefix + "0" * 1000 + digits,
                               prefix + "_".join("000" + digits)):
                    with self.subTest(value=value, prefix=prefix):
                        self.assertEqual(tokenize(padded)[0].value, value)

    def test_existing_spelling_limit_includes_prefix_but_not_separators(self):
        for prefix in ("", "0x", "0o", "0b"):
            literal = prefix + "0" * (4095 - len(prefix)) + "1"
            self.assertEqual(tokenize(literal)[0].value, 1)
            separated = prefix + "_".join(literal[len(prefix):])
            self.assertEqual(tokenize(separated)[0].value, 1)
            with self.assertRaises(HeptaError) as caught:
                tokenize(prefix + "0" + literal[len(prefix):])
            self.assertEqual(caught.exception.diagnostic.code, "E_LEX_NUMBER")
            self.assertIn("4096", caught.exception.diagnostic.message)

    def test_long_magnitudes_rejected_without_decimal_conversion(self):
        for literal in ("9" * 4096, "0x" + "f" * 3600,
                        "0o" + "7" * 4094, "0b" + "1" * 4094):
            with self.subTest(base=literal[:2]), self.assertRaises(HeptaError) as caught:
                tokenize(literal)
            self.assertIn("128-bit", caught.exception.diagnostic.message)

    def test_float_values_do_not_inherit_integer_ceiling(self):
        for literal in ("1e100", "1" + "0" * 100 + ".0"):
            token = tokenize(literal)[0]
            self.assertEqual(token.kind, "FLOAT")
            self.assertEqual(token.value, 1e100)

    def test_all_original_crash_contexts_return_serializable_diagnostics(self):
        large = "0x" + "f" * 3600
        for name, source in contexts(large).items():
            for backend in ("rust", "c"):
                with self.subTest(context=name, backend=backend):
                    result = analyze(source, "huge.hepta", native=False, backend=backend)
                    self.assertFalse(result.report["ok"])
                    self.assertEqual(result.report["diagnostics"][0]["code"], "E_LEX_NUMBER")
                    self.assertEqual(result.report["diagnostics"][0]["phase"], "lex")
                    self.assertNotIn("interface_sha256", result.report)
                    self.assertIsNone(result.rust)
                    self.assertIsNone(result.c)
                    json.dumps(result.report)

    def test_boundary_rejection_is_context_and_base_independent(self):
        for literal in spellings(MAX_INTEGER + 1):
            for name, source in contexts(literal).items():
                with self.subTest(context=name, base=literal[:2]):
                    result = analyze(source, native=False)
                    self.assertFalse(result.report["ok"])
                    self.assertEqual(result.report["diagnostics"][0]["code"], "E_LEX_NUMBER")

    def test_admitted_interface_values_hash_and_resource_diagnostics_render(self):
        for literal in spellings(MAX_INTEGER):
            for name in ("array_parameter", "array_field", "nested_array", "resource", "unknown_resource"):
                source = contexts(literal)[name]
                with self.subTest(context=name, base=literal[:2]):
                    self.assertEqual(len(interface_hash(parse(source))), 64)
                    result = analyze(source, native=False)
                    json.dumps(result.report)
                    if "resource" in name:
                        self.assertFalse(result.report["ok"])
                        self.assertEqual(result.report["diagnostics"][0]["code"], "E_RESOURCE_UNSUPPORTED")

    def test_fixed_width_type_ranges_and_signed_minimum_are_preserved(self):
        for literal in spellings(MAX_INTEGER):
            result = analyze(f"fn f() -> u128 effects {{}} {{ return {literal}; }}", native=False)
            self.assertTrue(result.report["ok"], result.report)
            self.assertIn(f"{MAX_INTEGER}u128", result.rust)
        for literal in spellings(1 << 127):
            result = analyze(f"fn f() -> i128 effects {{panic}} {{ return -{literal}; }}", native=False)
            self.assertTrue(result.report["ok"], result.report)
        for typ, literal, code in (("u8", "256", "E_INTEGER_RANGE"),
                                   ("i128", str(1 << 127), "E_INTEGER_RANGE"),
                                   ("u128", "-1", "E_UNARY_TYPE")):
            result = check(parse(f"fn f() -> {typ} effects {{panic}} {{ return {literal}; }}"))
            self.assertFalse(result.ok)
            self.assertIn(code, [d.code for d in result.diagnostics])

    def test_pointer_sized_ranges_still_belong_to_the_target(self):
        for typ in ("usize", "isize"):
            result = analyze(f"fn f() -> {typ} effects {{}} {{ return {MAX_INTEGER}; }}", native=False)
            self.assertTrue(result.report["ok"], result.report)
            self.assertEqual(result.report["status"], "frontend_only")

    def test_imported_huge_value_is_a_positioned_source_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = root / "child.hepta"
            child.write_text("pub " + contexts("0x" + "f" * 3600)["usize"], encoding="utf-8")
            entry = root / "main.hepta"
            entry.write_text("import child;", encoding="utf-8")
            with self.assertRaises(HeptaError) as caught:
                load_project(entry)
            self.assertEqual(caught.exception.diagnostic.code, "E_LEX_NUMBER")
            self.assertEqual(Path(caught.exception.diagnostic.span.path), child)

    def test_cli_returns_json_without_traceback_for_original_crashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "large.hepta"
            for name in ("array_parameter", "resource", "usize"):
                source.write_text(contexts("0x" + "f" * 3600)[name], encoding="utf-8")
                result = subprocess.run([sys.executable, "-m", "hepta", "check", str(source), "--frontend-only"],
                                        cwd=ROOT, capture_output=True, text=True, timeout=30)
                with self.subTest(context=name):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("Traceback", result.stderr)
                    report = json.loads(result.stdout)
                    self.assertFalse(report["ok"])
                    self.assertEqual(report["diagnostics"][0]["code"], "E_LEX_NUMBER")

    def test_smallest_python_decimal_limit_without_mutating_process_setting(self):
        script = '''
import json, sys
from hepta.lexer import tokenize
from hepta.pipeline import analyze
before = sys.get_int_max_str_digits()
assert before == 640
assert tokenize("0" * 4000 + "1")[0].value == 1
assert tokenize("0x" + "0" * 4000 + "1")[0].value == 1
for literal in ("0x" + "f" * 600, "9" * 700):
    report = analyze("fn f() -> usize effects {} { return " + literal + "; }", native=False).report
    assert not report["ok"]
    assert report["diagnostics"][0]["code"] == "E_LEX_NUMBER"
    json.dumps(report)
assert sys.get_int_max_str_digits() == before
'''
        before = sys.get_int_max_str_digits()
        env = dict(os.environ, PYTHONINTMAXSTRDIGITS="640")
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sys.get_int_max_str_digits(), before)

    @unittest.skipUnless(shutil.which("rustc"), "requires pinned native rustc")
    def test_admitted_boundaries_pass_native_rust_validation(self):
        source = f"""
        pub fn maximum() -> u128 effects {{}} {{ return {MAX_INTEGER}; }}
        pub fn minimum() -> i128 effects {{panic}} {{ return -{1 << 127}; }}
        pub fn array(x: read [u8; 1]) -> usize effects {{}} resources {{ heap_allocations = 0; }} {{ return len(x); }}
        """
        result = analyze(source)
        self.assertTrue(result.report["ok"], result.report)
        self.assertEqual(result.report["status"], "checked")


if __name__ == "__main__":
    unittest.main()
