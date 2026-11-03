"""Canonical decimal literals must round once at their destination precision."""
from fractions import Fraction
import math
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import emit_rust
from hepta.c_backend import emit_c
from hepta.checker import check
from hepta.parser import parse

CC = os.environ.get('CC') or shutil.which('gcc')
RUSTC = os.environ.get('RUSTC') or shutil.which('rustc')


def rational_bits(bits, width):
    precision, bias = (23, 127) if width == 32 else (52, 1023)
    exponent, mantissa = bits >> precision, bits & ((1 << precision) - 1)
    value = Fraction(mantissa if exponent == 0 else mantissa + (1 << precision))
    shift = (1 if exponent == 0 else exponent) - bias - precision
    return value * (2 ** shift if shift >= 0 else Fraction(1, 1 << -shift))


def oracle(text, width):
    # Hepta currently stores binary64 in the AST, and both emitters use repr.
    value = float(text)
    sign = int(math.copysign(1, value) < 0) << (width - 1)
    exact = abs(Fraction(repr(value)))
    maximum = 0x7f7fffff if width == 32 else 0x7fefffffffffffff
    lo, hi = 0, maximum
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if rational_bits(mid, width) <= exact:
            lo = mid
        else:
            hi = mid - 1
    if lo == maximum:
        top = rational_bits(maximum, width)
        overflow_midpoint = top + (top - rational_bits(maximum - 1, width)) / 2
        return sign | (maximum + int(exact >= overflow_midpoint))
    midpoint = (rational_bits(lo, width) + rational_bits(lo + 1, width)) / 2
    return sign | (lo + int(exact > midpoint or (exact == midpoint and lo & 1)))


def cases():
    values = ['0.0', '-0.0', '1.0000000596046448', '1.00000005960464477',
              '0.1', '1e-50', '7.006492321624085e-46', '1.401298464324817e-45',
              '1.1754942807573643e-38', '3.4028234663852886e38',
              '3.4028235677973366e38']
    rng = random.Random(20261103)
    bits = [1, 2, 0x007ffffe, 0x007fffff, 0x00800000, 0x3f7fffff,
            0x3f800000, 0x3f800001, 0x7f7ffffe]
    bits += [rng.randrange(0, 0x7f7fffff) for _ in range(64)]
    for pattern in bits:
        midpoint = float((rational_bits(pattern, 32) + rational_bits(pattern + 1, 32)) / 2)
        for v in (math.nextafter(midpoint, -math.inf), midpoint, math.nextafter(midpoint, math.inf)):
            values.extend((repr(v), repr(-v)))
    return [(32, s) for s in dict.fromkeys(values)] + [(64, s) for s in
        ('0.0', '-0.0', '0.1', '5e-324', '2.225073858507201e-308',
         '2.2250738585072014e-308', '1.7976931348623157e308', '-1.7976931348623157e308')]


def frontend(rows):
    source = '\n'.join(f'export "C" fn value_{i}() -> f{width} effects {{}} {{ return {text}; }}'
                       for i, (width, text) in enumerate(rows))
    p = parse(source)
    c = check(p)
    if not c.ok:
        raise AssertionError([d.to_dict() for d in c.diagnostics])
    return p, c


@unittest.skipUnless(CC, 'GCC required')
class CFloatLiteralTests(unittest.TestCase):
    def execute_c(self, rows):
        p, c = frontend(rows)
        harness = ['int main(void) {']
        for i, (width, _) in enumerate(rows):
            typ = 'float' if width == 32 else 'double'
            harness.append(f'{typ} v{i}=value_{i}(); uint{width}_t b{i}; '
                           f'memcpy(&b{i},&v{i},sizeof b{i}); printf("%" PRIu{width} "\\n", b{i});')
        harness.append('return 0; }')
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / 'literals.c'
            src.write_text(emit_c(p, c, crate_type='staticlib') + '\n' + '\n'.join(harness))
            for opt in ('-O0', '-O3'):
                exe = root / 'native'
                compiled = subprocess.run([CC, '-std=c11', opt, '-fexcess-precision=standard',
                    '-fsanitize=undefined', '-fno-sanitize-recover=all', str(src), '-lm', '-o', str(exe)],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(compiled.returncode, 0, compiled.stderr)
                run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertNotIn('runtime error:', run.stderr)
                self.assertEqual([int(x) for x in run.stdout.split()], [oracle(s, w) for w, s in rows])

    def test_rounding_ties_neighbours_subnormals_and_range(self):
        self.execute_c(cases())

    def test_known_double_rounding_and_signed_zero(self):
        self.assertEqual(oracle('1.0000000596046448', 32), 0x3f800001)
        self.assertEqual(oracle('-0.0', 32), 0x80000000)
        self.execute_c([(32, '1.0000000596046448'), (32, '-1.0000000596046448'),
                        (32, '-0.0'), (64, '-0.0')])

    def test_original_spelling_is_not_claimed_to_survive_ast(self):
        p, c = frontend([(32, '1.00000005960464477')])
        expr = p.functions[0].body[0].data['expr']
        self.assertEqual(repr(expr.value), '1.0000000596046448')
        self.assertIn('1.0000000596046448f32', emit_rust(p, c, crate_type='staticlib'))
        self.assertIn('1.0000000596046448f)', emit_c(p, c, crate_type='staticlib'))
        self.assertLess(Fraction('1.00000005960464477'), Fraction(1) + Fraction(1, 1 << 24))
        # The checker also permits integer-valued float AST payloads.
        expr.value = 1
        self.assertTrue(check(p).ok)
        self.assertIn('1.0f)', emit_c(p, check(p), crate_type='staticlib'))

    def test_infinite_target_literals_rejected(self):
        for text in ('3.402823567797337e38', '-3.402823567797337e38', '1e39', '-1e39'):
            self.assertEqual(oracle(text, 32) & 0x7fffffff, 0x7f800000)
            p, c = frontend([(32, text)])
            with self.subTest(text=text), self.assertRaises(HeptaError) as caught:
                emit_c(p, c, crate_type='staticlib')
            self.assertEqual(caught.exception.diagnostic.code, 'E_C_BACKEND_LITERAL')

    @unittest.skipUnless(RUSTC, 'Rust reference unavailable')
    def test_real_rust_same_ast_corpus_and_overflow_refusal(self):
        rows = cases()
        p, c = frontend(rows)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            src = root / 'literal.rs'
            main = 'fn main() {\n' + '\n'.join(f'println!("{{}}", value_{i}().to_bits());' for i in range(len(rows))) + '\n}'
            src.write_text(emit_rust(p, c, crate_type='staticlib') + main)
            exe = root / 'native'
            result = subprocess.run([RUSTC, '--edition=2021', str(src), '-o', str(exe)], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual([int(x) for x in run.stdout.split()], [oracle(s, w) for w, s in rows])
            p, c = frontend([(32, '1e39')])
            src.write_text(emit_rust(p, c, crate_type='staticlib'))
            rejected = subprocess.run([RUSTC, '--crate-type=lib', str(src), '-o', str(root/'invalid.rlib')], capture_output=True, text=True, timeout=60)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn('out of range for `f32`', rejected.stderr)
