"""Exact-rational oracle for C numeric conversion; no native timing claims."""
from fractions import Fraction
from pathlib import Path
import platform
import random
import shutil
import subprocess
import tempfile
import unittest

from hepta.c_backend import SCALARS, compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse
from tests.test_c_float_casts import INTEGER_TYPES, bounds


def rounded_bits(value, width, *, negative=False):
    """Round an exact nonnegative rational using quotient/remainder arithmetic."""
    frac, bias = (23, 127) if width == 32 else (52, 1023)
    sign = int(negative) << (width - 1)
    if not value:
        return sign
    n, d = value.numerator, value.denominator
    exponent = n.bit_length() - d.bit_length()
    if (n < d << exponent) if exponent >= 0 else (n << -exponent < d):
        exponent -= 1
    exponent = max(exponent, 1 - bias)
    shift = exponent - frac
    numerator, denominator = (n, d << shift) if shift >= 0 else (n << -shift, d)
    q, remainder = divmod(numerator, denominator)
    if 2 * remainder > denominator or (2 * remainder == denominator and q % 2):
        q += 1
    if q >= 1 << (frac + 1):
        q >>= 1
        exponent += 1
    if exponent > bias:
        return sign | ((2 * bias + 1) << frac)
    if q < 1 << frac:
        return sign | q
    return sign | ((exponent + bias) << frac) | (q - (1 << frac))


def decode(bits, width):
    frac, bias = (23, 127) if width == 32 else (52, 1023)
    negative = bool(bits >> (width - 1))
    exponent, mantissa = (bits >> frac) & (2 * bias + 1), bits & ((1 << frac) - 1)
    if exponent == 2 * bias + 1:
        return ('nan' if mantissa else 'infinity'), negative
    significand = mantissa + ((1 << frac) if exponent else 0)
    power = (exponent or 1) - bias - frac
    return Fraction(significand << power, 1) if power >= 0 else Fraction(significand, 1 << -power), negative


def convert_bits(bits, source_width, target_width):
    value, negative = decode(bits, source_width)
    frac, bias = (23, 127) if target_width == 32 else (52, 1023)
    if value == 'nan':
        return None
    if value == 'infinity':
        return (int(negative) << (target_width - 1)) | ((2 * bias + 1) << frac)
    return rounded_bits(value, target_width, negative=negative)


def corpus():
    rng = random.Random(2026110308)
    rows = []
    for index, name in enumerate(INTEGER_TYPES):
        lo, hi = bounds(name)
        values = {lo, hi, 0, 1, hi - 1}
        if lo < 0:
            values.update((-1, lo + 1))
        for exponent in range(64):
            for offset in (-3, -2, -1, 0, 1, 2, 3):
                for sign in (1, -1):
                    v = sign * ((1 << exponent) + offset)
                    if lo <= v <= hi:
                        values.add(v)
        # Integer values just around rounding midpoints, including values
        # where an intermediate binary64 would lose the +1 before binary32.
        for precision in (24, 53):
            for exponent in range(precision, 64):
                spacing = 1 << (exponent - precision + 1)
                for parity in (0, 1):
                    midpoint = (1 << exponent) + parity * spacing + spacing // 2
                    for offset in (-1, 0, 1):
                        for sign in (-1, 1):
                            n = sign * (midpoint + offset)
                            if lo <= n <= hi:
                                values.add(n)
        values.update(rng.randint(lo, hi) for _ in range(256))
        if hi - lo == 255:
            values.update(range(lo, hi + 1))
        rows.extend((index, n & ((1 << 64) - 1),
                     [(w, rounded_bits(Fraction(abs(n)), w, negative=n < 0)) for w in (32, 64)])
                    for n in sorted(values))
    for width, index in ((32, 10), (64, 11)):
        frac, bias = (23, 127) if width == 32 else (52, 1023)
        patterns = {0, 1, (1 << frac) - 1, 1 << frac, bias << frac,
                    ((2 * bias + 1) << frac) - 1, (2 * bias + 1) << frac,
                    ((2 * bias + 1) << frac) | 1, ((2 * bias + 1) << frac) | (1 << (frac - 1))}
        if width == 64:
            # Exact midpoint and binary64 neighbours around binary32 normal,
            # subnormal, zero and overflow transitions. No floating arithmetic.
            for e in (0, 1, 2, 126, 127, 128, 253, 254):
                for m in (0, 1, 2, (1 << 23) - 2, (1 << 23) - 1):
                    a = (e << 23) | m
                    av, _ = decode(a, 32)
                    bv, _ = decode(a + 1, 32)
                    if bv == 'infinity':
                        bv = Fraction(1 << 128)
                    midpoint = (av + bv) / 2
                    center = rounded_bits(midpoint, 64)
                    patterns.update((center - 1, center, center + 1))
        patterns.update(rng.getrandbits(width - 1) for _ in range(512))
        patterns |= {p | (1 << (width - 1)) for p in patterns}
        rows.extend((index, bits, [(96 - width, convert_bits(bits, width, 96 - width))]) for bits in sorted(patterns))
    return rows


def source_matrix():
    return '\n'.join(
        [f'export "C" fn cast_{s}_{t}(x: {s}) -> {t} effects {{}} {{ return x as {t}; }}'
         for s in INTEGER_TYPES for t in ('f32', 'f64')] +
        [f'export "C" fn cast_{s}_{t}(x: {s}) -> {t} effects {{}} {{ return x as {t}; }}'
         for s, t in (('f32', 'f64'), ('f64', 'f32'))])


class CFloatConversionTests(unittest.TestCase):
    def emitted(self, source, crate_type='obj'):
        program = parse(source)
        checked = check(program)
        self.assertTrue(checked.ok, checked.diagnostics)
        return emit_c(program, checked, crate_type=crate_type)

    def test_twenty_two_conversion_pairs_emit(self):
        self.emitted(source_matrix())

    def assert_observations(self, text, rows):
        observed = [line.split() for line in text.splitlines()]
        self.assertEqual(len(observed), len(rows))
        for (index, bits, expectations), values in zip(rows, observed):
            self.assertEqual(len(values), len(expectations))
            for (width, expected), raw in zip(expectations, values):
                actual = int(raw, 16)
                if expected is None:
                    self.assertEqual(decode(actual, width)[0], 'nan', (index, hex(bits), hex(actual)))
                else:
                    self.assertEqual(actual, expected, (index, hex(bits), width, hex(actual), hex(expected)))

    @unittest.skipUnless(shutil.which('gcc'), 'GCC required')
    def test_native_exact_bits_all_rounding_modes_and_x86_flush_modes(self):
        generated = self.emitted(source_matrix())
        driver = ['#include <fenv.h>', '#if defined(__x86_64__)', '#include <xmmintrin.h>', '#endif',
                  'int main(int argc, char **argv) {',
                  'int modes[] = {FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO};',
                  'if (argc < 2 || fesetround(modes[atoi(argv[1])])) return 3;',
                  '#if defined(__x86_64__)',
                  'if (argc > 2) _mm_setcsr(_mm_getcsr() | 0x8040u);', '#endif',
                  'unsigned kind; uint64_t bits; while (scanf("%u %" SCNx64, &kind, &bits) == 2) { switch(kind) {']
        for index, source in enumerate((*INTEGER_TYPES, 'f32', 'f64')):
            width = 64 if source.endswith('size') else int(source[1:])
            driver.append(f'case {index}: {{ uint{width}_t raw = (uint{width}_t)bits; {SCALARS[source]} x; memcpy(&x, &raw, sizeof x);')
            targets = ('f32', 'f64') if index < 10 else (('f64',) if source == 'f32' else ('f32',))
            for target in targets:
                tw = int(target[1:])
                driver.append(f'{{ {SCALARS[target]} y = cast_{source}_{target}(x); uint{tw}_t out; memcpy(&out, &y, sizeof out); printf("%" PRIx64 " ", (uint64_t)out); }}')
            driver.append('break; }')
        driver.append('default: return 4; } puts(""); } return 0; }')
        rows = corpus()
        wire = ''.join(f'{i} {b:x}\n' for i, b, _ in rows)
        with tempfile.TemporaryDirectory(prefix='hepta-c-float-convert-') as directory:
            for optimize in (False, True):
                report = compile_c(generated + '\n' + '\n'.join(driver),
                                   output=Path(directory) / f'conversions-{optimize}', optimize=optimize,
                                   sanitize=True, link_args=['-fsanitize=float-cast-overflow'])
                self.assertTrue(report['ok'], report['diagnostics'])
                for rounding in range(4):
                    for flush in range(2 if platform.machine() == 'x86_64' else 1):
                        with self.subTest(optimize=optimize, rounding=rounding, flush=flush):
                            args = [report['artifact'], str(rounding)] + (['flush'] if flush else [])
                            result = subprocess.run(args, input=wire, text=True, capture_output=True, timeout=20)
                            self.assertEqual(result.returncode, 0, result.stderr)
                            self.assertEqual(result.stderr, '')
                            self.assert_observations(result.stdout, rows)

    def test_oracle_known_ties_overflow_and_signed_zero(self):
        self.assertEqual(rounded_bits(Fraction(16777217), 32), 0x4b800000)
        self.assertEqual(rounded_bits(Fraction(16777219), 32), 0x4b800002)
        self.assertEqual(rounded_bits(Fraction((1 << 63) + (1 << 39) + 1), 32), 0x5f000001)
        self.assertEqual(rounded_bits(Fraction((1 << 64) - 1), 64), 0x43f0000000000000)
        self.assertEqual(rounded_bits(Fraction(1, 1 << 150), 32), 0)
        self.assertEqual(rounded_bits(Fraction(3, 1 << 150), 32), 2)
        self.assertEqual(rounded_bits(Fraction(1, 1 << 150), 32, negative=True), 0x80000000)
        self.assertEqual(rounded_bits(Fraction((1 << 25) - 1) * (1 << 103), 32), 0x7f800000)
        self.assertEqual(convert_bits(0x80000000, 32, 64), 0x8000000000000000)

    @unittest.skipUnless(shutil.which('gcc'), 'GCC required')
    def test_effectful_operands_execute_once_and_short_circuit(self):
        source = r'''fn step_i(counter: mut i32) -> i64 effects { write, panic } {
            counter = counter + 1; return 16777217;
        }
        fn step_f(counter: mut i32) -> f64 effects { write, panic } {
            counter = counter + 1; return 3.75;
        }
        fn main() -> Unit effects { write, panic } {
            let mut count: i32 = 0;
            let x: f32 = step_i(mut count) as f32;
            assert((x as i64) == 16777216); assert(count == 1);
            let y: f32 = step_f(mut count) as f32;
            assert((y as f64) == 3.75); assert(count == 2);
            assert(true || (step_i(mut count) as f64 == 0.0));
            assert(true || (step_f(mut count) as f32 == x));
            assert(count == 2);
        }'''
        with tempfile.TemporaryDirectory(prefix='hepta-c-conversion-effects-') as directory:
            for optimize in (False, True):
                report = compile_c(self.emitted(source, 'bin'), output=Path(directory) / str(optimize),
                                   optimize=optimize, sanitize=True)
                self.assertTrue(report['ok'], report['diagnostics'])
                result = subprocess.run([report['artifact']], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('gcc'), 'GCC required')
    def test_fast_math_and_unknown_representation_are_rejected(self):
        generated = self.emitted('fn main() -> Unit effects {} { let x: f32 = 3 as f32; }', 'bin')
        with tempfile.TemporaryDirectory(prefix='hepta-c-conversion-profile-') as directory:
            for label, source, flags in (
                    ('fast', generated, ['-ffast-math']),
                    ('unknown', generated.replace('#if !defined(__STDC_IEC_559__)',
                         '#undef __STDC_IEC_559__\n#if !defined(__STDC_IEC_559__)'), []),
                    ('word-order', generated.replace('#if !defined(__STDC_IEC_559__)',
                         '#undef __FLOAT_WORD_ORDER__\n#define __FLOAT_WORD_ORDER__ 0\n#if !defined(__STDC_IEC_559__)'), [])):
                with self.subTest(profile=label):
                    report = compile_c(source, output=Path(directory) / label, link_args=flags)
                    self.assertFalse(report['ok'])
                    self.assertIn('Numeric float casts require', str(report['diagnostics']))

    @unittest.skipUnless(shutil.which('rustc'), 'rustc required for actual same-corpus reference')
    def test_native_rust_matches_exact_oracle(self):
        source = ['use std::io::{self, BufRead}; fn main() { for line in io::stdin().lock().lines() {',
                  'let line = line.unwrap(); let mut parts = line.split_whitespace();',
                  'let kind: u32 = parts.next().unwrap().parse().unwrap();',
                  'let bits = u64::from_str_radix(parts.next().unwrap(), 16).unwrap(); match kind {']
        for i, name in enumerate((*INTEGER_TYPES, 'f32', 'f64')):
            expr = f'bits as {name}' if i < 10 else ('f32::from_bits(bits as u32)' if i == 10 else 'f64::from_bits(bits)')
            source.append(f'{i} => {{ let x = {expr};')
            for target in (('f32', 'f64') if i < 10 else (('f64',) if i == 10 else ('f32',))):
                source.append(f'print!("{{:x}} ", (x as {target}).to_bits());')
            source.append('},')
        source.append('_ => panic!("kind") }; println!(); } }')
        rows = corpus()
        with tempfile.TemporaryDirectory(prefix='hepta-rust-float-convert-') as directory:
            path, binary = Path(directory) / 'reference.rs', Path(directory) / 'reference'
            path.write_text('\n'.join(source))
            build = subprocess.run([shutil.which('rustc'), str(path), '-C', 'opt-level=3', '-o', str(binary)], capture_output=True, text=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(binary)], input=''.join(f'{i} {b:x}\n' for i, b, _ in rows), text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_observations(result.stdout, rows)


if __name__ == '__main__':
    unittest.main()
