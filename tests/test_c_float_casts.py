"""Native GCC saturation controls for the independent float-to-integer path."""
import math
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse

INTEGER_TYPES = ('i8', 'u8', 'i16', 'u16', 'i32', 'u32', 'i64', 'u64', 'isize', 'usize')


def bounds(name):
    bits = 64 if name.endswith('size') else int(name[1:])
    return (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if name.startswith('i') else (0, (1 << bits) - 1)


def oracle(value, name):
    lo, hi = bounds(name)
    if math.isnan(value):
        return 0
    if value <= lo:
        return lo
    if value >= hi:
        return hi
    return int(value)


def float_samples():
    rng = random.Random(20261103)
    samples = []
    for width, float_format, int_format in ((32, 'f', 'I'), (64, 'd', 'Q')):
        def encode(value):
            return struct.unpack('>' + int_format, struct.pack('>' + float_format, value))[0]
        def decode(bits):
            return struct.unpack('>' + float_format, struct.pack('>' + int_format, bits))[0]
        patterns = {encode(v) for v in (0.0, -0.0, 0.5, -0.5, 42.9, -42.9, float('inf'), -float('inf'), float('nan'))}
        # Exact bit neighbours of every saturation boundary, plus smallest
        # subnormal, both NaN signs, and independently sampled bit patterns.
        for integer in INTEGER_TYPES:
            lo, hi = bounds(integer)
            for value in (float(lo), float(hi), float(hi + 1)):
                bits = encode(value)
                patterns.update(b for b in (bits - 1, bits, bits + 1) if 0 <= b < 1 << width)
        patterns.update((1, (1 << (width - 1)) | 1, encode(float('nan')) | (1 << (width - 1))))
        signaling_nan = 0x7f800001 if width == 32 else 0x7ff0000000000001
        patterns.update((signaling_nan, signaling_nan | (1 << (width - 1))))
        patterns.update(rng.getrandbits(width) for _ in range(256))
        samples.extend((width, bits, decode(bits)) for bits in sorted(patterns))
    return samples


class CFloatCastTests(unittest.TestCase):
    def emitted(self, source, crate_type='bin'):
        program = parse(source)
        checked = check(program)
        self.assertTrue(checked.ok, checked.diagnostics)
        return emit_c(program, checked, crate_type=crate_type)

    def test_all_twenty_float_integer_pairs_emit(self):
        source = '\n'.join(f'export "C" fn cast_{s}_{t}(x: {s}) -> {t} effects {{}} {{ return x as {t}; }}'
                           for s in ('f32', 'f64') for t in INTEGER_TYPES)
        self.emitted(source, 'obj')

    def test_integer_to_float_and_float_width_changes_emit(self):
        for source in ('let x: f64 = 3 as f64;', 'let x: f32 = 3.5 as f32;'):
            with self.subTest(source=source):
                self.emitted('fn main() -> Unit effects {} { ' + source + ' }')

    @unittest.skipUnless(shutil.which('gcc'), 'GCC required for actual native casts')
    def test_native_boundaries_and_seeded_bits_under_float_cast_sanitizer(self):
        source = '\n'.join(f'export "C" fn cast_{s}_{t}(x: {s}) -> {t} effects {{}} {{ return x as {t}; }}'
                           for s in ('f32', 'f64') for t in INTEGER_TYPES)
        generated = self.emitted(source, 'obj')
        samples = float_samples()
        driver = ['int main(void) { unsigned width; uint64_t bits;',
                  'while (scanf("%u %" SCNx64, &width, &bits) == 2) {',
                  'if (width == 32) { uint32_t raw = (uint32_t)bits; float x; memcpy(&x, &raw, sizeof x);']
        for source_type in ('f32', 'f64'):
            if source_type == 'f64':
                driver.append('} else { double x; memcpy(&x, &bits, sizeof x);')
            for target in INTEGER_TYPES:
                macro, cast = ('PRId64', 'int64_t') if target.startswith('i') else ('PRIu64', 'uint64_t')
                driver.append(f'printf("%" {macro} " ", ({cast})cast_{source_type}_{target}(x));')
        driver.extend(['} puts(""); } return 0; }'])
        stdin = ''.join(f'{width} {bits:x}\n' for width, bits, _ in samples)
        expected = [[oracle(value, target) for target in INTEGER_TYPES] for _, _, value in samples]
        with tempfile.TemporaryDirectory(prefix='hepta-c-casts-') as directory:
            for optimize in (False, True):
                with self.subTest(optimize=optimize):
                    report = compile_c(generated + '\n' + '\n'.join(driver),
                                       output=Path(directory) / f'casts-{optimize}',
                                       optimize=optimize, sanitize=True,
                                       link_args=['-fsanitize=float-cast-overflow'])
                    self.assertTrue(report['ok'], report['diagnostics'])
                    result = subprocess.run([report['artifact']], input=stdin, text=True,
                                            capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, '')
                    observed = [[int(value) for value in line.split()] for line in result.stdout.splitlines()]
                    self.assertEqual(observed, expected)

    @unittest.skipUnless(shutil.which('gcc'), 'GCC required for actual native casts')
    def test_effectful_cast_operand_runs_once_and_short_circuits(self):
        source = '''
        fn step(counter: mut i32) -> f64 effects { write, panic } {
            counter = counter + 1; return 3.75;
        }
        fn main() -> Unit effects { write, panic } {
            let mut count: i32 = 0;
            let result: i32 = step(mut count) as i32;
            assert(result == 3); assert(count == 1);
            assert(true || (step(mut count) as i32 == 3));
            assert(count == 1);
        }
        '''
        with tempfile.TemporaryDirectory(prefix='hepta-c-cast-effects-') as directory:
            report = compile_c(self.emitted(source), output=Path(directory) / 'effects',
                               sanitize=True, link_args=['-fsanitize=float-cast-overflow'])
            self.assertTrue(report['ok'], report['diagnostics'])
            result = subprocess.run([report['artifact']], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('rustc'), 'rustc required for real Rust reference casts')
    def test_actual_rust_casts_match_the_same_bit_pattern_oracle(self):
        samples = float_samples()
        source = ['use std::io::{self, BufRead};', 'fn main() {',
                  'for line in io::stdin().lock().lines() {',
                  'let line = line.unwrap(); let mut parts = line.split_whitespace();',
                  'let width: u32 = parts.next().unwrap().parse().unwrap();',
                  'let bits = u64::from_str_radix(parts.next().unwrap(), 16).unwrap();',
                  'if width == 32 { let x = f32::from_bits(bits as u32);']
        for source_type in ('f32', 'f64'):
            if source_type == 'f64':
                source.append('} else { let x = f64::from_bits(bits);')
            for target in INTEGER_TYPES:
                source.append(f'print!("{{}} ", x as {target});')
        source.append('} println!(); } }')
        with tempfile.TemporaryDirectory(prefix='hepta-rust-cast-reference-') as directory:
            file = Path(directory) / 'reference.rs'
            file.write_text('\n'.join(source))
            binary = Path(directory) / 'reference'
            build = subprocess.run([shutil.which('rustc'), str(file), '-C', 'opt-level=3',
                                    '-C', 'overflow-checks=yes', '-o', str(binary)],
                                   text=True, capture_output=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stderr)
            result = subprocess.run([str(binary)],
                                    input=''.join(f'{width} {bits:x}\n' for width, bits, _ in samples),
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            observed = [[int(value) for value in line.split()] for line in result.stdout.splitlines()]
            expected = [[oracle(value, target) for target in INTEGER_TYPES] for _, _, value in samples]
            self.assertEqual(observed, expected)
