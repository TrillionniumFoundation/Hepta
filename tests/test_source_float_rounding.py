"""Source decimal meaning survives parsing until the destination type is known."""
from decimal import Decimal, localcontext
from fractions import Fraction
import os
from pathlib import Path
import shutil
import random
import struct
import subprocess
import tempfile
import unittest

from hepta.ast import Expr, Type
from hepta.backend import emit_rust
from hepta.c_backend import emit_c
from hepta.checker import check
from hepta.parser import parse
from hepta.semantic_ir import lower_checked_program
from tests.test_c_float_literals import rational_bits

CC = os.environ.get('CC') or shutil.which('gcc')
RUSTC = os.environ.get('RUSTC') or shutil.which('rustc')


def exact_bits(text, width):
    """Independent binary search over all positive finite representable values."""
    exact = abs(Fraction(text))
    sign = int(text.startswith('-')) << (width - 1)
    maximum = 0x7f7fffff if width == 32 else 0x7fefffffffffffff
    lo, hi = 0, maximum
    while lo < hi:
        midpoint = (lo + hi + 1) // 2
        if rational_bits(midpoint, width) <= exact:
            lo = midpoint
        else:
            hi = midpoint - 1
    upper = rational_bits(lo + 1, width) if lo < maximum else (
        2 * rational_bits(lo, width) - rational_bits(lo - 1, width))
    midpoint = (rational_bits(lo, width) + upper) / 2
    return sign | (lo + int(exact > midpoint or exact == midpoint and lo & 1))


def source_rows():
    # These distinctions disappear if the source is first rounded to binary64.
    rows = []
    for width, spellings in (
        (32, ('1.00000005960464477', '1.000000059604644775390625',
              '1.000000059604644775390625000001',
              '1.000000178813934326171874999999',
              '1.000000178813934326171875',
              '0.499999985098838806152343749999',
              '0.49999998509883880615234375',
              '7.00649232162408535461864791644958065640130970938257885878534141944895541342930300743319094181060791015625e-46',
              '7.00649232162408535461864791644958065640130970938257885878534141944895541342930300743319094181060791015624e-46',
              '7.00649232162408535461864791644958065640130970938257885878534141944895541342930300743319094181060791015626e-46',
              '3.40282356779733661637539395458142568447e38',
              '0.0')),
        (64, ('1.00000000000000011102230246251565404236316680908203125',
              '1.000000000000000111022302462515654042363166809082031251',
              '2.2250738585072011360574097967091319759348195463516456480234261096e-308',
              '0.0'))):
        for text in spellings:
            rows.extend(((width, text), (width, '-' + text)))
    return rows


def frontend(rows):
    program = parse('\n'.join(
        f'export "C" fn source_{i}() -> f{width} effects {{}} {{ return {text}; }}'
        for i, (width, text) in enumerate(rows)))
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return program, checked


class SourceFloatRoundingTests(unittest.TestCase):
    def test_exact_rounder_at_independent_binary_midpoint_neighbours(self):
        from hepta.float_literals import round_source_float
        rng = random.Random(20261103)
        with localcontext() as context:
            context.prec = 1200
            for width, maximum, normal, one in ((32, 0x7f7fffff, 0x00800000, 0x3f800000),
                                                (64, 0x7fefffffffffffff, 0x0010000000000000,
                                                 0x3ff0000000000000)):
                patterns = [0, 1, 2, normal - 1, normal, one - 1, one,
                            one + 1, maximum - 1, maximum]
                patterns += [rng.randrange(maximum) for _ in range(64)]
                for pattern in patterns:
                    lower = rational_bits(pattern, width)
                    upper = (rational_bits(pattern + 1, width) if pattern < maximum
                             else 2 * lower - rational_bits(pattern - 1, width))
                    midpoint = (lower + upper) / 2
                    decimal = Decimal(midpoint.numerator) / Decimal(midpoint.denominator)
                    spelling = format(decimal, 'f')
                    places = len(spelling.partition('.')[2])
                    epsilon = Decimal(1).scaleb(-places - 2)
                    for neighbour in (decimal - epsilon, decimal, decimal + epsilon):
                        for sign in ('', '-'):
                            text = sign + format(neighbour, 'f')
                            expected = exact_bits(text, width)
                            with self.subTest(width=width, pattern=pattern, text=text[:40]):
                                if expected & ((1 << (width - 1)) - 1) == maximum + 1:
                                    with self.assertRaises(OverflowError):
                                        round_source_float(text, f'f{width}')
                                else:
                                    observed = round_source_float(text, f'f{width}')
                                    bits = int.from_bytes(struct.pack('>f' if width == 32 else '>d', observed), 'big')
                                    self.assertEqual(bits, expected)

    def test_parser_retains_original_spelling_and_checker_rounds_at_type(self):
        program = parse('fn f() -> f32 effects {} { return 1.00000005960464477; }')
        expr = program.functions[0].body[0].data['expr']
        self.assertEqual(expr.literal_text, '1.00000005960464477')
        checked = check(program)
        self.assertTrue(checked.ok)
        self.assertEqual(expr.value, 1.0)
        self.assertTrue(check(program).ok)
        self.assertEqual(expr.value, 1.0)
        # A fresh type check reads the spelling again, not its last f32 value.
        program.functions[0].return_type = Type('f64')
        self.assertTrue(check(program).ok)
        self.assertEqual(expr.value, float(expr.literal_text))

    def test_typed_snapshot_and_all_emitters_share_resolved_value(self):
        program, checked = frontend([(32, '1.00000005960464477')])
        snapshot = lower_checked_program(program, checked)
        literal = snapshot['functions'][0]['body'][0]['data']['expr']
        self.assertEqual((literal['type'], literal['value']), ('f32', 1.0))
        self.assertIn('1.0f32', emit_rust(program, checked, crate_type='staticlib'))
        self.assertIn('1.0f)', emit_c(program, checked, crate_type='staticlib'))

    def test_contexts_and_explicit_cast_keep_their_distinct_meaning(self):
        source = '''
            fn identity(x: f32) -> f32 effects {} { return x; }
            fn inferred() -> f32 effects {} {
                let x: f32 = 1.00000005960464477;
                return identity(x + 1.00000005960464477);
            }
            fn casted() -> f32 effects {} { return 1.00000005960464477 as f32; }
        '''
        program = parse(source)
        checked = check(program)
        self.assertTrue(checked.ok, checked.diagnostics)
        first = program.functions[1].body[0].data['expr']
        cast_child = program.functions[2].body[0].data['expr'].children[0]
        self.assertEqual(first.value, 1.0)
        self.assertEqual(checked.expr_types[id(cast_child)], Type('f64'))
        self.assertEqual(cast_child.value, float('1.00000005960464477'))

    def test_separators_spans_and_extreme_underflow(self):
        source = 'fn f() -> f32 effects {} { return 1.000_000_059_604_644_77; }'
        program = parse(source, 'literal.hepta')
        expr = program.functions[0].body[0].data['expr']
        self.assertEqual(expr.literal_text, '1.00000005960464477')
        self.assertEqual(source[expr.span.start:expr.span.end], '1.000_000_059_604_644_77')
        self.assertTrue(check(program).ok)
        self.assertEqual(expr.value, 1.0)
        program, checked = frontend([(32, '1e-9999'), (64, '1e-9999')])
        self.assertTrue(checked.ok)
        self.assertEqual([f.body[0].data['expr'].value for f in program.functions], [0.0, 0.0])

    def test_frontend_rejects_target_overflow_and_malformed_spelling(self):
        for text in ('3.40282356779733661637539395458142568448e38', '1e39'):
            with self.subTest(text=text):
                program = parse(f'fn f() -> f32 effects {{}} {{ return {text}; }}')
                checked = check(program)
                self.assertFalse(checked.ok)
                self.assertIn('E_FLOAT_RANGE', [d.code for d in checked.diagnostics])
        for text in ('NaN', 'Infinity', '1;abort()', '1e', '9' * 4097):
            with self.subTest(text=text[:20]):
                program = parse('fn f() -> f32 effects {} { return 1.0; }')
                program.functions[0].body[0].data['expr'].literal_text = text
                self.assertFalse(check(program).ok)
        # Constructed AST payloads without source spelling remain supported.
        program = parse('fn f() -> f32 effects {} { return 1.0; }')
        program.functions[0].body[0].data['expr'] = Expr('float', 1)
        self.assertTrue(check(program).ok)

    @unittest.skipUnless(CC, 'GCC required')
    def test_real_c_source_rounding_at_o0_o3_with_ubsan(self):
        rows = source_rows()
        program, checked = frontend(rows)
        harness = ['int main(void) {']
        for i, (width, _) in enumerate(rows):
            typ = 'float' if width == 32 else 'double'
            harness.append(f'{typ} v{i}=source_{i}(); uint{width}_t b{i}; '
                           f'memcpy(&b{i},&v{i},sizeof b{i}); printf("%" PRIu{width} "\\n", b{i});')
        harness.append('return 0; }')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.c'
            source.write_text(emit_c(program, checked, crate_type='staticlib') + '\n' + '\n'.join(harness))
            for optimization in ('-O0', '-O3'):
                executable = root / 'native'
                result = subprocess.run([CC, '-std=c11', optimization, '-fexcess-precision=standard',
                    '-fsanitize=undefined', '-fno-sanitize-recover=all', str(source), '-lm', '-o', str(executable)],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual([int(x) for x in run.stdout.split()], [exact_bits(t, w) for w, t in rows])

    @unittest.skipUnless(RUSTC, 'Rust reference required')
    def test_real_rust_matches_source_oracle_and_untranslated_literals(self):
        rows = source_rows()
        program, checked = frontend(rows)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.rs'
            direct = '\n'.join(f'fn direct_{i}() -> f{w} {{ {t}f{w} }}' for i, (w, t) in enumerate(rows))
            main = 'fn main() {\n' + '\n'.join(
                f'println!("{{}} {{}}", h_source_{i}().to_bits(), direct_{i}().to_bits());'
                for i in range(len(rows))) + '\n}'
            source.write_text(emit_rust(program, checked, crate_type='staticlib') + direct + main)
            executable = root / 'native'
            result = subprocess.run([RUSTC, '--edition=2021', str(source), '-o', str(executable)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual([tuple(map(int, row.split())) for row in run.stdout.splitlines()],
                             [(exact_bits(t, w), exact_bits(t, w)) for w, t in rows])


if __name__ == '__main__':
    unittest.main()
