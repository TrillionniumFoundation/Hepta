"""C scalar float-to-integer saturation without out-of-range C conversions."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.backend import compile_rust, emit_rust
from hepta.c_backend import compile_c, emit_c
from hepta.checker import check
from hepta.parser import parse
from hepta.pipeline import analyze_project
import test_c_fieldless_enums as fieldless

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ('i8', 'u8', 'i16', 'u16', 'i32', 'u32', 'i64', 'u64', 'isize', 'usize')


class FloatIntCastTests(unittest.TestCase):
    setUp = fieldless.FieldlessEnumTests.setUp
    frontend = fieldless.FieldlessEnumTests.frontend

    def execute(self, source, *, project=None):
        if project is None:
            program, checked = self.frontend(source)
        else:
            result = analyze_project(project, backend='c', native=False, crate_type='bin')
            self.assertTrue(result.report['ok'], result.report)
            program, checked = result.program, result.checked
        generated = emit_c(program, checked)
        rust = emit_rust(program, checked, crate_type='bin')
        for optimize in (False, True):
            report = compile_c(generated, output=self.root/'native', optimize=optimize,
                               sanitize=True, link_args=['-fsanitize=float-cast-overflow'])
            self.assertTrue(report['ok'], report)
            self.assertFalse(report['rustc_used'])
            run = subprocess.run([report['artifact']], capture_output=True, timeout=10)
            self.assertEqual((run.returncode, run.stdout, run.stderr), (0, b'', b''))
        if os.environ.get('HEPTA_ENUM_REQUIRE_RUST') == '1':
            compiler = os.environ.get('RUSTC') or shutil.which('rustc')
            self.assertTrue(compiler, 'Native Rust required but unavailable')
            version = subprocess.run([compiler, '--version'], capture_output=True, text=True, timeout=10)
            self.assertTrue(version.returncode == 0 and version.stdout.startswith('rustc 1.90.0 '), version)
            for optimize in (False, True):
                report = compile_rust(rust, rustc=compiler, crate_type='bin', optimize=optimize, output=self.root/'rust')
                self.assertTrue(report['ok'], report)
                run = subprocess.run([report['artifact']], capture_output=True, timeout=10)
                self.assertEqual((run.returncode, run.stdout, run.stderr), (0, b'', b''))
        return generated

    def test_rust_success_consumer_requests_binary_without_native_rust(self):
        """Mocked Rust call contract only; both C compilations/runs stay real."""
        original_run = subprocess.run
        calls = []
        executions = []
        compiler = 'mocked-rust-success-contract'
        artifact = str(self.root / 'mocked-rust-contract-not-an-executable')

        def compile_contract(source, **kwargs):
            self.assertEqual(kwargs.get('crate_type'), 'bin')
            self.assertIn('fn main()', source)
            self.assertEqual(kwargs['rustc'], compiler)
            calls.append(kwargs['optimize'])
            return {'ok': True, 'artifact': artifact, 'crate_type': 'bin',
                    'rustc_crate_type': 'bin'}

        def run_contract(args, *positional, **kwargs):
            if args == [compiler, '--version']:
                return subprocess.CompletedProcess(args, 0, 'rustc 1.90.0 (mocked contract)\n', '')
            if args == [artifact]:
                executions.append(args)
                return subprocess.CompletedProcess(args, 0, b'', b'')
            return original_run(args, *positional, **kwargs)

        with patch.dict(os.environ, {'HEPTA_ENUM_REQUIRE_RUST': '1', 'RUSTC': compiler}), \
             patch(__name__ + '.compile_rust', side_effect=compile_contract), \
             patch('subprocess.run', side_effect=run_contract):
            self.execute('fn main()->Unit effects {panic} {assert((3.75 as i32)==3);}')
        self.assertEqual(calls, [False, True])
        self.assertEqual(executions, [[artifact], [artifact]])

    def test_every_float_integer_pair_truncates_both_signs(self):
        functions, assertions = [], []
        for source in ('f32', 'f64'):
            for target in TARGETS:
                name = source + '_' + target
                functions.append(f'fn {name}(x:{source})->{target} effects {{}} {{return x as {target};}}')
                negative = -3 if target.startswith('i') else 0
                assertions.append(f'assert({name}(3.875)==3);assert({name}(-3.875)=={negative});assert({name}(0.875)==0);assert({name}(-0.875)==0);')
        self.execute(''.join(functions)+'fn main()->Unit effects {panic} {'+''.join(assertions)+'}')

    def test_signed_limits_saturate_at_exact_power_of_two(self):
        functions, assertions = [], []
        for source in ('f32', 'f64'):
            for target in ('i8', 'i16', 'i32', 'i64', 'isize'):
                bits = 64 if target == 'isize' else int(target[1:])
                bound = 1 << (bits-1)
                name = source+'_'+target
                functions.append(f'fn {name}(x:{source})->{target} effects {{}} {{return x as {target};}}')
                assertions.append(f'assert({name}({float(bound)!r})=={bound-1});assert({name}(-{float(bound)!r})=={-bound});')
        self.execute(''.join(functions)+'fn main()->Unit effects {panic} {'+''.join(assertions)+'}')

    def test_unsigned_limits_and_negative_values_saturate(self):
        functions, assertions = [], []
        for source in ('f32', 'f64'):
            for target in ('u8', 'u16', 'u32', 'u64', 'usize'):
                bits = 64 if target == 'usize' else int(target[1:])
                bound = 1 << bits
                name = source+'_'+target
                functions.append(f'fn {name}(x:{source})->{target} effects {{}} {{return x as {target};}}')
                assertions.append(f'assert({name}({float(bound)!r})=={bound-1});assert({name}(-{float(bound)!r})==0);')
        self.execute(''.join(functions)+'fn main()->Unit effects {panic} {'+''.join(assertions)+'}')

    def test_nan_and_infinities_from_runtime_arithmetic(self):
        functions, assertions = [], []
        for source in ('f32', 'f64'):
            for target in TARGETS:
                bits = 64 if target in ('isize', 'usize') else int(target[1:])
                signed = target.startswith('i')
                low, high = (-(1 << (bits-1)), (1 << (bits-1))-1) if signed else (0, (1 << bits)-1)
                name = source+'_'+target
                functions.append(f'fn {name}(x:{source},y:{source})->{target} effects {{panic}} {{return (x/y) as {target};}}')
                assertions.append(f'assert({name}(0.0,0.0)==0);assert({name}(1.0,0.0)=={high});assert({name}(-1.0,0.0)=={low});')
        self.execute(''.join(functions)+'fn main()->Unit effects {panic} {'+''.join(assertions)+'}')

    def test_fractional_values_at_small_integer_boundaries(self):
        self.execute('''fn narrow(x:f64)->i8 effects {} {return x as i8;}
        fn byte(x:f32)->u8 effects {} {return x as u8;}
        fn main()->Unit effects {panic} {
            assert(narrow(127.999)==127);assert(narrow(-128.999)==-128);
            assert(narrow(128.001)==127);assert(narrow(-129.001)==-128);
            assert(byte(255.999)==255);assert(byte(256.001)==255);assert(byte(-0.999)==0);
        }''')

    def test_signed_zero_and_small_nonzero_values(self):
        self.execute('''fn f(x:f64)->i64 effects {} {return x as i64;}
        fn g(x:f32)->u64 effects {} {return x as u64;}
        fn main()->Unit effects {panic} {
            assert(f(0.0)==0);assert(f(-0.0)==0);assert(f(1.0e-300)==0);assert(f(-1.0e-300)==0);
            assert(g(0.0)==0);assert(g(-0.0)==0);assert(g(1.0e-30)==0);assert(g(-1.0e-30)==0);
        }''')

    def test_operand_evaluates_once_and_call_order_is_preserved(self):
        self.execute('''fn next(n:mut i32)->f64 effects {write,panic} {n=n+1;return 7.75;}
        fn pair(a:i32,b:i32)->i32 effects {panic} {return a*10+b;}
        fn main()->Unit effects {write,panic} {let mut n:i32=0;
            let a=next(mut n) as i32;assert(a==7);assert(n==1);
            assert(pair(next(mut n) as i32,next(mut n) as i32)==77);assert(n==3);
            assert(true || (next(mut n) as i32)==0);assert(n==3);
            assert(!(false && (next(mut n) as i32)==0));assert(n==3);
        }''')

    def test_aggregate_payload_and_match_cast_composition(self):
        self.execute('''struct Box<T>{value:T} enum Event<T>{Some(T),None}
        fn main()->Unit effects {write,panic} {
            let mut xs:[i16;2]=[2.75 as i16,-3.75 as i16];xs[1]=4.25 as i16;
            let b=Box::<Result<Event<u8>,i64>>{value:Result::Ok(Event::Some(999.0 as u8))};
            match b.value {Result::Ok(v)=>{match v {Event::Some(x)=>{assert(x==255);},Event::None=>{assert(false);}}},Result::Err(_)=>{assert(false);}}
            assert(xs[0]==2);assert(xs[1]==4);
        }''')

    def test_cross_module_cast_function_uses_existing_pipeline(self):
        (self.root/'convert.hepta').write_text('pub fn value(x:f64)->u8 effects {} {return x as u8;}')
        entry=self.root/'main.hepta'
        entry.write_text('import convert as c;fn main()->Unit effects {panic} {assert(c::value(999.0)==255);}')
        self.execute(None, project=entry)

    def test_all_twenty_helpers_are_unique_and_deterministic(self):
        source=''.join(f'fn f_{a}_{b}(x:{a})->{b} effects {{}} {{return x as {b};}}' for a in ('f32','f64') for b in TARGETS)
        p,c=self.frontend(source)
        code=emit_c(p,c,crate_type='obj')
        self.assertEqual(code,emit_c(p,c,crate_type='obj'))
        self.assertEqual(code.count('if (x != x) return 0;'),20)
        for a in ('f32','f64'):
            for b in TARGETS:self.assertEqual(code.count(f'__hepta_cb_{a}_to_{b}('),2)
        self.assertIn('FLT_MANT_DIG == 24 && DBL_MANT_DIG == 53',code)

    def test_wide_integer_cast_classes_remain_structurally_refused(self):
        for target in ('i128','u128'):
            p,c=self.frontend(f'fn f(x:f64)->{target} effects {{}} {{return x as {target};}}')
            with self.assertRaises(HeptaError) as error:emit_c(p,c,crate_type='obj')
            self.assertEqual(error.exception.diagnostic.code,'E_C_BACKEND_SUBSET')

    def test_frontend_non_numeric_cast_refusals_remain(self):
        for expression in ('true as i32','1 as bool','1.0 as bool'):
            result=check(parse(f'fn main()->Unit effects {{}} {{let x={expression};}}'))
            self.assertFalse(result.ok)
            self.assertIn('E_CAST',[d.code for d in result.diagnostics])

    def test_integer_only_source_does_not_require_float_profile(self):
        p,c=self.frontend('fn f(x:i32)->u8 effects {} {return x as u8;}')
        code=emit_c(p,c,crate_type='obj')
        self.assertNotIn('Float casts require',code)
        self.assertNotIn('if (x != x) return 0;',code)

    def test_cli_example_executes(self):
        run=subprocess.run([sys.executable,'-m','hepta','run',str(ROOT/'examples/c_float_int_casts.hepta'),'--backend','c'],cwd=ROOT,capture_output=True,timeout=60)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertNotIn(b'runtime error:',run.stderr)


if __name__ == '__main__': unittest.main()
