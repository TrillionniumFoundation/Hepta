"""Actual native volatile access and an explicit unsafe Rust export boundary."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

from hepta.backend import compile_rust, find_rustc
from hepta.c_backend import compile_c
from hepta.pipeline import analyze, hsir_analysis, cfg_analysis, resource_ir_analysis, concurrent_ir_analysis

SOURCE = '''module volatile_registers;
export "C" fn write_read(registers: raw mut u32, index: usize, value: u32)->u32
 effects {unsafe,io,write} {
 unsafe { volatile_store(registers,index,value); return volatile_load(registers,index); }
}
export "C" fn read_twice(registers:raw const u32)->u32 effects {unsafe,io} {
 unsafe {let first=volatile_load(registers,0); let second=volatile_load(registers,0);
 return wrapping_add(first,second);}
}
'''


class VolatileTests(unittest.TestCase):
    def test_frontend_requires_unsafe_io_write_and_supported_register_type(self):
        rejected = {
            'outside_unsafe': SOURCE.replace('unsafe { volatile_store(registers,index,value); return volatile_load(registers,index); }', 'volatile_store(registers,index,value); return volatile_load(registers,index);'),
            'missing_io': SOURCE.replace('{unsafe,io,write}', '{unsafe,write}'),
            'missing_write': SOURCE.replace('{unsafe,io,write}', '{unsafe,io}'),
            'readonly_store': SOURCE.replace('registers: raw mut u32', 'registers: raw const u32'),
            'boolean_register': 'module bad;fn f(p:raw const bool)->bool effects {unsafe,io}{unsafe{return volatile_load(p,0);}}',
            'wide_register': 'module bad;fn f(p:raw const u128)->u128 effects {unsafe,io}{unsafe{return volatile_load(p,0);}}',
            'non_pointer': 'module bad;fn f(p:u32)->u32 effects {unsafe,io}{unsafe{return volatile_load(p,0);}}',
            'missing_value': 'module bad;fn f(p:raw mut u32)->Unit effects {unsafe,io,write}{unsafe{volatile_store(p,0);}}',
        }
        for name, source in rejected.items():
            with self.subTest(name=name):
                for backend in ('rust','c'):
                    result=analyze(source,native=False,backend=backend)
                    self.assertFalse(result.report['ok'],result.report)
                    self.assertTrue(result.report['diagnostics'])

    def test_actual_c_and_rust_access_valid_allocated_register_arrays(self):
        with tempfile.TemporaryDirectory(prefix='hepta-volatile-test-') as td:
            d=Path(td)
            c=analyze(SOURCE,backend='c');r=analyze(SOURCE)
            self.assertTrue(c.report['ok'],c.report);self.assertTrue(r.report['ok'],r.report)
            self.assertIn('volatile const uint32_t',c.c)
            self.assertIn('wrapping_add',r.rust)
            c_driver='''\nint main(void) {uint32_t values[3]={11,22,33};
 if(write_read(values,1,99)!=99||read_twice(values)!=22) return 1;
 if(values[0]!=11||values[1]!=99||values[2]!=33) return 2;
 return 0;}\n'''
            rust_driver='''\nfn main(){let mut values=[11u32,22,33];
 unsafe {assert_eq!(h_write_read(values.as_mut_ptr(),1,99),99);assert_eq!(h_read_twice(values.as_ptr()),22);}
 assert_eq!(values,[11,99,33]);}\n'''
            cb=compile_c(c.c+c_driver,output=d/'c',crate_type='bin',sanitize=True)
            rb=compile_rust(r.rust+rust_driver,output=d/'rust',crate_type='bin')
            self.assertTrue(cb['ok'],cb);self.assertTrue(rb['ok'],rb)
            for p in ('c','rust'):
                result=subprocess.run([str(d/p)],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)

    def test_exported_unsafe_obligations_are_not_a_safe_rust_api(self):
        source='''module unsafe_api;
export "C" fn write_one(data:raw mut u32)->Unit effects {unsafe,write} {
 unsafe {store(data,0,7);}
}
pub fn read_one(data:raw const u32)->u32 effects {unsafe} {unsafe{return load(data,0);}}
pub fn pure(value:u32)->u32 effects {} {return value;}
'''
        analysis=analyze(source)
        self.assertTrue(analysis.report['ok'],analysis.report)
        self.assertIn('pub unsafe extern "C" fn h_write_one',analysis.rust)
        self.assertIn('pub unsafe fn h_read_one',analysis.rust)
        self.assertIn('pub fn h_pure',analysis.rust)
        with tempfile.TemporaryDirectory(prefix='hepta-unsafe-api-test-') as td:
            d=Path(td);lib=d/'libhepta_program.rlib'
            built=compile_rust(analysis.rust,output=lib,crate_type='rlib')
            self.assertTrue(built['ok'],built)
            consumer='''extern crate hepta_program;fn main(){let mut x=1u32;
 hepta_program::h_write_one(&mut x);assert_eq!(hepta_program::h_read_one(&x),7);}
'''
            path=d/'consumer.rs';path.write_text(consumer)
            argv=[find_rustc(),str(path),'--edition=2021','-C','panic=abort','--extern','hepta_program='+str(lib),'-o',str(d/'consumer')]
            rejected=subprocess.run(argv,capture_output=True,text=True,timeout=30)
            self.assertNotEqual(rejected.returncode,0)
            self.assertIn('E0133',rejected.stderr)
            # Only the valid-array caller with an explicit unsafe acknowledgement executes.
            path.write_text(consumer.replace('hepta_program::h_write_one(&mut x);assert_eq!(hepta_program::h_read_one(&x),7);','unsafe {hepta_program::h_write_one(&mut x);assert_eq!(hepta_program::h_read_one(&x),7);}'))
            accepted=subprocess.run(argv,capture_output=True,text=True,timeout=30)
            self.assertEqual(accepted.returncode,0,accepted.stderr)
            self.assertEqual(subprocess.run([str(d/'consumer')],timeout=10).returncode,0)

    def test_optimized_llvm_retains_two_volatile_reads(self):
        result=analyze(SOURCE)
        self.assertTrue(result.report['ok'],result.report)
        with tempfile.TemporaryDirectory(prefix='hepta-volatile-ir-') as td:
            d=Path(td);source=d/'code.rs';source.write_text(result.rust);ir=d/'code.ll'
            built=subprocess.run([find_rustc(),str(source),'--edition=2021','--crate-type=lib','--emit=llvm-ir','-C','opt-level=3','-o',str(ir)],capture_output=True,text=True,timeout=30)
            self.assertEqual(built.returncode,0,built.stderr)
            text=ir.read_text();start=text.index('define ');body=text[text.index('@read_twice(',start):];body=body[:body.index('\n}')]
            self.assertEqual(body.count('load volatile i32'),2,body)
            self.assertIn('store volatile i32',text)

    def test_no_std_allows_volatile_io_but_still_rejects_hosted_printing(self):
        allowed=analyze(SOURCE,target='thumbv7em-none-eabi',no_std=True)
        self.assertTrue(allowed.report['ok'],allowed.report)
        self.assertIn('#![no_std]',allowed.rust)
        forbidden=analyze('fn f()->Unit effects {io,alloc,block,panic}{print_i64(1);}',no_std=True,native=False)
        self.assertFalse(forbidden.report['ok'])
        self.assertIn('E_NO_STD',[d['code'] for d in forbidden.report['diagnostics']])
        self.assertFalse(analyze(SOURCE,no_std=True,backend='c',native=False).report['ok'])

    def test_volatile_sites_are_external_obligations_not_ir_proofs(self):
        result=analyze(SOURCE,native=False)
        hsir=hsir_analysis(result)['hsir'];cfg=cfg_analysis(result)['cfg']
        self.assertEqual(len(hsir['volatile_accesses']),4)
        self.assertEqual(hsir['volatile_accesses'],cfg['volatile_accesses'])
        for site in hsir['volatile_accesses']:
            self.assertEqual(site['status'],'external_obligation_not_proved')
            self.assertIn('no_atomic_or_fence_guarantee',site['requirements'])
        self.assertTrue(all('volatile_access' in item['reasons'] for item in hsir['external_obligations']))
        self.assertTrue(all(value is False for value in hsir['claims'].values()))
        self.assertFalse(resource_ir_analysis(result)['ok'])
        self.assertFalse(concurrent_ir_analysis(result)['ok'])

    def test_public_unsafe_binary_entry_has_an_explicit_process_root(self):
        result=analyze('pub fn main()->i32 effects {unsafe}{unsafe{} return 0;}',crate_type='bin')
        self.assertTrue(result.report['ok'],result.report)
        self.assertIn('pub unsafe fn h_main',result.rust)
        self.assertIn('std::process::exit(unsafe { h_main() })',result.rust)


if __name__=='__main__':unittest.main()
