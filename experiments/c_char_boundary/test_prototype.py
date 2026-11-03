"""Named adversarial tests for the experimental, not-production char profile."""
from dataclasses import replace
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust, emit_rust
from hepta.c_backend import compile_c
from hepta.c_import import import_header
from hepta.pipeline import analyze_project
from .prototype import Prepared, Rejected, MODES, compiler_driver, digest, run

CC = os.environ.get('CC') or shutil.which('gcc')
RUSTC = os.environ.get('RUSTC') or shutil.which('rustc')
EFFECTS = 'ffi,unsafe,alloc,block,panic,io,write,spawn'


@unittest.skipUnless(CC, 'GCC required')
class CharPrototypeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-char-cases-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture(self, header='#include <stddef.h>\nsize_t strlen(const char *s);\n',
                body=None, mode='default'):
        header_path=self.root/'api.h';header_path.write_text(header)
        driver=compiler_driver(self.root,CC,mode)
        imported=import_header(header_path,cc=str(driver),module='native')
        typ=imported.manifest['primitive_types']['char']['hepta']
        if body is None:
            body='let bytes:[@CHAR@;3]=[65,66,0]; unsafe {assert(native::strlen(ptr_read(read bytes))==2);}'
        binding=self.root/'native.hepta';binding.write_text(imported.source)
        self.sidecar=binding.with_suffix('.hepta.imports.json')
        self.sidecar.write_text(json.dumps(imported.manifest))
        entry=self.root/'main.hepta'
        entry.write_text('import native; fn main()->Unit effects {'+EFFECTS+'} {'+body.replace('@CHAR@',typ)+'}')
        return entry,typ

    def prepared(self,*args,**kwargs):
        mode=kwargs.get('mode','default')
        entry,typ=self.fixture(*args,**kwargs)
        prepared=Prepared(entry,cc=CC,char_mode=mode)
        self.addCleanup(prepared.close)
        return prepared,typ

    def execute(self,p, native=None, expected='', *, opt=False,lto=False):
        exe,receipt=p.compile(optimize=opt,native_source=native,lto=lto,strict_aliasing=True)
        self.assertEqual(run([exe]),expected)
        self.assertFalse(receipt['foreign_binary_authenticated'])
        self.assertFalse(receipt['atomic_system_snapshot'])
        self.assertTrue(receipt['dependencies_observed_after_compile'])
        return receipt

    def mutation_compile(self,p,source, *, includes=()):
        file=self.root/'mutation.c';file.write_text(source)
        result=subprocess.run([CC,'-std=c11','-O3',*MODES[p.context.char_mode],*includes,
                               '-Werror=incompatible-pointer-types','-c',str(file),'-o',str(self.root/'mutation.o')],
                              capture_output=True,text=True,timeout=30)
        return result

    def test_strlen_original_header(self):
        p,_=self.prepared()
        old=analyze_project(self.root/'main.hepta',backend='c')
        self.assertFalse(old.report['ok'])
        self.assertEqual(old.report['diagnostics'][0]['code'],'E_C_COMPILE')
        for opt in [False,True]:self.execute(p,opt=opt)

    def test_puts_original_header(self):
        p,_=self.prepared('int puts(const char *s);',
                         'let bytes:[@CHAR@;3]=[65,66,0]; unsafe {let result=native::puts(ptr_read(read bytes)); assert(result>=0);}')
        for opt in [False,True]:self.execute(p,expected='AB\n',opt=opt)

    def test_scalar_char_extrema(self):
        for mode,lo,hi in [('signed',-128,127),('unsigned',0,255)]:
            p,_=self.prepared('char echo_char(char x);',
                             f'unsafe {{assert(native::echo_char({lo})=={lo}); assert(native::echo_char({hi})=={hi});}}',mode=mode)
            for opt in [False,True]:self.execute(p,'char echo_char(char x){return x;}',opt=opt)

    def test_mutable_and_const_char_pointer(self):
        p,_=self.prepared('char update_char(char *p); char read_char(const char *p);',
            'let mut bytes:[@CHAR@;2]=[65,0]; unsafe {assert(native::read_char(ptr_read(read bytes))==65); assert(native::update_char(ptr_mut(mut bytes))==65); assert(native::read_char(ptr_read(read bytes))==7);}')
        impl='char update_char(char *p){char x=*p;*p=7;return x;} char read_char(const char *p){return *p;}'
        for opt in [False,True]:self.execute(p,impl,opt=opt)

    def test_returned_and_null_char_pointer(self):
        p,_=self.prepared('char *next_char(char *p); const char *read_next(const char *p); char *null_char(char x); char is_null(char *p);',
            'let mut bytes:[@CHAR@;3]=[65,66,0]; unsafe {let p=native::next_char(ptr_mut(mut bytes)); assert(load(p,0)==66); let q=native::read_next(ptr_read(read bytes)); assert(load(q,0)==66); assert(native::is_null(native::null_char(0))==1);}')
        impl='char *next_char(char*p){return p+1;} const char *read_next(const char*p){return p+1;} char *null_char(char x){(void)x;return (char*)0;} char is_null(char*p){return p==(char*)0;}'
        for opt in [False,True]:self.execute(p,impl,opt=opt)

    def test_signedness_flag_variants(self):
        receipts=[]
        for mode in ['default','signed','unsigned']:
            p,typ=self.prepared(mode=mode)
            r=self.execute(p,opt=True)
            self.assertEqual(p.context.char_signed,typ=='i8')
            self.assertTrue(all(f in r['flags'] for f in MODES[mode]))
            receipts.append(r)
        self.assertNotEqual(receipts[1]['flags'],receipts[2]['flags'])

    def test_adapter_local_symbols(self):
        p,_=self.prepared();self.execute(p)
        symbols=run(['nm','-g',str(p.directory/'unit-0.o')])
        self.assertIn(' U strlen',symbols)
        self.assertNotIn('__hepta_char_adapter_',symbols)
        local=run(['nm',str(p.directory/'unit-0.o')])
        self.assertIn(' t __hepta_char_adapter_',local)

    def test_original_multi_tu_lto(self):
        p,_=self.prepared('char echo_char(char x);','unsafe {assert(native::echo_char(73)==73);}')
        r=self.execute(p,'char echo_char(char x){return x;}',opt=True,lto=True)
        self.assertIn('-Werror=lto-type-mismatch',r['flags'])
        self.assertIn('-fstrict-aliasing',r['flags'])
        self.assertTrue(any(x.endswith('native.c') for x in r['dependencies_observed_after_compile']))
        self.assertTrue(any(x.endswith('program.c') for x in r['dependencies_observed_after_compile']))

    def test_changed_generated_source(self):
        p,_=self.prepared();binding=self.root/'native.hepta';binding.write_text(binding.read_text()+'\n')
        with self.assertRaises((Rejected,HeptaError)):p.compile()

    def test_changed_header(self):
        p,_=self.prepared();(self.root/'api.h').write_text('size_t strlen(char *s);')
        with self.assertRaises(Rejected):p.compile()

    def test_changed_actual_prototype(self):
        p,_=self.prepared('#ifndef SAMPLE_H\n#define SAMPLE_H\nchar echo_char(char x);\n#endif',
                          'unsafe {assert(native::echo_char(1)==1);}')
        r=self.mutation_compile(p,'#define SAMPLE_H\nint echo_char(int x);\n'+p._source())
        self.assertNotEqual(r.returncode,0);self.assertIn('native prototype',r.stderr)

    def test_changed_actual_typedef(self):
        p,_=self.prepared('#ifndef SAMPLE_H\n#define SAMPLE_H\ntypedef char Text; Text echo_char(Text x);\n#endif',
                          'unsafe {assert(native::echo_char(1)==1);}')
        r=self.mutation_compile(p,'#define SAMPLE_H\ntypedef short Text; Text echo_char(Text x);\n'+p._source())
        self.assertNotEqual(r.returncode,0);self.assertIn('native typedef',r.stderr)

    def test_forged_char_mapping(self):
        entry,_=self.fixture();m=json.loads(self.sidecar.read_text());m['primitive_types']['char']['hepta']='u16';self.sidecar.write_text(json.dumps(m))
        with self.assertRaises(Rejected):Prepared(entry,cc=CC)

    def test_wrong_host_or_target(self):
        for key in ['host','target']:
            entry,_=self.fixture();m=json.loads(self.sidecar.read_text());m[key]='wrong';self.sidecar.write_text(json.dumps(m))
            with self.assertRaises((Rejected,HeptaError)):Prepared(entry,cc=CC)

    def test_missing_header(self):
        entry,_=self.fixture();(self.root/'api.h').unlink()
        with self.assertRaises(Rejected):Prepared(entry,cc=CC)

    def test_char_double_pointer(self):
        for text in ['char read_char(char **p);','typedef char *Text; char read_char(Text p);']:
            entry,_=self.fixture(text,'')
            with self.assertRaises(Rejected):Prepared(entry,cc=CC)

    def test_record_or_array_boundary(self):
        for text in ['struct R {char value;}; char echo_char(char x);','struct R {char value[2];}; char echo_char(char x);']:
            entry,_=self.fixture(text,'')
            with self.assertRaises(Rejected):Prepared(entry,cc=CC)

    def test_variadic_function_pointer_atomic_volatile(self):
        for text in ['char f(char x,...);','char f(char (*p)(char));','char f(volatile char *p);','char f(_Atomic char *p);']:
            with self.assertRaises((Rejected,HeptaError)):self.fixture(text,'')

    def test_stale_flags_context(self):
        p,_=self.prepared();p.context=replace(p.context,char_mode='unsigned' if p.context.char_mode!='unsigned' else 'signed')
        with self.assertRaises(Rejected):p.compile()

    def test_late_flag_override(self):
        p,_=self.prepared()
        with self.assertRaises(TypeError):p.compile(extra_flags=['-funsigned-char'])

    def test_export_misrouting(self):
        entry,_=self.fixture();binding=self.root/'native.hepta';text=binding.read_text().replace('extern "C"','export "C"').rsplit(';',1)[0]+' {return 0;}\n'
        binding.write_text(text);m=json.loads(self.sidecar.read_text());m['source_sha256']=digest(text.encode());self.sidecar.write_text(json.dumps(m))
        with self.assertRaises((Rejected,HeptaError)):Prepared(entry,cc=CC)

    def test_ordinary_byte_apis(self):
        entry,_=self.fixture('signed char byte_echo(signed char x);','unsafe {assert(native::byte_echo(73)==73);}')
        with self.assertRaises(Rejected):Prepared(entry,cc=CC)
        analysis=analyze_project(entry,backend='c',native=False,crate_type='bin');self.assertTrue(analysis.report['ok'])
        c=self.root/'byte.c';c.write_text('signed char byte_echo(signed char x){return x;}')
        native=compile_c(analysis.c,output=self.root/'byte',link_args=[str(c)],sanitize=True)
        self.assertTrue(native['ok'],native);self.assertEqual(run([native['artifact']]),'')

    def test_v1_and_low_level_apis(self):
        entry,_=self.fixture();old=analyze_project(entry,backend='c');self.assertFalse(old.report['ok']);self.assertEqual(old.report['diagnostics'][0]['code'],'E_C_COMPILE')
        self.sidecar.unlink()
        with self.assertRaises(HeptaError):Prepared(entry,cc=CC)

    def test_foreign_obligations(self):
        p,_=self.prepared();r=self.execute(p)
        self.assertFalse(r['foreign_binary_authenticated']);self.assertFalse(r['atomic_system_snapshot'])
        self.assertTrue(all('ffi' in f.effects for f in p.program.functions if f.extern_c))

    def test_noncharacter_byte_representation(self):
        p,_=self.prepared();source=re.sub(r'\bint8_t\b','__hepta_fake_i8',p._source())
        r=self.mutation_compile(p,'typedef short __hepta_fake_i8;\n'+source)
        self.assertNotEqual(r.returncode,0);self.assertIn('i8 character representation',r.stderr)

    def test_adapter_header_namespace_collision(self):
        p,_=self.prepared('typedef char __hepta_char_adapter_0; char echo_char(char x);','unsafe {assert(native::echo_char(7)==7);}')
        self.assertNotEqual(p.context.boundaries[0].adapter,'__hepta_char_adapter_0')
        self.execute(p,'char echo_char(char x){return x;}')

    def test_successful_probe_then_dependency_drift(self):
        p,_=self.prepared('#ifndef SAMPLE_H\n#define SAMPLE_H\ntypedef char Text; Text echo_char(Text x);\n#endif',
                          'unsafe {assert(native::echo_char(1)==1);}')
        source=p._source();original_hash=p.context.header_hash
        dependency=self.root/'controlled-include.h';dependency.write_text('/* fixed search path, initially empty */\n')
        command=('-include',str(dependency))
        first=self.mutation_compile(p,source,includes=command);self.assertEqual(first.returncode,0,first.stderr)
        dependency.write_text('#define SAMPLE_H\ntypedef short Text; Text echo_char(Text x);\n')
        second=self.mutation_compile(p,source,includes=command)
        self.assertEqual(digest(p.snapshot.read_bytes()),original_hash)
        self.assertNotEqual(second.returncode,0);self.assertIn('native typedef',second.stderr)

    def test_const_typedef_and_return_erasure(self):
        entry,_=self.fixture('typedef const char Text; Text *return_text(Text *p);','')
        binding=self.root/'native.hepta';text=binding.read_text().replace('raw const','raw mut');binding.write_text(text)
        m=json.loads(self.sidecar.read_text());m['source_sha256']=digest(text.encode());self.sidecar.write_text(json.dumps(m))
        with self.assertRaises(Rejected):Prepared(entry,cc=CC)

    def test_native_implementation_flags_bound(self):
        p,_=self.prepared('char echo_char(char x);','unsafe {assert(native::echo_char(255)==255);}',mode='unsigned')
        r=self.execute(p,'char echo_char(char x){return x;}',opt=True,lto=True)
        self.assertIn('-funsigned-char',r['flags']);self.assertIsNotNone(r['native_source_sha256'])

    @unittest.skipUnless(RUSTC and Path(RUSTC).is_file(),'actual Rust required')
    def test_actual_rust_reference(self):
        for mode in ['signed','unsigned']:
            p,_=self.prepared(mode=mode)
            exe=self.root/'rust'
            result=compile_rust(emit_rust(p.program,p.checked,crate_type='bin'),rustc=RUSTC,crate_type='bin',output=exe)
            self.assertTrue(result['ok'],result);self.assertEqual(run([exe]),'')
            lo,hi=(-128,127) if mode=='signed' else (0,255)
            p,_=self.prepared('char echo_char(char x);',
                f'unsafe {{assert(native::echo_char({lo})=={lo}); assert(native::echo_char({hi})=={hi});}}',mode=mode)
            self.execute(p,'char echo_char(char x){return x;}',opt=True)
            result=compile_rust(emit_rust(p.program,p.checked,crate_type='bin'),rustc=RUSTC,
                crate_type='bin',output=exe,link_args=[str(p.directory/'unit-1.o'),'-lubsan'],linker=CC)
            self.assertTrue(result['ok'],result);self.assertEqual(run([exe]),'')
