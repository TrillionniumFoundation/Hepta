"""Locked seven-module consumers of unchanged libraries and Copy-ADT compiler."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from hepta.ast import HeptaError
from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.packages import load_package,verify_lock,write_lock
from hepta.pipeline import analyze_project
ROOT=Path(__file__).resolve().parents[1]
CONTRACT='resources { heap_allocations = 0; may_block = false; may_suspend = false; may_spawn = false; }'
BACKEND=os.environ.get('HEPTA_TYPED_STDLIB_BACKEND','c')
ARR=lambda xs:'['+','.join(map(str,xs))+']'

def success(text='zé😀é\0',query=233):
    raw=text.encode();wire=base64.b64encode(len(raw).to_bytes(2,'big')+raw);ordered=sorted(map(ord,text))
    import bisect
    source=f'''let input:[u8;{len(wire)}]={ARR(wire)};
let mut scratch:[u8;{len(raw)+5}]={ARR([165]*(len(raw)+5))};
let mut scalars:[u64;{len(text)+3}]={ARR([999]*(len(text)+3))};
let result=typed::index_packet(read input,0,{len(wire)},mut scratch,mut scalars,{query});
match result {{Result::Ok(c)=>{{let done=c.done;assert(c.value.scalars=={len(text)});assert(c.value.lower=={1+bisect.bisect_left(ordered,query)});assert(c.value.upper=={1+bisect.bisect_right(ordered,query)});}},Result::Err(_)=>{{assert(false);}}}}
'''
    for name,expected in [('input',wire),('scratch',[165]+list(len(raw).to_bytes(2,'big')+raw)+[165,165]),('scalars',[999]+ordered+[999,999])]:
        source+=''.join(f'assert({name}[{i}]=={v});\n' for i,v in enumerate(expected))
    return source

class TypedStdlibTests(unittest.TestCase):
    def setUp(self):
        self.assertIn(BACKEND,('c','rust'))
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-typed-stdlib-test-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        shutil.copytree(ROOT/'stdlib',self.root/'stdlib')
        for name in ('typed_packet','typed_text'):
            shutil.copytree(ROOT/'examples/packages'/name,self.root/'examples/packages'/name)
        self.app=self.root/'examples/packages/typed_text'

    def source(self,body,prefix=''):
        (self.app/'src/main.hepta').write_text('import typed;\n'+prefix+'\nfn main()->Unit effects {panic,write,unsafe}\n'+CONTRACT+'\n{\n'+body+'\n}\n',encoding='utf-8')
        write_lock(self.app)

    def native(self):
        analysis=analyze_project(self.app,backend=BACKEND,crate_type='bin',locked=True)
        self.assertTrue(analysis.report['ok'],analysis.report);self.assertEqual(len(analysis.project.modules),7)
        for optimize in (False,True):
            artifact=self.root/('native-o3' if optimize else 'native-o0')
            build=(compile_c(analysis.c,output=artifact,optimize=optimize,sanitize=True) if BACKEND=='c' else compile_rust(analysis.rust,output=artifact,crate_type='bin',optimize=optimize))
            self.assertTrue(build['ok'],build)
            if BACKEND=='c':self.assertIn('-fno-sanitize-recover=all',build['flags'])
            run=subprocess.run([str(artifact)],capture_output=True,timeout=20)
            self.assertEqual((run.returncode,run.stdout,run.stderr),(0,b'',b''))
            path=os.environ.get('HEPTA_TYPED_STDLIB_RECEIPTS')
            if path:
                with open(path,'a',encoding='utf-8') as f:f.write(json.dumps({'method':self.id(),'backend':BACKEND,'optimize':optimize,'build':build,'returncode':run.returncode,'source_sha256':hashlib.sha256((self.app/'src/main.hepta').read_bytes()).hexdigest()},sort_keys=True)+'\n')

    def test_unicode_success_exact_buffers_and_unit(self):
        self.source(success());self.native()

    def test_empty_packet_and_repeated_scalar_bounds(self):
        self.source(success('',0));self.native()
        self.source(success('aaaa',97));self.native()

    def test_all_five_typed_errors_and_mutation_boundaries(self):
        cases=[(b'!!!!','Decode',None),(base64.b64encode(b'x'),'ShortHeader',b'x'),
               (base64.b64encode(b'\0\2a'),'LengthMismatch',b'\0\2a'),
               (base64.b64encode(b'\0\1\xff'),'InvalidText',b'\0\1\xff'),
               (base64.b64encode(b'\0\2aa'),'ScalarCapacity',b'\0\2aa')]
        parts=[]
        for i,(wire,error,decoded) in enumerate(cases):
            parts += [f'let w{i}:[u8;{len(wire)}]={ARR(wire)};let mut s{i}:[u8;8]={ARR([165]*8)};let mut u{i}:[u64;2]=[999,999];',
                      f'let r{i}=typed::index_packet(read w{i},0,{len(wire)},mut s{i},mut u{i},0);',
                      f'match r{i} {{ Result::Ok(_)=>{{assert(false);}},Result::Err(e)=>{{match e {{'+','.join('typed::PacketError::'+v+'(x)=>{'+('assert(x==2);' if v=='ScalarCapacity' and v==error else 'let unit=x;' if v==error else 'assert(false);')+'}' for v in ('Decode','ShortHeader','LengthMismatch','InvalidText','ScalarCapacity'))+'}}}',
                      f'assert(u{i}[0]==999 && u{i}[1]==999);']
            expected=[165]*8
            if decoded is not None:expected[1:1+len(decoded)]=decoded
            parts += [f'assert(s{i}[{j}]=={v});' for j,v in enumerate(expected)]
        self.source('\n'.join(parts));self.native()

    def test_result_copy_survives_later_call_and_raw_store(self):
        self.source('''let w:[u8;4]=[65,65,70,66];let bad:[u8;4]=[33,33,33,33];
let mut s:[u8;5]=[165,165,165,165,165];let mut u:[u64;3]=[999,999,999];
let original=typed::index_packet(read w,0,4,mut s,mut u,65);
let mut results:[Result<typed::Committed<typed::Bounds>,typed::PacketError>;1]=[original];
unsafe {store(ptr_mut(mut results),0,typed::index_packet(read bad,0,4,mut s,mut u,65));}
match original {Result::Ok(c)=>{assert(c.value.scalars==1);let x=c.done;},Result::Err(_)=>{assert(false);}}
match results[0] {Result::Ok(_)=>{assert(false);},Result::Err(e)=>{match e {
typed::PacketError::Decode(x)=>{let done=x;},typed::PacketError::ShortHeader(_)=>{assert(false);},typed::PacketError::LengthMismatch(_)=>{assert(false);},typed::PacketError::InvalidText(_)=>{assert(false);},typed::PacketError::ScalarCapacity(_)=>{assert(false);}}}}
assert(s[3]==65 && u[1]==65);''');self.native()

    def test_temporary_result_array_read_preserves_typed_value(self):
        prefix='''fn collect(w:read [u8],s:mut [u8],u:mut [u64])->[Result<typed::Committed<typed::Bounds>,typed::PacketError>;2] effects {write,panic} {
let r=typed::index_packet(read w,0,len(read w),mut s,mut u,65);return [r,r];}
'''
        self.source('''let w:[u8;4]=[65,65,70,66];let mut s:[u8;5]=[165,165,165,165,165];let mut u:[u64;3]=[999,999,999];
let result=collect(read w,mut s,mut u)[1];match result {Result::Ok(c)=>{assert(c.value.upper==2);let x=c.done;},Result::Err(_)=>{assert(false);}}
assert(s[3]==65 && u[1]==65);''',prefix);self.native()

    def test_locked_dependency_edits_reject_and_recover(self):
        self.source(success('abc',98));self.native()
        for library in ('bytes','base64','utf8','ordering'):
            path=self.root/'stdlib'/library/'src/lib.hepta';before=path.read_bytes()
            path.write_bytes(before+b'\n// changed component\n')
            with self.assertRaises(HeptaError) as caught:analyze_project(self.app,backend=BACKEND,crate_type='bin',locked=True)
            self.assertEqual(caught.exception.diagnostic.code,'E_LOCK_STALE')
            path.write_bytes(before);verify_lock(load_package(self.app))
        self.native()

    def test_relocated_seven_module_lock_executes(self):
        self.source(success('x\0é',120));lock=(self.app/'Hepta.lock').read_bytes()
        destination=self.root/'relocated';shutil.copytree(self.root/'stdlib',destination/'stdlib')
        shutil.copytree(self.root/'examples',destination/'examples')
        self.app=destination/'examples/packages/typed_text'
        self.assertEqual((self.app/'Hepta.lock').read_bytes(),lock);verify_lock(load_package(self.app));self.native()

    def test_nonexhaustive_typed_error_match_is_rejected(self):
        self.source('''let w:[u8;4]=[33,33,33,33];let mut s:[u8;5]=[0,0,0,0,0];let mut u:[u64;1]=[0];
match typed::index_packet(read w,0,4,mut s,mut u,0) {Result::Ok(_)=>{},Result::Err(e)=>{match e {typed::PacketError::Decode(_)=>{}}}}''')
        analysis=analyze_project(self.app,backend=BACKEND,crate_type='bin',locked=True)
        self.assertFalse(analysis.report['ok']);self.assertIsNone(analysis.c)
        self.assertEqual([d['code'] for d in analysis.report['diagnostics']],['E_MATCH_EXHAUSTIVE'])

    def test_public_cli_locked_example_executes(self):
        command=[sys.executable,'-B','-m','hepta','run',str(ROOT/'examples/packages/typed_text'),'--locked','--backend',BACKEND,'--json']
        run=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=120)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr);self.assertEqual(run.stderr,'')
        report=json.loads(run.stdout);self.assertTrue(report['ok'],report)

    def test_exact_component_sources_and_original_store_gate(self):
        sys.path.insert(0,str(ROOT/'tools'))
        from verify_typed_stdlib_sources import verify
        from verify_store_adt_sources import verify as inherited
        self.assertTrue(verify()['complete_pass']);self.assertTrue(inherited()['complete_pass'])
