"""Independent byte witnesses, malformed facts and actual Core module projects."""
import builtins
import copy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import struct
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from hepta.hia_core_module_graph_native import (
    MAGIC, RESULT, NONE, SOURCE, NativeCoreModuleGraph, CoreModuleRejected,
    WORKSPACE_SCHEMA, encode_workspace, link_workspace,
)
ROOT = Path(__file__).resolve().parents[1]

def independent_case():
    # Complete packet and result bytes authored without the encoder/resolver.
    raw = struct.pack('<10Q', MAGIC,2,2,1,1,2,16,0,3,0)
    raw += struct.pack('<8Q', 0,3,0,1, 3,3,1,1)
    raw += struct.pack('<8Q', 0,6,4,0, 1,10,3,0)
    raw += struct.pack('<7Q', 0,13,3,3,3,10,3)
    raw += struct.pack('<3Q', 0,13,3)
    raw += struct.pack('<6Q', 0,6,4, 1,10,3)
    raw += b'applibmainincuse'
    expected = struct.pack('<14Q',RESULT,2,2,1,1,2,0,0, 1,0, 1, 1, 0,NONE)
    return raw, expected

def vm(raw, capacity):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    body, owners, views = Body(0), [], []
    for size, initial in ((len(raw),raw),(capacity,bytes([90])*capacity),(8192,b'')):
        owner=body.value('buffer','buffer.new',[body.const('usize',size)])
        view=body.value('mutbuf','borrow.mut',[owner])
        for i, x in enumerate(initial):
            if x: body.effect('buffer.store',[view,body.const('usize',i),body.const('u8',x)])
        owners.append(owner);views.append(view)
    body.effect('loan.end',[views[0]])
    views[0]=body.value('readbuf','borrow.read',[owners[0]])
    result=body.value('u32','call',views,{'function':'f0'})
    data=[body.value('u8','buffer.load',[views[1],body.const('usize',i)]) for i in range(capacity)]
    for v in views:body.effect('loan.end',[v])
    for owner in owners:body.effect('owner.drop',[owner])
    text=('hia-asm.v1 hepta.hia.program.v8 module_graph_reference\nfn observe() -> (u32,'
          +','.join(['u8']*capacity)+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
          +body.text()+'  ret('+','.join([result,*data])+')\nend\n'+SOURCE.read_text().split('\n',1)[1])
    actual=execute_program(assemble_program(text),'observe',[],max_steps=3000000)
    assert actual['status']=='returned',actual
    assert actual['resources']['live_owners']==actual['resources']['live_local_loans']==0
    status,*output=actual['values']
    return status,bytes(output)

def project(increment=1):
    from tests.test_hia_program import b,c,f,i,m,ret
    app=m(f('work',[('a','u32')],['u32'],[],[
        b('entry',[('a','u32')],[i('call',['a'],[('result','u32')],function='use')],ret('result'))]))
    app['module']='app'
    app['schema']='hepta.hia.program.v8'
    lib=m(f('work',[('a','u32')],['u32'],[],[
        b('entry',[('a','u32')],[c('one','u32',increment),i('int.add.wrap',['a','one'],[('result','u32')])],ret('result'))]))
    lib['module']='lib'
    lib['schema']='hepta.hia.program.v8'
    return {'schema':WORKSPACE_SCHEMA,'entry':'app','modules':[
        {'core':app,'exports':['work'],'imports':[{'alias':'use','module':'lib','symbol':'work'}]},
        {'core':lib,'exports':['work'],'imports':[]}]}

class CoreModuleGraphSourceTests(unittest.TestCase):
    def test_generation_and_complete_independent_VM_result(self):
        from tools.generate_hia_core_module_graph import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        raw,expected=independent_case()
        self.assertEqual(vm(raw,len(expected)),(len(expected),expected))
        self.assertEqual(vm(raw+b'!',32),(0xffffffff,bytes([90])*32))
        self.assertEqual(vm(raw,32),(0xfffffffe,bytes([90])*32))

class CoreModuleGraphNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Independent interpretation precedes every native seed/image build.
        raw,expected=independent_case()
        assert vm(raw,len(expected))==(len(expected),expected)
        cls.temp=tempfile.TemporaryDirectory(prefix='hia-core-modules-')
        cls.folder=Path(cls.temp.name)
        from tools.qualify_hia_selfhost import compile_stage,build_seed
        cold=os.environ.get('HEPTA_HIA_CORE_MODULE_GRAPH_COLD_REPORT')
        if cold:
            report=json.loads(Path(cold).read_bytes())
            assert report['status']=='COLD_SELFHOST_REPLAY_PASS' and all(report['checks'].values())
            nested=json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler=Path(nested['generations'][-1]['produced_image'])
            assert report['generation_sha256']==[sha256(cls.compiler.read_bytes()).hexdigest()]*3
        else:
            seed,_=build_seed(cls.folder)
            source=(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
            first,_=compile_stage(cls.folder,'B1',seed,source,image_format='seed-shared')
            second,_=compile_stage(cls.folder,'B2',first,source)
            assert first.read_bytes()==second.read_bytes()
            cls.compiler=second
        image,cls.receipt=compile_stage(cls.folder,'core-module-graph',cls.compiler,SOURCE.read_bytes())
        cls.image=image
        cls.native=NativeCoreModuleGraph(image.read_bytes(),sha256(image.read_bytes()).hexdigest())

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_all_native_bytes_match_prebuild_independent_VM(self):
        raw,expected=independent_case()
        self.assertEqual(self.native.run(raw),expected)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])

    def test_actual_project_with_all_high_level_resolvers_forbidden_and_changed_source(self):
        from hepta.hia_program import execute_program
        original_import=builtins.__import__
        def guarded(name,*args,**kwargs):
            if name in {'hepta.modules','hepta.packages','hepta.pipeline','hepta.parser','hepta.semantics'}:
                raise AssertionError('high-level module resolver reached')
            return original_import(name,*args,**kwargs)
        for increment in (1,7):
            with patch('builtins.__import__',side_effect=guarded):
                verified,receipt=link_workspace(project(increment),native=self.native)
            self.assertEqual(receipt['module_order'],[1,0])
            self.assertEqual(verified.as_dict()['exports'],['f0'])
            self.assertEqual(execute_program(verified,'f0',[41])['result'],41+increment)
            self.assertEqual(verified.as_dict()['functions'][0]['blocks'][0]['ops'][0]['attrs']['function'],'f1')

    def test_core_resource_and_returned_loan_obligations_not_removed(self):
        from tests.test_hia_program import b,c,f,i,m,ret
        from hepta.hia_program import execute_program,HIAProgramRejected
        p=project()
        p['modules'][1]['core']=m(f('load',[('r','readbuf')],['u8'],['read','trap'],[
            b('entry',[('r','readbuf')],[c('zero','usize',0),i('buffer.load',['r','zero'],[('v','u8')])],ret('v'))]))
        p['modules'][1]['core']['module']='lib';p['modules'][1]['exports']=['load']
        p['modules'][0]['imports'][0]['symbol']='load'
        p['modules'][0]['core']=m(f('work',[],['u8'],['alloc','read','trap'],[
            b('entry',[],[c('size','usize',1),i('buffer.new',['size'],[('owned','buffer')]),
                i('borrow.read',['owned'],[('r','readbuf')]),i('call',['r'],[('v','u8')],function='use'),
                i('loan.end',['r']),i('owner.drop',['owned'])],ret('v'))]))
        p['modules'][0]['core']['module']='app'
        verified,_=link_workspace(p,native=self.native)
        actual=execute_program(verified,'f0',[])
        self.assertEqual(actual['result'],0)
        self.assertEqual(actual['resources']['live_owners'],0)
        bad=copy.deepcopy(p);bad['modules'][0]['core']['functions'][0]['blocks'][0]['ops'].pop()
        with self.assertRaises(HIAProgramRejected):link_workspace(bad,native=self.native)

    def test_all_declaration_visibility_alias_unresolved_and_cycle_refusals(self):
        cases=[]
        p=project();p['modules'].append(copy.deepcopy(p['modules'][1]));cases.append((p,'duplicate module'))
        p=project();p['modules'][1]['core']['functions']*=2;cases.append((p,'duplicate local function'))
        p=project();p['modules'][0]['imports'][0]['alias']='work';cases.append((p,'alias collides'))
        p=project();p['modules'][0]['imports']*=2;cases.append((p,'alias collides'))
        p=project();p['modules'][0]['imports'][0]['module']='missing';cases.append((p,'module not found'))
        p=project();p['modules'][0]['imports'][0]['symbol']='missing';cases.append((p,'function not found'))
        p=project();p['modules'][1]['exports']=[];cases.append((p,'private'))
        p=project();p['entry']='missing';cases.append((p,'entry module not found'))
        p=project();p['modules'][1]['exports']=['missing'];cases.append((p,'exported function not found'))
        p=project();p['modules'][1]['exports']*=2;cases.append((p,'duplicate exported'))
        p=project();p['modules'][0]['core']['functions'][0]['blocks'][0]['ops'][0]['attrs']['function']='missing';cases.append((p,'unresolved call'))
        p=project();p['modules'][1]['imports']=[{'alias':'back','module':'app','symbol':'work'}];cases.append((p,'cycle'))
        p=project();p['modules'][1]['imports']=[{'alias':'self_alias','module':'lib','symbol':'work'}];cases.append((p,'cycle'))
        for p,text in cases:
            with self.subTest(text=text),self.assertRaisesRegex(CoreModuleRejected,text):
                link_workspace(p,native=self.native)

    def test_cross_module_parameter_bound_returned_loans_and_false_origin_refusal(self):
        from tests.test_hia_program import b,c,f,i,m,ret
        from hepta.hia_program import execute_program,HIAProgramRejected
        for mode in ('read','mut'):
            typ=mode+'buf'
            helper=f('identity',[('r',typ)],[typ],[],[b('entry',[('r',typ)],[],ret('r'))])
            helper['return_loans']=['r']
            app=f('main',[],['u8'],['alloc','read','trap'],[b('entry',[],[
                c('size','usize',1),c('index','usize',0),i('buffer.new',['size'],[('owner','buffer')]),
                i('borrow.'+mode,['owner'],[('parent',typ)]),
                i('call',['parent'],[('child',typ)],function='returned'),
                i('buffer.load',['child','index'],[('v','u8')]),i('loan.end',['child']),
                i('loan.end',['parent']),i('owner.drop',['owner'])],ret('v'))])
            a=m(app);a['schema']='hepta.hia.program.v8';a['module']='app'
            lib=m(helper);lib['schema']='hepta.hia.program.v8';lib['module']='lib'
            p={'schema':WORKSPACE_SCHEMA,'entry':'app','modules':[
                {'core':a,'imports':[{'alias':'returned','module':'lib','symbol':'identity'}],'exports':['main']},
                {'core':lib,'imports':[],'exports':['identity']}]}
            verified,_=link_workspace(p,native=self.native)
            actual=execute_program(verified,'f0',[])
            self.assertEqual(actual['result'],0)
            self.assertEqual(actual['resources']['live_owners'],0)
            bad=copy.deepcopy(p);bad['modules'][1]['core']['functions'][0]['return_loans']=['not_a_parameter']
            with self.assertRaises(HIAProgramRejected):link_workspace(bad,native=self.native)

    def test_identifier_frame_refusals_and_no_publication_on_semantic_policy_failure(self):
        for name in ('', 'bad-name', '0name', '__hia_private', 'é', 'x'*129):
            p=project();p['modules'][1]['core']['module']=name
            p['modules'][0]['imports'][0]['module']=name
            with self.subTest(name=name),self.assertRaises(CoreModuleRejected):link_workspace(p,native=self.native)
        p=project();p['modules'][1]['exports']=[]
        raw,*_=encode_workspace(p)
        src=ctypes.create_string_buffer(raw,len(raw));out=ctypes.create_string_buffer(bytes([90])*512)
        scratch=ctypes.create_string_buffer(bytes([165])*8192)
        self.assertEqual(self.native._entry(src,len(raw),out,512,scratch,8192),0xfffffff5)
        self.assertEqual(out.raw[:512],bytes([90])*512)
        p=project();p['modules'][0]['core']['schema']={}
        with self.assertRaises(CoreModuleRejected):encode_workspace(p)

    def test_random_shuffled_dependency_projects(self):
        from tests.test_hia_program import b,c,f,i,m,ret
        from hepta.hia_program import execute_program
        rng=random.Random(5816)
        for case in range(80):
            n=rng.randrange(2,9);modules=[];values={}
            for k in range(n):
                imports=[]
                if k==0:
                    value=rng.randrange(40);ops=[c('v','u32',value)]
                else:
                    dep=rng.randrange(k);value=values[dep]
                    imports=[{'alias':'use','module':'m'+str(dep),'symbol':'work'}]
                    ops=[i('call',[],[('v','u32')],function='use')]
                core=m(f('work',[],['u32'],[],[b('entry',[],ops,ret('v'))]));core['module']='m'+str(k)
                modules.append({'core':core,'imports':imports,'exports':['work']});values[k]=value
            rng.shuffle(modules)
            verified,receipt=link_workspace({'schema':WORKSPACE_SCHEMA,'entry':'m'+str(n-1),'modules':modules},native=self.native)
            name=next(r['linked_name'] for r in receipt['function_names'] if r['module_index']==receipt['entry_module_index'])
            self.assertEqual(execute_program(verified,name,[])['result'],values[n-1])
            order={modules[mi]['core']['module']:pos for pos,mi in enumerate(receipt['module_order'])}
            for module in modules:
                for imp in module['imports']:
                    self.assertLess(order[imp['module']],order[module['core']['module']])

    def test_entire_module_and_import_bounds_in_reverse_order_under_original_process_limits(self):
        from tests.test_hia_program import b,c,f,m,ret
        from tools.qualify_hia_selfhost import invoke
        n=1024
        for count in (n-1,4096):
            modules=[]
            for k in range(n):
                core=m(f('work',[],['u32'],[],[b('entry',[],[c('v','u32',0)],ret('v'))]))
                core['module']='m'+str(k)
                imports=[] if k==0 else [{'alias':'use','module':'m'+str(k-1),'symbol':'work'}]
                if k==n-1:
                    imports += [{'alias':'extra'+str(j),'module':'m0','symbol':'work'}
                                for j in range(count-(n-1))]
                modules.append({'core':core,'imports':imports,'exports':['work']})
            wire,*_=encode_workspace({'schema':WORKSPACE_SCHEMA,'entry':'m1023','modules':modules[::-1]})
            # Independent exact expected bytes: reverse declaration indexes, all
            # extra imports target the last definition, only entry is public.
            targets=[1]+[n-1]*(count-(n-1))+list(range(2,n))
            words=[RESULT,n,n,count,0,n,0,0,*range(n-1,-1,-1),*targets,0,*([NONE]*(n-1))]
            expected=struct.pack('<'+str(len(words))+'Q',*words)
            receipt,actual=invoke(self.folder,'module-profile-'+str(count),self.image,wire)
            self.assertEqual(receipt['status'],'returned')
            self.assertEqual(receipt['limits']['cpu_seconds'],10)
            self.assertEqual(receipt['core_u32'],len(expected))
            self.assertEqual(actual[:len(expected)],expected)
            evidence=os.environ.get('HEPTA_HIA_CORE_MODULE_GRAPH_OBSERVATIONS')
            if evidence:
                retained=Path(evidence)/('profile-'+str(count));retained.mkdir(parents=True)
                for name,value in {'input.bin':wire,'expected.bin':expected,
                                   'actual.bin':actual[:len(expected)],
                                   'module-graph.image.bin':self.image.read_bytes()}.items():
                    (retained/name).write_bytes(value)
                (retained/'native-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')

    def test_mutated_packet_refusals_output_canary_short_buffers_and_concurrency(self):
        raw,expected=independent_case()
        malformed=[b'',raw+b'!',raw[:-1]]
        # Mutate counts, ownership, partitions and string ranges. Export-name
        # changes may be semantically valid; these indexes specifically cannot.
        for at in (0,8,16,24,32,40,48,56,64,72,80,88,96,104,144,168,208,264):
            changed=bytearray(raw);struct.pack_into('<Q',changed,at,NONE);malformed.append(bytes(changed))
        for value in malformed:
            src=ctypes.create_string_buffer(value,max(1,len(value)))
            out=ctypes.create_string_buffer(bytes([90])*512);scratch=ctypes.create_string_buffer(bytes([165])*8192)
            code=self.native._entry(src,len(value),out,512,scratch,8192)
            self.assertEqual(code,0xffffffff)
            self.assertEqual(out.raw[:512],bytes([90])*512)
        src=ctypes.create_string_buffer(raw,len(raw))
        for capacity,scratch_size in ((len(expected)-1,8192),(512,len(expected)+31)):
            out=ctypes.create_string_buffer(bytes([90])*512);scratch=ctypes.create_string_buffer(bytes([165])*8192)
            self.assertEqual(self.native._entry(src,len(raw),out,capacity,scratch,scratch_size),0xfffffffe)
            self.assertEqual(out.raw[:512],bytes([90])*512)
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(list(pool.map(self.native.run,[raw]*64)),[expected]*64)

    def test_real_native_Core_JSON_compiler_on_original_and_modified_project(self):
        import subprocess
        from tests.test_hia_program import b,c,f,i,ret
        from tools.qualify_hia_selfhost import compile_stage
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from hepta.hia_core_json_frontend_native import NativeCoreJsonFrontend
        frontend_image,_=compile_stage(self.folder,'core-frontend',self.compiler,
            (ROOT/'examples/hia_bootstrap/core_json_frontend.hiaasm').read_bytes())
        frontend=NativeCoreJsonFrontend(frontend_image.read_bytes(),sha256(frontend_image.read_bytes()).hexdigest())
        linker_image,_=compile_stage(self.folder,'native-linker',self.compiler,
            (ROOT/'examples/hia_bootstrap/elf_static_linker.hiaasm').read_bytes())
        linker=NativeHiaJsonImage(linker_image.read_bytes(),sha256(linker_image.read_bytes()).hexdigest())
        from tools.generate_hia_elf_linker import MAGIC as LINK_MAGIC,WORKSPACE_BYTES
        for increment in (1,7):
            workspace=project(increment)
            workspace['modules'][0]['core']['functions'].append(f('start',[],['u32'],[],[
                b('entry',[],[c('a','u32',41),i('call',['a'],[('result','u32')],function='work')],ret('result'))]))
            workspace['modules'][0]['exports']=['start']
            verified,_=link_workspace(workspace,native=self.native)
            from hepta.hia_program import execute_program
            oracle=execute_program(verified,'f1',[])
            self.assertEqual(oracle['result'],41+increment)
            rendered=frontend.render(verified.canonical_bytes,output_profile='elf')
            image,_=compile_stage(self.folder,'module-project-'+str(increment),self.compiler,rendered)
            obj=image.read_bytes();entry=b'f1'
            frame=struct.pack('<4Q',LINK_MAGIC,1,len(entry),0)+entry+struct.pack('<Q',len(obj))+obj
            src=ctypes.create_string_buffer(frame,len(frame));out=ctypes.create_string_buffer(65536)
            scratch=ctypes.create_string_buffer(WORKSPACE_BYTES)
            size=linker._entry(src,len(frame),out,65536,scratch,WORKSPACE_BYTES)
            self.assertTrue(0<size<65536)
            executable=self.folder/('project-'+str(increment));executable.write_bytes(out.raw[:size]);executable.chmod(0o700)
            actual=subprocess.run([str(executable)],capture_output=True,timeout=2,env={'PATH':''})
            self.assertEqual((actual.returncode,actual.stdout,actual.stderr),(41+increment,b'',b''))
            evidence=os.environ.get('HEPTA_HIA_CORE_MODULE_GRAPH_OBSERVATIONS')
            if evidence:
                retained=Path(evidence)/('project-'+str(increment));retained.mkdir(parents=True)
                payloads={'workspace.json':json.dumps(workspace,sort_keys=True).encode(),
                          'linked-core.json':verified.canonical_bytes,'program.hiaasm':rendered,
                          'program.o':obj,'program.elf':out.raw[:size]}
                for name,raw in payloads.items():(retained/name).write_bytes(raw)
                (retained/'execution.json').write_text(json.dumps({
                    'increment':increment,'independent_Core_VM_result':oracle['result'],
                    'actual_kernel_exit':actual.returncode,'stdout_hex':actual.stdout.hex(),
                    'stderr_hex':actual.stderr.hex(),'empty_PATH':True,
                    'native_module_policy_compiler_frontend_and_linker':True,
                    'host_JSON_Core_verification_and_build_custody':True,
                    'sha256':{n:sha256(v).hexdigest() for n,v in payloads.items()}},indent=2)+'\n')

    def test_explicit_workspace_build_driver_uses_admitted_compiler_and_preserves_exports(self):
        cold=os.environ.get('HEPTA_HIA_CORE_MODULE_GRAPH_COLD_REPORT')
        if not cold:
            # Absent a real completed cold report, test refusal only. Positive
            # installed build acceptance is a distinct formal stage with an
            # actual same-source cold report; never fabricate that evidence.
            from tools.build_hia_core_module_graph import build
            absent=self.folder/'invalid-cold.json';absent.write_text('{}')
            with self.assertRaisesRegex(ValueError,'completed matching native cold'):
                build(self.folder/'not-installed',self.compiler,absent)
            self.assertFalse((self.folder/'not-installed').exists())
            return
        from tools.build_hia_core_module_graph import build
        from tools.build_hia_json_preflight import build as build_frontend
        from tools.compile_hia_core_workspace import compile_workspace
        manifest=build(self.folder/'graph-installed',self.compiler,Path(cold))
        frontend=build_frontend(self.folder/'frontend-installed',self.compiler,Path(cold),candidate='core-frontend')
        target=self.folder/'workspace-driver'
        image=compile_workspace(json.dumps(project()).encode(),manifest,frontend,self.compiler,target)
        self.assertEqual(image.read_bytes()[:4],b'\x7fELF')
        record=json.loads((target/'workspace.receipt.json').read_bytes())
        self.assertEqual(record['output_profile'],'elf')
        self.assertFalse(record['reference_module_policy_fallback'])
        self.assertFalse(record['whole_native_workspace_qualified'])
        with self.assertRaisesRegex(ValueError,'no silent export stripping'):
            compile_workspace(json.dumps(project()).encode(),manifest,frontend,self.compiler,self.folder/'refused-flat',output_profile='flat')
        self.assertFalse((self.folder/'refused-flat').exists())
