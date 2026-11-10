"""Independent Core VM before native compilation; full wire and ABI witnesses."""
import copy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from hepta.hia_core_workspace_json_native import SOURCE, NativeCoreWorkspaceJson, link_workspace
from hepta.hia_core_module_graph_native import CoreModuleRejected, encode_workspace
from tests.test_hia_core_module_graph_native import project, independent_case, NativeCoreModuleGraph

ROOT=Path(__file__).resolve().parents[1]


def wire(doc):
    return json.dumps(doc,separators=(',',':'),ensure_ascii=False).encode()


def independent_project():
    # Deliberately authored as a complete expected Core result, not by the
    # workspace bridge or an algorithm that repeats capture avoidance.
    doc=project()
    doc['modules'][0]['core']['functions'][0]['name']='main'
    doc['modules'][0]['exports']=['main']
    doc['modules'][1]['core']['functions'][0]['name']='inc'
    doc['modules'][1]['exports']=['inc']
    doc['modules'][0]['imports'][0]['symbol']='inc'
    fn0=copy.deepcopy(doc['modules'][0]['core']['functions'][0])
    fn1=copy.deepcopy(doc['modules'][1]['core']['functions'][0])
    fn0['blocks'][0]['ops'][0]['attrs']['function']='f1'
    fn1['name']='f1'
    expected={'schema':'hepta.hia.program.v8','module':'core_workspace','functions':[fn0,fn1],'exports':['main']}
    return doc,expected


def vm(wire_bytes, expected):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    b=Body(0);owners=[];views=[]
    for size,data in ((len(wire_bytes),wire_bytes),(8192,b''),(1<<20,b'')):
        owner=b.value('buffer','buffer.new',[b.const('usize',size)])
        view=b.value('mutbuf','borrow.mut',[owner])
        for i,x in enumerate(data):
            if x:b.effect('buffer.store',[view,b.const('usize',i),b.const('u8',x)])
        owners.append(owner);views.append(view)
    b.effect('loan.end',[views[0]])
    views[0]=b.value('readbuf','borrow.read',[owners[0]])
    result=b.value('u32','call',views,{'function':'f0'})
    actual=[]
    for start in range(0,len(expected),8):
        word=b.const('u64',0)
        for i in range(start,min(start+8,len(expected))):
            value=b.value('u8','buffer.load',[views[1],b.const('usize',i)])
            value=b.value('u64','int.cast',[value],{'mode':'wrap'})
            value=b.value('u64','int.shl.checked',[value,b.const('u64',(i-start)*8)])
            word=b.value('u64','bit.or',[word,value])
        actual.append(word)
    for v in views:b.effect('loan.end',[v])
    for owner in owners:b.effect('owner.drop',[owner])
    text=('hia-asm.v1 hepta.hia.program.v8 workspace_json_vm\nfn observe() -> (u32,'
          +','.join(['u64']*len(actual))+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
          +b.text()+'  ret('+','.join([result,*actual])+')\nend\n'+SOURCE.read_text().split('\n',1)[1])
    actual=execute_program(assemble_program(text),'observe',[],max_steps=10000000)
    assert actual['status']=='returned',actual
    assert actual['resources']['live_owners']==actual['resources']['live_local_loans']==0
    status,*values=actual['values']
    return status,b''.join(v.to_bytes(8,'little') for v in values)[:len(expected)]


class CoreWorkspaceJsonSourceTests(unittest.TestCase):
    def test_generated_source_and_single_loan_graph_relocation(self):
        from tools.generate_hia_core_workspace_json import document, relocated_graph
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        for fn in relocated_graph():
            self.assertEqual([a.annotation.id for a in fn.args.args].count('mutbuf'),1)
            self.assertNotIn('readbuf',[a.annotation.id for a in fn.args.args])

    def test_complete_independent_vm_before_any_native_image(self):
        doc,expected=independent_project()
        expected_bytes=b'{"module":"core_workspace","schema":"hepta.hia.program.v8","functions":'+json.dumps(expected['functions'],sort_keys=True,separators=(',',':')).encode()+b',"exports":["main"]}'
        self.assertEqual(vm(wire(doc),expected_bytes),(len(expected_bytes),expected_bytes))


class CoreWorkspaceJsonNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Do not compile a seed until interpretation of the entire source and
        # its graph relocation has returned the independently expected bytes.
        CoreWorkspaceJsonSourceTests('test_complete_independent_vm_before_any_native_image').test_complete_independent_vm_before_any_native_image()
        cls.temp=tempfile.TemporaryDirectory(prefix='hia-workspace-json-')
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
            first,_=compile_stage(cls.folder,'B1',seed,(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes(),image_format='seed-shared')
            second,_=compile_stage(cls.folder,'B2',first,(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes())
            assert first.read_bytes()==second.read_bytes()
            cls.compiler=second
        image,cls.receipt=compile_stage(cls.folder,'core-workspace-json',cls.compiler,SOURCE.read_bytes())
        cls.image=image
        cls.native=NativeCoreWorkspaceJson(image.read_bytes(),sha256(image.read_bytes()).hexdigest())
        image,_=compile_stage(cls.folder,'core-module-graph',cls.compiler,(ROOT/'examples/hia_bootstrap/core_module_graph.hiaasm').read_bytes())
        cls.graph=NativeCoreModuleGraph(image.read_bytes(),sha256(image.read_bytes()).hexdigest())

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_native_complete_expected_output_and_independent_fact_packet(self):
        doc,expected=independent_project()
        output=self.native.run(wire(doc))
        self.assertEqual(json.loads(output),expected)
        # Inspect ALL native-produced fact bytes, not merely counts or hashes.
        raw=wire(doc);s=ctypes.create_string_buffer(raw,len(raw));o=ctypes.create_string_buffer(1<<20);w=ctypes.create_string_buffer(1<<20)
        status=self.native._entry(s,len(raw),o,len(o),w,len(w))
        self.assertEqual(output,o.raw[:status])
        base,size=struct.unpack_from('<2Q',w)
        # The older resolver witness interns its hand-authored string table;
        # JSON transport intentionally appends every encountered name. This is
        # an independent COMPLETE append-order packet, not the old interned one.
        expected_facts=struct.pack('<10Q',int.from_bytes(b'HIAMOD01','little'),2,2,1,1,2,35,0,3,0)
        expected_facts+=struct.pack('<8Q',3,3,0,1,26,3,1,1)
        expected_facts+=struct.pack('<8Q',0,6,4,0,1,29,3,0)
        expected_facts+=struct.pack('<7Q',0,13,3,16,3,19,3)
        expected_facts+=struct.pack('<3Q',0,10,3)
        expected_facts+=struct.pack('<6Q',0,22,4,1,32,3)
        expected_facts+=b'appappmainuseuselibincmainlibincinc'
        self.assertEqual(w.raw[base:base+size],expected_facts)
        work=struct.unpack_from('<Q',w,16)[0]
        self.assertEqual(w.raw[work:work+len(independent_case()[1])],independent_case()[1])
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])

    def test_all_primitive_versions_order_whitespace_and_changed_sources(self):
        from hepta.hia_core_module_graph_native import link_workspace as old_link
        from hepta.hia_schema import PRIMITIVE_SCHEMAS
        from hepta.hia_program import execute_program
        for schema in sorted(PRIMITIVE_SCHEMAS):
            for reverse in (False,True):
                p=project(7)
                for item in p['modules']:item['core']['schema']=schema
                if reverse:p['modules'].reverse()
                raw=json.dumps(p,indent=2).encode().replace(b'"app"',b'"\\u0061pp"')
                expected,_=old_link(raw,native=self.graph)
                with patch('hepta.hia_core_module_graph_native.encode_workspace',side_effect=AssertionError('host workspace encoder called')):
                    actual,receipt=link_workspace(raw,native=self.native)
                self.assertEqual(actual.sha256,expected.sha256)
                self.assertEqual(execute_program(actual,'work',[41])['result'],48)
                self.assertFalse(receipt['reference_module_policy_or_materialization_fallback'])

    def test_native_fact_bytes_match_host_transport_for_different_orders(self):
        for reverse in (False,True):
            doc=project()
            if reverse:doc['modules'].reverse()
            raw=json.dumps(doc,indent=1).encode().replace(b'"work"',b'"w\\u006frk"')
            s=ctypes.create_string_buffer(raw,len(raw));o=ctypes.create_string_buffer(1<<20);w=ctypes.create_string_buffer(1<<20)
            status=self.native._entry(s,len(raw),o,len(o),w,len(w))
            self.assertLess(status,0xffff0000)
            base,size=struct.unpack_from('<2Q',w)
            self.assertEqual(w.raw[base:base+size],encode_workspace(raw)[0])

    def test_public_fN_collision_avoidance(self):
        from hepta.hia_core_module_graph_native import link_workspace as old_link
        for public in ('f0','f1','f6','a'*127+'x','a'*127+'y'):
            p=project();p['modules'][0]['core']['functions'][0]['name']=public;p['modules'][0]['exports']=[public]
            actual,_=link_workspace(wire(p),native=self.native)
            expected,_=old_link(p,native=self.graph)
            self.assertEqual(actual.sha256,expected.sha256)
            self.assertEqual(actual.as_dict()['exports'],[public])

    def test_framing_duplicate_decoded_keys_and_profiles_fail_closed(self):
        cases=[b'null',b'{}',wire(project())+b'!',b'{"schema":0,"\\u0073chema":1}']
        p=project();p['extra']=0;cases.append(wire(p))
        p=project();p['entry']=1;cases.append(wire(p))
        p=project();p['modules']=[];cases.append(wire(p))
        p=project();p['modules'][0]['core']['extra']=0;cases.append(wire(p))
        p=project();p['modules'][0]['imports'][0]['extra']=0;cases.append(wire(p))
        p=project();p['modules'][0]['core']['functions'][0]['blocks'][0]['ops'][0]['attrs']['function']=None;cases.append(wire(p))
        p=project();p['modules'][0]['core']['schema']='hepta.hia.program.v7';cases.append(wire(p))
        p=project();p['modules'][0]['core']['schema']='hepta.hia.composite.v4';cases.append(wire(p))
        for raw in cases:
            with self.subTest(raw=raw[:120]):
                with self.assertRaises(CoreModuleRejected):self.native.run(raw)

    def test_graph_policy_invalid_names_privacy_unresolved_and_cycles_preserved(self):
        mutations=[lambda p:p.update(entry='missing'),
                   lambda p:p['modules'][0]['core'].update(module='lib'),
                   lambda p:p['modules'][0]['imports'][0].update(alias='work'),
                   lambda p:p['modules'][0]['imports'][0].update(module='missing'),
                   lambda p:p['modules'][0]['imports'][0].update(symbol='missing'),
                   lambda p:p['modules'][1].update(exports=[]),
                   lambda p:p['modules'][0].update(exports=['missing']),
                   lambda p:p['modules'][0].update(exports=['work','work']),
                   lambda p:p['modules'][0]['core']['functions'][0].update(name='__hia_x'),
                   lambda p:p['modules'][0]['imports'][0].update(alias='bad-name'),
                   lambda p:p['modules'][1].update(imports=[{'alias':'back','module':'app','symbol':'work'}])]
        for mutate in mutations:
            p=project();mutate(p)
            with self.assertRaises(CoreModuleRejected):self.native.run(wire(p))

    def test_host_general_Core_safety_is_not_bypassed(self):
        from hepta.hia_program import HIAProgramRejected
        p=project()
        p['modules'][1]['core']['functions'][0]['blocks'][0]['ops'][0]['attrs']['value']=-1
        with self.assertRaises(HIAProgramRejected):link_workspace(wire(p),native=self.native)

    def test_cross_module_returned_loans_and_false_origin_refusal(self):
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
            a=m(app);a.update(schema='hepta.hia.program.v8',module='app')
            lib=m(helper);lib.update(schema='hepta.hia.program.v8',module='lib')
            p={'schema':'hepta.hia.core-workspace.v1','entry':'app','modules':[
                {'core':a,'imports':[{'alias':'returned','module':'lib','symbol':'identity'}],'exports':['main']},
                {'core':lib,'imports':[],'exports':['identity']}]}
            verified,_=link_workspace(wire(p),native=self.native)
            actual=execute_program(verified,'main',[])
            self.assertEqual(actual['result'],0)
            self.assertEqual(actual['resources']['live_owners'],0)
            bad=copy.deepcopy(p);bad['modules'][1]['core']['functions'][0]['return_loans']=['not_a_parameter']
            with self.assertRaises(HIAProgramRejected):link_workspace(wire(bad),native=self.native)
            bad=copy.deepcopy(p);bad['modules'][0]['core']['functions'][0]['blocks'][0]['ops'].pop()
            with self.assertRaises(HIAProgramRejected):link_workspace(wire(bad),native=self.native)

    def test_actual_original_modified_ELF_ABI_without_host_materializer(self):
        import subprocess
        from tests.test_hia_program import b,c,f,ret
        from tools.qualify_hia_selfhost import compile_stage
        from hepta.hia_core_json_frontend_native import NativeCoreJsonFrontend
        from hepta.object_symbols import inspect_object_symbols
        image,_=compile_stage(self.folder,'workspace-abi-frontend',self.compiler,
            (ROOT/'examples/hia_bootstrap/core_json_frontend.hiaasm').read_bytes())
        frontend=NativeCoreJsonFrontend(image.read_bytes(),sha256(image.read_bytes()).hexdigest())
        longest='public_'+('x'*121)
        names=['f6','work','f1','f0',longest,longest[:-1]+'y']
        for increment in (1,7):
            for reverse in (False,True):
                p=project(increment);app=p['modules'][0]
                constants={name:100+index+increment for index,name in enumerate(names) if name!='work'}
                for name,value in constants.items():
                    app['core']['functions'].append(f(name,[],['u32'],[],[
                        b('entry',[],[c('value','u32',value)],ret('value'))]))
                app['exports']=names[:]
                if reverse:p['modules'].reverse()
                with patch('hepta.hia_core_module_graph_native.link_workspace',side_effect=AssertionError('host materialization fallback')):
                    checked,_=link_workspace(wire(p),native=self.native)
                label='workspace-abi-'+str(increment)+'-'+str(int(reverse))
                assembly=frontend.render(checked.canonical_bytes,output_profile='elf')
                obj,record=compile_stage(self.folder,label,self.compiler,assembly)
                self.assertEqual(record['forbidden_compiler_modules_loaded'],[])
                inventory=inspect_object_symbols(obj.read_bytes(),'ELF64',62)
                self.assertEqual(inventory['defined'],frozenset(names))
                library=self.folder/(label+'.so')
                subprocess.run(['cc','-shared','-Wl,-z,defs,-z,noexecstack,-z,relro,-z,now',str(obj),'-o',str(library)],check=True,capture_output=True)
                loaded=ctypes.CDLL(str(library));work=loaded.work
                work.argtypes=[ctypes.c_uint32];work.restype=ctypes.c_uint32
                for value in (0,1,41,255,65535,0xffffffff):self.assertEqual(work(value),(value+increment)&0xffffffff)
                for name,value in constants.items():
                    fn=getattr(loaded,name);fn.argtypes=[];fn.restype=ctypes.c_uint32
                    self.assertEqual(fn(),value)
                retained=os.environ.get('HEPTA_HIA_CORE_WORKSPACE_JSON_OBSERVATIONS')
                if retained:
                    folder=Path(retained)/label;folder.mkdir(parents=True)
                    payloads={'workspace.json':wire(p),'linked-core.json':checked.canonical_bytes,
                              'program.hiaasm':assembly,'program.o':obj.read_bytes(),'library.so':library.read_bytes()}
                    for name,data in payloads.items():(folder/name).write_bytes(data)
                    (folder/'execution.json').write_text(json.dumps({'actual_abi_calls':11,
                        'expected_public_symbols':names,'defined_symbols':sorted(inventory['defined']),
                        'increment':increment,'reverse':reverse,'host_shared_linker_used':True,
                        'sha256':{n:sha256(d).hexdigest() for n,d in payloads.items()}},indent=2)+'\n')

    def test_full_1024_module_4096_import_profile_under_original_10_cpu_seconds(self):
        import subprocess,sys
        from tests.test_hia_program import b,c,f,m,ret
        n=1024
        modules=[]
        for k in range(n):
            core=m(f('work',[],['u32'],[],[b('entry',[],[c('v','u32',0)],ret('v'))]))
            core.update(schema='hepta.hia.program.v8',module='m'+str(k))
            imports=[] if k==0 else [{'alias':'use','module':'m'+str(k-1),'symbol':'work'}]
            if k==n-1:imports += [{'alias':'extra'+str(j),'module':'m0','symbol':'work'} for j in range(4096-(n-1))]
            modules.append({'core':core,'imports':imports,'exports':['work']})
        p={'schema':'hepta.hia.core-workspace.v1','entry':'m1023','modules':modules[::-1]}
        raw=wire(p)
        child='''import json,pathlib,resource,sys
from hashlib import sha256
from hepta.hia_core_workspace_json_native import NativeCoreWorkspaceJson
resource.setrlimit(resource.RLIMIT_CPU,(10,10))
resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
image=pathlib.Path(sys.argv[1]).read_bytes()
native=NativeCoreWorkspaceJson(image,sha256(image).hexdigest())
sys.stdout.buffer.write(native.run(sys.stdin.buffer.read()))
'''
        result=subprocess.run([sys.executable,'-B','-c',child,str(self.image)],input=raw,capture_output=True,timeout=13)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        linked=json.loads(result.stdout)
        self.assertEqual(len(linked['functions']),1024)
        self.assertEqual(linked['exports'],['work'])
        self.assertEqual([fn['name'] for fn in linked['functions']],['work']+['f'+str(i) for i in range(1,1024)])
        retained=os.environ.get('HEPTA_HIA_CORE_WORKSPACE_JSON_OBSERVATIONS')
        if retained:
            folder=Path(retained)/'full-module-profile';folder.mkdir(parents=True)
            (folder/'workspace.json').write_bytes(raw);(folder/'linked-core.json').write_bytes(result.stdout)
            (folder/'execution.json').write_text(json.dumps({'returncode':result.returncode,'cpu_limit':10,
                'address_limit':268435456,'modules':1024,'imports':4096,'functions':1024,
                'input_sha256':sha256(raw).hexdigest(),'output_sha256':sha256(result.stdout).hexdigest()},indent=2)+'\n')

    def test_output_capacity_and_source_guards(self):
        raw=wire(project());s=ctypes.create_string_buffer(raw+b'guard',len(raw)+5)
        o=ctypes.create_string_buffer(b'Z'*100,100);w=ctypes.create_string_buffer(1<<20)
        self.assertEqual(self.native._entry(s,len(raw),o,100,w,len(w)),0xfffffffe)
        self.assertEqual(o.raw,b'Z'*100)
        o=ctypes.create_string_buffer(1<<20)
        self.assertLess(self.native._entry(s,len(raw),o,len(o),w,len(w)),0xffff0000)
        self.assertEqual(s.raw,raw+b'guard')

    def test_concurrent_native_calls_keep_private_arenas(self):
        raws=[wire(project(i)) for i in (1,2,7,17)]
        with ThreadPoolExecutor(max_workers=4) as pool:actual=list(pool.map(self.native.run,raws))
        self.assertEqual(actual,[self.native.run(raw) for raw in raws])

    def test_entire_call_bound_and_one_over_rejection(self):
        from tests.test_hia_program import b,f,i,m,ret
        app=m(f('main',[],[],[],[b('entry',[],[i('call',[],[],function='use') for _ in range(16384)],ret())]))
        lib=m(f('work',[],[],[],[b('entry',[],[],ret())]))
        app.update(schema='hepta.hia.program.v8',module='app');lib.update(schema='hepta.hia.program.v8',module='lib')
        p={'schema':'hepta.hia.core-workspace.v1','entry':'app','modules':[
            {'core':app,'imports':[{'alias':'use','module':'lib','symbol':'work'}],'exports':['main']},
            {'core':lib,'imports':[],'exports':['work']}]}
        candidate=json.loads(self.native.run(wire(p)))
        ops=candidate['functions'][0]['blocks'][0]['ops']
        self.assertEqual(len(ops),16384)
        self.assertTrue(all(op['attrs']['function']=='f1' for op in ops))
        app['functions'][0]['blocks'][0]['ops'].append(i('call',[],[],function='use'))
        with self.assertRaises(CoreModuleRejected):self.native.run(wire(p))

    def test_installed_build_driver_and_no_manifest_fallback(self):
        from tools.build_hia_core_workspace_json import build
        from tools.build_hia_json_preflight import build as build_frontend
        from tools.compile_hia_core_workspace import compile_workspace
        cold=os.environ.get('HEPTA_HIA_CORE_MODULE_GRAPH_COLD_REPORT')
        if not cold:
            absent=self.folder/'missing-cold.json';absent.write_text('{}')
            with self.assertRaisesRegex(ValueError,'completed matching native cold'):
                build(self.folder/'refused-install',self.compiler,absent)
            self.assertFalse((self.folder/'refused-install').exists())
            return
        manifest=build(self.folder/'workspace-installed',self.compiler,Path(cold))
        frontend=build_frontend(self.folder/'workspace-frontend-installed',self.compiler,Path(cold),candidate='core-frontend')
        target=self.folder/'workspace-json-build'
        with patch('hepta.hia_core_module_graph_native.link_workspace',side_effect=AssertionError('host fallback')):
            image=compile_workspace(wire(project()),None,frontend,self.compiler,target,workspace_json_manifest=manifest)
        self.assertEqual(image.read_bytes()[:4],b'\x7fELF')
        receipt=json.loads((target/'workspace.receipt.json').read_bytes())
        self.assertEqual(receipt['JSON_framing_fact_encoding_graph_policy_and_Core_materialization'],'HIA_NATIVE')
        self.assertFalse(receipt['reference_module_policy_or_materialization_fallback'])
        self.assertTrue(receipt['host_general_Core_verification_and_filesystem_build_install_bridge'])
        with self.assertRaisesRegex(ValueError,'exactly one'):
            compile_workspace(wire(project()),manifest,frontend,self.compiler,self.folder/'mixed-selection',workspace_json_manifest=manifest)
        self.assertFalse((self.folder/'mixed-selection').exists())
        broken=self.folder/'bad-selected-manifest.json';broken.write_text('{}')
        with self.assertRaises(ValueError):
            compile_workspace(wire(project()),None,frontend,self.compiler,self.folder/'no-fallback',workspace_json_manifest=broken)
        self.assertFalse((self.folder/'no-fallback').exists())
