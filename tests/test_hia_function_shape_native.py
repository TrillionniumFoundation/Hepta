"""Raw independent VM fixtures, production oracle mutations and full profiles."""
import copy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_function_shape_native import SOURCE,SCHEMA,SELECTOR,ERROR_CODES,NativeFunctionShape,scratch_sizes

VALID=b'{"name":"identity","params":[{"name":"x","type":"u32"}],"returns":["u32"],"effects":[],"entry":"entry","blocks":[{"id":"entry","params":[{"name":"x","type":"u32"}],"ops":[],"term":{"op":"ret","values":["x"]}}]}'


def wire(fn):return json.dumps(fn,separators=(',',':'),ensure_ascii=False).encode()


def reference(fn,chain=False,loans=False):
    from hepta.hia_program import _function_shape,HIAProgramRejected
    try:_function_shape(fn,recursive_chain=chain,parameter_loan_returns=loans)
    except HIAProgramRejected as exc:return exc.code
    return None


def interpreted(raw,chain=False,loans=False):
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    state,arena=scratch_sizes(len(raw))
    body=Body(0);owners=[];views=[]
    for size,initial in ((len(raw),raw),(state,b''),(arena,b'')):
        owner=body.value('buffer','buffer.new',[body.const('usize',size)])
        view=body.value('mutbuf','borrow.mut',[owner])
        for index,value in enumerate(initial):
            if value:body.effect('buffer.store',[view,body.const('usize',index),body.const('u8',value)])
        owners.append(owner);views.append(view)
    flags=int(chain)+2*int(loans)
    if flags:body.effect('buffer.store',[views[2],body.const('usize',40),body.const('u8',flags)])
    body.effect('loan.end',[views[0]])
    views[0]=body.value('readbuf','borrow.read',[owners[0]])
    result=body.value('u32','call',views,{'function':'f0'})
    for view in views:body.effect('loan.end',[view])
    for owner in owners:body.effect('owner.drop',[owner])
    text=('hia-asm.v1 hepta.hia.program.v8 shape_observer\nfn observe() -> (u32) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+body.text()+'  ret('+result+')\nend\n'+SOURCE.read_text().split('\n',1)[1])
    out=execute_program(assemble_program(text),'observe',[],max_steps=3000000)
    assert out['status']=='returned',out
    assert out['resources']['live_owners']==out['resources']['live_local_loans']==0
    return out['result']


class FunctionShapeSourceTests(unittest.TestCase):
    def test_generated_source_catalog_and_independent_VM(self):
        from tools.generate_hia_function_shape import document,TYPES
        from hepta.hia_opcodes import TYPES as catalog
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(set(TYPES),catalog)
        self.assertEqual(render_assembly(document()),SOURCE.read_text())
        # Expected decisions authored without the host _function_shape oracle.
        self.assertEqual(interpreted(VALID),0)
        self.assertEqual(interpreted(VALID.replace(b'"identity"',b'"malloc"')),0xfffffffa)
        self.assertEqual(interpreted(VALID.replace(b'"id":"entry"',b'"id":"missing"')),0xfffffff6)


class FunctionShapeNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Independent ordinary Core VM executes before any native seed/image.
        assert interpreted(VALID)==0
        cls.temp=tempfile.TemporaryDirectory(prefix='hia-function-shape-')
        cls.folder=Path(cls.temp.name)
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cold=os.environ.get('HEPTA_HIA_FUNCTION_SHAPE_COLD_REPORT')
        if cold:
            report=json.loads(Path(cold).read_bytes())
            assert report['status']=='COLD_SELFHOST_REPLAY_PASS' and all(report['checks'].values())
            nested=json.loads(Path(report['nested_report']).read_bytes())
            compiler=Path(nested['generations'][-1]['produced_image'])
            assert report['generation_sha256']==[sha256(compiler.read_bytes()).hexdigest()]*3
        else:
            seed,_=build_seed(cls.folder)
            compiler_source=SOURCE.with_name('selfhost.hepta').read_bytes()
            first,_=compile_stage(cls.folder,'B1',seed,compiler_source,image_format='seed-shared')
            compiler,_=compile_stage(cls.folder,'B2',first,compiler_source)
            assert first.read_bytes()==compiler.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'function-shape',compiler,SOURCE.read_bytes())
        cls.compiler=compiler
        raw=image.read_bytes();cls.native=NativeFunctionShape(raw,sha256(raw).hexdigest())
        cls.manifest=cls.folder/'manifest.json'
        cls.manifest.write_text(json.dumps(dict(schema=SCHEMA,source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
            image_path=image.name,image_sha256=sha256(raw).hexdigest(),compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def compare(self,fn,chain=False,loans=False):
        expected=reference(fn,chain,loans)
        actual=self.native.status(wire(fn),recursive_chain=chain,parameter_loan_returns=loans)
        self.assertEqual(ERROR_CODES.get(actual) if actual else None,expected,(actual,fn))
        self.assertNotEqual(actual,0xfffffffd)

    def test_native_independent_witness_and_parser_refusals(self):
        self.assertEqual(self.native.status(VALID),0)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])
        for raw in (b'',b'{',VALID+b'x',b'{"name":"a","name":"b"}'):
            self.assertNotEqual(self.native.status(raw),0)
        for root in (None,False,0,[],{},'x'):
            self.assertEqual(self.native.status(wire(root)),0xfffffffb)
        # Native admission never consults the reference policy or host JSON.
        with (patch('hepta.hia_program._function_shape',side_effect=AssertionError('foreign shape')),
              patch('json.loads',side_effect=AssertionError('foreign decoder'))):
            self.assertEqual(self.native.status(VALID),0)

    def test_every_declaration_kind_and_schema_loan_chain_features(self):
        from tools.generate_hia_function_shape import TYPES
        for typ in TYPES:
            fn=json.loads(VALID)
            fn['params'][0]['type']=fn['blocks'][0]['params'][0]['type']=typ
            fn['returns']=[typ]
            for chain in (False,True):
                for loans in (False,True):
                    self.compare(fn,chain,loans)
                    with_origin=copy.deepcopy(fn);with_origin['return_loans']=['x']
                    self.compare(with_origin,chain,loans)
        for name in ('','x'*128,'x'*129,'__hia_private','__hia_','__hi','á','a.b','0a','malloc','free','_' ):
            fn=json.loads(VALID);fn['name']=name;self.compare(fn)
        for effect in ([],['read'],['read','write','alloc','trap'],['read','read'],['x'],[True],None):
            fn=json.loads(VALID);fn['effects']=effect;self.compare(fn)

    def test_structural_fields_malformed_values_and_diagnostic_precedence(self):
        valid=json.loads(VALID)
        values=(None,False,0,'x',[],{},['x'])
        for field in valid:
            for value in values:
                fn=copy.deepcopy(valid);fn[field]=value;self.compare(fn)
            fn=copy.deepcopy(valid);del fn[field];self.compare(fn)
        for field in valid['blocks'][0]:
            for value in values:
                fn=copy.deepcopy(valid);fn['blocks'][0][field]=value;self.compare(fn)
        for field in ('name','type'):
            for value in values:
                fn=copy.deepcopy(valid);fn['params'][0][field]=value;self.compare(fn)
        fn=copy.deepcopy(valid);fn['params']*=2;fn['returns']=False;self.compare(fn)
        fn=copy.deepcopy(valid);fn['blocks'][0]['ops']=[
            {'op':'anything','args':[],'out':[{'name':'x','type':'u32'}],'attrs':False}]
        self.compare(fn)  # Malformed attributes precede the cross-instruction SSA test.

    def test_cfg_order_edges_reachability_cycles_and_all_terminators(self):
        base=json.loads(VALID)
        for size in (2,3,9):
            fn=copy.deepcopy(base)
            for index in range(size-1):
                name='block'+str(index)
                fn['blocks'].append({'id':name,'params':[],'ops':[],
                    'term':{'op':'jump','target':name,'args':[]}})
            fn['blocks'][0]['term']={'op':'jump','target':'block0','args':[]}
            self.compare(fn)
            fn['blocks'][1]['term']={'op':'branch','cond':'x','then':{'target':'block0','args':[]},
                'else':{'target':fn['blocks'][-1]['id'],'args':[]}}
            self.compare(fn)
            random.Random(331).shuffle(fn['blocks']);self.compare(fn)
        for term in ({'op':'ret','values':[]},{'op':'trap','code':'user'},
                     {'op':'trap','code':'not_a_trap'}, {'op':'jump','target':'entry','args':['x']},
                     {'op':'jump','target':'missing','args':[]}, {'op':'branch','cond':'bad-name','then':{},'else':{}},
                     {'op':'unknown'}, {},None):
            fn=copy.deepcopy(base);fn['blocks'][0]['term']=term;self.compare(fn)

    def test_full_4096_block_profile_without_compiler_256_block_substitution(self):
        fn={'name':'full','params':[],'returns':[],'effects':[],'entry':'b0','blocks':[]}
        for i in range(4096):
            term=({'op':'jump','target':'b'+str(i+1),'args':[]} if i<4095 else {'op':'ret','values':[]})
            fn['blocks'].append({'id':'b'+str(i),'params':[],'ops':[],'term':term})
        self.compare(fn)
        fn['blocks'].append({'id':'extra','params':[],'ops':[],'term':{'op':'ret','values':[]}})
        self.compare(fn)

    def test_complete_Core_byte_node_depth_profiles_and_one_past(self):
        fn=json.loads(VALID)
        fn['blocks'][0]['ops']=[{'op':'opaque','args':[],'out':[],'attrs':{'payload':[]}}]
        def nodes(value):
            pending=[value];total=0
            while pending:
                v=pending.pop();total+=1
                if type(v) is dict:pending.extend(v.values())
                if type(v) is list:pending.extend(v)
            return total
        payload=fn['blocks'][0]['ops'][0]['attrs']['payload']
        payload.extend([None]*(262144-nodes(fn)))
        self.assertEqual(nodes(fn),262144)
        self.assertEqual(self.native.status(wire(fn)),0)
        payload.append(None)
        self.assertEqual(self.native.status(wire(fn)),0xfffffffe)
        # Root -> blocks -> block -> ops -> instruction -> attrs -> payload.
        nested=None
        for _ in range(58):nested=[nested]
        fn['blocks'][0]['ops'][0]['attrs']['payload']=nested
        self.assertEqual(self.native.status(wire(fn)),0)
        fn['blocks'][0]['ops'][0]['attrs']['payload']=[nested]
        self.assertEqual(self.native.status(wire(fn)),0xfffffffe)
        attrs=fn['blocks'][0]['ops'][0]['attrs'];attrs['payload']=''
        size=8388608-len(wire(fn));attrs['payload']='x'*size
        self.assertEqual(len(wire(fn)),8388608)
        self.assertEqual(self.native.status(wire(fn)),0)
        # Over-budget bytes never reach the code image.
        self.assertEqual(self.native.status(wire(fn)+b' '),0xfffffffe)

    def test_actual_selected_Core_has_no_old_shape_fallback_and_keeps_body_safety(self):
        from hepta.hia_program import verify_program,HIAProgramRejected
        from hepta.hia_program_runtime import execute_program
        from tests.test_hia_program import joined_loan_program
        with (patch.dict(os.environ,{SELECTOR:str(self.manifest)}),
              patch('hepta.hia_program._reference_function_shape',side_effect=AssertionError('foreign shape'))):
            checked=verify_program(joined_loan_program())
            for cond in (False,True):
                observation=execute_program(checked,'join',[cond])
                self.assertEqual(observation['result'],0)
                self.assertEqual(observation['resources']['live_owners'],0)
                self.assertEqual(observation['resources']['live_local_loans'],0)
            bad=joined_loan_program();bad['functions'][0]['blocks'][0]['ops'][0]['op']='not_an_opcode'
            with self.assertRaises(HIAProgramRejected):verify_program(bad)
            bad=joined_loan_program();bad['functions'][0]['blocks'][0]['id']='missing'
            with self.assertRaises(HIAProgramRejected):verify_program(bad)
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)+'.missing'}):
            with self.assertRaises(FileNotFoundError):verify_program(joined_loan_program())

    def test_strict_build_refuses_wrong_source_before_output_and_uses_matching_cold(self):
        from tools.build_hia_function_shape import build
        wrong=self.folder/'wrong-cold.json'
        wrong.write_text(json.dumps({'status':'COLD_SELFHOST_REPLAY_PASS','profile':'wrong','source_manifest':{}}))
        output=self.folder/'wrong-build'
        with self.assertRaisesRegex(ValueError,'source identity'):build(output,self.compiler,wrong)
        self.assertFalse(output.exists())
        old=os.environ.get('HEPTA_HIA_FUNCTION_SHAPE_WRONG_COLD_REPORT')
        if old:
            with self.assertRaisesRegex(ValueError,'source identity'):build(output,self.compiler,Path(old))
            self.assertFalse(output.exists())
        cold=os.environ.get('HEPTA_HIA_FUNCTION_SHAPE_COLD_REPORT')
        if cold:
            from hepta.hia_function_shape_native import installed_function_shape
            manifest=build(self.folder/'matching-build',self.compiler,Path(cold))
            self.assertEqual(installed_function_shape(str(manifest)).status(VALID),0)

    def test_deterministic_random_multi_faults_and_declared_key_order(self):
        rng=random.Random(830492)
        candidates=(None,False,0,'bad-name',[],{},['x'],['u32'])
        for _ in range(500):
            fn=json.loads(VALID)
            fn['return_loans']=[rng.choice((None,'x','missing',True))]
            for _ in range(rng.randrange(1,5)):
                key=rng.choice(tuple(fn));fn[key]=copy.deepcopy(rng.choice(candidates))
            self.compare(fn,bool(rng.randrange(2)),bool(rng.randrange(2)))
        # Keys and text may be escaped and reordered; this is not the emitter's
        # restricted grammar. The decoded object must have the same policy.
        escaped=VALID.replace(b'"name"',b'"na\\u006de"').replace(b'"identity"',b'"ident\\u0069ty"')
        self.assertEqual(self.native.status(escaped),0)


if __name__=='__main__':unittest.main()
