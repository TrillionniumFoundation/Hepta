"""Independent whole-document VM witnesses and complete primitive shape parity."""
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program_shape_native import SOURCE,SCHEMA,SELECTOR,ERROR_CODES,NativeProgramShape

VALID=b'{"schema":"hepta.hia.program.v1","module":"independent","functions":[{"name":"f","params":[],"returns":[],"effects":[],"entry":"entry","blocks":[{"id":"entry","params":[],"ops":[],"term":{"op":"ret","values":[]}}]}]}'


def wire(value):return json.dumps(value,separators=(',',':'),ensure_ascii=False).encode('utf-8')


def reference(program):
    from hepta.hia_program import _primitive_structure,HIAProgramRejected
    try:_primitive_structure(program)
    except HIAProgramRejected as exc:return exc.code
    return None


def interpreted(raw):
    from tests import test_hia_function_shape_native as observer
    with patch.object(observer,'SOURCE',SOURCE):return observer.interpreted(raw)


class ProgramShapeSourceTests(unittest.TestCase):
    def test_generated_complete_source_and_independent_VM_before_native(self):
        from tools.generate_hia_program_shape import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(render_assembly(document()),SOURCE.read_text())
        self.assertEqual(interpreted(VALID),0)
        self.assertEqual(interpreted(VALID.replace(b'program.v1',b'program.v9')),0xfffffff4)
        self.assertEqual(interpreted(VALID[:-1]+b',"exports":["missing"]}'),0xfffffff3)

    def test_complete_closed_catalog_and_version_feature_correspondence(self):
        from hepta.hia_schema import PRIMITIVE_SCHEMAS,supports_feature
        from hepta.hia_opcodes import SCALARS
        from tools.generate_hia_function_shape import TYPES
        self.assertEqual(SCALARS,set(TYPES[:12]))
        self.assertEqual(PRIMITIVE_SCHEMAS,{'hepta.hia.program.v'+str(v) for v in range(1,9)})
        for version in range(1,9):
            schema='hepta.hia.program.v'+str(version)
            self.assertEqual(supports_feature(schema,'recursive_chain'),version>=7)
            self.assertEqual(supports_feature(schema,'parameter_loan_returns'),version>=8)


class ProgramShapeNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert interpreted(VALID)==0
        cls.temp=tempfile.TemporaryDirectory(prefix='hia-program-shape-');cls.folder=Path(cls.temp.name)
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cold=os.environ.get('HEPTA_HIA_PROGRAM_SHAPE_COLD_REPORT')
        if cold:
            report=json.loads(Path(cold).read_bytes())
            assert report['status']=='COLD_SELFHOST_REPLAY_PASS' and all(report['checks'].values())
            nested=json.loads(Path(report['nested_report']).read_bytes())
            compiler=Path(nested['generations'][-1]['produced_image'])
            assert report['generation_sha256']==[sha256(compiler.read_bytes()).hexdigest()]*3
        else:
            seed,_=build_seed(cls.folder)
            compiler_source=SOURCE.with_name('selfhost.hiaasm').read_bytes()
            first,_=compile_stage(cls.folder,'B1',seed,compiler_source,image_format='seed-shared')
            compiler,_=compile_stage(cls.folder,'B2',first,compiler_source)
            assert first.read_bytes()==compiler.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'program-shape',compiler,SOURCE.read_bytes())
        cls.compiler=compiler;raw=image.read_bytes();cls.native=NativeProgramShape(raw,sha256(raw).hexdigest())
        cls.manifest=cls.folder/'manifest.json'
        cls.manifest.write_text(json.dumps(dict(schema=SCHEMA,source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),
            image_path=image.name,image_sha256=sha256(raw).hexdigest(),compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def compare(self,value):
        expected=reference(value);actual=self.native.status(wire(value))
        self.assertEqual(ERROR_CODES.get(actual) if actual else None,expected,(actual,value))
        self.assertNotEqual(actual,0xfffffffd)

    def test_independent_raw_decisions_and_forbidden_host_parsers(self):
        self.assertEqual(self.native.status(VALID),0)
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])
        for value in (None,False,0,'x',[],{}):self.assertEqual(self.native.status(wire(value)),0xfffffffb)
        for raw in (b'',b'{',VALID+b'x',b'{"schema":0,"schema":1}'):
            self.assertNotEqual(self.native.status(raw),0)
        with (patch('hepta.hia_program._primitive_structure',side_effect=AssertionError('foreign structure')),
              patch('hepta.hia_program._function_shape',side_effect=AssertionError('foreign function')),
              patch('json.loads',side_effect=AssertionError('foreign decoder'))):
            self.assertEqual(self.native.status(VALID),0)

    def test_all_versions_module_names_and_whole_declaration_faults(self):
        p=json.loads(VALID)
        for version in range(1,10):
            p['schema']='hepta.hia.program.v'+str(version);self.compare(p)
        for name in ('','_','module','x'*128,'x'*129,'malloc','__hia_private','雪'):
            p=json.loads(VALID);p['module']=name;self.compare(p)
        for key in ('schema','module','functions'):
            for value in (None,False,0,[],{},['x'],'unknown'):
                p=json.loads(VALID);p[key]=value;self.compare(p)
            p=json.loads(VALID);del p[key];self.compare(p)
        p=json.loads(VALID);p['extra']=0;self.compare(p)

    def test_function_local_names_are_not_global_and_duplicate_precedence(self):
        p=json.loads(VALID);fn=p['functions'][0]
        fn['params']=[{'name':'x','type':'u32'}];fn['returns']=['u32']
        fn['blocks'][0]['params']=copy.deepcopy(fn['params']);fn['blocks'][0]['term']['values']=['x']
        p['functions']=[copy.deepcopy(fn) for _ in range(128)]
        for index,fn in enumerate(p['functions']):fn['name']='f'+str(index)
        self.compare(p)
        p['functions'][-1]['name']='f0';self.compare(p)
        p['functions'][-1]['blocks'][0]['ops']=False;self.compare(p)

    def test_exports_all_positions_permissions_and_error_order(self):
        p=json.loads(VALID);p['functions'][0]['params']=[{'name':'p','type':'buffer'}]
        p['functions'][0]['blocks'][0]['params']=copy.deepcopy(p['functions'][0]['params'])
        for exports in ([],['f'],['missing'],['f','f'],['missing','missing'],['missing','bad-name'],None,False,{},[True]):
            p['exports']=exports;self.compare(p)
        p['functions'][0]['params']=[];p['functions'][0]['blocks'][0]['params']=[]
        p['exports']=['f'];p['functions'][0]['returns']=['buffer'];self.compare(p)
        p['functions'][0]['returns']=['u64'];self.compare(p)

    def test_full_1024_functions_and_exports_not_compiler_128_profile(self):
        p=json.loads(VALID);fn=p['functions'][0]
        p['functions']=[dict(copy.deepcopy(fn),name='f'+str(i)) for i in range(1024)]
        p['exports']=[fn['name'] for fn in p['functions']]
        self.compare(p)
        p['exports'].append('missing');self.compare(p)
        p['functions'].append(dict(copy.deepcopy(fn),name='extra'));self.compare(p)

    def test_deterministic_schema_export_and_function_mutations(self):
        rng=random.Random(71842)
        for _ in range(500):
            p=json.loads(VALID)
            if rng.randrange(2):p['exports']=rng.choice(([],['f'],['missing'],['f','f'],None))
            for _ in range(rng.randrange(1,4)):
                if rng.randrange(2):
                    key=rng.choice(tuple(p));p[key]=rng.choice((None,False,0,'bad-name',[],{}))
                else:
                    fn=p.get('functions')
                    if type(fn) is list and fn and type(fn[0]) is dict:
                        key=rng.choice(tuple(fn[0]));fn[0][key]=rng.choice((None,False,0,'bad-name',[],{}))
            self.compare(p)

    def test_all_versions_loan_origins_permissions_and_chain_declarations(self):
        from tools.generate_hia_function_shape import TYPES
        for version in range(1,9):
            for typ in TYPES:
                p=json.loads(VALID);p['schema']='hepta.hia.program.v'+str(version)
                fn=p['functions'][0];fn['params']=[{'name':'r','type':typ}];fn['returns']=[typ]
                fn['blocks'][0]['params']=copy.deepcopy(fn['params']);fn['blocks'][0]['term']['values']=['r']
                self.compare(p)
                fn['return_loans']=['r'];self.compare(p)
                if typ=='readbuf':
                    fn['returns']=['mutbuf'];self.compare(p)

    def test_full_document_byte_node_depth_and_block_limits(self):
        p=json.loads(VALID);fn=p['functions'][0]
        fn['blocks'][0]['ops']=[{'op':'opaque','args':[],'out':[],'attrs':{'payload':[]}}]
        def nodes(root):
            pending=[root];total=0
            while pending:
                v=pending.pop();total+=1
                if type(v) is dict:pending.extend(v.values())
                if type(v) is list:pending.extend(v)
            return total
        payload=fn['blocks'][0]['ops'][0]['attrs']['payload']
        payload.extend([None]*(262144-nodes(p)))
        self.assertEqual(nodes(p),262144);self.assertEqual(self.native.status(wire(p)),0)
        payload.append(None);self.assertEqual(self.native.status(wire(p)),0xfffffffe)
        nested=None
        for _ in range(56):nested=[nested]
        attrs=fn['blocks'][0]['ops'][0]['attrs'];attrs['payload']=nested
        self.assertEqual(self.native.status(wire(p)),0)
        attrs['payload']=[nested];self.assertEqual(self.native.status(wire(p)),0xfffffffe)
        attrs['payload']='';attrs['payload']='x'*(8388608-len(wire(p)))
        self.assertEqual(len(wire(p)),8388608);self.assertEqual(self.native.status(wire(p)),0)
        self.assertEqual(self.native.status(wire(p)+b' '),0xfffffffe)
        fn['blocks']=[]
        for i in range(4096):
            term={'op':'jump','target':'b'+str(i+1),'args':[]} if i<4095 else {'op':'ret','values':[]}
            fn['blocks'].append({'id':'b'+str(i),'params':[],'ops':[],'term':term})
        fn['entry']='b0';random.Random(592).shuffle(fn['blocks']);self.compare(p)
        fn['blocks'].append({'id':'extra','params':[],'ops':[],'term':{'op':'ret','values':[]}});self.compare(p)

    def test_actual_selected_general_Core_and_composite_normalization_preserve_body_safety(self):
        from hepta.hia_program import verify_program,HIAProgramRejected
        from hepta.hia_program_runtime import execute_program
        from tests.test_hia_program import joined_loan_program
        with (patch.dict(os.environ,{SELECTOR:str(self.manifest)}),
              patch('hepta.hia_program._reference_primitive_structure',side_effect=AssertionError('foreign declarations')),
              patch('hepta.hia_program._reference_function_shape',side_effect=AssertionError('foreign function'))):
            checked=verify_program(joined_loan_program())
            for cond in (False,True):
                observation=execute_program(checked,'join',[cond])
                self.assertEqual(observation['result'],0)
                self.assertEqual(observation['resources']['live_owners'],0)
                self.assertEqual(observation['resources']['live_local_loans'],0)
            bad=joined_loan_program();bad['functions'][0]['blocks'][0]['ops'][0]['op']='unknown_opcode'
            with self.assertRaises(HIAProgramRejected):verify_program(bad)
            bad=joined_loan_program();bad['exports']=['missing']
            with self.assertRaises(HIAProgramRejected):verify_program(bad)
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)+'.missing'}):
            with self.assertRaises(FileNotFoundError):verify_program(joined_loan_program())

    def test_strict_build_wrong_source_and_current_cold_identity(self):
        from tools.build_hia_program_shape import build
        wrong=self.folder/'wrong-cold.json';wrong.write_text(json.dumps({'profile':'wrong','source_manifest':{}}))
        output=self.folder/'wrong-build'
        with self.assertRaisesRegex(ValueError,'source identity'):build(output,self.compiler,wrong)
        self.assertFalse(output.exists())
        old=os.environ.get('HEPTA_HIA_PROGRAM_SHAPE_WRONG_COLD_REPORT')
        if old:
            with self.assertRaisesRegex(ValueError,'source identity'):build(output,self.compiler,Path(old))
            self.assertFalse(output.exists())
        cold=os.environ.get('HEPTA_HIA_PROGRAM_SHAPE_COLD_REPORT')
        if cold:
            from hepta.hia_program_shape_native import installed_program_shape
            manifest=build(self.folder/'matching-build',self.compiler,Path(cold))
            self.assertEqual(installed_program_shape(str(manifest)).status(VALID),0)


if __name__=='__main__':unittest.main()
