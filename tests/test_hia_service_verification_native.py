"""Complete nine-method verification controller and its original-first gates."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from hepta import hia_agent_service as api
from hepta import hia_service_verification_native as native
from hepta.hia_agent_assembly import assemble_program,render_assembly
from tests import hia_service_verification_controls as controls
from tests import hia_service_verification_oracle as oracle
from tools import generate_hia_service_verification as generator
from tools import qualify_hia_service_verification_finite as qualification
from tools.read_hia_service_verification_finite import read as read_finite

ROOT=Path(__file__).resolve().parents[1]
COLD='HEPTA_HIA_SERVICE_VERIFICATION_COLD_REPORT'
DEVELOPMENT='HEPTA_HIA_SERVICE_VERIFICATION_DEVELOPMENT_COMPILER'
EVIDENCE='HEPTA_HIA_SERVICE_VERIFICATION_EVIDENCE'
SOURCE_EVIDENCE='HEPTA_HIA_SERVICE_VERIFICATION_SOURCE_EVIDENCE'

def source_directory(label):
    declared=os.environ.get(SOURCE_EVIDENCE)
    if declared=='':raise ValueError('empty verification Source evidence')
    if declared is None:
        temporary=tempfile.TemporaryDirectory(prefix='hia-verification-source-')
        root=Path(temporary.name)/label;root.mkdir();return root,temporary
    base=Path(declared).absolute();base.mkdir(mode=0o700,parents=True,exist_ok=True)
    root=Path(tempfile.mkdtemp(prefix=label+'-',dir=base))
    controls.write(root/'invocation.json',{'argv':sys.argv,'pid':os.getpid(),'ppid':os.getppid(),
        'enclosing_source_build_observations':os.environ.get('HEPTA_HIA_SOURCE_BUILD_OBSERVATIONS'),
        'scope':'independent Source finite observations; no executable mapping or cold qualification'})
    return root,None

class ServiceVerificationSourceTests(unittest.TestCase):
    def test_01_original_full_methods_public_binding_and_complete_generated_profile(self):
        import inspect
        import textwrap
        from hepta import hia_service_verification_protocol as protocol
        from tools.hia_service_verification_graph import ROWS
        raw=(ROOT/'hepta/hia_agent_service.py').read_bytes()
        lines=raw.splitlines(keepends=True);tree=ast.parse(raw)
        service=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='HIAAgentService')
        for mode,name in enumerate(oracle.METHODS,1):
            method=next(n for n in service.body if isinstance(n,ast.FunctionDef) and n.name==name)
            start=min([method.lineno]+[x.lineno for x in method.decorator_list])
            actual=b''.join(lines[start-1:method.end_lineno])
            original=(oracle.ORIGINALS/(name+'.py.txt')).read_bytes()
            self.assertEqual(actual,original)
            self.assertEqual(sha256(actual).hexdigest(),oracle.PINNED[name+'.py.txt'])
            wrapper=getattr(api,'_selected_service_verification_'+str(mode))
            reference=getattr(api,'_SERVICE_VERIFICATION_REFERENCE_'+str(mode))
            self.assertIs(getattr(api.HIAAgentService,name),wrapper)
            self.assertEqual(inspect.signature(wrapper),inspect.signature(reference))
            self.assertIs(reference.__globals__,vars(api))
            self.assertIs(api._SERVICE_VERIFICATION_GLOBAL_BUILTINS[mode],reference.__builtins__)
            self.assertEqual(api._SERVICE_VERIFICATION_LOCAL_NAMES[mode],
                             reference.__code__.co_varnames+reference.__code__.co_cellvars)
            self.assertEqual(api._SERVICE_VERIFICATION_CELL_NAMES[mode],
                             frozenset(reference.__code__.co_cellvars))
            binding=next(n for n in tree.body if isinstance(n,ast.FunctionDef)
                         and n.name=='_selected_service_verification_'+str(mode))
            frozen=ast.parse(textwrap.dedent(original.decode())).body[0]
            self.assertEqual(ast.dump(binding.args),ast.dump(frozen.args))
            self.assertEqual(ast.dump(binding.returns) if binding.returns else None,
                             ast.dump(frozen.returns) if frozen.returns else None)
            self.assertEqual(isinstance(vars(api.HIAAgentService)[name],staticmethod),mode==6)
        self.assertIs(api._SERVICE_VERIFICATION_NAMESPACE,vars(api))
        for capsule in api._SERVICE_VERIFICATION_IMPORTS.values():
            self.assertIs(capsule.__globals__,vars(api))
            self.assertIs(capsule.__builtins__,api._SERVICE_VERIFICATION_GLOBAL_BUILTINS[1])
        # Each business iteration/branch body is an authored HIA continuation.
        # Mechanical host iteration used to allocate/read ABI records is outside
        # this literal-port check and is not advertised as business control.
        adapter=ast.parse((ROOT/'hepta/hia_service_verification_native.py').read_bytes())
        frame=next(n for n in adapter.body if isinstance(n,ast.ClassDef) and n.name=='ServiceVerificationFrame')
        ports=[n for n in frame.body if isinstance(n,ast.FunctionDef) and n.name.startswith('_port_')]
        self.assertEqual({n.name[6:] for n in ports},set(protocol.PORTS))
        forbidden=(ast.For,ast.AsyncFor,ast.While,ast.ListComp,ast.DictComp,ast.SetComp,ast.GeneratorExp)
        self.assertFalse(any(isinstance(n,forbidden) for port in ports for n in ast.walk(port)))
        self.assertEqual(len(protocol.PORTS),446)
        self.assertEqual(len(protocol.MODE_RANGES),26)
        self.assertEqual(protocol.GENERATOR_MODES,frozenset(range(22,27)))
        self.assertEqual(tuple(row['name'] for row in ROWS),protocol.PORTS)
        self.assertEqual(tuple(row['id'] for row in ROWS),tuple(range(1,447)))
        for row in ROWS:
            targets=[row['raised']]
            if row['kind']=='effect':targets.append(row['next'])
            elif row['kind']=='boolean':targets.extend((row['yes'],row['no']))
            else:targets.extend(row['cases'].values())
            for target in targets:
                if target.startswith('@'):
                    self.assertIn(target,('@return','@propagate','@yield'))
                else:
                    self.assertIn(target,protocol.PORT)
                    low,high=protocol.MODE_RANGES[row['mode']]
                    self.assertLessEqual(low,protocol.PORT[target]);self.assertLessEqual(protocol.PORT[target],high)
        source=native.SOURCE.read_bytes()
        self.assertEqual(source,render_assembly(generator.document()).encode())
        document=assemble_program(source).as_dict()
        self.assertLessEqual(len(document['functions']),128)
        self.assertLessEqual(sum(len(f['blocks']) for f in document['functions']),1536)
        self.assertLessEqual(sum(len(b['ops']) for f in document['functions'] for b in f['blocks']),8192)
        self.assertLessEqual(len(source),1<<20)
        self.assertLessEqual(len(source.splitlines()),16384)
        for function in document['functions']:
            entry=next(b for b in function['blocks'] if b['id']==function['entry'])
            self.assertEqual(entry['params'],function['params'])
            self.assertLessEqual(len(function['blocks']),256)
            definitions=[]
            for block in function['blocks']:
                self.assertLessEqual(len(block['params']),16)
                definitions += [x['name'] for x in block['params']]
                definitions += [x['name'] for op in block['ops'] for x in op['out']]
            self.assertEqual(len(definitions),len(set(definitions)))
            self.assertLessEqual(len(definitions),2048)
        from hepta.hia_native_helpers import HELPERS
        self.assertEqual(HELPERS[native.SELECTOR],('hia_service_verification_native','NativeServiceVerification'))
        root,temporary=source_directory('unbound-cell-protocol')
        try:
            from tests.hia_service_verification_cells import run
            report=run(root/'cell-controls')
            self.assertEqual(report['count'],6)
            self.assertTrue(report['same_original_bytes'])
            self.assertEqual(len(report['bound_controls']),2)
        finally:
            if temporary is not None:temporary.cleanup()

    def test_02_all_fixed_base_originals_twice_then_public_independent_VM(self):
        root,temporary=source_directory('VM-base185')
        try:
            qualification.originals(root/'original',complete=False)
            qualification.compare(root/'candidate',root/'original','vm')
            report=read_finite(root/'original',root/'candidate')
            self.assertEqual(report['count'],185)
            self.assertGreater(report['actual_entries'],0)
        finally:
            if temporary is not None:temporary.cleanup()

    def test_03_full_original_unselected_public_domain_lazy_and_empty_selector(self):
        root,temporary=source_directory('unselected-base185')
        try:
            qualification.originals(root/'original',complete=False)
            qualification.compare(root/'candidate',root/'original','unselected')
            report=read_finite(root/'original',root/'candidate')
            self.assertEqual(report['count'],185)
            self.assertEqual(report['actual_entries'],0)
            code="""import importlib.abc,json,sys
sys.path.insert(0,sys.argv[1])
optional='hepta.hia_service_verification_native'
class BlockOptional(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name==optional:raise AssertionError('absent selector imported optional owner')
sys.meta_path.insert(0,BlockOptional())
from hepta import hia_agent_service as api
from types import SimpleNamespace
assert optional not in sys.modules
program=SimpleNamespace(sha256='candidate',input_sha256='input',
                        as_dict=lambda:{'functions':[{'name':'entry'}]})
value=api.HIAAgentService._native_refinement_binding(
    {'native_artifact':'native','build_receipt':'build'},
    {'object_artifact':'object','output_kind':'shared','native_build':{}},
    program,b'object',b'final')
assert optional not in sys.modules
print(json.dumps({'value':value,'optional_imported':False},sort_keys=True))
"""
            stdout,stderr,receipt=controls.run_process(root,'lazy-absent-owner',['-c',code,ROOT],
                env=controls.clean_environment(),timeout=60)
            lazy=json.loads(stdout)
            self.assertIs(lazy['optional_imported'],False)
            self.assertEqual(lazy['value']['entry_symbols'],['entry'])
            controls.write(root/'lazy-absent-owner-readback.json',{'child':receipt,'observation':lazy})
            saved=os.environ.get(native.SELECTOR)
            try:
                os.environ[native.SELECTOR]=''
                with controls.attributes(api,{'_SERVICE_VERIFICATION_REFERENCE_6':controls.forbidden}):
                    with self.assertRaises(ValueError):
                        api.HIAAgentService._native_refinement_binding(**controls.binding_arguments())
            finally:
                if saved is None:os.environ.pop(native.SELECTOR,None)
                else:os.environ[native.SELECTOR]=saved
        finally:
            if temporary is not None:temporary.cleanup()

class ServiceVerificationNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_service_verification import build
        from tools.build_hia_store_artifact_profile import build as store_build
        from tools.build_hia_service_context import build as context_build
        from tools.build_hia_json_preflight import current_sources
        cold,development,evidence=(os.environ.get(x) for x in (COLD,DEVELOPMENT,EVIDENCE))
        if (cold is None)==(development is None) or cold=='' or development=='' or evidence=='':
            raise ValueError('one matching current cold report or explicit DEV compiler is required')
        cls.temporary=None
        if evidence is None:
            cls.temporary=tempfile.TemporaryDirectory(prefix='hia-service-verification-')
            cls.root=Path(cls.temporary.name);cls.addClassCleanup(cls.temporary.cleanup)
        else:
            cls.root=Path(evidence).absolute();cls.root.mkdir(mode=0o700,parents=True,exist_ok=False)
        cls.cold=cold;cls.sources=current_sources()
        if cold is not None:
            from tools.hia_cold_compiler import compiler_from_cold_report
            cls.compiler=compiler_from_cold_report(Path(cold))
        else:cls.compiler=Path(development)
        cls.compiler_raw=cls.compiler.read_bytes()
        cls.manifest=build(cls.root/'verification',cls.compiler,cold,development=cold is None)
        cls.store_manifest=store_build(cls.root/'store',cls.compiler,cold,development=cold is None)
        cls.context_manifest=context_build(cls.root/'context',cls.compiler,cold,development=cold is None)
        cls.manifest_pins={str(x):sha256(x.read_bytes()).hexdigest()
                           for x in (cls.manifest,cls.store_manifest,cls.context_manifest)}

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        after=current_sources()
        stable=after==cls.sources and cls.compiler.read_bytes()==cls.compiler_raw
        stable=stable and all(sha256(Path(x).read_bytes()).hexdigest()==pin for x,pin in cls.manifest_pins.items())
        controls.write(cls.root/'component-custody.json',{'schema':'hepta.hia.service-verification-component-custody.v1',
            'source_before':cls.sources,'source_after':after,'source_and_compiler_unchanged':stable,
            'compiler_sha256':sha256(cls.compiler_raw).hexdigest(),'manifests':cls.manifest_pins,
            'matching_cold_report':cls.cold,
            'scope':'DEVELOPMENT_COMPONENT' if cls.cold is None else 'MATCHING_SOURCE_COLD_COMPONENT',
            'whole_native_stack_qualified':False,'opaque_Core_solver_emission_and_Store_providers_hosted':True})
        if not stable:raise AssertionError('verification current source/compiled input changed')

    def setUp(self):
        self.output=self.root/self._testMethodName;self.output.mkdir()

    def control(self,mode,*,timeout=60):
        output=self.output/mode
        stdout,stderr,receipt=controls.run_process(self.output,mode,[
            ROOT/'tests/hia_service_verification_controls.py','--mode',mode,'--manifest',self.manifest,
            '--store-manifest',self.store_manifest,'--context-manifest',self.context_manifest,'--output',output],
            env=controls.clean_environment(),timeout=timeout)
        raw=(output/'report.json').read_bytes();value=json.loads(raw)
        self.assertEqual(value['status'],'PASS');self.assertEqual(value['mode'],mode)
        self.assertEqual(value['source_before'],value['source_after'])
        self.assertEqual(value['actual_image_sha256'],json.loads(self.manifest.read_bytes())['image_sha256'])
        controls.write(self.output/(mode+'-receipt.json'),{'child':receipt,'report_sha256':sha256(raw).hexdigest()})
        return value['observations']

    def test_01_complete_original_first_base_and_every_declared_fault_native(self):
        qualification.originals(self.output/'original')
        qualification.compare(self.output/'candidate',self.output/'original','native',self.manifest)
        report=read_finite(self.output/'original',self.output/'candidate')
        authority=json.loads((self.output/'original/original-authority.json').read_bytes())
        self.assertEqual(report['count'],authority['count'])
        self.assertGreater(report['count'],185)
        self.assertGreater(report['actual_entries'],0)

    def test_02_complete_packets_all_bytes_independent_VM_and_native(self):
        report=self.control('packets',timeout=180)
        self.assertGreater(report['count'],0)
        self.assertEqual(report['VM_entries'],report['count'])
        self.assertTrue(report['complete_VM_native_bytes_equal'])
        self.assertTrue(report['all_446_ports'])
        self.assertTrue(report['all_26_modes'])

    def test_03_ordinary_foreign_identity_and_safe_preentry(self):
        self.assertEqual(len(self.control('foreign')['rows']),12)

    def test_04_actual_return_loss_receipt_corruption_and_no_retry(self):
        self.assertEqual(len(self.control('loss')['rows']),37)

    def test_05_same_frame_thread_fork_stale_context_and_escaped_lazy_generators(self):
        self.assertEqual(len(self.control('creator')['rows']),4)
        output=self.output/'lazy-generators'
        _,_,receipt=controls.run_process(self.output,'lazy-generators',[
            ROOT/'tests/hia_service_verification_lazy.py','--manifest',self.manifest,'--output',output],
            env=controls.clean_environment(),timeout=60)
        raw=(output/'report.json').read_bytes();report=json.loads(raw)
        self.assertEqual(report['status'],'PASS')
        self.assertEqual(report['count'],12);self.assertEqual(report['differences'],0)
        self.assertEqual(report['retained_calls'],0);self.assertGreater(report['actual_entries'],0)
        self.assertEqual((output/'original-observations.json').read_bytes(),
                         (output/'candidate-observations.json').read_bytes())
        controls.write(self.output/'lazy-receipt.json',{'child':receipt,'report_sha256':sha256(raw).hexdigest()})

    def test_06_actual_SQL_Store_retirement_whole_ACK_and_swallowed_child_loss(self):
        result=self.control('resources')
        self.assertEqual(len(result['rows']),10)
        self.assertTrue(result['actual_SQL_and_native_providers'])
        self.assertGreater(result['unknowns_remain_in_owned_child'],0)

    def test_07_public_signatures_static_instance_class_overrides_and_pinned_source(self):
        self.assertTrue(self.control('public')['class_instance_static_subclass_bindings_preserved'])
        self.assertTrue(self.control('scope')['pinned_worker_alternate_refused'])

    def test_08_real_installed_worker_completed_replay_unknown_and_source_drift(self):
        from tests.hia_service_verification_installed import run
        report=run(self.manifest,self.store_manifest,self.output/'installed')
        observations=report['observations']
        self.assertEqual(observations['normal']['response']['result']['checks'][0]['status'],'proved')
        self.assertEqual(observations['normal_state'],observations['replay_state'])
        self.assertEqual(observations['lost_state']['request'],('running',))
        self.assertEqual(observations['unknown_state']['request'],('running',))
        self.assertEqual(observations['unknown_state']['costs'],observations['lost_state']['costs']+1)
        self.assertTrue(report['runtime_authoring_imports_forbidden'])
