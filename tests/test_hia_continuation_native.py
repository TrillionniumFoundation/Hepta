"""Native multi-image scheduling: no host step/handoff or runtime authoring.

External object effects deliberately remain on the peer side of the pipe.
The development manifests are explicit; these tests do not admit a product.
"""
from __future__ import annotations
import ctypes
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
FRAME=struct.Struct('<16Q');EVENT=struct.Struct('<8Q')
MAGIC=int.from_bytes(b'HIALOW01','little')
RPC=int.from_bytes(b'HIAIPC01','little')


def packet(policy,pool,units,abi):
    modes=sorted(abi['modes'].values(),key=lambda x:x['number'])
    header=(int.from_bytes(b'HIACTPK1','little'),len(policy),len(units),
        abi['workspace_bytes'],abi['output_bytes'],abi['pool_bytes'],
        abi['literal_count'],len(modes),len(pool))
    return (struct.pack('<9Q',*header)+struct.pack('<'+'Q'*len(units),*(len(x) for x in units))
        +b''.join(struct.pack('<QQ',x['number'],x['arity']) for x in modes)
        +policy+pool+b''.join(units))


def call(image,raw,capacity=2<<20):
    source=ctypes.create_string_buffer(raw);output=ctypes.create_string_buffer(capacity+16)
    ctypes.memset(output,0xA5,len(output));state=ctypes.create_string_buffer(65536)
    result=image._entry(source,len(raw),output,capacity,state,len(state))
    if output.raw[capacity:]!=b'\xA5'*16:raise AssertionError('output canary changed')
    if source.raw[:len(raw)]!=raw:raise AssertionError('read-only input changed')
    return result,output.raw[:capacity]


class ContinuationSourceTests(unittest.TestCase):
    def test_pack_publication_checks_actual_native_extents_and_exact_receipt_types(self):
        from tools.build_hia_native_continuation import _checked_pack_result
        image=b'native-packer';source=b'pack-input'
        header=bytearray(176);header[:8]=b'HIAINP01'
        struct.pack_into('<2Q',header,8,1,176)
        struct.pack_into('<2Q',header,96,177,177)
        executable=bytes(header)+b'\xc3';output=executable+b'\xa5'*31
        digest=lambda raw:sha256(raw).hexdigest()
        receipt=dict(status='returned',result_u64=177,core_u32=177,abi_status=0,
            image_sha256=digest(image),source_sha256=digest(source),
            input_sha256=digest(source),input_bytes=len(source),output_sha256=digest(output),
            source_unchanged=True,buffer_redzones_unchanged=True,
            output_tail_unchanged=True,input_pages_read_only=True,
            forbidden_compiler_modules_loaded=[])
        def checked(row=receipt,actual=output,capacity=len(output),transport='inprocess'):
            return _checked_pack_result(row,actual,image=image,source=source,
                capacity=capacity,transport=transport)
        self.assertEqual(checked(),executable)
        corruptions=(dict(core_u32=True,result_u64=True),
            dict(core_u32=177.0,result_u64=177.0),dict(abi_status=False),
            dict(abi_status=0.0),dict(result_u64=177+(1<<32)),
            dict(input_bytes=True),dict(input_bytes=len(source)+1),
            dict(input_sha256=None),dict(input_sha256='0'*64),
            dict(source_sha256='0'*64),dict(image_sha256='0'*64),
            dict(output_sha256='0'*64),dict(source_unchanged=1),
            dict(buffer_redzones_unchanged=1),dict(output_tail_unchanged=1),
            dict(input_pages_read_only=1),dict(forbidden_compiler_modules_loaded=()),
            dict(forbidden_compiler_modules_loaded=['hepta.compiler']),
            dict(core_u32=178,result_u64=178),dict(core_u32=176,result_u64=176),
            dict(core_u32=len(output)+1,result_u64=len(output)+1))
        for changes in corruptions:
            with self.subTest(receipt_changes=changes),self.assertRaises(ValueError):
                checked({**receipt,**changes})
        for actual in (b'',output[:-1],output+b'\xa5',bytearray(output)):
            with self.subTest(output_type=type(actual),length=len(actual)),self.assertRaises(ValueError):
                checked({**receipt,'output_sha256':digest(actual)},actual)
        for capacity in (True,0,(64<<20)+1):
            with self.subTest(capacity=capacity),self.assertRaises(ValueError):checked(capacity=capacity)
        for offset in (0,8,16,24,96,104,175):
            broken=bytearray(output);broken[offset]^=1;broken=bytes(broken)
            with self.subTest(header_offset=offset),self.assertRaises(ValueError):
                checked({**receipt,'output_sha256':digest(broken)},broken)
        with self.assertRaises(ValueError):checked([])
        with self.assertRaises(ValueError):checked(transport='unknown')
        with self.assertRaises(ValueError):checked(transport='subprocess')


    def test_unqualified_builder_refuses_before_output_creation(self):
        from tools.build_hia_native_continuation import build
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'compiler').write_bytes(b'not qualified');(root/'cold.json').write_text('{}')
            with self.assertRaises(ValueError):build(root/'must-not-exist',root/'compiler',root/'cold.json')
            self.assertFalse((root/'must-not-exist').exists())

    def test_worker_scope_rejects_all_unregistered_schedulers_before_mapping(self):
        import importlib
        from hepta.hia_native_helpers import native_helpers_scope
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from hepta.hia_native_continuation import NativeContinuation
        from hepta.hia_native_continuation_inprocess import InProcessContinuation
        from hepta.hia_native_continuation_selection import installed_native_continuation
        with native_helpers_scope(),patch.object(NativeHiaJsonImage,'__init__',side_effect=AssertionError('unregistered mapping')),patch('subprocess.Popen',side_effect=AssertionError('unregistered process')):
            for family in ('core_lowering','core_emitter','byte_wrapper','machine_object','execution_observation'):
                module=importlib.import_module('hepta.hia_'+family+'_selection')
                with self.subTest(family=family):
                    with self.assertRaisesRegex(ValueError,'outside the pinned worker bundle'):getattr(module,'installed_'+family)('/must-not-open',{})
            with self.assertRaisesRegex(ValueError,'outside the pinned worker bundle'):installed_native_continuation('/must-not-open',{})
            for factory in (NativeContinuation,InProcessContinuation):
                with self.assertRaisesRegex(ValueError,'outside the pinned worker bundle'):factory(None,None,pool_bytes=64)

    def test_generator_and_independent_policy_VM(self):
        from tools.generate_hia_continuation import policy_source,packer_source
        from tools.generate_hia_artifact_publication import document
        from hepta.hia_agent_assembly import assemble_program,render_assembly
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        for name,source in (('continuation_policy',policy_source()),('continuation_packer',packer_source()),('continuation_inprocess_packer',packer_source(in_process=True))):
            raw=(ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()
            self.assertEqual(render_assembly(document(source,name)).encode(),raw)
        program=assemble_program((ROOT/'examples/hia_bootstrap/continuation_policy.hepta').read_bytes())
        workspace=bytearray(65536);struct.pack_into('<Q',workspace,16,1)
        meta=struct.pack('<8Q',int.from_bytes(b'HIACTN01','little'),1,1024,128,64,3,1,0)
        meta+=struct.pack('<6Q',100,10,110,10,1,0)
        def invoke(raw):
            owners=[_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(128)),_Owner(-3,workspace)]
            machine=_Machine(program,4_000_000,16<<20,None,128)
            value=machine.invoke(next(iter(machine.functions.values())),[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
            self.assertEqual(bytes(owners[0].data),raw)
            return value,owners[1].data
        self.assertEqual(invoke(meta)[0],1)
        struct.pack_into('<Q',workspace,8,64)
        pool=struct.pack('<2Q',int.from_bytes(b'HIALIT01','little'),3)+bytes(48)
        result,output=invoke(pool);self.assertEqual(result,3)
        self.assertEqual(EVENT.unpack_from(output)[:3],(RPC,3,64))
        self.assertEqual(invoke(b'')[0],2)
        self.assertEqual(invoke(FRAME.pack(MAGIC,0,0,2,*([0]*12)))[0],16)


class ContinuationNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        proof=os.environ.get('HEPTA_HIA_CONTINUATION_DEVELOPMENT_BUILD')
        bundle=os.environ.get('HEPTA_HIA_CONTINUATION_OBSERVATION_MANIFEST')
        cold=os.environ.get('HEPTA_HIA_NATIVE_CONTINUATION_COLD_REPORT')
        if cold and (proof or bundle):raise AssertionError('development cannot override matching-source cold')
        cls.official_manifest=None
        if cold:
            from tools.build_hia_native_continuation import build
            cold_report=json.loads(Path(cold).read_bytes());nested=json.loads(Path(cold_report['nested_report']).read_bytes())
            compiler=Path(nested['generations'][-1]['produced_image'])
            cls.build_directory=tempfile.TemporaryDirectory(prefix='hia-continuation-cold-build-');cls.addClassCleanup(cls.build_directory.cleanup)
            cls.official_manifest=build(Path(cls.build_directory.name)/'built',compiler,Path(cold))
            result=json.loads((cls.official_manifest.parent/'build.json').read_bytes())
            rows=[dict(name=name,image=receipt['produced_image'],image_sha256=receipt['produced_sha256']) for name,receipt in zip(('continuation_policy','continuation_packer','continuation_inprocess_packer'),result['native_compile_receipts'])]
            bundle=str(cls.official_manifest.parent/'policy/manifest.json')
        else:
            if not proof or not bundle:raise unittest.SkipTest('explicit continuation cold report or development images required')
            rows=json.loads(Path(proof).read_bytes())['units']
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        from hepta.hia_execution_observation_selection import installed_execution_observation
        from hepta import hia_opcodes
        cls.images={};cls.image_bytes={}
        for row in rows:
            raw=Path(row['image']).read_bytes()
            cls.images[row['name']]=NativeHiaJsonImage(raw,row['image_sha256']);cls.image_bytes[row['name']]=raw
        cls.owner=installed_execution_observation(str(Path(bundle).resolve()),vars(hia_opcodes))
        cls.policy_bundle=Path(bundle).resolve()
        cls.abi=json.loads((ROOT/'docs/HIA_EXECUTION_OBSERVATION_ABI.json').read_bytes())
        manifest=Path(bundle);metadata=json.loads(manifest.read_bytes());native=[]
        for name in ('execution_observation_pool',*cls.abi['units']):
            unit=manifest.parent/metadata['unit_manifests'][name];entry=json.loads(unit.read_bytes())
            raw=(unit.parent/entry['image_path']).read_bytes()
            if sha256(raw).hexdigest()!=entry['image_sha256']:raise AssertionError('development bundle image drift')
            native.append(raw)
        cls.native=native
        cls.input=packet(cls.image_bytes['continuation_policy'],native[0],native[1:],cls.abi)
        result,raw=call(cls.images['continuation_packer'],cls.input)
        if not 0<result<=len(raw):raise AssertionError(('native packer refused',hex(result)))
        cls.executable=raw[:result]
        result,inprocess=call(cls.images['continuation_inprocess_packer'],cls.input)
        if not 0<result<=len(inprocess):raise AssertionError(('native in-process packer refused',hex(result)))
        cls.inprocess_executable=inprocess[:result]
        if cls.official_manifest is not None:
            if (cls.official_manifest.parent/'continuation.native').read_bytes()!=cls.executable:
                raise AssertionError('independent packing differs from cold-admitted builder')
            if (cls.official_manifest.parent/'continuation.image.bin').read_bytes()!=cls.inprocess_executable:
                raise AssertionError('independent in-process packing differs from cold-admitted builder')
        cls.directory=tempfile.TemporaryDirectory(prefix='hia-continuation-tests-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.path=Path(cls.directory.name)/'native';cls.path.write_bytes(cls.executable);cls.path.chmod(0o500)
        cls.native_counts=[]

    def development_selected_bundle(self,label,*,in_process=False):
        from hepta.hia_agent_contract import CONTINUATION_BUILD_FILES
        directory=Path(self.directory.name)/label;directory.mkdir()
        shutil.copytree(self.policy_bundle.parent,directory/'policy')
        for p in (directory/'policy').rglob('*'):
            if p.is_file():p.chmod(0o600)
        raw=self.inprocess_executable if in_process else self.executable
        target=directory/('continuation.image.bin' if in_process else 'continuation.native');target.write_bytes(raw);target.chmod(0o400 if in_process else 0o500)
        base=(directory/'policy/manifest.json').read_bytes()
        value=dict(schema='hepta.hia.native-continuation-inprocess.v1' if in_process else 'hepta.hia.native-continuation.v1',kind='execution-observation',policy_bundle='policy/manifest.json',policy_bundle_sha256=sha256(base).hexdigest(),compiler_sha256=json.loads(base)['compiler_sha256'],image_path=target.name,image_sha256=sha256(raw).hexdigest(),resource_sha256={name:sha256((ROOT/name).read_bytes()).hexdigest() for name in CONTINUATION_BUILD_FILES},runtime_sha256={'hepta/'+name:sha256((ROOT/'hepta'/name).read_bytes()).hexdigest() for name in ('hia_native_continuation.py','hia_native_continuation_selection.py','hia_native_continuation_inprocess.py','hia_native_helpers.py','hia_core_lowering_native.py')})
        path=directory/'manifest.json';path.write_text(json.dumps(value,sort_keys=True));path.chmod(0o600)
        return path

    def test_ordinary_selector_uses_native_scheduler_and_binds_installation_sources(self):
        from hepta import hia_opcodes
        from hepta.hia_core_lowering_native import LoweringSession
        from hepta.hia_execution_observation_selection import SELECTOR,installed_execution_observation,native_implementation_identity
        from tests.test_hia_execution_observation_native import cases,outcome
        path=self.development_selected_bundle('ordinary-selector')
        before=installed_execution_observation(str(self.policy_bundle),vars(hia_opcodes))
        expected=[(status,ledger,options,outcome(lambda status=status,ledger=ledger,options=options:hia_opcodes._reference_validate_execution_observation(status,ledger,**options))) for status,ledger,options in cases()]
        with patch.dict(os.environ,{SELECTOR:str(path)}),patch.object(hia_opcodes,'_reference_validate_execution_observation',side_effect=AssertionError('retained ledger')),patch.object(LoweringSession,'step',side_effect=AssertionError('retained step')),patch.object(LoweringSession,'handoff',side_effect=AssertionError('retained handoff')):
            for status,ledger,options,wanted in expected:
                with self.subTest(status=status,options=options):
                    self.assertEqual(outcome(lambda:hia_opcodes.validate_execution_observation(status,ledger,**options)),wanted)
            identity=native_implementation_identity(vars(hia_opcodes))
            self.assertIn(b'native-execution-observation-v1',identity)
            self.assertIn(sha256(self.executable).hexdigest().encode().hex().encode(),identity)
        self.assertFalse(hasattr(before,'_continuation'))

    def test_selected_bundle_drift_refuses_before_fallback_or_child_launch(self):
        from hepta import hia_opcodes
        from hepta.hia_execution_observation_selection import installed_execution_observation
        path=self.development_selected_bundle('selected-drift');raw=path.read_bytes();value=json.loads(raw)
        installed_execution_observation(str(path),vars(hia_opcodes))
        with patch('subprocess.Popen',side_effect=AssertionError('must refuse before child launch')):
            target=path.parent/'continuation.native';image=target.read_bytes()
            target.chmod(0o700);target.write_bytes(image+b'changed');target.chmod(0o500)
            try:
                with self.assertRaisesRegex(ValueError,'executable identity mismatch'):installed_execution_observation(str(path),vars(hia_opcodes))
            finally:target.chmod(0o700);target.write_bytes(image);target.chmod(0o500)
            for key,bad in (('kind','core-lowering'),('policy_bundle','other.json'),('image_path','other.native'),('policy_bundle_sha256','0'*64),('runtime_sha256',{}),('resource_sha256',{})):
                path.write_text(json.dumps({**value,key:bad}));path.chmod(0o600)
                try:
                    with self.assertRaises(ValueError):installed_execution_observation(str(path),vars(hia_opcodes))
                finally:path.write_bytes(raw)

    def test_installed_wheel_ordinary_selection_has_no_authoring_or_host_scheduler(self):
        self.installed_wheel_case(in_process=False)

    def test_installed_inprocess_wheel_prohibits_process_launch_and_authoring(self):
        self.installed_wheel_case(in_process=True)

    def installed_wheel_case(self,*,in_process):
        directory=Path(self.directory.name)/('installed-inprocess-wheel' if in_process else 'installed-wheel');directory.mkdir()
        source=directory/'source';source.mkdir()
        shutil.copytree(ROOT/'hepta',source/'hepta',ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        declarations={node.targets[0].id:ast.literal_eval(node.value) for node in ast.parse((ROOT/'hepta/hia_agent_contract.py').read_text()).body if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('DISCOVERY_FILES','NATIVE_SOURCE_FILES','SOURCE_BUILD_FILES','COMPILER_BUILD_FILES','PUBLICATION_BUILD_FILES','BACKEND_BUILD_FILES','EMITTER_BUILD_FILES','BYTE_WRAPPER_BUILD_FILES','MACHINE_OBJECT_BUILD_FILES','EXECUTION_OBSERVATION_BUILD_FILES','CONTINUATION_BUILD_FILES')}
        names=['setup.py','pyproject.toml','MANIFEST.in','README.md']
        for symbol,values in declarations.items():names.extend('docs/'+n if symbol=='DISCOVERY_FILES' else n for n in values)
        for name in names:
            target=source/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
        python=os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON',sys.executable)
        built=subprocess.run([python,'-B','setup.py','bdist_wheel','--dist-dir',str(directory/'wheels')],cwd=source,capture_output=True,timeout=120)
        self.assertEqual(built.returncode,0,built.stdout+built.stderr)
        wheels=list((directory/'wheels').glob('*.whl'));self.assertEqual(len(wheels),1)
        site=directory/'site';site.mkdir()
        with zipfile.ZipFile(wheels[0]) as archive:archive.extractall(site)
        selected=self.development_selected_bundle('installed-inprocess-selected' if in_process else 'installed-selected',in_process=in_process)
        code='''import importlib.abc,os,sys
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=='tools' or fullname.startswith('tools.') or 'generate_hia_' in fullname:raise AssertionError('authoring import '+fullname)
sys.meta_path.insert(0,NoTools())
from unittest.mock import patch
from contextlib import nullcontext
from hepta import hia_opcodes as op
from hepta.hia_core_lowering_native import LoweringSession
assert op.__file__.startswith(sys.argv[1])
os.environ['HEPTA_HIA_EXECUTION_OBSERVATION_MANIFEST']=sys.argv[2]
ledger=dict.fromkeys(op.EXECUTION_RESOURCE_FIELDS,0)
with (patch('subprocess.Popen',side_effect=AssertionError('installed in-process no-child contract')) if sys.argv[3]=='inprocess' else nullcontext()),patch.object(op,'_reference_validate_execution_observation',side_effect=AssertionError('retained ledger')),patch.object(LoweringSession,'step',side_effect=AssertionError('retained step')),patch.object(LoweringSession,'handoff',side_effect=AssertionError('retained handoff')):
 assert op.validate_execution_observation('returned',ledger,steps=1,max_steps=10,max_heap_bytes=64) is None
assert not any(n=='tools' or n.startswith('tools.') for n in sys.modules)
print('installed native scheduling passed')
'''
        observed=subprocess.run([sys.executable,'-B','-I','-S','-c',code,str(site),str(selected),'inprocess' if in_process else 'subprocess'],cwd=directory,env={'PATH':''},capture_output=True,timeout=30)
        self.assertEqual(observed.returncode,0,observed.stdout+observed.stderr)
        self.assertEqual(observed.stdout,b'installed native scheduling passed\n')

    def test_inprocess_ordinary_selector_retains_original_objects_and_no_child_contract(self):
        from hepta import hia_opcodes
        from hepta.hia_core_lowering_native import LoweringSession
        from hepta.hia_native_continuation_inprocess import InProcessContinuation
        from hepta.hia_execution_observation_selection import SELECTOR,installed_execution_observation
        from tests.test_hia_execution_observation_native import cases,outcome
        path=self.development_selected_bundle('inprocess-selected',in_process=True)
        owner=installed_execution_observation(str(path),vars(hia_opcodes))
        expected=[(status,ledger,options,outcome(lambda status=status,ledger=ledger,options=options:hia_opcodes._reference_validate_execution_observation(status,ledger,**options))) for status,ledger,options in cases()]
        observations=[];original=InProcessContinuation.run
        def run(engine,session):
            result=original(engine,session)
            observations.append(session.native_observation)
            return result
        with patch.dict(os.environ,{SELECTOR:str(path)}),patch('subprocess.Popen',side_effect=AssertionError('in-process no-child contract')),patch.object(LoweringSession,'run',side_effect=AssertionError('host scheduler')),patch.object(LoweringSession,'step',side_effect=AssertionError('host step')),patch.object(LoweringSession,'handoff',side_effect=AssertionError('host handoff')),patch.object(hia_opcodes,'_reference_validate_execution_observation',side_effect=AssertionError('host ledger')),patch.object(InProcessContinuation,'run',run):
            for status,ledger,options,wanted in expected:
                with self.subTest(status=status,options=options):self.assertEqual(outcome(lambda:hia_opcodes.validate_execution_observation(status,ledger,**options)),wanted)
        self.assertTrue(observations)
        self.assertGreater(sum(h[3] for h in observations),0)
        self.assertGreater(sum(h[4] for h in observations),0)
        self.assertIs(installed_execution_observation(str(path),vars(hia_opcodes)),owner)

    def test_inprocess_single_use_source_capture_and_exception_closure(self):
        from hepta.hia_core_lowering_native import LoweringSession
        from hepta.hia_native_continuation_inprocess import InProcessContinuation
        peer=InProcessContinuation(self.inprocess_executable,sha256(self.inprocess_executable).hexdigest(),pool_bytes=self.abi['pool_bytes'])
        session=LoweringSession(self.owner,self.owner.modes['need']['number'],(True,None))
        with patch('subprocess.Popen',side_effect=AssertionError('no child')):
            self.assertIsNone(peer.run(session))
            self.assertTrue(session.finished)
            with self.assertRaisesRegex(RuntimeError,'already consumed'):peer.run(session)
        session=LoweringSession(self.owner,self.owner.modes['need']['number'],(True,None))
        with patch.object(session,'observe',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):peer.run(session)
        self.assertTrue(session.finished)
        self.assertIsNone(peer.invoke(self.owner,'need',(True,None)))
        for raw,digest,pool in ((self.inprocess_executable,'0'*64,self.abi['pool_bytes']),
                (b'bad',sha256(b'bad').hexdigest(),self.abi['pool_bytes']),
                (self.inprocess_executable,sha256(self.inprocess_executable).hexdigest(),True)):
            with self.assertRaises(ValueError):InProcessContinuation(raw,digest,pool_bytes=pool)

    def test_inprocess_warm_source_drift_refuses_before_native_entry(self):
        from hepta import hia_opcodes
        from hepta.hia_execution_observation_selection import installed_execution_observation
        path=self.development_selected_bundle('inprocess-drift',in_process=True)
        owner=installed_execution_observation(str(path),vars(hia_opcodes))
        target=path.parent/'continuation.image.bin';original=target.read_bytes()
        target.chmod(0o600);target.write_bytes(original+b'changed');target.chmod(0o400)
        try:
            with patch.object(owner._continuation,'_entry',side_effect=AssertionError('must refuse before entry')):
                with self.assertRaisesRegex(ValueError,'executable identity mismatch'):installed_execution_observation(str(path),vars(hia_opcodes))
        finally:target.chmod(0o600);target.write_bytes(original);target.chmod(0o400)

    def test_held_sessions_and_cached_engines_cannot_enter_unpinned_worker(self):
        from hepta.hia_core_lowering_native import LoweringSession
        from hepta.hia_native_helpers import native_helpers_scope
        from hepta.hia_native_continuation import NativeContinuation
        from hepta.hia_native_continuation_inprocess import InProcessContinuation
        mode=self.owner.modes['need']['number']
        engines=(NativeContinuation(self.path,sha256(self.executable).hexdigest(),pool_bytes=self.abi['pool_bytes']),
            InProcessContinuation(self.inprocess_executable,sha256(self.inprocess_executable).hexdigest(),pool_bytes=self.abi['pool_bytes']))
        for method in ('run','step','handoff','observe'):
            session=LoweringSession(self.owner,mode,(True,None))
            with native_helpers_scope(),patch.object(self.owner.images[0],'_entry',side_effect=AssertionError('unregistered native unit')):
                with self.assertRaisesRegex(ValueError,'outside the pinned worker bundle'):
                    getattr(session,method)(*([session.initial] if method=='step' else []))
            self.assertTrue(session.finished);self.assertFalse(session.pending)
        for engine in engines:
            session=LoweringSession(self.owner,mode,(True,None))
            with native_helpers_scope(),patch('subprocess.Popen',side_effect=AssertionError('unregistered native process')):
                with self.assertRaisesRegex(ValueError,'outside the pinned worker bundle'):engine.run(session)
            self.assertTrue(session.finished);self.assertFalse(session.pending)
        # Rejection consumes only the held session, not an unrelated fresh use.
        self.assertIsNone(engines[1].invoke(self.owner,'need',(True,None)))

    def test_inprocess_packer_matches_independent_Core_VM_and_original_caps(self):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        abi=dict(units=['test'],workspace_bytes=1024,output_bytes=128,pool_bytes=64,literal_count=3,modes={'test':dict(number=1,arity=0)})
        raw=packet(b'\xc3',b'\xc3',[b'\xc3'],abi)
        self.assertEqual(len(raw),99)
        source=(ROOT/'examples/hia_bootstrap/continuation_inprocess_packer.hepta').read_bytes()
        program=assemble_program(source);owners=[_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(b'\xa5'*2048)),_Owner(-3,bytearray(1024))]
        machine=_Machine(program,4_000_000,16<<20,None,128)
        wanted=machine.invoke(next(iter(machine.functions.values())),[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
        actual,output=call(self.images['continuation_inprocess_packer'],raw,2048)
        self.assertEqual(actual,wanted);self.assertEqual(output,bytes(owners[1].data));self.assertEqual(bytes(owners[0].data),raw)
        self.assertGreater(actual,176)
        for bad in (raw[:-1],raw+b'x',bytes(len(raw))):
            returned,output=call(self.images['continuation_inprocess_packer'],bad,2048)
            self.assertEqual(returned,0xffffffff);self.assertEqual(output,b'\xa5'*2048)
        returned,output=call(self.images['continuation_inprocess_packer'],raw,128)
        self.assertEqual(returned,0xfffffffe);self.assertEqual(output,b'\xa5'*128)

    def test_inprocess_invalid_unit_results_and_short_buffers_refuse_before_effects(self):
        from hepta.hia_core_lowering_native import LoweringSession
        from hepta.hia_native_continuation_inprocess import InProcessContinuation,WORK,OUTPUT
        def emitted(status,opcode=0,target=0,magic=MAGIC):
            code=b''
            for offset,value in ((0,magic),(16,opcode),(24,target)):
                code+=b'\x48\xb8'+struct.pack('<Q',value)+b'\x48\x89\x42'+bytes([offset])
            return code+b'\x48\xb8'+struct.pack('<Q',status)+b'\xc3'
        stubs=[emitted(s) for s in (1<<32,(1<<32)+1,3,0xffffffffffffffff)]
        stubs.extend((emitted(2,19,1),emitted(1,19),emitted(0,1),emitted(0,0,magic=0)))
        abi={**self.abi,'units':['test-only-refusal']}
        for index,stub in enumerate(stubs):
            with self.subTest(stub=index):
                raw=packet(self.image_bytes['continuation_policy'],self.native[0],[stub],abi)
                size,output=call(self.images['continuation_inprocess_packer'],raw)
                self.assertTrue(176<size<len(output))
                raw=output[:size];peer=InProcessContinuation(raw,sha256(raw).hexdigest(),pool_bytes=abi['pool_bytes'])
                session=LoweringSession(self.owner,self.owner.modes['need']['number'],(True,None))
                with patch.object(session,'observe',side_effect=AssertionError('invalid native frame escaped to effect')):
                    with self.assertRaisesRegex(RuntimeError,'protocol refusal: 16'):peer.run(session)
                self.assertTrue(session.finished);self.assertFalse(session.pending)
        peer=InProcessContinuation(self.inprocess_executable,sha256(self.inprocess_executable).hexdigest(),pool_bytes=self.abi['pool_bytes'])
        source=ctypes.create_string_buffer(128);output=ctypes.create_string_buffer(b'\xa5'*OUTPUT);work=ctypes.create_string_buffer(WORK)
        for input_size,output_size,work_size in ((127,OUTPUT,WORK),(128,OUTPUT-1,WORK),(128,OUTPUT,WORK-1)):
            self.assertEqual(peer._entry(source,input_size,output,output_size,work,work_size),17)
            self.assertEqual(output.raw[:OUTPUT],b'\xa5'*OUTPUT);self.assertEqual(work.raw,bytes(WORK))
        session=LoweringSession(self.owner,self.owner.modes['need']['number'],(True,None))
        with patch('hepta.hia_native_continuation_inprocess._protect',side_effect=OSError('protection refused')):
            with self.assertRaisesRegex(OSError,'protection refused'):peer.run(session)
        self.assertTrue(session.finished)

    def read(self,proc,size,deadline):
        result=bytearray()
        while len(result)<size:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([proc.stdout],[],[],remaining)[0]:raise TimeoutError('native continuation peer deadline')
            part=os.read(proc.stdout.fileno(),size-len(result))
            if not part:raise RuntimeError('native continuation truncated event')
            result.extend(part)
        return bytes(result)

    def invoke(self,name,arguments,trace=None):
        from hepta.hia_core_lowering_native import LoweringSession,_decode_pool
        mode=self.owner.modes[name];session=LoweringSession(self.owner,mode['number'],arguments)
        argv=[str(self.path)] if trace is None else [shutil.which('strace'),'-f','-o',str(trace),'-e','trace=execve,open,openat,clone,clone3,fork,vfork',str(self.path)]
        proc=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''},cwd=self.directory.name,bufsize=0)
        deadline=time.monotonic()+10
        try:
            header=EVENT.unpack(self.read(proc,64,deadline));self.assertEqual(header[:3],(RPC,3,self.abi['pool_bytes']))
            pool=self.read(proc,header[2],deadline);self.assertEqual(_decode_pool(pool,self.abi['literal_count']),self.owner.literals)
            proc.stdin.write(session.initial)
            while True:
                header=EVENT.unpack(self.read(proc,64,deadline));self.assertEqual(header[0],RPC)
                self.assertLessEqual(header[2],self.abi['output_bytes']);body=self.read(proc,header[2],deadline)
                words=FRAME.unpack_from(body)
                if header[1]==0:
                    self.assertEqual(len(body),128);self.assertEqual(words[2],0)
                    proc.stdin.close();proc.wait(timeout=max(0.001,deadline-time.monotonic()))
                    self.assertEqual(proc.returncode,0);self.assertEqual(proc.stdout.read(),b'');self.assertEqual(proc.stderr.read(),b'')
                    self.native_counts.append(header)
                    return session.value(words[3])
                self.assertEqual(header[1],1)
                self.assertEqual(len(body),128+words[4]*8)
                session.status,session.pending=1,True
                session.request=(words,struct.unpack_from('<'+'Q'*words[4],body,128))
                proc.stdin.write(session.observe())
        finally:
            if proc.poll() is None:proc.kill();proc.wait(timeout=3)
            for stream in (proc.stdin,proc.stdout,proc.stderr):stream.close()

    def test_real_multi_image_ledger_with_host_scheduler_forbidden(self):
        from hepta import hia_opcodes
        from hepta.hia_core_lowering_native import LoweringSession
        from tests.test_hia_execution_observation_native import cases,outcome
        observed=[]
        with patch.object(LoweringSession,'step',side_effect=AssertionError('retained host step')),patch.object(LoweringSession,'handoff',side_effect=AssertionError('retained host handoff')),patch.object(self.owner,'invoke',side_effect=lambda name,args:self.invoke(name,args)):
            for status,ledger,options in cases():
                with self.subTest(status=status,options=options):
                    expected=outcome(lambda:hia_opcodes._reference_validate_execution_observation(status,ledger,**options))
                    actual=outcome(lambda:self.owner.invoke('validate_execution_observation',(status,ledger,(
                        options['steps'],options['max_steps'],options['max_heap_bytes'],options.get('error_code'),options.get('with_chains',False),options.get('allow_host_memory',False),options.get('live_external_roots',0)))))
                    self.assertEqual(actual,expected);observed.append(actual[0])
        self.assertIn('returned',observed);self.assertIn('raised',observed)
        self.assertTrue(any(row[4]>0 for row in self.native_counts))

    def test_descriptor_pinned_ordinary_transport_replaces_host_scheduler(self):
        from hepta import hia_opcodes
        from hepta.hia_core_lowering_native import LoweringSession
        from hepta.hia_native_continuation import NativeContinuation
        from tests.test_hia_execution_observation_native import cases,outcome
        peer=NativeContinuation(self.path,sha256(self.executable).hexdigest(),pool_bytes=self.abi['pool_bytes'])
        counts=[]
        def invoke(name,args):
            mode=self.owner.modes[name];session=LoweringSession(self.owner,mode['number'],args)
            returned=peer.run(session,timeout=10);counts.append(session.native_observation)
            self.assertTrue(session.finished)
            with self.assertRaisesRegex(RuntimeError,'consumed'):peer.run(session)
            return returned
        with patch.object(LoweringSession,'step',side_effect=AssertionError('retained step')),patch.object(LoweringSession,'handoff',side_effect=AssertionError('retained handoff')),patch.object(self.owner,'invoke',side_effect=invoke):
            for status,ledger,options in cases():
                with self.subTest(status=status,options=options):
                    expected=outcome(lambda:hia_opcodes._reference_validate_execution_observation(status,ledger,**options))
                    actual=outcome(lambda:peer.invoke(self.owner,'validate_execution_observation',(status,ledger,(
                        options['steps'],options['max_steps'],options['max_heap_bytes'],options.get('error_code'),options.get('with_chains',False),options.get('allow_host_memory',False),options.get('live_external_roots',0)))))
                    self.assertEqual(actual,expected)
        self.assertTrue(any(row[4]>0 for row in counts))
        self.assertEqual(self.path.read_bytes(),self.executable)

    def test_descriptor_transport_refuses_identity_modes_and_links(self):
        from hepta.hia_native_continuation import NativeContinuation
        peer=NativeContinuation(self.path,'0'*64,pool_bytes=self.abi['pool_bytes'])
        with self.assertRaisesRegex(ValueError,'identity mismatch'):peer.invoke(self.owner,'need',(True,'unused'))
        target=Path(self.directory.name)/'writable';target.write_bytes(self.executable);target.chmod(0o720)
        peer=NativeContinuation(target,sha256(self.executable).hexdigest(),pool_bytes=self.abi['pool_bytes'])
        with self.assertRaisesRegex(ValueError,'owned bounded ordinary'):peer.invoke(self.owner,'need',(True,'unused'))

    def test_sealed_execution_resists_same_inode_rewrite_and_retains_custody(self):
        import errno
        import fcntl
        from hepta import hia_native_continuation as transport
        from hepta.hia_core_lowering_native import LoweringSession
        target=Path(self.directory.name)/'source-race';target.write_bytes(self.executable);target.chmod(0o500)
        original_inode=target.stat().st_ino
        peer=transport.NativeContinuation(target,sha256(self.executable).hexdigest(),pool_bytes=self.abi['pool_bytes'])
        real_popen=subprocess.Popen;observations=[]
        def changed_popen(argv,**kwargs):
            fd,=kwargs['pass_fds']
            seals=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
            self.assertEqual(fcntl.fcntl(fd,fcntl.F_GET_SEALS)&seals,seals)
            for operation in (lambda:os.pwrite(fd,b'X',0),lambda:os.ftruncate(fd,0),lambda:os.ftruncate(fd,len(self.executable)+1)):
                with self.assertRaises(OSError) as caught:operation()
                self.assertEqual(caught.exception.errno,errno.EPERM)
            self.assertEqual(os.pread(fd,len(self.executable)+1,0),self.executable)
            target.chmod(0o700);target.write_bytes(b'not executable replacement bytes');target.chmod(0o500)
            self.assertEqual(target.stat().st_ino,original_inode)
            proc=real_popen(argv,**kwargs);observations.append(proc)
            return proc
        session=LoweringSession(self.owner,self.owner.modes['need']['number'],(True,'unused'))
        with patch.object(transport.subprocess,'Popen',side_effect=changed_popen):
            with self.assertRaisesRegex(ValueError,'changed during invocation'):peer.run(session,timeout=10)
        self.assertTrue(session.finished)
        self.assertTrue(hasattr(session,'native_observation'))
        self.assertEqual(observations[0].returncode,0)
        # Changed source is still rejected; only its original immutable bytes
        # executed. The old mutable-inode execution race is not reclassified.
        self.assertNotEqual(target.read_bytes(),self.executable)
        target.chmod(0o500);linked=Path(self.directory.name)/'hardlink';os.link(target,linked)
        with self.assertRaisesRegex(ValueError,'owned bounded ordinary'):peer.invoke(self.owner,'need',(True,'unused'))

    def test_open_refusals_close_consumed_sessions_without_descriptor_leaks(self):
        from hepta.hia_core_lowering_native import LoweringSession
        from hepta.hia_native_continuation import NativeContinuation
        root=Path(self.directory.name)
        denied=root/'open-refusal-denied';denied.write_bytes(self.executable);denied.chmod(0)
        linked=root/'open-refusal-link';linked.symlink_to(denied)
        fifo=root/'open-refusal-fifo';os.mkfifo(fifo,0o600)
        before=len(list(Path('/proc/self/fd').iterdir()))
        try:
            for path in (root/'open-refusal-missing',denied,linked,root,fifo):
                with self.subTest(path=path.name):
                    peer=NativeContinuation(path,sha256(self.executable).hexdigest(),pool_bytes=self.abi['pool_bytes'])
                    session=LoweringSession(self.owner,self.owner.modes['need']['number'],(True,None))
                    with self.assertRaises((OSError,ValueError)):peer.run(session,timeout=1)
                    self.assertTrue(session.finished)
                    self.assertFalse(session.pending)
                    self.assertIsNone(session.request)
                    self.assertTrue(session._native_started)
                    with self.assertRaisesRegex(RuntimeError,'consumed'):peer.run(session)
        finally:denied.chmod(0o600)
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)

    def test_no_runtime_tool_file_or_child_dependency(self):
        if not shutil.which('strace'):self.fail('real strace prerequisite required')
        trace=Path(self.directory.name)/'effects.log'
        self.assertIsNone(self.invoke('need',(True,'unused'),trace))
        raw=trace.read_text()
        self.assertEqual(raw.count('execve('),1)
        self.assertNotIn('open(',raw);self.assertNotIn('openat(',raw)
        for operation in ('clone(','clone3(','fork(','vfork('):self.assertNotIn(operation,raw)

    def test_exact_packer_rejections_and_output_canary(self):
        image=self.images['continuation_packer']
        for at,value in ((0,0),(8,0),(16,0),(16,129),(24,1023),(32,127),(40,63),(48,2),(56,0),(56,1025),(64,0),(72,0)):
            raw=bytearray(self.input);struct.pack_into('<Q',raw,at,value)
            self.assertEqual(call(image,bytes(raw))[0],0xffffffff,(at,value))
        self.assertEqual(call(image,self.input[:-1])[0],0xffffffff)
        self.assertEqual(call(image,self.input+b'x')[0],0xffffffff)
        self.assertEqual(call(image,self.input,128)[0],0xfffffffe)

    def test_eof_extra_arguments_and_partial_packet_refuse(self):
        for argv,wire in (([str(self.path)],b''),([str(self.path)],b'x'*127),([str(self.path),'extra'],b'')):
            result=subprocess.run(argv,input=wire,capture_output=True,timeout=3,env={'PATH':''})
            self.assertEqual(result.returncode,16)
            self.assertEqual(result.stderr,b'')
        self.assertEqual(subprocess.run([str(self.path)],input=FRAME.pack(0,*([0]*15)),capture_output=True,timeout=3).returncode,16)

    def test_dirty_native_result_and_invalid_frames_never_reach_peer(self):
        def emitted(status,opcode,unit=0,magic=MAGIC):
            # Test-only trusted native stubs deliberately violate the image ABI.
            # The scheduler must reject them before an external peer effect.
            code=b''
            for offset,value in ((0,magic),(16,opcode),(24,unit)):
                code+=b'\x48\xb8'+struct.pack('<Q',value)+b'\x48\x89\x42'+bytes([offset])
            return code+b'\x48\xb8'+struct.pack('<Q',status)+b'\xc3'
        stubs=[b'\x48\xb8'+struct.pack('<Q',x)+b'\xc3' for x in (1<<32,(1<<32)+1,3,0xffffffffffffffff)]
        stubs.extend((emitted(2,19,1),emitted(1,19),emitted(0,1),emitted(0,0,magic=0)))
        abi={**self.abi,'units':['test-only-refusal']}
        initial=FRAME.pack(MAGIC,0,0,1,3,*([0]*11))
        for i,stub in enumerate(stubs):
            with self.subTest(stub=i):
                raw=packet(self.image_bytes['continuation_policy'],self.native[0],[stub],abi)
                size,built=call(self.images['continuation_packer'],raw)
                self.assertLess(size,len(built))
                target=Path(self.directory.name)/('refusal-'+str(i));target.write_bytes(built[:size]);target.chmod(0o500)
                result=subprocess.run([str(target)],input=initial,capture_output=True,timeout=3,env={'PATH':''})
                self.assertEqual(result.returncode,16)
                # Only the pool event can precede a refusal. No object effect
                # request or fake terminal result can escape on stdout.
                self.assertEqual(len(result.stdout),64+self.abi['pool_bytes'])
                self.assertEqual(result.stderr,b'')

    def test_closed_output_reports_io_error_instead_of_sigpipe(self):
        # Close the read end BEFORE exec. Closing Popen's PIPE afterwards races
        # with a child which can write its 2,640-byte pool event and finish EOF
        # handling before the parent is scheduled to close the reader.
        reader,writer=os.pipe()
        os.close(reader)
        try:
            proc=subprocess.Popen([str(self.path)],stdin=subprocess.DEVNULL,stdout=writer,stderr=subprocess.PIPE,env={'PATH':''})
        finally:
            os.close(writer)
        try:
            self.assertEqual(proc.wait(timeout=3),15)
            self.assertEqual(proc.stderr.read(),b'')
        finally:
            if proc.poll() is None:proc.kill();proc.wait(timeout=3)
            proc.stderr.close()


if __name__=='__main__':unittest.main()
