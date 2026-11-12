"""Actual sdist/wheel/installed native-worker resources, not source-path borrowing."""
from pathlib import Path
from hashlib import sha256
import json,os,shutil,subprocess,sys,tarfile,tempfile,unittest,zipfile
from hepta.hia_agent_contract import DISCOVERY_FILES,NATIVE_SOURCE_FILES,SOURCE_BUILD_FILES,COMPILER_BUILD_FILES,PUBLICATION_BUILD_FILES,installation_manifest
from hepta.hia_agent_store import wire
ROOT=Path(__file__).resolve().parents[1]
RESOURCES=tuple('docs/'+n for n in DISCOVERY_FILES)+NATIVE_SOURCE_FILES+SOURCE_BUILD_FILES+COMPILER_BUILD_FILES+PUBLICATION_BUILD_FILES
# Actual runtime bindings include single-image aliases and shared source tables.
BUNDLED_SOURCE_BINDINGS={
    'cli_control':('hepta.hia_cli_native','SOURCES','control'),
    'cli_format':('hepta.hia_cli_native','SOURCES','format'),
    'composite_function_admit':('hepta.hia_composite_functions_native','SOURCES','admit'),
    'composite_function_records':('hepta.hia_composite_functions_native','SOURCES','records'),
    'composite_function_advanced':('hepta.hia_composite_functions_native','SOURCES','advanced'),
    'composite_function_terms':('hepta.hia_composite_functions_native','SOURCES','terms'),
    'composite_function_render':('hepta.hia_composite_functions_native','SOURCES','render'),
    'composite_constructor_owner':('hepta.hia_composite_constructor_native','SOURCES','owner'),
    'composite_constructor_render':('hepta.hia_composite_constructor_native','SOURCES','render'),
    'composite_outer_owner':('hepta.hia_composite_outer_native','SOURCES','owner'),
    'composite_outer_render':('hepta.hia_composite_outer_native','SOURCES','render'),
    'heap_live_engine':('hepta.hia_heap_live_native','SOURCE',None),
    'program_normalization':('hepta.hia_program_normalization_native','SOURCES','normalization'),
    'cpython_note_packer':('hepta.hia_program_normalization_native','NOTE_SOURCES','examples/hia_bootstrap/cpython_note_packer.hiaasm'),
    'hia_program_normalization_notes':('hepta.hia_program_normalization_native','NOTE_SOURCES','hepta/hia_program_normalization_notes.py'),
}

class AgentInstalledResourceSourceTests(unittest.TestCase):
    def test_actual_build_hook_uses_distinct_discovery_and_native_resource_paths(self):
        import ast
        source=ast.parse((ROOT/'setup.py').read_text())
        functions=[n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='agent_resources']
        self.assertEqual(len(functions),1)
        namespace={'ast':ast,'Path':Path,'ROOT':ROOT}
        exec(compile(ast.Module(body=functions,type_ignores=[]),'setup.py','exec'),namespace)
        self.assertEqual(namespace['agent_resources'](),RESOURCES)

    def test_sdist_manifest_explicitly_preserves_every_agent_resource(self):
        declared={line.removeprefix('include ') for line in (ROOT/'MANIFEST.in').read_text().splitlines() if line.startswith('include ')}
        self.assertEqual(declared,set(RESOURCES));self.assertEqual(len(declared),len(RESOURCES))

    def test_every_actual_worker_asset_is_in_source_release_and_shared_identity(self):
        from tools.hia_selfhost_contract import SOURCE_FILES,CONTRACT_PATH
        from tools.hia_release import BOOTSTRAP_FILES
        for paths in ((*SOURCE_FILES,CONTRACT_PATH),BOOTSTRAP_FILES):
            self.assertLessEqual(set(RESOURCES),set(paths))

    def test_complete_source_binding_map_matches_each_actual_runtime_bridge(self):
        from importlib import import_module
        observed={}
        for resource in NATIVE_SOURCE_FILES:
            name=Path(resource).stem
            if name in BUNDLED_SOURCE_BINDINGS:
                module,attribute,key=BUNDLED_SOURCE_BINDINGS[name]
                binding=getattr(import_module(module),attribute)
                source=binding if key is None else binding[key]
            else:
                source=import_module('hepta.hia_'+name+'_native').SOURCE
            self.assertEqual(source,ROOT/resource)
            observed[name]=source
        self.assertEqual(len(observed),len(NATIVE_SOURCE_FILES))
        self.assertLessEqual(set(BUNDLED_SOURCE_BINDINGS),set(observed))

class AgentInstalledResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_agent_identity_native import witnesses
        witnesses() # Complete independent VM bytes precede native seed.
        from tests.test_hia_agent_slice_native import references
        references() # Graph result bytes also precede native seed.
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        from hepta.hia_agent_identity_native import SOURCE,SCHEMA
        from tests.test_hia_agent_entry import CHILD
        from tests.test_hia_artifact_publication_native import observe,fields,vm_pack
        observe(b'abc',b'abc',fields(p0=3,p16=3,p24=3))
        vm_pack(b'\xc3',b'\xc3')  # Publication policy/packer VM before native seed.
        cls.temp=tempfile.TemporaryDirectory(prefix='hia-installed-resources-');cls.folder=Path(cls.temp.name)
        source=cls.folder/'source';source.mkdir();cls.source=source
        shutil.copytree(ROOT/'hepta',source/'hepta',ignore=shutil.ignore_patterns('__pycache__'))
        for name in (*RESOURCES,'setup.py','pyproject.toml','MANIFEST.in'):
            target=source/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
        def build(name,args):
            with (cls.folder/(name+'.log')).open('xb') as out:
                result=subprocess.run([sys.executable,'-B',*map(str,args)],cwd=source,
                    env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},stdout=out,stderr=subprocess.STDOUT)
            if result.returncode:raise AssertionError(name+': '+(cls.folder/(name+'.log')).read_text())
        # Exercise both source-distribution and wheel packaging, outside ROOT.
        build('sdist',['setup.py','sdist','--dist-dir',cls.folder/'sdist'])
        archive,=(cls.folder/'sdist').glob('*.tar.gz')
        with tarfile.open(archive) as tar:
            paths=tar.getnames();prefix=paths[0].split('/')[0]+'/'
            for name in RESOURCES:assert tar.extractfile(prefix+name).read()==(ROOT/name).read_bytes()
        build('wheel',['-m','pip','wheel','--no-deps','--no-build-isolation','--wheel-dir',cls.folder/'wheels',archive])
        wheel,=(cls.folder/'wheels').glob('*.whl');cls.wheel=wheel;cls.installed=cls.folder/'installed'
        build('install',['-m','pip','install','--no-deps','--no-index','--target',cls.installed,wheel])
        cls.native=cls.folder/'native';cls.native.mkdir()
        seed,_=build_seed(cls.native);compiler=(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
        first,_=compile_stage(cls.native,'B1',seed,compiler,image_format='seed-shared')
        second,_=compile_stage(cls.native,'B2',first,compiler);assert first.read_bytes()==second.read_bytes()
        image,_=compile_stage(cls.native,'identity',second,SOURCE.read_bytes())
        cls.manifest=cls.native/'manifest.json';cls.manifest.write_text(json.dumps(dict(schema=SCHEMA,source_sha256=sha256(SOURCE.read_bytes()).hexdigest(),image_path=image.name,image_sha256=sha256(image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        from hepta.hia_agent_slice_native import SOURCE as SLICE_SOURCE,SCHEMA as SLICE_SCHEMA
        slice_image,_=compile_stage(cls.native,'slice',second,SLICE_SOURCE.read_bytes())
        cls.slice_manifest=cls.native/'slice-manifest.json'
        cls.slice_manifest.write_text(json.dumps(dict(schema=SLICE_SCHEMA,
            source_sha256=sha256(SLICE_SOURCE.read_bytes()).hexdigest(),image_path=slice_image.name,
            image_sha256=sha256(slice_image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        from hepta.hia_agent_data_json_native import SOURCE as DATA_SOURCE, SCHEMA as DATA_SCHEMA
        data_image,_=compile_stage(cls.native,'agent-data-json',second,DATA_SOURCE.read_bytes())
        cls.data_manifest=cls.native/'data-manifest.json'
        cls.data_manifest.write_text(json.dumps(dict(schema=DATA_SCHEMA,
            source_sha256=sha256(DATA_SOURCE.read_bytes()).hexdigest(),image_path=data_image.name,
            image_sha256=sha256(data_image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        from hepta.hia_agent_binary64_native import SOURCE as FLOAT_SOURCE, SCHEMA as FLOAT_SCHEMA
        float_image,_=compile_stage(cls.native,'agent-binary64',second,FLOAT_SOURCE.read_bytes())
        cls.float_manifest=cls.native/'binary64-manifest.json'
        cls.float_manifest.write_text(json.dumps(dict(schema=FLOAT_SCHEMA,
            source_sha256=sha256(FLOAT_SOURCE.read_bytes()).hexdigest(),image_path=float_image.name,
            image_sha256=sha256(float_image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        # These are the genuine B2-produced Core-policy images, not a fixture ABI.
        cls.core_manifests={}
        from importlib import import_module
        for key in ('program_shape','instruction_policy','core_admission'):
            module=import_module('hepta.hia_'+key+'_native')
            core_image,_=compile_stage(cls.native,key,second,module.SOURCE.read_bytes())
            core_manifest=cls.native/(key+'-manifest.json')
            core_manifest.write_text(json.dumps(dict(schema=module.SCHEMA,
                source_sha256=sha256(module.SOURCE.read_bytes()).hexdigest(),image_path=core_image.name,
                image_sha256=sha256(core_image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
            cls.core_manifests[key]=core_manifest
        from hepta.hia_agent_binary64_format_native import SOURCE as PRINT_SOURCE, SCHEMA as PRINT_SCHEMA
        print_image,_=compile_stage(cls.native,'agent-binary64-format',second,PRINT_SOURCE.read_bytes())
        cls.print_manifest=cls.native/'binary64-format-manifest.json'
        cls.print_manifest.write_text(json.dumps(dict(schema=PRINT_SCHEMA,
            source_sha256=sha256(PRINT_SOURCE.read_bytes()).hexdigest(),image_path=print_image.name,
            image_sha256=sha256(print_image.read_bytes()).hexdigest(),compiler_sha256=sha256(second.read_bytes()).hexdigest())))
        from hepta.hia_native_helpers import SCHEMA as HELPERS_SCHEMA, TARGET as HELPERS_TARGET, ABI as HELPERS_ABI
        cls.helpers_manifest=cls.native/'worker-helpers.json'
        cls.helpers_manifest.write_text(json.dumps({
            'schema':HELPERS_SCHEMA,'target':HELPERS_TARGET,'abi':HELPERS_ABI,
            'helpers':[{'selector':selector,'manifest_path':manifest.name,
                        'manifest_sha256':sha256(manifest.read_bytes()).hexdigest()}
                       for selector,manifest in (
                           ('HEPTA_HIA_AGENT_IDENTITY_MANIFEST',cls.manifest),
                           ('HEPTA_HIA_AGENT_SLICE_MANIFEST',cls.slice_manifest),
                           ('HEPTA_HIA_AGENT_DATA_JSON_MANIFEST',cls.data_manifest),
                           ('HEPTA_HIA_AGENT_BINARY64_MANIFEST',cls.float_manifest),
                           ('HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST',cls.print_manifest))]},
            sort_keys=True),encoding='utf-8')
        cls.helpers_sha256=sha256(cls.helpers_manifest.read_bytes()).hexdigest()
        cls.helper_flags=('--native-helpers-manifest',str(cls.helpers_manifest),
                          '--expected-native-helpers-sha256',cls.helpers_sha256)
        from tools.build_hia_artifact_publication import build,current_sources,SOURCES,OPERATIONS
        from tools.hia_selfhost_contract import PROFILE
        cls.publication=cls.native/'publication';cold_path=os.environ.get('HEPTA_HIA_ARTIFACT_PUBLICATION_COLD_REPORT')
        if cold_path:
            cold=json.loads(Path(cold_path).read_bytes());nested=json.loads(Path(cold['nested_report']).read_bytes())
            qualified=Path(nested['generations'][-1]['produced_image'])
            assert qualified.read_bytes()==second.read_bytes()
            build(cls.publication,qualified,Path(cold_path))
        else:
            # Honest actual B2 development build; never invent a cold PASS.
            from tools.qualify_hia_selfhost import invoke
            from tools.generate_hia_artifact_publication import MAGIC
            from tools.qualify_hia_selfhost_cli import inspect_executable
            import struct
            cls.publication.mkdir();images={}
            for label,name in zip(('policy','packer','sha256'),SOURCES[:3]):
                images[label],_=compile_stage(cls.publication,label,second,(ROOT/name).read_bytes())
            policy=images['policy'].read_bytes();sha=images['sha256'].read_bytes()
            result,raw=invoke(cls.publication,'pack',images['packer'],struct.pack('<3Q',MAGIC,len(policy),len(sha))+policy+sha)
            assert result['status']=='returned' and 0<result['core_u32']<=len(raw)
            code=raw[:result['core_u32']];inspect_executable(code)
            app=cls.publication/'hia-artifact';app.write_bytes(code);app.chmod(0o700)
            (cls.publication/'build.json').write_text(json.dumps(dict(schema='hepta.hia.artifact-publication-build.v1',
                status='NATIVE_ARTIFACT_PUBLICATION_BUILT',profile=PROFILE,source_manifest=current_sources(),operations=OPERATIONS,
                executable_path='hia-artifact',executable_sha256=sha256(code).hexdigest(),
                source_sha256={name:sha256((ROOT/name).read_bytes()).hexdigest() for name in SOURCES},development_only=True)))
        prefix=CHILD.split('from hepta.cli import')[0]
        cls.child='import sys\nsys.path.insert(0,sys.argv[1])\n'+prefix+'\nBUNDLED_SOURCE_BINDINGS='+repr(BUNDLED_SOURCE_BINDINGS)+'\n'+'''
from pathlib import Path
from hepta import hia_agent_store as store
from hepta.hia_agent_identity_native import SOURCE
assert Path(sys.argv[1]) in SOURCE.parents,SOURCE
assert not any('agent-identity-install-development' in p for p in sys.path)
def absent(*a,**kw):raise AssertionError('foreign scalar identity predicate')
store._reference_uint64=absent;store._reference_digest=absent
assert store.uint64('18446744073709551615','epoch')==18446744073709551615
assert store.canonical_digest('a'*64)
from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_worker import main
if sys.argv[2]=='identity':print(__import__('json').dumps(installation_manifest()))
elif sys.argv[2]=='printing':
    from hepta.hia_agent_binary64_format_native import SOURCE as PRINT_SOURCE
    assert Path(sys.argv[1]) in PRINT_SOURCE.parents,PRINT_SOURCE
    import json
    json.JSONEncoder.iterencode=absent
    sys.stdout.buffer.write(store.wire({'zero':-0.0,'ratio':1.25,'tiny':5e-324,'large':1e16,'text':'中'}))
elif sys.argv[2] in ('publication','artifact-store'):
    import importlib.abc,os,inspect
    class NoBuildTools(importlib.abc.MetaPathFinder):
        def find_spec(self,fullname,path=None,target=None):
            if fullname=='tools' or fullname.startswith('tools.'):
                raise AssertionError('installed runtime tried to import checkout build tools')
    sys.meta_path.insert(0,NoBuildTools())
    manifest=sys.argv[3];case=Path(sys.argv[4]);payload=b'installed\\x00native\\xff'
    if sys.argv[2]=='publication':
        from hepta import artifact_publication as publication
        os.environ['HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST']=manifest
        publication._read_exact=absent;publication.sha256=absent
        stage=case/'stage';dest=case/'published'
        receipt=publication.publish_verified(stage,dest,payload)
        assert publication.verify_published(stage,dest,payload)==receipt
        assert stage.stat().st_ino==dest.stat().st_ino
        assert publication.withdraw_own_link(stage,dest) and not dest.exists()
        print(json.dumps(receipt,sort_keys=True))
    else:
        os.environ['HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST']=manifest
        original_hash=store.sha256;original_read=store.stable_read
        def guard_hash(data):
            if inspect.currentframe().f_back.f_code.co_name in ('put','get'):absent()
            return original_hash(data)
        def guard_read(*args,**kwargs):
            if inspect.currentframe().f_back.f_code.co_name in ('put','get'):absent()
            return original_read(*args,**kwargs)
        store.sha256=guard_hash;store.stable_read=guard_read
        state=store.AgentStore(case/'state')
        try:
            ref=state.put(payload,'input',{'installed':True})
            assert state.get(ref)==(payload,{'installed':True})
            assert state.put(payload,'input',{'installed':True})==ref
        finally:state.close()
        state=store.AgentStore(case/'state')
        try:assert state.get(ref)==(payload,{'installed':True})
        finally:state.close()
        print(json.dumps(ref,sort_keys=True))
    assert not any(n=='tools' or n.startswith('tools.') for n in sys.modules)
elif sys.argv[2]=='data':
    from hepta.hia_agent_data_json_native import SOURCE as DATA_SOURCE
    assert Path(sys.argv[1]) in DATA_SOURCE.parents,DATA_SOURCE
    import json
    json.loads=absent;store.re.compile=absent;store.preflight_hia_json=absent
    store.float=absent
    from hepta.hia_agent_binary64_native import SOURCE as FLOAT_SOURCE
    assert Path(sys.argv[1]) in FLOAT_SOURCE.parents,FLOAT_SOURCE
    print(json.dumps(store.decode_data(sys.stdin.buffer.read()),ensure_ascii=False,sort_keys=True))
elif sys.argv[2]=='source-bindings':
    from importlib import import_module
    from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
    names=[Path(name).stem for name in NATIVE_SOURCE_FILES]
    observed={}
    for name in names:
        if name in BUNDLED_SOURCE_BINDINGS:
            module,attribute,key=BUNDLED_SOURCE_BINDINGS[name]
            binding=getattr(import_module(module),attribute)
            source=binding if key is None else binding[key]
        else:
            source=import_module('hepta.hia_'+name+'_native').SOURCE
        assert Path(sys.argv[1]) in source.parents,source
        assert source.is_file(),source
        observed[name]=str(source.relative_to(Path(sys.argv[1])/'hepta/_data'))
    print(__import__('json').dumps(observed,sort_keys=True))
elif sys.argv[2] in ('native-Core','native-Core-whole'):
    import os
    from hepta import hia_program as Core
    from hepta.hia_program_tools import decode_json
    os.environ['HEPTA_HIA_PROGRAM_SHAPE_MANIFEST']=sys.argv[3]
    os.environ['HEPTA_HIA_INSTRUCTION_POLICY_MANIFEST']=sys.argv[4]
    Core._reference_primitive_structure=absent;Core._reference_function_shape=absent
    Core.opcode_spec=absent;Core.check_instruction=absent
    if sys.argv[2]=='native-Core-whole':
        os.environ['HEPTA_HIA_CORE_ADMISSION_MANIFEST']=sys.argv[5]
        Core._verify_function=absent
    checked=Core.verify_program(decode_json(sys.stdin.buffer.read()))
    print(__import__('json').dumps(Core.execute_program(checked,'answer',[])))
elif sys.argv[2]=='slice':
    from hepta import hia_edit_query as editing
    from hepta.hia_agent_slice_native import SOURCE as SLICE_SOURCE
    assert Path(sys.argv[1]) in SLICE_SOURCE.parents,SLICE_SOURCE
    editing._reference_edit_slice=absent;editing._cfg_downstream_slice=absent
    doc=__import__('json').loads(sys.stdin.buffer.read())
    print(__import__('json').dumps(editing.prepare_edit(doc,function='calculate',block='entry',output='y',fields=['op'])))
else:
    # Direct installed-helper controls above keep their explicit selectors.
    # Worker entry receives only the administrator-pinned CLI bundle.
    import os
    for key in tuple(os.environ):
        if key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'):
            del os.environ[key]
    result=main(['--state-root',sys.argv[2],'--request-json-stdin',*sys.argv[3:]])
    assert not blocked.intersection(sys.modules)
    raise SystemExit(result)
assert not blocked.intersection(sys.modules)
'''
        cls.identity=json.loads(cls.invoke('identity',b'').stdout)
        cls.request=dict(schema='hia-agent-worker-request-v1',tool='hia_describe',arguments={'section':'language'},profile_sha256='a'*64,catalog_sha256=cls.identity['catalog_sha256'])
        cls.request['request_sha256']=sha256(wire(cls.request)).hexdigest()

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    @classmethod
    def invoke(cls,state,request,extra=()):
        if str(state) not in ('identity','printing','publication','artifact-store','data',
                              'source-bindings','native-Core','native-Core-whole','slice'):
            extra=(*cls.helper_flags,*extra)
        return subprocess.run([sys.executable,'-I','-S','-B','-c',cls.child,str(cls.installed),str(state),*extra],input=request,capture_output=True,timeout=15,cwd=cls.folder,
            env={'PATH':'','LANG':'C','LC_ALL':'C','HEPTA_HIA_AGENT_IDENTITY_MANIFEST':str(cls.manifest),'HEPTA_HIA_AGENT_SLICE_MANIFEST':str(cls.slice_manifest),
                 'HEPTA_HIA_AGENT_DATA_JSON_MANIFEST':str(cls.data_manifest),
                 'HEPTA_HIA_AGENT_BINARY64_MANIFEST':str(cls.float_manifest),
                 'HEPTA_HIA_AGENT_BINARY64_FORMAT_MANIFEST':str(cls.print_manifest)})

    def publication_case(self,label):
        case=self.folder/label;case.mkdir()
        (case/'stage').write_bytes(b'installed\x00native\xff')
        return case

    def test_actual_installed_native_publication_and_store_without_tools_or_host_payload_fallback(self):
        for mode in ('publication','artifact-store'):
            case=self.publication_case('installed-'+mode)
            result=self.invoke(mode,b'',(str(self.publication/'build.json'),str(case)))
            self.assertEqual(result.returncode,0,result.stderr)
            value=json.loads(result.stdout)
            self.assertEqual(value['sha256'],sha256(b'installed\x00native\xff').hexdigest())
            self.assertFalse((case/'published').exists())

    def _assert_publication_dual_python_source_custody(self, role, missing):
        name='hepta/hia_program_normalization_notes.py'
        module=self.installed/name;resource=self.installed/'hepta/_data'/name
        self.assertNotEqual(module,resource)
        original=module.read_bytes()
        self.assertEqual(original,resource.read_bytes())
        source=module if role=='module' else resource
        held=source.with_name(source.name+'.publication-custody-held')
        label='publication-notes-'+role+('-missing' if missing else '-tampered')
        case=self.publication_case(label)
        # Reuse the actual installed wheel and existing HIA publisher image.
        # Poison the other identity route and every execution/fallback point:
        # these negative controls must stop in the publisher's own admission.
        child=r'''
import importlib.abc,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
class NoBuildTools(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname=='tools' or fullname.startswith('tools.'):
            raise AssertionError('installed publisher imported checkout tools')
sys.meta_path.insert(0,NoBuildTools())
from hepta import artifact_publication as publication
from hepta import artifact_publication_native as publisher
from hepta import hia_agent_contract as contract
assert Path(sys.argv[1]) in Path(publisher.__file__).parents
def forbidden(*args,**kwargs):raise AssertionError('custody refusal reached foreign effects or another identity route')
contract.installation_manifest=forbidden
publisher.os.memfd_create=forbidden
publisher.subprocess.run=forbidden
publication._read_exact=forbidden
publication.sha256=forbidden
manifest=sys.argv[2];case=Path(sys.argv[3])
if sys.argv[4]=='admit':
    code=publisher._validated_code(manifest)
    assert type(code) is bytes and code[:4]==b'\x7fELF'
    sys.stdout.write('ADMITTED\n')
else:
    os.environ['HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST']=manifest
    publication.publish_verified(case/'stage',case/'published',b'installed\x00native\xff')
'''
        def invoke(mode):
            return subprocess.run(
                [sys.executable,'-I','-S','-B','-c',child,str(self.installed),
                 str(self.publication/'build.json'),str(case),mode],
                capture_output=True,timeout=15,cwd=self.folder,
                env={'PATH':'','LANG':'C','LC_ALL':'C'})
        admitted=invoke('admit')
        self.assertEqual(admitted.returncode,0,admitted.stderr)
        self.assertEqual(admitted.stdout,b'ADMITTED\n');self.assertEqual(admitted.stderr,b'')
        if missing:source.rename(held)
        else:source.write_bytes(original+b'\n# actual installed source drift\n')
        try:
            result=invoke('publish')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout,b'')
            self.assertIn(b'E_PUBLISH_NATIVE_CUSTODY',result.stderr)
            self.assertFalse((case/'published').exists())
            self.assertEqual((case/'stage').read_bytes(),b'installed\x00native\xff')
            self.assertFalse((case/'state').exists())
        finally:
            if missing:held.rename(source)
            else:source.write_bytes(original)
        self.assertEqual(module.read_bytes(),original)
        self.assertEqual(resource.read_bytes(),original)

    def test_installed_publication_rejects_changed_actual_notes_module_before_execution(self):
        self._assert_publication_dual_python_source_custody('module',False)

    def test_installed_publication_rejects_missing_actual_notes_module_before_execution(self):
        self._assert_publication_dual_python_source_custody('module',True)

    def test_installed_publication_rejects_changed_notes_resource_before_execution(self):
        self._assert_publication_dual_python_source_custody('resource',False)

    def test_installed_publication_rejects_missing_notes_resource_before_execution(self):
        self._assert_publication_dual_python_source_custody('resource',True)

    def test_installed_publication_missing_build_assets_refuse_before_filesystem_effects(self):
        for index,name in enumerate(PUBLICATION_BUILD_FILES):
            source=self.installed/'hepta/_data'/name;held=source.with_suffix(source.suffix+'.held')
            source.rename(held)
            try:
                case=self.publication_case('missing-publication-input-'+str(index))
                result=self.invoke('publication',b'',(str(self.publication/'build.json'),str(case)))
                self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
                self.assertFalse((case/'published').exists())
                self.assertEqual((case/'stage').read_bytes(),b'installed\x00native\xff')
            finally:held.rename(source)

    def test_installed_publication_rejects_tampered_package_contract_code_and_inventory(self):
        manifest=self.publication/'build.json';original_manifest=manifest.read_bytes()
        targets=[self.installed/'hepta/artifact_publication_native.py',
                 self.installed/'hepta/_data/docs/HIA_SELFHOST_CORE_SUPPORT.json',
                 self.publication/'hia-artifact']
        for index,target in enumerate(targets):
            original=target.read_bytes();target.write_bytes(original+b'\n')
            try:
                case=self.publication_case('tampered-publication-'+str(index))
                result=self.invoke('publication',b'',(str(manifest),str(case)))
                self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
                self.assertFalse((case/'published').exists())
            finally:target.write_bytes(original)
        extra=self.installed/'hepta/unexpected_installed_module.py';extra.write_text('# unbound production module\n')
        try:
            case=self.publication_case('extra-publication-module')
            result=self.invoke('publication',b'',(str(manifest),str(case)))
            self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
            self.assertFalse((case/'published').exists())
        finally:extra.unlink()
        record=json.loads(original_manifest);record['source_sha256']['tools/hia_artifact_publication_syscalls.S']='0'*64
        manifest.write_text(json.dumps(record))
        try:
            case=self.publication_case('mismatched-publication-source')
            result=self.invoke('publication',b'',(str(manifest),str(case)))
            self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
            self.assertFalse((case/'published').exists())
        finally:manifest.write_bytes(original_manifest)

    def test_installed_binary64_printing_has_no_host_printer_or_checkout_fallback(self):
        result=self.invoke('printing',b'')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,'{"large":1e+16,"ratio":1.25,"text":"中","tiny":5e-324,"zero":-0.0}'.encode())
        source=self.installed/'hepta/_data/examples/hia_bootstrap/agent_binary64_format.hiaasm'
        held=source.with_suffix('.held');source.rename(held)
        try:
            result=self.invoke('printing',b'')
            self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'')
        finally:held.rename(source)

    def test_all_native_Source_bindings_are_actual_installed_package_bytes(self):
        result=self.invoke('source-bindings',b'')
        self.assertEqual(result.returncode,0,result.stderr)
        observed=json.loads(result.stdout)
        self.assertEqual(set(observed.values()),set(NATIVE_SOURCE_FILES))
        self.assertEqual(len(observed),len(NATIVE_SOURCE_FILES))
        for name in observed.values():
            self.assertEqual((self.installed/'hepta/_data'/name).read_bytes(),(ROOT/name).read_bytes())

    def test_actual_installed_native_Core_policies_preserve_body_guards_and_missing_source_refusal(self):
        from tests.test_hia_program import b,c,f,m,ret
        doc=m(f('answer',[],['u32'],[],[b('entry',[],[c('v','u32',42)],ret('v'))]))
        doc['schema']='hepta.hia.program.v8'
        manifests=tuple(str(self.core_manifests[key]) for key in ('program_shape','instruction_policy'))
        result=self.invoke('native-Core',wire(doc),manifests)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['result'],42)
        # Existing body type obligations remain mandatory after native shape.
        doc['functions'][0]['blocks'][0]['ops'][0]['out'][0]['type']='u64'
        refused=self.invoke('native-Core',wire(doc),manifests)
        self.assertNotEqual(refused.returncode,0)
        self.assertEqual(refused.stdout,b'')
        self.assertIn(b'E_HIA_TYPE',refused.stderr)
        doc['functions'][0]['blocks'][0]['ops'][0]['out'][0]['type']='u32'
        resource=self.installed/'hepta/_data/examples/hia_bootstrap/program_shape.hiaasm'
        held=resource.with_suffix('.held');resource.rename(held)
        try:
            refused=self.invoke('native-Core',wire(doc),manifests)
            self.assertNotEqual(refused.returncode,0)
            self.assertEqual(refused.stdout,b'')
        finally:held.rename(resource)

    def test_actual_installed_whole_native_Core_preserves_body_guards_and_missing_source_refusal(self):
        from tests.test_hia_program import b,c,f,m,ret
        doc=m(f('answer',[],['u32'],[],[b('entry',[],[c('v','u32',42)],ret('v'))]))
        doc['schema']='hepta.hia.program.v8'
        manifests=tuple(str(self.core_manifests[key]) for key in ('program_shape','instruction_policy','core_admission'))
        result=self.invoke('native-Core-whole',wire(doc),manifests)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['result'],42)
        # Existing body type obligations remain mandatory inside the selected native whole-body kernel.
        doc['functions'][0]['blocks'][0]['ops'][0]['out'][0]['type']='u64'
        refused=self.invoke('native-Core-whole',wire(doc),manifests)
        self.assertNotEqual(refused.returncode,0)
        self.assertEqual(refused.stdout,b'')
        self.assertIn(b'E_HIA_TYPE',refused.stderr)
        doc['functions'][0]['blocks'][0]['ops'][0]['out'][0]['type']='u32'
        resource=self.installed/'hepta/_data/examples/hia_bootstrap/core_admission.hiaasm'
        held=resource.with_suffix('.held');resource.rename(held)
        try:
            refused=self.invoke('native-Core-whole',wire(doc),manifests)
            self.assertNotEqual(refused.returncode,0)
            self.assertEqual(refused.stdout,b'')
        finally:held.rename(resource)

    def test_installed_binary64_source_has_no_decimal_converter_or_checkout_fallback(self):
        source=self.installed/'hepta/_data/examples/hia_bootstrap/agent_binary64.hiaasm'
        held=source.with_suffix('.held');source.rename(held)
        try:
            result=self.invoke('data',b'1.25e-3')
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout,b'')
        finally:held.rename(source)

    def test_installed_data_decoder_has_no_payload_parser_or_source_fallback(self):
        wire=b'{"ratio":1.25e-3,"negative_zero":-0.0,"n":18446744073709551616}'
        result=self.invoke('data',wire)
        self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout)
        self.assertEqual(value['ratio'],0.00125)
        self.assertEqual(value['negative_zero'].hex(),'-0x0.0p+0')
        self.assertEqual(value['n'],18446744073709551616)
        source=self.installed/'hepta/_data/examples/hia_bootstrap/agent_data_json.hiaasm'
        held=source.with_suffix('.held');source.rename(held)
        try:
            rejected=self.invoke('data',wire)
            self.assertNotEqual(rejected.returncode,0)
        finally:held.rename(source)

    def _assert_dual_python_source_custody(self, role, missing):
        name='hepta/hia_program_normalization_notes.py'
        module=self.installed/name
        resource=self.installed/'hepta/_data'/name
        self.assertNotEqual(module,resource)
        original_module,original_resource=module.read_bytes(),resource.read_bytes()
        self.assertEqual(original_module,original_resource)
        target=module if role=='module' else resource
        raw=target.read_bytes()
        case='dual-python-'+role+('-missing' if missing else '-tampered')
        state=self.folder/case
        self.assertFalse(state.exists())
        held=target.with_name(target.name+'.custody-held')
        if missing:
            self.assertFalse(held.exists())
            target.rename(held)
        else:
            target.write_bytes(raw+b'\n# controlled installed source custody change\n')
        try:
            identity=self.invoke('identity',b'')
            self.assertNotEqual(identity.returncode,0,
                                (identity.stdout,identity.stderr))
            self.assertEqual(identity.stdout,b'')
            self.assertTrue(identity.stderr)
            result=self.invoke(state,wire(self.request),
                ('--expected-worker-sha256',self.identity['worker_sha256']))
            self.assertNotEqual(result.returncode,0,(result.stdout,result.stderr))
            self.assertEqual(result.stdout,b'')
            self.assertFalse(state.exists())
        finally:
            if missing:held.rename(target)
            else:target.write_bytes(raw)
        self.assertEqual(module.read_bytes(),original_module)
        self.assertEqual(resource.read_bytes(),original_resource)
        restored=self.invoke('identity',b'')
        self.assertEqual(restored.returncode,0,restored.stderr)
        self.assertEqual(json.loads(restored.stdout),self.identity)
        print(json.dumps({'case':case,'identity_returncode':identity.returncode,
            'worker_returncode':result.returncode,'worker_stdout_bytes':len(result.stdout),
            'service_state_created':state.exists(),'restored_identity_equal':True},
            sort_keys=True))

    def test_installed_python_resource_module_tamper_refuses_before_service(self):
        self._assert_dual_python_source_custody('module',False)

    def test_installed_python_resource_module_missing_refuses_before_service(self):
        self._assert_dual_python_source_custody('module',True)

    def test_installed_python_resource_data_tamper_refuses_before_service(self):
        self._assert_dual_python_source_custody('resource',False)

    def test_installed_python_resource_data_missing_refuses_before_service(self):
        self._assert_dual_python_source_custody('resource',True)

    def test_wheel_resources_are_exact_and_worker_identity_matches_source(self):
        with zipfile.ZipFile(self.wheel) as z:
            for name in RESOURCES:
                self.assertEqual(z.read('hepta/_data/'+name),(ROOT/name).read_bytes())
                self.assertEqual((self.installed/'hepta/_data'/name).read_bytes(),(ROOT/name).read_bytes())
        self.assertEqual(self.identity,installation_manifest())

    def test_real_installed_native_worker_without_checkout_or_reference_predicates(self):
        state=self.folder/'valid';r=self.invoke(state,wire(self.request))
        self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertEqual(r.stderr,b'')
        report=json.loads(r.stdout)
        self.assertEqual(report['native_helpers_sha256'],self.helpers_sha256)
        self.assertEqual(report['response']['status'],'completed');self.assertTrue(state.is_dir())

    def test_real_installed_edit_query_without_reference_graph_algorithms(self):
        from tests.test_hia_edit_query import fixture
        from hepta.hia_edit_query import prepare_edit
        doc=fixture();expected=prepare_edit(doc,function='calculate',block='entry',output='y',fields=['op'])
        result=self.invoke('slice',wire(doc))
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        self.assertEqual(result.stderr,b'');self.assertEqual(json.loads(result.stdout),expected)

    def test_missing_slice_source_refuses_before_state_without_checkout_fallback(self):
        p=self.installed/'hepta/_data/examples/hia_bootstrap/agent_slice.hiaasm';hold=p.with_suffix('.held');p.rename(hold)
        try:
            state=self.folder/'missing-slice';result=self.invoke(state,wire(self.request))
            self.assertNotEqual(result.returncode,0);self.assertEqual(result.stdout,b'');self.assertFalse(state.exists())
        finally:hold.rename(p)

    def test_missing_native_source_fails_before_service_no_source_fallback(self):
        p=self.installed/'hepta/_data/examples/hia_bootstrap/agent_identity.hiaasm';hold=p.with_suffix('.held');p.rename(hold)
        try:
            state=self.folder/'missing';r=self.invoke(state,wire(self.request))
            self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'');self.assertFalse(state.exists())
        finally:hold.rename(p)

    def test_tampered_native_source_fails_before_service(self):
        p=self.installed/'hepta/_data/examples/hia_bootstrap/agent_identity.hiaasm';raw=p.read_bytes();p.write_bytes(raw+b'\n')
        try:
            state=self.folder/'tampered';r=self.invoke(state,wire(self.request))
            self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'');self.assertFalse(state.exists())
            self.assertIn(b'source identity mismatch',r.stderr)
        finally:p.write_bytes(raw)

    def test_tampered_discovery_doc_invalidates_worker_pin_before_state(self):
        p=self.installed/'hepta/_data/docs/HIA_PROGRAM.md';raw=p.read_bytes();p.write_bytes(raw+b'\n')
        try:
            state=self.folder/'stale';r=self.invoke(state,wire(self.request),('--expected-worker-sha256',self.identity['worker_sha256']))
            self.assertEqual(r.returncode,2);self.assertEqual(r.stdout,b'');self.assertFalse(state.exists())
            self.assertIn(b'administrator source pin differs',r.stderr)
        finally:p.write_bytes(raw)

    def test_missing_entire_installed_resource_root_has_no_cwd_fallback(self):
        p=self.installed/'hepta/_data';hold=p.with_name('_data-held');p.rename(hold)
        try:
            state=self.folder/'no-data';r=self.invoke(state,wire(self.request))
            self.assertNotEqual(r.returncode,0);self.assertEqual(r.stdout,b'');self.assertFalse(state.exists())
        finally:hold.rename(p)
