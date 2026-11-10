"""Actual sdist/wheel/installed native-worker resources, not source-path borrowing."""
from pathlib import Path
from hashlib import sha256
import json,os,shutil,subprocess,sys,tarfile,tempfile,unittest,zipfile
from hepta.hia_agent_contract import DISCOVERY_FILES,NATIVE_SOURCE_FILES,installation_manifest
from hepta.hia_agent_store import wire
ROOT=Path(__file__).resolve().parents[1]
RESOURCES=tuple('docs/'+n for n in DISCOVERY_FILES)+NATIVE_SOURCE_FILES

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
        prefix=CHILD.split('from hepta.cli import')[0]
        cls.child='import sys\nsys.path.insert(0,sys.argv[1])\n'+prefix+'''
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
elif sys.argv[2]=='data':
    from hepta.hia_agent_data_json_native import SOURCE as DATA_SOURCE
    assert Path(sys.argv[1]) in DATA_SOURCE.parents,DATA_SOURCE
    import json
    json.loads=absent;store.re.compile=absent;store.preflight_hia_json=absent
    store.float=absent
    from hepta.hia_agent_binary64_native import SOURCE as FLOAT_SOURCE
    assert Path(sys.argv[1]) in FLOAT_SOURCE.parents,FLOAT_SOURCE
    print(json.dumps(store.decode_data(sys.stdin.buffer.read()),ensure_ascii=False,sort_keys=True))
elif sys.argv[2]=='slice':
    from hepta import hia_edit_query as editing
    from hepta.hia_agent_slice_native import SOURCE as SLICE_SOURCE
    assert Path(sys.argv[1]) in SLICE_SOURCE.parents,SLICE_SOURCE
    editing._reference_edit_slice=absent;editing._cfg_downstream_slice=absent
    doc=__import__('json').loads(sys.stdin.buffer.read())
    print(__import__('json').dumps(editing.prepare_edit(doc,function='calculate',block='entry',output='y',fields=['op'])))
else:
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
        return subprocess.run([sys.executable,'-I','-S','-B','-c',cls.child,str(cls.installed),str(state),*extra],input=request,capture_output=True,timeout=15,cwd=cls.folder,
            env={'PATH':'','LANG':'C','LC_ALL':'C','HEPTA_HIA_AGENT_IDENTITY_MANIFEST':str(cls.manifest),'HEPTA_HIA_AGENT_SLICE_MANIFEST':str(cls.slice_manifest),
                 'HEPTA_HIA_AGENT_DATA_JSON_MANIFEST':str(cls.data_manifest),
                 'HEPTA_HIA_AGENT_BINARY64_MANIFEST':str(cls.float_manifest)})

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

    def test_wheel_resources_are_exact_and_worker_identity_matches_source(self):
        with zipfile.ZipFile(self.wheel) as z:
            for name in RESOURCES:
                self.assertEqual(z.read('hepta/_data/'+name),(ROOT/name).read_bytes())
                self.assertEqual((self.installed/'hepta/_data'/name).read_bytes(),(ROOT/name).read_bytes())
        self.assertEqual(self.identity,installation_manifest())

    def test_real_installed_native_worker_without_checkout_or_reference_predicates(self):
        state=self.folder/'valid';r=self.invoke(state,wire(self.request))
        self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertEqual(r.stderr,b'')
        self.assertEqual(json.loads(r.stdout)['response']['status'],'completed');self.assertTrue(state.is_dir())

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
