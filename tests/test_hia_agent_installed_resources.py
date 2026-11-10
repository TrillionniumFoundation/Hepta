"""Actual sdist/wheel/installed native-worker resources, not source-path borrowing."""
from pathlib import Path
from hashlib import sha256
import json,os,shutil,subprocess,sys,tarfile,tempfile,unittest,zipfile
from hepta.hia_agent_contract import DISCOVERY_FILES,installation_manifest
from hepta.hia_agent_store import wire
ROOT=Path(__file__).resolve().parents[1]
RESOURCES=tuple('docs/'+n for n in DISCOVERY_FILES)+('examples/hia_bootstrap/agent_identity.hiaasm',)

class AgentInstalledResourceSourceTests(unittest.TestCase):
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
            env={'PATH':'','LANG':'C','LC_ALL':'C','HEPTA_HIA_AGENT_IDENTITY_MANIFEST':str(cls.manifest)})

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
