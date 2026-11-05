"""Typed package migration over real unchanged codecs; no compatibility inference."""
from __future__ import annotations
import base64,hashlib,json,os,signal,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from hepta.ast import HeptaError
from hepta.packages import load_package,verify_lock,write_lock
from hepta.lock_diff import compare_locks
from hepta.pipeline import analyze_project
from hepta.c_backend import compile_c
from hepta.backend import compile_rust
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from typed_stdlib_oracle import source as vector_source,raw_case
from test_typed_stdlib import success,CONTRACT
BACKEND=os.environ.get('HEPTA_VERSIONED_TYPED_BACKEND','c')
LIBS={'codec':'bytes','base64':'base64','utf8':'utf8','order':'ordering'}

def manifest(path,name,version,deps,kind='lib'):
    text=f'[package]\nname={json.dumps(name)}\nversion={json.dumps(version)}\nkind={json.dumps(kind)}\n[dependencies]\n'
    for alias,spec in sorted(deps.items()):text+=alias+'={'+', '.join(k+'='+json.dumps(v) for k,v in spec.items())+'}\n'
    (path/'hepta.toml').write_text(text,encoding='utf-8')

class VersionedTypedTests(unittest.TestCase):
    def setUp(self):
        self.assertIn(BACKEND,('c','rust'))
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-versioned-typed-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for version in (1,2):
            for library in LIBS.values():
                path=self.root/f'{library}{version}';shutil.copytree(ROOT/'stdlib'/library,path)
                manifest(path,'hepta_'+library,f'0.{version}.0',{})
            typed=self.root/f'typed{version}';shutil.copytree(ROOT/'examples/packages/typed_packet/src',typed/'src')
            manifest(typed,'typed_packet',f'{version}.0.0',{a:self.spec(n,f'=0.{version}.0') for a,n in LIBS.items()})
        self.app=self.root/'app';(self.app/'src').mkdir(parents=True)
        self.source('import typed;\nfn main()->Unit effects {panic,write} '+CONTRACT+' {\n'+success()+'}\n')
        self.requirement('=1.0.0')

    def spec(self,name,requirement):
        return {'package':'hepta_'+name,'version':requirement,'candidates':[f'../{name}1',f'../{name}2']}
    def requirement(self,value='>=1.0.0',order=None,candidates=None):
        deps={'typed':{'package':'typed_packet','version':value,'candidates':candidates or ['../typed1','../typed2']}}
        if order is not None:deps['selected_order']=self.spec('ordering',order)
        manifest(self.app,'versioned_typed','1.0.0',deps,'bin')
    def source(self,text):(self.app/'src/main.hepta').write_text(text,encoding='utf-8')
    def selected(self,v):
        app=load_package(self.app);typed=app.dependencies['typed']
        self.assertEqual((typed.version,typed.root.name),(f'{v}.0.0',f'typed{v}'))
        self.assertEqual({a:(d.version,d.root.name) for a,d in typed.dependencies.items()},{a:(f'0.{v}.0',f'{n}{v}') for a,n in LIBS.items()})
        return app
    def cli(self,*args,expected=0):
        env={**os.environ,'PYTHONPATH':str(ROOT),'PYTHONDONTWRITEBYTECODE':'1','PYTHONIOENCODING':'utf-8'}
        p=subprocess.run([sys.executable,'-B','-m','hepta',*map(str,args)],cwd=self.root,env=env,capture_output=True,text=True,encoding='utf-8',timeout=120)
        self.assertEqual(p.returncode,expected,p.stdout+p.stderr);self.assertEqual(p.stderr,'');return json.loads(p.stdout)
    def lock(self,label):
        report=self.cli('lock',self.app);self.assertTrue(report['ok']);p=self.root/(label+'.lock');p.write_bytes((self.app/'Hepta.lock').read_bytes());self.assertEqual(json.loads(p.read_bytes()),report['snapshot']);return p
    def stale(self):
        with self.assertRaises(HeptaError) as c:analyze_project(self.app,backend=BACKEND,locked=True,crate_type='bin')
        self.assertEqual(c.exception.diagnostic.code,'E_LOCK_STALE')
    def diff(self,a,b,changed=True):
        frozen={p:p.read_bytes() for p in (a,b)};r=self.cli('lock-diff',a,b,'--check',expected=int(changed));self.assertEqual(r,compare_locks(a,b));self.assertEqual(r['compatibility'],'not_assessed');self.assertEqual(r['changed'],changed);self.assertEqual(frozen,{p:p.read_bytes() for p in frozen});return r
    def native(self,good=True):
        a=analyze_project(self.app,backend=BACKEND,locked=True,crate_type='bin');self.assertTrue(a.report['ok'],a.report);self.assertEqual(len(a.project.modules),7)
        for opt in (False,True):
            out=self.root/('o3' if opt else 'o0')
            b=compile_c(a.c,output=out,optimize=opt,sanitize=True) if BACKEND=='c' else compile_rust(a.rust,output=out,crate_type='bin',optimize=opt)
            self.assertTrue(b['ok'],b)
            if BACKEND=='c':self.assertIn('-fno-sanitize-recover=all',b['flags'])
            p=subprocess.run([str(out)],capture_output=True,timeout=30)
            self.assertEqual(p.returncode,0 if good else -signal.SIGABRT);self.assertEqual(p.stdout,b'')
            if good or BACKEND=='c':self.assertEqual(p.stderr,b'')
            else:self.assertIn(b'assertion',p.stderr)
            print('VERSIONED_TYPED_NATIVE '+json.dumps({'method':self.id(),'expected_success':good,'returncode':p.returncode,'optimized':opt,'backend':BACKEND,'build':b,'lock_sha256':json.loads((self.app/'Hepta.lock').read_bytes())['sha256']},sort_keys=True),flush=True)

    def test_complete_transitive_upgrade_and_lock_review(self):
        old=self.lock('old');self.selected(1);self.native();self.requirement();self.stale();new=self.lock('new');self.selected(2)
        d=self.diff(old,new);self.assertEqual([x['path'] for x in d['packages']['added']],sorted(['../typed2']+[f'../{n}2' for n in LIBS.values()]));self.assertEqual([x['path'] for x in d['packages']['removed']],sorted(['../typed1']+[f'../{n}1' for n in LIBS.values()]));self.assertEqual(d['dependencies']['retargeted'],[{'package':'.','alias':'typed','before':'../typed1','after':'../typed2'}]);self.native()

    def test_root_constraint_backtracks_complete_typed_graph(self):
        self.requirement();old=self.lock('high');self.selected(2);self.requirement(order='<0.2.0');self.stale();new=self.lock('low');p=self.selected(1);self.assertIs(p.dependencies['selected_order'],p.dependencies['typed'].dependencies['order']);self.diff(old,new);self.native()

    def test_all_typed_errors_and_complete_backing_survive_upgrade(self):
        vectors=[raw_case(b'\0\3a\xc3\xa9',233,scalars=5),(b'!!!!',0,4,8,3,0),raw_case(b'x'),raw_case(b'\0\2a'),raw_case(b'\0\1\xff'),raw_case(b'\0\2aa',scalars=2)]
        self.source(vector_source(vectors));self.lock('low');self.native();self.requirement();self.stale();self.lock('high');self.selected(2);self.native()

    def test_valid_lock_cannot_approve_wrong_error_payload_and_rollback(self):
        self.source(vector_source([raw_case(b'\0\2aa',scalars=2)]));old=self.lock('low');before=(self.app/'hepta.toml').read_bytes();self.native()
        p=self.root/'typed2/src/lib.hepta';text=p.read_text();needle='ScalarCapacity(len(read scalars))';self.assertEqual(text.count(needle),1);p.write_text(text.replace(needle,'ScalarCapacity(len(read scalars) + 1)'))
        self.requirement();new=self.lock('bad');self.selected(2);verify_lock(load_package(self.app));self.diff(old,new);self.native(False)
        (self.app/'hepta.toml').write_bytes(before);(self.app/'Hepta.lock').write_bytes(old.read_bytes());self.selected(1);verify_lock(load_package(self.app));self.native()

    def test_valid_lock_cannot_approve_ordering_regression_and_rollback(self):
        old=self.lock('low');before=(self.app/'hepta.toml').read_bytes();p=self.root/'ordering2/src/lib.hepta';text=p.read_text();begin=text.index('fn sift_u64(');end=text.index('pub fn sort_u64(');part=text[begin:end];self.assertEqual(part.count('] < values['),1);self.assertEqual(part.count('] >= values['),1);part=part.replace('] < values[','] > values[').replace('] >= values[','] <= values[');p.write_text(text[:begin]+part+text[end:])
        self.requirement();new=self.lock('bad');verify_lock(load_package(self.app));self.diff(old,new);self.native(False)
        (self.app/'hepta.toml').write_bytes(before);(self.app/'Hepta.lock').write_bytes(old.read_bytes());verify_lock(load_package(self.app));self.selected(1);self.native()

    def test_unsatisfied_refresh_preserves_lock_and_recovers(self):
        old=self.lock('old');original=(self.app/'hepta.toml').read_bytes();self.requirement('=2.0.0',order='<0.2.0');r=self.cli('lock',self.app,expected=1);self.assertEqual(r['diagnostics'][0]['code'],'E_PACKAGE_RESOLUTION');self.assertEqual((self.app/'Hepta.lock').read_bytes(),old.read_bytes());(self.app/'hepta.toml').write_bytes(original);verify_lock(load_package(self.app));self.selected(1);self.native()

    def test_selected_and_unselected_changes_obey_lock_boundary(self):
        self.lock('old');old=(self.app/'Hepta.lock').read_bytes()
        for name in ['typed','bytes','base64','utf8','ordering']:
            p=self.root/f'{name}2/src/lib.hepta';p.write_bytes(p.read_bytes()+b'\n// unselected source\n');verify_lock(load_package(self.app));self.assertEqual((self.app/'Hepta.lock').read_bytes(),old)
            p=self.root/f'{name}1/src/lib.hepta';data=p.read_bytes();p.write_bytes(data+b'\n// selected source\n');self.stale();p.write_bytes(data);verify_lock(load_package(self.app))
        self.native()

    def test_equivalent_requirement_changes_only_manifest_identity(self):
        old=self.lock('old');self.requirement('>=1.0.0, <2.0.0');self.stale();new=self.lock('new');self.selected(1);d=self.diff(old,new);self.assertEqual(d['packages'],{'added':[],'removed':[],'changed':[]});self.assertEqual(d['dependencies'],{'added':[],'removed':[],'retargeted':[]});self.assertEqual([x['path'] for x in d['files']['changed']],['hepta.toml'])

    def test_equal_version_retarget_remains_visible(self):
        old=self.lock('old');shutil.copytree(self.root/'typed1',self.root/'typedcopy');self.requirement('=1.0.0',candidates=['../typedcopy']);self.stale();new=self.lock('new');d=self.diff(old,new);self.assertEqual(d['dependencies']['retargeted'],[{'package':'.','alias':'typed','before':'../typed1','after':'../typedcopy'}]);self.native()

    def test_relocated_versioned_graph_reuses_identical_lock(self):
        self.requirement();self.lock('high');lock=(self.app/'Hepta.lock').read_bytes();destination=self.root/'relocated';destination.mkdir()
        for p in list(self.root.iterdir()):
            if p.is_dir() and p!=destination:shutil.copytree(p,destination/p.name)
        self.app=destination/'app';self.assertEqual((self.app/'Hepta.lock').read_bytes(),lock);verify_lock(load_package(self.app));self.native()

    def test_public_cli_checked_in_versioned_typed_example(self):
        r=self.cli('run',ROOT/'examples/packages/versioned_typed_text','--locked','--backend',BACKEND,'--json');self.assertTrue(r['ok'],r)

    def test_exact_suppliers_and_inverse_provenance(self):
        from verify_versioned_typed_sources import verify
        self.assertTrue(verify()['complete_pass'])
