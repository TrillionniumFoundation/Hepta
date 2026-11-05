"""Real source-library consumers under bounded offline candidate migration.

Version numbers and intentionally broken candidates are disposable test fixtures,
not claims of released packages or inferred compatibility.
"""
from __future__ import annotations
import base64
import bisect
import hashlib
import json
import os
import signal
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from hepta.ast import HeptaError
from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.lock_diff import compare_locks
from hepta.modules import load_project
from hepta.packages import load_package, verify_lock, write_lock
from hepta.pipeline import analyze_project

ROOT = Path(__file__).resolve().parents[1]
BACKEND = os.environ.get('HEPTA_VERSIONED_STDLIB_BACKEND', 'c')
LIBS = {'codec': 'bytes', 'base64': 'base64', 'utf8': 'utf8', 'order': 'ordering'}
CONTRACT = 'resources { heap_allocations = 0; may_block = false; may_suspend = false; may_spawn = false; }'


def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def verify_components(root=ROOT):
    """Verify both exact suppliers and reversible two-entry manifest adaptation."""
    manifest = json.loads((root/'tests/versioned_stdlib_components.json').read_bytes())
    if manifest['parents'] != {'698':'999850195334cc8439cfbb95de09e6e49faeee2c',
                               '699':'fccbc1a9cf5f6639d29bb8e96aa10381be5141a6'}:
        raise AssertionError('Unexpected composition parents')
    if len(manifest['preserved']) != 68:
        raise AssertionError('Incomplete component inventory')
    for path, expected in manifest['preserved'].items():
        data = (root/path).read_bytes()
        if blob(data) != expected['git_blob'] or hashlib.sha256(data).hexdigest() != expected['sha256']:
            raise AssertionError('Changed component: ' + path)
    original = (root/'tests/versioned_stdlib_parent_manifest.json').read_bytes()
    if blob(original) != manifest['stdlib_manifest_original_git_blob'] or hashlib.sha256(original).hexdigest() != manifest['stdlib_manifest_original_sha256']:
        raise AssertionError('Changed original stdlib manifest')
    current = (root/'tools/stdlib_integration_components.json').read_bytes()
    if hashlib.sha256(current).hexdigest() != manifest['stdlib_manifest_updated_sha256']:
        raise AssertionError('Changed adapted stdlib manifest')
    adapted = json.loads(current)
    parent = json.loads(original)
    old_by_path = {x['path']: x for x in parent['compiler']['files']}
    changed = []
    for entry in adapted['compiler']['files']:
        if entry['path'] in manifest['replaced_compiler_inputs']:
            path = entry['path']
            if entry['supplier_pr'] != 698 or entry['supplier_head'] != manifest['parents']['698']:
                raise AssertionError('Unexpected compiler supplier')
            if blob((root/path).read_bytes()) != entry['git_blob']:
                raise AssertionError('Incorrect replacement compiler bytes')
            changed.append(path)
            entry.clear(); entry.update(old_by_path[path])
    if sorted(changed) != ['hepta/cli.py','hepta/packages.py'] or adapted != parent:
        raise AssertionError('Manifest changes exceed the two compiler inputs')
    if (json.dumps(adapted, indent=2)+'\n').encode() != original:
        raise AssertionError('Inverse adaptation did not recover original bytes')
    return manifest


def consumer_source(text='zé😀é\0', query=233):
    """Expected packet fields and every backing element come from Python."""
    raw = text.encode('utf-8')
    wire = bytes([255]) + base64.b64encode(len(raw).to_bytes(2,'big')+raw) + bytes([255])
    ordered = sorted(map(ord,text))
    scratch = [165] + list(len(raw).to_bytes(2,'big')+raw) + [165,165]
    scalars = [999]+ordered+[999,999]
    arr = lambda x:'['+','.join(map(str,x))+']'
    lines = [f'let wire: [u8; {len(wire)}] = {arr(wire)};',
             f'let mut scratch: [u8; {len(scratch)}] = {arr([165]*len(scratch))};',
             f'let mut scalars: [u64; {len(scalars)}] = {arr([999]*len(scalars))};',
             f'let result = packet::index_packet(read wire, 1, {len(wire)-1}, mut scratch, mut scalars, {query});']
    for field,want in zip(('stage','scalars','lower','upper'),(0,len(text),1+bisect.bisect_left(ordered,query),1+bisect.bisect_right(ordered,query))):
        lines.append(f'assert(result.{field} == {want});')
    for name,values in [('wire',wire),('scratch',scratch),('scalars',scalars)]:
        lines += [f'assert({name}[{i}] == {v});' for i,v in enumerate(values)]
    return 'import packet;\nfn main() -> Unit effects { panic, write }\n'+CONTRACT+'\n{\n'+'\n'.join(lines)+'\n}\n'


class VersionedStdlibTests(unittest.TestCase):
    def setUp(self):
        self.assertIn(BACKEND,('c','rust'))
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-versioned-stdlib-case-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for alias,library in LIBS.items():
            for version in (1,2):
                directory = self.root/f'{library}{version}'
                shutil.copytree(ROOT/'stdlib'/library,directory)
                p=directory/'hepta.toml'
                p.write_text(p.read_text().replace('0.1.0',f'0.{version}.0'))
        for version in (1,2):
            directory=self.root/f'engine{version}'
            (directory/'src').mkdir(parents=True)
            shutil.copyfile(ROOT/'examples/packages/indexed_text/src/packet.hepta',directory/'src/lib.hepta')
            deps={alias:self.spec(library,f'=0.{version}.0') for alias,library in LIBS.items()}
            self.manifest(directory,'packet_engine',f'{version}.0.0',deps)
        self.app=self.root/'app'
        (self.app/'src').mkdir(parents=True)
        (self.app/'src/main.hepta').write_text(consumer_source(),encoding='utf-8')
        self.app_manifest('=1.0.0')

    def spec(self,library,requirement='>=0.1.0'):
        return {'package':f'hepta_{library}', 'version':requirement,
                'candidates':[f'../{library}1',f'../{library}2']}

    def manifest(self,path,name,version,deps,kind='lib'):
        content=f'[package]\nname={json.dumps(name)}\nversion={json.dumps(version)}\nkind={json.dumps(kind)}\n\n[dependencies]\n'
        for alias,spec in sorted(deps.items()):
            content+=alias+'={'+', '.join(k+'='+json.dumps(v) for k,v in spec.items())+'}\n'
        (path/'hepta.toml').write_text(content,encoding='utf-8')

    def app_manifest(self,requirement='>=1.0.0',order=None):
        deps={'packet':{'package':'packet_engine','version':requirement,'candidates':['../engine1','../engine2']}}
        if order is not None: deps['selected_order']=self.spec('ordering',order)
        self.manifest(self.app,'versioned_text','1.0.0',deps,kind='bin')

    def cli(self,*args,expected=0):
        env={**os.environ,'PYTHONPATH':str(ROOT),'PYTHONDONTWRITEBYTECODE':'1','PYTHONIOENCODING':'utf-8'}
        p=subprocess.run([sys.executable,'-B','-m','hepta',*map(str,args)],cwd=self.root,env=env,capture_output=True,text=True,encoding='utf-8',timeout=120)
        self.assertEqual(p.returncode,expected,p.stdout+p.stderr)
        self.assertEqual(p.stderr,'')
        return json.loads(p.stdout)

    def lock(self,label):
        result=self.cli('lock',self.app)
        self.assertTrue(result['ok'])
        saved=self.root/(label+'.lock')
        shutil.copyfile(self.app/'Hepta.lock',saved)
        self.assertEqual(result['snapshot'],json.loads(saved.read_bytes()))
        return saved

    def stale(self):
        with self.assertRaises(HeptaError) as caught: load_project(self.app,locked=True)
        self.assertEqual(caught.exception.diagnostic.code,'E_LOCK_STALE')

    def selected(self,version):
        p=load_package(self.app)
        e=p.dependencies['packet']
        self.assertEqual(e.version,f'{version}.0.0')
        self.assertEqual({a:d.version for a,d in e.dependencies.items()},{a:f'0.{version}.0' for a in LIBS})
        self.assertEqual({a:d.root.name for a,d in e.dependencies.items()},{a:f'{n}{version}' for a,n in LIBS.items()})
        return p

    def compare(self,before,after,changed=True):
        snapshot={p:p.read_bytes() for p in (before,after)}
        report=self.cli('lock-diff',before,after,'--check',expected=int(changed))
        self.assertEqual(report,compare_locks(before,after))
        self.assertEqual(report['compatibility'],'not_assessed')
        self.assertEqual(report['changed'],changed)
        self.assertEqual({p:p.read_bytes() for p in snapshot},snapshot)
        return report

    def native(self,good=True):
        result=analyze_project(self.app,backend=BACKEND,locked=True,crate_type='bin')
        self.assertTrue(result.report['ok'],result.report)
        self.assertEqual(len(result.project.modules),6)
        for opt in (False,True):
            output=self.root/('run-o3' if opt else 'run-o0')
            if BACKEND=='c':
                build=compile_c(result.c,output=output,optimize=opt,sanitize=True)
                self.assertIn('-fsanitize=undefined',build['flags'])
                self.assertIn('-fno-sanitize-recover=all',build['flags'])
            else: build=compile_rust(result.rust,output=output,crate_type='bin',optimize=opt)
            self.assertTrue(build['ok'],build)
            run=subprocess.run([str(output)],capture_output=True,text=True,timeout=20)
            self.assertEqual(run.stdout,'')
            if good: self.assertEqual((run.returncode,run.stderr),(0,''))
            else:
                if BACKEND == 'c':
                    self.assertEqual(run.returncode, -signal.SIGABRT)
                    self.assertEqual(run.stderr, '')
                else:
                    self.assertEqual(run.returncode, -signal.SIGABRT)
                    self.assertIn('assertion',run.stderr.lower())
            print('VERSIONED_STDLIB_NATIVE '+json.dumps({'backend':BACKEND,'optimized':opt,'expected_success':good,'returncode':run.returncode,'stderr':run.stderr,'artifact_sha256':build['artifact_sha256'],'toolchain':build['toolchain'],'source_sha256':build.get('source_sha256',build.get('rust_sha256')),'flags':build.get('flags'),'lock_sha256':json.loads((self.app/'Hepta.lock').read_bytes())['sha256']},sort_keys=True),flush=True)

    def test_four_library_transitive_upgrade_and_native_packet(self):
        old=self.lock('old');self.selected(1);self.native()
        self.app_manifest();self.stale()
        new=self.lock('new');self.selected(2)
        report=self.compare(old,new)
        self.assertEqual([x['path'] for x in report['packages']['removed']],sorted(['../engine1']+[f'../{n}1' for n in LIBS.values()]))
        self.assertEqual([x['path'] for x in report['packages']['added']],sorted(['../engine2']+[f'../{n}2' for n in LIBS.values()]))
        self.assertEqual(report['dependencies']['retargeted'],[{'package':'.','alias':'packet','before':'../engine1','after':'../engine2'}])
        self.native()

    def test_root_transitive_constraint_backtracks_real_consumer(self):
        self.app_manifest();old=self.lock('old');self.selected(2)
        self.app_manifest(order='<0.2.0');self.stale()
        new=self.lock('new');p=self.selected(1)
        self.assertIs(p.dependencies['selected_order'],p.dependencies['packet'].dependencies['order'])
        self.compare(old,new);self.native()

    def test_unsatisfied_refresh_preserves_lock_then_recovers(self):
        self.lock('old');old=(self.app/'Hepta.lock').read_bytes()
        self.app_manifest('=2.0.0',order='<0.2.0')
        rejected=self.cli('lock',self.app,expected=1)
        self.assertEqual(rejected['diagnostics'][0]['code'],'E_PACKAGE_RESOLUTION')
        self.assertEqual((self.app/'Hepta.lock').read_bytes(),old)
        rejected=self.cli('check',self.app,'--locked','--backend',BACKEND,'--frontend-only','--json',expected=1)
        self.assertFalse(rejected['ok'])
        self.app_manifest('=1.0.0')
        verify_lock(load_package(self.app));self.selected(1);self.native()

    def test_lock_validity_does_not_approve_behavior_break(self):
        old=self.lock('old')
        source=self.root/'ordering2/src/lib.hepta'
        text=source.read_text()
        begin=text.index('fn sift_u64(');end=text.index('pub fn sort_u64(')
        part=text[begin:end]
        self.assertEqual(part.count('] < values['),1)
        self.assertEqual(part.count('] >= values['),1)
        part=part.replace('] < values[','] > values[').replace('] >= values[','] <= values[')
        source.write_text(text[:begin]+part+text[end:])
        self.app_manifest();new=self.lock('broken')
        self.selected(2);verify_lock(load_package(self.app))
        self.compare(old,new);self.native(good=False)
        # Explicit rollback chooses old sources; no automatic compatibility claim.
        self.app_manifest('=1.0.0');self.lock('restored');self.native()

    def test_each_selected_library_change_requires_new_snapshot(self):
        old=self.lock('old')
        for name in LIBS.values():
            with self.subTest(name=name):
                p=self.root/f'{name}1/src/lib.hepta';data=p.read_bytes()
                p.write_bytes(data+b'\n// selected fixture edit\n');self.stale()
                new=self.lock(name)
                report=self.compare(old,new)
                self.assertEqual([x['path'] for x in report['files']['changed']],[f'../{name}1/src/lib.hepta'])
                self.assertTrue(all(not x for x in report['packages'].values()))
                self.assertTrue(all(not x for x in report['dependencies'].values()))
                p.write_bytes(data);self.lock('restored')

    def test_unselected_sources_do_not_change_current_lock(self):
        old=self.lock('old')
        for name in LIBS.values():
            p=self.root/f'{name}2/src/lib.hepta';p.write_bytes(p.read_bytes()+b'\n// unselected fixture edit\n')
        verify_lock(load_package(self.app))
        self.compare(old,self.lock('same'),changed=False)
        self.app_manifest();self.stale();new=self.lock('new')
        self.compare(old,new);self.native()

    def test_layout_preserving_relocation_and_public_cli(self):
        self.app_manifest();self.lock('old')
        moved=self.root/'relocated'
        # Copy only fixture packages, not locks or native outputs at fixture root.
        for p in list(self.root.iterdir()):
            if p.is_dir() and p!=moved: shutil.copytree(p,moved/p.name)
        original=self.app;self.app=moved/'app'
        try:
            verify_lock(load_package(self.app));self.selected(2)
            before=(self.app/'Hepta.lock').read_bytes();write_lock(self.app)
            self.assertEqual((self.app/'Hepta.lock').read_bytes(),before)
            result=self.cli('run',self.app,'--locked','--backend',BACKEND,'--json')
            self.assertEqual((result['returncode'],result['stdout'],result['stderr']),(0,'',''))
        finally:self.app=original

    def test_equal_selected_versions_retarget_source_paths(self):
        self.lock('old')
        shutil.copytree(self.root/'ordering1',self.root/'ordering1copy')
        engine=self.root/'engine1/hepta.toml'
        engine.write_text(engine.read_text().replace('../ordering1','../ordering1copy'))
        self.stale();new=self.lock('new')
        report=self.compare(self.root/'old.lock',new)
        self.assertEqual(report['dependencies']['retargeted'],[{'package':'../engine1','alias':'order','before':'../ordering1','after':'../ordering1copy'}])
        self.native()

    def test_candidate_order_and_range_change_preserves_native_selection(self):
        self.app_manifest();old=self.lock('old')
        p=self.app/'hepta.toml'
        p.write_text(p.read_text().replace('["../engine1", "../engine2"]','["../engine2", "../engine1"]').replace('>=1.0.0','>=1.0.0, <3.0.0'))
        self.stale();new=self.lock('new');self.selected(2)
        report=self.compare(old,new)
        self.assertTrue(all(not x for x in report['packages'].values()))
        self.assertTrue(all(not x for x in report['dependencies'].values()))
        self.assertEqual([x['path'] for x in report['files']['changed']],['hepta.toml'])
        self.native()

    def test_checked_in_versioned_example_public_cli(self):
        example = ROOT/'examples/packages/versioned_text'
        app = self.root/'examples/packages/versioned_text'
        shutil.copytree(example,app)
        shutil.copytree(ROOT/'stdlib',self.root/'stdlib')
        for name in ('main.hepta','packet.hepta'):
            self.assertEqual((example/'src'/name).read_bytes(),
                             (ROOT/'examples/packages/indexed_text/src'/name).read_bytes())
        original = self.app
        self.app = app
        try:
            verify_lock(load_package(app))
            frozen = (app/'Hepta.lock').read_bytes()
            write_lock(app)
            self.assertEqual((app/'Hepta.lock').read_bytes(),frozen)
            result = self.cli('run',app,'--locked','--backend',BACKEND,'--json')
            self.assertEqual((result['returncode'],result['stdout'],result['stderr']),(0,'',''))
        finally: self.app=original

    def test_exact_component_bytes_and_reversible_manifest_projection(self):
        verify_components()


if __name__=='__main__':unittest.main()
