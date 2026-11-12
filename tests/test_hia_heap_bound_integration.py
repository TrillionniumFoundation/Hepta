"""Installed four-image heap composition, worker custody and source rejection.

The child imports only the built wheel and standard-library test machinery.
All retained heap/static policy callbacks and authoring imports are poisoned.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch
import zipfile

from tests.test_hia_heap_bound_native import (
    ROOT, SELECTORS, RESOURCES, HeapBuildFixture, selected, components,
)

CHILD = r'''
import sys
sys.path.insert(0,sys.argv[1])
import importlib.abc
from hashlib import sha256
import json
from pathlib import Path
from unittest.mock import patch

class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if fullname.split('.')[0] in ('tools','tests'):
            raise AssertionError('installed heap imported authoring or test code')
sys.meta_path.insert(0,NoAuthoring())

from hepta import hia_heap_bound as heap, hia_heap_bound_native as controller
from hepta import hia_heap_live_native as live, hia_heap_payload_native as payload
from hepta import hia_static_budget as static, hia_static_budget_native as structural
from hepta import hia_native_helpers as helpers
from hepta.hia_native_helpers import native_helpers_scope
from hepta.hia_checker_identity import checker_native_selection

def absent(*args,**kwargs):
    raise AssertionError('installed heap reached a retained heap/static policy')
for name in [name for name in vars(heap) if name.startswith('_reference_')]:
    setattr(heap,name,absent)
for name in ('_function','_dag','_scoped_allocating_cycle_peak','_qualify_finite_entry_live_heap_budget'):
    setattr(heap,name,absent)
heap._FiniteInvocationAnalysis.__init__=absent
for name in [name for name in vars(static) if name.startswith('_reference_')]:
    setattr(static,name,absent)
for name in ('_bound_function','_audit_v7_byte_resource_profile','_audit_v8_resource_profile'):
    setattr(static,name,absent)
modules=(controller,live,structural,payload)
loaders=(controller.installed_heap_controller,live.installed_heap_live,
         structural.installed_static_budget,payload.installed_heap_payload)
installed=Path(sys.argv[1]).resolve()
for path in (heap.__file__,static.__file__,*(module.SOURCE for module in modules)):
    assert Path(path).resolve().is_relative_to(installed),path
bundle,digest,mode=sys.argv[2:5]
entries={module.SELECTOR:0 for module in modules}

if mode=='drift':
    try:
        with native_helpers_scope(bundle,digest):
            raise AssertionError('changed installed heap source was admitted')
    except ValueError as error:
        assert str(error)=='native helper source identity mismatch',str(error)
        print(json.dumps({'refused':str(error),'entries':entries},sort_keys=True))
elif mode=='incomplete':
    with patch.object(helpers.importlib,'import_module',
                      side_effect=AssertionError('mapping/import before complete dependency admission')):
        try:
            with native_helpers_scope(bundle,digest):
                raise AssertionError('incomplete heap group was admitted')
        except ValueError as error:
            assert str(error)=='native heap controller requires its complete pinned dependency set',str(error)
            print(json.dumps({'refused':str(error),'entries':entries},sort_keys=True))
elif mode=='worker':
    import runpy
    sys.argv=['hia-agent-worker','--installation-manifest','--native-helpers-manifest',bundle,
              '--expected-native-helpers-sha256',digest]
    runpy.run_module('hepta.hia_agent_worker',run_name='__main__')
else:
    cases=json.loads(Path(sys.argv[5]).read_bytes())
    with native_helpers_scope(bundle,digest) as binding:
        for module,loader in zip(modules,loaders):
            image=loader(binding.selections[module.SELECTOR])
            assert image in binding.images.values()
            original=image._entry
            def counted(*args,selector=module.SELECTOR,original=original):
                entries[selector]+=1
                return original(*args)
            image._entry=counted
        reports=[]
        for case in cases:
            module=heap if case['owner']=='heap' else static
            try:
                result=getattr(module,case['entry'])(case['program'],*case['arguments'],**case['keywords'])
                reports.append({'returned':result})
            except Exception as error:
                cause=error.__cause__
                reports.append({'type':type(error).__name__,'code':getattr(error,'code',None),
                    'message':str(error),'cause':None if cause is None else
                    {'type':type(cause).__name__,'code':getattr(cause,'code',None),'message':str(cause)}})
        assert all(count>0 for count in entries.values()),entries
        identity=checker_native_selection()
        assert not any(name.split('.')[0] in ('tools','tests') for name in sys.modules)
        binding.check()
        print(json.dumps({'reports':reports,'native_entries':entries,
              'sources':{module.SELECTOR:{'path':str(module.SOURCE),
                       'sha256':sha256(module.SOURCE.read_bytes()).hexdigest()} for module in modules},
              'helpers_sha256':binding.sha256,
              'checker':{key:identity[key] for key in entries}},sort_keys=True))
'''


class InstalledHeapBoundTests(HeapBuildFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
        from hepta.hia_native_helpers import SCHEMA, TARGET, ABI
        cls.package_source=cls.folder/'package-source'
        cls.package_source.mkdir()
        shutil.copytree(ROOT/'hepta',cls.package_source/'hepta',
                        ignore=shutil.ignore_patterns('__pycache__'))
        resources=tuple('docs/'+name for name in DISCOVERY_FILES)+NATIVE_SOURCE_FILES+PUBLICATION_BUILD_FILES
        cls.resources={name:(ROOT/name).read_bytes() for name in resources}
        for name in (*resources,'setup.py','pyproject.toml','MANIFEST.in'):
            target=cls.package_source/name
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes((ROOT/name).read_bytes())
        def package(label,arguments):
            with (cls.folder/(label+'.log')).open('xb') as stream:
                result=subprocess.run([sys.executable,'-B',*map(str,arguments)],cwd=cls.package_source,
                    env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'},stdout=stream,
                    stderr=subprocess.STDOUT,timeout=180)
            if result.returncode:
                raise AssertionError(label+': '+(cls.folder/(label+'.log')).read_text())
        package('sdist',['setup.py','sdist','--dist-dir',cls.folder/'sdist'])
        archive,=(cls.folder/'sdist').glob('*.tar.gz')
        with tarfile.open(archive) as source_archive:
            prefix=source_archive.getnames()[0].split('/')[0]+'/'
            for name,raw in cls.resources.items():
                assert source_archive.extractfile(prefix+name).read()==raw,name
        package('wheel',['-m','pip','wheel','--no-deps','--no-build-isolation',
                         '--wheel-dir',cls.folder/'wheels',archive])
        cls.wheel,=(cls.folder/'wheels').glob('*.whl')
        cls.wheel_bytes=cls.wheel.read_bytes()
        with zipfile.ZipFile(cls.wheel) as wheel:
            for name,raw in cls.resources.items():
                assert wheel.read('hepta/_data/'+name)==raw,name
        cls.installed=cls.folder/'installed'
        package('install',['-m','pip','install','--no-deps','--no-index',
                           '--target',cls.installed,cls.wheel])
        cls.bundle_value={'schema':SCHEMA,'target':TARGET,'abi':ABI,'helpers':[
            {'selector':selector,'manifest_path':str(path),
             'manifest_sha256':sha256(cls.held[path]).hexdigest()}
            for selector,path in zip(SELECTORS,cls.paths)]}
        cls.bundle=cls.folder/'worker-helpers.json'
        cls.bundle_bytes=(json.dumps(cls.bundle_value,sort_keys=True)+'\n').encode()
        cls.bundle.write_bytes(cls.bundle_bytes)
        cls.bundle.chmod(0o600)
        cls.bundle_sha=sha256(cls.bundle_bytes).hexdigest()
        from hepta import hia_heap_bound as heap, hia_static_budget as static
        from tests.test_hia_heap_bound import local_buffers
        def program(version):
            value=local_buffers()
            value['schema']='hepta.hia.program.v'+str(version)
            value['exports']=['finite']
            return value
        names=('analyze_constant_live_heap','qualify_live_heap_budget','qualify_entry_live_heap_budget',
               'qualify_finite_entry_live_heap_budget','qualify_finite_entry_live_heap_budget_v8',
               'qualify_finite_entry_live_heap_budget_v8_with_borrowed_extents','analyze_entry_payload_bound')
        cls.cases=[
            {'owner':'heap','entry':names[0],'program':program(1),'arguments':[],'keywords':{}},
            {'owner':'heap','entry':names[1],'program':program(1),'arguments':[],'keywords':{'max_live_heap_bytes':12}},
            {'owner':'heap','entry':names[2],'program':program(8),'arguments':['finite'],'keywords':{'max_live_heap_bytes':12}},
            {'owner':'heap','entry':names[3],'program':program(7),'arguments':['finite',[]],'keywords':{'max_live_heap_bytes':12}},
            {'owner':'heap','entry':names[4],'program':program(8),'arguments':['finite',[]],'keywords':{'max_live_heap_bytes':12}},
            {'owner':'heap','entry':names[5],'program':program(8),'arguments':['finite',[]],'keywords':{'max_live_heap_bytes':12}},
            {'owner':'heap','entry':names[6],'program':program(1),'arguments':['finite'],'keywords':{}},
            {'owner':'heap','entry':names[1],'program':program(1),'arguments':[],'keywords':{'max_live_heap_bytes':11}},
            {'owner':'static','entry':'analyze_static_budget','program':program(1),'arguments':[],
             'keywords':{'max_live_heap_bytes':12}},
            {'owner':'static','entry':'qualify_bounded_resources','program':program(8),'arguments':[],
             'keywords':{'limits':{'max_allocator_interactions':100,'max_vm_ticks':10000,
                                  'max_call_depth':256,'max_live_heap_bytes':12}}},
        ]
        cls.expected=[]
        with selected(None):
            for case in cls.cases:
                module=heap if case['owner']=='heap' else static
                try:
                    value=getattr(module,case['entry'])(case['program'],*case['arguments'],**case['keywords'])
                    cls.expected.append({'returned':value})
                except Exception as error:
                    cause=error.__cause__
                    cls.expected.append({'type':type(error).__name__,'code':getattr(error,'code',None),
                        'message':str(error),'cause':None if cause is None else
                        {'type':type(cause).__name__,'code':getattr(cause,'code',None),'message':str(cause)}})
        cls.case_path=cls.folder/'cases.json'
        cls.case_path.write_text(json.dumps(cls.cases,sort_keys=True)+'\n')
        (cls.folder/'reference.json').write_text(json.dumps(cls.expected,sort_keys=True)+'\n')
        (cls.folder/'installed-child.py').write_text(CHILD)
        cls.child_cwd=cls.folder/'unrelated-working-directory'
        cls.child_cwd.mkdir()

    @classmethod
    def tearDownClass(cls):
        stable=(cls.wheel.read_bytes()==cls.wheel_bytes
                and cls.bundle.read_bytes()==cls.bundle_bytes
                and all((cls.installed/'hepta/_data'/name).read_bytes()==raw
                        for name,raw in cls.resources.items()))
        cls.observations['installed_artifacts_unchanged']=stable
        super().tearDownClass()
        if not stable:
            raise AssertionError('installed heap inputs changed')

    def child(self,mode,bundle=None,digest=None,label=None):
        environment={key:value for key,value in os.environ.items()
                     if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        result=subprocess.run([sys.executable,'-I','-B','-c',CHILD,str(self.installed),
            str(bundle or self.bundle),digest or self.bundle_sha,mode,str(self.case_path)],
            cwd=self.child_cwd,env=environment,capture_output=True,timeout=120)
        name=label or mode
        (self.folder/(name+'.stdout')).write_bytes(result.stdout)
        (self.folder/(name+'.stderr')).write_bytes(result.stderr)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertFalse(result.stderr)
        return json.loads(result.stdout)

    def test_installed_all_seven_public_apis_and_nested_static_composition(self):
        result=self.child('execute')
        self.assertEqual(result['reports'],self.expected)
        self.assertEqual(result['helpers_sha256'],self.bundle_sha)
        for selector,resource,path in zip(SELECTORS,RESOURCES,self.paths):
            self.assertGreater(result['native_entries'][selector],0)
            self.assertEqual(Path(result['sources'][selector]['path']),self.installed/'hepta/_data'/resource)
            self.assertEqual(result['sources'][selector]['sha256'],sha256(self.resources[resource]).hexdigest())
            metadata=json.loads(self.held[path])
            self.assertEqual(result['checker'][selector]['images']['image']['image_sha256'],metadata['image_sha256'])
        self.observations['installed_public']=result

    def test_each_missing_heap_dependency_refuses_before_any_selected_mapping(self):
        rows=[]
        for removed in (SELECTORS[1],SELECTORS[2],SELECTORS[3]):
            value={**self.bundle_value,'helpers':[row for row in self.bundle_value['helpers']
                                                if row['selector']!=removed]}
            path=self.folder/('missing-'+removed+'.json')
            raw=(json.dumps(value,sort_keys=True)+'\n').encode()
            path.write_bytes(raw)
            path.chmod(0o600)
            result=self.child('incomplete',path,sha256(raw).hexdigest(),label='missing-'+removed)
            self.assertEqual(result['entries'],dict.fromkeys(SELECTORS,0))
            rows.append({'removed':removed,'result':result})
        self.observations['missing_dependencies']=rows

    def test_changed_installed_heap_source_refuses_before_any_execution(self):
        rows=[]
        for resource in (RESOURCES[0],RESOURCES[1],RESOURCES[3]):
            path=self.installed/'hepta/_data'/resource
            original=self.resources[resource]
            path.write_bytes(original+b'\n# controlled installed heap source drift\n')
            try:
                result=self.child('drift',label='drift-'+Path(resource).stem)
                self.assertEqual(result['entries'],dict.fromkeys(SELECTORS,0))
                rows.append({'source':resource,'result':result})
            finally:
                path.write_bytes(original)
        self.observations['installed_source_drift']=rows

    def test_worker_receipt_binds_the_same_complete_four_image_group(self):
        result=self.child('worker')
        self.assertEqual(result['native_helpers_sha256'],self.bundle_sha)
        self.assertRegex(result['worker_sha256'],'^[0-9a-f]{64}$')
        self.observations['worker']=result


if __name__=='__main__':
    unittest.main()
