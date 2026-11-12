"""Complete native outer/constructor/function integration and installed-wheel custody."""
from contextlib import ExitStack
from hashlib import sha256
import gc
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_composite_outer_native import SELECTOR, KERNELS
from hepta.hia_composite_constructor_native import SELECTOR as CONSTRUCTOR_SELECTOR
from hepta.hia_composite_functions_native import SELECTOR as FUNCTION_SELECTOR
from hepta.hia_composite_types_native import SELECTOR as TYPE_SELECTOR
from hepta.hia_task_helpers_native import SELECTOR as HELPER_SELECTOR
from hepta.hia_program import verify_core
from hepta.hia_program_runtime import execute_program
from tests import test_hia_program_composite as nominal
from tests import test_hia_composite_returned_loans as loans
from tests import test_hia_partial_record as partial

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = ('HEPTA_HIA_COMPOSITE_OUTER_DEVELOPMENT_MANIFEST',
               'HEPTA_HIA_COMPOSITE_CONSTRUCTOR_DEVELOPMENT_MANIFEST',
               'HEPTA_HIA_COMPOSITE_FUNCTIONS_DEVELOPMENT_MANIFEST',
               'HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST',
               'HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST')
HOST = ('_reference_lower', 'function', '_reference_initialize', '_reference_function', '_reference_parameters',
        '_reference_check_task', 'loan_origins', '_reference_helper', 'parameters',
        'check_task', 'fresh', 'reserve_values', 'flat_parameters', 'constant',
        'zeros', 'drop_padding', 'helper')


def forbidden(*args, **kwargs):
    raise AssertionError('retained nominal semantic owner invoked')


class NativeOuterIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.hia_composite_function_fixture import composite_function_fixture
        fixture = composite_function_fixture()
        cls.env = fixture.complete_environment
        cls.reference_env = {**cls.env, SELECTOR: '', CONSTRUCTOR_SELECTOR: '', FUNCTION_SELECTOR: ''}
        evidence = os.environ.get('HEPTA_HIA_OUTER_INTEGRATION_EVIDENCE')
        cls.evidence = Path(evidence) if evidence else None
        if cls.evidence is not None:
            cls.evidence.mkdir(parents=True, exist_ok=True)

    def native(self, document):
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, self.env))
            stack.enter_context(patch.object(composite, '_Types', new=forbidden))
            for name in HOST:
                stack.enter_context(patch.object(composite._Elaborator, name, new=forbidden))
            return verify_core(document)

    def test_complete_public_pipeline_and_actual_core_execution(self):
        fixtures = [nominal.stored_loan_program, nominal.enum_owner_program,
                    nominal.task_program, nominal.scalar_task_program, nominal.owned_result_task_program,
                    partial.roundtrip_program, partial.task_partial_program, partial.chain_partial_program,
                    loans.pair_program, loans.task_program, loans.direct_downgrade_program]
        rows = []
        for factory in fixtures:
            with self.subTest(fixture=factory.__name__):
                document = factory()
                with patch.dict(os.environ, self.reference_env):
                    expected = verify_core(document)
                actual = self.native(document)
                self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                                 (expected.canonical_bytes, expected.structured_bytes))
                row = {'fixture': factory.__module__ + '.' + factory.__name__,
                       'source_sha256': sha256(json.dumps(document,sort_keys=True).encode()).hexdigest(),
                       'canonical_sha256': sha256(actual.canonical_bytes).hexdigest()}
                if factory is nominal.stored_loan_program:
                    for flag in (False, True):
                        reference = execute_program(expected, 'stored', [flag])
                        native = execute_program(actual, 'stored', [flag])
                        self.assertEqual(native, reference)
                    row['actual_core_vm_cases'] = 2
                elif factory is nominal.scalar_task_program:
                    self.assertEqual(execute_program(actual, 'scalar_task', []),
                                     execute_program(expected, 'scalar_task', []))
                    row['actual_core_vm_cases'] = 1
                elif factory is nominal.task_program:
                    for mode in (0, 1, 2):
                        self.assertEqual(execute_program(actual, 'task_case', [mode]),
                                         execute_program(expected, 'task_case', [mode]))
                    row['actual_core_vm_cases'] = 3
                rows.append(row)
                del actual, expected
                gc.collect()
        if self.evidence is not None:
            (self.evidence/'public-pipeline.json').write_text(json.dumps(rows,indent=2)+'\n')

    def test_real_sdist_to_wheel_without_old_owners_and_all_new_resource_refusals(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES
        new_resources = ['examples/hia_bootstrap/composite_' + owner + '_' + name + '.hiaasm'
                         for owner in ('constructor', 'outer') for name in KERNELS]
        for name in new_resources:
            self.assertIn(name, resources)
        with tempfile.TemporaryDirectory(prefix='hia-outer-wheel-', dir='/dev/shm') as temporary:
            folder = Path(temporary)
            source = folder/'source'; source.mkdir()
            shutil.copytree(ROOT/'hepta', source/'hepta', ignore=shutil.ignore_patterns('__pycache__'))
            for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
                target = source/name; target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT/name,target)
            sdists, wheels, installed = folder/'sdist', folder/'wheels', folder/'installed'
            rows = []
            result = subprocess.run([sys.executable, '-B', 'setup.py', 'sdist', '--dist-dir', str(sdists)],
                cwd=source, capture_output=True, timeout=120,
                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            rows.append({'label': 'sdist-build', 'returncode': result.returncode,
                         'stdout': result.stdout.decode(), 'stderr': result.stderr.decode()})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            archive, = sdists.glob('*.tar.gz')
            with tarfile.open(archive) as package:
                prefix = package.getnames()[0].split('/')[0] + '/'
                for name in resources:
                    self.assertEqual(package.extractfile(prefix + name).read(), (ROOT / name).read_bytes())
            rows.append({'label': 'sdist-resource-readback', 'resource_count': len(resources),
                         'new_nominal_resources': new_resources,
                         'sdist_sha256': sha256(archive.read_bytes()).hexdigest(),
                         'sdist_bytes': archive.stat().st_size})
            command = [sys.executable,'-B','-m','pip','wheel','--no-deps','--no-build-isolation',
                       '--wheel-dir',str(wheels),str(archive)]
            result = subprocess.run(command,cwd=folder,capture_output=True,timeout=120)
            rows.append({'label':'wheel-build','returncode':result.returncode,
                         'stdout':result.stdout.decode(),'stderr':result.stderr.decode()})
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            wheel, = wheels.glob('*.whl')
            result = subprocess.run([sys.executable,'-B','-m','pip','install','--no-deps','--no-index',
                '--target',str(installed),str(wheel)],cwd=folder,capture_output=True,timeout=120)
            rows.append({'label':'wheel-install','returncode':result.returncode,
                         'stdout':result.stdout.decode(),'stderr':result.stderr.decode(),
                         'wheel_sha256':sha256(wheel.read_bytes()).hexdigest(),'wheel_bytes':wheel.stat().st_size})
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            document = nominal.stored_loan_program()
            with patch.dict(os.environ,self.reference_env):
                expected = verify_core(document).canonical_bytes
            gc.collect()
            data = folder/'source.json'; data.write_text(json.dumps(document))
            images, selections = {}, {}
            for selector, owner in ((CONSTRUCTOR_SELECTOR, 'constructor'), (SELECTOR, 'outer')):
                origin = Path(self.env[selector]); bundle = json.loads(origin.read_bytes())
                for name in KERNELS:
                    component = origin.parent/bundle['kernels'][name]
                    value = json.loads(component.read_bytes())
                    image = folder/(owner+'-'+name+'.image.bin')
                    image.write_bytes((component.parent/value['image_path']).read_bytes())
                    value['image_path'] = image.name
                    target = folder/(owner+'-'+name+'.json'); target.write_text(json.dumps(value))
                    bundle['kernels'][name] = target.name
                    images[owner, name] = image
                selected = folder/(owner+'.json'); selected.write_text(json.dumps(bundle))
                selections[selector] = str(selected)
            child = '''import sys,importlib.abc,json
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=='tools' or fullname.startswith('tools.'):raise AssertionError('authoring tools imported')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as c
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_program_runtime import execute_program
from hepta.hia_composite_outer_native import SOURCES
from hepta.hia_composite_constructor_native import SOURCES as CTOR_SOURCES
from hepta.hia_composite_functions_native import SOURCES as FUNCTION_SOURCES
from hepta.hia_composite_types_native import SOURCE as TYPE_SOURCE
from hepta.hia_task_helpers_native import SOURCE as HELPER_SOURCE
all_sources=[*SOURCES.values(),*CTOR_SOURCES.values(),*FUNCTION_SOURCES.values(),TYPE_SOURCE,HELPER_SOURCE]
assert len(all_sources)==11 and all(Path(sys.argv[1]) in p.parents for p in all_sources)
def absent(*args,**kwargs):raise AssertionError('retained nominal semantic owner invoked')
c._Types=absent
for name in json.loads(sys.argv[3]):setattr(c._Elaborator,name,absent)
try:
 checked=verify_core(Path(sys.argv[2]).read_bytes())
 execute_program(checked,'stored',[False]);execute_program(checked,'stored',[True])
except HIAProgramRejected as error:
 print(json.dumps({'error':error.code,'text':str(error)}));sys.exit(7)
sys.stdout.buffer.write(checked.canonical_bytes)
'''
            environment = {**os.environ,**self.env,**selections,'PATH':'','PYTHONPATH':'',
                           'PYTHONDONTWRITEBYTECODE':'1'}
            def invoke(label):
                result = subprocess.run([sys.executable,'-I','-S','-c',child,str(installed),str(data),json.dumps(HOST)],
                    cwd=folder,capture_output=True,timeout=30,env=environment)
                rows.append({'label':label,'returncode':result.returncode,
                             'stdout':result.stdout.decode(),'stderr':result.stderr.decode()})
                if self.evidence is not None:
                    (self.evidence/'wheel-records.json').write_text(json.dumps(rows,indent=2)+'\n')
                return result
            result = invoke('actual-complete-native-wheel')
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(result.stdout,expected)
            for owner, name in images:
                paths = list(installed.rglob('composite_'+owner+'_'+name+'.hiaasm'))
                self.assertEqual(len(paths),1)
                sourcepath=paths[0]; original=sourcepath.read_bytes()
                try:
                    for mutation in ('changed','missing'):
                        if mutation=='changed':sourcepath.write_bytes(original+b'\n')
                        else:sourcepath.unlink()
                        result=invoke(owner+'-'+name+'-source-'+mutation)
                        self.assertEqual(result.returncode,7,result.stdout+result.stderr)
                        self.assertEqual(json.loads(result.stdout)['error'],'E_HIA_TYPE')
                finally:
                    sourcepath.write_bytes(original)
                image=images[owner, name]; original=image.read_bytes()
                try:
                    for mutation in ('changed', 'missing'):
                        if mutation == 'changed': image.write_bytes(bytes([original[0]^1])+original[1:])
                        else: image.unlink()
                        result=invoke(owner+'-'+name+'-image-'+mutation)
                        self.assertEqual(result.returncode,7,result.stdout+result.stderr)
                        self.assertEqual(json.loads(result.stdout)['error'],'E_HIA_TYPE')
                finally:
                    image.write_bytes(original)
            for selector, selected in selections.items():
                path = Path(selected); original = path.read_bytes()
                try:
                    for mutation in ('changed', 'missing'):
                        if mutation == 'changed': path.write_bytes(b'{}')
                        else: path.unlink()
                        result = invoke(selector+'-'+mutation)
                        self.assertEqual(result.returncode, 7, result.stdout+result.stderr)
                        self.assertEqual(json.loads(result.stdout)['error'], 'E_HIA_TYPE')
                finally:
                    path.write_bytes(original)
            if self.evidence is not None:
                shutil.copyfile(archive, self.evidence / archive.name)
                shutil.copyfile(wheel, self.evidence / wheel.name)
                (self.evidence/'installed-source-pins.json').write_text(json.dumps({
                    path.relative_to(installed).as_posix(): sha256(path.read_bytes()).hexdigest()
                    for path in sorted(installed.rglob('*')) if path.is_file()}, indent=2, sort_keys=True)+'\n')


if __name__ == '__main__':
    unittest.main()
