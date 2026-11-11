"""Complete native constructor/function integration and installed-wheel custody."""
from contextlib import ExitStack
from hashlib import sha256
import gc
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_program_composite as composite
from hepta.hia_composite_constructor_native import SELECTOR, KERNELS
from hepta.hia_composite_functions_native import SELECTOR as FUNCTION_SELECTOR
from hepta.hia_composite_types_native import SELECTOR as TYPE_SELECTOR
from hepta.hia_task_helpers_native import SELECTOR as HELPER_SELECTOR
from hepta.hia_program import verify_core
from hepta.hia_program_runtime import execute_program
from tests import test_hia_program_composite as nominal
from tests import test_hia_composite_returned_loans as loans
from tests import test_hia_partial_record as partial

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = ('HEPTA_HIA_COMPOSITE_CONSTRUCTOR_DEVELOPMENT_MANIFEST',
               'HEPTA_HIA_COMPOSITE_FUNCTIONS_DEVELOPMENT_MANIFEST',
               'HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST',
               'HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST')
HOST = ('_reference_initialize', '_reference_function', '_reference_parameters',
        '_reference_check_task', 'loan_origins', '_reference_helper', 'parameters',
        'check_task', 'fresh', 'reserve_values', 'flat_parameters', 'constant',
        'zeros', 'drop_padding', 'helper')


def forbidden(*args, **kwargs):
    raise AssertionError('retained nominal semantic owner invoked')


class NativeConstructorIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.hia_composite_function_fixture import composite_function_fixture
        fixture = composite_function_fixture()
        cls.env = fixture.constructor_function_environment
        cls.reference_env = {**cls.env, SELECTOR: '', FUNCTION_SELECTOR: ''}
        evidence = os.environ.get('HEPTA_HIA_CONSTRUCTOR_INTEGRATION_EVIDENCE')
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
                self.assertEqual(actual.canonical_bytes, expected.canonical_bytes)
                row = {'fixture': factory.__module__ + '.' + factory.__name__,
                       'source_sha256': sha256(json.dumps(document,sort_keys=True).encode()).hexdigest(),
                       'canonical_sha256': sha256(actual.canonical_bytes).hexdigest()}
                if factory is nominal.stored_loan_program:
                    for flag in (False, True):
                        reference = execute_program(expected, 'stored', [flag])
                        native = execute_program(actual, 'stored', [flag])
                        self.assertEqual(native, reference)
                    row['actual_core_vm_cases'] = 2
                rows.append(row)
                del actual, expected
                gc.collect()
        if self.evidence is not None:
            (self.evidence/'public-pipeline.json').write_text(json.dumps(rows,indent=2)+'\n')

    def test_installed_wheel_without_retained_nominal_owners_and_tamper_refusal(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, PUBLICATION_BUILD_FILES
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + PUBLICATION_BUILD_FILES
        for name in KERNELS:
            self.assertIn('examples/hia_bootstrap/composite_constructor_' + name + '.hepta', resources)
        with tempfile.TemporaryDirectory(prefix='hia-ctor-wheel-', dir='/dev/shm') as temporary:
            folder = Path(temporary)
            source = folder/'source'; source.mkdir()
            shutil.copytree(ROOT/'hepta', source/'hepta', ignore=shutil.ignore_patterns('__pycache__'))
            for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
                target = source/name; target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT/name,target)
            wheels, installed = folder/'wheels', folder/'installed'
            rows = []
            command = [sys.executable,'-B','-m','pip','wheel','--no-deps','--no-build-isolation',
                       '--wheel-dir',str(wheels),str(source)]
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
            origin = Path(self.env[SELECTOR]); bundle = json.loads(origin.read_bytes())
            images = {}
            for name in KERNELS:
                component = origin.parent/bundle['kernels'][name]
                value = json.loads(component.read_bytes())
                image = folder/(name+'.image.bin')
                image.write_bytes((component.parent/value['image_path']).read_bytes())
                value['image_path'] = image.name
                target = folder/(name+'.json'); target.write_text(json.dumps(value))
                bundle['kernels'][name] = target.name
                images[name] = image
            selected = folder/'constructor.json'; selected.write_text(json.dumps(bundle))
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
from hepta.hia_composite_constructor_native import SOURCES
assert all(Path(sys.argv[1]) in p.parents for p in SOURCES.values())
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
            environment = {**os.environ,**self.env,SELECTOR:str(selected),'PATH':'','PYTHONPATH':'',
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
            for name in KERNELS:
                paths = list(installed.rglob('composite_constructor_'+name+'.hepta'))
                self.assertEqual(len(paths),1)
                sourcepath=paths[0]; original=sourcepath.read_bytes()
                try:
                    for mutation in ('changed','missing'):
                        if mutation=='changed':sourcepath.write_bytes(original+b'\n')
                        else:sourcepath.unlink()
                        result=invoke(name+'-source-'+mutation)
                        self.assertEqual(result.returncode,7,result.stdout+result.stderr)
                        self.assertEqual(json.loads(result.stdout)['error'],'E_HIA_TYPE')
                finally:
                    sourcepath.write_bytes(original)
                image=images[name]; original=image.read_bytes()
                try:
                    image.write_bytes(bytes([original[0]^1])+original[1:])
                    result=invoke(name+'-image-changed')
                    self.assertEqual(result.returncode,7,result.stdout+result.stderr)
                    self.assertEqual(json.loads(result.stdout)['error'],'E_HIA_TYPE')
                finally:
                    image.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
