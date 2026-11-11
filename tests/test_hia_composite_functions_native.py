"""Post-restart reconstruction of complete-function acceptance controls.

This is a new test revision. Historical pre-restart passes are not a receipt for
this file; selected images and cold/development provenance remain explicit.
"""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
from hashlib import sha256
import inspect
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
from hepta.hia_composite_functions_native import KERNELS, SOURCES, SELECTOR, installed_composite_functions
from hepta.hia_composite_types_native import SELECTOR as TYPE_SELECTOR
from hepta.hia_task_helpers_native import SELECTOR as HELPER_SELECTOR
from hepta.hia_program import HIAProgramRejected, verify_core
from tests import test_hia_program_composite as fixtures
from tests import test_hia_partial_record as partial
from tests import test_hia_composite_returned_loans as loans
from tests import test_hia_composite_v6_resources as resources

ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT = 'HEPTA_HIA_COMPOSITE_FUNCTIONS_DEVELOPMENT_MANIFEST'
TYPE_DEVELOPMENT = 'HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST'
HELPER_DEVELOPMENT = 'HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST'
COLD_REPORT = 'HEPTA_HIA_COMPOSITE_FUNCTIONS_COLD_REPORT'
HOST_METHODS = ('_reference_function', '_reference_parameters', '_reference_check_task',
    'loan_origins', '_reference_helper', 'fresh', 'reserve_values', 'flat_parameters',
    'constant', 'zeros', 'drop_padding', 'helper')


def absent(*args, **kwargs):
    raise AssertionError('a hosted nominal semantic owner was invoked')


class FunctionSourceTests(unittest.TestCase):
    def test_five_sources_reproduce_with_unchanged_compiler_limits(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_composite_functions import document
        for name in KERNELS:
            with self.subTest(kernel=name):
                data = document(name)
                source = render_assembly(data).encode()
                self.assertEqual(source, SOURCES[name].read_bytes())
                self.assertLessEqual(len(source), 1 << 20)
                self.assertLessEqual(len(data['functions']), 128)
                self.assertLessEqual(sum(len(f['blocks']) for f in data['functions']), 1536)
                self.assertLessEqual(sum(len(b['ops']) for f in data['functions'] for b in f['blocks']), 8192)
                self.assertTrue(all(len(f['blocks']) <= 256 for f in data['functions']))
                self.assertTrue(all(len(f['params']) <= 16 for f in data['functions']))
                self.assertTrue(all(len(b['params']) <= 16 for f in data['functions'] for b in f['blocks']))

    def test_original_body_and_indivisible_bundle(self):
        from hepta.hia_composite_functions_native import NativeCompositeFunctions
        original = inspect.getsource(composite._Elaborator._reference_function)
        original = original.replace('def _reference_function(', 'def function(', 1).rstrip('\n') + '\n'
        self.assertEqual(sha256(original.encode()).hexdigest(),
            'b7336fb540911f220fef676d082c1a365d4712703ba5f08faeff3ac985913972')
        with self.assertRaisesRegex(ValueError, 'every HIA kernel'):
            NativeCompositeFunctions({'admit': object()}, types_source_sha256='0' * 64,
                                     helpers_source_sha256='0' * 64)

    def test_cold_gate_refuses_before_output_is_created(self):
        from tools.build_hia_composite_functions import build
        with tempfile.TemporaryDirectory(prefix='hia-function-cold-gate-') as directory:
            folder = Path(directory)
            compiler, report, output = folder / 'compiler', folder / 'report.json', folder / 'output'
            compiler.write_bytes(b'unqualified compiler')
            report.write_text(json.dumps({'status': 'DEVELOPMENT_ONLY'}))
            with self.assertRaisesRegex(ValueError, 'completed matching native cold qualification'):
                build(output, compiler, report)
            self.assertFalse(output.exists())


class CompleteNativeFunctionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        development = [os.environ.get(n) for n in (DEVELOPMENT, TYPE_DEVELOPMENT, HELPER_DEVELOPMENT)]
        cold = os.environ.get(COLD_REPORT)
        if cold and any(development):
            raise AssertionError('development images cannot override cold qualification')
        if any(development) and not all(development):
            raise AssertionError('development owner requires all three exact manifests')
        temporary = tempfile.TemporaryDirectory(prefix='hia-function-fixture-')
        cls.addClassCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        if all(development):
            cls.manifest, cls.type_manifest, cls.helper_manifest = map(Path, development)
            cls.fixture_scope = 'DEVELOPMENT_ONLY'
        elif cold:
            from tools.build_hia_composite_functions import build as build_functions
            from tools.build_hia_json_preflight import build
            report = json.loads(Path(cold).read_bytes())
            nested = json.loads(Path(report['nested_report']).read_bytes())
            compiler = Path(nested['generations'][-1]['produced_image'])
            cls.manifest = build_functions(folder / 'functions', compiler, Path(cold))
            cls.type_manifest = build(folder / 'types', compiler, Path(cold), candidate='composite-types')
            cls.helper_manifest = build(folder / 'helpers', compiler, Path(cold), candidate='task-helpers')
            cls.fixture_scope = 'MATCHING_SOURCE_COLD_BUILD'
        else:
            from tools.qualify_hia_selfhost import build_seed, compile_stage
            from hepta.hia_composite_types_native import SOURCE as TYPE_SOURCE, SCHEMA as TYPE_SCHEMA
            from hepta.hia_task_helpers_native import SOURCE as HELPER_SOURCE, SCHEMA as HELPER_SCHEMA
            from hepta.hia_composite_functions_native import SCHEMA
            seed, _ = build_seed(folder)
            source = TYPE_SOURCE.with_name('selfhost.hiaasm').read_bytes()
            first, _ = compile_stage(folder, 'B1', seed, source, image_format='seed-shared')
            compiler, _ = compile_stage(folder, 'B2', first, source)
            assert first.read_bytes() == compiler.read_bytes()
            rows = [('types', TYPE_SOURCE, TYPE_SCHEMA), ('helpers', HELPER_SOURCE, HELPER_SCHEMA)]
            rows += [(n, SOURCES[n], 'hepta.hia.composite-function-' + n + '-native.v1') for n in KERNELS]
            manifests = {}
            for name, path, schema in rows:
                image, receipt = compile_stage(folder, 'function-fixture-' + name, compiler, path.read_bytes())
                target = folder / (name + '.manifest.json')
                target.write_text(json.dumps(dict(schema=schema, source_sha256=sha256(path.read_bytes()).hexdigest(),
                    image_path=image.name, image_sha256=sha256(image.read_bytes()).hexdigest(),
                    compiler_sha256=sha256(compiler.read_bytes()).hexdigest())))
                (folder / (name + '.development-compile.json')).write_text(json.dumps(receipt, indent=2))
                manifests[name] = target.name
            cls.type_manifest, cls.helper_manifest = folder / manifests['types'], folder / manifests['helpers']
            cls.manifest = folder / 'manifest.json'
            cls.manifest.write_text(json.dumps(dict(schema=SCHEMA,
                kernels={n: manifests[n] for n in KERNELS},
                types_source_sha256=sha256(TYPE_SOURCE.read_bytes()).hexdigest(),
                helpers_source_sha256=sha256(HELPER_SOURCE.read_bytes()).hexdigest())))
            cls.fixture_scope = 'BOOTSTRAP_DEVELOPMENT_ONLY'
        cls.bundle = installed_composite_functions(cls.manifest)
        cls.env = {SELECTOR: str(cls.manifest), TYPE_SELECTOR: str(cls.type_manifest),
                   HELPER_SELECTOR: str(cls.helper_manifest)}
        cls.reference_env = {SELECTOR: '', TYPE_SELECTOR: '', HELPER_SELECTOR: ''}

    def native(self, document):
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, self.env))
            stack.enter_context(patch.object(composite, '_Types', new=absent))
            for name in HOST_METHODS:
                stack.enter_context(patch.object(composite._Elaborator, name, new=absent))
            return verify_core(document)

    def test_public_profiles_and_fixtures_without_host_semantic_owners(self):
        documents = []
        for schema in ('hepta.hia.composite.v1', 'hepta.hia.composite.v2',
                       'hepta.hia.composite.v3', 'hepta.hia.composite.v4'):
            for factory in (fixtures.stored_loan_program, fixtures.enum_owner_program, fixtures.scalar_task_program):
                document = factory(); document['schema'] = schema
                documents.append(document)
        documents += [fixtures.task_program(), fixtures.owned_result_task_program(),
            partial.roundtrip_program(), partial.task_partial_program(), partial.nested_record_program(),
            partial.chain_partial_program(), loans.task_program(), loans.pair_program('read'),
            loans.pair_program('mut'), resources.composite_bulk_program(), resources.composite_range_task_program()]
        for document in documents:
            with self.subTest(schema=document['schema'], module=document['module']):
                with patch.dict(os.environ, self.reference_env):
                    expected = verify_core(document)
                actual = self.native(document)
                self.assertEqual((actual.canonical_bytes, actual.structured_bytes),
                                 (expected.canonical_bytes, expected.structured_bytes))

    def test_missing_native_dependencies_refuse_without_function_fallback(self):
        for missing in (TYPE_SELECTOR, HELPER_SELECTOR):
            with self.subTest(missing=missing), patch.dict(os.environ, {**self.env, missing: ''}), \
                 patch.object(composite._Elaborator, '_reference_function', new=absent):
                with self.assertRaisesRegex(HIAProgramRejected, 'requires native'):
                    verify_core(fixtures.stored_loan_program())

    def test_private_member_replacement_or_mutation_poison_the_session(self):
        for replacement in (False, True):
            with self.subTest(replacement=replacement), patch.dict(os.environ, self.env):
                owner = composite._Elaborator(fixtures.stored_loan_program())
                session = owner._native_function_session
                original = owner.document['functions'][0]
                submitted = deepcopy(original) if replacement else original
                saved = deepcopy(original)
                before = (owner.serial, owner.value_slots, owner.types.observations)
                submitted['blocks'] = 0
                try:
                    with patch.object(composite._Elaborator, '_reference_function', new=absent):
                        with self.assertRaisesRegex(HIAProgramRejected,
                                'not an admitted document member' if replacement else 'changed after snapshot'):
                            owner.function(submitted)
                        original.clear(); original.update(saved)
                        with self.assertRaisesRegex(HIAProgramRejected, 'closed or broken'):
                            owner.function(original)
                    self.assertEqual((owner.serial, owner.value_slots, owner.types.observations), before)
                finally:
                    session.close(); owner.types.close()

    def test_large_output_retains_the_original_later_error_order(self):
        from tests.test_hia_program import b, f, ret
        definitions = [fixtures.record('A', [('p' + str(n), 'u8') for n in range(64)]),
                       fixtures.record('R', [('part' + str(n), 'A') for n in range(8)])]
        params = [('input', 'R')]
        large = f('large', params, ['R'] * 1000, [], [b('entry', params, [], ret(*(['input'] * 1000)))])
        later = f('later', [], [], [], [b('entry', [], [], ret())]); later['blocks'] = 0
        for document in (loans.v4(definitions, large), loans.v4(definitions, large, later)):
            with self.subTest(functions=len(document['functions'])):
                with patch.dict(os.environ, self.reference_env), self.assertRaises(HIAProgramRejected) as expected:
                    verify_core(document)
                with self.assertRaises(HIAProgramRejected) as actual:
                    self.native(document)
                self.assertEqual((actual.exception.code, str(actual.exception)),
                                 (expected.exception.code, str(expected.exception)))

    def test_real_installed_wheel_and_each_source_or_image_custody_refusal(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, PUBLICATION_BUILD_FILES
        resource_names = tuple('docs/' + n for n in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + PUBLICATION_BUILD_FILES
        for name in KERNELS:
            self.assertIn('examples/hia_bootstrap/composite_function_' + name + '.hiaasm', resource_names)
        with tempfile.TemporaryDirectory(prefix='hia-function-wheel-') as directory:
            folder = Path(directory)
            source = folder / 'source'; source.mkdir()
            shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
            for name in (*resource_names, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
                target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            wheels, installed = folder / 'wheels', folder / 'installed'
            for command in ([sys.executable, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
                             '--wheel-dir', str(wheels), str(source)],):
                run = subprocess.run(command, cwd=folder, capture_output=True, timeout=120,
                                     env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            wheel, = wheels.glob('*.whl')
            run = subprocess.run([sys.executable, '-B', '-m', 'pip', 'install', '--no-deps', '--no-index',
                '--target', str(installed), str(wheel)], cwd=folder, capture_output=True, timeout=120,
                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            document = loans.task_program()
            with patch.dict(os.environ, self.reference_env):
                expected = verify_core(document).canonical_bytes
            data = folder / 'input.json'; data.write_text(json.dumps(document))
            bundle = json.loads(self.manifest.read_bytes())
            local_images = {}
            for name in KERNELS:
                original = self.manifest.parent / bundle['kernels'][name]
                value = json.loads(original.read_bytes())
                image = original.parent / value['image_path']
                target = folder / (name + '.image.bin'); target.write_bytes(image.read_bytes())
                value['image_path'] = target.name
                manifest = folder / (name + '.manifest.json'); manifest.write_text(json.dumps(value))
                bundle['kernels'][name] = manifest.name
                local_images[name] = target
            selected_bundle = folder / 'bundle.json'; selected_bundle.write_text(json.dumps(bundle))
            child = '''import sys,importlib.abc,json
sys.path.insert(0,sys.argv[1])
class NoTools(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=='tools' or fullname.startswith('tools.'):raise AssertionError('authoring tools imported')
sys.meta_path.insert(0,NoTools())
from pathlib import Path
from hepta import hia_program_composite as c
from hepta.hia_program import verify_core,HIAProgramRejected
from hepta.hia_composite_functions_native import SOURCES
assert all(Path(sys.argv[1]) in p.parents for p in SOURCES.values())
def absent(*args,**kwargs):raise AssertionError('host nominal semantic owner invoked')
c._Types=absent
for name in ('_reference_function','_reference_parameters','_reference_check_task','loan_origins',
 '_reference_helper','fresh','reserve_values','flat_parameters','constant','zeros','drop_padding','helper'):
 setattr(c._Elaborator,name,absent)
try:
 result=verify_core(Path(sys.argv[2]).read_bytes())
except HIAProgramRejected as error:
 print(json.dumps({'error':error.code,'text':str(error)}));sys.exit(7)
sys.stdout.buffer.write(result.canonical_bytes)
'''
            environment = {**os.environ, **self.env, SELECTOR: str(selected_bundle),
                           'PATH': '', 'PYTHONPATH': '', 'PYTHONDONTWRITEBYTECODE': '1'}

            def invoke():
                return subprocess.run([sys.executable, '-I', '-S', '-c', child, str(installed), str(data)],
                    cwd=folder, capture_output=True, timeout=30, env=environment)

            run = invoke()
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertEqual(run.stdout, expected)
            for name in KERNELS:
                matches = list(installed.rglob('composite_function_' + name + '.hiaasm'))
                self.assertEqual(len(matches), 1)
                source_path = matches[0]; original = source_path.read_bytes()
                try:
                    for mutation in ('changed', 'missing'):
                        if mutation == 'changed': source_path.write_bytes(original + b'\n')
                        else: source_path.unlink()
                        run = invoke()
                        self.assertEqual(run.returncode, 7, (name, mutation, run.stdout, run.stderr))
                        self.assertEqual(json.loads(run.stdout)['error'], 'E_HIA_TYPE')
                finally:
                    source_path.write_bytes(original)
            image = local_images['records']; original = image.read_bytes()
            try:
                image.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                run = invoke()
                self.assertEqual(run.returncode, 7, run.stdout + run.stderr)
                self.assertEqual(json.loads(run.stdout)['error'], 'E_HIA_TYPE')
            finally:
                image.write_bytes(original)


if __name__ == '__main__':
    unittest.main()
