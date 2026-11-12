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
import tarfile
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
    def test_bootstrap_source_or_seed_change_cannot_relabel_the_compiled_input(self):
        from tests import hia_composite_function_fixture as fixture
        # These compiler stand-ins inject file races; no executable is loaded.
        for fault in (None, 'source', 'seed'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                types, helpers = folder / 'types.hepta', folder / 'helpers.hepta'
                sources = {name: folder / (name + '.hepta') for name in KERNELS}
                constructors = {name: folder / ('constructor-' + name + '.hepta')
                                for name in fixture.CONSTRUCTOR_KERNELS}
                outers = {name: folder / ('outer-' + name + '.hepta') for name in fixture.OUTER_KERNELS}
                compiler_source = folder / 'selfhost.hepta'
                for path in (types, helpers, compiler_source, *sources.values(),
                             *constructors.values(), *outers.values()):
                    path.write_bytes(('non-executable source ' + path.name).encode())
                original = types.read_bytes()

                def seed(output, *, source):
                    path = output / 'B0.so'; path.write_bytes(b'non-executable seed')
                    receipt = dict(source_sha256=sha256(source).hexdigest(),
                                   artifact_sha256=sha256(path.read_bytes()).hexdigest(),
                                   artifact_bytes=path.stat().st_size)
                    if fault == 'seed':
                        path.write_bytes(b'replaced non-executable seed')
                    return path, receipt

                def compile_stage(output, label, image, raw, **options):
                    path = output / (label + '.image.bin')
                    path.write_bytes(b'non-executable fixed point' if label in ('B1', 'B2')
                                     else b'non-executable image for ' + raw)
                    if fault == 'source' and label == 'function-fixture-types':
                        types.write_bytes(b'different non-executable source')
                    return path, dict(input_sha256=sha256(raw).hexdigest(),
                        source_sha256=sha256(raw).hexdigest(), source_unchanged=True,
                        artifact_sha256=sha256(image.read_bytes()).hexdigest(),
                        produced_sha256=sha256(path.read_bytes()).hexdigest())

                with ExitStack() as stack:
                    for name, value in (('TYPE_SOURCE', types), ('HELPER_SOURCE', helpers), ('SOURCES', sources),
                                        ('CONSTRUCTOR_SOURCES', constructors), ('OUTER_SOURCES', outers)):
                        stack.enter_context(patch.object(fixture, name, value))
                    stack.enter_context(patch('tools.qualify_hia_selfhost.build_seed', new=seed))
                    stack.enter_context(patch('tools.qualify_hia_selfhost.compile_stage', new=compile_stage))
                    if fault:
                        message = ('source changed during compilation' if fault == 'source'
                                   else 'seed image differs from its publication receipt')
                        with self.assertRaisesRegex(ValueError, message):
                            fixture._bootstrap_development(folder)
                        self.assertFalse((folder / 'manifest.json').exists())
                    else:
                        _, manifest, _, _, _ = fixture._bootstrap_development(folder)
                        self.assertEqual(json.loads(manifest.read_bytes())['source_sha256'],
                                         sha256(original).hexdigest())

    def test_fixture_disk_image_drift_refuses_before_or_during_cached_loading(self):
        from types import SimpleNamespace
        from tests import hia_composite_function_fixture as fixture
        # Explicit immutable-image stand-ins model a warm loader cache. They
        # carry hashes only and cannot execute the non-code byte fixtures.
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            rows = fixture.source_rows()
            manifests, images, loaded = {}, {}, {}
            for name, source, schema in rows:
                image = folder / (name + '.bin'); image.write_bytes(('non-code ' + name).encode())
                digest = sha256(image.read_bytes()).hexdigest()
                manifest = folder / (name + '.json')
                manifest.write_text(json.dumps(dict(schema=schema,
                    source_sha256=sha256(source.read_bytes()).hexdigest(), image_path=image.name,
                    image_sha256=digest, compiler_sha256='0' * 64)))
                manifests[name], images[name], loaded[name] = manifest, image, SimpleNamespace(image_sha256=digest)
            bundle = folder / 'bundle.json'
            bundle.write_text(json.dumps(dict(schema=fixture.SCHEMA,
                kernels={name: manifests[name].name for name in KERNELS},
                types_source_sha256=sha256(fixture.TYPE_SOURCE.read_bytes()).hexdigest(),
                helpers_source_sha256=sha256(fixture.HELPER_SOURCE.read_bytes()).hexdigest())))
            constructor = folder / 'constructor.json'
            constructor.write_text(json.dumps(dict(schema=fixture.CONSTRUCTOR_SCHEMA,
                kernels={name: manifests['constructor-' + name].name for name in fixture.CONSTRUCTOR_KERNELS},
                types_source_sha256=sha256(fixture.TYPE_SOURCE.read_bytes()).hexdigest())))
            outer = folder / 'outer.json'
            outer.write_text(json.dumps(dict(schema=fixture.OUTER_SCHEMA,
                kernels={name: manifests['outer-' + name].name for name in fixture.OUTER_KERNELS},
                types_source_sha256=sha256(fixture.TYPE_SOURCE.read_bytes()).hexdigest(),
                helpers_source_sha256=sha256(fixture.HELPER_SOURCE.read_bytes()).hexdigest(),
                function_sources_sha256={name: sha256(SOURCES[name].read_bytes()).hexdigest() for name in KERNELS})))
            paths = tuple(map(str, (bundle, manifests['types'], manifests['helpers'], constructor, outer)))
            originals = {name: path.read_bytes() for name, path in images.items()}
            for changed, when in ((name, when) for name in images for when in ('before', 'during')):
                for name, path in images.items():
                    path.write_bytes(originals[name])
                with self.subTest(image=changed, when=when), ExitStack() as stack:
                    if when == 'before':
                        images[changed].write_bytes(b'changed non-code bytes')
                        stack.enter_context(patch.object(fixture, 'installed_composite_functions', new=absent))
                        message = 'image differs from its manifest'
                    else:
                        stack.enter_context(patch.object(fixture, 'installed_composite_functions',
                            new=lambda path: SimpleNamespace(images={name: loaded[name] for name in KERNELS})))
                        stack.enter_context(patch.object(fixture, 'installed_composite_types',
                            new=lambda path: loaded['types']))
                        stack.enter_context(patch.object(fixture, 'installed_task_helpers',
                            new=lambda path: loaded['helpers']))
                        stack.enter_context(patch.object(fixture, 'installed_composite_constructor',
                            new=lambda path: SimpleNamespace(images={name: loaded['constructor-' + name]
                                for name in fixture.CONSTRUCTOR_KERNELS})))
                        def load_outer(path):
                            images[changed].write_bytes(b'changed non-code bytes')
                            return SimpleNamespace(images={name: loaded['outer-' + name]
                                for name in fixture.OUTER_KERNELS})
                        stack.enter_context(patch.object(fixture, 'installed_composite_outer', new=load_outer))
                        message = 'fixture changed'
                    with self.assertRaisesRegex(ValueError, message):
                        fixture._build_fixture('DEVELOPMENT_ONLY', paths)

    def test_fixture_rejects_mixed_or_partial_provenance_before_build(self):
        from tests.hia_composite_function_fixture import (
            COLD_KEYS, DEVELOPMENT_KEYS, composite_function_fixture, configuration)
        development = dict(zip(DEVELOPMENT_KEYS,
            ('functions.json', 'types.json', 'helpers.json', 'constructor.json', 'outer.json')))
        invalid = [dict(list(development.items())[index] for index in range(5) if mask & (1 << index))
                   for mask in range(1, 31)]
        invalid += [{**development, key: 'cold.json'} for key in COLD_KEYS]
        invalid += [{COLD_KEYS[0]: 'first.json', COLD_KEYS[1]: 'second.json'}]
        for selected in invalid:
            with self.subTest(selected=selected), patch.dict(os.environ,
                    {**dict.fromkeys((*COLD_KEYS, *DEVELOPMENT_KEYS), ''), **selected}), \
                    patch('tests.hia_composite_function_fixture._build_fixture', new=absent):
                with self.assertRaises(ValueError):
                    composite_function_fixture()
        self.assertEqual(configuration({}), ('BOOTSTRAP_DEVELOPMENT_ONLY', ()))
        self.assertEqual(configuration(development)[0], 'DEVELOPMENT_ONLY')
        self.assertEqual(configuration(dict.fromkeys(COLD_KEYS, 'cold.json'))[0],
                         'MATCHING_SOURCE_COLD_BUILD')

    def test_failed_build_raw_evidence_and_cleanup_never_replace_original_failure(self):
        from tests import hia_composite_function_fixture as fixture
        # No image is executed: these are explicit partial-build custody
        # controls, with an injected failure before any manifest is admitted.
        for mode in ('capture', 'capture-fails', 'cleanup-fails'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                evidence = Path(directory) / 'evidence'
                original = RuntimeError('original incomplete compiler build')
                temporary = []
                def failed(folder):
                    temporary.append(folder)
                    artifact = folder / 'partial-original.bin'
                    artifact.write_bytes(b'explicit non-code failed-build control')
                    artifact.chmod(0o600)
                    raise original
                stack.enter_context(patch.object(fixture, '_bootstrap_development', new=failed))
                if mode == 'capture-fails':
                    def capture_failed(*args):
                        raise OSError('injected evidence copy failure')
                    stack.enter_context(patch.object(fixture, '_copy_build_evidence', new=capture_failed))
                if mode == 'cleanup-fails':
                    cleanup = tempfile.TemporaryDirectory.cleanup
                    def cleanup_failed(instance):
                        cleanup(instance)
                        raise OSError('injected cleanup failure after real removal')
                    stack.enter_context(patch.object(tempfile.TemporaryDirectory, 'cleanup', new=cleanup_failed))
                try:
                    fixture._build_fixture('BOOTSTRAP_DEVELOPMENT_ONLY', (),
                                           evidence_destination=str(evidence))
                except RuntimeError as held:
                    self.assertIs(held, original)
                else:
                    self.fail('failed compiler build published a fixture')
                self.assertEqual(len(temporary), 1)
                self.assertFalse(temporary[0].exists())
                self.assertFalse((evidence / 'custody.json').exists())
                if mode == 'capture-fails':
                    self.assertFalse((evidence / 'failure-custody.json').exists())
                    self.assertIn('failure evidence capture', original.__notes__[0])
                else:
                    value = json.loads((evidence / 'failure-custody.json').read_bytes())
                    self.assertEqual(value['status'], 'BUILD_FAILED_RAW_ONLY')
                    self.assertFalse(value['fixture_usable'])
                    self.assertFalse(value['matching_source_cold_build_qualified'])
                    self.assertEqual(value['files'][0]['mode'], 0o600)
                    self.assertEqual((evidence / value['files'][0]['path']).read_bytes(),
                                     b'explicit non-code failed-build control')
                if mode == 'cleanup-fails':
                    self.assertIn('temporary build cleanup', original.__notes__[0])

    def test_warm_fixture_cannot_silently_discard_changed_evidence_destination(self):
        from types import SimpleNamespace
        from tests import hia_composite_function_fixture as fixture
        cached = SimpleNamespace(evidence_destination='', check_custody=lambda: None)
        with patch.dict(fixture._FIXTURES, {('BOOTSTRAP_DEVELOPMENT_ONLY', ()): cached}, clear=True), \
                patch.dict(os.environ, dict.fromkeys((*fixture.DEVELOPMENT_KEYS, *fixture.COLD_KEYS,
                                                      fixture.EVIDENCE_KEY), '')), \
                patch.object(fixture, '_build_fixture', new=absent):
            self.assertIs(fixture.composite_function_fixture(), cached)
            with patch.dict(os.environ, {fixture.EVIDENCE_KEY: 'new-evidence-after-build'}):
                with self.assertRaisesRegex(ValueError, 'evidence destination changed'):
                    fixture.composite_function_fixture()

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
        from tests.hia_composite_function_fixture import composite_function_fixture
        fixture = composite_function_fixture()
        cls.manifest = fixture.manifest
        cls.type_manifest = fixture.type_manifest
        cls.helper_manifest = fixture.helper_manifest
        cls.fixture_scope = fixture.scope
        cls.bundle = fixture.bundle
        cls.env = fixture.environment
        cls.reference_env = fixture.reference_environment

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

    def test_real_sdist_to_installed_wheel_and_each_source_or_image_custody_refusal(self):
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES
        resource_names = (tuple('docs/' + n for n in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES
        for name in KERNELS:
            self.assertIn('examples/hia_bootstrap/composite_function_' + name + '.hepta', resource_names)
        with tempfile.TemporaryDirectory(prefix='hia-function-wheel-') as directory:
            folder = Path(directory)
            source = folder / 'source'; source.mkdir()
            shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
            for name in (*resource_names, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
                target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            sdists, wheels, installed = folder / 'sdist', folder / 'wheels', folder / 'installed'
            run = subprocess.run([sys.executable, '-B', 'setup.py', 'sdist', '--dist-dir', str(sdists)],
                cwd=source, capture_output=True, timeout=120,
                env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            archive, = sdists.glob('*.tar.gz')
            with tarfile.open(archive) as package:
                prefix = package.getnames()[0].split('/')[0] + '/'
                for name in resource_names:
                    self.assertEqual(package.extractfile(prefix + name).read(), (ROOT / name).read_bytes())
            for command in ([sys.executable, '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
                             '--wheel-dir', str(wheels), str(archive)],):
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
                matches = list(installed.rglob('composite_function_' + name + '.hepta'))
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
