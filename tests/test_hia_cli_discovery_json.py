"""Discovery JSON source, strict custody, original observations and real wheel."""
from __future__ import annotations

import ast
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
from tools import hia_cli_discovery_controls as controls
from tools import hia_cli_discovery_custody as custody
from tools import qualify_hia_cli_discovery_json as qualifier
from hepta import hia_cli_discovery_json_native as runtime

R5_SOURCE_SHA256 = '8e14590337e501c2315befe8dea1df9f6e7b02dbda28ca82d54b2f20959ed543'
R5_CASES_SHA256 = '685058650030c887a6983540a4a98e19d61c27be778559baeaa7ee99fd2aaa84'
COLD_REPORT = 'HEPTA_HIA_CLI_DISCOVERY_JSON_COLD_REPORT'
ROLES = ('DISCOVERY_FILES', 'NATIVE_SOURCE_FILES', 'SOURCE_BUILD_FILES', 'COMPILER_BUILD_FILES',
         'PUBLICATION_BUILD_FILES', 'BACKEND_BUILD_FILES', 'EMITTER_BUILD_FILES',
         'BYTE_WRAPPER_BUILD_FILES', 'MACHINE_OBJECT_BUILD_FILES', 'EXECUTION_OBSERVATION_BUILD_FILES',
         'CONTINUATION_BUILD_FILES')


class CliDiscoveryJsonSourceTests(unittest.TestCase):
    def test_portable_generation_is_exact_frozen_r5_with_original_limits(self):
        from tools import generate_hia_cli_discovery_json as generator
        raw, report = generator.generation()
        self.assertEqual(raw, runtime.SOURCE.read_bytes())
        self.assertEqual(sha256(raw).hexdigest(), R5_SOURCE_SHA256)
        self.assertEqual(report['counts'], {'functions': 39, 'blocks': 256, 'operations': 5476, 'max_ssa': 540})
        self.assertEqual(report['table_sha256'], '6acd153f66c909c9f39438d517e7a27abf0cb3e5b81b5b445f5123fbed633d07')
        self.assertEqual(report['final_json_documents_stored'], 0)
        self.assertEqual(report['catalog_digests_stored'], 0)
        self.assertNotIn('/workspace/', (ROOT / 'tools/generate_hia_cli_discovery_json.py').read_text())

    def test_structured_metadata_contains_no_final_json_or_catalog_digest(self):
        from tools import generate_hia_cli_discovery_json as generator
        table, _cap, _cat = generator.structured_table()
        seed = table.encode()
        self.assertEqual(len(table.nodes), 434)
        self.assertEqual(len(seed), 10851)
        self.assertEqual(len(generator.original.OPCODES), 50)
        self.assertEqual(len(generator.PRIMITIVE_PROFILES), 8)
        for _label, _request, raw in controls.original_oracles():
            value = json.loads(raw)
            self.assertNotIn(raw, seed)
            canonical = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
            self.assertNotIn(canonical, seed)
            if 'catalog_sha256' in value:
                self.assertNotIn(value['catalog_sha256'].encode(), seed)
                self.assertNotIn(bytes.fromhex(value['catalog_sha256']), seed)

    def test_all_original_61_frames_and_six_vm_labels_are_retained(self):
        path = ROOT / 'tests/fixtures/hia_cli_discovery_r5_cases.json'
        self.assertEqual(sha256(path.read_bytes()).hexdigest(), R5_CASES_SHA256)
        old = json.loads(path.read_bytes())
        cases = controls.cases(controls.original_oracles())
        self.assertEqual(len(cases), 61)
        self.assertEqual([row[0] for row in cases], [row['label'] for row in old['rows']])
        for case, row in zip(cases, old['rows']):
            with self.subTest(label=row['label']):
                label, request, extent, work, status, result, _guard_all, fill = case
                self.assertEqual((request.hex(), extent, work, fill),
                    (row['request_hex'], row['output_extent'], row['workspace_extent'], row['fill']))
                self.assertEqual(row['result'], len(result) if result is not None else status)
        self.assertEqual(controls.VM_LABELS, ('capabilities-exact', 'catalog-v1-exact', 'catalog-v8-exact',
            'catalog-v8-short-0', 'unknown-schema-8', 'short-work-131071'))

    def test_original_cli_parser_outputs_and_both_old_assets_are_unchanged(self):
        # R20's other CLI continuation revision is not part of 0daf. Retain
        # the actual integration baseline in full, permitting only the exact
        # five opt-in hook edits recorded here; no original test is altered.
        path = ROOT / 'tests/fixtures/hia_cli_discovery_0daf_baseline.json'
        self.assertEqual(sha256(path.read_bytes()).hexdigest(),
                         '2d6e4aed65731fd39b200f1ac94ae0e60e0e557e842699a9ce6db43186882d43')
        baseline = json.loads(path.read_bytes())
        self.assertEqual(baseline['base_commit'], '0daf86d0e5b8a8c13c15185d2b2bf553fbb81310')
        for name, record in baseline['files'].items():
            with self.subTest(path=name):
                actual = (ROOT / name).read_text()
                for edit in reversed(record['edits']):
                    self.assertEqual(actual.count(edit['new']), 1)
                    actual = actual.replace(edit['new'], edit['old'])
                self.assertEqual(sha256(actual.encode()).hexdigest(), record['baseline_sha256'])

    def test_unqualified_cold_rejects_before_directory_or_compiler(self):
        from tools import build_hia_cli_discovery_json as builder
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cold, compiler = root / 'cold.json', root / 'image.bin'
            cold.write_text('{}')
            compiler.write_bytes(b'not a compiler')
            with patch('tools.qualify_hia_selfhost.compile_stage', side_effect=AssertionError('compile entered')):
                with self.assertRaises(ValueError):
                    builder.build(root / 'output', compiler, cold)
                with self.assertRaises(ValueError):
                    qualifier.prepare_fixture(root / 'fixture', cold)
            self.assertFalse((root / 'output').exists())
            self.assertFalse((root / 'fixture').exists())

    def test_production_fixture_rejects_development_scope_and_mixed_selection(self):
        from tools.build_hia_cli_discovery_json import DEVELOPMENT_SCOPE
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'build.json').write_text(json.dumps({'schema': 'hepta.hia.cli-discovery-json-build.v1',
                'status': 'NATIVE_CANDIDATE_BUILT', 'scope': DEVELOPMENT_SCOPE, 'matching_cold': False}))
            (root / 'manifest.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'development or stale'):
                qualifier._built(root, {})
            path = root / 'FIXTURE.json'
            path.write_text(json.dumps({'schema': qualifier.FIXTURE_SCHEMA,
                                      'status': 'DEVELOPMENT_ONLY', 'matching_cold': False}))
            with self.assertRaises(ValueError):
                qualifier.admit_fixture(path)
            with patch.dict(os.environ, {qualifier.COLD_FIXTURE: str(path), qualifier.DEVELOPMENT: str(path)}):
                with self.assertRaisesRegex(ValueError, 'exactly one'):
                    CliDiscoveryJsonNativeTests.setUpClass()
            for cold, development in (('fixture', ''), ('', 'manifest'), ('', ''), ('', None), (None, '')):
                environment = {qualifier.EVIDENCE: str(root / 'outside')}
                if cold is not None:
                    environment[qualifier.COLD_FIXTURE] = cold
                if development is not None:
                    environment[qualifier.DEVELOPMENT] = development
                with self.subTest(cold=cold, development=development), patch.dict(os.environ, environment, clear=True):
                    with patch.object(qualifier, 'admit_fixture', side_effect=AssertionError('fixture provider entered')):
                        with self.assertRaisesRegex(ValueError, 'exactly one'):
                            CliDiscoveryJsonNativeTests.setUpClass()
            for selected in ({COLD_REPORT: ''},
                    {COLD_REPORT: 'cold', qualifier.COLD_FIXTURE: 'fixture'},
                    {COLD_REPORT: 'cold', qualifier.DEVELOPMENT: 'development'}):
                with patch.dict(os.environ, {qualifier.EVIDENCE: str(root / 'outside'), **selected}, clear=True):
                    with patch.object(qualifier, 'prepare_fixture', side_effect=AssertionError('fixture compiler entered')):
                        with self.assertRaisesRegex(ValueError, 'exactly one'):
                            CliDiscoveryJsonNativeTests.setUpClass()

    def test_current_source_closure_includes_every_consumed_owner_file(self):
        from tools.hia_selfhost_contract import SOURCE_FILES, file_digests
        # The original contract also enumerates every hepta/*.py source.
        # Check that real closure, and explicit registration for all other inputs.
        self.assertTrue(set(custody.OWNER_FILES).issubset(file_digests(ROOT)))
        self.assertTrue({name for name in custody.OWNER_FILES if not name.startswith('hepta/')}
                        .issubset(SOURCE_FILES))
        self.assertEqual(len(custody.OWNER_FILES), len(set(custody.OWNER_FILES)))
        actual = custody.owner_sources()
        custody.require_owner_sources(actual)
        for name in custody.OWNER_FILES:
            bad = dict(actual)
            del bad[name]
            with self.subTest(missing=name), self.assertRaises(ValueError):
                custody.require_owner_sources(bad)

    def test_actual_runtime_resource_is_in_one_role_and_sdist(self):
        from hepta import hia_agent_contract as contract
        values = {name: getattr(contract, name) for name in ROLES}
        self.assertEqual(sum(group.count(runtime.SOURCE_NAME) for group in values.values()), 1)
        self.assertIn(runtime.SOURCE_NAME, contract.NATIVE_SOURCE_FILES)
        self.assertEqual(runtime.SOURCE, ROOT / runtime.SOURCE_NAME)
        self.assertEqual((ROOT / 'MANIFEST.in').read_text().splitlines().count('include ' + runtime.SOURCE_NAME), 1)

    def test_strict_manifest_refuses_bad_metadata_before_mapping(self):
        source = runtime.SOURCE.read_bytes()
        valid = {'schema': runtime.SCHEMA, 'source_sha256': sha256(source).hexdigest(),
                 'image_path': 'image.bin', 'image_sha256': '1' * 64, 'compiler_sha256': '2' * 64}
        mutations = [{'unknown': 1}, {'schema': 'wrong'}, {'source_sha256': '0' * 64},
                     {'image_path': '../image.bin'}, {'image_path': '/tmp/image.bin'},
                     {'image_path': ''}, {'image_path': '..'}, {'image_sha256': True},
                     {'compiler_sha256': 'X' * 64}]
        for mutation in mutations:
            value = {**valid, **mutation}
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                runtime._manifest(json.dumps(value).encode(), sha256(source).hexdigest())
        with self.assertRaises(ValueError):
            runtime._manifest(b'{"schema":1,"schema":2}', sha256(source).hexdigest())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'manifest.json'
            path.write_bytes(b' ' * 16385)
            with patch.object(runtime, '_captured', side_effect=AssertionError('mapping entered')):
                with self.assertRaises(ValueError):
                    runtime.installed_cli_discovery_json(path)

    def test_result_admission_rejects_every_incomplete_or_exceptional_outcome(self):
        group = 'native'
        ids = list(qualifier.GROUPS[group])
        valid = {'schema': 'hepta.hia.cli-discovery-json-test-observations.v1',
                 'scope': 'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY', 'status': 'PASS', 'group': group,
                 'request_sha256': 'a' * 64, 'loaded_ids': ids, 'started_ids': ids, 'stopped_ids': ids,
                 'loaded': 1, 'tests_run': 1, 'source_and_inputs_unchanged': True,
                 **{key: [] for key in qualifier.ANOMALIES}}
        qualifier.admit_result(valid, group, 'a' * 64)
        mutations = [{key: ['observed']} for key in qualifier.ANOMALIES]
        mutations += [{key: []} for key in ('loaded_ids', 'started_ids', 'stopped_ids')]
        mutations += [{'loaded': True}, {'tests_run': True}, {'tests_run': 0},
                      {'source_and_inputs_unchanged': False}, {'request_sha256': 'b' * 64}]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                qualifier.admit_result({**valid, **mutation}, group, 'a' * 64)

    def test_original_budgets_and_four_native_ids_are_explicit(self):
        self.assertEqual((qualifier.SECONDS, qualifier.CLEANUP_SECONDS), (180, 3))
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(CliDiscoveryJsonNativeTests)
        self.assertEqual([test.id() for test in suite], list(qualifier.EXPECTED_IDS))
        body = (ROOT / 'tools/hia_cli_discovery_controls.py').read_text()
        self.assertIn('_Machine(program, 10000000, 8 << 20, None, 128)', body)
        self.assertIn('capture_output=True, timeout=20)', body)
        parser = ast.parse((ROOT / 'tools/qualify_hia_cli_discovery_json.py').read_text())
        options = {arg.value for node in ast.walk(parser) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Attribute) and node.func.attr == 'add_argument'
                   for arg in node.args if isinstance(arg, ast.Constant)}
        self.assertNotIn('--development', options)
        self.assertNotIn('--development-compiler', options)

    def test_input_binding_mode_and_bytes_drift_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'input.bin'
            path.write_bytes(b'fixed')
            original = custody.binding(path)
            custody.check_bindings([original])
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                custody.check_bindings([original])
            path.write_bytes(b'fixed')
            path.chmod(original['mode'] ^ 0o100)
            with self.assertRaises(ValueError):
                custody.check_bindings([original])
            path.chmod(original['mode'])
            with self.assertRaises(ValueError):
                custody.check_bindings([original, original])
        # Controlled receipt-shape fixture, not an execution or cold observation.
        fields = {'abi_status', 'core_u32', 'forbidden_compiler_modules_loaded', 'image_sha256',
                  'limits', 'loader_operations', 'native_elapsed_ns', 'output_sha256', 'output_unchanged',
                  'result_u64', 'return_encoding', 'source_sha256', 'source_unchanged', 'status',
                  'workspace_header'}
        host = {'artifact_sha256', 'case', 'format', 'input_bytes', 'input_sha256',
                'produced_bytes', 'produced_image', 'produced_sha256', 'runner_sha256', 'wall_elapsed_ns'}
        child = {name: 1 for name in fields}
        receipt = {**child, **{name: 0 for name in host}}
        custody.admit_child_output(receipt, custody.encoded(child), b'')
        for stdout, stderr in ((custody.encoded({**child, 'native_elapsed_ns': 2}), b''),
                (custody.encoded({**child, 'core_u32': True}), b''),
                (custody.encoded(child), b'nonempty'), (b'{}', b'')):
            with self.subTest(stdout=stdout, stderr=stderr), self.assertRaises(ValueError):
                custody.admit_child_output(receipt, stdout, stderr)


class CliDiscoveryJsonNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold = os.environ.get(qualifier.COLD_FIXTURE)
        cold_report = os.environ.get(COLD_REPORT)
        development = os.environ.get(qualifier.DEVELOPMENT)
        selectors = (qualifier.COLD_FIXTURE, COLD_REPORT, qualifier.DEVELOPMENT)
        if (sum(name in os.environ for name in selectors) != 1
                or not (cold or cold_report or development)):
            raise ValueError('exactly one explicit discovery cold or development fixture is required')
        evidence = os.environ.get(qualifier.EVIDENCE)
        if not evidence:
            raise ValueError('explicit discovery evidence outside the source tree is required')
        cls.folder = Path(evidence).resolve()
        if cls.folder.is_relative_to(ROOT):
            raise ValueError('discovery evidence must be outside the source tree')
        if cold_report is not None:
            # Full retained discovery reaches this only after its same-run cold
            # report exists. Each test class owns an exclusive fixture subtree.
            cls.folder = cls.folder / cls.__name__
        cls.folder.mkdir(parents=True, exist_ok=True)
        if cold_report is not None:
            cold = str(qualifier.prepare_fixture(cls.folder / 'cold-fixture', Path(cold_report)))
        cls.cold = cold
        if cold:
            fixture = qualifier.admit_fixture(cold)
            cls.manifest = Path(fixture['build']['manifest'])
            cls.scope = 'MATCHING_SOURCE_COLD_FIXTURE'
        else:
            from tools.build_hia_cli_discovery_json import DEVELOPMENT_SCOPE
            cls.manifest = Path(development).resolve(strict=True)
            report = custody.read_json((cls.manifest.parent / 'build.json').read_bytes())
            custody.require(report.get('scope') == DEVELOPMENT_SCOPE and report.get('matching_cold') is False
                            and report.get('authority') is None, 'explicit development build required')
            custody.check_bindings(report['input_bindings'])
            custody.require(report['owner_sources_before'] == custody.owner_sources() == report['owner_sources_after'],
                            'development owner sources changed')
            cls.scope = 'DEVELOPMENT_ONLY_NOT_COLD'
        value = custody.read_json(cls.manifest.read_bytes())
        cls.image = cls.manifest.parent / value['image_path']
        cls.inputs = [custody.binding(cls.manifest), custody.binding(cls.image)]
        cls.sources = custody.owner_sources()
        cls.owner = runtime.installed_cli_discovery_json(cls.manifest)

    @classmethod
    def guard(cls):
        custody.check_bindings(cls.inputs)
        custody.require(custody.owner_sources() == cls.sources, 'discovery observation source drift')
        if cls.cold:
            qualifier.admit_fixture(cls.cold)

    def tearDown(self):
        self.guard()

    def test_01_all_original_61_native_observations(self):
        result = controls.native_controls(self.folder / 'native', self.image, guard=self.guard)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(len(result['rows']), 61)
        self.assertEqual(result['actual_native_entries'], 61)

    def test_02_all_original_six_vm_full_buffers(self):
        result = controls.vm_controls(self.folder / 'vm', self.folder / 'native', guard=self.guard)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual([row['label'] for row in result['rows']], list(controls.VM_LABELS))

    def test_03_public_byte_api_does_not_call_python_semantic_owners(self):
        from hepta import cli, hia_opcodes
        expected = controls.original_oracles()
        observed = []
        with ExitStack() as stack:
            stack.enter_context(patch.object(cli, 'agent_capabilities', side_effect=AssertionError('old capabilities entered')))
            stack.enter_context(patch.object(hia_opcodes, 'opcode_catalog', side_effect=AssertionError('old catalog entered')))
            stack.enter_context(patch.object(json, 'dumps', side_effect=AssertionError('host JSON constructor entered')))
            for label, request, raw in expected:
                value = self.owner.render(request)
                self.assertEqual(value, raw)
                observed.append({'label': label, 'bytes': len(value), 'sha256': sha256(value).hexdigest()})
            self.assertEqual(self.owner.capabilities_json(), expected[0][2])
            self.assertEqual(self.owner.catalog_json(), expected[-1][2])
            with self.assertRaises(runtime.DiscoveryRefused) as refused:
                self.owner.catalog_json(b'unknown')
            self.assertEqual(refused.exception.status, 0xfffffffd)
        controls.save(self.folder / 'RUNTIME.json', {'status': 'PASS', 'scope': self.scope,
            'actual_calls': 13, 'old_semantic_body_entries': 0, 'host_json_constructor_entries': 0,
            'observations': observed, 'ordinary_cli_replaced': False})

    def test_04_real_portable_wheel_resource_and_fresh_binding(self):
        from hepta import hia_agent_contract as contract
        case = self.folder / 'installed'
        case.mkdir(mode=0o700)
        source, wheels, installed = case / 'source', case / 'wheels', case / 'installed'
        source.mkdir()
        resources = tuple('docs/' + name for name in contract.DISCOVERY_FILES)
        for role in ROLES[1:]:
            resources += getattr(contract, role)
        self.assertEqual(resources.count(runtime.SOURCE_NAME), 1)
        shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        bundle = case / 'bundle'
        bundle.mkdir()
        shutil.copyfile(self.manifest, bundle / 'manifest.json')
        shutil.copyfile(self.image, bundle / self.image.name)
        records = []
        def command(argv, label, *, environment=None):
            completed = subprocess.run(argv, cwd=case, env=environment, capture_output=True, timeout=20)
            (case / (label + '.stdout.raw')).write_bytes(completed.stdout)
            (case / (label + '.stderr.raw')).write_bytes(completed.stderr)
            records.append({'label': label, 'argv': argv, 'returncode': completed.returncode,
                            'stdout_sha256': sha256(completed.stdout).hexdigest(),
                            'stderr_sha256': sha256(completed.stderr).hexdigest()})
            controls.save(case / 'COMMANDS.json', records)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors='replace'))
            return completed
        packaging = os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
        command([packaging, '-B', '-m', 'pip', 'wheel', '--no-cache-dir', '--no-deps', '--no-index',
                 '--no-build-isolation', '--wheel-dir', str(wheels), str(source)], 'wheel-build')
        wheel, = wheels.glob('*.whl')
        with zipfile.ZipFile(wheel) as archive:
            self.assertEqual(archive.read('hepta/_data/' + runtime.SOURCE_NAME), runtime.SOURCE.read_bytes())
            self.assertFalse(any(name.startswith(('tools/', 'examples/')) for name in archive.namelist()))
        command([packaging, '-B', '-m', 'pip', 'install', '--no-cache-dir', '--no-deps', '--no-index',
                 '--target', str(installed), str(wheel)], 'wheel-install')
        expected = {label: sha256(raw).hexdigest() for label, _request, raw in controls.original_oracles()}
        (case / 'EXPECTED.json').write_text(json.dumps(expected, sort_keys=True))
        child = r'''import hashlib,json,os,pathlib,sys
sys.path.insert(0,sys.argv[1])
from hepta import hia_cli_discovery_json_native as n
assert not (pathlib.Path(sys.argv[1])/'pyproject.toml').exists()
assert n.SOURCE==pathlib.Path(sys.argv[1])/'hepta/_data'/n.SOURCE_NAME
manifest=pathlib.Path(sys.argv[2]); expected=json.loads(pathlib.Path(sys.argv[3]).read_bytes())
owner=n.installed_cli_discovery_json(manifest)
from hepta import cli,hia_opcodes
def forbidden(*a,**kw):raise AssertionError('retained JSON policy entered')
cli.agent_capabilities=forbidden;hia_opcodes.opcode_catalog=forbidden
observed={'capabilities':hashlib.sha256(owner.capabilities_json()).hexdigest()}
for version in range(1,9):
 observed['catalog-v'+str(version)]=hashlib.sha256(owner.catalog_json(('hepta.hia.program.v'+str(version)).encode())).hexdigest()
observed['catalog-default']=hashlib.sha256(owner.catalog_json()).hexdigest()
assert observed==expected
source=n.SOURCE.read_bytes(); image=manifest.parent/json.loads(manifest.read_bytes())['image_path']; code=image.read_bytes()
refusals=[]
def refuse(label):
 try:n.installed_cli_discovery_json(manifest)
 except (ValueError,OSError):refusals.append(label)
 else:raise AssertionError(label)
try:
 n.SOURCE.write_bytes(source+b'\n');refuse('changed-package-source')
finally:n.SOURCE.write_bytes(source)
try:
 n.SOURCE.unlink();refuse('missing-package-source-no-checkout-fallback')
finally:n.SOURCE.write_bytes(source)
try:
 image.write_bytes(code[:-1]+bytes([code[-1]^1]));refuse('changed-image-after-warm-load')
finally:image.write_bytes(code)
assert hashlib.sha256(owner.capabilities_json()).hexdigest()==expected['capabilities']
assert n.installed_cli_discovery_json(manifest).image_sha256==hashlib.sha256(code).hexdigest()
assert not any(name=='tools' or name.startswith('tools.') for name in sys.modules)
assert sys.flags.isolated and sys.flags.no_site and os.environ['PATH']==''
print(json.dumps({'status':'PASS','source':str(n.SOURCE),'source_sha256':hashlib.sha256(source).hexdigest(),
 'outputs':observed,'refusals':refusals,'isolated_without_site':True,'empty_PATH':True,
 'old_policy_calls':0,'ordinary_cli_replaced':False,'whole_native_delivery_qualified':False},sort_keys=True))
'''
        script = case / 'installed-observation.py'
        script.write_text(child)
        environment = {key: value for key, value in os.environ.items() if not key.startswith('HEPTA_')}
        environment.update(PATH='', PYTHONPATH='', HOME=str(case / 'empty-home'))
        result = command([sys.executable, '-I', '-S', '-B', str(script), str(installed),
                          str(bundle / 'manifest.json'), str(case / 'EXPECTED.json')],
                         'installed-execution', environment=environment)
        observed = json.loads(result.stdout)
        self.assertEqual(observed['status'], 'PASS')
        self.assertEqual(observed['outputs'], expected)
        self.assertEqual(len(observed['refusals']), 3)
        self.assertEqual(observed['source_sha256'], R5_SOURCE_SHA256)
        controls.save(case / 'REPORT.json', {'status': 'PASS', 'scope': self.scope,
            'wheel_sha256': sha256(wheel.read_bytes()).hexdigest(), 'wheel_bytes': wheel.stat().st_size,
            'observations': observed, 'commands': records})


if __name__ == '__main__':
    unittest.main()
