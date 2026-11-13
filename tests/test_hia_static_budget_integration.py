"""Installed structural policy and public execution with pinned HIA owners.

Independent reports are obtained before selection. The isolated installed child
forbids authoring imports and every retained structural policy entry. Separate
heap analysis and final serialization remain explicitly foreign continuations.
The fixture admits the current cold compiler or labels the retained compiler
as development; neither a package nor its manifest grants whole qualification.
"""
import ast
from hashlib import sha256
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
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RESOURCE = 'examples/hia_bootstrap/static_budget.hepta'
SELECTOR = 'HEPTA_HIA_STATIC_BUDGET_MANIFEST'
COLD_REPORT = 'HEPTA_HIA_STATIC_BUDGET_COLD_REPORT'
DEVELOPMENT_COMPILER = 'HEPTA_HIA_STATIC_BUDGET_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_STATIC_BUDGET_EVIDENCE'
EXECUTION = 'HEPTA_HIA_PROGRAM_EXECUTION_MANIFEST'


class StaticBudgetIntegrationSourceTests(unittest.TestCase):
    def test_v6_environment_selects_current_cold_and_records_discarded_inputs(self):
        runner = ROOT / 'review-evidence/hia-native-rewrite-20261111/v69/qualification/run_hia_qualification_v6.py'
        tree = ast.parse(runner.read_text())
        selected = [node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == 'qualification_environment'
                    or isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                        and target.id == 'COLD_REPORT_FAMILIES' for target in node.targets)]
        namespace = {'os': os, 'sha256': sha256}
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(runner), 'exec'), namespace)
        inherited = {COLD_REPORT: '/old/cold', SELECTOR: '/old/image',
                     DEVELOPMENT_COMPILER: '/old/compiler', 'UNCHANGED': 'value'}
        environment, observation = namespace['qualification_environment'](inherited, Path('/new/cold'))
        self.assertEqual(environment[COLD_REPORT], '/new/cold')
        self.assertNotIn(SELECTOR, environment)
        self.assertNotIn(DEVELOPMENT_COMPILER, environment)
        self.assertEqual(environment['UNCHANGED'], 'value')
        for category, name in (('cold_report', COLD_REPORT), ('production', SELECTOR),
                               ('development', DEVELOPMENT_COMPILER)):
            self.assertEqual(observation['discarded'][category][name]['value_sha256'],
                             sha256(os.fsencode(inherited[name])).hexdigest())
        self.assertIs(observation['inherited_environment_claimed_unchanged'], False)
        self.assertEqual(inherited[COLD_REPORT], '/old/cold')

    def test_resource_release_worker_checker_and_transitive_source_custody(self):
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from hepta.hia_native_helpers import HELPERS
        from hepta.hia_checker_identity import CORE_SOURCE_FILES, NATIVE_OWNERS
        from tools.hia_selfhost_contract import SOURCE_FILES, validate_contract
        from tools.hia_release import BOOTSTRAP_FILES
        self.assertIn(RESOURCE, NATIVE_SOURCE_FILES)
        self.assertIn('include ' + RESOURCE, (ROOT / 'MANIFEST.in').read_text().splitlines())
        self.assertIn(RESOURCE, SOURCE_FILES)
        self.assertIn(RESOURCE, BOOTSTRAP_FILES)
        self.assertEqual(HELPERS[SELECTOR], ('hia_static_budget_native', 'NativeStaticBudget'))
        self.assertEqual(NATIVE_OWNERS[SELECTOR], ('hia_static_budget_native', 'installed_static_budget'))
        self.assertTrue({'hia_static_budget.py', 'hia_static_budget_native.py',
                         'hia_heap_bound.py'} <= set(CORE_SOURCE_FILES))
        contract = validate_contract()
        required = {RESOURCE, 'hepta/hia_static_budget.py', 'hepta/hia_static_budget_native.py',
                    'hepta/hia_heap_bound.py', 'hepta/hia_native_value_graph.py',
                    'tools/hia_native_value_graph.py', 'tools/hia_native_bigints.py',
                    'tools/hia_heap_bound_graphs.py', 'tools/generate_hia_static_budget.py',
                    'tests/test_hia_static_budget_native.py',
                    'tests/test_hia_static_budget_integration.py',
                    'tests/test_hia_native_bigints.py', 'tests/test_hia_heap_graphs_native.py',
                    'tests/test_hia_native_binary_graph.py', 'docs/HIA_STATIC_BUDGET_NATIVE.md'}
        self.assertTrue(required <= set(contract['source_identity']['files']))
        owner = contract['native_static_budget']
        for name in ('default_changed', 'old_host_owners_removed', 'whole_native_delivery_qualified'):
            self.assertIs(owner[name], False)

    def test_component_and_installed_cold_conflicts_refuse_before_input_io(self):
        from tests.test_hia_static_budget_native import StaticBudgetNativeTests
        with patch.dict(os.environ, {COLD_REPORT: '/unread-cold',
                                    DEVELOPMENT_COMPILER: '/unread-development'}), \
                patch.object(Path, 'read_bytes', side_effect=AssertionError('read before conflict')):
            for fixture in (StaticBudgetNativeTests, InstalledStaticBudgetTests):
                with self.subTest(fixture=fixture.__name__), self.assertRaisesRegex(ValueError, 'mutually exclusive'):
                    fixture.setUpClass()


CHILD = r'''
import sys
sys.path.insert(0, sys.argv[1])
import importlib.abc
import json
from pathlib import Path
from hashlib import sha256

class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in ('tools', 'tests'):
            raise AssertionError('installed budget imported authoring or test code')
sys.meta_path.insert(0, NoAuthoring())

from hepta import hia_static_budget as budget
from hepta import hia_program_runtime as runtime
from hepta import hia_static_budget_native as structural
from hepta import hia_program_execution_native as execution
from hepta.hia_native_helpers import native_helpers_scope
from hepta.hia_checker_identity import checker_native_selection

def absent(*args, **kwargs):
    raise AssertionError('installed path reached retained structural or VM policy')
for name in ('_reference_audit_resource_profile', '_reference_qualify_vm_call_depth',
             '_reference_analyze_static_budget', '_reference_qualify_bounded_resources',
             '_bound_function', '_limit', '_successors'):
    assert hasattr(budget, name), name
    setattr(budget, name, absent)
runtime._Machine = absent
installed = Path(sys.argv[1]).resolve()
for path in (budget.__file__, runtime.__file__, structural.SOURCE, execution.SOURCE):
    assert Path(path).resolve().is_relative_to(installed), path
bundle, digest, mode = sys.argv[2:5]
entries = {structural.SELECTOR: 0, execution.SELECTOR: 0}

if mode == 'drift':
    try:
        with native_helpers_scope(bundle, digest):
            raise AssertionError('changed installed static source was admitted')
    except ValueError as exc:
        assert str(exc) == 'native helper source identity mismatch', str(exc)
        print(json.dumps({'refused': str(exc), 'entries': entries}, sort_keys=True))
elif mode == 'worker':
    import runpy
    sys.argv = ['hia-agent-worker', '--installation-manifest',
                '--native-helpers-manifest', bundle,
                '--expected-native-helpers-sha256', digest]
    runpy.run_module('hepta.hia_agent_worker', run_name='__main__')
else:
    cases = json.loads(Path(sys.argv[5]).read_bytes())
    with native_helpers_scope(bundle, digest) as binding:
        for module, loader in ((structural, structural.installed_static_budget),
                               (execution, execution.installed_program_execution)):
            native = loader(binding.selections[module.SELECTOR])
            assert native in binding.images.values()
            old = native._entry
            def counted(*args, selector=module.SELECTOR, entry=old):
                entries[selector] += 1
                return entry(*args)
            native._entry = counted
        reports = []
        for case in cases:
            try:
                if case['entry'] == 'execute_program':
                    result = runtime.execute_program(case['program'], case['function'],
                                                     case['arguments'], **case['limits'])
                else:
                    result = getattr(budget, case['entry'])(case['program'], **case['limits'])
                reports.append({'returned': result})
            except Exception as exc:
                row = {'type': type(exc).__name__, 'message': str(exc),
                       'code': getattr(exc, 'code', None)}
                if hasattr(exc, 'report'):
                    row['report'] = exc.report
                reports.append(row)
        assert all(value > 0 for value in entries.values()), entries
        identity = checker_native_selection()
        assert not any(name.split('.')[0] in ('tools', 'tests') for name in sys.modules)
        binding.check()
        print(json.dumps({'reports': reports, 'native_entries': entries,
            'sources': {module.SELECTOR: {'path': str(module.SOURCE),
                       'sha256': sha256(module.SOURCE.read_bytes()).hexdigest()}
                       for module in (structural, execution)},
            'helpers_sha256': binding.sha256,
            'checker': {key: identity[key] for key in entries}}, sort_keys=True))
'''


class InstalledStaticBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold, development = os.environ.get(COLD_REPORT), os.environ.get(DEVELOPMENT_COMPILER)
        if cold and development:
            raise ValueError('cold and retained development installation fixtures are mutually exclusive')
        if not cold and not development:
            raise unittest.SkipTest('an explicit cold report or retained development compiler is required')
        from tools.build_hia_json_preflight import build, admit_cold_build, current_sources
        from tools.qualify_hia_selfhost import compile_stage
        from hepta.hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES
        from hepta.hia_native_helpers import SCHEMA, TARGET, ABI
        cls.cold_bytes = None
        if cold:
            cls.cold_path = Path(cold)
            cls.cold_bytes = cls.cold_path.read_bytes()
            report = json.loads(cls.cold_bytes)
            nested = json.loads(Path(report['nested_report']).read_bytes())
            cls.compiler = Path(nested['generations'][-1]['produced_image'])
            cls.compiler_bytes = cls.compiler.read_bytes()
            cls.source_identity = admit_cold_build(cls.compiler_bytes, cls.cold_bytes)
            cls.scope = 'CURRENT_SOURCE_COLD_INSTALLED_STRUCTURAL_AND_EXECUTION_COMPONENTS'
        else:
            cls.compiler = Path(development)
            cls.compiler_bytes = cls.compiler.read_bytes()
            cls.source_identity = current_sources()
            cls.scope = 'PREDECESSOR_COMPILER_DEVELOPMENT_INSTALLED_STRUCTURAL_AND_EXECUTION_COMPONENTS'
        evidence = os.environ.get(EVIDENCE)
        cls.folder = Path(evidence) / 'installed' if evidence else Path(tempfile.mkdtemp(prefix='hia-budget-installed-'))
        cls.folder.mkdir(parents=True, exist_ok=not bool(evidence))
        cls.manifests, cls.held, cls.image_sha = {}, {}, {}
        for candidate, stem, selector in (('static-budget', 'static_budget', SELECTOR),
                                          ('program-execution', 'program_execution', EXECUTION)):
            target = cls.folder / candidate
            raw = (ROOT / ('examples/hia_bootstrap/' + stem + '.hepta')).read_bytes()
            if cold:
                manifest = build(target, cls.compiler, cls.cold_path, candidate=candidate)
            else:
                target.mkdir()
                image, receipt = compile_stage(target, candidate, cls.compiler, raw)
                value = {'schema': 'hepta.hia.' + candidate + '-native.v1',
                         'source_sha256': sha256(raw).hexdigest(), 'image_path': image.name,
                         'image_sha256': sha256(image.read_bytes()).hexdigest(),
                         'compiler_sha256': sha256(cls.compiler_bytes).hexdigest()}
                manifest = target / 'manifest.json'
                manifest.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
                (target / 'compile-receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
            cls.manifests[selector] = manifest
            cls.held[manifest] = manifest.read_bytes()
            value = json.loads(cls.held[manifest])
            image = manifest.parent / value['image_path']
            cls.held[image] = image.read_bytes()
            cls.image_sha[selector] = sha256(cls.held[image]).hexdigest()
        cls.source = cls.folder / 'source'
        cls.source.mkdir()
        shutil.copytree(ROOT / 'hepta', cls.source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
        resources = tuple('docs/' + name for name in DISCOVERY_FILES) + NATIVE_SOURCE_FILES + SOURCE_BUILD_FILES + COMPILER_BUILD_FILES + PUBLICATION_BUILD_FILES + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES + ENTRY_BUILD_FILES
        cls.resources = {name: (ROOT / name).read_bytes() for name in resources}
        for name in (*resources, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
            target = cls.source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())

        def package(label, arguments):
            log = cls.folder / (label + '.log')
            with log.open('xb') as output:
                result = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=cls.source,
                    env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}, stdout=output,
                    stderr=subprocess.STDOUT, timeout=180)
            if result.returncode:
                raise AssertionError(label + ': ' + log.read_text())
        package('sdist', ['setup.py', 'sdist', '--dist-dir', cls.folder / 'sdist'])
        archive, = (cls.folder / 'sdist').glob('*.tar.gz')
        with tarfile.open(archive) as source_archive:
            prefix = source_archive.getnames()[0].split('/')[0] + '/'
            for name, raw in cls.resources.items():
                assert source_archive.extractfile(prefix + name).read() == raw, name
        package('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
                          '--wheel-dir', cls.folder / 'wheels', archive])
        cls.wheel, = (cls.folder / 'wheels').glob('*.whl')
        cls.wheel_bytes = cls.wheel.read_bytes()
        with zipfile.ZipFile(cls.wheel) as wheel:
            for name, raw in cls.resources.items():
                assert wheel.read('hepta/_data/' + name) == raw, name
        cls.installed = cls.folder / 'installed'
        package('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--target', cls.installed, cls.wheel])
        cls.installed_source = cls.installed / 'hepta/_data' / RESOURCE
        assert cls.installed_source.read_bytes() == cls.resources[RESOURCE]
        cls.bundle = cls.folder / 'worker-helpers.json'
        cls.bundle.write_text(json.dumps({'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [
            {'selector': selector, 'manifest_path': str(manifest),
             'manifest_sha256': sha256(cls.held[manifest]).hexdigest()}
            for selector, manifest in cls.manifests.items()]}, sort_keys=True) + '\n')
        cls.bundle_bytes = cls.bundle.read_bytes()
        cls.bundle_sha = sha256(cls.bundle_bytes).hexdigest()

        from hepta import hia_static_budget as budget
        from hepta import hia_program_runtime as runtime
        from tests.test_hia_static_budget_native import constant, repeated_calls, policy
        owned = repeated_calls(2, 3)
        owned['schema'] = 'hepta.hia.program.v8'
        owned['exports'] = ['f0002']
        cls.cases = [
            {'entry': 'qualify_vm_call_depth', 'program': constant(), 'limits': {'max_call_depth': 4}},
            {'entry': 'analyze_static_budget', 'program': constant(8), 'limits': {}},
            {'entry': 'analyze_static_budget', 'program': repeated_calls(70, 8), 'limits': {}},
            {'entry': 'qualify_bounded_resources', 'program': constant(8), 'limits': {'limits': policy()}},
            {'entry': 'analyze_static_budget', 'program': constant(), 'limits': {'max_vm_ticks': 0}},
            {'entry': 'execute_program', 'program': owned, 'function': 'f0002', 'arguments': [],
             'limits': {'bounded_resource_limits': policy()}},
            {'entry': 'execute_program', 'program': owned, 'function': 'f0002', 'arguments': [],
             'limits': {'bounded_resource_limits': policy(), 'allocation_fail_at': 2}},
        ]
        environment = {name: value for name, value in os.environ.items()
                       if not (name.startswith('HEPTA_HIA_') and name.endswith('_MANIFEST'))}
        cls.expected = []
        with patch.dict(os.environ, environment, clear=True):
            for case in cls.cases:
                try:
                    if case['entry'] == 'execute_program':
                        result = runtime.execute_program(case['program'], case['function'],
                                                         case['arguments'], **case['limits'])
                    else:
                        result = getattr(budget, case['entry'])(case['program'], **case['limits'])
                    cls.expected.append({'returned': result})
                except Exception as exc:
                    row = {'type': type(exc).__name__, 'message': str(exc), 'code': getattr(exc, 'code', None)}
                    if hasattr(exc, 'report'):
                        row['report'] = exc.report
                    cls.expected.append(row)
        cls.inputs = cls.folder / 'cases.json'
        cls.inputs.write_text(json.dumps(cls.cases, sort_keys=True) + '\n')
        (cls.folder / 'reference.json').write_text(json.dumps(cls.expected, sort_keys=True) + '\n')
        (cls.folder / 'installed-child.py').write_text(CHILD)
        (cls.folder / 'source-before.json').write_text(json.dumps(cls.source_identity, sort_keys=True, indent=2) + '\n')
        cls.child_cwd = cls.folder / 'unrelated-working-directory'
        cls.child_cwd.mkdir()

    @classmethod
    def tearDownClass(cls):
        from tools.build_hia_json_preflight import current_sources
        stable = (current_sources() == cls.source_identity
                  and cls.compiler.read_bytes() == cls.compiler_bytes
                  and cls.wheel.read_bytes() == cls.wheel_bytes
                  and cls.bundle.read_bytes() == cls.bundle_bytes
                  and all(path.read_bytes() == raw for path, raw in cls.held.items())
                  and all((ROOT / name).read_bytes() == raw for name, raw in cls.resources.items())
                  and cls.installed_source.read_bytes() == cls.resources[RESOURCE])
        if cls.cold_bytes is not None:
            stable = stable and cls.cold_path.read_bytes() == cls.cold_bytes
        (cls.folder / 'observations.json').write_text(json.dumps({
            'scope': cls.scope, 'inputs_unchanged': stable,
            'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(),
            'image_sha256': cls.image_sha, 'whole_native_delivery_qualified': False},
            sort_keys=True, indent=2) + '\n')
        if not stable:
            raise AssertionError('installed structural controls changed frozen inputs')

    def child(self, mode):
        environment = {key: value for key, value in os.environ.items()
                       if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        result = subprocess.run([sys.executable, '-I', '-B', '-c', CHILD, str(self.installed),
            str(self.bundle), self.bundle_sha, mode, str(self.inputs)], cwd=self.child_cwd,
            env=environment, capture_output=True, timeout=120)
        (self.folder / (mode + '.stdout')).write_bytes(result.stdout)
        (self.folder / (mode + '.stderr')).write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(result.stderr)
        return json.loads(result.stdout)

    def test_installed_public_policy_and_bounded_vm_use_both_pinned_images(self):
        value = self.child('execute')
        self.assertEqual(value['reports'], self.expected)
        self.assertEqual(value['helpers_sha256'], self.bundle_sha)
        for selector, stem in ((SELECTOR, 'static_budget'), (EXECUTION, 'program_execution')):
            self.assertGreater(value['native_entries'][selector], 0)
            source = 'examples/hia_bootstrap/' + stem + '.hepta'
            self.assertEqual(Path(value['sources'][selector]['path']), self.installed / 'hepta/_data' / source)
            self.assertEqual(value['sources'][selector]['sha256'], sha256(self.resources[source]).hexdigest())
            self.assertEqual(value['checker'][selector]['images']['image']['image_sha256'], self.image_sha[selector])

    def test_changed_installed_static_source_refuses_before_any_execution(self):
        self.installed_source.write_bytes(self.resources[RESOURCE] + b'\n# controlled static source drift\n')
        try:
            value = self.child('drift')
            self.assertEqual(value['refused'], 'native helper source identity mismatch')
            self.assertEqual(value['entries'], {SELECTOR: 0, EXECUTION: 0})
        finally:
            self.installed_source.write_bytes(self.resources[RESOURCE])

    def test_fresh_worker_installation_receipt_binds_the_same_bundle(self):
        receipt = self.child('worker')
        self.assertEqual(receipt['native_helpers_sha256'], self.bundle_sha)
        self.assertRegex(receipt['worker_sha256'], '^[0-9a-f]{64}$')


if __name__ == '__main__':
    unittest.main()
