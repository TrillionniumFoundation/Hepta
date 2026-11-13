"""Cold admission/portable controls and the complete retained direct caller set.

Source controls never mint cold authority. Native methods require the actual
fixture produced by tools.qualify_hia_linux_stdio from the current cold report.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_linux_stdio import PROFILE, PROFILE_SOURCE_FILES, profile_resource_path
from tools import hia_linux_stdio_cold as custody
from tools import build_hia_linux_stdio_cold as builder
from tools import qualify_hia_linux_stdio as qualifier
from tests import hia_linux_stdio_cases as retained

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL = 'tests/fixtures/hia_linux_stdio_public_native_r2.py.txt'


def _tree(raw):
    return ast.parse(raw)


def _function(tree, name):
    matches = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(matches) != 1:
        raise AssertionError('one exact function required: ' + name)
    return matches[0]


def _fields(node):
    if isinstance(node, ast.AST):
        return (type(node).__name__, tuple((name, _fields(value)) for name, value in ast.iter_fields(node)))
    if isinstance(node, list):
        return tuple(map(_fields, node))
    return (type(node).__name__, node)


class LinuxStdioColdSourceTests(unittest.TestCase):
    def test_entry_resources_keep_all_four_predecessors_and_are_not_runtime_bridges(self):
        from hepta.hia_agent_contract import ENTRY_BUILD_FILES, NATIVE_SOURCE_FILES
        from tools.hia_candidate_preflight import native_source_files
        original = ('examples/hia_bootstrap/release_launch_policy.hepta',
                    'examples/hia_bootstrap/release_launch_packer.hepta',
                    'examples/hia_bootstrap/candidate_build_policy.hepta',
                    'examples/hia_bootstrap/candidate_build_packer.hepta')
        self.assertEqual(ENTRY_BUILD_FILES, original + PROFILE_SOURCE_FILES)
        self.assertTrue(set(ENTRY_BUILD_FILES).isdisjoint(NATIVE_SOURCE_FILES))
        paths = native_source_files((ROOT / 'hepta/hia_agent_contract.py').read_text())
        for name in PROFILE_SOURCE_FILES:
            self.assertEqual(paths.count(name), 1)
        self.assertEqual(len(paths), len(set(paths)))

    def test_complete_cold_inputs_are_declared_and_fresh(self):
        from tools.hia_selfhost_contract import SOURCE_FILES
        from tools.hia_release import BOOTSTRAP_FILES
        self.assertEqual(len(custody.REQUIRED_SOURCES), len(set(custody.REQUIRED_SOURCES)))
        self.assertLessEqual(set(custody.REQUIRED_SOURCES), set(SOURCE_FILES))
        self.assertLessEqual(set(custody.REQUIRED_SOURCES), set(BOOTSTRAP_FILES))
        source = {name: custody.digest((ROOT / name).read_bytes()) for name in custody.REQUIRED_SOURCES}
        custody.admit_required_sources(source)
        missing = dict(source); del missing[custody.COMPILER_SOURCE]
        with self.assertRaisesRegex(ValueError, 'missing from cold source map'):
            custody.admit_required_sources(missing)
        changed = dict(source); changed[custody.PACKER_SOURCE] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'differs from cold source map'):
            custody.admit_required_sources(changed)

    def test_public_resource_lookup_is_closed_and_does_not_select_native_code(self):
        for name in PROFILE_SOURCE_FILES:
            self.assertEqual(profile_resource_path(name), ROOT / name)
            self.assertTrue(profile_resource_path(name).read_bytes())
        for name in ('selfhost.hepta', '../selfhost.hepta', '/tmp/x', '', None, True):
            with self.subTest(name=name), self.assertRaises(ValueError):
                profile_resource_path(name)

    def test_original_case_helpers_have_exact_complete_ast(self):
        old = _tree((ROOT / HISTORICAL).read_bytes())
        new = _tree((ROOT / 'tests/hia_linux_stdio_cases.py').read_bytes())
        for name in ('sha', 'dump', 'impose', 'direct', 'reference'):
            with self.subTest(name=name):
                self.assertEqual(_fields(_function(old, name)), _fields(_function(new, name)))

    def test_original_twelve_inputs_and_comparison_statements_are_unchanged(self):
        old = _tree((ROOT / HISTORICAL).read_bytes())
        new = _tree((ROOT / 'tests/hia_linux_stdio_cases.py').read_bytes())
        main = _function(old, 'main')
        assignments = {n.targets[0].id: n for n in ast.walk(main)
                       if isinstance(n, ast.Assign) and len(n.targets) == 1
                       and isinstance(n.targets[0], ast.Name)
                       and n.targets[0].id in ('data', 'definitions', 'checks')}
        definitions = _function(new, 'case_definitions')
        self.assertEqual(_fields(definitions.body[:2]), _fields([assignments['data'], assignments['definitions']]))
        checks = _function(new, 'case_checks')
        original_loop = next(n for n in ast.walk(main) if isinstance(n, ast.For)
                             and isinstance(n.target, ast.Tuple)
                             and [x.id for x in n.target.elts] ==
                             ['name', 'program', 'payload', 'mode', 'ignored', 'rc', 'stdout'])
        start = original_loop.body.index(assignments['checks'])
        self.assertEqual(_fields(checks.body[:4]), _fields(original_loop.body[start:start + 4]))
        self.assertEqual(len(retained.case_definitions()), 12)

    def test_five_original_hia_programs_have_exact_hashes_and_public_roundtrips(self):
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(set(qualifier.CASE_SOURCE_SHA256), set(custody.CASE_NAMES))
        for name in custody.CASE_NAMES:
            raw = qualifier._case_source(name)
            checked = assemble_program(raw, profile=PROFILE)
            with self.subTest(name=name):
                self.assertEqual(render_assembly(checked, profile=PROFILE).encode(), raw)
                self.assertEqual(custody.digest(raw), qualifier.CASE_SOURCE_SHA256[name])

    def test_original_57_and_complete_new_12_have_exact_ordered_ids(self):
        suite, ids = qualifier.load_suite()
        old = unittest.TestLoader().loadTestsFromNames(qualifier.SELECTORS[:3])
        old_ids = [test.id() for test in qualifier.flatten(old)]
        self.assertEqual(len(old_ids), 57)
        self.assertEqual(ids[:57], old_ids)
        self.assertEqual(len(ids), suite.countTestCases())
        self.assertEqual(len(ids), 69)
        self.assertEqual(len(set(ids)), 69)
        self.assertTrue(all(name.startswith(__name__ + '.LinuxStdioMatchingColdNativeTests.')
                            for name in ids[57:]))

    def test_failed_development_or_missing_cold_refuses_before_build_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path = folder / 'cold.json'
            for status in ('DEVELOPMENT_BUILD', 'PASS', 'FAIL', 'QUALIFICATION_TIMEOUT'):
                path.write_text(json.dumps({'schema': 'hepta.hia.selfhost-cold-replay.v1',
                                            'status': status, 'returncode': 0}))
                with self.subTest(status=status), mock.patch.object(custody, 'compile_bound',
                        side_effect=AssertionError('compile must not run')):
                    with self.assertRaises(ValueError):
                        builder.build_toolchain(folder / 'not-created', path)
                self.assertFalse((folder / 'not-created').exists())
            with self.assertRaises(FileNotFoundError):
                builder.build_toolchain(folder / 'not-created', folder / 'missing.json')
            self.assertFalse((folder / 'not-created').exists())

    def test_original_cold_deadline_terminal_and_cleanup_are_strictly_typed(self):
        # Shape-only control: this object is never passed to admit_cold and is
        # not a cold report or a source/image authority.
        value = {'schema': 'hepta.hia.selfhost-cold-replay.v1',
                 'status': 'COLD_SELFHOST_REPLAY_PASS', 'returncode': 0,
                 'qualification_wall_limit_seconds': 180, 'cleanup_wall_limit_seconds': 3,
                 'nested_report': '/shape-only/not-a-report', 'nested_report_sha256': '0' * 64,
                 'process_owner': {'schema': 'hepta.hia.selfhost-process-owner.v1',
                    'status': 'OWNED_PROCESS_COMPLETED', 'returncode': 0,
                    'qualification_seconds': 180, 'cleanup_seconds': 3,
                    'timed_out': False, 'exit_observed_before_deadline': True,
                    'cleanup': {'complete': True}}}
        custody.outer_shape(value)
        mutations = [('returncode', False), ('qualification_wall_limit_seconds', 181),
                     ('qualification_wall_limit_seconds', 180.0), ('cleanup_wall_limit_seconds', 4),
                     ('cleanup_wall_limit_seconds', 3.0), ('nested_report', '')]
        for key, replacement in mutations:
            changed = copy.deepcopy(value); changed[key] = replacement
            with self.subTest(key=key, replacement=replacement), self.assertRaises(ValueError):
                custody.outer_shape(changed)
        for key, replacement in [('returncode', False), ('timed_out', 0),
                ('exit_observed_before_deadline', 1), ('qualification_seconds', 181),
                ('cleanup_seconds', 4), ('cleanup', {'complete': 1})]:
            changed = copy.deepcopy(value); changed['process_owner'][key] = replacement
            with self.subTest(owner_key=key), self.assertRaises(ValueError):
                custody.outer_shape(changed)

    def test_input_rechecks_observe_actual_changes_and_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source = root / 'input'; source.write_bytes(b'old')
            record = custody.pin(source); custody.check_bindings([record])
            source.write_bytes(b'new')
            with self.assertRaises(ValueError):
                custody.check_bindings([record])
            source.write_bytes(b'old'); source.chmod(record['mode'] ^ 0o100)
            with self.assertRaises(ValueError):
                custody.check_bindings([record])
            source.chmod(record['mode'])
            link = root / 'link'; link.symlink_to(source)
            with self.assertRaises(ValueError):
                custody.pin(link)
            with self.assertRaises(ValueError):
                custody.check_bindings([record, record])

    def test_duplicate_and_nonfinite_json_cannot_supply_custody(self):
        for raw in (b'{"status":"FAIL","status":"PASS"}', b'{"x":NaN}',
                    b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                custody.decode(raw)

    def test_development_fixture_or_toolchain_cannot_reenter_cold_builder(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'development.json'
            for function, schema in ((builder.admit_toolchain, builder.TOOLCHAIN_SCHEMA),
                    (builder.admit_program, builder.PROGRAM_SCHEMA),
                    (qualifier.admit_fixture, qualifier.FIXTURE_SCHEMA)):
                path.write_text(json.dumps({'schema': schema, 'status': 'DEVELOPMENT_BUILD',
                    'matching_cold': False, 'profile': PROFILE}))
                with self.subTest(function=function.__name__), self.assertRaises(ValueError):
                    function(path)
        with self.assertRaises(ValueError):
            qualifier.load_fixture({})
        with self.assertRaises(ValueError):
            qualifier.load_fixture({qualifier.COLD_FIXTURE_ENV: '', qualifier.EVIDENCE_ENV: 'x'})

    def test_qualifier_rejects_ambient_override_before_read_or_mkdir(self):
        for key in (qualifier.COLD_FIXTURE_ENV, qualifier.EVIDENCE_ENV):
            with self.subTest(key=key), mock.patch.dict(os.environ, {key: ''}), \
                    mock.patch.object(qualifier, 'admit_cold', side_effect=AssertionError('no admission')):
                with self.assertRaises(ValueError):
                    qualifier.qualify('/not-opened', '/not-created')

    def test_incomplete_or_anomalous_child_report_cannot_become_authority(self):
        # Producer-shape control only; the real parent additionally checks the
        # actual owned process and all twelve executable/VM records.
        row = {'schema': 'hepta.hia.linux-stdio-cold-observations.v1',
               'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY', 'status': 'PASS',
               'request_sha256': 'shape-only', 'loaded_ids': list(qualifier.EXPECTED_IDS),
               'started_ids': list(qualifier.EXPECTED_IDS), 'stopped_ids': list(qualifier.EXPECTED_IDS),
               'tests_run': 69, 'source_and_inputs_unchanged': True,
               'anomalies': {name: [] for name in qualifier.ANOMALIES}}
        qualifier.admit_child_report(row, 'shape-only')
        for field in ('loaded_ids', 'started_ids', 'stopped_ids'):
            changed = copy.deepcopy(row); changed[field].pop()
            with self.subTest(field=field), self.assertRaises(ValueError):
                qualifier.admit_child_report(changed, 'shape-only')
        for name in qualifier.ANOMALIES:
            changed = copy.deepcopy(row); changed['anomalies'][name].append('real rejection')
            with self.subTest(anomaly=name), self.assertRaises(ValueError):
                qualifier.admit_child_report(changed, 'shape-only')
        for key, value in [('tests_run', 69.0), ('source_and_inputs_unchanged', 1),
                           ('scope', 'MATCHING_CURRENT_SOURCE_COLD')]:
            changed = copy.deepcopy(row); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                qualifier.admit_child_report(changed, 'shape-only')

    def test_compile_observation_rejects_unobserved_request_extensions(self):
        # Protocol shape only: no compiler/image authority is manufactured.
        child = {name: 0 for name in custody.CHILD_FIELDS}
        receipt = {**child, **{name: 0 for name in custody.RECEIPT_HOST_FIELDS}}
        custody.child_receipt(child, receipt)
        for name in custody.CHILD_FIELDS:
            missing = dict(child); del missing[name]
            changed = dict(receipt); changed[name] = 1
            with self.subTest(missing_field=name), self.assertRaises(ValueError):
                custody.child_receipt(missing, receipt)
            with self.subTest(changed_field=name), self.assertRaises(ValueError):
                custody.child_receipt(child, changed)
        for name in custody.RECEIPT_HOST_FIELDS:
            missing = dict(receipt); del missing[name]
            with self.subTest(missing_host_field=name), self.assertRaises(ValueError):
                custody.child_receipt(child, missing)
        with self.assertRaises(ValueError):
            custody.child_receipt({**child, 'unknown': 0}, receipt)
        with self.assertRaises(ValueError):
            custody.child_receipt(child, {**receipt, 'unknown': 0})
        changed = dict(receipt); changed['abi_status'] = False
        with self.assertRaises(ValueError):
            custody.child_receipt(child, changed)
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); provider = folder / 'provider'; provider.write_bytes(b'\xc3')
            payload = b'not-an-executed-program'; label = 'shape'
            request = {'format': 'flat-x86-64', 'capacity': custody.CAPACITY,
                'image': str(provider), 'image_sha256': custody.digest(provider.read_bytes()),
                'source': str(folder / (label + '.input.bin')), 'source_sha256': custody.digest(payload),
                'output': str(folder / (label + '.output.bin')), 'workspace_fill': 0,
                'workspace_size': custody.CAPACITY}
            (folder / (label + '.input.bin')).write_bytes(payload)
            (folder / (label + '.output.bin')).write_bytes(b'')
            (folder / (label + '.receipt.json')).write_text('{}')
            (folder / (label + '.stdout.log')).write_text('{}')
            (folder / (label + '.stderr.log')).write_bytes(b'')
            for key, value in [('workspace_fill', False), ('workspace_fill', 1),
                    ('capacity', float(custody.CAPACITY)), ('workspace_size', True),
                    ('observe_trap_writes', True), ('output_initial_hex', '')]:
                changed = dict(request); changed[key] = value
                (folder / (label + '.request.json')).write_text(json.dumps(changed))
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'native request differs'):
                    custody.observation(folder, label, provider, payload)
            (folder / (label + '.request.json')).write_text(json.dumps(request))
            with self.assertRaisesRegex(ValueError, 'actual child stdout differs'):
                custody.observation(folder, label, provider, payload)

    def test_native_limits_and_owned_process_limits_are_not_overridable(self):
        self.assertEqual((qualifier.GROUP_SECONDS, qualifier.CLEANUP_SECONDS,
                          qualifier.COMPILE_SECONDS, custody.CAPACITY), (180, 3, 20, 1048576))
        source = _tree((ROOT / 'tools/build_hia_linux_stdio_cold.py').read_bytes())
        functions = {n.name: n for n in source.body if isinstance(n, ast.FunctionDef)}
        for name in ('build_toolchain', 'build_program'):
            self.assertFalse(any(a.arg in {'timeout', 'capacity', 'workspace_size', 'development'}
                for a in (*functions[name].args.args, *functions[name].args.kwonlyargs)))
        expected = {'schema': 'hepta.hia.selfhost-process-owner.v1',
            'status': 'OWNED_PROCESS_COMPLETED', 'returncode': 0,
            'qualification_seconds': 180, 'cleanup_seconds': 3,
            'timed_out': False, 'exit_observed_before_deadline': True, 'cleanup': {'complete': True}}
        self.assertTrue(qualifier._owner_pass(expected))
        for key, value in [('returncode', False), ('timed_out', 0),
                ('qualification_seconds', 181), ('cleanup_seconds', 3.0), ('cleanup', {'complete': 1})]:
            changed = copy.deepcopy(expected); changed[key] = value
            with self.subTest(key=key):
                self.assertFalse(qualifier._owner_pass(changed))

    def test_profile_mechanism_and_external_vm_edge_are_explicit(self):
        from hepta import hia_checker_identity as identity
        self.assertIn('hia_linux_stdio.py', identity.CHECKER_MECHANISM_SOURCE_FILES)
        self.assertNotIn('hia_linux_stdio.py', identity.SEMANTIC_CORE_SOURCE_FILES)
        dependencies = {n.module + '.py' for n in ast.walk(_tree((ROOT / 'hepta/hia_linux_stdio.py').read_bytes()))
                        if isinstance(n, ast.ImportFrom) and n.level == 1 and n.module}
        other = dependencies - set(identity.SEMANTIC_CORE_SOURCE_FILES) - set(identity.CHECKER_MECHANISM_SOURCE_FILES)
        self.assertEqual(other, {'hia_program_runtime.py'})
        self.assertEqual(tuple(identity.CHECKER_MECHANISM_EXTERNAL_PROVIDERS['hia_linux_stdio.py']),
                         ('hia_program_runtime.py',))
        self.assertIn('hia_linux_stdio.py', identity.CORE_SOURCE_FILES)
        self.assertEqual(identity.CHECKER_MECHANISM_EXTERNAL_PROVIDERS['hia_agent_assembly.py'],
                         ('hia_program_tools.py',))


class LinuxStdioPortableSourceTests(unittest.TestCase):
    def test_actual_sdist_wheel_installed_lookup_and_missing_resource_refusal(self):
        from tests.test_hia_agent_installed_resources import RESOURCES, SDIST_SUPPORT_FILES
        from hepta.hia_agent_contract import (
            DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES,
            COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES,
            EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES,
            EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES, ENTRY_BUILD_FILES,
        )
        roles = (
            ('DISCOVERY_FILES', tuple('docs/' + name for name in DISCOVERY_FILES)),
            ('NATIVE_SOURCE_FILES', NATIVE_SOURCE_FILES),
            ('SOURCE_BUILD_FILES', SOURCE_BUILD_FILES),
            ('COMPILER_BUILD_FILES', COMPILER_BUILD_FILES),
            ('PUBLICATION_BUILD_FILES', PUBLICATION_BUILD_FILES),
            ('BACKEND_BUILD_FILES', BACKEND_BUILD_FILES),
            ('EMITTER_BUILD_FILES', EMITTER_BUILD_FILES),
            ('BYTE_WRAPPER_BUILD_FILES', BYTE_WRAPPER_BUILD_FILES),
            ('MACHINE_OBJECT_BUILD_FILES', MACHINE_OBJECT_BUILD_FILES),
            ('EXECUTION_OBSERVATION_BUILD_FILES', EXECUTION_OBSERVATION_BUILD_FILES),
            ('CONTINUATION_BUILD_FILES', CONTINUATION_BUILD_FILES),
            ('ENTRY_BUILD_FILES', ENTRY_BUILD_FILES),
        )
        resources = tuple(name for _, names in roles for name in names)
        self.assertEqual(resources, RESOURCES)
        self.assertEqual(len(resources), len(set(resources)))
        resource_bytes = {name: (ROOT / name).read_bytes() for name in resources}
        explicit = os.environ.get('HEPTA_HIA_LINUX_STDIO_SOURCE_EVIDENCE')
        temporary = None
        if explicit:
            folder = Path(explicit).absolute(); folder.mkdir(mode=0o700, exist_ok=False)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='hia-linux-stdio-portable-')
            folder = Path(temporary.name)
        try:
            source = folder / 'source'; source.mkdir()
            shutil.copytree(ROOT / 'hepta', source / 'hepta', ignore=shutil.ignore_patterns('__pycache__'))
            for name in (*resources, *SDIST_SUPPORT_FILES, 'setup.py', 'pyproject.toml', 'MANIFEST.in'):
                target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            environment = {'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8',
                           'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
                           'PIP_NO_INDEX': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1'}
            def run(name, argv, cwd=source):
                result = subprocess.run([sys.executable, '-B', *map(str, argv)], cwd=cwd,
                    env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                (folder / (name + '.stdout')).write_bytes(result.stdout)
                (folder / (name + '.stderr')).write_bytes(result.stderr)
                self.assertEqual(result.returncode, 0, (name, result.stderr[-4000:].decode(errors='replace')))
                return result.stdout
            run('sdist', ['setup.py', 'sdist', '--dist-dir', folder / 'sdist'])
            archive, = (folder / 'sdist').glob('*.tar.gz')
            with tarfile.open(archive) as tar:
                prefix = tar.getmembers()[0].name.split('/')[0] + '/'
                for name in resources:
                    self.assertEqual(tar.extractfile(prefix + name).read(), resource_bytes[name], name)
            run('wheel', ['-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation',
                          '--wheel-dir', folder / 'wheel', archive])
            wheel, = (folder / 'wheel').glob('*.whl')
            with zipfile.ZipFile(wheel) as zipped:
                self.assertEqual({name for name in zipped.namelist()
                                  if name.startswith('hepta/_data/') and not name.endswith('/')},
                                 {'hepta/_data/' + name for name in resources})
                for name in resources:
                    self.assertEqual(zipped.read('hepta/_data/' + name), resource_bytes[name], name)
            installed = folder / 'installed'
            run('install', ['-m', 'pip', 'install', '--no-deps', '--no-index', '--target', installed, wheel])
            for name in resources:
                self.assertEqual((installed / 'hepta/_data' / name).read_bytes(), resource_bytes[name], name)
            (folder / 'RESOURCE-READBACK.json').write_text(json.dumps({
                'roles': {role: list(names) for role, names in roles},
                'resources': {name: {'bytes': len(raw), 'sha256': custody.digest(raw)}
                              for name, raw in resource_bytes.items()},
                'sdist_wheel_installed_complete_bytes_equal': True,
            }, indent=2, sort_keys=True) + '\n')
            input_program = folder / 'explicit-input.hepta'
            input_program.write_bytes(qualifier._case_source('zero-transfer'))
            child = '''import hashlib,json,pathlib,sys
sys.path.insert(0,sys.argv[1])
from hepta.hia_linux_stdio import PROFILE,PROFILE_SOURCE_FILES,profile_resource_path
from hepta.hia_agent_assembly import assemble_program,render_assembly
from hepta.hia_program import verify_program,HIAProgramRejected
from hepta.hia_program_runtime import execute_program
root=pathlib.Path(sys.argv[1])
result={}
for name in PROFILE_SOURCE_FILES:
 p=profile_resource_path(name)
 assert p==root/'hepta'/'_data'/name
 result[name]=hashlib.sha256(p.read_bytes()).hexdigest()
raw=pathlib.Path(sys.argv[2]).read_bytes()
checked=assemble_program(raw,profile=PROFILE)
assert render_assembly(checked,profile=PROFILE).encode()==raw
seen=[]
def provider(request):
 seen.append((request.fd,request.count))
 return 0,b''
observed=execute_program(checked,'f0',(b'',bytes(16),bytes(16)),profile=PROFILE,linux_stdio_provider=provider)
assert seen==[(0,0),(1,0)] and observed['values']==[0]
assert observed['actual_kernel_execution'] is False
assert observed['output_hex']==bytes(16).hex() and observed['workspace_hex']==bytes(16).hex()
for operation in (lambda:assemble_program(raw),lambda:verify_program(checked),
                  lambda:execute_program(checked,'f0',(b'',bytes(16),bytes(16)))):
 try:operation()
 except HIAProgramRejected:pass
 else:raise AssertionError('default entry admitted physical profile')
print(json.dumps(result,sort_keys=True))
'''
            observed = json.loads(run('installed', ['-I', '-c', child, installed, input_program], cwd=folder))
            self.assertEqual(observed, {name: custody.digest((ROOT / name).read_bytes())
                                        for name in PROFILE_SOURCE_FILES})
            for index, name in enumerate(PROFILE_SOURCE_FILES):
                path = installed / 'hepta/_data' / name
                original = path.read_bytes(); path.unlink()
                failure = subprocess.run([sys.executable, '-I', '-B', '-c', child, str(installed), str(input_program)],
                    cwd=ROOT, env=environment, capture_output=True, timeout=60)
                (folder / ('missing-' + str(index) + '.stdout')).write_bytes(failure.stdout)
                (folder / ('missing-' + str(index) + '.stderr')).write_bytes(failure.stderr)
                self.assertNotEqual(failure.returncode, 0)
                self.assertIn(b'FileNotFoundError', failure.stderr)
                path.write_bytes(original)
            self.assertEqual(json.loads(run('restored', ['-I', '-c', child, installed, input_program], cwd=folder)), observed)
        finally:
            if temporary is not None:
                temporary.cleanup()


class LinuxStdioMatchingColdNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_path, cls.fixture, cls.output = qualifier.load_fixture()
        cls.fixture_binding = custody.pin(cls.fixture_path)
        cls.output.mkdir(mode=0o700, parents=False, exist_ok=False)

    def _case(self, index):
        custody.guard_authority(self.fixture['authority'])
        self.assertEqual(custody.pin(self.fixture_path), self.fixture_binding)
        name, program, payload, mode, ignored, expected_rc, expected_stdout = retained.case_definitions()[index]
        build = self.fixture['programs'][program]
        custody.check_bindings([build['build']])
        executable = Path(build['executable'])
        self.assertEqual(custody.digest(executable.read_bytes()), build['executable_sha256'])
        folder = self.output / name; folder.mkdir(mode=0o700)
        checked = assemble_program(qualifier._case_source(program), profile=PROFILE)
        reference = retained.reference(checked, payload, mode, ignored)
        retained.dump(folder / 'PUBLIC-VM.json', reference)
        actual = retained.direct(folder / 'kernel', executable, payload, mode, ignored)
        checks = retained.case_checks(name, build, reference, actual, expected_rc, expected_stdout)
        row = {'id': name, 'program': program, 'checks': checks,
               'status': 'PASS' if all(checks.values()) else 'FAIL', 'actual': actual}
        retained.dump(folder / 'RESULT.json', row)
        self.assertTrue(all(checks.values()), row)
        custody.guard_authority(self.fixture['authority'])
        custody.check_bindings([build['build']])
        self.assertEqual(custody.pin(self.fixture_path), self.fixture_binding)

    def test_01_empty_input(self): self._case(0)
    def test_02_short_binary_input(self): self._case(1)
    def test_03_zero_count_open(self): self._case(2)
    def test_04_zero_count_closed_read(self): self._case(3)
    def test_05_zero_count_closed_write(self): self._case(4)
    def test_06_full_signed_read_ebadf(self): self._case(5)
    def test_07_full_signed_write_ebadf(self): self._case(6)
    def test_08_sigpipe_default(self): self._case(7)
    def test_09_sigpipe_inherited_ignore_epipe(self): self._case(8)
    def test_10_exact_one_mib(self): self._case(9)
    def test_11_over_one_mib_rejected_before_write(self): self._case(10)
    def test_12_bounds_before_read(self): self._case(11)
