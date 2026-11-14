"""Source refusals and new permanent cold-owned roundtrip test identities.

The Source class executes no native compiler/payload and grants no cold
qualification. Native classes require the qualifier's actual current-cold
fixture; absent fixtures skip in ordinary discovery and are fatal in the
strict qualifier. Original development outcomes are not inherited.
"""
from pathlib import Path
import ast
import copy
import os
import tempfile
import unittest
from unittest import mock

from tools import hia_linux_file_roundtrip_cold as custody
from tools import qualify_hia_linux_file_roundtrip as qualifier
from tests.hia_linux_file_roundtrip_ids import (
    CASE_NAMES, METHOD_NAMES, GROUP_COUNTS, GROUP_ORDER, GROUP_CLASSES, EXPECTED_IDS,
)

ROOT = Path(__file__).resolve().parents[1]


def _functions(raw):
    tree = ast.parse(raw)
    return {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _body(node):
    return ast.dump(node, include_attributes=False)


class LinuxFileRoundtripColdSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = custody.retained()

    def test_complete_original_fixture_and_known_failure(self):
        original = self.original
        self.assertEqual(len(original['kernel_cases']), 130)
        self.assertEqual(len(original['pipeline_rows']), 7)
        self.assertEqual(original['tail_fault_names'], ['C1-last-byte', 'C2-last-byte'])
        separate = original['known_separate_semantic_suite']
        self.assertEqual((separate['logical_vm_cases'], separate['passed'], separate['failed']), (6, 5, 1))
        self.assertEqual(separate['failed_case'], 'root-v8-cross-target-loans')
        self.assertEqual(separate['fuel_limit'], 10000000)
        self.assertEqual(separate['status'], 'ORIGINAL_FUEL_FAILURE_RETAINED_NOT_RECLASSIFIED')
        self.assertIs(original['matching_cold'], False)
        self.assertIs(original['whole_native'], False)
        for row in original['kernel_cases']:
            for name in ('input', 'stdout', 'stderr'):
                self.assertEqual(custody.digest(custody.retained_bytes(row[name])), row[name]['sha256'])

    def test_permanent_ordered_ids_and_denominators(self):
        self.assertEqual(GROUP_ORDER, ('kernel', 'pipeline', 'tail_faults', 'portable'))
        self.assertEqual(GROUP_COUNTS, {'kernel': 130, 'pipeline': 7, 'tail_faults': 2, 'portable': 1})
        self.assertEqual(CASE_NAMES['kernel'], tuple(row['name'] for row in self.original['kernel_cases']))
        self.assertEqual(CASE_NAMES['pipeline'], tuple(row[0] for row in self.original['pipeline_rows']))
        self.assertEqual(CASE_NAMES['tail_faults'], tuple(self.original['tail_fault_names']))
        for group in GROUP_ORDER:
            suite, identities = qualifier.load_suite(group)
            self.assertEqual(tuple(identities), EXPECTED_IDS[group])
            self.assertEqual(suite.countTestCases(), GROUP_COUNTS[group])
            self.assertEqual(len(set(identities)), GROUP_COUNTS[group])
        complete = unittest.TestLoader().loadTestsFromName('tests.test_hia_linux_file_roundtrip_cold')
        all_ids = [test.id() for test in qualifier.flatten(complete)]
        self.assertEqual(len(all_ids), 156)
        self.assertEqual(len(set(all_ids)), 156)

    def test_reference_and_tail_projection_bodies_are_original(self):
        current = _functions((ROOT / 'tests/hia_linux_file_roundtrip_cases.py').read_bytes())
        for path, name in (('R3/run_pipeline_vm_r1.py', 'reference'), ('R3/run_tail_faults_r1.py', 'projected_document')):
            original = _functions(custody.retained_bytes(self.original['original_scripts'][path]))
            self.assertEqual(_body(current[name]), _body(original[name]), name)

    def test_observer_payload_is_original_hia_projection(self):
        previous = custody.retained_bytes(self.original['original_scripts']['R3/postreturn_exec_observer.py'])
        self.assertEqual((ROOT / 'tests/hia_linux_file_roundtrip_exec.py').read_bytes(), previous)
        previous = _functions(custody.retained_bytes(self.original['original_scripts']['R3/generate_postreturn_observer.py']))
        current = _functions((ROOT / 'tests/hia_linux_file_roundtrip_observer.py').read_bytes())
        self.assertEqual(set(previous), set(current))
        self.assertEqual({key: _body(value) for key, value in previous.items()},
                         {key: _body(value) for key, value in current.items()})

    def test_original_check_dictionaries_remain_exact(self):
        current = _functions((ROOT / 'tests/hia_linux_file_roundtrip_cases.py').read_bytes())
        def checks(node):
            return [_body(item.value) for item in ast.walk(node)
                if isinstance(item, ast.Assign) and isinstance(item.value, ast.Dict)
                and any(isinstance(target, ast.Name) and target.id == 'checks' for target in item.targets)]
        for path, name in (('R2/run_kernel_130_r1.py', 'kernel_case'),
                           ('R3/run_pipeline_vm_r1.py', 'pipeline_case'),
                           ('R3/run_tail_faults_r1.py', 'tail_fault_case')):
            previous = ast.parse(custody.retained_bytes(self.original['original_scripts'][path]))
            self.assertEqual(checks(previous), checks(current[name]))
            self.assertEqual(len(checks(current[name])), 1)

    def test_optional_profile_has_five_sources_without_worker_growth(self):
        from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES, fresh_profile_identity, guard_profile_identity
        from tests.hia_linux_file_roundtrip_portable import default_resources
        self.assertEqual(tuple(OPTIONAL_PROFILE_FILES[custody.PROFILE]), custody.PROFILE_SOURCE_FILES)
        self.assertEqual(len(custody.PROFILE_SOURCE_FILES), 5)
        self.assertEqual(len(default_resources()), 210)
        self.assertTrue(set(default_resources()).isdisjoint(custody.PROFILE_SOURCE_FILES))
        identity = fresh_profile_identity(custody.PROFILE)
        self.assertEqual(identity, guard_profile_identity(custody.PROFILE, identity))
        self.assertEqual(set(identity['files']), set(custody.PROFILE_SOURCE_FILES))

    def test_current_cold_owner_closure_is_explicit(self):
        self.assertEqual(len(custody.REQUIRED_SOURCES), len(set(custody.REQUIRED_SOURCES)))
        self.assertTrue(set(custody.original.REQUIRED_SOURCES) <= set(custody.REQUIRED_SOURCES))
        required = ('hepta/hia_optional_profiles.py', 'tools/hia_linux_file_roundtrip_readback.py',
            'tools/qualify_hia_linux_file_roundtrip.py', 'tools/build_hia_linux_file_roundtrip_cold.py',
            'tests/hia_linux_file_roundtrip_exec.py', 'tests/hia_linux_file_roundtrip_observer.py',
            'tests/hia_linux_file_roundtrip_ids.py', 'tests/hia_linux_file_roundtrip_portable.py',
            'tests/hia_linux_file_roundtrip_installed.py', custody.RETAINED)
        for name in (*required, *custody.PROFILE_SOURCE_FILES):
            self.assertIn(name, custody.REQUIRED_SOURCES)
        with self.assertRaisesRegex(ValueError, 'missing'):
            custody.admit_required_sources({})

    def test_cold_refuses_development_before_any_compilation(self):
        from tools import build_hia_linux_file_roundtrip_cold as builder
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'development.json'
            custody.publish(source, {'schema': 'development', 'status': 'PASS', 'matching_cold': True})
            with mock.patch.object(builder, 'compile_bound', side_effect=AssertionError('must not compile')) as compile_call:
                with self.assertRaises(ValueError):
                    builder.build_toolchain(root / 'not-created', source)
            compile_call.assert_not_called()
            self.assertFalse((root / 'not-created').exists())

    def test_cold_exact_original_owner_limits(self):
        owner = {'schema': 'hepta.hia.selfhost-process-owner.v1', 'status': 'OWNED_PROCESS_COMPLETED',
            'returncode': 0, 'qualification_seconds': 180, 'cleanup_seconds': 3,
            'timed_out': False, 'exit_observed_before_deadline': True,
            'cleanup': {'complete': True, 'observed_echild': True}}
        outer = {'schema': 'hepta.hia.selfhost-cold-replay.v1', 'status': 'COLD_SELFHOST_REPLAY_PASS',
            'returncode': 0, 'qualification_wall_limit_seconds': 180, 'cleanup_wall_limit_seconds': 3,
            'process_owner': owner, 'nested_report': 'only-shape-no-authority', 'nested_report_sha256': '0' * 64}
        # This shape-only check creates no B image, fixture or positive cold result.
        for field, value in (('returncode', False), ('qualification_wall_limit_seconds', 181),
                             ('cleanup_wall_limit_seconds', 4), ('status', 'DEVELOPMENT_PASS')):
            changed = copy.deepcopy(outer); changed[field] = value
            with self.assertRaises(ValueError): custody.original.outer_shape(changed)
        changed = copy.deepcopy(outer); changed['process_owner']['returncode'] = False
        with self.assertRaises(ValueError): custody.original.outer_shape(changed)

    def test_fixture_cannot_supply_cold_authority(self):
        from tools import build_hia_linux_file_roundtrip_cold as builder
        fake = {'schema': qualifier.FIXTURE_SCHEMA, 'status': qualifier.FIXTURE_STATUS,
            'scope': qualifier.SCOPE, 'profile': custody.PROFILE, 'matching_cold': True,
            'qualification_complete': False, 'whole_native': False, 'default_activated': False,
            'full_checker_vm_qualification': False, 'limits': dict(qualifier.LIMITS),
            'authority': {'schema': 'development', 'physical_profile': custody.PROFILE}}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'FIXTURE.json'; custody.publish(path, fake)
            with mock.patch.object(builder, 'admit_program', side_effect=AssertionError('must refuse first')) as child:
                with self.assertRaises(ValueError): qualifier.admit_fixture(path)
            child.assert_not_called()
        for field, value in (('matching_cold', 1), ('whole_native', True), ('qualification_complete', True),
                             ('full_checker_vm_qualification', True), ('status', 'PASS')):
            changed = copy.deepcopy(fake); changed[field] = value
            with self.assertRaises(ValueError): qualifier.fixture_shape(changed)

    def test_child_report_rejects_missing_reordered_and_bool_counts(self):
        group = 'pipeline'; identities = list(EXPECTED_IDS[group])
        report = {'schema': qualifier.RESULT_SCHEMA, 'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY',
            'status': 'PASS', 'group': group, 'request_sha256': '0' * 64, 'source_and_inputs_unchanged': True,
            'tests_run': 7, 'loaded_ids': identities, 'started_ids': identities, 'stopped_ids': identities,
            'anomalies': {key: [] for key in qualifier.ANOMALIES}}
        # Mechanical result-shape validation is separate from actual observations.
        qualifier.admit_child_report(report, '0' * 64, group)
        for key, value in (('tests_run', True), ('tests_run', 6), ('stopped_ids', identities[:-1]),
                           ('started_ids', list(reversed(identities))), ('source_and_inputs_unchanged', 1)):
            changed = copy.deepcopy(report); changed[key] = value
            with self.assertRaises(ValueError): qualifier.admit_child_report(changed, '0' * 64, group)
        for anomaly in qualifier.ANOMALIES:
            changed = copy.deepcopy(report); changed['anomalies'][anomaly] = ['real failure']
            with self.assertRaises(ValueError): qualifier.admit_child_report(changed, '0' * 64, group)

    def test_owner_requires_deadline_and_cleanup(self):
        owner = {'schema': 'hepta.hia.selfhost-process-owner.v1', 'status': 'OWNED_PROCESS_COMPLETED',
            'returncode': 0, 'qualification_seconds': 180, 'cleanup_seconds': 3,
            'timed_out': False, 'exit_observed_before_deadline': True,
            'cleanup': {'complete': True, 'observed_echild': True}}
        self.assertTrue(custody.owner_pass(owner))
        self.assertTrue(qualifier.cleanup_observed(owner))
        self.assertFalse(qualifier.cleanup_observed(None))
        self.assertFalse(qualifier.cleanup_observed({'cleanup': {'complete': True}}))
        for field, value in (('returncode', False), ('qualification_seconds', 181), ('cleanup_seconds', 4),
                             ('timed_out', True), ('exit_observed_before_deadline', False), ('cleanup', {'complete': True})):
            changed = copy.deepcopy(owner); changed[field] = value
            self.assertFalse(custody.owner_pass(changed))

    def test_all_captured_bytes_and_modes_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'input'; path.write_bytes(b'original'); path.chmod(0o400)
            binding = custody.pin(path); custody.check_bindings([binding])
            path.chmod(0o600)
            with self.assertRaises(ValueError): custody.check_bindings([binding])
            path.write_bytes(b'changed!'); path.chmod(0o400)
            with self.assertRaises(ValueError): custody.check_bindings([binding])
            link = Path(temporary) / 'symlink'; link.symlink_to(path)
            with self.assertRaises(ValueError): custody.pin(link)

    def test_retained_input_decode_rejects_drift(self):
        sample = self.original['kernel_cases'][0]['input']
        changed = dict(sample, bytes=sample['bytes'] + 1)
        with self.assertRaises(ValueError): custody.retained_bytes(changed)
        changed = dict(sample, sha256='0' * 64)
        with self.assertRaises(ValueError): custody.retained_bytes(changed)
        changed = dict(sample, bytes=True)
        with self.assertRaises(ValueError): custody.retained_bytes(changed)

    def test_build_failure_retains_partial_files(self):
        from tools import build_hia_linux_file_roundtrip_cold as builder
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fake = root / 'not-an-executable'; fake.write_bytes(b'observation-only')
            authority = {'compiler': str(fake)}
            with mock.patch.object(builder, 'admit_cold', return_value=authority), \
                    mock.patch.object(builder, 'compile_bound', side_effect=RuntimeError('injected before execution')) as invoked:
                with self.assertRaisesRegex(RuntimeError, 'injected before execution'):
                    builder.build_toolchain(root / 'build', root / 'absent')
            self.assertEqual(invoked.call_count, 1)
            result = custody.decode((root / 'build/BUILD.json').read_bytes())
            self.assertEqual(result['status'], 'FAIL'); self.assertIs(result['matching_cold'], False)
            self.assertIn('injected before execution', result['traceback'])
            self.assertEqual(len(result['retained_files']), 3)
            custody.check_bindings(result['retained_files'])

    def test_portable_uses_explicit_profile_and_real_kernel(self):
        source = (ROOT / 'tests/hia_linux_file_roundtrip_portable.py').read_text()
        from tests import hia_linux_file_roundtrip_portable as portable
        self.assertEqual(portable.BUILD_PROFILE_ENV, 'HEPTA_HIA_BUILD_PROFILES')
        self.assertEqual(portable.COMMAND_SECONDS, 60)
        self.assertEqual(portable.PORTABLE_CASES, ('exports-metadata-empty', 'v6-checked-overflow', 'entry-undefined-SSA'))
        run = _functions(source)['run']
        calls = [item for item in ast.walk(run) if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)]
        self.assertTrue(any(item.func.id == 'direct' for item in calls))
        self.assertTrue(any(item.func.id == 'build_portable_bundle' for item in calls))
        command_calls = {item.args[0].value: item for item in calls if item.func.id == 'command'
                         and item.args and isinstance(item.args[0], ast.Constant) and isinstance(item.args[0].value, str)}
        self.assertIn('default-wheel', command_calls); self.assertIn('selected-wheel', command_calls)
        self.assertNotIn('profile', {k.arg for k in command_calls['default-wheel'].keywords})
        self.assertTrue(next(k.value.value for k in command_calls['selected-wheel'].keywords if k.arg == 'profile'))
        self.assertIn('changed-ELF', command_calls); self.assertIn('changed-source', command_calls)


class _MatchingColdCase(unittest.TestCase):
    group = None

    @classmethod
    def setUpClass(cls):
        if qualifier.COLD_FIXTURE_ENV not in os.environ:
            raise unittest.SkipTest('explicit actual matching-current-cold roundtrip fixture required')
        from tests.hia_linux_file_roundtrip_cases import context
        path, fixture, evidence = qualifier.load_fixture()
        cls.fixture_path, cls.fixture, cls.evidence = path, fixture, evidence
        cls.context = context(fixture); cls.context['production_path'] = fixture['production']['path']
        cls.addClassCleanup(cls.final_guard)

    @classmethod
    def final_guard(cls):
        custody.guard_authority(cls.fixture['authority'])
        if qualifier.admit_fixture(cls.fixture_path) != cls.fixture:
            raise AssertionError('full fixture changed during original group')


class RoundtripMatchingColdKernelTests(_MatchingColdCase):
    group = 'kernel'


class RoundtripMatchingColdPipelineTests(_MatchingColdCase):
    group = 'pipeline'


class RoundtripMatchingColdTailFaultTests(_MatchingColdCase):
    group = 'tail_faults'


class RoundtripMatchingColdPortableTests(_MatchingColdCase):
    group = 'portable'


def _method(group, index):
    def observed(self):
        from tests import hia_linux_file_roundtrip_cases as cases
        if group == 'kernel':
            cases.kernel_case(self.context, self.evidence, index)
        elif group == 'pipeline':
            cases.pipeline_case(self.context, self.evidence, index)
        elif group == 'tail_faults':
            cases.tail_fault_case(self.context, self.evidence, index)
        else:
            from tests.hia_linux_file_roundtrip_portable import run
            run(self.context, self.evidence)
    return observed


for _group in GROUP_ORDER:
    _class = globals()[GROUP_CLASSES[_group]]
    for _index, _name in enumerate(METHOD_NAMES[_group]):
        _function = _method(_group, _index)
        _function.__name__ = _name
        _function.__qualname__ = _class.__qualname__ + '.' + _name
        setattr(_class, _name, _function)

del _group, _class, _index, _name, _function


if __name__ == '__main__':
    unittest.main()
