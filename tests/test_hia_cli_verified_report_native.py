"""Report-owner source admission and the complete retained140 observations."""
from __future__ import annotations
import ast
import copy
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

ROOT = Path(__file__).resolve().parents[1]


def fixture_selection():
    from tools import qualify_hia_cli_verified_report_bundle as qualifier
    cold, development = os.environ.get(qualifier.COLD_FIXTURE), os.environ.get(qualifier.DEVELOPMENT)
    if cold and development:
        raise AssertionError('development cannot override current-cold report selection')
    if not cold and not development:
        raise unittest.SkipTest('requires an explicit report cold fixture or development manifest')
    if cold:
        fixture = qualifier.admit_fixture(cold)
        return Path(fixture['build']['manifest']), fixture, 'MATCHING_CURRENT_SOURCE_COLD_FIXTURE'
    manifest = Path(development).resolve(strict=True)
    observed = qualifier.inspect_build(manifest.parent, None)
    if observed['manifest'] != str(manifest):
        raise AssertionError('development report manifest is not its actual build output')
    return manifest, observed, 'EXPLICIT_DEVELOPMENT_ONLY'


class CliVerifiedReportSourceTests(unittest.TestCase):
    def test_seven_complete_original_method_bodies_and_definition_are_retained(self):
        from tools.hia_cli_verified_report_custody import retained_inputs
        retained = retained_inputs()
        original = ast.parse(retained['original_class']['text']).body[0]
        actual = next(node for node in ast.parse((ROOT / 'hepta/hia_program.py').read_bytes()).body
                      if isinstance(node, ast.ClassDef) and node.name == 'VerifiedProgram')
        self.assertEqual(ast.dump(original, include_attributes=False), ast.dump(actual, include_attributes=False))
        policy = {node.name: node for node in ast.parse((ROOT / 'tools/hia_verified_report_policy.py').read_bytes()).body
                  if isinstance(node, ast.FunctionDef)}
        self.assertEqual(list(policy), retained['methods'])
        for name in retained['methods']:
            node = copy.deepcopy(next(node for node in original.body if isinstance(node, ast.FunctionDef) and node.name == name))
            node.decorator_list = []
            with self.subTest(name=name):
                self.assertEqual(ast.dump(node, include_attributes=False), ast.dump(policy[name], include_attributes=False))

    def test_original43_exact_bytes_ids_and_all140_case_names_remain(self):
        from tools.hia_cli_verified_report_custody import retained_inputs
        from tools.qualify_hia_cli_verified_report_bundle import groups, _flatten
        retained = retained_inputs()
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromNames(('tests.test_hia_cli_native', 'tests.test_hia_cli_continuation_native'))
        self.assertEqual(loader.errors, [])
        self.assertEqual([test.id() for test in _flatten(suite)], retained['original_cli_ids'])
        self.assertEqual(suite.countTestCases(), 43)
        self.assertEqual(tuple(retained['original_cli_ids']), groups()['original_cli'])
        self.assertEqual(len(retained['case_names']), 140)
        self.assertEqual(len(set(retained['case_names'])), 140)
        self.assertEqual(len(groups()['report']), 2)

    def test_report_generator_reproduces_exact_hia_and_mechanical_ports(self):
        paths = ('examples/hia_bootstrap/verified_report.hepta', 'hepta/hia_verified_report_ports.py')
        before = {name: (ROOT / name).read_bytes() for name in paths}
        process = subprocess.run([sys.executable, '-I', '-B', str(ROOT / 'tools/generate_hia_verified_report.py'), '--check'],
                                 cwd=ROOT, capture_output=True, timeout=20)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual({name: (ROOT / name).read_bytes() for name in paths}, before)

    def test_report_image_stays_within_all_original_compiler_limits(self):
        from hepta.hia_agent_assembly import assemble_program
        raw = (ROOT / 'examples/hia_bootstrap/verified_report.hepta').read_bytes()
        program = assemble_program(raw).as_dict()
        self.assertLessEqual(len(raw), 1 << 20)
        self.assertEqual(len(program['functions']), 25)
        self.assertLessEqual(sum(len(fn['blocks']) for fn in program['functions']), 1536)
        self.assertLessEqual(sum(len(block['ops']) for fn in program['functions'] for block in fn['blocks']), 8192)
        for function in program['functions']:
            self.assertLessEqual(len(function['blocks']), 256)
            definitions = {item['name'] for item in function['params']}
            for block in function['blocks']:
                definitions.update(item['name'] for item in block['params'])
                definitions.update(item['name'] for operation in block['ops'] for item in operation['out'])
            self.assertLessEqual(len(definitions), 2048)

    def test_unqualified_cold_rejects_before_output_and_compiler(self):
        from tools import build_hia_cli_verified_report_bundle as builder
        from tools import qualify_hia_cli_verified_report_bundle as qualifier
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); cold = root / 'cold.json'; cold.write_text('{}')
            compiler = root / 'compiler'; compiler.write_bytes(b'not a qualified compiler')
            with patch.object(builder, 'compile_stage', side_effect=AssertionError('compiler entered')):
                with self.assertRaises(ValueError):
                    builder.build(root / 'build', compiler, cold)
                with self.assertRaises(ValueError):
                    qualifier.prepare_fixture(root / 'fixture', cold)
            self.assertFalse((root / 'build').exists())
            self.assertFalse((root / 'fixture').exists())

    def test_development_fixture_never_grants_current_cold_authority(self):
        from tools import qualify_hia_cli_verified_report_bundle as qualifier
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'fixture.json'
            row = {'schema': qualifier.FIXTURE_SCHEMA, 'status': qualifier.FIXTURE_STATUS, 'scope': qualifier.SCOPE,
                   'authority': {}, 'build': {}, 'owner_sources': {}, 'matching_cold': False,
                   'ordinary_cli_activated': False, 'whole_cli_native': False, 'whole_verify_native': False,
                   'whole_native_delivery_qualified': False}
            path.write_text(json.dumps(row))
            with patch.object(qualifier, 'admit_cold', side_effect=AssertionError('authority entered')):
                with self.assertRaises(ValueError):
                    qualifier.admit_fixture(path)
            with patch.dict(os.environ, {qualifier.COLD_FIXTURE: str(path), qualifier.DEVELOPMENT: str(path)}, clear=True):
                with self.assertRaises(AssertionError):
                    fixture_selection()

    def test_strict_result_admission_rejects_missing_exceptional_or_boolean_counts(self):
        from tools import qualify_hia_cli_verified_report_bundle as qualifier
        for group, ids in qualifier.groups().items():
            expected = list(ids)
            good = {'schema': 'hepta.hia.cli-verified-report-test-observations.v1', 'scope': 'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY',
                    'status': 'PASS', 'group': group, 'request_sha256': 'a' * 64, 'loaded_ids': expected,
                    'started_ids': expected, 'stopped_ids': expected, 'loaded': len(expected), 'tests_run': len(expected),
                    'source_and_inputs_unchanged': True, **{key: [] for key in qualifier.ANOMALIES}}
            if group == 'original_cli':
                good['fixture_provider_calls'] = [{'status': 'BUILT_AND_READ_BACK'}, {'status': 'BUILT_AND_READ_BACK'},
                                                 {'status': 'REJECTED_BEFORE_BUILD'}]
            qualifier.admit_result(good, group, 'a' * 64)
            for key in qualifier.ANOMALIES:
                bad = copy.deepcopy(good); bad[key] = ['actual abnormal outcome']
                with self.subTest(group=group, field=key), self.assertRaises(ValueError):
                    qualifier.admit_result(bad, group, 'a' * 64)
            for key in ('loaded_ids', 'started_ids', 'stopped_ids'):
                bad = copy.deepcopy(good); bad[key] = expected[:-1]
                with self.subTest(group=group, field=key), self.assertRaises(ValueError):
                    qualifier.admit_result(bad, group, 'a' * 64)
            for key in ('loaded', 'tests_run'):
                for number in (0, True, len(expected) - 1):
                    bad = copy.deepcopy(good); bad[key] = number
                    with self.subTest(group=group, field=key, number=number), self.assertRaises(ValueError):
                        qualifier.admit_result(bad, group, 'a' * 64)

    def test_actual_child_stdout_is_bound_and_missing_or_extra_fields_reject(self):
        from tools.hia_cli_verified_report_custody import retained_inputs
        from tools.hia_cli_discovery_custody import admit_child_output
        original = retained_inputs()['actual_compile_observation']
        receipt = original['receipt']; stdout = original['stdout'].encode(); stderr = bytes.fromhex(original['stderr_hex'])
        child = admit_child_output(receipt, stdout, stderr)
        self.assertEqual(child, json.loads(stdout))
        for key in tuple(child):
            bad = dict(child); del bad[key]
            with self.subTest(removed=key), self.assertRaises(ValueError):
                admit_child_output(receipt, json.dumps(bad).encode(), stderr)
        with self.assertRaises(ValueError):
            admit_child_output(receipt, json.dumps({**child, 'unexpected': 1}).encode(), stderr)
        with self.assertRaises(ValueError):
            admit_child_output(receipt, stdout, b'actual nonempty child stderr')

    def test_every_owner_file_is_in_explicit_source_closure(self):
        from tools.hia_cli_verified_report_custody import OWNER_FILES, owner_sources
        from tools.hia_selfhost_contract import SOURCE_FILES
        self.assertEqual(len(OWNER_FILES), len(set(OWNER_FILES)))
        self.assertEqual(set(owner_sources()), set(OWNER_FILES))
        self.assertTrue(set(OWNER_FILES).issubset(SOURCE_FILES))

    def test_report_is_one_real_native_resource_and_has_no_entry_group_alias(self):
        from hepta import hia_agent_contract as contract
        from hepta.hia_optional_profiles import OPTIONAL_PROFILE_FILES
        from hepta.hia_cli_verified_report_native import BUNDLE_SCHEMA
        path = 'examples/hia_bootstrap/verified_report.hepta'
        # Preserve this original component test ID. The independently versioned
        # successor moves its real resource out of the fixed worker ABI.
        self.assertEqual(contract.NATIVE_SOURCE_FILES.count(path), 0)
        self.assertNotIn(path, contract.ENTRY_BUILD_FILES)
        self.assertEqual(OPTIONAL_PROFILE_FILES[BUNDLE_SCHEMA], (path,))
        self.assertTrue((ROOT / 'hepta/hia_verified_report_native.py').is_file())
        self.assertIn('include ' + path, (ROOT / 'MANIFEST.in').read_text().splitlines())

    def test_invalid_flat_bundle_refuses_before_any_real_mapping(self):
        from hepta.hia_cli_verified_report_native import BUNDLE_SCHEMA, installed_bundle
        from hepta import hia_json_preflight_native as bridge
        fields = {'schema': BUNDLE_SCHEMA}
        for name in ('control', 'format', 'discovery', 'routing', 'parser_context', 'verified_report'):
            fields[name + '_manifest'] = name + '/manifest.json'
            fields[name + '_manifest_sha256'] = 'a' * 64
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'manifest.json'
            for label, changed in (('extra', {**fields, 'unexpected': 0}),
                                   ('traversal', {**fields, 'control_manifest': '../outside'}),
                                   ('digest', {**fields, 'control_manifest_sha256': True})):
                raw = json.dumps(changed).encode(); path.write_bytes(raw)
                with self.subTest(label=label), patch.object(bridge, '_load_manifest', side_effect=AssertionError('mapped')):
                    with self.assertRaises(ValueError):
                        installed_bundle(path, raw, changed)


    def test_z_incomplete_owner_cleanup_stops_before_the_next_group(self):
        from tools import qualify_hia_cli_verified_report_bundle as qualifier
        from tools import build_hia_json_preflight as cold_builder
        selected = qualifier.groups()
        # Synthetic owner receipts exercise orchestration only. No child,
        # compiler, cold authority or Native observation is executed here.
        for complete, echild, later_group in ((False, True, False),
                                               (True, False, False),
                                               (True, True, True)):
            with self.subTest(complete=complete, echild=echild), tempfile.TemporaryDirectory() as folder:
                root = Path(folder); output = root / 'qualification'
                authority = {'cold_report': str(root / 'cold.json'), 'source_manifest': {}}
                calls = []
                good_owner = {'status': 'OWNED_PROCESS_COMPLETED', 'returncode': 0,
                              'qualification_seconds': 180, 'cleanup_seconds': 3,
                              'timed_out': False, 'exit_observed_before_deadline': True,
                              'cleanup': {'complete': True, 'observed_echild': True}}

                def observed_owner(command, command_output, environment):
                    if '--_prepare' in command:
                        calls.append('prepare')
                        prepared = Path(command[command.index('--_prepare') + 1])
                        prepared.mkdir()
                        (prepared / 'FIXTURE.json').write_bytes(b'{}\n')
                        return copy.deepcopy(good_owner)
                    self.assertIn('--_child', command)
                    request_path = Path(command[command.index('--_child') + 1])
                    request_raw = request_path.read_bytes()
                    request = json.loads(request_raw)
                    group = request['group']; calls.append(group)
                    ids = list(selected[group])
                    observations = {
                        'schema': 'hepta.hia.cli-verified-report-test-observations.v1',
                        'scope': 'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY', 'status': 'PASS',
                        'group': group, 'request_sha256': sha256(request_raw).hexdigest(),
                        'loaded_ids': ids, 'started_ids': ids, 'stopped_ids': ids,
                        'loaded': len(ids), 'tests_run': len(ids),
                        'source_and_inputs_unchanged': True,
                        **{key: [] for key in qualifier.ANOMALIES},
                    }
                    if group == 'original_cli':
                        observations['fixture_provider_calls'] = [
                            {'status': 'BUILT_AND_READ_BACK'}, {'status': 'BUILT_AND_READ_BACK'},
                            {'status': 'REJECTED_BEFORE_BUILD'}]
                    qualifier.publish(request['output'], observations)
                    owner = copy.deepcopy(good_owner)
                    if group == 'original_cli':
                        owner['returncode'] = 1
                        owner['cleanup'] = {'complete': complete, 'observed_echild': echild}
                    return owner

                with patch.object(qualifier, 'admit_cold', return_value=authority), \
                     patch.object(qualifier, 'guard_authority'), \
                     patch.object(qualifier, 'admit_fixture'), \
                     patch.object(qualifier, '_owned', side_effect=observed_owner), \
                     patch.object(cold_builder, 'current_sources', return_value={}):
                    result = qualifier.qualify(output, authority['cold_report'])
                expected_calls = ['prepare', 'original_cli'] + (['report'] if later_group else [])
                self.assertEqual(calls, expected_calls)
                self.assertEqual([row['group'] for row in result['groups']], expected_calls[1:])
                self.assertEqual(result['groups'][0]['owner']['cleanup'],
                                 {'complete': complete, 'observed_echild': echild})
                self.assertEqual(result['groups'][0]['status'], 'FAIL')
                self.assertEqual(result['status'], 'FAIL')
                self.assertIs(result['qualification_complete'], False)
                self.assertEqual((output / 'report').exists(), later_group)
                self.assertEqual(json.loads((output / 'REPORT.json').read_bytes()), result)



class CliVerifiedReportNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools import qualify_hia_cli_verified_report_bundle as qualifier
        cls.manifest, cls.fixture, cls.scope = fixture_selection()
        evidence = os.environ.get(qualifier.EVIDENCE)
        cls.temporary = None
        if evidence:
            base = Path(evidence).absolute(); base.mkdir(parents=True, exist_ok=True)
            cls.folder = base / cls.__name__; cls.folder.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-verified-report-native-')
            cls.folder = Path(cls.temporary.name)
            cls.addClassCleanup(cls.temporary.cleanup)

    def test_original_140_report_and_cli_observations(self):
        from tools.hia_verified_report_controls import run_observations
        from tools.hia_cli_verified_report_custody import retained_inputs
        report = run_observations(self.folder / 'original140', self.manifest)
        expected = retained_inputs()['case_names']
        self.assertEqual(report['status'], 'PASS', report.get('traceback'))
        self.assertEqual([row['name'] for row in report['cases']], expected)
        self.assertEqual(report['case_count'], 140)
        self.assertEqual(report['failed_cases'], [])
        self.assertTrue(all(row['passed'] for row in report['cases']))
        self.assertTrue(report['source_unchanged'])
        self.assertTrue(report['session_released_without_gc'])
        self.assertGreater(report['actual_machine_frames'], 0)
        self.assertFalse(report['new_whole_verify_claim'])

    def test_report_warm_mapping_and_strict_image_readback_remain_distinct(self):
        from hepta.hia_cli_native import installed_cli, installed_cli_strict
        from hepta.hia_program import verify_program
        from tests.test_hia_program import m, f, b, c, ret
        from tools.hia_cli_verified_report_custody import binding, publish
        warm = installed_cli(str(self.manifest))
        strict = installed_cli_strict(str(self.manifest))
        self.assertIs(warm.control, strict.control)
        self.assertIs(warm.formatter, strict.formatter)
        self.assertIs(warm.routing, strict.routing)
        self.assertIs(warm.verified_report, strict.verified_report)
        document = m(f('calculate', [], ['u32'], [], [b('entry', [], [c('answer', 'u32', 7)], ret('answer'))]))
        value = verify_program(document)
        expected = value.report()
        original = warm.verified_report.invoke_bound_report(value.report)
        self.assertEqual(original, expected)
        envelope = json.loads(self.manifest.read_bytes())
        child = self.manifest.parent / envelope['verified_report_manifest']
        child_data = json.loads(child.read_bytes())
        image = child.parent / child_data['image_path']
        before = image.read_bytes()
        before_pin = binding(image)
        self.assertGreater(len(before), 0)
        observed = {'before': before_pin, 'warm_mapping_retained': False,
                    'warm_result_equal': False, 'strict_drift_rejected': False}
        try:
            image.write_bytes(bytes((before[0] ^ 1,)) + before[1:])
            same = installed_cli(str(self.manifest))
            self.assertIs(same.control, warm.control)
            self.assertIs(same.formatter, warm.formatter)
            self.assertIs(same.routing, warm.routing)
            self.assertIs(same.verified_report, warm.verified_report)
            observed['warm_mapping_retained'] = True
            self.assertEqual(same.verified_report.invoke_bound_report(value.report), expected)
            observed['warm_result_equal'] = True
            with self.assertRaises(ValueError):
                installed_cli_strict(str(self.manifest))
            observed['strict_drift_rejected'] = True
        finally:
            image.write_bytes(before)
            observed['after'] = binding(image)
            publish(self.folder / 'warm-strict-report-image.json', observed)
        self.assertEqual(observed['after'], before_pin)
        self.assertIs(installed_cli_strict(str(self.manifest)).verified_report, warm.verified_report)


if __name__ == '__main__':
    unittest.main()
