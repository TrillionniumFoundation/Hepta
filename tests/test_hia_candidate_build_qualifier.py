"""Source-only negative controls for exact candidate-build cold custody.

Synthetic shape records below are unit inputs, never matching-cold evidence.
No test here builds a native image or manufactures a positive cold fixture.
"""
from copy import deepcopy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from contextlib import redirect_stderr

from tools import qualify_hia_candidate_build as q


class CandidateBuildQualifierSourceTests(unittest.TestCase):
    def test_original_nine_business_methods_and_exact_order_remain(self):
        observed = q._original_methods()
        self.assertEqual(len(observed), 9)
        self.assertEqual(set(observed), set(q.EXPECTED_IDS))
        suite, ids = q.load_suite()
        self.assertEqual(ids, list(q.EXPECTED_IDS))
        self.assertEqual(suite.countTestCases(), 9)
        self.assertEqual(sum('.CandidateBuildSourceTests.' in value for value in ids), 5)
        self.assertEqual(sum('.CandidateBuildNativeTests.' in value for value in ids), 4)
        self.assertEqual((q.GROUP_SECONDS, q.CLEANUP_SECONDS, q.COMPILE_SECONDS, q.CAPACITY),
                         (180, 3, 20, 1048576))

    def test_cold_selection_is_explicit_nonempty_and_excludes_any_development_key(self):
        self.assertIsNone(q.selected_cold_fixture({}))
        self.assertIsNone(q.selected_cold_fixture({q.DEVELOPMENT_ENV: '/development'}))
        self.assertEqual(q.selected_cold_fixture({q.COLD_FIXTURE_ENV: '/cold/FIXTURE.json'}),
                         Path('/cold/FIXTURE.json'))
        for value in ('', None, False, 0):
            with self.subTest(empty=value), self.assertRaises(ValueError):
                q.selected_cold_fixture({q.COLD_FIXTURE_ENV: value})
        for value in ('', '/development'):
            with self.subTest(development=value), self.assertRaises(ValueError):
                q.selected_cold_fixture({q.COLD_FIXTURE_ENV: '/cold', q.DEVELOPMENT_ENV: value})

    def test_development_record_cannot_be_admitted_as_a_cold_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'BUILD.json'
            path.write_text(json.dumps({'schema': 'hepta.hia.candidate-build-bootstrap.v1',
                                        'status': 'DEVELOPMENT_NATIVE_BUILDER_CREATED',
                                        'development': True, 'cold_authority': False}))
            with mock.patch.object(q, 'admit_cold', side_effect=AssertionError('unadmitted record reached cold provider')) as call:
                with self.assertRaises(ValueError):
                    q.admit_fixture(path)
                call.assert_not_called()

    def test_outer_limits_exit_cleanup_and_exact_types_are_required(self):
        shape = {'schema': 'hepta.hia.selfhost-cold-replay.v1', 'status': 'COLD_SELFHOST_REPLAY_PASS',
                 'returncode': 0, 'qualification_wall_limit_seconds': 180, 'cleanup_wall_limit_seconds': 3,
                 'nested_report': '/shape-only/not-an-authority', 'nested_report_sha256': '0' * 64,
                 'process_owner': {'status': 'OWNED_PROCESS_COMPLETED', 'returncode': 0, 'timed_out': False,
                                   'exit_observed_before_deadline': True, 'cleanup': {'complete': True}}}
        q._outer_shape(shape)
        for key, value in [('returncode', False), ('qualification_wall_limit_seconds', 181),
                           ('qualification_wall_limit_seconds', True), ('cleanup_wall_limit_seconds', 4),
                           ('cleanup_wall_limit_seconds', 3.0), ('nested_report', '')]:
            bad = deepcopy(shape)
            bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                q._outer_shape(bad)
        for key, value in [('status', 'FAIL'), ('returncode', False), ('timed_out', 0),
                           ('timed_out', True), ('exit_observed_before_deadline', False),
                           ('exit_observed_before_deadline', 1), ('cleanup', {'complete': 1})]:
            bad = deepcopy(shape)
            bad['process_owner'][key] = value
            with self.subTest(owner_key=key, value=value), self.assertRaises(ValueError):
                q._outer_shape(bad)

    def test_invalid_real_cold_input_refuses_before_fixture_or_builder(self):
        from tools import build_hia_candidate_build as builder
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cold = root / 'not-cold.json'
            cold.write_text('{}')
            output = root / 'fixture'
            with mock.patch.object(builder, 'build', side_effect=AssertionError('builder entered before cold admission')) as call:
                with self.assertRaises(ValueError):
                    q.prepare_fixture(output, cold)
                call.assert_not_called()
            self.assertFalse(output.exists())

    def test_new_sources_and_each_catalog_source_are_required_without_omissions(self):
        from tools.build_hia_candidate_build import SOURCE_NAMES
        from tools.generate_hia_candidate_build import catalog
        names = q.required_source_names()
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(set(SOURCE_NAMES) <= set(names))
        self.assertTrue(set(q.EXTRA_REQUIRED_SOURCES) <= set(names))
        self.assertTrue({'examples/hia_bootstrap/' + row['source_name'] for row in catalog()} <= set(names))
        actual = {name: sha256((q.ROOT / name).read_bytes()).hexdigest() for name in names}
        q._admit_required_sources(actual)
        for name in names:
            with self.subTest(missing=name):
                bad = dict(actual)
                del bad[name]
                with self.assertRaises(ValueError):
                    q._admit_required_sources(bad)
            with self.subTest(changed=name):
                bad = {**actual, name: '0' * 64}
                with self.assertRaises(ValueError):
                    q._admit_required_sources(bad)

    def test_frozen_input_binding_rejects_bytes_modes_duplicates_and_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'input'
            path.write_bytes(b'original')
            before = q._pin(path)
            q._check_bindings([before])
            with self.assertRaises(ValueError):
                q._check_bindings([before, before])
            path.write_bytes(b'different')
            with self.assertRaises(ValueError):
                q._check_bindings([before])
            path.write_bytes(b'original')
            path.chmod(before['mode'] ^ 0o100)
            with self.assertRaises(ValueError):
                q._check_bindings([before])
            path.chmod(before['mode'])
            alias = path.parent / 'alias'
            alias.symlink_to(path)
            with self.assertRaises(ValueError):
                q._pin(alias)
            q._check_bindings([before])

    def test_actual_request_requires_all_nine_fields_and_original_exact_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            image, source, output = folder / 'image', folder / 'case.input.bin', folder / 'case.output.bin'
            image.write_bytes(b'\xc3')
            source.write_bytes(b'unit-input')
            output.write_bytes(b'unit-output')
            (folder / 'case.receipt.json').write_text('{}')
            request = {'capacity': q.CAPACITY, 'format': 'flat-x86-64', 'image': str(image),
                       'image_sha256': sha256(image.read_bytes()).hexdigest(), 'output': str(output),
                       'source': str(source), 'source_sha256': sha256(source.read_bytes()).hexdigest(),
                       'workspace_fill': 0, 'workspace_size': q.CAPACITY}
            changes = [('capacity', True), ('capacity', q.CAPACITY + 1), ('workspace_size', True),
                       ('workspace_fill', 1), ('workspace_fill', False), ('image_sha256', '0' * 64),
                       ('source_sha256', '0' * 64), ('format', 'linked-selfhost'),
                       ('source', str(folder / 'another')), ('extra', 1)]
            for key, value in changes:
                bad = {**request, key: value}
                (folder / 'case.request.json').write_text(json.dumps(bad))
                with self.subTest(key=key, value=value), mock.patch(
                        'tools.qualify_hia_selfhost._compile_observation_size',
                        side_effect=AssertionError('invalid request reached receipt admission')) as call:
                    with self.assertRaises(ValueError):
                        q._observation(folder, 'case', image, source.read_bytes())
                    call.assert_not_called()
            for key in request:
                bad = dict(request)
                del bad[key]
                (folder / 'case.request.json').write_text(json.dumps(bad))
                with self.subTest(missing=key), self.assertRaises(ValueError):
                    q._observation(folder, 'case', image, source.read_bytes())

    def test_complete_observation_schema_rejects_skips_counts_ids_and_missing_frames(self):
        report = {'schema': 'hepta.hia.candidate-build-observations.v1', 'scope': 'OBSERVATIONS_ONLY_NO_COLD_AUTHORITY',
                  'status': 'PASS', 'request_sha256': 'shape-only', 'loaded_ids': list(q.EXPECTED_IDS),
                  'started_ids': list(q.EXPECTED_IDS), 'stopped_ids': list(q.EXPECTED_IDS), 'tests_run': 9,
                  'source_and_inputs_unchanged': True, 'anomalies': {name: [] for name in q.ANOMALIES},
                  'native_observations': [{} for _ in range(75)], 'vm_observations': [{} for _ in range(69)]}
        q.admit_child_report(report, 'shape-only')
        for key, value in [('tests_run', 8), ('tests_run', 9.0), ('source_and_inputs_unchanged', 1),
                           ('loaded_ids', list(q.EXPECTED_IDS[:-1])), ('started_ids', list(reversed(q.EXPECTED_IDS))),
                           ('stopped_ids', list(q.EXPECTED_IDS[:-1])), ('native_observations', [{}] * 74),
                           ('vm_observations', [{}] * 68), ('scope', 'MATCHING_COLD_AUTHORITY')]:
            bad = {**report, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                q.admit_child_report(bad, 'shape-only')
        for name in q.ANOMALIES:
            bad = deepcopy(report)
            bad['anomalies'][name] = ['unit-anomaly']
            with self.subTest(anomaly=name), self.assertRaises(ValueError):
                q.admit_child_report(bad, 'shape-only')

    def test_development_bootstrap_never_enters_production_receipt_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / 'BUILD.json').write_text(json.dumps({'schema': 'hepta.hia.candidate-build-bootstrap.v1',
                'status': 'DEVELOPMENT_NATIVE_BUILDER_CREATED', 'development': True, 'cold_authority': False}))
            with mock.patch.object(q, '_compile_observation', side_effect=AssertionError('development reached cold receipts')) as call:
                with self.assertRaises(ValueError):
                    q._production_build(folder, {})
                call.assert_not_called()

    def test_matching_cold_flag_requires_fresh_actual_authority_again(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cold = root / 'invalid-cold.json'
            cold.write_text('{}')
            path = root / 'FIXTURE.json'
            path.write_text(json.dumps({'schema': q.FIXTURE_SCHEMA, 'status': q.FIXTURE_STATUS,
                'matching_cold': True, 'qualification_complete': False, 'whole_native': False,
                'authority': {'cold_report': str(cold)}}))
            with mock.patch.object(q, 'admit_cold', wraps=q.admit_cold) as call, mock.patch.object(
                    q, '_fixture_description', side_effect=AssertionError('cached flag reached production fixture')) as describe:
                with self.assertRaises(ValueError):
                    q.admit_fixture(path)
                call.assert_called_once_with(str(cold))
                describe.assert_not_called()

    def test_qualifier_cli_cannot_select_a_development_compiler_or_fixture(self):
        for extra in (['--development'], ['--compiler', '/unknown-compiler']):
            with self.subTest(option=extra), mock.patch('sys.argv', ['qualifier', '--cold-report', '/cold',
                    '--evidence', '/output', *extra]), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    q.main()
                self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
