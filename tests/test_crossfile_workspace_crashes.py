"""Actual native checkpoint deaths plus semantic evidence mutation controls.

These unit tests explicitly use fixture process separation. Only the separate
qualification command can claim strict namespace execution, and it has no
fixture-mode option and no fallback when namespaces are unavailable.
"""
from __future__ import annotations

import copy
import json
import os
import unittest
from unittest.mock import patch

from hepta.backend import find_rustc
from experiments.agent_eval.harness import EvalError
from experiments.crossfile_eval.records import seal_record
from experiments.crossfile_eval.scoring import compiler_identity
from experiments.crossfile_eval.tasks import canonical, digest, task_request
from experiments.crossfile_eval.workspace_session import ProductionWorkspaceSession
from experiments.crossfile_eval.workspace_crash_qualification import (
    _CrashQualificationSession, _qualify_case, _reference_edits, qualify_workspace_crashes,
)
from experiments.crossfile_eval.workspace_crash_evidence import validate_crash_case


def native():
    try:
        return find_rustc(os.environ.get('RUSTC'))
    except Exception as exc:
        raise unittest.SkipTest('native compiler unavailable: ' + str(exc)) from exc


class CrossfileCheckpointDeathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rustc = native()
        cls.compiler = compiler_identity(cls.rustc)
        cls.cases = {point: _qualify_case('api_migration', point, cls.compiler, rustc=cls.rustc, fixture=True)
                     for point in ('prepared', 'published')}
        for point, record in cls.cases.items():
            if record.get('status') != 'qualified':
                raise AssertionError((point, record.get('error'), record.get('score')))

    def test_prepublication_death_recovers_old_then_identical_request_commits(self):
        run = self.cases['prepared']
        self.assertTrue(validate_crash_case(run, require_namespace=False))
        events = run['session']['events']
        self.assertEqual(events[5]['process_returncode'], 71)
        self.assertEqual(events[7]['recovery'], 'aborted')
        self.assertEqual(events[8]['recovery'], 'aborted')
        self.assertEqual(events[6]['current_snapshot'], run['initial_snapshot'])
        self.assertEqual(events[5]['patch_sha256'], events[9]['patch_sha256'])
        self.assertTrue(run['retry']['applied'])
        self.assertEqual(run['score']['passed'], 75)

    def test_postpublication_death_recovers_new_and_rejects_stale_retry(self):
        run = self.cases['published']
        self.assertTrue(validate_crash_case(run, require_namespace=False))
        events = run['session']['events']
        self.assertEqual(events[5]['process_returncode'], 71)
        self.assertEqual(events[6]['current_snapshot'], run['prepared_snapshot'])
        self.assertEqual(events[7]['recovery'], 'committed')
        self.assertFalse(run['retry']['applied'])
        self.assertEqual(run['retry']['diagnostics'][0]['code'], 'E_STALE_PROJECT')
        self.assertFalse(run['session']['committed'])  # no successful reply was received
        self.assertFalse(run['session']['production_workspace_v4_exercised'])
        self.assertTrue(run['claims']['workspace_crash_recovery_exercised'])
        self.assertEqual(events[11]['old_pinned_snapshot'], run['initial_snapshot'])

    def test_process_separation_evidence_cannot_claim_strict_namespaces(self):
        with self.assertRaisesRegex(ValueError, 'namespace'):
            validate_crash_case(self.cases['prepared'])

    def test_resealed_semantic_mutations_do_not_pass_as_completed_crashes(self):
        mutations = {
            'normal_exit': lambda r: r['session']['events'][5].update(process_returncode=0),
            'timeout': lambda r: r['session']['events'][5].update(process_status='timeout'),
            'fake_ack': lambda r: r['session']['events'][5].update(ok=True, applied=True),
            'wrong_marker_point': lambda r: r['session']['events'][5]['crash_marker'].update(checkpoint='published'),
            'no_independent_gate': lambda r: r['session']['events'].pop(4),
            'wrong_gate_source': lambda r: r['session']['events'][4]['result'].update(source_sha256=r['base_sha256']),
            'wrong_recovery': lambda r: r['session']['events'][7].update(recovery='committed'),
            'lost_historical_pin': lambda r: r['session']['events'][11].update(old_pinned_snapshot=r['prepared_snapshot']),
            'retry_rebased': lambda r: r['session']['events'][9]['patch_preconditions'].update(expected_version=r['submitted_version']),
            'wrong_score_source': lambda r: r['score'].update(source_sha256=r['base_sha256']),
            'fewer_cases': lambda r: r['score'].update(passed=74, total=74),
            'fake_model': lambda r: r.update(actual_ai_model_runs=1),
            'deadline_laundered': lambda r: r.update(wall_seconds=0),
            'native_failure_hidden': lambda r: r['score'].update(native_returncode=11),
            'ambiguous_rollback': lambda r: r['injected_failure'].update(publication_state='rolled_back'),
            'profile_changed': lambda r: r['session']['profile'].update(rustc_sha256='0' * 64),
            'malformed_session': lambda r: r.update(session=None),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = copy.deepcopy(self.cases['prepared'])
                mutate(changed)
                if name == 'wrong_marker_point':
                    event = changed['session']['events'][5]
                    event['crash_marker_sha256'] = digest(canonical(event['crash_marker']))
                with self.assertRaises(ValueError):
                    validate_crash_case(seal_record(changed), require_namespace=False)

    def test_deadline_exhaustion_is_retained_as_failed_not_a_qualified_case(self):
        with patch('experiments.crossfile_eval.workspace_crash_qualification.CASE_WALL_SECONDS', 0.0):
            result = _qualify_case('api_migration', 'prepared', self.compiler, rustc=self.rustc, fixture=True)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['error']['code'], 'E_WALL_BUDGET')
        self.assertIsNone(result['score'])
        self.assertFalse(result['claims']['workspace_crash_recovery_exercised'])

    def test_unsupported_namespace_never_runs_fixture_fallback(self):
        with patch('experiments.crossfile_eval.workspace_crash_qualification.probe_sandbox',
                   return_value={'available': False, 'reason': 'unit-test unavailable host'}), \
             patch('experiments.crossfile_eval.workspace_crash_qualification._qualify_case',
                   side_effect=AssertionError('must not start a task without namespaces')):
            result = qualify_workspace_crashes(self.rustc)
        self.assertEqual(result['status'], 'environment_blocked')
        self.assertEqual(len(result['planned_cases']), 10)
        self.assertEqual(result['runs'], [])
        self.assertEqual(result['actual_ai_model_runs'], 0)

    def test_normal_provider_worker_has_no_fault_injection_capability(self):
        session = ProductionWorkspaceSession(task_request('defect_repair', 'hepta'), rustc=self.rustc, fixture=True)
        self.addCleanup(session.close)
        self.assertFalse((session.directory / 'workspace_crash_frontend.py').exists())
        indexed = session.execute('query_nodes', {}, 10)
        edits = _reference_edits(session, 'defect_repair', 10)
        for edit in edits:
            node = next(n for n in indexed['nodes'][edit['target']] if n['id'] == edit['node'])
            edit['op'] = 'replace_' + node['native_kind']
        request = {'schema': 'hepta.patch.v4', 'expected_version': session.version,
                   'expected_interface_sha256': session.interface_sha256, 'interface_policy': 'preserve', 'edits': edits}
        # The normal wire helper ignores this unrecognized field. It cannot
        # turn a JSON argument into the private Python checkpoint callback.
        result = session._rpc('commit', 15, patch=request, qualification_checkpoint='published')
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['applied'])
        self.assertEqual(session.events[-1]['process_returncode'], 0)

    def test_missing_crash_is_rejected_even_with_a_copied_good_marker(self):
        request = {'schema': 'hepta.patch.v4', 'expected_version': '1' * 64,
                   'expected_interface_sha256': '2' * 64, 'interface_policy': 'preserve', 'edits': []}
        for status, code in (('exited', 0), ('timeout', 71), ('exited', -9)):
            with self.subTest(status=status, code=code):
                session = _CrashQualificationSession(task_request('defect_repair', 'hepta'), 'prepared',
                                                     rustc=self.rustc, fixture=True)
                self.addCleanup(session.close)
                marker = copy.deepcopy(self.cases['prepared']['session']['events'][5]['crash_marker'])
                marker['patch_sha256'] = digest(canonical(request))
                with patch('experiments.crossfile_eval.workspace_crash_qualification.run_bounded', return_value={
                        'status': status, 'returncode': code, 'stdout': json.dumps(marker), 'stderr': ''}):
                    with self.assertRaises(EvalError) as caught:
                        session._rpc('commit', 1, patch=request)
                self.assertEqual(caught.exception.code, 'E_WORKSPACE_CRASH_NOT_OBSERVED')
                self.assertFalse(session.fault_observed)
                self.assertEqual(session.publication_state, 'unverified_after_commit')
                session.close()


if __name__ == '__main__':
    unittest.main()
