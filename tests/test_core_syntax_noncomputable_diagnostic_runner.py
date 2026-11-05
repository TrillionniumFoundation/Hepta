"""Independent mock integration of the explicit noncomputable diagnostic mode.

No Lean is executed. Exit-zero mocks cannot establish theorem or bridge proofs.
"""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from tools import diagnose_core_syntax_declarations as runner
from tools import check_core_syntax_staged as base
from tools import core_syntax_diagnostic_capture as collector
from tools.core_syntax_structured_stages import build_inputs
from tools.core_syntax_noncomputable_diagnostic_sources import build_noncomputable_diagnostic


class NoncomputableDiagnosticRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = build_inputs()
        cls.candidate = build_noncomputable_diagnostic(cls.prepared)

    def exercise(self, behavior='success', *, candidate=None, mode=True, preflight_failure=False):
        candidate = self.candidate if candidate is None else candidate
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            executable = home / 'pinned/bin/lean'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'nonexecutable mock only')
            (home / 'pinned/lib/lean').mkdir(parents=True)
            identity = {'mock-source': 'a' * 64}
            support = {'lib/lean/Init.olean': 'b' * 64,
                       'lib/lean/Lean/Elab/Tactic/Omega.olean': 'c' * 64}
            calls, launched_sources, capture_attempts = [], [], []

            def invoke(exe, source, output, root):
                self.assertIn(source.stem, ('Baseline', 'SyntaxData'))
                calls.append(source.stem)
                stage = next(item for item in self.prepared['stages'] if item.name == source.stem)
                self.assertEqual(source.read_bytes(), stage.source.encode())
                launched_sources.append(source.read_text())
                output.write_bytes(b'mocked parent olean: ' + stage.name.encode())
                return {'returncode': 0, 'timed_out': False, 'incomplete': False,
                        'output_truncated': False, 'stderr': '',
                        'stdout': '\n'.join("'" + name + "' does not depend on any axioms"
                                            for name in sorted(stage.expected_theorems)) + '\n'}

            def capture(exe, source, output, root, *, safe_root, markers, manifest_reference):
                capture_attempts.append(source.stem)
                self.assertEqual(source.stem, 'LinearTransport')
                self.assertEqual(source.read_bytes(), candidate.stages[2].source.encode())
                self.assertEqual(markers, candidate.markers)
                self.assertEqual(manifest_reference, {'path': 'diagnostic-manifest.json',
                                                     'sha256': candidate.manifest_sha256})
                self.assertNotEqual(source.read_text(), candidate.marker_source)
                self.assertEqual(source.read_text().count('noncomputable def '), 1537)
                for name, text in candidate.retained_extra_sources.items():
                    self.assertEqual(safe_root.read(name, base.MAX_SOURCE), text.encode())
                    self.assertNotEqual(root / name, source)
                if behavior == 'platform':
                    return {'status': 'diagnostic_infrastructure_failed', 'process_started': False,
                            'leader_reaped': False, 'drain_complete': False, 'cleanup_deadline_exceeded': False,
                            'cleanup_incomplete': False, 'output_truncated': False, 'returncode': None,
                            'files': {}, 'raw_files': {}, 'metadata_remaining_bytes': collector.METADATA_LIMIT}
                calls.append(source.stem)
                launched_sources.append(source.read_text())
                process = dict(status='diagnostic_timeout' if behavior=='timeout' else 'diagnostic_completed',
                               process_started=True, returncode=0, leader_reaped=True, drain_complete=True,
                               cleanup_deadline_exceeded=False, cleanup_incomplete=False, output_truncated=False,
                               manifest_reference=manifest_reference)
                events = collector._record_bytes(dict(kind='terminal', process=process,
                    accounting_before_terminal=dict(raw_written_bytes=len(b'nonaccepting mock output'), metadata_written_bytes=0)))
                for name, data in zip(collector.DIAGNOSTIC_FILES, (b'nonaccepting mock output', b'', events)):
                    safe_root.write(name, data)
                output.write_bytes(b'candidate output must never be admitted')
                if behavior == 'changed_source':
                    source.write_bytes(source.read_bytes() + b'\n-- changed after capture began\n')
                elif behavior == 'changed_manifest':
                    path = root / 'diagnostic-manifest.json'
                    path.write_bytes(path.read_bytes() + b' ')
                elif behavior == 'changed_retained_marker':
                    path = root / next(iter(candidate.retained_extra_sources))
                    path.write_bytes(path.read_bytes() + b'\n-- changed retained M\n')
                files = {}
                for name in collector.DIAGNOSTIC_FILES:
                    raw = (root / name).read_bytes()
                    files[name] = {'path': name, 'bytes': len(raw), 'sha256': base.digest(raw)}
                return {**process, 'files': files,
                        'raw_files': {name: info for name, info in files.items()
                                      if name != 'LinearTransport.events.jsonl'},
                        'metadata_remaining_bytes': collector.METADATA_LIMIT - files['LinearTransport.events.jsonl']['bytes']}

            def execute():
                return runner.execute_diagnostic(executable, home / 'out', self.prepared, candidate,
                                                 identity, support, lambda: identity, lambda _: support,
                                                 base.digest(executable.read_bytes()), run_process=invoke,
                                                 capture=capture, noncomputable=mode)

            if preflight_failure:
                with self.assertRaises((ValueError, KeyError)):
                    execute()
                self.assertEqual(calls, [])
                self.assertEqual(capture_attempts, [])
                self.assertFalse((home / 'out').exists())
                return None
            report = execute()
            self.assertEqual(json.loads((home / 'out/RESULT.json').read_text()), report)
            self.assertEqual(report['data_codegen_mode'], 'explicit_noncomputable')
            self.assertEqual(report['authority'], 'DENY_ALL')
            self.assertEqual(len(report['obligations']), 12)
            self.assertTrue(all(item['status'] == 'unproved' for item in report['obligations']))
            for flag in ('kernel_core_syntax_connection_checked', 'actual_core_bridge_proved',
                         'python_exporter_refinement_proved', 'body_prefix_refinement_proved',
                         'all_edge_transfer_proved', 'initialization_elision_authorized',
                         'native_admission', 'production_admission', 'performance_qualified', 'quota_equivalence'):
                self.assertIs(report[flag], False)
            self.assertLessEqual(report['invocations'], 3)
            self.assertEqual(len(report['not_scheduled']), 7)
            self.assertLessEqual(len(capture_attempts), 1)
            self.assertNotIn(candidate.marker_source, launched_sources)
            self.assertFalse((home / 'out/LinearTransport.finished.json').exists())
            for stage in report['stages']:
                if stage['name'] == 'LinearTransport':
                    self.assertNotIn('olean', stage)
            return report, calls, capture_attempts

    def test_exact_candidate_and_unchanged_parents_only_three_stages_always_deny(self):
        report, calls, attempts = self.exercise()
        self.assertEqual(report['status'], 'diagnostic_completed')
        self.assertEqual(calls, ['Baseline', 'SyntaxData', 'LinearTransport'])
        self.assertEqual(attempts, ['LinearTransport'])
        self.assertEqual(report['invocations'], 3)
        self.assertEqual(tuple(stage.name for stage in self.candidate.stages),
                         ('Baseline', 'SyntaxData', 'LinearTransport'))
        retained = sum(stage.source_bytes for stage in self.prepared['stages'])
        retained += self.candidate.stages[2].source_bytes
        retained += sum(len(value.encode()) for value in self.candidate.retained_extra_sources.values())
        self.assertEqual(retained, self.candidate.manifest['retained_total_source_bytes'])
        self.assertLessEqual(retained, base.MAX_TOTAL_SOURCE)

    def test_platform_refusal_never_falls_back_to_original_marker_source(self):
        report, calls, attempts = self.exercise('platform')
        self.assertEqual(report['status'], 'diagnostic_infrastructure_failed')
        self.assertEqual(calls, ['Baseline', 'SyntaxData'])
        self.assertEqual(attempts, ['LinearTransport'])
        self.assertEqual(report['invocations'], 2)

    def test_timeout_never_retries_candidate_or_original_marker_source(self):
        report, calls, attempts = self.exercise('timeout')
        self.assertEqual(report['status'], 'diagnostic_timeout')
        self.assertEqual(calls, ['Baseline', 'SyntaxData', 'LinearTransport'])
        self.assertEqual(attempts, ['LinearTransport'])

    def test_candidate_source_rewrite_after_launch_fails_identity_gate(self):
        report, calls, _ = self.exercise('changed_source')
        self.assertEqual(report['status'], 'diagnostic_failed')
        self.assertIn('diagnostic source changed', report['error'])
        self.assertEqual(len(calls), 3)

    def test_combined_marker_manifest_rewrite_fails_identity_gate(self):
        report, calls, _ = self.exercise('changed_manifest')
        self.assertEqual(report['status'], 'diagnostic_failed')
        self.assertIn('diagnostic source changed', report['error'])
        self.assertEqual(len(calls), 3)

    def test_retained_original_marker_source_rewrite_fails_identity_gate(self):
        report, calls, _ = self.exercise('changed_retained_marker')
        self.assertEqual(report['status'], 'diagnostic_failed')
        self.assertIn('diagnostic source changed', report['error'])
        self.assertEqual(len(calls), 3)

    def test_original_mode_and_non_boolean_flags_reject_candidate_before_launch(self):
        for mode in (False, 1, 'true', None):
            with self.subTest(mode=repr(mode)):
                self.exercise(mode=mode, preflight_failure=True)

    def test_wrong_source_substitution_is_rejected_before_any_launch(self):
        stages = list(self.candidate.stages)
        stages[2] = replace(stages[2], source=self.candidate.marker_source)
        wrong = replace(self.candidate, stages=tuple(stages))
        self.exercise(candidate=wrong, preflight_failure=True)
