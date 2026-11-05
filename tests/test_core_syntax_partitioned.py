"""Exact eleven-stage admission controls under mocks, never kernel evidence."""
from contextlib import ExitStack, redirect_stdout, redirect_stderr
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import check_core_syntax_partitioned as runner
from tools import check_core_syntax_staged as base
from tools import core_syntax_partition_sources as sources


class PartitionedRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = sources.build_inputs()

    def exercise(self, *, fail_at=None, behavior=None, change_at='CertPart02', patches=()):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            home = Path(folder)
            executable = home / 'pinned/bin/lean'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'never execute this mock')
            (home / 'pinned/lib/lean').mkdir(parents=True)
            identity = {'source': 'a' * 64}
            support = {'lib/lean/Init.olean': 'b' * 64,
                       'lib/lean/Lean/Elab/Tactic/Omega.olean': 'c' * 64}
            current_identity, current_support = dict(identity), dict(support)
            calls = []
            produced = {}

            def invoke(exe, source, output, root):
                stage = next(s for s in self.prepared['stages'] if s.name == source.stem)
                calls.append(stage.name)
                self.assertEqual(source.read_bytes(), stage.source.encode())
                started = json.loads((root / (stage.name + '.started.json')).read_text())
                self.assertEqual(started['status'], 'running')
                self.assertEqual(started['source_sha256'], stage.source_sha256)
                self.assertEqual(set(started['parents']), set(stage.parents))
                self.assertEqual(set(started['parent_receipts']), set(stage.parents))
                for receipt in started['parent_receipts'].values():
                    self.assertEqual(receipt['sha256'], base.digest((root / receipt['path']).read_bytes()))
                for parent in started['parents'].values():
                    self.assertIn(parent['successful_stage'], calls[:-1])
                    self.assertEqual(parent['sha256'], base.digest((root / parent['path']).read_bytes()))
                output.write_bytes(b'mock olean ' + stage.name.encode())
                produced[stage.name] = output
                lines = ["'" + name + "' does not depend on any axioms" for name in sorted(stage.expected_theorems)]
                result = {'returncode': 0, 'timed_out': False, 'incomplete': False,
                          'output_truncated': False, 'stdout': '\n'.join(lines), 'stderr': ''}
                if stage.name == fail_at:
                    result.update(returncode=1, stderr='error: forced stage failure')
                if stage.name == change_at:
                    if behavior == 'missing_inventory':
                        result['stdout'] = '\n'.join(lines[1:])
                    elif behavior == 'duplicate_inventory':
                        result['stdout'] += '\n' + lines[0]
                    elif behavior == 'wrong_inventory':
                        result['stdout'] += "\n'Unexpected.theorem' does not depend on any axioms"
                    elif behavior == 'sorry_axiom':
                        result['stdout'] = result['stdout'].replace('does not depend on any axioms',
                                                                   'depends on axioms: [sorryAx]', 1)
                    elif behavior == 'changed_parent':
                        produced['CertPart01'].write_bytes(b'parent substituted after check')
                    elif behavior == 'changed_parent_receipt':
                        (root / 'CertPart01.finished.json').write_bytes(b'{}\n')
                    elif behavior in ('changed_stdout', 'changed_stderr', 'changed_run', 'changed_started'):
                        target = {'changed_stdout': 'Baseline.stdout', 'changed_stderr': 'Baseline.stderr',
                                  'changed_run': 'RUN.json', 'changed_started': 'Baseline.started.json'}[behavior]
                        (root / target).write_bytes(b'tampered evidence')
                    elif behavior == 'changed_manifest':
                        (root / 'manifest.json').write_bytes(b'{}\n')
                    elif behavior == 'changed_binary':
                        executable.write_bytes(b'replaced executable')
                    elif behavior == 'changed_support':
                        current_support['lib/lean/Init.olean'] = 'd' * 64
                    elif behavior == 'changed_source_identity':
                        current_identity['source'] = 'd' * 64
                    elif behavior == 'changed_source':
                        source.write_bytes(source.read_bytes() + b'\n-- altered\n')
                    elif behavior == 'unexpected_output':
                        (root / 'unrequested.so').write_bytes(b'forbidden')
                    elif behavior == 'missing_olean':
                        output.unlink()
                return result

            for name, value in patches:
                stack.enter_context(patch.object(base, name, value))
            report = runner.execute_partitioned(executable, home / 'out', self.prepared, identity, support,
                                                 lambda: dict(current_identity), lambda _: dict(current_support),
                                                 base.digest(executable.read_bytes()), run_process=invoke)
            self.assertEqual(json.loads((home / 'out/RESULT.json').read_text()), report)
            self.assertEqual(report['protocol'], sources.PROTOCOL)
            self.assertEqual(report['expected_stage_count'], 11)
            self.assertIsNone(report['diagnostic_stage_limit'])
            self.assertEqual(report['authority'], 'DENY_ALL')
            self.assertEqual(len(report['obligations']), 12)
            self.assertTrue(all(item['status'] == 'unproved' for item in report['obligations']))
            for flag in ('actual_core_bridge_proved', 'python_exporter_refinement_proved',
                         'body_prefix_refinement_proved', 'all_edge_transfer_proved',
                         'initialization_elision_authorized', 'native_admission',
                         'production_admission', 'performance_qualified', 'quota_equivalence'):
                self.assertIs(report[flag], False)
            self.assertLessEqual(report['invocations'], 11)
            if behavior is None:
                displayed = io.StringIO()
                with redirect_stdout(displayed):
                    runner.print_diagnostics(home / 'out')
                self.assertIn('RESULT.json', displayed.getvalue())
            return report, calls

    def test_complete_eleven_stage_mock_requires_full_roots_inventory_and_negatives(self):
        report, calls = self.exercise()
        self.assertEqual(report['status'], 'passed', report.get('error'))
        self.assertTrue(report['kernel_core_syntax_connection_checked'])
        self.assertEqual(calls, list(runner.STAGES))
        self.assertEqual(report['invocations'], 11)
        self.assertEqual(set(report['frozen_receipt_sha256']),
                         {'manifest.json', 'RUN.json'} | {name + suffix for name in runner.STAGES
                          for suffix in ('.started.json', '.stdout', '.stderr', '.finished.json')})
        self.assertEqual(set(report['modules']), {s.module_name for s in self.prepared['stages']})
        self.assertEqual(set(report['theorems']), set(self.prepared['expected_theorems']))
        self.assertEqual(len(report['theorems']), 66)
        self.assertEqual(set(report['rejection_certificates']), base.NEGATIVES)
        for key, binding in self.prepared['manifest']['inputs'].items():
            self.assertEqual(sum(binding['theorem_counts'].values()), 843)
            self.assertIn(binding['root_owner'], report['modules'])

    def test_failure_at_each_of_eleven_stages_stops_every_successor(self):
        for index, name in enumerate(runner.STAGES):
            with self.subTest(stage=name):
                report, calls = self.exercise(fail_at=name)
                self.assertEqual(report['status'], 'failed')
                self.assertFalse(report['kernel_core_syntax_connection_checked'])
                self.assertEqual(calls, list(runner.STAGES[:index + 1]))
                self.assertEqual(report['stages'][-1]['status'], 'failed')
                self.assertNotIn('olean', report['stages'][-1])

    def test_missing_duplicate_extra_or_sorry_inventory_cannot_admit_partition(self):
        for behavior in ('missing_inventory', 'duplicate_inventory', 'wrong_inventory', 'sorry_axiom'):
            with self.subTest(behavior=behavior):
                report, calls = self.exercise(behavior=behavior)
                self.assertEqual(report['status'], 'failed')
                self.assertFalse(report['kernel_core_syntax_connection_checked'])
                self.assertEqual(calls[-1], 'CertPart02')

    def test_successful_partitions_cannot_replace_final_positive_or_negative_inventory(self):
        for stage in ('Connections', 'TransportRejections', 'WrongArm'):
            with self.subTest(stage=stage):
                report, calls = self.exercise(behavior='missing_inventory', change_at=stage)
                self.assertEqual(report['status'], 'failed')
                self.assertFalse(report['kernel_core_syntax_connection_checked'])
                self.assertEqual(calls[-1], stage)

    def test_parent_module_change_stops_chain_without_reusing_old_success(self):
        for behavior in ('changed_parent', 'changed_parent_receipt', 'changed_manifest',
                         'changed_stdout', 'changed_stderr', 'changed_run', 'changed_started'):
            with self.subTest(behavior=behavior):
                report, calls = self.exercise(behavior=behavior)
                self.assertEqual(report['status'], 'failed')
                self.assertFalse(report['kernel_core_syntax_connection_checked'])
                self.assertEqual(calls, list(runner.STAGES[:4]))
                expected = 'accepted module changed' if behavior == 'changed_parent' else 'partition frozen receipt changed'
                self.assertIn(expected, report['error'])

    def test_binary_support_source_and_output_identity_changes_fail_closed(self):
        for behavior in ('changed_binary', 'changed_support', 'changed_source_identity',
                         'changed_source', 'unexpected_output', 'missing_olean'):
            with self.subTest(behavior=behavior):
                report, calls = self.exercise(behavior=behavior, change_at='CertPart01')
                self.assertEqual(report['status'], 'failed')
                self.assertFalse(report['kernel_core_syntax_connection_checked'])
                self.assertEqual(calls, list(runner.STAGES[:3]))

    def test_expired_launch_deadline_starts_nothing(self):
        report, calls = self.exercise(patches=(('LAUNCH_SECONDS', 0),))
        self.assertEqual(report['status'], 'failed')
        self.assertFalse(report['kernel_core_syntax_connection_checked'])
        self.assertEqual(calls, [])
        self.assertEqual(base.MAX_INVOCATIONS, 11)
        self.assertEqual(base.PROCESS_SECONDS, 60)
        self.assertEqual(base.LAUNCH_SECONDS, 540)

    def test_twelfth_stage_legacy_unknown_protocol_and_partial_mode_are_rejected(self):
        variants = [self.prepared['original_prepared'],
                    dict(self.prepared, stages=self.prepared['stages'] + self.prepared['stages'][-1:])]
        unknown = dict(self.prepared)
        unknown['manifest'] = dict(self.prepared['manifest'], protocol='unknown-partition-v99')
        variants.append(unknown)
        for prepared in variants:
            with self.subTest(protocol=prepared['manifest'].get('protocol')):
                with patch.object(base, 'execute_plan') as run:
                    with self.assertRaises(ValueError):
                        runner.execute_partitioned(None, None, prepared, {}, {}, None, None, '')
                    run.assert_not_called()
        with patch.object(base, 'validate_plan') as validate:
            with self.assertRaisesRegex(ValueError, 'complete eleven-stage'):
                base.execute_plan(None, None, self.prepared, {}, {}, None, None, '', stage_limit=2)
            validate.assert_not_called()
        # Historical ten-stage validation remains valid only through its own path.
        base.validate_plan(self.prepared['original_prepared'])
        with self.assertRaises(ValueError):
            base.validate_plan(unknown)

    def test_pinned_binary_cannot_be_reset_during_partition_preparation(self):
        from tools import check_core_syntax_lean as original
        from tools import qualify_hia_selected_formal as checker
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)
            executable = root / 'pinned/bin/lean'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'pinned mock')
            pinned = base.digest(executable.read_bytes())
            (root / 'formal').mkdir()
            (root / 'formal/toolchain-lock.json').write_text(json.dumps({'lean_binary_sha256': pinned}))
            support = {'lib/lean/Init.olean': 'a' * 64,
                       'lib/lean/Lean/Elab/Tactic/Omega.olean': 'b' * 64}
            def prepare():
                executable.write_bytes(b'not the pinned mock')
                return self.prepared
            stack.enter_context(patch.object(runner, 'ROOT', root))
            stack.enter_context(patch.object(runner, 'source_identity', return_value={'mock': 'c' * 64}))
            stack.enter_context(patch.object(checker, '_support_identity', return_value=support))
            stack.enter_context(patch.object(original, 'fixed_input', return_value={'bytes': self.prepared['canonical_bytes']}))
            stack.enter_context(patch.object(sources, 'build_inputs', side_effect=prepare))
            launch = stack.enter_context(patch.object(base.subprocess, 'run'))
            with self.assertRaisesRegex(ValueError, 'pinned Lean binary changed before execution'):
                runner.qualify(executable, root / 'out')
            launch.assert_not_called()
            self.assertFalse((root / 'out').exists())

    def test_source_identity_binds_new_cli_source_and_existing_security_dependencies(self):
        identity = runner.source_identity()
        for name in ('tools/check_core_syntax_partitioned.py', 'tools/core_syntax_partition_sources.py',
                     'tools/check_core_syntax_staged.py', 'tools/core_syntax_structured_sources.py',
                     'tools/core_syntax_structured_stages.py', 'tools/core_syntax_stage_sources.py',
                     'experiments/hia_initialization_frontiers_20261103/StructuredTransport.lean'):
            self.assertEqual(identity[name], base.digest((runner.ROOT / name).read_bytes()))

    def test_fixed_diagnostic_reader_covers_all_six_parts_without_directory_discovery(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for i in range(1, 7):
                (root / f'CertPart{i:02d}.stdout').write_text(f'part {i}')
            (root / 'LinearTransport.stdout').write_text('old layout secret')
            (root / 'unrequested.txt').write_text('unexpected secret')
            (root / 'CertPart01.olean').write_text('module must not print')
            output = io.StringIO()
            with redirect_stdout(output):
                runner.print_diagnostics(root)
            self.assertIn('Incomplete diagnostic output', output.getvalue())
            self.assertNotIn('part 1', output.getvalue())
            (root / 'RUN.json').write_bytes(b'{}')
            (root / 'Baseline.started.json').write_bytes(b'{}')
            (root / 'Baseline.stderr').write_bytes(b'')
            (root / 'manifest.json').write_bytes(b'{}')
            frozen = {name: base.digest((root / name).read_bytes())
                      for name in (*runner.DIAGNOSTIC_FILES, 'manifest.json')
                      if name != 'RESULT.json' and (root / name).exists()}
            result = {'protocol': runner.PROTOCOL, 'status': 'failed', 'frozen_receipt_sha256': frozen}
            (root / 'RESULT.json').write_text(json.dumps(result))
            output = io.StringIO()
            with redirect_stdout(output):
                runner.print_diagnostics(root)
            for i in range(1, 7):
                self.assertIn(f'CertPart{i:02d}.stdout\npart {i}', output.getvalue())
            self.assertNotIn('secret', output.getvalue())
            self.assertNotIn('module must not print', output.getvalue())
            for name in ('RUN.json', 'Baseline.started.json', 'Baseline.stderr', 'CertPart06.stdout', 'manifest.json'):
                original = (root / name).read_bytes()
                (root / name).write_bytes(b'tampered')
                shown = io.StringIO()
                with self.subTest(tampered=name), redirect_stdout(shown):
                    with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                        runner.print_diagnostics(root)
                self.assertEqual(shown.getvalue(), '')
                (root / name).write_bytes(original)
            for kind in ('symlink', 'fifo', 'hardlink'):
                target = root / 'RUN.json'
                if target.exists() or target.is_symlink():
                    target.unlink()
                if kind == 'symlink':
                    target.symlink_to(root / 'unrequested.txt')
                elif kind == 'fifo':
                    os.mkfifo(target)
                else:
                    os.link(root / 'unrequested.txt', target)
                with self.subTest(kind=kind), redirect_stdout(io.StringIO()), self.assertRaises((ValueError, OSError)):
                    runner.print_diagnostics(root)

            (root / 'RUN.json').unlink()
            with patch.object(runner.os, 'read', return_value=b''), redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, 'diagnostic short read'):
                    runner.print_diagnostics(root)

    def test_cli_has_no_diagnostic_stage_limit_or_fallback_switch(self):
        for option in (['--diagnostic-stage-limit', '2'], ['--noncomputable-data'], ['--fallback']):
            with self.subTest(option=option), patch.object(runner, 'qualify') as qualify:
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    runner.main(['--output-directory', '/tmp/not-created'] + option)
                self.assertEqual(error.exception.code, 2)
                qualify.assert_not_called()
