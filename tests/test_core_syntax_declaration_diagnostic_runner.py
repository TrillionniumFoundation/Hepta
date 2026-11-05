"""Only mocked diagnostic orchestration; no Lean or target execution."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import diagnose_core_syntax_declarations as runner
from tools import check_core_syntax_staged as base
from tools import core_syntax_diagnostic_capture as collector
from tools.core_syntax_structured_stages import build_inputs
from tools.core_syntax_declaration_diagnostic_sources import build_diagnostic_sources


class DiagnosticRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = build_inputs()
        cls.diagnostic = build_diagnostic_sources(cls.prepared)

    def exercise(self, behavior='success'):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            executable = home/'pinned/bin/lean'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'not executable; mocked')
            (home/'pinned/lib/lean').mkdir(parents=True)
            identity = {'mock': 'a'*64}
            support = {'lib/lean/Init.olean':'b'*64, 'lib/lean/Lean/Elab/Tactic/Omega.olean':'c'*64}
            calls = []
            def invoke(exe, source, output, root):
                calls.append(source.stem)
                stage = next(s for s in self.prepared['stages'] if s.name == source.stem)
                output.write_bytes(('mock-'+stage.name).encode())
                stdout = '\n'.join("'"+n+"' does not depend on any axioms" for n in sorted(stage.expected_theorems))+'\n'
                if behavior == 'bad_parent' and stage.name == 'SyntaxData':
                    stdout = stdout.replace(sorted(stage.expected_theorems)[0], 'fake')
                return dict(returncode=0, timed_out=False, incomplete=False, output_truncated=False,
                            stdout=stdout, stderr='')
            def capture(exe, source, output, root, *, safe_root, markers, manifest_reference):
                if behavior == 'platform':
                    return dict(status='diagnostic_infrastructure_failed', process_started=False,
                                leader_reaped=False, drain_complete=False, cleanup_deadline_exceeded=False,
                                cleanup_incomplete=False, output_truncated=False, returncode=None,
                                metadata_remaining_bytes=16384, files={}, raw_files={})
                calls.append(source.stem)
                if behavior == 'uncertain':
                    raise RuntimeError('capture failed after possible launch')
                self.assertEqual(source.read_text(), self.diagnostic.stages[2].source)
                self.assertEqual(len(markers), 24)
                self.assertEqual(manifest_reference['sha256'], self.diagnostic.manifest_sha256)
                status = {'timeout':'diagnostic_timeout', 'limit':'diagnostic_output_limit',
                          'claim_pass':'passed'}.get(behavior, 'diagnostic_completed')
                process = dict(status=status, process_started=True, returncode=0, leader_reaped=True,
                               drain_complete=True, cleanup_deadline_exceeded=False, cleanup_incomplete=False,
                               output_truncated=status=='diagnostic_output_limit', manifest_reference=manifest_reference)
                events = collector._record_bytes(dict(kind='terminal', process=process,
                    accounting_before_terminal=dict(raw_written_bytes=len(b'fixed mock output'), metadata_written_bytes=0)))
                for name, value in [('LinearTransport.stdout', b'fixed mock output'),
                                    ('LinearTransport.stderr', b''),
                                    ('LinearTransport.events.jsonl', events)]:
                    safe_root.write(name, value)
                output.write_bytes(b'never admitted')
                if behavior == 'change_parent':
                    (root/'HiaSyntaxResearch/SyntaxData.olean').write_bytes(b'changed')
                if behavior == 'extra_module':
                    (root/'HiaSyntaxResearch/ParallelTransport.olean').write_bytes(b'forbidden')
                if behavior == 'change_binary':
                    executable.write_bytes(b'changed')
                files = {}
                for name in ('LinearTransport.stdout','LinearTransport.stderr','LinearTransport.events.jsonl'):
                    raw=(root/name).read_bytes()
                    files[name]=dict(path=name,bytes=len(raw),sha256=base.digest(raw))
                if behavior == 'changed_log':
                    (root/'LinearTransport.stdout').write_bytes(b'altered after frozen capture receipt')
                return dict(**process, files=files,
                            raw_files={n:v for n,v in files.items() if n != 'LinearTransport.events.jsonl'},
                            metadata_remaining_bytes=0 if behavior=='no_metadata' else 16384-len(events))
            try:
                report = runner.execute_diagnostic(executable, home/'out', self.prepared, self.diagnostic,
                          identity, support, lambda:identity, lambda _:support,
                          base.digest(executable.read_bytes()), run_process=invoke, capture=capture)
                saved = json.loads((home/'out/RESULT.json').read_text())
                self.assertEqual(saved, report)
                self.assertFalse(report['kernel_core_syntax_connection_checked'])
                self.assertEqual(report['authority'], 'DENY_ALL')
                self.assertTrue(all(x['status']=='unproved' for x in report['obligations']))
                self.assertNotIn('LinearTransport.finished.json', [p.name for p in (home/'out').iterdir()])
                return report, calls
            except Exception:
                raise

    def test_three_successes_still_no_acceptance_or_fourth_stage(self):
        report, calls = self.exercise()
        self.assertEqual(calls, ['Baseline','SyntaxData','LinearTransport'])
        self.assertEqual(report['status'], 'diagnostic_completed')
        self.assertEqual(report['invocations'],3)
        self.assertEqual(len(report['not_scheduled']),7)
        self.assertNotIn('olean', report['stages'][2])

    def test_platform_refusal_does_not_launch_third(self):
        report,calls=self.exercise('platform')
        self.assertEqual(calls,['Baseline','SyntaxData'])
        self.assertEqual(report['invocations'],2)
        self.assertEqual(report['status'],'diagnostic_infrastructure_failed')

    def test_bad_parent_stops_before_diagnostic(self):
        report,calls=self.exercise('bad_parent')
        self.assertEqual(calls,['Baseline','SyntaxData'])
        self.assertEqual(report['status'],'diagnostic_failed')

    def test_changed_parent_module_rejected(self):
        self.assertEqual(self.exercise('change_parent')[0]['status'],'diagnostic_failed')

    def test_unexpected_downstream_module_rejected(self):
        self.assertEqual(self.exercise('extra_module')[0]['status'],'diagnostic_failed')

    def test_changed_binary_rejected(self):
        self.assertEqual(self.exercise('change_binary')[0]['status'],'diagnostic_failed')

    def test_timeout_remains_nonaccepting(self):
        report,calls=self.exercise('timeout')
        self.assertEqual(report['status'],'diagnostic_timeout')
        self.assertEqual(len(calls),3)

    def test_output_limit_remains_nonaccepting(self):
        self.assertEqual(self.exercise('limit')[0]['status'],'diagnostic_output_limit')

    def test_capture_cannot_forge_acceptance(self):
        self.assertEqual(self.exercise('claim_pass')[0]['status'],'diagnostic_failed')

    def test_no_metadata_allowance_fails_closed(self):
        self.assertEqual(self.exercise('no_metadata')[0]['status'],'diagnostic_failed')

    def test_uncertain_capture_preserves_three_launch_upper_bound(self):
        report,calls=self.exercise('uncertain')
        self.assertEqual(report['status'],'diagnostic_failed')
        self.assertEqual(report['invocations'],3)
        self.assertFalse(report['invocation_count_exact'])
        self.assertEqual(len(calls),3)

    def test_log_rewrite_after_capture_receipt_is_rejected(self):
        report,calls=self.exercise('changed_log')
        self.assertEqual(report['status'],'diagnostic_failed')
        self.assertIn('capture file identity differs',report['error'])
        self.assertEqual(len(calls),3)

    def test_original_acceptance_validator_rejects_instrumented_plan(self):
        mutated=dict(self.prepared,stages=self.diagnostic.stages)
        with self.assertRaises(ValueError):
            base.validate_plan(mutated)

    def test_event_reader_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'external').write_bytes(b'not for reading')
            (root/'LinearTransport.events.jsonl').symlink_to(root/'external')
            with self.assertRaises(OSError):
                runner.print_events(root)


class DiagnosticEvidenceBudgetTests(unittest.TestCase):
    def test_maximum_invalid_utf8_evidence_prints_byte_exact_once_within_total(self):
        import io
        from tools import core_syntax_diagnostic_capture as collector
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            files={'LinearTransport.stdout':b'\xff'*collector.RAW_LIMIT,
                   'LinearTransport.stderr':b'',
                   'LinearTransport.events.jsonl':b'x'*(collector.METADATA_LIMIT-3),
                   'RESULT.json':b'{}\n'}
            for name,data in files.items():
                (root/name).write_bytes(data)
            stream=io.BytesIO()
            class Stdout:
                buffer=stream
            with patch('sys.stdout',Stdout()):
                runner.print_events(root)
            expected=b''.join(n.encode()+b'\n'+files[n]+b'\n' for n in runner.LIVE_NAMES)
            self.assertEqual(stream.getvalue(),expected)
            self.assertLessEqual(sum(map(len,files.values()))+len(expected),base.MAX_DIAGNOSTIC)
            self.assertEqual(expected.count(b'\xff'),collector.RAW_LIMIT)

    def test_oversized_final_summary_is_replaced_by_explicit_failure(self):
        from tools import core_syntax_diagnostic_capture as collector
        with tempfile.TemporaryDirectory() as folder:
            root=base.SafeRoot(Path(folder)/'out')
            try:
                root.write('LinearTransport.events.jsonl',b'x'*10000)
                report={'status':'diagnostic_completed','unexpected_large_metadata':'x'*20000}
                runner.write_result_with_budget(root,report,collector)
                raw=root.read('RESULT.json',collector.METADATA_LIMIT)
                self.assertEqual(json.loads(raw)['status'],'diagnostic_failed')
                self.assertNotIn('unexpected_large_metadata',report)
                self.assertLessEqual(len(raw)+10000,collector.METADATA_LIMIT)
            finally:
                root.close()

    def test_no_space_for_failure_receipt_leaves_no_false_complete_result(self):
        from tools import core_syntax_diagnostic_capture as collector
        with tempfile.TemporaryDirectory() as folder:
            root=base.SafeRoot(Path(folder)/'out')
            try:
                root.write('LinearTransport.events.jsonl',b'x'*collector.METADATA_LIMIT)
                with self.assertRaises(ValueError):
                    runner.write_result_with_budget(root,{'status':'diagnostic_completed'},collector)
                self.assertFalse((root.path/'RESULT.json').exists())
            finally:
                root.close()

    def test_printer_refuses_actual_overbudget_bytes_before_any_display(self):
        import io
        from tools import core_syntax_diagnostic_capture as collector
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/'LinearTransport.stdout').write_bytes(b'x'*(collector.RAW_LIMIT+1))
            stream=io.BytesIO()
            class Stdout:
                buffer=stream
            with patch('sys.stdout',Stdout()),self.assertRaises(ValueError):
                runner.print_events(root)
            self.assertEqual(stream.getvalue(),b'')

    def test_printer_checks_frozen_capture_identity_again(self):
        import io
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            old=b'original'
            receipt={'stages':[dict(name='LinearTransport',capture_files={
                'LinearTransport.stdout':dict(path='LinearTransport.stdout',bytes=len(old),sha256=base.digest(old))})]}
            (root/'RESULT.json').write_bytes(runner._encoded(receipt))
            (root/'LinearTransport.stdout').write_bytes(b'changed')
            stream=io.BytesIO()
            class Stdout:
                buffer=stream
            with patch('sys.stdout',Stdout()),self.assertRaisesRegex(ValueError,'changed before presentation'):
                runner.print_events(root)
            self.assertEqual(stream.getvalue(),b'')

    def test_main_does_not_print_a_second_copy_of_final_report(self):
        with patch('sys.argv',['diagnose','--lean','fake','--output-directory','fake']),\
             patch.object(runner,'diagnose',return_value={'status':'diagnostic_completed'}),\
             patch('builtins.print') as printing:
            self.assertEqual(runner.main(),1)
            printing.assert_not_called()
