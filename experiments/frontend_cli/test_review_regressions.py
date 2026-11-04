"""Independent CLI refusal, identity and output-transport regressions."""
import io
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from hepta import pipeline
from hepta.ast import Diagnostic, HeptaError
from experiments.frontend_adapter.adapter import FrontendRequest
from experiments.policy_failures.owner import Cancelled, Failure, Rejected
from . import cli


class ReviewRegressions(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.entry = Path(temporary.name) / 'main.hepta'
        self.entry.write_text('fn main()->Unit effects {} {}')
        self.argv = ['check', '--frontend-only', '--policy',
                     'loader-experimental-v1', str(self.entry)]

    def evaluate(self):
        return cli.evaluate(self.argv)

    def assert_no_partial(self, envelope):
        self.assertIsNone(envelope['report'])
        serialized = json.dumps(envelope)
        for key in ('compiler_sha256', 'source_sha256', 'interface_sha256', 'rust_sha256'):
            self.assertNotIn(key, serialized)
        self.assertNotIn('PRIVATE_EXCEPTION_CONTENT', serialized)

    def test_constructor_refusal_preserves_real_first_record(self):
        first = Failure('unsupported_runtime', 'bootstrap')
        with patch.object(cli, 'FrontendRequest', side_effect=Rejected('PRIVATE_EXCEPTION_CONTENT', first)):
            envelope, code = self.evaluate()
        self.assertEqual(code, 3)
        self.assertEqual(envelope['first_failure']['category'], 'unsupported_runtime')
        self.assertEqual(envelope['first_failure']['observed_reads'], 0)
        self.assert_no_partial(envelope)

    def test_replaced_public_owner_preserves_original_context_failure(self):
        request = None
        def checkpoint():
            request.owner = object()
        request = FrontendRequest(checkpoint=checkpoint)
        with patch.object(cli, 'FrontendRequest', return_value=request):
            envelope, code = self.evaluate()
        self.assertEqual(code, 3)
        self.assertEqual(envelope['first_failure']['category'], 'policy_drift')
        self.assert_no_partial(envelope)

    def test_constructor_unexpected_never_invents_loader_failure(self):
        with patch.object(cli, 'FrontendRequest', side_effect=RuntimeError('PRIVATE_EXCEPTION_CONTENT')):
            envelope, code = self.evaluate()
        self.assertEqual(code, 70)
        self.assertIsNone(envelope['first_failure'])
        self.assert_no_partial(envelope)

    def test_first_io_beats_bubbled_diagnostic(self):
        request = FrontendRequest()
        first = request._context.record(category='io', phase='read')
        error = HeptaError(Diagnostic('E_TEST', 'ordinary public diagnostic'))
        with patch.object(request, 'check', side_effect=error), patch.object(cli, 'FrontendRequest', return_value=request):
            envelope, code = self.evaluate()
        self.assertEqual(code, 3)
        self.assertEqual(envelope['first_failure']['category'], first.category)
        self.assert_no_partial(envelope)

    def test_returned_final_io_race_preserves_report_but_refuses(self):
        from experiments.loader_budget import prototype as reader
        request = None
        def checkpoint():
            if request.phase == 'after_analysis':
                patcher = patch.object(reader.os, 'open', side_effect=OSError('PRIVATE_EXCEPTION_CONTENT'))
                patcher.start()
                self.addCleanup(patcher.stop)
        request = FrontendRequest(checkpoint=checkpoint)
        with patch.object(cli, 'FrontendRequest', return_value=request):
            envelope, code = self.evaluate()
        self.assertEqual(code, 3)
        self.assertEqual(envelope['outcome'], 'refused')
        self.assertIs(envelope['ok'], False)
        self.assertEqual(envelope['first_failure']['category'], 'io')
        self.assertEqual(envelope['report']['diagnostics'][-1]['code'], 'E_MODULE_RACE')
        self.assertIn('compiler_sha256', envelope['report'])

    def test_exception_after_real_analysis_discards_partial_hashes(self):
        real = pipeline.analyze
        def throw_after_analysis(*args, **kwargs):
            report = real(*args, **kwargs).report
            self.assertTrue(report['ok'])
            self.assertIn('compiler_sha256', report)
            raise RuntimeError('PRIVATE_EXCEPTION_CONTENT')
        with patch.object(pipeline, 'analyze', side_effect=throw_after_analysis):
            envelope, code = self.evaluate()
        self.assertEqual(code, 70)
        self.assert_no_partial(envelope)

    def test_system_exit_zero_is_never_success(self):
        for exit_code in (0, 2, 'PRIVATE_EXCEPTION_CONTENT'):
            with self.subTest(exit_code=exit_code), patch.object(pipeline, 'analyze', side_effect=SystemExit(exit_code)):
                envelope, code = self.evaluate()
            self.assertEqual(code, 70)
            self.assertEqual(envelope['first_failure']['category'], 'unexpected')
            self.assert_no_partial(envelope)

    def test_keyboard_interrupt_is_distinct(self):
        with patch.object(pipeline, 'analyze', side_effect=KeyboardInterrupt()):
            envelope, code = self.evaluate()
        self.assertEqual(code, 130)
        self.assertEqual(envelope['outcome'], 'interrupted')
        self.assert_no_partial(envelope)

    def test_memory_recursion_are_not_budget(self):
        for error, category in ((MemoryError(), 'memory'), (RecursionError(), 'recursion')):
            with self.subTest(category=category), patch.object(pipeline, 'analyze', side_effect=error):
                envelope, code = self.evaluate()
            self.assertEqual(code, 70)
            self.assertEqual(envelope['first_failure']['category'], category)
            self.assert_no_partial(envelope)

    def test_success_requires_exact_shape_and_frontend_status(self):
        for change in ({'ok': 1}, {'status': 'checked'}, {'schema': 'hepta.other.v1'}, {'ok': True, 'status': 'rejected'}, {'ok': False, 'status': 'frontend_only'}):
            request = FrontendRequest()
            result = request.check(str(self.entry))
            result.report.update(change)
            with self.subTest(change=change), patch.object(request, 'check', return_value=result), patch.object(cli, 'FrontendRequest', return_value=request):
                envelope, code = self.evaluate()
            self.assertEqual(code, 70)
            self.assert_no_partial(envelope)

    def test_first_failure_cannot_wrap_successful_inner_report(self):
        request = FrontendRequest()
        result = request.check(str(self.entry))
        request._context.record(category='io', phase='revalidation')
        with patch.object(request, 'check', return_value=result), patch.object(cli, 'FrontendRequest', return_value=request):
            envelope, code = self.evaluate()
        self.assertEqual(code, 70)
        self.assertEqual(envelope['first_failure']['category'], 'io')
        self.assert_no_partial(envelope)

    def test_report_string_fields_reject_foreign_equality_without_calling_it(self):
        calls = []
        class Foreign:
            def __eq__(self, other):
                calls.append(other)
                return True
            def __ne__(self, other):
                calls.append(other)
                return False
        for field in ('schema', 'status'):
            request = FrontendRequest()
            result = request.check(str(self.entry))
            result.report[field] = Foreign()
            with patch.object(request, 'check', return_value=result), patch.object(cli, 'FrontendRequest', return_value=request):
                envelope, code = self.evaluate()
            self.assertEqual(code, 70)
            self.assert_no_partial(envelope)
        self.assertEqual(calls, [])

    def test_failure_category_rejected_without_foreign_protocols(self):
        calls = []
        class Foreign:
            def __eq__(self, other):
                calls.append(other)
                return False
            def __hash__(self):
                calls.append('hash')
                return 0
        bad = Failure(Foreign(), 'read')
        output = io.StringIO()
        with patch.object(cli, 'FrontendRequest', side_effect=Rejected('PRIVATE_EXCEPTION_CONTENT', bad)):
            code = cli.main(self.argv, stdout=output, stderr=io.StringIO())
        self.assertEqual(code, 70)
        self.assertEqual(calls, [])
        self.assert_no_partial(json.loads(output.getvalue()))

    def test_failure_observed_counts_must_be_exact_nonnegative_integers(self):
        for field in ('observed_bytes', 'observed_reads'):
            for value in (None, True, -1, 1.0):
                bad = Failure('io', 'read', **{field: value})
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    cli.failure_json(bad)

    def test_usage_rejected_before_request_construction(self):
        cases = [self.argv + ['--native'], self.argv + ['--output', 'do-not-write'],
                 self.argv + ['--locked', '--locked'],
                 ['check', '--frontend-on', '--policy', 'loader-experimental-v1', str(self.entry)],
                 ['@' + str(self.entry)], self.argv + ['--policy', 'loader-experimental-v1']]
        for argv in cases:
            with self.subTest(argv=argv), patch.object(cli, 'FrontendRequest', side_effect=AssertionError('must not construct')) as factory:
                envelope, code = cli.evaluate(argv)
            self.assertEqual(code, 2)
            factory.assert_not_called()
            self.assert_no_partial(envelope)

    def test_short_write_is_transport_failure_without_retry(self):
        class Short(io.StringIO):
            calls = 0
            def write(self, text):
                self.calls += 1
                super().write(text[:2])
                return 2
        output = Short()
        code = cli.main(self.argv, stdout=output, stderr=io.StringIO())
        self.assertEqual(code, 74)
        self.assertEqual(output.calls, 1)

    def test_write_failure_no_second_json_attempt(self):
        class Broken(io.StringIO):
            calls = 0
            def write(self, text):
                self.calls += 1
                raise BrokenPipeError('PRIVATE_EXCEPTION_CONTENT')
        output, errors = Broken(), io.StringIO()
        code = cli.main(self.argv, stdout=output, stderr=errors)
        self.assertEqual(code, 74)
        self.assertEqual(output.calls, 1)
        self.assertNotIn('PRIVATE_EXCEPTION_CONTENT', errors.getvalue())
        self.assertNotIn('Traceback', errors.getvalue())

    def test_flush_failure_is_not_success_and_no_retry(self):
        class BadFlush(io.StringIO):
            calls = 0
            def write(self, text):
                self.calls += 1
                return super().write(text)
            def flush(self):
                raise OSError('PRIVATE_EXCEPTION_CONTENT')
        output = BadFlush()
        self.assertEqual(cli.main(self.argv, stdout=output, stderr=io.StringIO()), 74)
        self.assertEqual(output.calls, 1)

    def test_stderr_failure_does_not_escape_transport_boundary(self):
        class Broken(io.StringIO):
            def write(self, text):
                raise BrokenPipeError('PRIVATE_EXCEPTION_CONTENT')
        self.assertEqual(cli.main(self.argv, stdout=Broken(), stderr=Broken()), 74)

    def test_unserializable_report_never_partially_written(self):
        request = FrontendRequest()
        result = request.check(str(self.entry))
        result.report['extra'] = object()
        output = io.StringIO()
        with patch.object(request, 'check', return_value=result), patch.object(cli, 'FrontendRequest', return_value=request):
            code = cli.main(self.argv, stdout=output, stderr=io.StringIO())
        self.assertEqual(code, 70)
        if output.getvalue():
            self.assert_no_partial(json.loads(output.getvalue()))

    def test_static_serialization_fallback_retains_envelope_schema(self):
        output = io.StringIO()
        with patch.object(cli.json, 'dumps', side_effect=MemoryError()):
            code = cli.main(self.argv, stdout=output, stderr=io.StringIO())
        self.assertEqual(code, 70)
        envelope = json.loads(output.getvalue())
        self.assertEqual(set(envelope), set(cli.envelope('error')))
        self.assert_no_partial(envelope)

    def test_serialization_failure_preserves_materialized_first_cause(self):
        first = cli.failure_json(Failure('io', 'revalidation', observed_reads=4))
        response = cli.envelope('refused', failure=first, report={'bad': object()})
        output = io.StringIO()
        with patch.object(cli, 'evaluate', return_value=(response, 3)):
            code = cli.main(self.argv, stdout=output, stderr=io.StringIO())
        self.assertEqual(code, 70)
        envelope = json.loads(output.getvalue())
        self.assertEqual(envelope['first_failure'], first)
        self.assert_no_partial(envelope)

    def test_prewrite_interruptions_have_explicit_outcomes(self):
        for kind, outcome in ((KeyboardInterrupt, 'interrupted'), (Cancelled, 'cancelled')):
            for target in ('parse', 'json.dumps'):
                for persistent in (False, True):
                    output = io.StringIO()
                    if target == 'parse':
                        real = cli.parse
                    else:
                        real = cli.json.dumps
                    calls = 0
                    def interrupt(*args, **kwargs):
                        nonlocal calls
                        calls += 1
                        if persistent or calls == 1:
                            raise kind('PRIVATE_EXCEPTION_CONTENT')
                        return real(*args, **kwargs)
                    with self.subTest(kind=kind, target=target, persistent=persistent), patch('experiments.frontend_cli.cli.' + target, side_effect=interrupt):
                        code = cli.main(['--help'], stdout=output, stderr=io.StringIO())
                    self.assertEqual(code, 130)
                    envelope = json.loads(output.getvalue())
                    self.assertEqual(envelope['outcome'], outcome)
                    self.assertIsNone(envelope['first_failure'])
                    self.assertEqual(set(envelope), set(cli.envelope('error')))
                    self.assert_no_partial(envelope)

    def test_interruption_preserves_first_cause_and_transport_precedence(self):
        first = cli.failure_json(Failure('io', 'revalidation', observed_reads=4))
        response = cli.envelope('refused', failure=first)
        output = io.StringIO()
        real = cli.json.dumps
        calls = 0
        def interrupt_once(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise KeyboardInterrupt()
            return real(*args, **kwargs)
        with patch.object(cli, 'evaluate', return_value=(response, 3)), patch.object(cli.json, 'dumps', side_effect=interrupt_once):
            code = cli.main(self.argv, stdout=output, stderr=io.StringIO())
        self.assertEqual(code, 130)
        envelope = json.loads(output.getvalue())
        self.assertEqual(envelope['outcome'], 'interrupted')
        self.assertEqual(envelope['first_failure'], first)
        self.assert_no_partial(envelope)
        class InterruptedOutput(io.StringIO):
            def write(self, text):
                raise KeyboardInterrupt()
        self.assertEqual(cli.main(['--help'], stdout=InterruptedOutput(), stderr=io.StringIO()), 74)

    def test_real_closed_stdout_has_no_shutdown_traceback(self):
        process = subprocess.Popen([sys.executable, '-B', '-m', 'experiments.frontend_cli', *self.argv],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.stdout.close()
        errors = process.stderr.read()
        self.assertEqual(process.wait(timeout=30), 74, errors.decode())
        process.stderr.close()
        self.assertNotIn(b'Traceback', errors)
        self.assertNotIn(b'Exception ignored', errors)


if __name__ == '__main__':
    unittest.main()
