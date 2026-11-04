"""Independent adapter lifecycle and completion regressions, not sandbox tests."""
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import patch

from hepta import pipeline
from experiments.loader_budget import prototype as reader
from experiments.policy_failures.owner import Owner, Rejected
from .adapter import FrontendRequest


class ReviewRegressions(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.entry = Path(temporary.name) / 'main.hepta'
        self.entry.write_text('fn main()->Unit effects {} {}')

    def test_no_caller_callback_after_final_validation(self):
        request = None
        callbacks = []
        validated = False
        def checkpoint():
            callbacks.append(validated)
            if validated:
                self.entry.write_text('changed after the final check')
        request = FrontendRequest(checkpoint=checkpoint)
        real_unchanged = request.owner.unchanged
        def unchanged(handle):
            nonlocal validated
            result = real_unchanged(handle)
            validated = True
            return result
        request.owner.unchanged = unchanged
        result = request.check(self.entry)
        self.assertTrue(result.report['ok'])
        self.assertTrue(validated)
        self.assertNotIn(True, callbacks)
        self.assertEqual(self.entry.read_text(), 'fn main()->Unit effects {} {}')

    def test_returned_checker_diagnostic_preserves_final_io_first_failure(self):
        self.entry.write_text('fn main()->bool effects {} { return 1; }')
        request = None
        injected = False
        def checkpoint():
            nonlocal injected
            if request.phase == 'after_analysis' and not injected:
                injected = True
                patcher = patch.object(reader.os, 'open', side_effect=OSError('final read fails'))
                patcher.start()
                self.addCleanup(patcher.stop)
        request = FrontendRequest(checkpoint=checkpoint)
        result = request.check(self.entry)
        codes = [d['code'] for d in result.report['diagnostics']]
        self.assertIn('E_TYPE', codes)
        self.assertEqual(codes[-1], 'E_MODULE_RACE')
        first = request.owner.context.failure
        self.assertEqual(first.category, 'io')
        with self.assertRaises(Rejected) as caught:
            request.check(self.entry)
        self.assertIs(caught.exception.failure, first)

    def test_swallowed_callback_reentrant_check_stays_terminal(self):
        request = None
        failures = []
        def checkpoint():
            if not failures:
                try:
                    request.check(self.entry)
                except Rejected as error:
                    failures.append(error.failure)
        request = FrontendRequest(checkpoint=checkpoint)
        with self.assertRaises(Rejected) as caught:
            request.check(self.entry)
        self.assertEqual(failures[0].category, 'reentrancy')
        self.assertIs(caught.exception.failure, failures[0])
        self.assertEqual(request.owner.context.reader.reads, 0)

    def test_late_cross_thread_cancel_does_not_change_completed_outcome(self):
        request = FrontendRequest()
        result = request.check(self.entry)
        original = dict(result.report)
        first = request.owner.context.failure
        thread = Thread(target=request.cancel)
        thread.start()
        thread.join()
        self.assertEqual(result.report, original)
        self.assertIs(request.owner.context.failure, first)
        self.assertTrue(result.report['ok'])
        self.assertEqual(request._state, 'finished')

    def test_real_pipeline_never_invokes_native_compiler(self):
        with patch.object(pipeline, 'compile_rust', side_effect=AssertionError('native invocation')) as native:
            result = FrontendRequest().check(self.entry)
        native.assert_not_called()
        self.assertEqual(result.report['status'], 'frontend_only')
        self.assertEqual(result.report['checks']['rust_borrows_types'], 'not_run')
        self.assertIsNotNone(result.rust)

    def test_caller_config_mutation_does_not_change_frozen_snapshot(self):
        config = {'locked': False}
        request = FrontendRequest(config=config)
        config['locked'] = True
        config['native'] = True
        result = request.check(self.entry)
        self.assertTrue(result.report['ok'])
        self.assertEqual(dict(request.config), {'locked': False})
        self.assertFalse(result.project.locked)

        for binding in ('context', 'reader'):
            with self.subTest(replaced_binding=binding):
                request = None
                replacement = Owner()
                def checkpoint():
                    if binding == 'context':
                        request.owner.context = replacement.context
                    else:
                        request.owner.context.reader = replacement.context.reader
                request = FrontendRequest(checkpoint=checkpoint)
                original_context = request.owner.context
                original_reader = original_context.reader
                with self.assertRaises(Rejected) as caught:
                    request.check(self.entry)
                self.assertEqual(caught.exception.failure.category, 'policy_drift')
                self.assertIs(caught.exception.failure, original_context.failure)
                self.assertTrue(original_context.closed)
                self.assertEqual(original_reader.reads, 0)
                self.assertEqual(replacement.context.reader.reads, 0)

    def test_source_change_after_real_analysis_returns_race(self):
        request = None
        changed = False
        def checkpoint():
            nonlocal changed
            if request.phase == 'after_analysis' and not changed:
                changed = True
                self.entry.write_text('fn changed()->Unit effects {} {}')
        request = FrontendRequest(checkpoint=checkpoint)
        result = request.check(self.entry)
        self.assertFalse(result.report['ok'])
        self.assertEqual(result.report['status'], 'rejected')
        self.assertEqual(result.report['diagnostics'][-1]['code'], 'E_MODULE_RACE')
        self.assertEqual(request._state, 'finished')

    def test_checker_exception_identity_and_first_failure_survive_retry(self):
        request = FrontendRequest()
        original = MemoryError('checker allocation')
        with patch.object(pipeline, 'check', side_effect=original):
            with self.assertRaises(MemoryError) as caught:
                request.check(self.entry)
        self.assertIs(caught.exception, original)
        first = request.owner.context.failure
        self.assertEqual(first.category, 'memory')
        reads = request.owner.context.reader.reads
        with self.assertRaises(Rejected) as later:
            request.check(self.entry)
        self.assertIs(later.exception.failure, first)
        self.assertEqual(request.owner.context.reader.reads, reads)


if __name__ == '__main__':
    unittest.main()
