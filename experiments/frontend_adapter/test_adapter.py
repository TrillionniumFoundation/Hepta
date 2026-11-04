"""Real-pipeline controls; patches are test probes, never adapter machinery."""
from contextlib import ExitStack
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta import modules, packages, pipeline
from hepta.ast import HeptaError
from experiments.policy_failures.owner import Cancelled, Owner, Policy, Rejected
from .adapter import FrontendRequest

TEXT = 'fn main()->Unit effects {} {}'


class AdapterTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.entry = self.root / 'main.hepta'
        self.entry.write_text(TEXT)

    def package(self):
        (self.root / 'hepta.toml').write_text(
            '[package]\nname="app"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
        packages.write_lock(self.root)

    def after_analysis(self, action, request=None):
        request = request or FrontendRequest()
        real = pipeline.analyze
        def wrapped(*args, **kwargs):
            result = real(*args, **kwargs)
            action(request, result)
            return result
        with patch.object(pipeline, 'analyze', wrapped):
            return request, request.check(self.entry)

    def assert_terminal(self, request, category):
        first = request.owner.context.failure
        self.assertEqual(first.category, category)
        reads = request.owner.context.reader.reads
        with self.assertRaises(Rejected) as later:
            request.check(self.entry)
        self.assertIs(later.exception.failure, first)
        self.assertEqual(request.owner.context.reader.reads, reads)
        self.assertTrue(request.owner.context.closed)

    def test_real_analysis_and_full_report_parity(self):
        expected = pipeline.analyze_project(self.entry, native=False)
        request = FrontendRequest()
        actual = request.check(self.entry)
        self.assertEqual(actual.report, expected.report)
        self.assertEqual(actual.rust, expected.rust)
        self.assertEqual(actual.program, expected.program)
        self.assertIs(actual.project, request.handle.project)
        self.assertIs(request.handle._owner, request.owner)
        self.assertEqual(actual.report['status'], 'frontend_only')
        self.assertIsNone(request.owner.context.failure)

    def test_all_examples_reports_and_original_load_diagnostics(self):
        graphs = diagnostics = 0
        paths = sorted(Path('examples').rglob('*.hepta'))
        self.assertEqual(len(paths), 80)
        for path in paths:
            with self.subTest(path=str(path)):
                request = FrontendRequest()
                try:
                    expected = pipeline.analyze_project(path, native=False)
                except HeptaError as old:
                    with self.assertRaises(HeptaError) as actual:
                        request.check(path)
                    self.assertEqual(actual.exception.diagnostic.to_dict(), old.diagnostic.to_dict())
                    diagnostics += 1
                else:
                    actual = request.check(path)
                    self.assertEqual(actual.report, expected.report)
                    self.assertEqual(actual.rust, expected.rust)
                    self.assertEqual(actual.project.source_bytes, expected.project.source_bytes)
                    self.assertEqual(actual.program, expected.program)
                    graphs += 1
        self.assertEqual((graphs, diagnostics), (68, 12))

    def test_rejected_checker_report_still_revalidates(self):
        self.entry.write_text('fn main()->i32 effects {} { return true; }')
        expected = pipeline.analyze_project(self.entry, native=False)
        request = FrontendRequest()
        reads = []
        real = pipeline.analyze
        def wrapped(*args, **kwargs):
            reads.append(request.owner.context.reader.reads)
            return real(*args, **kwargs)
        with patch.object(pipeline, 'analyze', wrapped):
            actual = request.check(self.entry)
        self.assertFalse(actual.report['ok'])
        self.assertEqual(actual.report, expected.report)
        self.assertGreater(request.owner.context.reader.reads, reads[0])
        self.assertIsNone(request.owner.context.failure)

    def test_no_legacy_loader_or_analyze_project_fallback(self):
        with patch.object(modules, 'load_project', side_effect=AssertionError('legacy load')), \
             patch.object(pipeline, 'analyze_project', side_effect=AssertionError('legacy wrapper')):
            self.assertTrue(FrontendRequest().check(self.entry).report['ok'])

    def test_no_public_unchanged_call(self):
        # Replacing the class method would itself violate inherited finite pins.
        # Observe Python calls instead, keeping those pins intact.
        import sys
        calls = []
        code = modules.LoadedProject.unchanged.__code__
        def trace(frame, event, arg):
            if event == 'call' and frame.f_code is code:
                calls.append(frame)
        old = sys.getprofile()
        try:
            sys.setprofile(trace)
            self.assertTrue(FrontendRequest().check(self.entry).report['ok'])
        finally:
            sys.setprofile(old)
        self.assertEqual(calls, [])

    def test_native_and_subprocess_routes_never_called(self):
        from hepta import c_backend, c_import
        with ExitStack() as stack:
            for obj, name in ((pipeline, 'compile_rust'), (c_backend, 'compile_c'),
                              (c_import, '_native_process'), (subprocess, 'Popen')):
                stack.enter_context(patch.object(obj, name, side_effect=AssertionError('native execution')))
            self.assertTrue(FrontendRequest().check(self.entry).report['ok'])
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['main.hepta'])

    def test_unknown_native_artifact_options_pre_owner(self):
        keys = ('native', 'backend', 'cc', 'rustc', 'target', 'no_std', 'crate_type',
                'c_optimization', 'output', 'command', 'build', 'run', 'emit', 'header',
                'patch', 'import_c', 'source_overrides', 'profile')
        with patch('experiments.frontend_adapter.adapter.Owner', side_effect=AssertionError('owner made')):
            for key in keys:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    FrontendRequest(config={key: None})

    def test_config_types_are_exact(self):
        class Dictionary(dict): pass
        for config in (Dictionary(), [], False):
            with self.subTest(config=config), self.assertRaises(TypeError):
                FrontendRequest(config=config)
        for value in (0, 1, None, 'false', object()):
            with self.subTest(value=value), self.assertRaises(TypeError):
                FrontendRequest(config={'locked': value})
        with self.assertRaises(ValueError):
            FrontendRequest(config={1: False})

    def test_non_none_overlays_pre_path_and_reads(self):
        class Entry:
            def __fspath__(self): raise AssertionError('path converted')
        for overrides in ({}, {str(self.entry): TEXT}, False, []):
            request = FrontendRequest()
            with self.subTest(overrides=overrides), self.assertRaises(Rejected):
                request.check(Entry(), source_overrides=overrides)
            self.assertEqual(request.owner.context.reader.reads, 0)
            self.assert_terminal(request, 'schema')

    def test_config_is_copied(self):
        config = {'locked': False}
        request = FrontendRequest(config=config)
        config['locked'] = True
        self.assertTrue(request.check(self.entry).report['ok'])

    def test_config_replacement_even_equal_refuses_pre_path(self):
        request = FrontendRequest()
        request.config = {'locked': False}
        with self.assertRaises(Rejected): request.check(self.entry)
        self.assertEqual(request.owner.context.reader.reads, 0)
        self.assert_terminal(request, 'policy_drift')

    def test_config_drift_in_callback_refuses_pre_load(self):
        request = FrontendRequest(checkpoint=lambda: setattr(request, 'config', {'locked': False}))
        with self.assertRaises(Rejected): request.check(self.entry)
        self.assertEqual(request.owner.context.reader.reads, 0)
        self.assert_terminal(request, 'policy_drift')

    def test_policy_replacement_refuses_pre_io(self):
        request = FrontendRequest()
        request.policy = Policy()
        with self.assertRaises(Rejected): request.check(self.entry)
        self.assertEqual(request.owner.context.reader.reads, 0)
        self.assert_terminal(request, 'policy_drift')

    def test_policy_value_drift_during_analysis(self):
        request = FrontendRequest()
        with self.assertRaises(Rejected):
            self.after_analysis(lambda r, _: object.__setattr__(r.policy, 'version', 'other'), request)
        self.assert_terminal(request, 'policy_drift')

    def test_context_replacement_cannot_reset_ledger(self):
        for late in (False, True):
            request = FrontendRequest(); original = request.owner.context
            replacement = Owner().context
            def mutate(r, _): r.owner.context = replacement
            with self.subTest(late=late), self.assertRaises(Rejected):
                if late:
                    self.after_analysis(mutate, request)
                else:
                    mutate(request, None); request.check(self.entry)
            self.assertEqual(original.failure.category, 'policy_drift')
            self.assertEqual(replacement.reader.reads, 0)
            self.assertTrue(original.closed)

    def test_ops_and_reader_replacement_cannot_reset_ledger(self):
        for field in ('ops', 'ops_context', 'reader'):
            request = FrontendRequest(); original = request.owner.context
            replacement = Owner()
            def mutate(r, _):
                if field == 'ops': r.owner._ops = replacement._ops
                elif field == 'ops_context': r.owner._ops.context = replacement.context
                else: r.owner.context.reader = replacement.context.reader
            with self.subTest(field=field), self.assertRaises(Rejected):
                self.after_analysis(mutate, request)
            self.assertEqual(original.failure.category, 'policy_drift')
            self.assertEqual(replacement.context.reader.reads, 0)
        # Drift wins before a new overlay/schema record and snapshots the old
        # ledger even when the next check argument is independently invalid.
        request = FrontendRequest()
        request.check(self.entry)
        original = request.owner.context.reader
        request.owner.context.reader = Owner().context.reader
        with self.assertRaises(Rejected) as caught:
            request.check(self.entry, source_overrides={})
        self.assertEqual(caught.exception.failure.category, 'policy_drift')
        self.assertEqual(caught.exception.failure.observed_reads, original.reads)
        self.assertEqual(caught.exception.failure.observed_bytes, original.bytes_read)

    def test_raw_spelling_and_alias_retarget(self):
        alias = self.root / 'alias.hepta'; alias.symlink_to(self.entry)
        other = self.root / 'other.hepta'; other.write_text(TEXT)
        raw = str(self.root) + '/./alias.hepta'
        request = FrontendRequest()
        real_load = request.owner.load
        seen = []
        def load(entry, **kwargs):
            seen.append(entry)
            return real_load(entry, **kwargs)
        request.owner.load = load
        real = pipeline.analyze
        def analyze(*args, **kwargs):
            result = real(*args, **kwargs)
            alias.unlink(); alias.symlink_to(other)
            return result
        with patch.object(pipeline, 'analyze', analyze): actual = request.check(raw)
        self.assertEqual(seen, [raw])
        self.assertEqual(actual.report['diagnostics'][-1]['code'], 'E_MODULE_RACE')
        self.assertFalse(actual.report['ok'])

    def test_source_race_legacy_diagnostic(self):
        request, actual = self.after_analysis(lambda r, _: self.entry.write_text(TEXT + '\n'))
        self.assertFalse(actual.report['ok'])
        self.assertEqual(actual.report['status'], 'rejected')
        self.assertEqual(actual.report['diagnostics'][-1]['code'], 'E_MODULE_RACE')
        self.assertIsNone(request.owner.context.failure)

    def test_public_maps_cannot_hide_source_race(self):
        def mutate(request, result):
            result.project.source_bytes.clear(); result.project.bindings.clear()
            self.entry.write_text(TEXT + '\n')
        _, actual = self.after_analysis(mutate)
        self.assertEqual(actual.report['diagnostics'][-1]['code'], 'E_MODULE_RACE')

    def test_final_read_budget_preserves_same_ledger(self):
        probe = Owner(); probe.load(self.entry)
        request = FrontendRequest(policy=Policy(limits={'reads': probe.context.reader.reads}))
        with self.assertRaises(Rejected) as error: request.check(self.entry)
        self.assertEqual(error.exception.failure.dimension, 'reads')
        self.assertEqual(request.owner.context.reader.reads, probe.context.reader.reads)
        self.assert_terminal(request, 'budget')

    def test_final_byte_budget_preserves_same_ledger(self):
        probe = Owner(); probe.load(self.entry)
        request = FrontendRequest(policy=Policy(limits={'total_bytes': probe.context.reader.bytes_read}))
        with self.assertRaises(Rejected) as error: request.check(self.entry)
        self.assertEqual(error.exception.failure.dimension, 'total_bytes')
        self.assert_terminal(request, 'budget')

    def test_package_inventory_race(self):
        self.package()
        _, actual = self.after_analysis(lambda r, _: (self.root / 'extra.hepta').write_text(TEXT))
        self.assertEqual(actual.report['diagnostics'][-1]['code'], 'E_MODULE_RACE')

    def test_locked_initial_and_late_lock_is_not_authenticated(self):
        self.package()
        expected = pipeline.analyze_project(self.entry, native=False, locked=True)
        request = FrontendRequest(config={'locked': True})
        _, actual = self.after_analysis(lambda r, _: (self.root / 'Hepta.lock').write_text('broken'), request)
        self.assertEqual(actual.report, expected.report)
        self.assertTrue(actual.report['ok'])

    def test_stale_initial_lock_original_diagnostic(self):
        self.package(); self.entry.write_text(TEXT + '\n')
        with self.assertRaises(HeptaError) as old:
            pipeline.analyze_project(self.entry, native=False, locked=True)
        request = FrontendRequest(config={'locked': True})
        with self.assertRaises(HeptaError) as new: request.check(self.entry)
        self.assertEqual(new.exception.diagnostic.to_dict(), old.exception.diagnostic.to_dict())
        self.assert_terminal(request, 'diagnostic')

    def test_final_io_failure_keeps_race_and_first_origin(self):
        request, actual = self.after_analysis(lambda r, _: self.entry.unlink())
        self.assertEqual(actual.report['diagnostics'][-1]['code'], 'E_MODULE_RACE')
        self.assert_terminal(request, 'io')

    def test_cancel_before_load_zero_reads(self):
        request = FrontendRequest(); request.cancel()
        with self.assertRaises(Cancelled): request.check(self.entry)
        self.assertEqual(request.owner.context.reader.reads, 0)
        self.assert_terminal(request, 'cancelled')

    def test_cancel_from_callback_zero_reads(self):
        request = FrontendRequest(checkpoint=lambda: request.cancel())
        with self.assertRaises(Cancelled): request.check(self.entry)
        self.assertEqual(request.owner.context.reader.reads, 0)
        self.assert_terminal(request, 'cancelled')

    def test_cancel_at_before_analysis(self):
        def checkpoint():
            if request.phase == 'before_analysis': request.cancel()
        request = FrontendRequest(checkpoint=checkpoint)
        with patch.object(pipeline, 'analyze', side_effect=AssertionError('analysis started')), self.assertRaises(Cancelled):
            request.check(self.entry)
        self.assert_terminal(request, 'cancelled')

    def test_cancel_during_analysis_waits_for_synchronous_return(self):
        request = FrontendRequest(); completed = []
        real = pipeline.analyze
        def analyze(*args, **kwargs):
            worker = threading.Thread(target=request.cancel); worker.start(); worker.join()
            result = real(*args, **kwargs)
            completed.append(result.report['ok'])
            return result
        with patch.object(pipeline, 'analyze', analyze), self.assertRaises(Cancelled):
            request.check(self.entry)
        self.assertEqual(completed, [True])
        self.assert_terminal(request, 'cancelled')

    def test_cancel_during_final_revalidation(self):
        def checkpoint():
            if request.phase == 'revalidation': request.cancel()
        request = FrontendRequest(checkpoint=checkpoint)
        with self.assertRaises(Cancelled): request.check(self.entry)
        self.assert_terminal(request, 'cancelled')

    def test_cancel_after_final_revalidation_no_result_returned(self):
        request = FrontendRequest()
        real = request.owner.unchanged
        def unchanged(handle):
            result = real(handle)
            request.cancel()
            return result
        request.owner.unchanged = unchanged
        with self.assertRaises(Cancelled): request.check(self.entry)
        self.assert_terminal(request, 'cancelled')

    def test_late_cancel_does_not_change_result_or_other_request(self):
        request = FrontendRequest(); actual = request.check(self.entry)
        request.cancel()
        self.assertTrue(actual.report['ok'])
        self.assertIsNone(request.owner.context.failure)
        self.assertTrue(FrontendRequest().check(self.entry).report['ok'])

    def test_repeat_success_is_structured_lifecycle_failure(self):
        request = FrontendRequest(); request.check(self.entry)
        with self.assertRaises(Rejected): request.check(self.entry)
        self.assert_terminal(request, 'lifecycle')

    def test_wrong_thread_zero_reads_and_sticky_failure(self):
        request = FrontendRequest(); errors = []
        def worker():
            try: request.check(self.entry)
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=worker); thread.start(); thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], Rejected)
        self.assertEqual(request.owner.context.reader.reads, 0)
        self.assert_terminal(request, 'thread')

    def test_swallowed_reentrancy_during_analysis_no_result(self):
        request = FrontendRequest()
        def reenter(r, _):
            try: r.check(self.entry)
            except Rejected: pass
        with self.assertRaises(Rejected): self.after_analysis(reenter, request)
        self.assert_terminal(request, 'reentrancy')

    def test_swallowed_reentrancy_in_callback_zero_reads(self):
        def callback():
            try: request.check(self.entry)
            except Rejected: pass
        request = FrontendRequest(checkpoint=callback)
        with self.assertRaises(Rejected): request.check(self.entry)
        self.assertEqual(request.owner.context.reader.reads, 0)
        self.assert_terminal(request, 'reentrancy')

    def test_original_analysis_exception_and_first_failure(self):
        for error, category in ((MemoryError('x'), 'memory'), (RecursionError('x'), 'recursion'),
                                (KeyboardInterrupt(), 'interrupted'), (RuntimeError('x'), 'unexpected')):
            request = FrontendRequest()
            with self.subTest(category=category), patch.object(pipeline, 'analyze', side_effect=error):
                with self.assertRaises(type(error)) as caught: request.check(self.entry)
                self.assertIs(caught.exception, error)
            self.assert_terminal(request, category)

    def test_callback_oserror_is_not_filesystem_io(self):
        error = OSError('callback')
        def callback(): raise error
        request = FrontendRequest(checkpoint=callback)
        with self.assertRaises(OSError) as caught: request.check(self.entry)
        self.assertIs(caught.exception, error)
        self.assert_terminal(request, 'unexpected')

    def test_unsupported_runtime_before_callback_or_io(self):
        with patch('experiments.package_copy.owner._SUPPORTED', False):
            with self.assertRaises(Rejected) as error:
                FrontendRequest(checkpoint=lambda: self.fail('callback invoked'))
        self.assertEqual(error.exception.failure.category, 'unsupported_runtime')
        self.assertEqual(error.exception.failure.observed_reads, 0)


if __name__ == '__main__': unittest.main()
