"""Independent late-lock ordering, origin and qualification regressions."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta import packages, pipeline
from hepta.ast import HeptaError
from experiments.policy_failures.owner import Policy, Rejected
from .adapter import FrontendRequest
from .owner import Owner
from . import cli

TEXT = 'fn main()->Unit effects {} {}'


class ReviewRegressions(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.entry = self.root / 'main.hepta'
        self.entry.write_text(TEXT)
        (self.root / 'hepta.toml').write_text('[package]\nname="app"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
        packages.write_lock(self.root)
        self.lock = self.root / 'Hepta.lock'
        self.argv = ['check', '--frontend-only', '--policy', 'loader-experimental-v1', str(self.entry), '--locked']

    def after_analysis(self, request, action):
        real = pipeline.analyze
        def analyze(*args, **kwargs):
            result = real(*args, **kwargs)
            action(result)
            return result
        with patch.object(pipeline, 'analyze', analyze):
            return request.check(self.entry)

    def poison_callback_after_lock_read(self, error):
        armed = []
        def checkpoint():
            if armed:
                raise error
        request = FrontendRequest(config={'locked': True}, checkpoint=checkpoint)
        real = request._ops.read
        def read(path, role):
            data = real(path, role)
            if request.phase == 'revalidation' and role == 'lock':
                armed.append(True)
            return data
        with patch.object(request._ops, 'read', read), self.assertRaises(type(error)) as caught:
            request.check(self.entry)
        self.assertIs(caught.exception, error)
        self.assertEqual(request._context.failure.category, 'unexpected')
        self.assertEqual(request.lock_revalidation, 'not_completed')
        first = request._context.failure
        reads = request._reader.reads
        with self.assertRaises(Rejected) as second:
            request.check(self.entry)
        self.assertIs(second.exception.failure, first)
        self.assertEqual(request._reader.reads, reads)

    def test_callback_value_error_not_rewritten_as_lock_diagnostic(self):
        self.poison_callback_after_lock_read(ValueError('private callback payload'))

    def test_callback_unicode_error_not_rewritten_as_lock_diagnostic(self):
        self.poison_callback_after_lock_read(UnicodeError('private callback payload'))

    def test_equal_content_symlink_retarget_is_refused(self):
        target_a, target_b = self.root / 'a.lock', self.root / 'b.lock'
        data = self.lock.read_bytes()
        target_a.write_bytes(data); target_b.write_bytes(data)
        self.lock.unlink(); self.lock.symlink_to(target_a)
        request = FrontendRequest(config={'locked': True})
        def change(_):
            self.lock.unlink(); self.lock.symlink_to(target_b)
        with self.assertRaises(Rejected) as error:
            self.after_analysis(request, change)
        self.assertEqual(error.exception.failure.category, 'schema')
        self.assertEqual(request.lock_revalidation, 'not_completed')

    def test_equivalent_same_path_replacement_remains_allowed(self):
        request = FrontendRequest(config={'locked': True})
        def replace(_):
            other = self.root / 'new.lock'
            other.write_text(json.dumps(json.loads(self.lock.read_text()), indent=1))
            os.replace(other, self.lock)
        result = self.after_analysis(request, replace)
        self.assertTrue(result.report['ok'])
        self.assertEqual(request.lock_revalidation, 'post_analysis_observed')

    def test_public_locked_state_and_package_cannot_hide_stale_lock(self):
        request = FrontendRequest(config={'locked': True})
        def change(result):
            result.project.locked = False
            result.project.package = None
            result.project.package_state = {}
            self.lock.write_text('{}')
        with self.assertRaises(HeptaError) as caught:
            self.after_analysis(request, change)
        self.assertEqual(caught.exception.diagnostic.code, 'E_LOCK_STALE')
        self.assertEqual(request._context.failure.category, 'diagnostic')

    def test_entry_alias_changed_during_lock_read_is_revalidated_afterward(self):
        alternate = self.root / 'alternate.hepta'
        alternate.write_text(TEXT)
        alias = self.root / 'alias.hepta'
        alias.symlink_to(self.entry)
        packages.write_lock(self.root)
        request = FrontendRequest(config={'locked': True})
        real = request._ops.read
        def read(path, role):
            data = real(path, role)
            if request.phase == 'revalidation' and role == 'lock':
                alias.unlink(); alias.symlink_to(alternate)
            return data
        with patch.object(request._ops, 'read', read):
            result = request.check(str(alias))
        self.assertFalse(result.report['ok'])
        self.assertEqual(result.report['diagnostics'][-1]['code'], 'E_MODULE_RACE')
        self.assertEqual(request.lock_revalidation, 'not_completed')

    def test_later_lock_mutation_exposes_documented_sequential_limit(self):
        request = FrontendRequest(config={'locked': True})
        real = request._ops.read
        changed = []
        def read(path, role):
            data = real(path, role)
            if request.phase == 'revalidation' and role == 'revalidation':
                self.lock.write_text('broken after observation')
                changed.append(True)
            return data
        with patch.object(request._ops, 'read', read), patch.object(cli, 'FrontendRequest', return_value=request):
            response, code = cli.evaluate(self.argv)
        self.assertTrue(changed)
        self.assertEqual(code, 0)
        self.assertEqual(response['lock_revalidation'], 'post_analysis_observed')
        self.assertIs(response['atomic_snapshot'], False)
        with self.assertRaises(HeptaError) as error:
            Owner().load(self.entry, locked=True)
        self.assertEqual(error.exception.diagnostic.code, 'E_LOCK_INVALID')

    def test_missing_lock_precedes_exhausted_read_budget(self):
        probe = Owner(); probe.load(self.entry, locked=True)
        cap = probe.context.reader.reads
        request = FrontendRequest(config={'locked': True}, policy=Policy(limits={'reads': cap}))
        with self.assertRaises(HeptaError) as error:
            self.after_analysis(request, lambda _: self.lock.unlink())
        self.assertEqual(error.exception.diagnostic.code, 'E_LOCK_MISSING')
        self.assertEqual(request._reader.reads, cap)
        self.assertEqual(request._context.failure.category, 'diagnostic')

    def test_nonregular_lock_substituted_after_file_check_refuses(self):
        request = FrontendRequest(config={'locked': True})
        real = request._ops.path
        changed = []
        def path(value, operation):
            result = real(value, operation)
            if request.phase == 'revalidation' and value == self.lock and operation == 'is_file' and not changed:
                self.lock.unlink(); os.mkfifo(self.lock); changed.append(True)
            return result
        with patch.object(request._ops, 'path', path), self.assertRaises(Rejected) as error:
            request.check(self.entry)
        self.assertTrue(changed)
        self.assertEqual(error.exception.failure.category, 'schema')
        self.assertEqual(request.lock_revalidation, 'not_completed')

    def altered_qualification(self, value, *, locked=True, rejected=False):
        request = FrontendRequest(config={'locked': locked})
        real = request.check
        def check(entry):
            result = real(entry)
            request.lock_revalidation = value
            if rejected:
                result.report['ok'] = False
                result.report['status'] = 'rejected'
            return result
        args = self.argv if locked else self.argv[:-1]
        with patch.object(request, 'check', check), patch.object(cli, 'FrontendRequest', return_value=request):
            return cli.evaluate(args)

    def test_qualification_requires_exact_string(self):
        class String(str):
            pass
        for value in (String('post_analysis_observed'), None, True, [], {}):
            with self.subTest(value=repr(value)):
                response, code = self.altered_qualification(value)
                self.assertEqual(code, 70)
                self.assertIsNone(response['report'])
                self.assertEqual(response['lock_revalidation'], 'not_completed')

    def test_qualification_does_not_call_custom_equality(self):
        calls = []
        class Equal:
            def __eq__(self, other):
                calls.append(other)
                return True
        response, code = self.altered_qualification(Equal())
        self.assertEqual(code, 70)
        self.assertEqual(calls, [])
        self.assertIsNone(response['report'])

    def test_locked_rejected_report_cannot_claim_not_requested(self):
        response, code = self.altered_qualification('not_requested', rejected=True)
        self.assertEqual(code, 70)
        self.assertIsNone(response['report'])

    def test_unlocked_report_cannot_claim_observation(self):
        response, code = self.altered_qualification('post_analysis_observed', locked=False)
        self.assertEqual(code, 70)
        self.assertIsNone(response['report'])

    def test_incomplete_locked_success_is_suppressed(self):
        response, code = self.altered_qualification('not_completed')
        self.assertEqual(code, 70)
        self.assertIsNone(response['report'])
        self.assertEqual(response['lock_revalidation'], 'not_completed')

    def test_serialization_failure_discards_completed_qualification(self):
        response, code = cli.evaluate(self.argv)
        self.assertEqual(code, 0)
        response['report']['non_json'] = object()
        output = io.StringIO()
        with patch.object(cli, 'evaluate', return_value=(response, 0)):
            code = cli.main(self.argv, stdout=output, stderr=io.StringIO())
        fallback = json.loads(output.getvalue())
        self.assertEqual(code, 70)
        self.assertEqual(fallback['lock_revalidation'], 'not_completed')
        self.assertIs(fallback['atomic_snapshot'], False)
        self.assertIsNone(fallback['report'])

    def test_emergency_fallback_is_conservative_and_full_schema(self):
        output = io.StringIO()
        with patch.object(cli.json, 'dumps', side_effect=RuntimeError('private encoder failure')):
            code = cli.main(['--help'], stdout=output, stderr=io.StringIO())
        fallback = json.loads(output.getvalue())
        self.assertEqual(code, 70)
        self.assertEqual(fallback['schema'], cli.SCHEMA)
        self.assertEqual(fallback['lock_revalidation'], 'not_completed')
        self.assertIs(fallback['atomic_snapshot'], False)
        self.assertIs(fallback['native_qualified'], False)
        self.assertIsNone(fallback['report'])

    def test_both_new_lock_and_graph_changes_prioritize_lock_stale(self):
        request = FrontendRequest(config={'locked': True})
        def change(_):
            self.entry.write_text(TEXT + '\n')
            packages.write_lock(self.root)
        with self.assertRaises(HeptaError) as error:
            self.after_analysis(request, change)
        self.assertEqual(error.exception.diagnostic.code, 'E_LOCK_STALE')
        self.assertEqual(request._context.failure.category, 'diagnostic')

    def test_old_valid_lock_and_graph_change_retains_race(self):
        request = FrontendRequest(config={'locked': True})
        result = self.after_analysis(request, lambda _: self.entry.write_text(TEXT + '\n'))
        self.assertEqual(result.report['diagnostics'][-1]['code'], 'E_MODULE_RACE')
        self.assertIsNone(request._context.failure)
        self.assertEqual(request.lock_revalidation, 'not_completed')


    def test_public_qualification_cannot_survive_failed_graph_check(self):
        request = FrontendRequest(config={'locked': True})
        def change(_):
            request.lock_revalidation = 'post_analysis_observed'
            self.entry.write_text(TEXT + '\n')
        result = self.after_analysis(request, change)
        self.assertFalse(result.report['ok'])
        self.assertEqual(request.lock_revalidation, 'not_completed')

    def test_public_qualification_does_not_change_unlocked_result(self):
        request = FrontendRequest()
        result = self.after_analysis(request, lambda _: setattr(request, 'lock_revalidation', 'post_analysis_observed'))
        self.assertTrue(result.report['ok'])
        self.assertEqual(request.lock_revalidation, 'not_requested')

    def test_read_io_first_origin_survives_close_error(self):
        from experiments.loader_budget import prototype as reader
        request = FrontendRequest(config={'locked': True})
        real_read, real_close = request._ops.read, reader.os.close
        read_error, close_error = OSError('private read'), RuntimeError('private close')
        def close(fd):
            real_close(fd)
            raise close_error
        def read(path, role):
            if request.phase == 'revalidation' and role == 'lock':
                with patch.object(reader.os, 'read', side_effect=read_error), patch.object(reader.os, 'close', close):
                    return real_read(path, role)
            return real_read(path, role)
        with patch.object(request._ops, 'read', read), patch.object(cli, 'FrontendRequest', return_value=request):
            response, code = cli.evaluate(self.argv)
        self.assertEqual(code, 3)
        self.assertEqual(response['first_failure']['category'], 'io')
        self.assertEqual(response['first_failure']['phase'], 'read')
        self.assertIsNone(response['report'])
        self.assertEqual(response['lock_revalidation'], 'not_completed')
        self.assertNotIn('private read', json.dumps(response))
        self.assertNotIn('private close', json.dumps(response))

    def test_swallowed_reentrant_lock_checkpoint_stays_terminal(self):
        armed, seen_busy, further_reads = [], [], []
        def checkpoint():
            if armed:
                armed.clear()
                try:
                    request.owner.revalidate(request.handle)
                except Rejected:
                    seen_busy.append(request.owner._busy)
        request = FrontendRequest(config={'locked': True}, checkpoint=checkpoint)
        real = request._ops.read
        def read(path, role):
            data = real(path, role)
            if request.phase == 'revalidation' and role == 'lock':
                armed.append(True)
            elif request.phase == 'revalidation':
                further_reads.append(role)
            return data
        with patch.object(request._ops, 'read', read), self.assertRaises(Rejected) as error:
            request.check(self.entry)
        self.assertEqual(error.exception.failure.category, 'reentrancy')
        self.assertEqual(seen_busy, [True])
        self.assertEqual(further_reads, [])
        self.assertFalse(request.owner._busy)
        self.assertEqual(request.lock_revalidation, 'not_completed')


    def test_public_qualification_resets_after_thrown_lock_diagnostic(self):
        request = FrontendRequest(config={'locked': True})
        def change(_):
            request.lock_revalidation = 'post_analysis_observed'
            self.lock.write_text('broken')
        with self.assertRaises(HeptaError) as error:
            self.after_analysis(request, change)
        self.assertEqual(error.exception.diagnostic.code, 'E_LOCK_INVALID')
        self.assertEqual(request.lock_revalidation, 'not_completed')


    def test_sticky_failure_cannot_accompany_completed_qualification(self):
        request = FrontendRequest(config={'locked': True})
        real = request.check
        def check(entry):
            result = real(entry)
            result.report['ok'] = False
            result.report['status'] = 'rejected'
            request._context.record(category='io', phase='read')
            return result
        with patch.object(request, 'check', check), patch.object(cli, 'FrontendRequest', return_value=request):
            response, code = cli.evaluate(self.argv)
        self.assertEqual(code, 70)
        self.assertEqual(response['error'], 'E_RESULT')
        self.assertIsNone(response['report'])
        self.assertEqual(response['first_failure']['category'], 'io')
        self.assertEqual(response['lock_revalidation'], 'not_completed')


if __name__ == '__main__':
    unittest.main()
