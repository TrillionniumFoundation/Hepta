"""No-follow, allowlisted upload staging controls, without native execution.

These tests only create temporary local filesystem fixtures. They never invoke
Clang, execute generated objects, upload files, or follow hostile link targets.
"""
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tools import stage_deferred_guard_evidence as staging


DENIAL_FLAGS = ('native_admission', 'production_admission', 'performance_qualified',
                'timing_performed', 'quota_equivalence')
LOG_NAMES = ('layout-tests.log', 'layout-run.log')


def put(root, relative, data=b'ordinary evidence'):
    path = Path(root) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def inventory(root):
    return {str(path.relative_to(root)): path.read_bytes()
            for path in Path(root).rglob('*') if path.is_file()}


class TemporaryTree(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.source = self.temporary / 'raw'
        self.source.mkdir()
        self.destination = self.temporary / 'upload'
        self.outside = self.temporary / 'outside'
        self.outside.mkdir()
        self.secret = b'PRIVATE_CONTENT_MUST_NEVER_APPEAR_IN_STAGED_PAYLOAD'
        self.private_file = put(self.outside, 'private-file', self.secret)
        self.logs = {name: put(self.temporary / 'logs', name, (name + '\n').encode())
                     for name in LOG_NAMES}
        # The helper is strictly a filesystem snapshot/copy operation.
        self.process = self.stack.enter_context(patch('subprocess.Popen',
            side_effect=AssertionError('staging must not execute a process')))

    def assert_denied_authority(self, report):
        self.assertEqual(report['authority'], 'DENY_ALL')
        for flag in DENIAL_FLAGS:
            self.assertIs(report[flag], False, flag)

    def run_stage(self, *, source=None, logs=None):
        return staging.stage(self.source if source is None else source,
                             self.destination, self.logs if logs is None else logs)

    def assert_refused(self, *, source=None, logs=None):
        report = self.run_stage(source=source, logs=logs)
        self.assertEqual(report['status'], 'refused', report)
        self.assertEqual(report['files'], {})
        self.assert_denied_authority(report)
        self.assertEqual(set(inventory(self.destination)), {'STAGING.json'})
        serialized = (self.destination / 'STAGING.json').read_bytes()
        self.assertEqual(json.loads(serialized), report)
        for forbidden in (self.secret, str(self.outside).encode(),
                          str(self.private_file).encode(), str(self.source).encode()):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(report['reason'], 'unsafe_or_unreadable_evidence')
        self.process.assert_not_called()
        return report

    def assert_snapshot_refused(self, source=None, allowed=None):
        with self.assertRaises((staging.UnsafeEvidence, OSError, ValueError)):
            staging.snapshot_tree(self.source if source is None else source, allowed)


class SnapshotTests(TemporaryTree):
    def test_detached_snapshot_preserves_exact_binary_and_empty_file_bytes(self):
        original = {'linear/reference.o': b'\x00\xff\x80binary\r\n',
                    'linear/deferred.ll': b'; synthetic LLVM\n', 'RESULT.json': b''}
        for name, data in original.items():
            put(self.source, name, data)
        snapshot = staging.snapshot_tree(self.source)
        self.assertEqual(snapshot, original)
        put(self.source, 'linear/reference.o', b'changed after snapshot')
        self.assertEqual(snapshot, original)
        self.assertTrue(all(type(data) is bytes for data in snapshot.values()))
        self.process.assert_not_called()

    def test_exact_allowlist_accepts_only_selected_regular_files(self):
        put(self.source, 'RESULT.json', b'{}')
        put(self.source, 'linear/reference.ll', b'; synthetic')
        allowed = {'RESULT.json', 'linear/reference.ll'}
        self.assertEqual(set(staging.snapshot_tree(self.source, allowed)), allowed)
        put(self.source, 'linear/deferred.ll', b'extra')
        self.assert_snapshot_refused(allowed=allowed)

    def test_allowlist_rejects_absolute_and_parent_traversal_names(self):
        for name in ('../private-file', '/private-file', 'linear/../../private-file',
                     'linear/../RESULT.json'):
            with self.subTest(name=name):
                self.assert_snapshot_refused(allowed={name})

    def test_empty_allowlist_rejects_unlisted_empty_directory(self):
        (self.source / 'unexpected').mkdir()
        self.assert_snapshot_refused(allowed=set())

    def test_symlink_file_is_rejected_without_following_target(self):
        (self.source / 'RESULT.json').symlink_to(self.private_file)
        self.assert_snapshot_refused()

    def test_symlink_directory_is_rejected_without_traversing_target(self):
        (self.source / 'linear').symlink_to(self.outside, target_is_directory=True)
        self.assert_snapshot_refused()

    def test_symlink_root_is_rejected(self):
        alias = self.temporary / 'raw-alias'
        alias.symlink_to(self.source, target_is_directory=True)
        self.assert_snapshot_refused(source=alias)

    def test_symlink_ancestor_of_root_is_rejected(self):
        nested = self.outside / 'nested'
        nested.mkdir()
        alias = self.temporary / 'ancestor-alias'
        alias.symlink_to(self.outside, target_is_directory=True)
        self.assert_snapshot_refused(source=alias / 'nested')

    def test_hardlinked_regular_file_is_rejected(self):
        os.link(self.private_file, self.source / 'RESULT.json')
        self.assert_snapshot_refused()

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO required')
    def test_fifo_is_rejected_without_blocking_on_read(self):
        os.mkfifo(self.source / 'RESULT.json')
        self.assert_snapshot_refused()

    def test_socket_mode_is_rejected_without_opening_or_reading(self):
        # This executor denies socket creation. A synthetic stat result tests
        # the same nonordinary-file branch without attempting that syscall.
        put(self.source, 'RESULT.json', b'never read as socket')
        original_stat = os.stat
        def socket_mode(path, *args, **kwargs):
            result = original_stat(path, *args, **kwargs)
            if path == 'RESULT.json' and kwargs.get('dir_fd') is not None:
                values = {name: getattr(result, name) for name in dir(result) if name.startswith('st_')}
                values['st_mode'] = stat.S_IFSOCK | 0o600
                return SimpleNamespace(**values)
            return result
        with patch.object(staging.os, 'stat', side_effect=socket_mode):
            self.assert_snapshot_refused()

    def test_safe_read_file_enforces_remaining_budget(self):
        target = put(self.source, 'RESULT.json', b'1234')
        self.assertEqual(staging.safe_read_file(target, remaining=4), b'1234')
        with self.assertRaises(staging.UnsafeEvidence):
            staging.safe_read_file(target, remaining=3)

    def test_safe_read_file_rejects_symlink_in_any_parent_component(self):
        put(self.source, 'linear/reference.o', b'ordinary')
        alias = self.temporary / 'raw-alias'
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises((OSError, staging.UnsafeEvidence)):
            staging.safe_read_file(alias / 'linear/reference.o')

    def test_safe_read_file_rejects_direct_symlink_and_hardlink(self):
        for name, hardlink in (('symlink', False), ('hardlink', True)):
            target = self.source / name
            if hardlink:
                os.link(self.private_file, target)
            else:
                target.symlink_to(self.private_file)
            with self.subTest(name=name), self.assertRaises((OSError, staging.UnsafeEvidence)):
                staging.safe_read_file(target)

    def test_file_budget_accepts_boundary_and_rejects_one_more_byte(self):
        put(self.source, 'RESULT.json', b'12345678')
        with patch.object(staging, 'MAX_FILE_BYTES', 8):
            self.assertEqual(staging.snapshot_tree(self.source), {'RESULT.json': b'12345678'})
            put(self.source, 'RESULT.json', b'123456789')
            self.assert_snapshot_refused()

    def test_aggregate_snapshot_budget_counts_across_subdirectories(self):
        put(self.source, 'linear/reference.o', b'1234')
        put(self.source, 'affine/deferred.o', b'5678')
        with patch.object(staging, 'MAX_TOTAL_BYTES', 8):
            self.assertEqual(sum(map(len, staging.snapshot_tree(self.source).values())), 8)
            put(self.source, 'RESULT.json', b'9')
            self.assert_snapshot_refused()

    def test_file_replaced_with_symlink_between_stat_and_open_fails_closed(self):
        target = put(self.source, 'RESULT.json', b'ordinary')
        original_open = os.open
        replaced = []
        def substitute(path, flags, *args, **kwargs):
            if path == 'RESULT.json' and kwargs.get('dir_fd') is not None and not replaced:
                replaced.append(True)
                target.unlink()
                target.symlink_to(self.private_file)
            return original_open(path, flags, *args, **kwargs)
        with patch.object(staging.os, 'open', side_effect=substitute):
            self.assert_snapshot_refused()
        self.assertTrue(replaced)

    def test_directory_replaced_with_symlink_between_stat_and_open_fails_closed(self):
        put(self.source, 'linear/reference.o', b'ordinary')
        original_open = os.open
        replaced = []
        def substitute(path, flags, *args, **kwargs):
            if path == 'linear' and kwargs.get('dir_fd') is not None and not replaced:
                replaced.append(True)
                (self.source / 'linear').rename(self.temporary / 'detached-linear')
                (self.source / 'linear').symlink_to(self.outside, target_is_directory=True)
            return original_open(path, flags, *args, **kwargs)
        with patch.object(staging.os, 'open', side_effect=substitute):
            self.assert_snapshot_refused()
        self.assertTrue(replaced)

    def test_disappearing_file_is_not_silently_omitted_from_snapshot(self):
        target = put(self.source, 'RESULT.json', b'ordinary')
        original_open = os.open
        removed = []
        def disappear(path, flags, *args, **kwargs):
            if path == 'RESULT.json' and kwargs.get('dir_fd') is not None and not removed:
                removed.append(True)
                target.unlink()
            return original_open(path, flags, *args, **kwargs)
        with patch.object(staging.os, 'open', side_effect=disappear):
            self.assert_snapshot_refused()
        self.assertTrue(removed)


class StagingTests(TemporaryTree):
    def test_allowlist_is_exactly_the_frozen_campaign_artifacts(self):
        expected = {'REGISTRATION.json', 'RESULT.json'}
        for workload in ('linear', 'affine'):
            expected.update(workload + '/' + name + '.json'
                            for name in ('PROPOSAL', 'CHECK', 'REFERENCE_PROOF'))
            expected.update(workload + '/' + arm + '.' + suffix
                            for arm in ('reference', 'deferred')
                            for suffix in ('core.json', 'll', 'llvm.json', 'o', 'text.bin',
                                           'asm', 'symbols', 'trace.o', 'shrink-wrap.mir.txt'))
        self.assertEqual(staging.allowed_artifact_paths(), expected)
        self.assertEqual(staging.LOG_NAMES, set(LOG_NAMES))
        self.assertEqual(staging.MAX_FILE_BYTES, 256 * 1024 * 1024)
        self.assertEqual(staging.MAX_TOTAL_BYTES, 512 * 1024 * 1024)

    def test_complete_safe_tree_and_both_logs_are_staged_with_hashes(self):
        original = {name: ('synthetic artifact: ' + name + '\n').encode()
                    for name in staging.allowed_artifact_paths()}
        for name, data in original.items():
            put(self.source, name, data)
        report = self.run_stage()
        self.assertEqual(report['status'], 'staged', report)
        self.assert_denied_authority(report)
        self.assertEqual(report['missing'], [])
        expected = {'evidence/' + name: data for name, data in original.items()}
        expected.update({'logs/' + name: path.read_bytes() for name, path in self.logs.items()})
        staged = inventory(self.destination)
        receipt = json.loads(staged.pop('STAGING.json'))
        self.assertEqual(receipt, report)
        self.assertEqual(staged, expected)
        self.assertEqual(report['files'], {name: {'sha256': sha256(data).hexdigest(), 'bytes': len(data)}
                                           for name, data in expected.items()})
        self.assertEqual(inventory(self.source), original)
        self.assertFalse(any(path.is_symlink() for path in self.destination.rglob('*')))
        self.process.assert_not_called()

    def test_failed_partial_run_stages_only_existing_evidence_and_available_logs(self):
        result = b'{"status":"failed","authority":"DENY_ALL"}\n'
        put(self.source, 'RESULT.json', result)
        put(self.source, 'linear/PROPOSAL.json', b'{}')
        self.logs['layout-run.log'].unlink()
        report = self.run_stage()
        self.assertEqual(report['status'], 'staged')
        self.assertEqual(report['missing'], ['layout-run.log'])
        self.assertEqual(set(report['files']), {'evidence/RESULT.json',
            'evidence/linear/PROPOSAL.json', 'logs/layout-tests.log'})
        self.assertEqual((self.destination / 'evidence/RESULT.json').read_bytes(), result)
        self.assert_denied_authority(report)

    def test_running_receipt_is_preserved_without_claiming_completed_diagnostic(self):
        put(self.source, 'RESULT.json', b'{"status":"running"}')
        report = self.run_stage(logs={})
        self.assertEqual(report['status'], 'staged')
        self.assertEqual(json.loads((self.destination / 'evidence/RESULT.json').read_text())['status'], 'running')
        self.assert_denied_authority(report)

    def test_absent_raw_root_can_stage_logs_but_reports_missing_source(self):
        self.source.rmdir()
        report = self.run_stage()
        self.assertEqual(report['status'], 'staged')
        self.assertEqual(report['missing'], ['source'])
        self.assertEqual(set(report['files']), {'logs/' + name for name in LOG_NAMES})

    def test_empty_source_and_expected_empty_workload_directories_are_safe(self):
        for workload in ('linear', 'affine'):
            (self.source / workload).mkdir()
        report = self.run_stage(logs={})
        self.assertEqual(report['status'], 'staged')
        self.assertEqual(report['files'], {})
        self.assertEqual(set(inventory(self.destination)), {'STAGING.json'})

    def test_symlink_file_refuses_entire_payload_even_after_safe_file(self):
        put(self.source, 'REGISTRATION.json', b'safe but must not be copied')
        (self.source / 'RESULT.json').symlink_to(self.private_file)
        self.assert_refused()

    def test_symlink_workload_directory_refuses_entire_payload(self):
        put(self.source, 'RESULT.json', b'safe but must not be copied')
        (self.source / 'linear').symlink_to(self.outside, target_is_directory=True)
        self.assert_refused()

    def test_symlink_raw_root_refuses_entire_payload(self):
        alias = self.temporary / 'raw-alias'
        alias.symlink_to(self.source, target_is_directory=True)
        self.assert_refused(source=alias)

    def test_symlink_raw_ancestor_refuses_entire_payload(self):
        alias = self.temporary / 'ancestor-alias'
        alias.symlink_to(self.temporary, target_is_directory=True)
        self.assert_refused(source=alias / 'raw')

    def test_each_log_symlink_refuses_all_safe_evidence_and_logs(self):
        put(self.source, 'RESULT.json', b'safe but must not be copied')
        for index, name in enumerate(LOG_NAMES):
            with self.subTest(log=name):
                self.destination = self.temporary / ('upload-' + str(index))
                path = self.logs[name]
                path.unlink()
                path.symlink_to(self.private_file)
                self.assert_refused()
                path.unlink()
                path.write_bytes(b'restored safe log')

    def test_each_log_symlink_ancestor_refuses_entire_payload(self):
        put(self.source, 'RESULT.json', b'safe but must not be copied')
        alias = self.temporary / 'log-ancestor-alias'
        alias.symlink_to(self.temporary / 'logs', target_is_directory=True)
        for index, name in enumerate(LOG_NAMES):
            with self.subTest(log=name):
                self.destination = self.temporary / ('upload-' + str(index))
                logs = {**self.logs, name: alias / name}
                self.assert_refused(logs=logs)

    def test_hardlinked_evidence_refuses_payload(self):
        os.link(self.private_file, self.source / 'RESULT.json')
        self.assert_refused()

    def test_each_hardlinked_log_refuses_payload(self):
        for index, name in enumerate(LOG_NAMES):
            with self.subTest(log=name):
                self.destination = self.temporary / ('upload-' + str(index))
                path = self.logs[name]
                path.unlink()
                os.link(self.private_file, path)
                self.assert_refused()
                path.unlink()
                path.write_bytes(b'restored safe log')

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO required')
    def test_fifo_evidence_and_log_refuse_without_blocking(self):
        os.mkfifo(self.source / 'RESULT.json')
        self.assert_refused()
        (self.source / 'RESULT.json').unlink()
        self.destination = self.temporary / 'upload-log'
        self.logs['layout-run.log'].unlink()
        os.mkfifo(self.logs['layout-run.log'])
        self.assert_refused()

    def test_socket_mode_for_evidence_and_log_refuses_without_reading(self):
        # Socket metadata is mocked because this executor denies AF_UNIX
        # socket creation; all link and FIFO controls use real fixtures.
        original_stat = os.stat
        for index, name in enumerate(('RESULT.json', 'layout-run.log')):
            self.destination = self.temporary / ('upload-' + str(index))
            if name == 'RESULT.json':
                put(self.source, name, b'never read as socket')
            def socket_mode(path, *args, **kwargs):
                result = original_stat(path, *args, **kwargs)
                if path == name and kwargs.get('dir_fd') is not None:
                    values = {field: getattr(result, field) for field in dir(result) if field.startswith('st_')}
                    values['st_mode'] = stat.S_IFSOCK | 0o600
                    return SimpleNamespace(**values)
                return result
            with self.subTest(name=name), patch.object(staging.os, 'stat', side_effect=socket_mode):
                self.assert_refused()

    def test_unexpected_old_zip_is_refused_without_publishing_any_payload(self):
        put(self.source, 'RESULT.json', b'safe but must not be copied')
        put(self.source, 'older-blocked-evidence.zip', self.secret)
        self.assert_refused()

    def test_unexpected_empty_directory_is_refused(self):
        (self.source / 'previous-campaign').mkdir()
        self.assert_refused()

    def test_nested_unregistered_artifact_is_refused(self):
        put(self.source, 'linear/deferred.ll', b'safe but must not be copied')
        put(self.source, 'linear/old-shared-library.so', self.secret)
        self.assert_refused()

    def test_arbitrary_or_traversing_log_keys_are_refused(self):
        for index, name in enumerate(('old-upload.zip', '../escape.log', '/absolute.log')):
            with self.subTest(name=name):
                self.destination = self.temporary / ('upload-' + str(index))
                self.assert_refused(logs={name: self.private_file})
        self.assertFalse((self.temporary / 'escape.log').exists())

    def test_per_file_limit_covers_evidence_and_each_log(self):
        put(self.source, 'RESULT.json', b'123456789')
        with patch.object(staging, 'MAX_FILE_BYTES', 8):
            self.assert_refused(logs={})
        (self.source / 'RESULT.json').unlink()
        for index, name in enumerate(LOG_NAMES):
            with self.subTest(log=name):
                self.destination = self.temporary / ('upload-log-' + str(index))
                self.logs[name].write_bytes(b'123456789')
                with patch.object(staging, 'MAX_FILE_BYTES', 8):
                    self.assert_refused(logs={name: self.logs[name]})

    def test_total_limit_counts_raw_artifacts_and_logs_together(self):
        put(self.source, 'RESULT.json', b'1234')
        self.logs['layout-tests.log'].write_bytes(b'5678')
        self.logs['layout-run.log'].write_bytes(b'9')
        with patch.object(staging, 'MAX_TOTAL_BYTES', 8):
            self.assert_refused()

    def test_total_limit_accepts_exact_boundary_across_raw_and_both_logs(self):
        put(self.source, 'RESULT.json', b'1234')
        self.logs['layout-tests.log'].write_bytes(b'56')
        self.logs['layout-run.log'].write_bytes(b'78')
        with patch.object(staging, 'MAX_TOTAL_BYTES', 8):
            report = self.run_stage()
        self.assertEqual(report['status'], 'staged')
        self.assertEqual(sum(item['bytes'] for item in report['files'].values()), 8)

    def test_io_error_text_cannot_leak_private_path_or_contents_in_report(self):
        message = str(self.private_file) + ': ' + self.secret.decode()
        with patch.object(staging, 'snapshot_tree', side_effect=OSError(message)):
            report = self.assert_refused()
        self.assertEqual(report['error_type'], 'OSError')

    def test_disappearing_source_entry_refuses_instead_of_claiming_missing_source(self):
        put(self.source, 'RESULT.json', b'ordinary')
        with patch.object(staging, 'snapshot_tree', side_effect=FileNotFoundError('hostile pathname')):
            report = self.assert_refused()
        self.assertNotIn('source', report['missing'])

    def test_existing_destination_is_refused_without_modifying_it(self):
        self.destination.mkdir()
        put(self.destination, 'existing.txt', b'keep existing data')
        with self.assertRaises((FileExistsError, staging.UnsafeEvidence)):
            self.run_stage()
        self.assertEqual(inventory(self.destination), {'existing.txt': b'keep existing data'})

    def test_symlink_destination_is_refused_without_following_it(self):
        self.destination.symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises((OSError, staging.UnsafeEvidence)):
            self.run_stage()
        self.assertEqual(inventory(self.outside), {'private-file': self.secret})

    def test_symlink_destination_ancestor_is_refused(self):
        alias = self.temporary / 'destination-alias'
        alias.symlink_to(self.outside, target_is_directory=True)
        self.destination = alias / 'upload'
        with self.assertRaises((OSError, staging.UnsafeEvidence)):
            self.run_stage()
        self.assertFalse((self.outside / 'upload').exists())

    def test_overlapping_source_and_destination_are_refused(self):
        for destination in (self.source, self.source / 'upload', self.temporary):
            with self.subTest(destination=destination), self.assertRaises(staging.UnsafeEvidence):
                staging.stage(self.source, destination, {})
        self.assertEqual(inventory(self.source), {})

    def test_post_snapshot_source_changes_do_not_change_staged_detached_bytes(self):
        put(self.source, 'RESULT.json', b'original snapshot')
        original_snapshot = staging.snapshot_tree
        def mutate_after_snapshot(source, allowed):
            captured = original_snapshot(source, allowed)
            put(self.source, 'RESULT.json', b'modified later')
            return captured
        with patch.object(staging, 'snapshot_tree', side_effect=mutate_after_snapshot):
            report = self.run_stage(logs={})
        self.assertEqual(report['status'], 'staged')
        self.assertEqual((self.destination / 'evidence/RESULT.json').read_bytes(), b'original snapshot')
        self.assertEqual(report['files']['evidence/RESULT.json']['sha256'], sha256(b'original snapshot').hexdigest())


if __name__ == '__main__':
    unittest.main()
