"""Finite source/IO controls for the explicit publication evidence observer.

These controls do not compile HIA, run a publication application, execute the
original 39 methods, or change their poison/limits.  The two small child uses
are ordinary process-record controls with their own explicit 3 second bounds.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tools import hia_artifact_publication_custody as custody
from tools import qualify_hia_artifact_publication_tests as qualifier


class _FailedResult:
    testsRun = 0

    @staticmethod
    def wasSuccessful():
        return False


class PublicationCustodyObserverTests(unittest.TestCase):
    def setUp(self):
        retained = os.environ.get('HEPTA_PUBLICATION_OBSERVER_CONTROL_RETAIN')
        if retained:
            # Explicit source-control custody only.  Normal discovery keeps
            # ordinary TemporaryDirectory cleanup; product tests are untouched.
            self.folder = None
            self.root = Path(tempfile.mkdtemp(prefix='hia-publication-observer-control-', dir=retained))
        else:
            self.folder = tempfile.TemporaryDirectory(prefix='hia-publication-observer-control-')
            self.addCleanup(self.folder.cleanup)
            self.root = Path(self.folder.name)
        self.session = custody.Session(self.root / 'records')
        self.session.test_id = self.id()
        self.executable = self.root / 'control-executable'
        # This file is retained by preflight-only controls, not executed.
        self.executable.write_bytes(b'CONTROL-ONLY-NOT-A-PRODUCT-IMAGE\n')
        self.argv = [str(self.executable), 'store-hash', str(self.root), 'a' * 64]

    def call(self, wire=b'complete offered input', **kwargs):
        return custody._Call(self.session, self.argv, wire, 3,
                             'finite observer control only', {'capture_output': True, **kwargs})

    def hold(self):
        record = self.session.finish(_FailedResult())
        self.assertEqual(record['status'], 'TESTS_FAIL_OR_CUSTODY_HOLD')
        actual, _ = custody.read_file(self.session.root / 'RUN.json')
        self.assertEqual(json.loads(actual), record)
        return record

    def incomplete(self, stage):
        self.assertEqual(len(self.session.calls), 1)
        call = self.session.calls[0]
        row = call.summary()
        self.assertEqual(row['test_id'], self.id())
        self.assertFalse(row['launch_attempted'])
        self.assertFalse(row['launch_completed'])
        self.assertIsNone(row['process'])
        self.assertEqual(row['preflight']['stage'], stage)
        self.assertFalse(row['preflight']['complete'])
        self.assertEqual(row['preflight']['error']['stage'], stage)
        self.assertTrue(row['record_errors'])
        self.assertTrue(custody.direct_child_custody_closed(row))
        return call, row

    def test_evidence_fsync_is_bound_while_shared_product_poison_remains_effective(self):
        actual = custody._EVIDENCE_FSYNC
        observed = []

        def record(fd):
            observed.append(os.fstat(fd).st_mode)
            return actual(fd)

        with patch.object(custody, '_EVIDENCE_FSYNC', side_effect=record), \
                patch.object(os, 'fsync', side_effect=AssertionError('host artifact fsync')) as poison:
            result = custody.write_new(self.root / 'evidence.bin', b'\0evidence\xff')
            self.assertEqual((self.root / 'evidence.bin').read_bytes(), b'\0evidence\xff')
            self.assertEqual(result['sha256'], sha256(b'\0evidence\xff').hexdigest())
            self.assertEqual(len(observed), 2)  # actual file and parent durability
            poison.assert_not_called()
            fd = os.open(self.root / 'evidence.bin', os.O_RDONLY)
            try:
                with self.assertRaisesRegex(AssertionError, 'host artifact fsync'):
                    os.fsync(fd)
            finally:
                os.close(fd)
            self.assertEqual(poison.call_count, 1)

    def test_complete_call_preflight_preserves_request_under_original_shared_poison(self):
        wire = b'\0independent offered payload\xff'
        with patch.object(os, 'fsync', side_effect=AssertionError('host artifact fsync')) as poison:
            call = self.call(wire)
            poison.assert_not_called()
        row = call.summary()
        self.assertEqual(row['preflight']['stage'], 'READY')
        self.assertTrue(row['preflight']['complete'])
        self.assertTrue(row['preflight']['request_written'])
        self.assertIsNone(row['preflight']['error'])
        self.assertEqual((call.root / 'stdin.offered.bin').read_bytes(), wire)
        self.assertEqual((call.root / 'executable.bin').read_bytes(), self.executable.read_bytes())
        request = json.loads((call.root / 'request.json').read_bytes())
        self.assertEqual(request, call.request)
        self.assertEqual(request['timeout'], 3)
        self.assertEqual(request['argv'], self.argv)
        self.assertFalse(row['launch_attempted'])

    def test_sealed_descriptor_preflight_uses_same_durability_binding(self):
        fd = os.memfd_create('observer-control', os.MFD_CLOEXEC)
        try:
            data = b'raw descriptor control; never executed'
            os.write(fd, data)
            self.argv[0] = '/proc/self/fd/' + str(fd)
            with patch.object(os, 'fsync', side_effect=AssertionError('host artifact fsync')) as poison:
                call = self.call(pass_fds=(fd,))
                poison.assert_not_called()
            self.assertEqual((call.root / 'executable.bin').read_bytes(), data)
            self.assertEqual(call.request['executable_original_identity'], custody.identity(os.fstat(fd)))
            self.assertEqual(call.request['pass_fds'], [fd])
        finally:
            os.close(fd)

    def test_invalid_wire_retains_initialized_call_and_run_failure(self):
        with self.assertRaisesRegex(TypeError, 'exact bytes'):
            self.call(bytearray(b'invalid wire type'))
        call, row = self.incomplete('ARGUMENTS')
        self.assertIsNone(call.request)
        self.assertIsNone(row['preflight']['stdin'])
        self.assertFalse((call.root / 'request.json').exists())
        record = self.hold()
        self.assertEqual(record['calls'][0]['preflight']['error']['type'], 'TypeError')
        self.assertEqual(record['tests_run'], 0)

    def test_existing_call_directory_failure_is_not_erased_by_summary(self):
        (self.session.root / 'calls' / '00000').mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):
            self.call()
        call, row = self.incomplete('DIRECTORY')
        self.assertFalse(row['preflight']['root_created'])
        self.assertIsNone(call.request)
        self.hold()

    def test_missing_executable_retains_complete_offered_stdin(self):
        self.executable.unlink()
        with self.assertRaises(FileNotFoundError):
            self.call(b'full bytes before executable failure')
        call, row = self.incomplete('EXECUTABLE_READ')
        self.assertEqual((call.root / 'stdin.offered.bin').read_bytes(), b'full bytes before executable failure')
        self.assertIsNotNone(row['preflight']['stdin'])
        self.assertIsNone(row['preflight']['executable'])
        self.hold()

    def test_symlink_executable_is_still_refused_and_original_link_unchanged(self):
        linked = self.root / 'linked-executable'
        linked.symlink_to(self.executable.name)
        self.argv[0] = str(linked)
        with self.assertRaises(ValueError):
            self.call()
        self.incomplete('EXECUTABLE_READ')
        self.assertTrue(linked.is_symlink())
        self.hold()

    def test_real_custody_fsync_failure_retains_partial_stdin_and_holds(self):
        wire = b'actual write before injected observer fsync failure'
        with patch.object(custody, '_EVIDENCE_FSYNC', side_effect=OSError('observer durability failure')):
            with self.assertRaisesRegex(OSError, 'observer durability failure'):
                self.call(wire)
        call, row = self.incomplete('STDIN')
        self.assertEqual((call.root / 'stdin.offered.bin').read_bytes(), wire)
        self.assertIsNone(row['preflight']['stdin'])  # no false durable receipt
        self.assertIsNone(call.request)
        self.hold()

    def test_partial_executable_write_preserves_both_originals_and_error_stage(self):
        original = custody.write_new

        def fail(path, data):
            if Path(path).name == 'executable.bin':
                original(path, data[:7])
                raise OSError('partial executable custody')
            return original(path, data)

        with patch.object(custody, 'write_new', side_effect=fail):
            with self.assertRaisesRegex(OSError, 'partial executable custody'):
                self.call(b'stdin survives')
        call, row = self.incomplete('EXECUTABLE_WRITE')
        self.assertEqual((call.root / 'stdin.offered.bin').read_bytes(), b'stdin survives')
        self.assertEqual((call.root / 'executable.bin').read_bytes(), self.executable.read_bytes()[:7])
        self.assertIsNone(row['preflight']['executable'])
        self.hold()

    def test_partial_request_is_preserved_without_claiming_it_was_written(self):
        original = custody.write_json

        def fail(path, value):
            if Path(path).name == 'request.json':
                custody.write_new(path, b'{"partial":')
                raise OSError('partial request custody')
            return original(path, value)

        with patch.object(custody, 'write_json', side_effect=fail):
            with self.assertRaisesRegex(OSError, 'partial request custody'):
                self.call()
        call, row = self.incomplete('REQUEST_WRITE')
        self.assertEqual((call.root / 'request.json').read_bytes(), b'{"partial":')
        self.assertFalse(row['preflight']['request_written'])
        self.assertEqual(row['preflight']['unwritten_request_data'], call.request)
        self.hold()
        quiet = qualifier.quiescence(self.session.root)
        self.assertEqual([r['ordinal'] for r in quiet['incomplete_preflight_requests']], [0])
        self.assertFalse(quiet['ready_for_fixture_read'])  # actual runner still alive

    def test_quiescence_does_not_parse_absent_unlaunched_request(self):
        with self.assertRaises(TypeError):
            self.call(bytearray())
        call, _ = self.incomplete('ARGUMENTS')
        self.hold()
        self.assertFalse((call.root / 'request.json').exists())
        quiet = qualifier.quiescence(self.session.root)
        self.assertEqual(quiet['not_observed_reaped'], [])
        self.assertEqual(len(quiet['incomplete_preflight_requests']), 1)
        self.assertFalse(quiet['ready_for_fixture_read'])

    def test_quiescence_never_treats_launched_partial_record_as_unlaunched(self):
        with self.assertRaises(TypeError):
            self.call(bytearray())
        record = self.hold()
        record['calls'][0]['launch_attempted'] = True
        (self.session.root / 'RUN.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'not proven unlaunched'):
            qualifier.quiescence(self.session.root)

    def test_quiescence_rejects_boolean_shape_corruption(self):
        with self.assertRaises(TypeError):
            self.call(bytearray())
        record = self.hold()
        record['calls'][0]['preflight']['complete'] = 0
        (self.session.root / 'RUN.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'shape'):
            qualifier.quiescence(self.session.root)

    def test_completed_preflight_missing_request_is_not_silently_skipped(self):
        call = self.call()
        self.hold()
        (call.root / 'request.json').unlink()
        with self.assertRaises(FileNotFoundError):
            qualifier.quiescence(self.session.root)

    def test_real_exited_preflight_runner_allows_failed_originals_custody_only(self):
        destination = self.root / 'child-records'
        source = Path(custody.__file__).resolve().parents[1]
        script = (
            'import sys;sys.path.insert(0,sys.argv[1]);'
            'from pathlib import Path;'
            'from tools import hia_artifact_publication_custody as c;'
            'from tools import qualify_hia_artifact_publication_tests as q;'
            'import unittest;'
            '\nclass T(unittest.TestCase):'
            '\n def id(self):return "SOURCE_CONTROL_ONLY.PREFLIGHT_FAILURE"'
            '\n def runTest(self):c._Call(c._ACTIVE,[sys.argv[3],"store-hash",sys.argv[2],"a"*64],bytearray(),3,"source control only",{})'
            '\nq.MODULES=("SOURCE_CONTROL_ONLY",)'
            '\nq.ORIGINAL_TEST_IDS=("SOURCE_CONTROL_ONLY.PREFLIGHT_FAILURE",)'
            '\nq.source_snapshot=lambda:{"scope":"synthetic source-control runner only"}'
            '\nq.copy_inputs=lambda session:{"original39_executed":False,"native_executed":False}'
            '\nq.unittest.defaultTestLoader.loadTestsFromNames=lambda names:unittest.TestSuite([T()])'
            '\nraise SystemExit(q.run_tests(sys.argv[2]))\n'
        )
        completed = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script,
                                    str(source), str(destination), str(self.executable)],
                                   capture_output=True, timeout=3)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(json.loads(completed.stdout)['status'], 'HOLD')
        self.assertIn(b'TypeError: test native stdin must be exact bytes', completed.stderr)
        custody.write_new(self.root / 'synthetic-runner.stdout.log', completed.stdout)
        custody.write_new(self.root / 'synthetic-runner.stderr.log', completed.stderr)
        record = json.loads((destination / 'RUN.json').read_bytes())
        self.assertEqual(record['status'], 'TESTS_FAIL_OR_CUSTODY_HOLD')
        self.assertEqual(record['tests_run'], 1)
        report = json.loads((destination / 'REPORT.json').read_bytes())
        self.assertEqual(report['status'], 'HOLD')
        self.assertEqual(report['expected_test_ids'], ['SOURCE_CONTROL_ONLY.PREFLIGHT_FAILURE'])
        self.assertEqual(report['anomalies']['errors'], 1)
        self.assertNotIn('failure', report)  # the original case error was not replaced by finalizer failure
        quiet = qualifier.quiescence(destination)
        self.assertTrue(quiet['ready_for_fixture_read'])
        self.assertEqual(len(quiet['incomplete_preflight_requests']), 1)
        self.assertFalse(quiet['full_process_tree_cleanup_claimed'])
        archive = self.root / 'actual-archive'
        self.assertEqual(qualifier.archive_evidence(destination, archive), 0)
        manifest = json.loads((archive / 'TYPED-MANIFEST.json').read_bytes())
        archive_report = json.loads((archive / 'ARCHIVE.json').read_bytes())
        self.assertEqual(archive_report['status'], 'CLOSED_ORIGINAL_FIXTURES_RETAINED')
        self.assertFalse(archive_report['test_result_reclassified'])
        with tarfile.open(archive / 'publication-originals.tar.gz', 'r:gz') as stream:
            names = {member.name for member in stream}
        self.assertTrue(any(name.endswith('/REPORT.json') for name in names))
        self.assertTrue(any(name.endswith('/RUN.json') for name in names))
        self.assertEqual(archive_report['typed_members'], len(manifest))
        self.assertEqual(json.loads((destination / 'REPORT.json').read_bytes())['status'], 'HOLD')

    def test_real_control_child_is_observed_under_poison_without_disabling_product_poison(self):
        self.executable.write_bytes(b'#!/bin/sh\nprintf "observer-control-only\\n"\n')
        self.executable.chmod(0o700)
        with patch.object(os, 'fsync', side_effect=AssertionError('host artifact fsync')) as poison:
            completed = self.session.run(self.argv, input=b'control stdin', capture_output=True, timeout=3)
            poison.assert_not_called()
            with self.assertRaisesRegex(AssertionError, 'host artifact fsync'):
                os.fsync(0)
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr),
                         (0, b'observer-control-only\n', b''))
        call = self.session.calls[0]
        self.assertTrue(custody.direct_child_custody_closed(call.summary()))
        record = self.hold()  # a source-control child is never a product PASS
        self.assertEqual(record['tests_run'], 0)
        self.assertEqual(record['calls'][0]['returncode'], 0)
        self.assertEqual(call.request['timeout'], 3)
        returned = [r for r in call.events if r['kind'] == 'COMMUNICATE_RETURN']
        self.assertEqual(len(returned), 1)
        out = returned[0]['stdout']
        self.assertEqual(Path(out['path']).read_bytes(), completed.stdout)


if __name__ == '__main__':
    unittest.main()
