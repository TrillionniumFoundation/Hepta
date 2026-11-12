"""Six source-only controls for the fixed system-interpreter admission.

No product modules, compiler or native image are imported. Runtime and fixture
bytes are only read; chmod is limited to private temporary source fixtures.
"""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

CONTROL = Path(__file__).resolve().parent
sys.path.insert(0, str(CONTROL))
import common

EXPECTED = [
    '__main__.RuntimeAdmissionSourceTests.test_declared_size_bound_still_precedes_payload',
    '__main__.RuntimeAdmissionSourceTests.test_exact_pinned_runtime_read',
    '__main__.RuntimeAdmissionSourceTests.test_ordinary_sources_keep_original_owner_and_mode_rules',
    '__main__.RuntimeAdmissionSourceTests.test_other_paths_and_links_do_not_inherit_runtime_role',
    '__main__.RuntimeAdmissionSourceTests.test_runtime_hash_is_required_after_complete_read',
    '__main__.RuntimeAdmissionSourceTests.test_runtime_metadata_rejections_precede_payload',
]
OBSERVATIONS = {}


def changed_stat(value, changes):
    fields = {name: getattr(value, name) for name in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size',
        'st_mtime_ns', 'st_ctime_ns')}
    fields.update(changes)
    return SimpleNamespace(**fields)


class RuntimeAdmissionSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runtime = Path(common.PINNED_INTERPRETER_PATH)
        cls.runtime_before = common.identity(cls.runtime.stat())
        cls.original_fstat = os.fstat
        OBSERVATIONS['runtime_before'] = cls.runtime_before

    @classmethod
    def tearDownClass(cls):
        after = common.identity(cls.runtime.stat())
        OBSERVATIONS['runtime_after'] = after
        if after != cls.runtime_before:
            raise AssertionError('read-only source controls changed runtime identity')

    def refuse_before_read(self, path, changes, maximum=None):
        target = path.stat()
        target_key = target.st_dev, target.st_ino
        original = self.original_fstat

        def fstat(fd):
            value = original(fd)
            if (value.st_dev, value.st_ino) == target_key:
                return changed_stat(value, changes)
            return value

        with mock.patch.object(common.os, 'fstat', side_effect=fstat):
            with mock.patch.object(common.os, 'read', side_effect=AssertionError('payload read before refusal')) as reads:
                with self.assertRaises(ValueError):
                    common.pin(path, maximum if maximum is not None else max(1, target.st_size))
                self.assertEqual(reads.call_count, 0)

    def test_declared_size_bound_still_precedes_payload(self):
        with mock.patch.object(common.os, 'read', side_effect=AssertionError('payload exceeds bound')) as reads:
            with self.assertRaisesRegex(ValueError, 'declared bound'):
                common.pin(self.runtime, common.PINNED_INTERPRETER_METADATA[3] - 1)
            self.assertEqual(reads.call_count, 0)

    def test_exact_pinned_runtime_read(self):
        actual = common.pin(self.runtime, common.PINNED_INTERPRETER_METADATA[3])
        self.assertEqual(actual['path'], common.PINNED_INTERPRETER_PATH)
        self.assertEqual(actual['sha256'], common.PINNED_INTERPRETER_SHA256)
        self.assertEqual((actual['identity']['uid'], actual['identity']['gid'],
                          actual['mode'], actual['size']), common.PINNED_INTERPRETER_METADATA)
        self.assertEqual(actual['identity']['nlink'], 1)
        OBSERVATIONS['actual_runtime_read'] = actual

    def test_ordinary_sources_keep_original_owner_and_mode_rules(self):
        with tempfile.TemporaryDirectory(prefix='numeric-source-owner-') as directory:
            path = Path(directory) / 'source.txt'
            path.write_bytes(b'ordinary control source\n')
            path.chmod(0o600)
            raw, actual = common.read_file(path, 1024)
            self.assertEqual(raw, b'ordinary control source\n')
            self.assertEqual(actual['identity']['uid'], os.geteuid())
            for mode in (0o620, 0o602, 0o666):
                with self.subTest(mode=oct(mode)):
                    path.chmod(mode)
                    with mock.patch.object(common.os, 'read', side_effect=AssertionError('writable source read')) as reads:
                        with self.assertRaisesRegex(ValueError, 'ownership or writable mode'):
                            common.pin(path)
                        self.assertEqual(reads.call_count, 0)
            path.chmod(0o600)
            wrong_uid = next(value for value in (65534, 65533, 65532) if value not in (0, os.geteuid()))
            self.refuse_before_read(path, {'st_uid': wrong_uid})

    def test_other_paths_and_links_do_not_inherit_runtime_role(self):
        with tempfile.TemporaryDirectory(prefix='numeric-runtime-alias-') as directory:
            path = Path(directory) / 'python3.12'
            path.write_bytes(b'not the pinned interpreter')
            path.chmod(0o755)
            self.assertNotEqual(str(path), common.PINNED_INTERPRETER_PATH)
            self.refuse_before_read(path, {'st_uid': 65534, 'st_gid': 65534})
            alias = Path(directory) / 'runtime-link'
            alias.symlink_to(self.runtime)
            with mock.patch.object(common.os, 'read', side_effect=AssertionError('symlink target read')) as reads:
                with self.assertRaises(OSError):
                    common.pin(alias)
                self.assertEqual(reads.call_count, 0)

    def test_runtime_hash_is_required_after_complete_read(self):
        original_sha256 = sha256
        observed = []

        class WrongDigest:
            def __init__(self):
                self.original = original_sha256()
                self.count = 0
                observed.append(self)

            def update(self, raw):
                self.original.update(raw)
                self.count += len(raw)

            def hexdigest(self):
                return '0' * 64

        with mock.patch.object(common, 'sha256', side_effect=WrongDigest):
            with self.assertRaisesRegex(ValueError, 'interpreter bytes differ'):
                common.pin(self.runtime)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0].count, common.PINNED_INTERPRETER_METADATA[3])
        self.assertEqual(observed[0].original.hexdigest(), common.PINNED_INTERPRETER_SHA256)
        OBSERVATIONS['wrong_digest_control'] = {
            'actual_bytes_read': observed[0].count,
            'actual_bytes_sha256': observed[0].original.hexdigest(),
            'injected_digest': '0' * 64,
            'runtime_bytes_mutated': False,
        }

    def test_runtime_metadata_rejections_precede_payload(self):
        for changes in (
            {'st_uid': 65533}, {'st_gid': 65533},
            {'st_mode': stat.S_IFREG | 0o775}, {'st_mode': stat.S_IFREG | 0o754},
            {'st_size': common.PINNED_INTERPRETER_METADATA[3] - 1},
            {'st_nlink': 2}, {'st_mode': stat.S_IFIFO | 0o600},
        ):
            with self.subTest(changes=changes):
                self.refuse_before_read(self.runtime, changes)


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed_ids = []

    def startTest(self, test):
        self.executed_ids.append(test.id())
        super().startTest(test)


def file_pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'size': len(raw), 'sha256': sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(mode=0o700)
    source_paths = [CONTROL / 'common.py', Path(__file__).resolve(),
                    CONTROL / 'run_source_permissions.py']
    before = [file_pin(path) for path in source_paths]
    report = {'schema': 'hepta.hia.numeric-runtime-admission-source-controls.v1',
              'status': 'HOLD', 'expected_ids': EXPECTED, 'native_executed': False,
              'compiler_executed': False, 'product_module_imported': False,
              'source_before': before}
    started = time.monotonic()
    try:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(RuntimeAdmissionSourceTests)
        loaded = [test.id() for test in suite]
        report['loaded_ids'] = loaded
        if loaded != EXPECTED or unittest.defaultTestLoader.errors:
            raise AssertionError('exact six source methods were not loaded')
        with (args.evidence / 'unittest.log').open('x') as log:
            with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('child process forbidden')):
                with mock.patch.object(ctypes, 'CDLL', side_effect=AssertionError('native library forbidden')):
                    with mock.patch.object(ctypes, 'PyDLL', side_effect=AssertionError('native library forbidden')):
                        result = unittest.TextTestRunner(stream=log, verbosity=2,
                            resultclass=RecordedResult).run(suite)
        anomalies = {
            'failures': [(test.id(), text) for test, text in result.failures],
            'errors': [(test.id(), text) for test, text in result.errors],
            'skips': [(test.id(), text) for test, text in result.skipped],
            'expected_failures': [(test.id(), text) for test, text in result.expectedFailures],
            'unexpected_successes': [test.id() for test in result.unexpectedSuccesses],
        }
        report.update(executed_ids=result.executed_ids, tests_run=result.testsRun,
                      anomalies=anomalies, observations=OBSERVATIONS)
        if result.testsRun == 6 and result.executed_ids == EXPECTED and not any(anomalies.values()):
            report['status'] = 'SOURCE_CONTROLS_PASS'
    except BaseException:
        import traceback
        report['status'] = 'HOLD'
        report['error'] = traceback.format_exc()
    finally:
        report['seconds'] = time.monotonic() - started
        report['source_after'] = [file_pin(path) for path in source_paths]
        if report['source_after'] != before:
            report['status'] = 'HOLD'
        with (args.evidence / 'report.json').open('x') as stream:
            json.dump(report, stream, sort_keys=True, indent=2)
            stream.write('\n')
    print(json.dumps({'status': report['status'], 'tests_run': report.get('tests_run')}))
    return 0 if report['status'] == 'SOURCE_CONTROLS_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
