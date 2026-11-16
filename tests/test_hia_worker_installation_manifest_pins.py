"""Explicit installation identity expectations in hosted and selected workers.

These added controls do not replace any original worker-report or UNKNOWN
method, input, installed command, or timeout. Native cases use the unchanged
worker-report build fixture and a real admitted v2 scope.
"""
from __future__ import annotations

from contextlib import ExitStack
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import hia_agent_worker as worker
from tests import test_hia_worker_report_native as original

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = 'HEPTA_HIA_WORKER_MANIFEST_PINS_EVIDENCE'
PIN_MESSAGE = 'administrator source pin differs before execution'
MODE_MESSAGE = 'manifest read and request execution are distinct modes'


def cases():
    result = []
    names = ('worker', 'backend', 'catalog')
    for mask in range(8):
        flags = []
        for index, name in enumerate(names):
            if mask & (1 << index):
                flags += ['--expected-' + name + '-sha256',
                          original.IDENTITIES[name + '_sha256']]
        result.append(('manifest/matching-subset/' + str(mask),
                       ['--installation-manifest', *flags], 'success'))
    for name in names:
        for label, wrong in (('mismatch', '0' * 64), ('empty', '')):
            flags = []
            for field in names:
                flags += ['--expected-' + field + '-sha256',
                          wrong if field == name else original.IDENTITIES[field + '_sha256']]
            result.append(('manifest/' + label + '/' + name,
                           ['--installation-manifest', *flags], 'pin'))
    result.append(('manifest/mode-error-before-pin',
                   ['--installation-manifest', '--request-json-stdin',
                    '--expected-worker-sha256', 'wrong'], 'mode'))
    return tuple(result)


def require_observation(test, result, kind, identities, *, public):
    terminal, stdout, stderr, events = result
    test.assertEqual([row[0] for row in events].count('manifest'), 1)
    test.assertFalse(any(row[0] in ('read', 'construct', 'call', 'close') for row in events))
    if kind == 'success':
        test.assertEqual(terminal, ('return', 0))
        test.assertEqual(stdout, original.wire(identities) + b'\n')
        test.assertEqual(stderr, '')
        test.assertEqual([row[0] for row in events], ['manifest', 'stdout'])
    elif kind == 'pin':
        test.assertEqual(terminal, ('return', 2) if public
                         else ('raise', 'AgentRejected', PIN_MESSAGE))
        test.assertEqual(stdout, b'')
        test.assertEqual(stderr, PIN_MESSAGE + '\n' if public else '')
        test.assertEqual([row[0] for row in events], ['manifest'])
    else:
        test.assertEqual(kind, 'mode')
        test.assertEqual(terminal, ('raise', 'SystemExit', '2'))
        test.assertEqual(stdout, b'')
        test.assertIn(MODE_MESSAGE, stderr)
        test.assertNotIn(PIN_MESSAGE, stderr)
        test.assertEqual([row[0] for row in events], ['manifest'])


def main_observation(arguments, *, bundle=None, bundle_sha=None, reference=False):
    identities = dict(original.IDENTITIES)
    if bundle is not None:
        identities['native_helpers_sha256'] = bundle_sha
    events = []
    output, errors = io.BytesIO(), io.StringIO()
    class Input:
        def read(self, size):
            events.append(('read', size))
            raise AssertionError('manifest query read request stdin')
    class Output:
        def write(self, raw):
            events.append(('stdout', len(raw)))
            return output.write(raw)
    def installation():
        events.append(('manifest', 1))
        return dict(identities)
    clean = {key: value for key, value in os.environ.items()
             if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, clean, clear=True))
        stack.enter_context(patch.object(worker, 'installation_manifest', installation))
        stack.enter_context(patch.object(sys, 'stdin', SimpleNamespace(buffer=Input())))
        stack.enter_context(patch.object(sys, 'stdout', SimpleNamespace(buffer=Output())))
        stack.enter_context(patch.object(sys, 'stderr', errors))
        stack.enter_context(patch('hepta.hia_agent_service.HIAAgentService',
                                  side_effect=AssertionError('manifest query constructed service')))
        argv = list(arguments)
        if bundle is not None:
            argv += ['--native-helpers-manifest', str(bundle),
                     '--expected-native-helpers-sha256', bundle_sha]
            if reference:
                stack.enter_context(patch.object(worker, '_run', worker._reference_run))
            else:
                stack.enter_context(patch.object(worker, '_reference_run',
                    side_effect=AssertionError('selected worker used retained policy')))
                stack.enter_context(patch.object(worker, 'wire',
                    side_effect=AssertionError('selected manifest used hosted encoding')))
        try:
            terminal = ('return', worker.main(argv))
        except SystemExit as error:
            terminal = ('raise', 'SystemExit', str(error))
    from hepta import hia_native_helpers as authority
    from hepta.hia_native_delivery import _current_request_observation
    if authority._ACTIVE is not None or authority._SCOPE_OWNER is not None:
        raise AssertionError('worker query left an active administrator scope')
    if _current_request_observation() is not None:
        raise AssertionError('worker query left an active request observation')
    return (terminal, output.getvalue(), errors.getvalue(), events), identities


class WorkerInstallationManifestSourceTests(unittest.TestCase):
    def test_01_retained_query_all_subsets_wrong_and_empty_pins_and_mode_priority(self):
        rows = cases()
        self.assertEqual(len(rows), 15)
        for label, arguments, kind in rows:
            with self.subTest(case=label):
                fixture = original.Fixture()
                fixture.argv = arguments
                require_observation(self, fixture.run(), kind, fixture.identities, public=False)

    def test_02_public_hosted_query_refuses_before_stdin_or_service(self):
        for label, arguments, kind in cases():
            with self.subTest(case=label):
                result, identities = main_observation(arguments)
                require_observation(self, result, kind, identities, public=True)

    def test_03_exact_successor_rejects_old_mixed_unknown_and_authority_drift(self):
        from tools import read_hia_worker_unknown as reader
        original_path = ROOT / 'tests/fixtures/worker_unknown_original_r17b/manifest.json'
        record_path = ROOT / 'tests/fixtures/worker_installation_manifest_successor_v1.json'
        original_raw, record_raw = original_path.read_bytes(), record_path.read_bytes()
        record = json.loads(record_raw)
        original_manifest = json.loads(original_raw)
        paths = {str(record_path): record_raw}
        for name in (*original_manifest['candidate_runtime'],
                     'tools/generate_hia_worker_report.py'):
            paths[str(ROOT / name)] = (ROOT / name).read_bytes()
        self.assertEqual(reader._manifest_query_source_successor(
            original_raw, lambda path: paths[str(path)]),
            {name: {'bytes': len(paths[str(ROOT / name)]),
                    'sha256': sha256(paths[str(ROOT / name)]).hexdigest()}
             for name in (*original_manifest['candidate_runtime'],
                          'tools/generate_hia_worker_report.py')})
        older = {}
        for name, entry in record['records'].items():
            value = paths[str(ROOT / name)].decode('utf-8')
            for edit in reversed(entry['reverse_segments']):
                at, current = edit['after_start'], edit['after_text']
                self.assertEqual(value[at:at + len(current)], current)
                value = value[:at] + edit['before_text'] + value[at + len(current):]
            older[str(ROOT / name)] = value.encode('utf-8')
        negatives = [('old-both', {**paths, **older})]
        for name, old_raw in older.items():
            negatives.append(('mixed-old/' + Path(name).name, {**paths, name: old_raw}))
            negatives.append(('unknown-byte/' + Path(name).name,
                              {**paths, name: paths[name] + b'\n'}))
        negatives.append(('successor-authority-byte',
                          {**paths, str(record_path): record_raw + b'\n'}))
        self.assertEqual(len(negatives), 6)
        for label, supplied in negatives:
            with self.subTest(case=label), self.assertRaises(ValueError):
                reader._manifest_query_source_successor(
                    original_raw, lambda path: supplied[str(path)])
        with self.assertRaises(ValueError):
            reader._manifest_query_source_successor(
                original_raw + b'\n', lambda path: paths[str(path)])
        for path, raw in paths.items():
            self.assertEqual(Path(path).read_bytes(), raw)
        self.assertEqual(original_path.read_bytes(), original_raw)


class WorkerInstallationManifestNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold = os.environ.get(original.COLD)
        development = os.environ.get(original.DEVELOPMENT)
        if ((cold is None) == (development is None)
                or cold == '' or development == ''):
            raise ValueError('one explicit worker-report cold report or DEV manifest is required')
        saved = os.environ.get(original.FIXTURE_EVIDENCE)
        evidence = os.environ.get(EVIDENCE)
        if evidence == '':
            raise ValueError('manifest pin evidence path must not be empty')
        try:
            if evidence is None:
                os.environ.pop(original.FIXTURE_EVIDENCE, None)
            else:
                os.environ[original.FIXTURE_EVIDENCE] = evidence
            original.WorkerReportNativeTests.setUpClass.__func__(cls)
        finally:
            if saved is None:
                os.environ.pop(original.FIXTURE_EVIDENCE, None)
            else:
                os.environ[original.FIXTURE_EVIDENCE] = saved

    @classmethod
    def tearDownClass(cls):
        original.WorkerReportNativeTests.tearDownClass.__func__(cls)

    def test_01_complete_native_policy_query_expectations_match_retained_path(self):
        for label, arguments, kind in cases():
            with self.subTest(case=label):
                before, after = original.Fixture(), original.Fixture()
                before.argv = list(arguments)
                after.argv = list(arguments)
                expected, actual = before.run(), after.run(self.manifest)
                require_observation(self, expected, kind, before.identities, public=False)
                self.assertEqual(actual, expected)

    def test_02_real_v2_scope_query_guard_and_mode_priority_with_retained_poison(self):
        for label, arguments, kind in cases():
            with self.subTest(case=label):
                expected, identities = main_observation(arguments, bundle=self.worker_bundle,
                                                       bundle_sha=self.worker_pin, reference=True)
                actual, actual_identities = main_observation(arguments, bundle=self.worker_bundle,
                                                            bundle_sha=self.worker_pin)
                require_observation(self, expected, kind, identities, public=True)
                self.assertEqual(actual_identities, identities)
                self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
