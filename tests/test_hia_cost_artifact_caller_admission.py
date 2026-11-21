"""Exact original Cost81 and Artifact132 source domains and capture custody."""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
from tests.hia_historical_diagnostic_controls import diagnostic_predecessor, historical_caller_dependencies
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_cost_ledger_callers as cost
from tools import qualify_hia_artifact_delivery_callers as artifact

ROOT = Path(__file__).resolve().parents[1]
SUBJECTS = (('cost81', cost, 81, 10), ('artifact132', artifact, 132, 11))


def inverse(raw, authority):
    value = raw
    for entry in reversed(authority['splices']):
        at = entry['new_offset']
        before, after = bytes.fromhex(entry['old_hex']), bytes.fromhex(entry['new_hex'])
        if value[at:at + len(after)] != after:
            raise AssertionError('current diagnostic source differs at exact splice')
        value = value[:at] + before + value[at + len(after):]
    if {'bytes': len(value), 'sha256': sha256(value).hexdigest()} != authority['original']:
        raise AssertionError('whole original diagnostic source was not restored')
    rebuilt = value
    for entry in reversed(authority['splices']):
        at = entry['old_offset']
        before, after = bytes.fromhex(entry['old_hex']), bytes.fromhex(entry['new_hex'])
        if rebuilt[at:at + len(before)] != before:
            raise AssertionError('original diagnostic splice differs')
        rebuilt = rebuilt[:at] + after + rebuilt[at + len(before):]
    if rebuilt != raw:
        raise AssertionError('whole current diagnostic forward replay differs')
    return value


def admit(subject, root):
    if subject is cost:
        return subject.admit_original_callers(root)
    return subject.admit_inventory(root, with_source_admission=True)


class CostArtifactCallerAdmissionSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frozen = {}
        cls.original_files = {}
        names = {cost._DIAGNOSTICS_HELPER, cost._DIAGNOSTICS_AUTHORITY,
                 'tools/qualify_hia_cost_ledger_callers.py',
                 'tools/qualify_hia_artifact_delivery_callers.py',
                 'tests/test_hia_cost_artifact_caller_admission.py'}
        for label, subject, count, captures in SUBJECTS:
            fixture = subject.FIXTURE_NAME if subject is cost else subject.FIXTURE
            raw = (ROOT / fixture).read_bytes()
            if sha256(raw).hexdigest() != subject.FIXTURE_SHA256:
                raise AssertionError('original complete caller inventory differs: ' + label)
            value = json.loads(raw)
            if len(value['ordered_ids']) != count:
                raise AssertionError('original complete caller count differs')
            cls.frozen[label] = value
            if subject is cost:
                paths = {name.replace('.', '/') + '.py' for name in value['modules']}
                cls.original_files[label] = {name: value['original_source_sha256'][name] for name in paths}
            else:
                cls.original_files[label] = {row['path']: row['sha256'] for row in value['modules']}
                names.add(value['direct_original_fixture'])
            names.update(cls.original_files[label])
            names.add(fixture)
        cls.sources = {name: (ROOT / name).read_bytes() for name in sorted(names)}
        cls.live_sources = dict(cls.sources)
        for pins in cls.original_files.values():
            historical_caller_dependencies(ROOT, cls.sources, pins)
        cls.actual_diagnostic = cls.sources[cost._DIAGNOSTICS_CALLER]
        cls.sources[cost._DIAGNOSTICS_CALLER] = diagnostic_predecessor(ROOT, cls.actual_diagnostic)
        cls.original = inverse(cls.sources[cost._DIAGNOSTICS_CALLER],
                               json.loads(cls.sources[cost._DIAGNOSTICS_AUTHORITY]))

    @classmethod
    def tearDownClass(cls):
        pinned = cls.live_sources
        if pinned != {name: (ROOT / name).read_bytes() for name in pinned}:
            raise AssertionError('caller Source input bytes changed')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-cost-artifact-callers-source-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, raw in self.sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    @contextmanager
    def change(self, name, raw):
        path = self.root / name
        before = path.read_bytes()
        if raw is None:
            path.unlink()
        else:
            path.write_bytes(raw)
        try:
            yield
        finally:
            path.write_bytes(before)

    def test_01_whole_original_and_current_domains_preserve_all_ids_and_selectors(self):
        for label, subject, count, captures in SUBJECTS:
            for current in (False, True):
                raw = self.sources[subject._DIAGNOSTICS_CALLER] if current else self.original
                with self.subTest(scope=label, current=current), self.change(subject._DIAGNOSTICS_CALLER, raw):
                    actual, proof = admit(subject, self.root)
                    self.assertEqual(actual, self.frozen[label])
                    self.assertEqual(proof['original_ordered_ids'], actual['ordered_ids'])
                    self.assertEqual(len(proof['original_ordered_ids']), count)
                    self.assertEqual(proof['original_files'], self.original_files[label])
                    self.assertEqual(len(proof['original_modules']), 7)
                    self.assertEqual(proof['production_source_exceptions'], [])
                    self.assertTrue(proof['terminal_reread_identical'])
                    self.assertTrue(proof['original_inventory_bytes_unchanged'])
                    self.assertFalse(proof['whole_native'])
                    adjustments = proof['reviewed_diagnostic_source_adjustments']
                    self.assertEqual(set(adjustments), {subject._DIAGNOSTICS_CALLER} if current else set())
                    if current:
                        relation = adjustments[subject._DIAGNOSTICS_CALLER]
                        self.assertEqual(relation['original_deadline_seconds'], 5)
                        self.assertEqual(relation['original_native_budget_ms'], 1)
                        self.assertEqual(relation['exact_splices'], 2)
                    if subject is artifact:
                        self.assertEqual(proof['original_direct_ordered_ids'], actual['direct_ordered_ids'])
                        self.assertEqual(proof['original_additional_ordered_ids'], actual['additional_ordered_ids'])
                        self.assertEqual([g['selector'] for g in actual['additional_groups']],
                                         [subject.PUBLIC_SELECTOR, subject.STORE_SELECTOR])
                        with patch.object(subject, 'ROOT', self.root):
                            self.assertEqual(subject.admit_inventory(), actual)
            with self.change(subject._DIAGNOSTICS_CALLER, self.original), \
                    self.change(subject._DIAGNOSTICS_HELPER, None), \
                    self.change(subject._DIAGNOSTICS_AUTHORITY, None):
                actual, proof = admit(subject, self.root)
                self.assertEqual(actual, self.frozen[label])
                self.assertEqual(proof['reviewed_diagnostic_source_adjustments'], {})

    def test_02_every_capture_refuses_missing_tamper_cached_and_terminal_drift(self):
        for label, subject, count, captures in SUBJECTS:
            _, proof = admit(subject, self.root)
            self.assertEqual(len(proof['captured_files']), captures)
            for name in proof['captured_files']:
                for mode in ('missing', 'tamper', 'no-cache', 'terminal-drift'):
                    with self.subTest(scope=label, path=name, mode=mode):
                        if mode == 'no-cache':
                            admit(subject, self.root)
                        if mode == 'terminal-drift':
                            target = self.root / name
                            real_read, calls = Path.read_bytes, []
                            def changed(path):
                                raw = real_read(path)
                                if path == target:
                                    calls.append(True)
                                    if len(calls) > 1:
                                        return raw + b'\n'
                                return raw
                            with patch.object(Path, 'read_bytes', changed), self.assertRaises(ValueError):
                                admit(subject, self.root)
                            self.assertGreaterEqual(len(calls), 2)
                        else:
                            raw = None if mode == 'missing' else self.sources[name] + b'\n'
                            with self.change(name, raw), self.assertRaises((ValueError, FileNotFoundError)):
                                admit(subject, self.root)

    def test_03_actual_capture_maps_and_valid_source_swaps_cannot_bypass_binding(self):
        from tests import hia_caller_diagnostics_admission as diagnostic
        for label, subject, count, captures in SUBJECTS:
            _, proof = admit(subject, self.root)
            captured = {name: sha256((self.root / name).read_bytes()).hexdigest()
                        for name in proof['captured_files']}
            subject.bind_admission_to_source_capture(proof, captured)
            for name in captured:
                missing, drift = dict(captured), dict(captured)
                missing.pop(name)
                drift[name] = '0' * 64
                for altered in (missing, drift):
                    with self.subTest(scope=label, path=name), self.assertRaises(ValueError):
                        subject.bind_admission_to_source_capture(proof, altered)
            with self.change(subject._DIAGNOSTICS_CALLER, self.original):
                actual = {name: sha256((self.root / name).read_bytes()).hexdigest()
                          for name in proof['captured_files']}
                with self.assertRaises(ValueError):
                    subject.bind_admission_to_source_capture(proof, actual)
            real_admit = diagnostic.admit
            target = self.root / subject._DIAGNOSTICS_CALLER
            def swapped(*args):
                relation = real_admit(*args)
                target.write_bytes(self.original)
                return relation
            with self.change(subject._DIAGNOSTICS_CALLER, self.sources[subject._DIAGNOSTICS_CALLER]), \
                    patch.object(diagnostic, 'admit', side_effect=swapped), self.assertRaises(ValueError):
                admit(subject, self.root)


if __name__ == '__main__':
    unittest.main()
