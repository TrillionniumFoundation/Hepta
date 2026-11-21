"""Exact old/current Journal preparation through complete caller source gates.

Only source admission is exercised. Original scopes are read as bytes; no
qualifier main, original caller method, product, HIA VM or native image is run.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
from tests.hia_historical_diagnostic_controls import diagnostic_predecessor, historical_caller_dependencies
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_journal_installed_preparation as journal
from tools import qualify_hia_service_discovery_callers as discovery
from tools import qualify_hia_service_verification_callers as verification
from tools import qualify_hia_store_transaction as transaction

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ((discovery, {'ordinary': 112, 'journal': 21, 'context': 15}),
            (verification, {'ordinary': 112, 'journal': 21}))
DIAGNOSTIC = 'tests/test_hia_agent_native_tools.py'
DIAGNOSTIC_AUTHORITY = 'tests/fixtures/caller_deadline_diagnostics_v1.json'
DIAGNOSTIC_HELPER = 'tests/hia_caller_diagnostics_admission.py'
SELF = 'tests/test_hia_journal_caller_preparation.py'
PRODUCERS = ('tools/qualify_hia_service_discovery_callers.py',
             'tools/qualify_hia_service_verification_callers.py',
             'tools/qualify_hia_store_transaction.py')


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def inverse(raw, value):
    original = raw
    for item in reversed(value['splices']):
        at = item['new_offset']
        before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
        if original[at:at + len(after)] != after:
            raise AssertionError('fixed current source splice differs')
        original = original[:at] + before + original[at + len(after):]
    if pin(original) != value['original']:
        raise AssertionError('fixed complete old source differs')
    replay = original
    for item in reversed(value['splices']):
        at = item['old_offset']
        before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
        if replay[at:at + len(before)] != before:
            raise AssertionError('fixed old source replay differs')
        replay = replay[:at] + after + replay[at + len(before):]
    if replay != raw:
        raise AssertionError('fixed complete current source replay differs')
    return original


class JournalCallerPreparationSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        names = set(journal.SOURCE_PATHS) | set(PRODUCERS) | {
            SELF, DIAGNOSTIC, DIAGNOSTIC_HELPER, DIAGNOSTIC_AUTHORITY,
            discovery.FIXTURE, verification.FIXTURE, transaction.FIXTURE}
        cls.scopes = {}
        for subject, counts in SERVICES:
            frozen = (ROOT / subject.FIXTURE).read_bytes()
            if sha256(frozen).hexdigest() != subject.FIXTURE_SHA256:
                raise AssertionError('original full caller scope bytes changed')
            cls.scopes[subject.FIXTURE] = json.loads(frozen)['scopes']
            for scope, expected in counts.items():
                selected = cls.scopes[subject.FIXTURE][scope]
                if len(selected['ordered_ids']) != expected:
                    raise AssertionError('complete original caller count differs')
                names.update(selected['files'])
        frozen = (ROOT / transaction.FIXTURE).read_bytes()
        if sha256(frozen).hexdigest() != transaction.FIXTURE_SHA256:
            raise AssertionError('original transaction separate61 inventory changed')
        cls.transaction = json.loads(frozen)
        names.update(row['path'] for row in cls.transaction['modules'])
        cls.sources = {name: (ROOT / name).read_bytes() for name in sorted(names)}
        cls.live_sources = dict(cls.sources)
        historical_caller_dependencies(ROOT, cls.sources, {
            name: pin['sha256'] for name, pin in cls.scopes[discovery.FIXTURE]['ordinary']['files'].items()})
        cls.actual_diagnostic = cls.sources[DIAGNOSTIC]
        cls.sources[DIAGNOSTIC] = diagnostic_predecessor(ROOT, cls.actual_diagnostic)
        cls.old_diagnostic = inverse(cls.sources[DIAGNOSTIC], json.loads(cls.sources[DIAGNOSTIC_AUTHORITY]))
        restored = inverse(cls.sources[journal.PATH], json.loads(cls.sources[journal.FIXTURE]))
        if restored != cls.sources[journal.ARCHIVE]:
            raise AssertionError('Journal fixed complete archive differs')

    @classmethod
    def tearDownClass(cls):
        pinned = cls.live_sources
        if pinned != {name: (ROOT / name).read_bytes() for name in pinned}:
            raise AssertionError('Journal caller Source inputs changed')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hia-journal-caller-source-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, raw in self.sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    @contextmanager
    def change(self, name, raw):
        path, original = self.root / name, (self.root / name).read_bytes()
        if raw is None: path.unlink()
        else: path.write_bytes(raw)
        try: yield
        finally: path.write_bytes(original)

    def test_01_every_original_scope_current_and_literal_sources_keep_the_complete_plan(self):
        count = 0
        for subject, counts in SERVICES:
            for scope_name, expected_count in counts.items():
                variants = (False, True) if scope_name in ('ordinary', 'journal') else (True,)
                for current in variants:
                    path = DIAGNOSTIC if scope_name == 'ordinary' else journal.PATH
                    raw = (self.sources[path] if current else
                           self.old_diagnostic if scope_name == 'ordinary' else self.sources[journal.ARCHIVE])
                    with self.subTest(subject=subject.__name__, scope=scope_name, current=current), self.change(path, raw):
                        scope, proof = subject.admit_original_scope(self.root, scope_name)
                        self.assertEqual(scope, self.scopes[subject.FIXTURE][scope_name])
                        self.assertEqual(len(proof['original_ordered_ids']), expected_count)
                        self.assertEqual(proof['original_outer_seconds'], scope['outer_seconds'])
                        self.assertEqual(proof['original_files'], scope['files'])
                        self.assertEqual(proof['production_source_exceptions'], [])
                        self.assertTrue(proof['terminal_reread_identical'])
                        self.assertFalse(proof['whole_native'])
                        journal_map = proof['reviewed_journal_installed_preparation_source_adjustments']
                        diagnostic_map = proof['reviewed_diagnostic_source_adjustments']
                        self.assertEqual(set(journal_map), {journal.PATH} if scope_name == 'journal' and current else set())
                        self.assertEqual(set(diagnostic_map), {DIAGNOSTIC} if scope_name == 'ordinary' and current else set())
                        digests = {name: expected['sha256'] for name, expected in proof['captured_files'].items()}
                        subject.bind_scope_admission_to_source_capture(proof, digests)
                        for name in proof['captured_files']:
                            changed = dict(digests)
                            changed.pop(name)
                            with self.subTest(missing_before_or_after=name), self.assertRaises(ValueError):
                                subject.bind_scope_admission_to_source_capture(proof, changed)
                        count += 1
        self.assertEqual(count, 9)

    def test_02_service_current_sources_reject_missing_drift_and_admission_capture_gaps(self):
        for subject, counts in SERVICES:
            for scope_name in ('ordinary', 'journal'):
                _, proof = subject.admit_original_scope(self.root, scope_name)
                for name in proof['captured_files']:
                    for action in ('missing', 'tamper', 'no-cache', 'terminal-drift'):
                        with self.subTest(subject=subject.__name__, scope=scope_name, path=name, action=action):
                            if action == 'no-cache': subject.admit_original_scope(self.root, scope_name)
                            if action == 'terminal-drift':
                                real_read, reads = Path.read_bytes, []
                                target = self.root / name
                                def changed(path):
                                    raw = real_read(path)
                                    if path == target:
                                        reads.append(True)
                                        if len(reads) > 1: return raw + b'\n'
                                    return raw
                                with patch.object(Path, 'read_bytes', changed), self.assertRaises(ValueError):
                                    subject.admit_original_scope(self.root, scope_name)
                                self.assertGreaterEqual(len(reads), 2)
                            else:
                                raw = None if action == 'missing' else self.sources[name] + b'\n'
                                with self.change(name, raw), self.assertRaises((ValueError, FileNotFoundError)):
                                    subject.admit_original_scope(self.root, scope_name)
            for invalid in (None, True, 'unlisted'):
                with self.subTest(scope=invalid), self.assertRaises(ValueError):
                    subject.admit_original_scope(self.root, invalid)
            # The helper can return only after capturing current source. A
            # change before its caller merges that capture must still refuse.
            real_admit, real_read, completed = journal.admit_source, Path.read_bytes, []
            def admitted(*args, **kwargs):
                result = real_admit(*args, **kwargs)
                completed.append(True)
                return result
            def source_after(path):
                raw = real_read(path)
                return raw + b'\n' if completed and path == self.root / journal.ARCHIVE else raw
            with patch.object(journal, 'admit_source', admitted), patch.object(Path, 'read_bytes', source_after), \
                    self.assertRaises(ValueError):
                subject.admit_original_scope(self.root, 'journal')
            self.assertTrue(completed)

    def test_03_transaction_separate_61_keeps_whole_inventory_and_rejects_every_capture_drift(self):
        with patch.object(transaction, 'ROOT', self.root):
            for current in (False, True):
                raw = self.sources[journal.PATH] if current else self.sources[journal.ARCHIVE]
                with self.subTest(current=current), self.change(journal.PATH, raw):
                    value, proof = transaction.admit_separate_inventory(with_source_admission=True)
                    self.assertEqual(value, self.transaction)
                    self.assertEqual(transaction.admit_separate_inventory(), self.transaction)
                    self.assertEqual(proof['original_module_counts'], [21, 25, 15])
                    self.assertEqual(proof['original_count'], 61)
                    self.assertEqual(proof['original_ordered_ids'], self.transaction['ordered_ids'])
                    self.assertEqual(proof['original_outer_seconds'], 1800)
                    self.assertEqual(set(proof['reviewed_journal_installed_preparation_source_adjustments']),
                                     {journal.PATH} if current else set())
            _, proof = transaction.admit_separate_inventory(with_source_admission=True)
            before = {name: expected['sha256'] for name, expected in proof['captured_files'].items()}
            transaction._bind_source_admission(proof, before)
            for name in proof['captured_files']:
                changed = dict(before)
                changed[name] = '0' * 64
                with self.subTest(binding=name), self.assertRaises(ValueError):
                    transaction._bind_source_admission(proof, changed)
                for action in ('missing', 'tamper', 'no-cache', 'terminal-drift'):
                    with self.subTest(path=name, action=action):
                        if action == 'no-cache': transaction.admit_separate_inventory()
                        if action == 'terminal-drift':
                            real_read, reads = Path.read_bytes, []
                            target = self.root / name
                            def changed_read(path):
                                raw = real_read(path)
                                if path == target:
                                    reads.append(True)
                                    if len(reads) > 1: return raw + b'\n'
                                return raw
                            with patch.object(Path, 'read_bytes', changed_read), self.assertRaises(ValueError):
                                transaction.admit_separate_inventory()
                            self.assertGreaterEqual(len(reads), 2)
                        else:
                            raw = None if action == 'missing' else self.sources[name] + b'\n'
                            with self.change(name, raw), self.assertRaises((ValueError, FileNotFoundError)):
                                transaction.admit_separate_inventory()
            with self.change(journal.PATH, self.sources[journal.ARCHIVE]), \
                    self.change(journal.FIXTURE, None), self.change(journal.HELPER, None), \
                    self.change(journal.ARCHIVE, None):
                self.assertEqual(transaction.admit_separate_inventory(), self.transaction)


if __name__ == '__main__':
    unittest.main()
