"""Bootstrap Journal source custody controls, without product/native execution."""
from __future__ import annotations

import builtins
from copy import deepcopy
from hashlib import sha256
from tests.hia_historical_diagnostic_controls import diagnostic_predecessor, historical_bootstrap_dependencies
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_journal_installed_preparation as preparation
from tools import qualify_hia_service_bootstrap_callers as callers
from tools import read_hia_service_bootstrap as reader


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = 'tests/fixtures/hia_service_bootstrap_original_r12/caller-scopes.json'
AUTHORITY_SHA256 = 'b8056f8c056409952ff219d4e1b789d40d754de4718023c9fcb467c02c893af4'
DIAGNOSTIC = 'tests/test_hia_agent_native_tools.py'
DIAGNOSTIC_HELPER = 'tests/hia_caller_diagnostics_admission.py'
DIAGNOSTIC_FIXTURE = 'tests/fixtures/caller_deadline_diagnostics_v1.json'
JOURNAL = 'tests/test_hia_agent_journal_native.py'
HELPER = 'tests/hia_journal_installed_preparation.py'
FIXTURE = 'tests/fixtures/journal_installed_preparation_v2.json'
ARCHIVE = 'tests/fixtures/journal_installed_preparation_v1.py.txt'
SLOT = 'reviewed_journal_installed_preparation_source_adjustments'
JOURNAL_INPUTS = (AUTHORITY, JOURNAL, HELPER, FIXTURE, ARCHIVE)
COUNTS = {'ordinary': 112, 'journal': 21, 'context': 15}


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


class ServiceBootstrapJournalPreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = (ROOT / AUTHORITY).read_bytes()
        if sha256(raw).hexdigest() != AUTHORITY_SHA256:
            raise AssertionError('the complete original Bootstrap authority changed')
        cls.scopes = json.loads(raw)['scopes']
        paths = {AUTHORITY, HELPER, FIXTURE, ARCHIVE,
                 DIAGNOSTIC_HELPER, DIAGNOSTIC_FIXTURE}
        for scope in cls.scopes.values():
            paths.update(scope['files'])
        from tests.hia_installed_distribution_history import predecessor
        cls.inputs = {name: (ROOT / name).read_bytes() for name in sorted(paths)}
        cls.inputs[JOURNAL] = predecessor(JOURNAL, cls.inputs[JOURNAL])
        fixed = {
            HELPER: {'bytes': 15935, 'sha256': '8938ae45ca0342ab5b67dd2eabb615d4b39d7e55b554513b5aa39a7463e59797'},
            FIXTURE: {'bytes': 14729, 'sha256': '81914ecb2bef21e9c641282dc8530158146ecadd4b86e8e4e6b3f83e71b73e7b'},
            ARCHIVE: {'bytes': 48482, 'sha256': 'a0a6e63291eb76ee84787b432c56eaa32bd1181b762f9593532c059d4a665077'},
            JOURNAL: {'bytes': 48798, 'sha256': '7d5cebde72523ade809346a30916a48611e18a157230b4f2f6129c0d16b8715c'},
        }
        if any(pin(cls.inputs[name]) != expected for name, expected in fixed.items()):
            raise AssertionError('the complete fixed Journal source relation changed')
        cls.journal_original = cls.inputs[ARCHIVE]
        if reader._restore_caller_journal_source(cls.inputs[JOURNAL], cls.inputs[FIXTURE]) != cls.journal_original:
            raise AssertionError('independent Journal inverse differs from the entire archive')
        historical_bootstrap_dependencies(ROOT, cls.inputs, cls.scopes)
        cls.actual_diagnostic = cls.inputs[DIAGNOSTIC]
        cls.inputs[DIAGNOSTIC] = diagnostic_predecessor(ROOT, cls.actual_diagnostic)
        cls.diagnostic_original = reader._restore_caller_diagnostic_source(
            cls.inputs[DIAGNOSTIC], cls.inputs[DIAGNOSTIC_FIXTURE])

    def stage(self, root, *, journal_current=True, diagnostic_current=True):
        for name, raw in self.inputs.items():
            if name == JOURNAL and not journal_current:
                raw = self.journal_original
            elif name == DIAGNOSTIC and not diagnostic_current:
                raw = self.diagnostic_original
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def inner(self, root, scope='journal'):
        declaration, proof = callers.admit_original_scope(root, scope)
        self.assertEqual(declaration, self.scopes[scope])
        before = {name: pin((root / name).read_bytes())['sha256'] for name in self.inputs}
        return {'caller_source_admission': proof, 'source_before': before,
                'source_after': dict(before)}

    def read(self, root, inner, *, scope='journal'):
        captured = []
        actual_import = builtins.__import__

        def independent(name, globals=None, locals=None, fromlist=(), level=0):
            forbidden = ('hia_journal_installed_preparation', 'hia_caller_diagnostics_admission',
                         'qualify_hia_service_bootstrap_callers')
            if (any(name == module or name.endswith('.' + module) for module in forbidden)
                    or name in ('tools', 'tests') and any(module in fromlist for module in forbidden)):
                raise AssertionError('the independent readback imported admission code')
            return actual_import(name, globals, locals, fromlist, level)

        with patch.object(reader, 'ROOT', root), patch.object(builtins, '__import__', independent):
            proof = reader._read_caller_source_admission(scope, self.scopes[scope], inner, captured)
        return proof, captured

    def test_all_old_current_source_combinations_preserve_every_original_scope(self):
        variants = 0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for journal_current in (False, True):
                for diagnostic_current in (False, True):
                    self.stage(root, journal_current=journal_current, diagnostic_current=diagnostic_current)
                    for scope, count in COUNTS.items():
                        with self.subTest(journal=journal_current, diagnostic=diagnostic_current, scope=scope):
                            inner = self.inner(root, scope)
                            observed, captured = self.read(root, inner, scope=scope)
                            self.assertEqual(observed, inner['caller_source_admission'])
                            self.assertEqual(observed['original_ordered_ids'], self.scopes[scope]['ordered_ids'])
                            self.assertEqual(observed['original_files'], self.scopes[scope]['files'])
                            self.assertEqual(observed['original_modules'], self.scopes[scope]['modules'])
                            self.assertEqual(len(observed['original_ordered_ids']), count)
                            self.assertEqual(observed['original_outer_seconds'], 1800)
                            self.assertEqual(SLOT in observed, journal_current and scope == 'journal')
                            expected = {AUTHORITY, *self.scopes[scope]['files']}
                            if scope == 'ordinary' and diagnostic_current:
                                expected.update((DIAGNOSTIC_HELPER, DIAGNOSTIC_FIXTURE))
                            if scope == 'journal' and journal_current:
                                expected.update((HELPER, FIXTURE, ARCHIVE))
                                detail = observed[SLOT][JOURNAL]
                                self.assertEqual(set(detail['captured_files']), {JOURNAL, HELPER, FIXTURE, ARCHIVE})
                                self.assertEqual(detail['original_method_ids'], self.scopes['journal']['ordered_ids'])
                                self.assertEqual(detail['original_method_count'], 21)
                                for field, limit in (('build', 120), ('install', 120), ('probe', 30)):
                                    self.assertEqual(detail['original_' + field + '_timeout_seconds'], limit)
                                self.assertEqual(detail['original_scope_budget_seconds'], 1800)
                                self.assertEqual(detail['production_source_exceptions'], [])
                                self.assertIs(detail['complete_original_inverse_verified'], True)
                                self.assertIs(detail['complete_current_forward_replay_verified'], True)
                            self.assertEqual(set(observed['captured_files']), expected)
                            self.assertEqual({str(path.relative_to(root)) for path, _ in captured}, expected)
                            callers.bind_scope_admission_to_source_capture(observed, inner['source_before'])
                            reader.unchanged(captured)
                            variants += 1
            # Literal old Journal uses exactly its historical proof shape and
            # admits without reading any new helper, fixture or archive.
            self.stage(root, journal_current=False)
            for name in (HELPER, FIXTURE, ARCHIVE):
                (root / name).unlink()
            declaration, proof = callers.admit_original_scope(root, 'journal')
            self.assertNotIn(SLOT, proof)
            before = {name: pin((root / name).read_bytes())['sha256'] for name in proof['captured_files']}
            observed, captured = self.read(root, {'source_before': before, 'source_after': dict(before)})
            self.assertEqual(observed, proof)
            reader.unchanged(captured)
        self.assertEqual(variants, 12)
        self.assertEqual(sum(COUNTS.values()), 148)

    def test_missing_drift_refreshed_authority_and_cached_inputs_are_rejected(self):
        rejected = 0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.stage(root)
            original = self.inner(root)
            for name in JOURNAL_INPUTS:
                path = root / name
                raw = path.read_bytes()
                for mutation in ('missing', 'changed'):
                    if mutation == 'missing':
                        path.unlink()
                    else:
                        path.write_bytes(raw + b'\n')
                    try:
                        with self.subTest(path=name, mutation=mutation, admission='producer'):
                            with self.assertRaises((ValueError, OSError)):
                                callers.admit_original_scope(root, 'journal')
                            rejected += 1
                        with self.subTest(path=name, mutation=mutation, admission='reader'):
                            with self.assertRaises((ValueError, OSError)):
                                self.read(root, original)
                            rejected += 1
                    finally:
                        path.write_bytes(raw)
                # Re-admission reads actual bytes again after an earlier PASS.
                self.inner(root)
                self.read(root, original)
                path.write_bytes(raw + b'\n')
                try:
                    with self.assertRaises(ValueError):
                        callers.admit_original_scope(root, 'journal')
                    rejected += 1
                    with self.assertRaises(ValueError):
                        self.read(root, original)
                    rejected += 1
                finally:
                    path.write_bytes(raw)
            for mutation in ('repin-current', 'remove-method', 'reorder-methods', 'raise-budget'):
                forged = json.loads(self.inputs[AUTHORITY])
                scope = forged['scopes']['journal']
                if mutation == 'repin-current':
                    scope['files'][JOURNAL] = pin(self.inputs[JOURNAL])
                elif mutation == 'remove-method':
                    scope['ordered_ids'].pop(); scope['count'] -= 1
                elif mutation == 'reorder-methods':
                    scope['ordered_ids'].reverse()
                else:
                    scope['outer_seconds'] = 1801
                (root / AUTHORITY).write_text(json.dumps(forged))
                try:
                    with self.subTest(authority=mutation):
                        with self.assertRaises(ValueError):
                            callers.admit_original_scope(root, 'journal')
                        with self.assertRaises(ValueError):
                            self.read(root, original)
                        rejected += 2
                finally:
                    (root / AUTHORITY).write_bytes(self.inputs[AUTHORITY])
        self.assertEqual(rejected, 38)

    def test_every_journal_proof_claim_and_source_capture_gap_is_rejected(self):
        rejected = 0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.stage(root)
            original = self.inner(root)
            changes = (
                ('schema', 'forged'), ('preparation_id', 'v1'), ('path', DIAGNOSTIC),
                ('original', pin(self.inputs[JOURNAL])), ('current', pin(self.journal_original)),
                ('authority', {}), ('archive', {}), ('exact_splice_count', True),
                ('complete_original_inverse_verified', False),
                ('complete_current_forward_replay_verified', False),
                ('original_method_count', 20), ('original_method_ids', []),
                ('original_build_timeout_seconds', 121), ('original_install_timeout_seconds', 121),
                ('original_probe_timeout_seconds', 31), ('original_scope_budget_seconds', 1801),
                ('captured_files', {}), ('terminal_reread_identical', 1),
                ('production_source_exceptions', [JOURNAL]), ('unknown_claim', None),
            )
            for name, bad in changes:
                forged = deepcopy(original)
                forged['caller_source_admission'][SLOT][JOURNAL][name] = bad
                with self.subTest(proof=name), self.assertRaises(ValueError):
                    self.read(root, forged)
                rejected += 1
            for mutation in ('no-proof', 'no-slot', 'empty-slot', 'wrong-source-slot'):
                forged = deepcopy(original)
                if mutation == 'no-proof':
                    del forged['caller_source_admission']
                elif mutation == 'no-slot':
                    del forged['caller_source_admission'][SLOT]
                elif mutation == 'empty-slot':
                    forged['caller_source_admission'][SLOT] = {}
                else:
                    detail = forged['caller_source_admission'][SLOT].pop(JOURNAL)
                    forged['caller_source_admission'][SLOT][DIAGNOSTIC] = detail
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    self.read(root, forged)
                rejected += 1
            for name in JOURNAL_INPUTS:
                for mutation in ('missing-both', 'changed-both', 'changed-after'):
                    forged = deepcopy(original)
                    if mutation == 'missing-both':
                        del forged['source_before'][name]; del forged['source_after'][name]
                    elif mutation == 'changed-both':
                        forged['source_before'][name] = forged['source_after'][name] = '0' * 64
                    else:
                        forged['source_after'][name] = '0' * 64
                    with self.subTest(path=name, mutation=mutation), self.assertRaises(ValueError):
                        self.read(root, forged)
                    rejected += 1
                for mutation in ('missing', 'changed'):
                    digests = dict(original['source_before'])
                    if mutation == 'missing':
                        del digests[name]
                    else:
                        digests[name] = '0' * 64
                    with self.assertRaises(ValueError):
                        callers.bind_scope_admission_to_source_capture(original['caller_source_admission'], digests)
                    rejected += 1
            (root / JOURNAL).write_bytes(self.journal_original)
            with self.assertRaises(ValueError):
                self.read(root, original)
            rejected += 1
        self.assertEqual(rejected, 50)

    def test_complete_raw_inverse_and_both_terminal_custody_boundaries_reject(self):
        rejected = 0
        raw, authority = self.inputs[JOURNAL], self.inputs[FIXTURE]
        modified = json.loads(authority)
        modified['splices'][0]['new_offset'] = True
        for source, provenance in (
            (raw + b'\n', authority), (raw[:-1], authority), (self.journal_original, authority),
            (bytearray(raw), authority), (raw, bytearray(authority)),
            (raw, authority + b'\n'), (raw, json.dumps(modified).encode()),
        ):
            with self.assertRaises(ValueError):
                reader._restore_caller_journal_source(source, provenance)
            rejected += 1
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.stage(root)
            original = self.inner(root)
            for name in JOURNAL_INPUTS:
                path = root / name
                before = path.read_bytes()
                _, captured = self.read(root, original)
                path.write_bytes(before + b'\n')
                try:
                    with self.assertRaises(ValueError):
                        reader.unchanged(captured)
                    rejected += 1
                finally:
                    path.write_bytes(before)
                actual_read = Path.read_bytes
                reads = [0]

                def changed_at_reread(target):
                    value = actual_read(target)
                    if target == path:
                        reads[0] += 1
                        if reads[0] > 1:
                            return value + b'\n'
                    return value

                with patch.object(Path, 'read_bytes', changed_at_reread):
                    with self.assertRaises(ValueError):
                        callers.admit_original_scope(root, 'journal')
                self.assertGreaterEqual(reads[0], 2)
                rejected += 1
            actual_admit = preparation.admit_source
            for name in (JOURNAL, HELPER, FIXTURE, ARCHIVE):
                path = root / name
                before = path.read_bytes()

                def change_after_admission(*args):
                    detail = actual_admit(*args)
                    path.write_bytes(self.journal_original if name == JOURNAL else before + b'\n')
                    return detail

                try:
                    with patch.object(preparation, 'admit_source', change_after_admission):
                        with self.assertRaises(ValueError):
                            callers.admit_original_scope(root, 'journal')
                    rejected += 1
                finally:
                    path.write_bytes(before)
        self.assertEqual(rejected, 21)


if __name__ == '__main__':
    unittest.main()
