"""Source admission controls only; these do not qualify native Bootstrap calls."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_caller_diagnostics_admission as diagnostics
from tools import qualify_hia_service_bootstrap_callers as callers


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = 'tests/fixtures/hia_service_bootstrap_original_r12/caller-scopes.json'
FIXTURE_SHA256 = 'b8056f8c056409952ff219d4e1b789d40d754de4718023c9fcb467c02c893af4'
HELPER = 'tests/hia_caller_diagnostics_admission.py'
COUNTS = {'ordinary': 112, 'journal': 21, 'context': 15}


class ServiceBootstrapCallerAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frozen = (ROOT / FIXTURE).read_bytes()
        if sha256(cls.frozen).hexdigest() != FIXTURE_SHA256:
            raise AssertionError('original Bootstrap scope authority changed')
        cls.scopes = json.loads(cls.frozen)['scopes']
        names = {FIXTURE, HELPER, diagnostics.FIXTURE}
        for scope in cls.scopes.values():
            names.update(scope['files'])
        cls.inputs = {name: (ROOT / name).read_bytes() for name in sorted(names)}
        cls.original_caller = diagnostics.restore(
            cls.inputs[diagnostics.PATH], cls.inputs[diagnostics.FIXTURE])

    def stage(self, root, *, original=False):
        for name, raw in self.inputs.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.original_caller if original and name == diagnostics.PATH else raw)

    def test_all_three_original_scopes_and_only_the_exact_reviewed_successor(self):
        variants = 0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for original in (True, False):
                self.stage(root, original=original)
                for name, count in COUNTS.items():
                    with self.subTest(original=original, scope=name):
                        scope, proof = callers.admit_original_scope(root, name)
                        self.assertEqual(scope, self.scopes[name])
                        self.assertEqual(len(scope['ordered_ids']), count)
                        self.assertEqual(scope['count'], count)
                        self.assertEqual(len(scope['ordered_ids']), len(set(scope['ordered_ids'])))
                        self.assertEqual(scope['outer_seconds'], 1800)
                        self.assertTrue(scope['runtime_TestLoader_must_match_all_ids'])
                        self.assertTrue(scope['all_methods_unfiltered'])
                        self.assertEqual(proof['original_ordered_ids'], scope['ordered_ids'])
                        self.assertEqual(proof['original_modules'], scope['modules'])
                        self.assertEqual(proof['original_files'], scope['files'])
                        self.assertEqual(proof['original_outer_seconds'], 1800)
                        self.assertEqual(proof['authority'], {
                            'path': FIXTURE, 'bytes': len(self.frozen), 'sha256': FIXTURE_SHA256})
                        expected_adjustments = {diagnostics.PATH} if not original and name == 'ordinary' else set()
                        self.assertEqual(set(proof['reviewed_diagnostic_source_adjustments']), expected_adjustments)
                        for adjustment in proof['reviewed_diagnostic_source_adjustments'].values():
                            self.assertEqual(adjustment['exact_splices'], 2)
                            self.assertEqual(adjustment['original'], diagnostics.ORIGINAL)
                            self.assertEqual(adjustment['current'], diagnostics.CURRENT)
                            self.assertTrue(adjustment['complete_original_inverse_verified'])
                            self.assertTrue(adjustment['complete_current_forward_replay_verified'])
                            self.assertEqual(adjustment['original_deadline_seconds'], 5)
                            self.assertEqual(adjustment['original_native_budget_ms'], 1)
                            self.assertFalse(adjustment['production_source_exception'])
                        expected_captures = {FIXTURE, *scope['files']}
                        if expected_adjustments:
                            expected_captures.update((HELPER, diagnostics.FIXTURE))
                        self.assertEqual(set(proof['captured_files']), expected_captures)
                        for filename, identity in proof['captured_files'].items():
                            raw = (root / filename).read_bytes()
                            self.assertEqual(identity, {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()})
                        callers.bind_scope_admission_to_source_capture(
                            proof, {filename: identity['sha256'] for filename, identity in proof['captured_files'].items()})
                        self.assertTrue(proof['terminal_reread_identical'])
                        self.assertTrue(proof['original_inventory_bytes_unchanged'])
                        self.assertEqual(proof['production_source_exceptions'], [])
                        self.assertFalse(proof['whole_native'])
                        variants += 1
        self.assertEqual(variants, 6)
        self.assertEqual(sum(COUNTS.values()), 148)

    def test_every_consumed_input_missing_changed_or_resigned_is_rejected(self):
        rejected = 0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.stage(root)
            for scope_name in COUNTS:
                _, proof = callers.admit_original_scope(root, scope_name)
                for filename in proof['captured_files']:
                    path = root / filename
                    raw = path.read_bytes()
                    for mutation in ('missing', 'changed'):
                        with self.subTest(scope=scope_name, filename=filename, mutation=mutation):
                            if mutation == 'missing':
                                path.unlink()
                            else:
                                path.write_bytes(raw + b'\n')
                            try:
                                with self.assertRaises((ValueError, OSError)):
                                    callers.admit_original_scope(root, scope_name)
                                rejected += 1
                            finally:
                                path.write_bytes(raw)
            # Updating a signed inventory to match an unreviewed caller cannot
            # authorize it: the complete historical inventory remains pinned.
            for mutation in ('repin-caller', 'remove-method', 'reorder-methods', 'raise-budget'):
                with self.subTest(mutation=mutation):
                    modified = json.loads(self.frozen)
                    scope = modified['scopes']['ordinary']
                    if mutation == 'repin-caller':
                        scope['files'][diagnostics.PATH] = dict(diagnostics.CURRENT)
                    elif mutation == 'remove-method':
                        scope['ordered_ids'].pop()
                        scope['count'] -= 1
                    elif mutation == 'reorder-methods':
                        scope['ordered_ids'].reverse()
                    else:
                        scope['outer_seconds'] = 1801
                    (root / FIXTURE).write_text(json.dumps(modified))
                    try:
                        with self.assertRaises(ValueError):
                            callers.admit_original_scope(root, 'ordinary')
                        rejected += 1
                    finally:
                        (root / FIXTURE).write_bytes(self.frozen)
            for invalid in ('', '../ordinary', 'ORDINARY', None, True, 0, [], {}):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(ValueError):
                        callers.admit_original_scope(root, invalid)
                    rejected += 1
        self.assertEqual(rejected, 44)

    def test_all_terminal_rereads_source_capture_gaps_and_stale_admissions_reject(self):
        rejected = 0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.stage(root)
            for scope_name in COUNTS:
                _, proof = callers.admit_original_scope(root, scope_name)
                for filename in proof['captured_files']:
                    target = root / filename
                    original_read = Path.read_bytes
                    reads = [0]

                    def changed_on_reread(path):
                        raw = original_read(path)
                        if path == target:
                            reads[0] += 1
                            if reads[0] > 1:
                                return raw + b'\n'
                        return raw

                    with self.subTest(scope=scope_name, filename=filename, mutation='terminal-reread'):
                        with patch.object(Path, 'read_bytes', changed_on_reread):
                            with self.assertRaises(ValueError):
                                callers.admit_original_scope(root, scope_name)
                        self.assertGreaterEqual(reads[0], 2)
                        rejected += 1
                    for mutation in ('missing-capture', 'different-capture'):
                        digests = {name: pin['sha256'] for name, pin in proof['captured_files'].items()}
                        if mutation == 'missing-capture':
                            del digests[filename]
                        else:
                            digests[filename] = '0' * 64
                        with self.subTest(scope=scope_name, filename=filename, mutation=mutation):
                            with self.assertRaises(ValueError):
                                callers.bind_scope_admission_to_source_capture(proof, digests)
                            rejected += 1
                    raw = target.read_bytes()
                    target.write_bytes(raw + b'\n')
                    try:
                        with self.subTest(scope=scope_name, filename=filename, mutation='no-cached-admission'):
                            with self.assertRaises(ValueError):
                                callers.admit_original_scope(root, scope_name)
                            rejected += 1
                    finally:
                        target.write_bytes(raw)
        self.assertEqual(rejected, 64)


if __name__ == '__main__':
    unittest.main()
