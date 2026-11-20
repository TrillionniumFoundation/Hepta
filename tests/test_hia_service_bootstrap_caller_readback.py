"""Independent source/proof readback controls; no native qualification claim."""
from __future__ import annotations

import builtins
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import read_hia_service_bootstrap as reader


ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = 'tests/fixtures/hia_service_bootstrap_original_r12/caller-scopes.json'
AUTHORITY_SHA256 = 'b8056f8c056409952ff219d4e1b789d40d754de4718023c9fcb467c02c893af4'
CALLER = 'tests/test_hia_agent_native_tools.py'
HELPER = 'tests/hia_caller_diagnostics_admission.py'
PROVENANCE = 'tests/fixtures/caller_deadline_diagnostics_v1.json'
PROVENANCE_SHA256 = '53aff1f370ac337d6246a0179f8b6d5c346fcc44ffd7f2187c515c95c663f97c'
COUNTS = {'ordinary': 112, 'journal': 21, 'context': 15}


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


class ServiceBootstrapCallerReadbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        frozen = (ROOT / AUTHORITY).read_bytes()
        provenance = (ROOT / PROVENANCE).read_bytes()
        if sha256(frozen).hexdigest() != AUTHORITY_SHA256 or sha256(provenance).hexdigest() != PROVENANCE_SHA256:
            raise AssertionError('fixed original scope or reviewed diagnostic authority differs')
        cls.scopes = json.loads(frozen)['scopes']
        cls.diagnostics = json.loads(provenance)
        names = {AUTHORITY, HELPER, PROVENANCE}
        for scope in cls.scopes.values():
            names.update(scope['files'])
        cls.inputs = {name: (ROOT / name).read_bytes() for name in sorted(names)}
        # Preserve every original 9-positive/136-negative readback control on
        # the full original Journal source. New preparation controls separately
        # admit and reject both exact complete Journal versions.
        journal_path = 'tests/test_hia_agent_journal_native.py'
        journal_archive = (ROOT / 'tests/fixtures/journal_installed_preparation_v1.py.txt').read_bytes()
        if pin(journal_archive) != cls.scopes['journal']['files'][journal_path]:
            raise AssertionError('retained complete Journal source differs')
        cls.inputs[journal_path] = journal_archive
        raw = cls.inputs[CALLER]
        if pin(raw) != cls.diagnostics['current']:
            raise AssertionError('the current exact diagnostic successor is required')
        original = raw
        for item in reversed(cls.diagnostics['splices']):
            start = item['new_offset']
            before, after = bytes.fromhex(item['old_hex']), bytes.fromhex(item['new_hex'])
            if original[start:start + len(after)] != after:
                raise AssertionError('independent test setup splice differs')
            original = original[:start] + before + original[start + len(after):]
        if pin(original) != cls.diagnostics['original']:
            raise AssertionError('independent test setup did not restore the full historical caller')
        cls.original = original

    def stage(self, root, *, original=False):
        for name, raw in self.inputs.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(self.original if original and name == CALLER else raw)

    def inner(self, root, scope_name, *, proof=True):
        scope = self.scopes[scope_name]
        consumed = {AUTHORITY, *scope['files']}
        adjustments = {}
        if CALLER in scope['files'] and (root / CALLER).read_bytes() != self.original:
            consumed.update((HELPER, PROVENANCE))
            adjustments[CALLER] = {
                'path': CALLER, 'original': self.diagnostics['original'],
                'current': self.diagnostics['current'], 'provenance_path': PROVENANCE,
                'provenance_sha256': PROVENANCE_SHA256, 'exact_splices': 2,
                'complete_original_inverse_verified': True,
                'complete_current_forward_replay_verified': True,
                'original_deadline_seconds': 5, 'original_native_budget_ms': 1,
                'production_source_exception': False,
            }
        captured = {name: pin((root / name).read_bytes()) for name in sorted(consumed)}
        before = {name: pin((root / name).read_bytes())['sha256'] for name in self.inputs}
        inner = {'source_before': before, 'source_after': dict(before)}
        if proof:
            inner['caller_source_admission'] = {
                'schema': 'hepta.hia.service-bootstrap-caller-source-admission.v1',
                'scope': scope_name,
                'authority': {'path': AUTHORITY, **pin(self.inputs[AUTHORITY])},
                'original_files': scope['files'], 'original_modules': scope['modules'],
                'original_ordered_ids': scope['ordered_ids'], 'original_outer_seconds': 1800,
                'reviewed_diagnostic_source_adjustments': adjustments,
                'captured_files': captured, 'terminal_reread_identical': True,
                'original_inventory_bytes_unchanged': True,
                'production_source_exceptions': [], 'whole_native': False,
            }
        return deepcopy(inner), set(consumed)

    def read(self, root, name, inner, captured=None):
        if captured is None:
            captured = []
        with patch.object(reader, 'ROOT', root):
            value = reader._read_caller_source_admission(name, self.scopes[name], inner, captured)
        return value, captured

    def test_all_original_and_current_scopes_without_importing_any_admission_producer(self):
        variants = 0
        actual_import = builtins.__import__

        def no_admission_import(name, globals=None, locals=None, fromlist=(), level=0):
            if (name in ('tests.hia_caller_diagnostics_admission',
                         'tools.qualify_hia_service_bootstrap_callers')
                    or name == 'tests' and 'hia_caller_diagnostics_admission' in fromlist
                    or name == 'tools' and 'qualify_hia_service_bootstrap_callers' in fromlist):
                raise AssertionError('independent reader imported its producer or admission helper')
            return actual_import(name, globals, locals, fromlist, level)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for original, proof_present in ((True, False), (True, True), (False, True)):
                self.stage(root, original=original)
                for name, count in COUNTS.items():
                    with self.subTest(original=original, proof_present=proof_present, scope=name):
                        inner, consumed = self.inner(root, name, proof=proof_present)
                        with patch.object(builtins, '__import__', no_admission_import):
                            observed, captured = self.read(root, name, inner)
                        self.assertEqual(len(observed['original_ordered_ids']), count)
                        self.assertEqual(observed['original_ordered_ids'], self.scopes[name]['ordered_ids'])
                        self.assertEqual(observed['original_modules'], self.scopes[name]['modules'])
                        self.assertEqual(observed['original_outer_seconds'], 1800)
                        self.assertEqual(observed['original_files'], self.scopes[name]['files'])
                        self.assertEqual({str(path.relative_to(root)) for path, _ in captured}, consumed)
                        self.assertEqual(set(observed['captured_files']), consumed)
                        if proof_present:
                            self.assertEqual(observed, inner['caller_source_admission'])
                        reader.unchanged(captured)
                        variants += 1
        self.assertEqual(variants, 9)
        self.assertEqual(sum(COUNTS.values()), 148)

    def test_missing_changed_and_resigned_sources_cannot_acquire_authority(self):
        rejected = 0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.stage(root)
            for name in COUNTS:
                inner, consumed = self.inner(root, name)
                for filename in sorted(consumed):
                    path = root / filename
                    raw = path.read_bytes()
                    for mutation in ('missing', 'changed'):
                        with self.subTest(scope=name, file=filename, mutation=mutation):
                            if mutation == 'missing':
                                path.unlink()
                            else:
                                path.write_bytes(raw + b'\n')
                            try:
                                with self.assertRaises((ValueError, OSError)):
                                    self.read(root, name, inner)
                                rejected += 1
                            finally:
                                path.write_bytes(raw)
            for filename in (CALLER, PROVENANCE):
                raw = (root / filename).read_bytes()
                (root / filename).write_bytes(raw + b'\n')
                try:
                    forged, _ = self.inner(root, 'ordinary')
                    with self.subTest(resigned=filename):
                        with self.assertRaises(ValueError):
                            self.read(root, 'ordinary', forged)
                        rejected += 1
                finally:
                    (root / filename).write_bytes(raw)
            inner, _ = self.inner(root, 'ordinary')
            for invalid in ('', '../ordinary', 'ORDINARY', None, True, 0, [], {}):
                with self.subTest(invalid_scope=invalid):
                    with patch.object(reader, 'ROOT', root):
                        with self.assertRaises(ValueError):
                            reader._read_caller_source_admission(invalid, self.scopes['ordinary'], inner, [])
                    rejected += 1
        self.assertEqual(rejected, 42)

    def test_every_proof_claim_and_source_capture_gap_is_independently_rejected(self):
        rejected = 0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.stage(root)
            pristine, _ = self.inner(root, 'ordinary')
            mutations = [
                ('schema', 'forged'), ('scope', 'journal'),
                ('authority', {'path': AUTHORITY, 'bytes': 28102, 'sha256': '0' * 64}),
                ('original_files', {}), ('original_modules', []), ('original_ordered_ids', []),
                ('original_outer_seconds', 1801), ('reviewed_diagnostic_source_adjustments', {}),
                ('captured_files', {}), ('terminal_reread_identical', 1),
                ('original_inventory_bytes_unchanged', 1), ('production_source_exceptions', [CALLER]),
                ('whole_native', True), ('unbound_extra', None),
            ]
            for field, bad in mutations:
                forged = deepcopy(pristine)
                forged['caller_source_admission'][field] = bad
                with self.subTest(proof_field=field):
                    with self.assertRaises(ValueError):
                        self.read(root, 'ordinary', forged)
                    rejected += 1
            adjustment_mutations = [
                ('exact_splices', 3), ('current', {'bytes': 46519, 'sha256': '0' * 64}),
                ('original', {'bytes': 45385, 'sha256': '0' * 64}),
                ('provenance_sha256', '0' * 64), ('original_deadline_seconds', 6),
                ('original_native_budget_ms', 2), ('complete_original_inverse_verified', False),
                ('complete_current_forward_replay_verified', False),
            ]
            for field, bad in adjustment_mutations:
                forged = deepcopy(pristine)
                forged['caller_source_admission']['reviewed_diagnostic_source_adjustments'][CALLER][field] = bad
                with self.subTest(adjustment_field=field):
                    with self.assertRaises(ValueError):
                        self.read(root, 'ordinary', forged)
                    rejected += 1
            forged = deepcopy(pristine)
            del forged['caller_source_admission']
            with self.assertRaises(ValueError):
                self.read(root, 'ordinary', forged)
            rejected += 1
            for name in COUNTS:
                pristine, consumed = self.inner(root, name)
                for filename in sorted(consumed):
                    for mutation in ('missing-both', 'changed-both', 'changed-after'):
                        forged = deepcopy(pristine)
                        if mutation == 'missing-both':
                            for field in ('source_before', 'source_after'):
                                del forged[field][filename]
                        elif mutation == 'changed-both':
                            for field in ('source_before', 'source_after'):
                                forged[field][filename] = '0' * 64
                        else:
                            forged['source_after'][filename] = '0' * 64
                        with self.subTest(scope=name, file=filename, mutation=mutation):
                            with self.assertRaises(ValueError):
                                self.read(root, name, forged)
                            rejected += 1
        self.assertEqual(rejected, 71)

    def test_all_late_custody_changes_and_nonexact_raw_splices_are_rejected(self):
        rejected = 0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.stage(root)
            for name in COUNTS:
                inner, consumed = self.inner(root, name)
                for filename in sorted(consumed):
                    _, captured = self.read(root, name, inner)
                    target = root / filename
                    raw = target.read_bytes()
                    target.write_bytes(raw + b'\n')
                    try:
                        with self.subTest(scope=name, late_file=filename):
                            with self.assertRaises(ValueError):
                                reader.unchanged(captured)
                            rejected += 1
                    finally:
                        target.write_bytes(raw)
            current, provenance = self.inputs[CALLER], self.inputs[PROVENANCE]
            altered = json.loads(provenance)
            altered['splices'][0]['old_offset'] += 1
            for raw, proof in (
                (current + b'\n', provenance), (self.original, provenance),
                (bytearray(current), provenance), (current, bytearray(provenance)),
                (current, provenance + b'\n'), (current[:-1], provenance),
                (current, json.dumps(altered).encode()),
            ):
                with self.subTest(raw_type=type(raw).__name__, raw_bytes=len(raw), proof_bytes=len(proof)):
                    with self.assertRaises(ValueError):
                        reader._restore_caller_diagnostic_source(raw, proof)
                    rejected += 1
        self.assertEqual(rejected, 23)


if __name__ == '__main__':
    unittest.main()
