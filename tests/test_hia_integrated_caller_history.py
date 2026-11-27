"""Physical source, immutable history and proof controls for three qualifiers."""
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_cold_caller_selection_history as history

ROOT = Path(__file__).resolve().parents[1]


class IntegratedCallerHistoryTests(unittest.TestCase):
    NAME = 'tools/qualify_hia_cost_ledger_callers.py'

    def source(self, name=None):
        return (ROOT / (name or self.NAME)).read_bytes()

    def copy_root(self, root):
        for name in (self.NAME, history.FIXTURE, history.INTEGRATED_FIXTURE,
                     history.INVERSE_HELPER):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())

    def prior_and_proof(self, name=None):
        name = name or self.NAME
        raw = self.source(name)
        original, proof = history.reviewed(name, raw)
        return raw, {'path': name, 'current_bytes': len(original),
                     'current_sha256': sha256(original).hexdigest()}, proof

    def test_three_full_sources_restore_both_fixed_predecessors_and_counts(self):
        self.assertEqual(len(history.INTEGRATED_EXPECTED), 3)
        self.assertEqual(sorted(history.INTEGRATED_CALLERS.values()), [50, 50, 81])
        frozen = (ROOT / history.FIXTURE).read_bytes()
        self.assertEqual(sha256(frozen).hexdigest(),
                         'a9c3182285be62898e01b1a836a0ac7a471dbf6a286b0ca0dccdc4b70eb859fc')
        for name, expected in history.INTEGRATED_EXPECTED.items():
            raw = self.source(name)
            selected, integrated, captures = history._integrated_predecessor(
                name, raw, ROOT, Path.read_bytes)
            original, proof = history.reviewed(name, raw)
            self.assertEqual(history.pin(raw), expected['new'])
            self.assertEqual(history.pin(selected), expected['old'])
            self.assertEqual(expected['old'], history.EXPECTED[name]['new'])
            self.assertEqual(history.pin(original), history.EXPECTED[name]['old'])
            self.assertEqual(set(captures),
                             {name, history.INTEGRATED_FIXTURE, history.INVERSE_HELPER})
            self.assertEqual(proof['integrated_source_admission'], integrated)
            self.assertEqual(proof['new'], expected['new'])
            self.assertFalse(proof['whole_native_delivery_qualified'])

    def test_exact_v1_source_still_uses_only_its_original_authority(self):
        for name in history.INTEGRATED_EXPECTED:
            selected, _, _ = history._integrated_predecessor(
                name, self.source(name), ROOT, Path.read_bytes)
            calls = []
            def take(path):
                calls.append(path.relative_to(ROOT).as_posix())
                return path.read_bytes()
            original, proof = history.reviewed(name, selected, take=take)
            self.assertEqual(calls, [history.FIXTURE, history.FIXTURE])
            self.assertEqual(history.pin(original), history.EXPECTED[name]['old'])
            self.assertNotIn('integrated_source_admission', proof)

    def test_unknown_partial_source_gains_no_history_exception(self):
        raw = self.source()
        for changed in (raw + b'# changed\n', raw[:-1], raw.replace(b'81', b'80', 1)):
            with self.subTest(digest=sha256(changed).hexdigest()):
                self.assertNotEqual(changed, raw)
                restored, proof = history.reviewed(
                    self.NAME, changed,
                    take=lambda path: self.fail('unknown bytes read a fixed authority'))
                self.assertEqual(restored, changed)
                self.assertIsNone(proof)

    def test_selected_root_source_must_equal_the_actual_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.copy_root(root)
            path = root / self.NAME
            path.write_bytes(self.source() + b' ')
            with self.assertRaises(ValueError):
                history.reviewed(self.NAME, self.source(), root=root)
            path.unlink()
            with self.assertRaises(FileNotFoundError):
                history.reviewed(self.NAME, self.source(), root=root)

    def test_missing_or_changed_fixture_and_inverse_helper_never_use_global_root(self):
        for name in (history.FIXTURE, history.INTEGRATED_FIXTURE, history.INVERSE_HELPER):
            with self.subTest(path=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.copy_root(root)
                path = root / name
                original = path.read_bytes()
                path.write_bytes(original + b' ')
                with self.assertRaises(ValueError):
                    history.reviewed(self.NAME, self.source(), root=root)
                path.unlink()
                with self.assertRaises(FileNotFoundError):
                    history.reviewed(self.NAME, self.source(), root=root)

    def test_every_v2_capture_is_reread_after_original_v1_admission(self):
        for target in (self.NAME, history.INTEGRATED_FIXTURE, history.INVERSE_HELPER):
            counts = {}
            v1_reads = []
            def take(path):
                name = path.relative_to(ROOT).as_posix()
                counts[name] = counts.get(name, 0) + 1
                if name == history.FIXTURE:
                    v1_reads.append(name)
                if name == target and counts[name] == 2:
                    self.assertEqual(len(v1_reads), 2)
                    return b'changed after original source admission'
                return path.read_bytes()
            with self.subTest(path=target), self.assertRaises(ValueError):
                history.reviewed(self.NAME, self.source(), take=take)
            self.assertEqual(counts[target], 2)

    def test_rebound_fixture_cannot_change_scope_or_complete_predecessor(self):
        original = json.loads((ROOT / history.INTEGRATED_FIXTURE).read_bytes())
        for mutation in ('pin', 'count', 'path', 'scope', 'false_is_not_zero'):
            value = json.loads(json.dumps(original))
            if mutation == 'pin':
                value['files'][self.NAME]['old']['bytes'] += 1
            elif mutation == 'count':
                value['original_callers'][self.NAME] -= 1
            elif mutation == 'path':
                value['files']['../' + self.NAME] = value['files'].pop(self.NAME)
            elif mutation == 'scope':
                value['source_kind'] = 'NATIVE_EXECUTION'
            else:
                value['whole_native_delivery_qualified'] = 0
            changed = (json.dumps(value, indent=2) + '\n').encode()
            def take(path):
                return changed if path == ROOT / history.INTEGRATED_FIXTURE else path.read_bytes()
            with self.subTest(mutation=mutation), patch.object(
                    history, 'INTEGRATED_FIXTURE_PIN', history.pin(changed)):
                with self.assertRaises(ValueError):
                    history.reviewed(self.NAME, self.source(), take=take)

    def test_rebound_fixture_bad_inverse_never_recovers_old_source(self):
        for value in (False, -1, 1 << 30):
            fixture = json.loads((ROOT / history.INTEGRATED_FIXTURE).read_bytes())
            fixture['files'][self.NAME]['hunks'][0]['new_offset'] = value
            changed = (json.dumps(fixture, indent=2) + '\n').encode()
            def take(path):
                return changed if path == ROOT / history.INTEGRATED_FIXTURE else path.read_bytes()
            with self.subTest(offset=value), patch.object(
                    history, 'INTEGRATED_FIXTURE_PIN', history.pin(changed)):
                with self.assertRaises(ValueError):
                    history.reviewed(self.NAME, self.source(), take=take)

    def test_adjustment_preserves_old_authority_and_refuses_cross_path_proof(self):
        raw, prior, proof = self.prior_and_proof()
        prior['original_sha256'] = '0' * 64
        adjusted = history.bind_adjustment(prior, raw, proof)
        self.assertEqual(adjusted['original_sha256'], prior['original_sha256'])
        self.assertEqual(adjusted['current_sha256'], history.current_pin(self.NAME)['sha256'])
        for other in history.INTEGRATED_EXPECTED:
            if other == self.NAME:
                continue
            _, _, foreign = self.prior_and_proof(other)
            with self.assertRaises(ValueError):
                history.bind_adjustment(prior, raw, foreign)
        with self.assertRaises(ValueError):
            history.bind_adjustment({**prior, 'path': False}, raw, proof)
        changed = {**proof, 'integrated_source_admission': None}
        with self.assertRaises(ValueError):
            history.bind_adjustment(prior, raw, changed)

    def test_adjustment_refuses_incomplete_or_rebound_v2_proof(self):
        raw, prior, proof = self.prior_and_proof()
        for field in ('path', 'old', 'new', 'fixture', 'inverse_helper',
                      'original_caller_count', 'terminal_reread_identical',
                      'whole_native_delivery_qualified'):
            nested = dict(proof['integrated_source_admission'])
            nested.pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                history.bind_adjustment(
                    prior, raw, {**proof, 'integrated_source_admission': nested})
        for field, value in (('terminal_reread_identical', 1),
                             ('whole_native_delivery_qualified', 0)):
            nested = {**proof['integrated_source_admission'], field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                history.bind_adjustment(
                    prior, raw, {**proof, 'integrated_source_admission': nested})


if __name__ == '__main__':
    unittest.main()
