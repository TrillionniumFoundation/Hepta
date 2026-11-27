"""Current physical source gates alongside the unchanged historical controls."""
import ast
from contextlib import contextmanager
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests import hia_scoped_evaluation_cold_preparation as preparation
from tools import hia_frozen_component_sources as engine
from tools import hia_native_cold_caller_history as cold
from tools import qualify_hia_service_discovery_callers as discovery
from tools import qualify_hia_service_verification_callers as verification
from tools import qualify_hia_evaluation_callers as evaluation

ROOT = Path(__file__).resolve().parents[1]
CASES = ((discovery, 'ordinary', 112), (discovery, 'journal', 21),
         (discovery, 'context', 15), (verification, 'ordinary', 112),
         (verification, 'journal', 21))


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


@contextmanager
def physical_tree(data):
    with tempfile.TemporaryDirectory(prefix='hia-current-scoped-capture-') as directory:
        root = Path(directory).resolve(strict=True)
        for name, raw in data.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        yield root


def capture_data(proof, key='captured_files'):
    return {name: (ROOT / name).read_bytes() for name in proof[key]}


class ScopedCurrentColdSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.states = []
        for module, scope, count in CASES:
            value, proof = module.admit_original_scope(ROOT, scope)
            cls.states.append((module, scope, count, value, proof, capture_data(proof)))

    def test_five_current_scopes_keep_every_id_budget_and_physical_capture(self):
        for module, scope, count, value, proof, data in self.states:
            with self.subTest(module=module.__name__, scope=scope):
                original = json.loads(data[module.FIXTURE])['scopes'][scope]
                self.assertEqual(value, original)
                self.assertEqual(len(value['ordered_ids']), count)
                self.assertEqual(value['outer_seconds'], 1800)
                self.assertEqual(proof['captured_files'], {n: pin(b) for n, b in data.items()})
                self.assertTrue(proof['terminal_reread_identical'])
                self.assertFalse(proof['whole_native'])
                expected_cold = {n for n in value['files'] if pin(data[n]) == cold.KNOWN_CURRENT.get(n)}
                self.assertEqual(set(proof.get('reviewed_native_cold_caller_adjustments', {})), expected_cold)
                for name in expected_cold:
                    review = proof['reviewed_scope_predecessors'][name]
                    self.assertEqual(review['physical'], pin(data[name]))
                    self.assertNotEqual(review['historical_input'], pin(data[name]))
                    self.assertFalse(review['physical_capture_rewritten'])
                    self.assertFalse(review['prior_projection_is_physical_source'])
                    self.assertEqual(review['prior_scope_review']['physical'], review['historical_input'])
                module.bind_scope_admission_to_source_capture(
                    proof, {n: pin(b)['sha256'] for n, b in data.items()})

    def test_every_actual_capture_rejects_missing_and_changed_independent_root_bytes(self):
        for module, scope, _, _, _, data in self.states:
            with physical_tree(data) as root:
                module.admit_original_scope(root, scope)
                for name, raw in data.items():
                    target = root / name
                    for missing in (True, False):
                        with self.subTest(module=module.__name__, scope=scope, path=name, missing=missing):
                            try:
                                if missing:
                                    target.unlink()
                                else:
                                    target.write_bytes(raw + b'\n')
                                with self.assertRaises((ValueError, OSError)):
                                    module.admit_original_scope(root, scope)
                            finally:
                                target.write_bytes(raw)

    def test_actual_file_changes_after_first_read_are_refused_at_terminal(self):
        real_read = Path.read_bytes
        for module, scope, _, _, _, data in self.states:
            with physical_tree(data) as root:
                for name, expected in data.items():
                    target, writes = root / name, []
                    def changed(path):
                        raw = real_read(path)
                        if path == target and not writes:
                            target.write_bytes(raw + b'\n')
                            writes.append(name)
                        return raw
                    with self.subTest(module=module.__name__, scope=scope, path=name):
                        try:
                            with patch.object(Path, 'read_bytes', changed), self.assertRaises((ValueError, OSError)):
                                module.admit_original_scope(root, scope)
                            self.assertEqual(writes, [name])
                        finally:
                            target.write_bytes(expected)

    def test_declared_root_alias_uses_one_physical_capture_domain(self):
        for module, scope, _, _, proof, data in self.states:
            with physical_tree(data) as root, tempfile.TemporaryDirectory() as directory:
                alias = Path(directory) / 'declared-source'
                alias.symlink_to(root, target_is_directory=True)
                _, actual = module.admit_original_scope(alias, scope)
                self.assertEqual(actual['captured_files'], proof['captured_files'])
                self.assertTrue(actual['terminal_reread_identical'])

    def test_previous_admission_does_not_authorize_a_later_or_different_root(self):
        for module, scope, _, _, _, data in self.states:
            with physical_tree(data) as first, physical_tree(data) as second:
                module.admit_original_scope(first, scope)
                name = next(iter(json.loads(data[module.FIXTURE])['scopes'][scope]['files']))
                (second / name).write_bytes(data[name] + b'\n')
                with self.assertRaises((ValueError, OSError)):
                    module.admit_original_scope(second, scope)
                (first / name).write_bytes(data[name] + b'\n')
                with self.assertRaises((ValueError, OSError)):
                    module.admit_original_scope(first, scope)


class ScopedEvaluationHistoricalViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.states = {}
        for domain in preparation.TESTS:
            with preparation.historical_view(ROOT, domain) as (stage, proof):
                physical = {name: (ROOT / name).read_bytes() for name in proof['actual_captured_files']}
                cls.states[domain] = (physical, proof)
            if proof['terminal_reread_identical'] is not True:
                raise AssertionError('source preparation did not close its physical interval')

    def test_complete_original_methods_and_runtime_entry_bodies_are_identical(self):
        value = json.loads((ROOT / preparation.FIXTURE).read_bytes())
        original_methods = 0
        for name, row in value['files'].items():
            current = (ROOT / name).read_bytes()
            old = engine.history_inverse(current, row, {'bytes': row['old_bytes'], 'sha256': row['old_sha256']})
            if name in preparation.TESTS.values():
                before, after = preparation._test_methods(old), preparation._test_methods(current)
                self.assertEqual(after, before)
                original_methods += len(before)
            else:
                def main(raw):
                    tree = ast.parse(raw)
                    return ast.dump(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main'))
                self.assertEqual(main(old), main(current))
        self.assertEqual(original_methods, 11)
        for domain, (data, proof) in self.states.items():
            self.assertEqual(proof['actual_captured_files'], {n: pin(b) for n, b in data.items()})
            self.assertFalse(proof['physical_capture_rewritten'])
            self.assertFalse(proof['historical_view_is_current_repository'])
            self.assertFalse(proof['native_product_execution_claimed'])
            self.assertTrue(proof['terminal_reread_identical'])

    def test_preparation_rejects_missing_and_tampered_captured_files_without_ambient_fallback(self):
        for domain, (data, _) in self.states.items():
            with physical_tree(data) as root:
                for name, raw in data.items():
                    target = root / name
                    for missing in (True, False):
                        with self.subTest(domain=domain, path=name, missing=missing):
                            try:
                                if missing:
                                    target.unlink()
                                else:
                                    target.write_bytes(raw + b'\n')
                                with self.assertRaises((ValueError, OSError)):
                                    with preparation.historical_view(root, domain):
                                        pass
                            finally:
                                target.write_bytes(raw)

    def test_physical_and_historical_files_are_both_checked_after_use(self):
        for domain, (data, _) in self.states.items():
            with physical_tree(data) as root:
                for name, raw in data.items():
                    with self.subTest(domain=domain, path=name, side='physical'):
                        try:
                            with self.assertRaises((ValueError, OSError)):
                                with preparation.historical_view(root, domain):
                                    (root / name).write_bytes(raw + b'\n')
                        finally:
                            (root / name).write_bytes(raw)
                with self.subTest(domain=domain, side='historical'):
                    with self.assertRaises((ValueError, OSError)):
                        with preparation.historical_view(root, domain) as (stage, proof):
                            name = next(iter(proof['reviewed_callers']))
                            (stage / name).write_bytes((stage / name).read_bytes() + b'\n')

    def test_import_time_reader_snapshot_rejects_disk_changes_before_first_use(self):
        data = self.states['scoped'][0]
        with physical_tree(data) as root:
            path = root / preparation.SELF
            spec = importlib.util.spec_from_file_location('isolated_scoped_history_reader', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            with module.historical_view(root, 'scoped'):
                pass
            original = path.read_bytes()
            path.write_bytes(original + b'\n# changed after import\n')
            with self.assertRaises(ValueError):
                with module.historical_view(root, 'scoped'):
                    pass


class EvaluationCurrentColdSourceTests(unittest.TestCase):
    def test_actual_complete_inventory_keeps_physical_captures_and_all_original_counts(self):
        inventory = json.loads((ROOT / evaluation.FIXTURE_NAME).read_bytes())
        records = {row['path']: row['sha256'] for row in inventory['modules'].values()}
        proof = {}
        evaluation.admit_original_sources(ROOT, records, source_proof=proof)
        self.assertEqual((len(records), inventory['all_original_tests'], inventory['ordinary_count']), (12, 183, 81))
        self.assertEqual(proof['original_source_sha256'], records)
        self.assertTrue(proof['terminal_reread_identical'])
        self.assertEqual(proof['production_source_exceptions'], [])
        for name, digest in proof['captured_source_sha256'].items():
            self.assertEqual(sha256((ROOT / name).read_bytes()).hexdigest(), digest)
        self.assertTrue(proof['reviewed_native_cold_caller_adjustments'])
        self.assertIn('tests/test_hia_slot_ledger_native_integration.py',
                      proof['reviewed_current_source_compositions'])

    def test_current_complete_evaluation_capture_rejects_late_physical_mutations(self):
        inventory = json.loads((ROOT / evaluation.FIXTURE_NAME).read_bytes())
        records = {row['path']: row['sha256'] for row in inventory['modules'].values()}
        proof = {}
        evaluation.admit_original_sources(ROOT, records, source_proof=proof)
        data = {name: (ROOT / name).read_bytes() for name in proof['captured_source_sha256']}
        real_read = Path.read_bytes
        with physical_tree(data) as root:
            for name, raw in data.items():
                target, writes = root / name, []
                def changed(path):
                    value = real_read(path)
                    if path == target and not writes:
                        target.write_bytes(value + b'\n')
                        writes.append(name)
                    return value
                with self.subTest(path=name):
                    try:
                        with patch.object(Path, 'read_bytes', changed), self.assertRaises((ValueError, OSError)):
                            evaluation.admit_original_sources(root, records)
                        self.assertEqual(writes, [name])
                    finally:
                        target.write_bytes(raw)


if __name__ == '__main__':
    unittest.main()
