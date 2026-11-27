"""Independent roots and unchanged original scope for Artifact134 source admission."""
import ast
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import hia_artifact_caller_source_history as history
from tools import qualify_hia_artifact_delivery_callers as subject

ROOT = Path(__file__).resolve().parents[1]


class ArtifactCompleteSourceHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original, cls.proof = subject.admit_inventory(ROOT, with_source_admission=True)
        cls.files = {name: (ROOT / name).read_bytes() for name in cls.proof['captured_files']}
        cls.live = dict(cls.files)

    @classmethod
    def tearDownClass(cls):
        if any((ROOT / name).read_bytes() != raw for name, raw in cls.live.items()):
            raise AssertionError('artifact source controls changed their live inputs')

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='hia-artifact-source-history-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name, raw in self.files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)

    def admit(self):
        return subject.admit_inventory(self.root, with_source_admission=True)

    def test_01_original132_and_exact_two_successors_have_complete_groups(self):
        original, proof = self.admit()
        groups, planned, added = subject.declared_execution_groups(original, proof)
        self.assertEqual(original, self.original)
        self.assertEqual(len(original['ordered_ids']), 132)
        self.assertEqual([group['count'] for group in groups], [63, 39, 32])
        self.assertEqual(len(planned), 134)
        self.assertEqual(len(set(planned)), 134)
        self.assertEqual(added, list(history.ASSEMBLY_ADDED_IDS))
        self.assertEqual([name for name in planned if name not in added], original['ordered_ids'])
        self.assertEqual([group['selector'] for group in groups],
                         [None, subject.PUBLIC_SELECTOR, subject.STORE_SELECTOR])
        self.assertEqual(set(proof['reviewed_integrated_source_adjustments']),
                         {history.ASSEMBLY, history.PUBLICATION, history.NATIVE_TOOLS})
        for name, raw in self.files.items():
            self.assertEqual(proof['captured_files'][name], history.pin(raw))
        self.assertFalse(proof['whole_native'])
        self.assertTrue(proof['terminal_reread_identical'])

    def test_02_complete_inverse_keeps_all_original_assembly_method_bodies(self):
        raw = self.files[history.ASSEMBLY]
        prior, proof = history.reviewed(self.root, history.ASSEMBLY, raw)
        def methods(source):
            return {cls.name + '.' + node.name: ast.dump(node, include_attributes=False)
                    for cls in ast.parse(source).body if isinstance(cls, ast.ClassDef)
                    for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name.startswith('test')}
        original, current = methods(prior), methods(raw)
        self.assertEqual(len(original), 18)
        self.assertEqual(len(current), 20)
        self.assertEqual({name: current[name] for name in original}, original)
        added = ['tests.test_hia_agent_assembly.' + name for name in sorted(set(current) - set(original))]
        self.assertEqual(added, list(history.ASSEMBLY_ADDED_IDS))
        self.assertEqual(history.pin(prior), history.REVIEWED[history.ASSEMBLY])
        self.assertTrue(proof['complete_current_forward_replay_verified'])

    def test_03_every_actual_capture_refuses_missing_changed_and_cached_bytes(self):
        for name, raw in self.files.items():
            target = self.root / name
            for mode in ('missing', 'tamper', 'after-warm-admission'):
                with self.subTest(path=name, mode=mode):
                    if mode == 'after-warm-admission':
                        self.admit()
                    if mode == 'missing':
                        target.unlink()
                    else:
                        target.write_bytes(raw + b'\n')
                    try:
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            self.admit()
                    finally:
                        target.write_bytes(raw)

    def test_04_every_actual_capture_refuses_terminal_drift(self):
        real_read = Path.read_bytes
        for name in self.files:
            target, reads = self.root / name, []
            def read(path):
                raw = real_read(path)
                if path == target:
                    reads.append(True)
                    if len(reads) > 1:
                        return raw + b'\n'
                return raw
            with self.subTest(path=name), patch.object(Path, 'read_bytes', read):
                with self.assertRaises(ValueError):
                    self.admit()
            self.assertGreaterEqual(len(reads), 2)

    def test_05_current_whole_sources_are_bound_to_requested_root_and_reader(self):
        for name in (history.ASSEMBLY, history.PUBLICATION, history.NATIVE_TOOLS):
            raw = self.files[name]
            target = self.root / name
            target.write_bytes(raw + b'\n')
            with self.subTest(path=name), self.assertRaises(ValueError):
                history.reviewed(self.root, name, raw)
            target.write_bytes(raw)
            captured = []
            def take(path):
                self.assertTrue(self.root in path.parents)
                captured.append(path)
                return path.read_bytes()
            restored, proof = history.reviewed(self.root, name, raw, take=take)
            self.assertEqual(history.pin(restored), history.REVIEWED[name])
            self.assertEqual(proof['physical'], history.pin(raw))
            self.assertGreaterEqual(captured.count(target), 2)
            wrong = self.root / 'empty-distinct-root'
            wrong.mkdir(exist_ok=True)
            with self.assertRaises(FileNotFoundError):
                history.reviewed(wrong, name, raw)
        old = bytearray(self.files[history.NATIVE_TOOLS])
        old[4929] = ord('3')
        with self.assertRaises(ValueError):
            history.reviewed(self.root, history.NATIVE_TOOLS, bytes(old))

    def test_06_execution_proof_cannot_drop_originals_or_current_successors(self):
        original, proof = self.admit()
        candidates = []
        for name in proof['reviewed_integrated_source_adjustments']:
            candidate = deepcopy(proof)
            del candidate['reviewed_integrated_source_adjustments'][name]
            candidates.append(candidate)
        for name in proof['captured_files']:
            candidate = deepcopy(proof)
            if name in subject._HISTORY_CURRENT or name == subject._HISTORY_HELPER:
                del candidate['captured_files'][name]
                candidates.append(candidate)
        for added in ([], list(reversed(history.ASSEMBLY_ADDED_IDS)),
                      [*history.ASSEMBLY_ADDED_IDS, 'tests.invented.test']):
            candidate = deepcopy(proof)
            candidate['reviewed_integrated_source_adjustments'][history.ASSEMBLY]['added_ordered_ids'] = added
            candidates.append(candidate)
        candidate = deepcopy(proof)
        candidate['original_ordered_ids'] = candidate['original_ordered_ids'][1:]
        candidates.append(candidate)
        for index, candidate in enumerate(candidates):
            with self.subTest(case=index), self.assertRaises((ValueError, KeyError)):
                subject.declared_execution_groups(original, candidate)
        for change in ('omit', 'reverse', 'duplicate'):
            candidate = deepcopy(original)
            ids = candidate['ordered_ids']
            candidate['ordered_ids'] = ids[1:] if change == 'omit' else (
                list(reversed(ids)) if change == 'reverse' else [*ids[:-1], ids[0]])
            with self.subTest(change=change), self.assertRaises(ValueError):
                subject.declared_execution_groups(candidate, proof)

    def test_07_six_result_assertion_is_explicit_typed_and_full_source_bound(self):
        original, proof = self.admit()
        record = proof['reviewed_integrated_source_adjustments'][history.NATIVE_TOOLS]
        six = record['native_result_assertion_successor']
        self.assertEqual(six['physical'], history.NATIVE_SIX)
        self.assertEqual(six['predecessor'], history.CURRENT[history.NATIVE_TOOLS])
        self.assertEqual((six['previous_expected'], six['current_expected']), (3, 6))
        self.assertEqual(six['definition'], 'ArtifactContractTests.test_discovery_is_readable_and_source_bound')
        self.assertFalse(six['original_deadlines_changed'])
        self.assertFalse(six['original_runtime_budgets_changed'])
        for key, changed in (
                ('previous_expected', 6), ('current_expected', 3),
                ('exact_byte_splices', True), ('original_deadlines_changed', 0),
                ('complete_original_inverse_verified', 1),
                ('definition', 'different.original.method')):
            candidate = deepcopy(proof)
            candidate['reviewed_integrated_source_adjustments'][history.NATIVE_TOOLS][
                'native_result_assertion_successor'][key] = changed
            with self.subTest(field=key), self.assertRaises(ValueError):
                subject.declared_execution_groups(original, candidate)
        candidate = deepcopy(proof)
        candidate['captured_files'][history.NATIVE_TOOLS] = history.CURRENT[history.NATIVE_TOOLS]
        with self.assertRaises(ValueError):
            subject.declared_execution_groups(original, candidate)
        target = self.root / history.NATIVE_TOOLS
        prior = bytearray(target.read_bytes())
        prior[4929] = ord('3')
        target.write_bytes(prior)
        _, prior_proof = self.admit()
        prior_record = prior_proof['reviewed_integrated_source_adjustments'][history.NATIVE_TOOLS]
        self.assertNotIn('native_result_assertion_successor', prior_record)
        self.assertEqual(prior_record['physical'], history.CURRENT[history.NATIVE_TOOLS])
        subject.declared_execution_groups(original, prior_proof)

    def test_08_new_source_inverse_imports_only_fixed_data_helpers(self):
        source = (ROOT / subject._HISTORY_HELPER).read_bytes()
        dependencies = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom):
                if node.module == 'tools':
                    dependencies.update('tools.' + alias.name for alias in node.names)
                else:
                    dependencies.add(node.module)
            elif isinstance(node, ast.Import):
                dependencies.update(alias.name for alias in node.names)
        self.assertEqual(dependencies, {'hashlib', 'json', 'pathlib',
            'tools.hia_frozen_component_sources', 'tools.hia_native_result_caller_history'})

    def test_09_real_unfiltered_discovery_contains_all134_declared_methods(self):
        from tools.run_hia_unittest_gate import load_declared_suite
        original, proof = self.admit()
        groups, planned, added = subject.declared_execution_groups(original, proof)
        observed = []
        for group in groups:
            suite, ids = load_declared_suite(group['modules'])
            self.assertEqual(list(ids), group['ordered_ids'])
            self.assertEqual(suite.countTestCases(), group['count'])
            observed.extend(ids)
        self.assertEqual(observed, planned)
        self.assertEqual(len(observed), 134)


if __name__ == '__main__':
    unittest.main()
