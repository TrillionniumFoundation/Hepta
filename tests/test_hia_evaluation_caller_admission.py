"""Complete original evaluation caller identities and exact diagnostic successors."""
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_native_helpers import HELPERS
from tests import hia_caller_diagnostics_admission as diagnostics
from tools import qualify_hia_evaluation_callers as qualifier

ROOT = Path(__file__).resolve().parents[1]
HELPER = 'tests/hia_caller_diagnostics_admission.py'
REGISTRY_TEST = 'tests/test_hia_worker_native_helpers.py'


class EvaluationCallerAdmissionSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frozen = (ROOT / qualifier.FIXTURE_NAME).read_bytes()
        if sha256(cls.frozen).hexdigest() != qualifier.FIXTURE_SHA256:
            raise AssertionError('complete original evaluation inventory changed')
        cls.inventory = json.loads(cls.frozen)
        cls.records = {row['path']: row['sha256'] for row in cls.inventory['modules'].values()}
        names = (*cls.records, qualifier.FIXTURE_NAME, HELPER, diagnostics.FIXTURE)
        cls.raws = {name: (ROOT / name).read_bytes() for name in names}
        # Reconstruct the reference as data independently of the admission helper.
        original = cls.raws[diagnostics.PATH]
        for row in reversed(json.loads(cls.raws[diagnostics.FIXTURE])['splices']):
            at = row['new_offset']
            new, old = bytes.fromhex(row['new_hex']), bytes.fromhex(row['old_hex'])
            if original[at:at + len(new)] != new:
                raise AssertionError('fixed diagnostic source segment changed')
            original = original[:at] + old + original[at + len(new):]
        if sha256(original).hexdigest() != cls.records[diagnostics.PATH]:
            raise AssertionError('independent full original diagnostic source differs')
        cls.original = original
        current = ('        self.assertEqual(len(HELPERS), ' + str(len(HELPERS)) + ')\n').encode()
        old = b'        self.assertEqual(len(HELPERS), 35)\n'
        registry = cls.raws[REGISTRY_TEST]
        if sha256(registry).hexdigest() != cls.records[REGISTRY_TEST]:
            if registry.count(current) != 1:
                raise AssertionError('actual registry count source differs')
            registry = registry.replace(current, old, 1)
        if sha256(registry).hexdigest() != cls.records[REGISTRY_TEST]:
            raise AssertionError('complete original registry caller differs')
        cls.original_registry = registry

    @classmethod
    def tearDownClass(cls):
        for name, raw in cls.raws.items():
            if (ROOT / name).read_bytes() != raw:
                raise AssertionError('actual input changed during source controls: ' + name)

    @contextmanager
    def tree(self, *, current_diagnostics=True, current_registry=True):
        with tempfile.TemporaryDirectory(prefix='hia-evaluation-source-admission-') as directory:
            root = Path(directory)
            for name, raw in self.raws.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            if not current_diagnostics:
                (root / diagnostics.PATH).write_bytes(self.original)
            if not current_registry:
                (root / REGISTRY_TEST).write_bytes(self.original_registry)
            yield root

    def test_complete_original_and_current_sources_keep_all_original_method_ids(self):
        from tools.run_hia_unittest_gate import load_declared_suite
        self.assertEqual((len(self.records), self.inventory['all_original_tests'],
                          self.inventory['ordinary_count']), (12, 183, 81))
        observed = 0
        for name, row in self.inventory['modules'].items():
            suite, ids = load_declared_suite((name,))
            self.assertEqual(list(ids), row['ordered_ids'])
            observed += suite.countTestCases()
        self.assertEqual(observed, 183)
        for current_diagnostics in (False, True):
            for current_registry in (False, True):
                with self.subTest(diagnostics=current_diagnostics, registry=current_registry), self.tree(
                        current_diagnostics=current_diagnostics, current_registry=current_registry) as root:
                    proof = {}
                    adjustments = qualifier.admit_original_sources(root, self.records, source_proof=proof)
                    self.assertEqual(proof['registry_count_assertion_adjustments'], adjustments)
                    self.assertEqual(len(adjustments), int(current_registry and len(HELPERS) != 35))
                    self.assertEqual(proof['original_source_sha256'], self.records)
                    expected_diagnostics = ({diagnostics.PATH: diagnostics.admit(
                        diagnostics.PATH, self.raws[diagnostics.PATH], self.records[diagnostics.PATH],
                        self.raws[diagnostics.FIXTURE])} if current_diagnostics else {})
                    self.assertEqual(proof['reviewed_diagnostic_source_adjustments'], expected_diagnostics)
                    expected_paths = {*self.records, qualifier.FIXTURE_NAME}
                    if current_diagnostics:
                        expected_paths.update((HELPER, diagnostics.FIXTURE))
                    self.assertEqual(set(proof['captured_source_sha256']), expected_paths)
                    for path, digest in proof['captured_source_sha256'].items():
                        self.assertEqual(sha256((root / path).read_bytes()).hexdigest(), digest)
                    self.assertTrue(proof['terminal_reread_identical'])
                    self.assertEqual(proof['production_source_exceptions'], [])

    def test_changed_source_missing_dependency_and_refreshed_authority_are_refused(self):
        for name in self.raws:
            for missing in (False, True):
                with self.subTest(path=name, missing=missing), self.tree() as root:
                    target = root / name
                    if missing:
                        target.unlink()
                    else:
                        target.write_bytes(target.read_bytes() + b'\n')
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        qualifier.admit_original_sources(root, self.records)
        changed = dict(self.records)
        changed[diagnostics.PATH] = diagnostics.CURRENT['sha256']
        omitted = dict(self.records)
        omitted.pop(diagnostics.PATH)
        for records in (changed, omitted, tuple(self.records.items())):
            with self.subTest(records=type(records).__name__), self.tree() as root:
                with self.assertRaises(ValueError):
                    qualifier.admit_original_sources(root, records)

    def test_every_captured_input_is_reread_and_no_previous_admission_is_cached(self):
        actual_read = Path.read_bytes
        for name in self.raws:
            with self.subTest(path=name), self.tree() as root:
                target = root / name
                calls = []
                def drift(path):
                    raw = actual_read(path)
                    if path == target and not calls:
                        path.write_bytes(raw + b'\n')
                        calls.append(str(path))
                    return raw
                with patch.object(Path, 'read_bytes', drift), self.assertRaises(ValueError):
                    qualifier.admit_original_sources(root, self.records)
                self.assertEqual(calls, [str(target)])
            with self.subTest(cached=name), self.tree() as root:
                qualifier.admit_original_sources(root, self.records)
                target = root / name
                target.write_bytes(target.read_bytes() + b'\n')
                with self.assertRaises(ValueError):
                    qualifier.admit_original_sources(root, self.records)


if __name__ == '__main__':
    unittest.main()
