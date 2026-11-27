"""Independent physical-source controls for historical caller test inputs."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.hia_historical_diagnostic_controls import cold_control_source
from tools import hia_cold_caller_sources as cold

ROOT = Path(__file__).resolve().parents[1]
FIXED = {
    'tests/test_hia_cost_ledger_native.py': {
        'current': {'bytes': 26137, 'sha256': '13b677939273323814166ae31aa154caa47fa8dccf83dfbf1076296ef54ed7c0'},
        'predecessor': {'bytes': 26206, 'sha256': '0acde16af9e90455567aeb10264666f121eed3c95f271e902074c6e9f4a4454e'}},
    'tests/test_hia_native_build_admission_native.py': {
        'current': {'bytes': 47949, 'sha256': '397d3466a30bbe4cfab9c9ce66f1554348b04f631feae1ffd9f78d44c9ae818a'},
        'predecessor': {'bytes': 48018, 'sha256': 'c46859c1a1e7d1a06a8a1c03d6da12adcd6785b24e5657cd3e727dddace8b342'}},
}
AUTHORITIES = (cold.FIXTURE, cold.PREVIOUS_FIXTURE, cold.SOURCE)


def mutate(raw):
    if not raw:
        raise AssertionError('control needs a nonempty full file')
    return bytes([raw[0] ^ 1]) + raw[1:]


class ColdHistoricalDiagnosticSourceTests(unittest.TestCase):
    @contextmanager
    def tree(self, name, *, predecessor=False):
        files = {path: (ROOT / path).read_bytes() for path in (*AUTHORITIES, name)}
        self.assertEqual(cold.pin(files[name]), FIXED[name]['current'])
        if predecessor:
            files[name] = cold.original_caller_source(ROOT, name, files[name])
            self.assertEqual(cold.pin(files[name]), FIXED[name]['predecessor'])
        with tempfile.TemporaryDirectory(prefix='hia-cold-historical-control-') as temporary:
            root = Path(temporary)
            for path, raw in files.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
            yield root, dict(files)

    def test_01_full_current_and_exact_predecessor_are_distinct_physical_inputs(self):
        for name in FIXED:
            for previous in (False, True):
                with self.subTest(name=name, predecessor=previous), self.tree(
                        name, predecessor=previous) as (root, files):
                    physical, adjustments = {}, {}
                    prior = cold_control_source(root, name, files[name], physical, adjustments)
                    self.assertEqual(cold.pin(prior), FIXED[name]['predecessor'])
                    self.assertEqual(physical, files)
                    self.assertEqual((root / name).read_bytes(), files[name])
                    self.assertEqual(set(adjustments), set() if previous else {name})
                    if not previous:
                        proof = adjustments[name]
                        self.assertEqual(proof['physical_current'], FIXED[name]['current'])
                        self.assertEqual(proof['predecessor'], FIXED[name]['predecessor'])
                        self.assertTrue(proof['complete_predecessor_restored'])
                        self.assertTrue(proof['complete_current_replayed'])
                        self.assertTrue(proof['terminal_reread_identical'])
                        self.assertFalse(proof['whole_native_delivery_qualified'])
                        self.assertEqual(proof['actual_captured_files'],
                                         {path: cold.pin(raw) for path, raw in files.items()})

    def test_02_same_length_unknown_current_and_predecessor_refuse(self):
        for name in FIXED:
            for previous in (False, True):
                with self.subTest(name=name, predecessor=previous), self.tree(
                        name, predecessor=previous) as (root, files):
                    changed = mutate(files[name])
                    self.assertEqual(len(changed), len(files[name]))
                    (root / name).write_bytes(changed)
                    with self.assertRaises(ValueError):
                        cold_control_source(root, name, changed, {}, {})
            with self.tree(name) as (root, files):
                with self.assertRaises(ValueError):
                    cold_control_source(root, name, bytearray(files[name]), {}, {})

    def test_03_argument_and_retained_physical_captures_cannot_be_mixed(self):
        for name in FIXED:
            with self.subTest(name=name), self.tree(name) as (root, files):
                previous = cold.original_caller_source(ROOT, name, files[name])
                with self.assertRaises(ValueError):
                    cold_control_source(root, name, previous, {}, {})
                with self.assertRaises(ValueError):
                    cold_control_source(root, name, files[name], {name: previous}, {})
                with self.assertRaises(ValueError):
                    cold_control_source(root, name, files[name], {},
                                        {name: {'physical_current': FIXED[name]['current']}})

    def test_04_missing_and_same_length_changed_authorities_refuse(self):
        name = next(iter(FIXED))
        for authority in AUTHORITIES:
            for fault in ('missing', 'same-length'):
                with self.subTest(authority=authority, fault=fault), self.tree(name) as (root, files):
                    path = root / authority
                    if fault == 'missing':
                        path.unlink()
                    else:
                        path.write_bytes(mutate(files[authority]))
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        cold_control_source(root, name, files[name], {}, {})

    def test_05_each_actual_terminal_reread_detects_physical_drift(self):
        name = next(iter(FIXED))
        original_read = Path.read_bytes
        for selected in (*AUTHORITIES, name):
            with self.subTest(path=selected), self.tree(name) as (root, files):
                target, fired = root / selected, []
                def read_then_change(path):
                    raw = original_read(path)
                    if path == target and not fired:
                        path.write_bytes(mutate(raw))
                        fired.append(str(path))
                    return raw
                with patch.object(Path, 'read_bytes', read_then_change):
                    with self.assertRaises(ValueError):
                        cold_control_source(root, name, files[name], {}, {})
                self.assertEqual(fired, [str(target)])

    def test_06_previous_acceptance_never_caches_an_authority_or_source(self):
        name = next(iter(FIXED))
        for selected in (*AUTHORITIES, name):
            with self.subTest(path=selected), self.tree(name) as (root, files):
                physical, adjustments = {}, {}
                cold_control_source(root, name, files[name], physical, adjustments)
                (root / selected).write_bytes(mutate(files[selected]))
                current = (root / name).read_bytes()
                with self.assertRaises(ValueError):
                    cold_control_source(root, name, current, physical, adjustments)

    def test_07_unlisted_inputs_gain_no_historical_source_exception(self):
        with tempfile.TemporaryDirectory(prefix='hia-cold-unlisted-control-') as temporary:
            raw, physical, adjustments = b'unlisted input', {}, {}
            self.assertEqual(cold_control_source(Path(temporary), 'tests/unlisted.py',
                                                 raw, physical, adjustments), raw)
            self.assertEqual(physical, {})
            self.assertEqual(adjustments, {})


    def test_08_exact_qualifier_dependency_keeps_its_original_capture_boundary(self):
        from tests import hia_native_transport_worker_successor as delivery
        captured = {}
        def capture(name):
            raw = (ROOT / name).read_bytes()
            if name in captured and captured[name] != raw:
                raise AssertionError('current dependency control source drifted')
            captured[name] = raw
            return raw
        actual = (ROOT / delivery.QUALIFIER_DEPENDENCY_PATH).read_bytes()
        current, *extensions = delivery.reviewed_qualifier_dependency(actual, capture)
        self.assertEqual(cold.pin(current), delivery.QUALIFIER_DEPENDENCY_CURRENT)
        self.assertTrue(any(extensions))
        self.assertTrue(captured)
        def no_new_capture(name):
            raise AssertionError('fixed complete dependency does not need a newer source history')
        result = delivery.reviewed_qualifier_dependency(current, no_new_capture)
        self.assertEqual(result, (current, False, False, False, False))
        captured.clear()
        with self.assertRaises(ValueError):
            delivery.reviewed_qualifier_dependency(mutate(current), capture)
        self.assertTrue(captured)
        for name, raw in captured.items():
            self.assertEqual((ROOT / name).read_bytes(), raw)

if __name__ == '__main__':
    unittest.main()
