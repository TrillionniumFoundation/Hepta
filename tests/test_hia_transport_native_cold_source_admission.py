"""Independent physical capture controls for native cold caller source admission."""
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests import hia_native_transport_worker_successor as subject
from tools import hia_cold_caller_sources as cold
from tools import hia_frozen_component_sources as history

ROOT = Path(__file__).resolve().parents[1]


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from objects(child)


class NativeColdTransportSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        real_read = Path.read_bytes
        captured = {}

        def capture(path):
            raw = real_read(path)
            try:
                name = path.relative_to(ROOT).as_posix()
            except ValueError:
                return raw
            if name in captured and captured[name] != raw:
                raise AssertionError('test setup observed changing physical source: ' + name)
            captured[name] = raw
            return raw

        cls.originals = {kind: json.loads(real_read(ROOT / item[0]))
                         for kind, item in subject.ORIGINALS.items()}
        cls.reports = {}
        with mock.patch.object(Path, 'read_bytes', capture):
            for kind, original in cls.originals.items():
                cls.reports[kind] = subject.admit_terminal_sources(
                    deepcopy(original), original_kind=kind)
        # Include every explicitly reported physical capture, independently of
        # whether an inner helper captured the original read callable earlier.
        for report in cls.reports.values():
            for entry in objects(report):
                for key in ('actual_captured_files', 'actual_physical_current'):
                    for name, expected in entry.get(key, {}).items():
                        raw = real_read(ROOT / name)
                        if pin(raw) != expected:
                            raise AssertionError('reported capture is not physical: ' + name)
                        if name in captured and captured[name] != raw:
                            raise AssertionError('captured source changed after admission: ' + name)
                        captured[name] = raw
        cls.captured = captured
        cls.relations = cold.read_relations(real_read(ROOT / cold.FIXTURE))

    @contextmanager
    def tree(self):
        with tempfile.TemporaryDirectory(prefix='hia-native-caller-physical-') as directory:
            root = Path(directory)
            for name, raw in self.captured.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            with mock.patch.object(subject, 'ROOT', root):
                yield root

    def admit(self, kind='native'):
        return subject.admit_terminal_sources(deepcopy(self.originals[kind]), original_kind=kind)

    def test_reported_current_sources_and_all_capture_maps_are_physical(self):
        for kind, report in self.reports.items():
            with self.subTest(kind=kind):
                self.assertEqual(len(self.originals[kind]['unchanged_files']),
                                 64 if kind == 'native' else 89)
                self.assertEqual(report['production_composition_source_count'], 13)
                self.assertTrue(report['original_inventories_unchanged'])
                for group in ('source_adjustments', 'shared_adjustments'):
                    for name, entry in report[group].items():
                        raw = (ROOT / name).read_bytes()
                        self.assertEqual({'bytes': entry['current_bytes'],
                                          'sha256': entry['current_sha256']}, pin(raw), name)
                native_count = 0
                for entry in objects(report):
                    for key in ('actual_captured_files', 'actual_physical_current'):
                        for name, expected in entry.get(key, {}).items():
                            self.assertEqual(expected, pin((ROOT / name).read_bytes()), name)
                    if entry.get('schema') == 'hepta.hia.native-cold-caller-source-admission.v1':
                        native_count += 1
                        name = entry['path']
                        self.assertEqual(entry['physical_current'], pin((ROOT / name).read_bytes()))
                        self.assertEqual(entry['predecessor'], self.relations[name]['predecessor'])
                        self.assertNotEqual(entry['physical_current'], entry['predecessor'])
                        self.assertTrue(entry['complete_predecessor_restored'])
                        self.assertTrue(entry['complete_current_replayed'])
                        self.assertTrue(entry['terminal_reread_identical'])
                        self.assertFalse(entry['whole_native_delivery_qualified'])
                self.assertGreater(native_count, 5)

    def test_complete_store_composition_preserves_service_and_tracks_evaluation_layer(self):
        supplied = {name: (ROOT / name).read_bytes() for name in history.CURRENT}
        restored, proof = history.restore(supplied, root=ROOT, take=Path.read_bytes)
        self.assertIsNotNone(proof)
        history.verify_unchanged(proof)
        self.assertEqual({name: pin(restored[name]) for name in history.CURRENT},
                         history.PREDECESSORS)
        service = 'hepta/hia_agent_service.py'
        self.assertEqual(pin(supplied[service]), history.CURRENT[service])
        self.assertNotIn(service, proof['review']['native_cold_caller_sources'])
        self.assertIn(subject.EVALUATION, proof['review']['native_cold_caller_sources'])
        self.assertEqual(proof['captures'][service], supplied[service])
        self.assertEqual(proof['captures'][subject.EVALUATION], supplied[subject.EVALUATION])
        self.assertEqual(proof['review']['actual_physical_current'],
                         {name: pin(raw) for name, raw in supplied.items()})
        self.assertEqual(proof['review']['historical_current_inputs'], history.CURRENT)
        self.assertTrue(proof['review']['terminal_reread_identical'])

    def test_native_inverse_is_bound_to_actual_source_helper_and_complete_predecessor(self):
        names = (subject.TRANSPORT, subject.EVALUATION, subject.JOURNAL_PREPARATION_PATH,
                 subject.QUALIFIER_PATHS[0], 'tests/test_hia_native_build_admission_native.py')
        for name in names:
            with self.subTest(path=name):
                raw = (ROOT / name).read_bytes()
                old, proof = history.cold_caller_source(ROOT, name, raw, take=Path.read_bytes)
                self.assertEqual(pin(old), self.relations[name]['predecessor'])
                self.assertEqual(proof['physical_current'], pin(raw))
                self.assertEqual(proof['actual_captured_files'][name], pin(raw))
                self.assertEqual(proof['helper'], {'path': cold.SOURCE,
                                                  **pin((ROOT / cold.SOURCE).read_bytes())})
                entry = {'path': name, 'current_bytes': len(old),
                         'current_sha256': sha256(old).hexdigest()}
                bound = history.bind_cold_caller_adjustment(entry, raw, proof)
                self.assertEqual(bound['current_sha256'], sha256(raw).hexdigest())
                for update in ({'path': 'unlisted'}, {'current_bytes': len(old) + 1},
                               {'current_sha256': '0' * 64}):
                    with self.assertRaises(ValueError):
                        history.bind_cold_caller_adjustment({**entry, **update}, raw, proof)

    def test_complete_chain_rejects_changes_to_new_sources_and_authorities(self):
        from tests.hia_installed_distribution_history import FIXTURE as installed_fixture
        from tests.hia_component_authoring_history import FIXTURE as component_fixture
        targets = (subject.TRANSPORT, subject.EVALUATION, subject.JOURNAL_PREPARATION_PATH,
                   subject.QUALIFIER_PATHS[0], cold.FIXTURE, cold.SOURCE,
                   history.SOURCE_HISTORY_FIXTURE, installed_fixture, component_fixture)
        for kind in ('native', 'store'):
            for name in targets:
                for position in (0, len(self.captured[name]) // 2, len(self.captured[name]) - 1):
                    with self.subTest(kind=kind, path=name, position=position), self.tree() as root:
                        path = root / name
                        raw = path.read_bytes()
                        changed = bytearray(raw)
                        changed[position] ^= 1
                        path.write_bytes(changed)
                        with self.assertRaises(ValueError):
                            self.admit(kind)

    def test_actual_post_capture_drift_is_refused_and_never_cached(self):
        from tests.hia_component_authoring_history import FIXTURE as component_fixture
        targets = (subject.TRANSPORT, subject.EVALUATION, subject.JOURNAL_PREPARATION_PATH,
                   cold.FIXTURE, cold.SOURCE, history.SOURCE_HISTORY_FIXTURE, component_fixture)
        real_read = Path.read_bytes
        for kind in ('native', 'store'):
            for name in targets:
                with self.subTest(kind=kind, path=name), self.tree() as root:
                    path = root / name
                    original = real_read(path)
                    fired = []

                    def drift(current):
                        raw = real_read(current)
                        if current == path and not fired:
                            fired.append(name)
                            current.write_bytes(raw + b'\n')
                        return raw

                    with mock.patch.object(Path, 'read_bytes', drift):
                        with self.assertRaises(ValueError):
                            self.admit(kind)
                    self.assertEqual(fired, [name])
                    path.write_bytes(original)
                    self.assertEqual(self.admit(kind)['production_composition_source_count'], 13)
                    path.write_bytes(original + b'\n')
                    with self.assertRaises(ValueError):
                        self.admit(kind)

    def test_current_sources_cannot_be_admitted_without_the_new_authority_or_helper(self):
        for name in (cold.FIXTURE, cold.SOURCE, history.SOURCE_HISTORY_FIXTURE):
            with self.subTest(path=name), self.tree() as root:
                (root / name).unlink()
                with self.assertRaises((ValueError, FileNotFoundError)):
                    self.admit()


if __name__ == '__main__':
    unittest.main()
