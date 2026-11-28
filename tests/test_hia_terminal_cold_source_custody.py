"""Additional source custody controls for the five terminal caller admissions.

The original 140 caller controls remain separate and unchanged. These tests
exercise complete current sources in an isolated root and refuse missing or
changed migration authorities and partially reverted production compositions.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from importlib import import_module
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tests import hia_caller_terminal_admission as terminal
from tests import hia_component_authoring_history as component
from tests import hia_installed_distribution_history as installed
from tests import hia_native_transport_worker_successor as delivery
from tools import hia_cold_caller_sources as cold
from tools import hia_frozen_component_sources as history

ROOT = Path(__file__).resolve().parents[1]
GATES = (
    ('build', 'tools.qualify_hia_native_build_admission_callers', 17),
    ('emission', 'tools.qualify_hia_emission_callers', 17),
    ('store', 'tools.qualify_hia_store_artifact_profile_callers', 18),
    ('read', 'tools.qualify_hia_service_read_callers', 17),
    ('inspection', 'tools.qualify_hia_service_inspection_callers', 17),
)


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


class TerminalColdSourceCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {}
        cls.physical = {}
        for kind, module, count in GATES:
            qualifier = import_module(module)
            inventory = json.loads((ROOT / qualifier.FIXTURE_NAME).read_bytes())
            argument = ({row['path']: row['sha256'] for row in inventory['modules'].values()}
                        if kind == 'build' else inventory)
            proof = []
            qualifier.admit_original_sources(ROOT, argument, terminal_evidence=proof)
            if len(proof) != 1 or proof[0]['original_source_count'] != count:
                raise AssertionError('complete current terminal caller domain differs')
            sources = {name: (ROOT / name).read_bytes()
                       for name in proof[0]['captured_files']}
            if {name: pin(raw) for name, raw in sources.items()} != proof[0]['captured_files']:
                raise AssertionError('terminal baseline lost physical source custody')
            cls.cases[kind] = (qualifier, argument, proof[0], sources)
            for name, raw in sources.items():
                if name in cls.physical and cls.physical[name] != raw:
                    raise AssertionError('terminal baselines observed different source bytes')
                cls.physical[name] = raw
        relation = json.loads(cls.physical[history.SOURCE_HISTORY_FIXTURE])
        cls.production_predecessors = {
            name: history.history_inverse(cls.physical[name], relation['files'][name],
                                          history.PREDECESSORS[name])
            for name in history.PRODUCTION_PATHS
        }

    @classmethod
    def tearDownClass(cls):
        if cls.physical != {name: (ROOT / name).read_bytes() for name in cls.physical}:
            raise AssertionError('terminal custody controls changed actual input bytes')

    def setUp(self):
        temporary = TemporaryDirectory(prefix='hia-terminal-cold-custody-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.sequence = 0

    def stage(self, kind):
        self.sequence += 1
        root = self.base / str(self.sequence)
        root.mkdir()
        for name, raw in self.cases[kind][3].items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        return root

    def admit(self, root, kind):
        qualifier, argument, _, _ = self.cases[kind]
        proof = []
        adjustments = qualifier.admit_original_sources(
            root, deepcopy(argument), terminal_evidence=proof)
        self.assertEqual(len(proof), 1)
        return adjustments, proof[0]

    def test_current_physical_capture_copy_has_no_foreign_root_dependency(self):
        original_read = Path.read_bytes
        permitted_code = {Path(cold.__file__)}
        for kind, _, count in GATES:
            with self.subTest(gate=kind):
                root = self.stage(kind)
                foreign = self.base / 'absent-global-root'
                def no_foreign_read(path):
                    if path.is_relative_to(ROOT) and path not in permitted_code:
                        raise AssertionError('caller read outside its selected source root: ' + str(path))
                    return original_read(path)
                with patch.object(delivery, 'ROOT', foreign), \
                     patch.object(installed, 'ROOT', foreign), \
                     patch.object(component, 'ROOT', foreign), \
                     patch.object(Path, 'read_bytes', no_foreign_read):
                    _, proof = self.admit(root, kind)
                self.assertEqual(proof, self.cases[kind][2])
                self.assertEqual(proof['original_source_count'], count)
                self.assertEqual(proof['captured_files'],
                                 {name: pin(raw) for name, raw in self.cases[kind][3].items()})
                self.assertEqual(proof['production_source_exceptions'], [])
                self.assertTrue(proof['original_inventory_bytes_unchanged'])
                self.assertTrue(proof['terminal_reread_identical'])
                self.assertIn(terminal.TRANSPORT, proof['reviewed_native_cold_caller_sources'])
                self.assertIn(terminal.EVALUATION, proof['reviewed_native_cold_caller_sources'])
                for source_proof in proof['reviewed_native_cold_caller_sources'].values():
                    self.assertFalse(source_proof['whole_native_delivery_qualified'])

    def test_current_sources_cannot_borrow_missing_history_from_the_import_root(self):
        required = (cold.FIXTURE, cold.PREVIOUS_FIXTURE, cold.SOURCE,
                    installed.FIXTURE, component.FIXTURE)
        for kind, _, _ in GATES:
            root = self.stage(kind)
            for name in required:
                with self.subTest(gate=kind, missing=name):
                    path = root / name
                    raw = path.read_bytes()
                    path.unlink()
                    try:
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            self.admit(root, kind)
                    finally:
                        path.write_bytes(raw)

    def test_every_current_capture_refuses_changed_bytes(self):
        for kind, _, _ in GATES:
            root = self.stage(kind)
            for name, raw in self.cases[kind][3].items():
                with self.subTest(gate=kind, path=name):
                    path = root / name
                    path.write_bytes(raw + b'\n')
                    try:
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            self.admit(root, kind)
                    finally:
                        path.write_bytes(raw)

    def test_exact_prior_production_files_cannot_mix_with_current_evaluation(self):
        groups = [(name,) for name in history.PRODUCTION_PATHS]
        groups.append(tuple(history.PRODUCTION_PATHS))
        for kind, _, _ in GATES:
            root = self.stage(kind)
            for names in groups:
                with self.subTest(gate=kind, reverted=names):
                    for name in names:
                        (root / name).write_bytes(self.production_predecessors[name])
                    try:
                        with self.assertRaises(ValueError):
                            self.admit(root, kind)
                    finally:
                        for name in names:
                            (root / name).write_bytes(self.cases[kind][3][name])

    def test_each_current_capture_is_reread_before_terminal_proof(self):
        actual_read = Path.read_bytes
        for kind, _, _ in GATES:
            root = self.stage(kind)
            for name in self.cases[kind][3]:
                with self.subTest(gate=kind, path=name):
                    target = root / name
                    counts = []
                    def drift(path):
                        raw = actual_read(path)
                        if path == target:
                            counts.append(True)
                            if len(counts) > 1:
                                return raw + b'\n'
                        return raw
                    with patch.object(Path, 'read_bytes', drift), self.assertRaises(ValueError):
                        self.admit(root, kind)
                    self.assertGreaterEqual(len(counts), 2)


if __name__ == '__main__':
    unittest.main()
