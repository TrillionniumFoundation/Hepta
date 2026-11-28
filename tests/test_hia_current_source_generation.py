"""Current physical source custody and retained original-domain controls."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from tools import hia_current_source_generation as generation
from tools import hia_current_store_source_history as current
from tools import hia_frozen_component_sources as frozen

ROOT = Path(__file__).resolve().parents[1]


class CurrentSourceGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        supplied = {n: (ROOT / n).read_bytes() for n in frozen.CURRENT}
        _, history = current.restore(supplied, root=ROOT)
        current.verify_unchanged(history)
        cls.sources = dict(history['captures'])
        cls.prior = dict(history['generation_history'].prior_sources)
        def capture_registry(path):
            name = path.relative_to(ROOT).as_posix()
            raw = path.read_bytes()
            if name in cls.sources and cls.sources[name] != raw:
                raise ValueError('actual registry fixture capture changed')
            cls.sources[name] = raw
            return raw
        current.reviewed_source(ROOT, generation.REGISTRY,
            (ROOT / generation.REGISTRY).read_bytes(), take=capture_registry)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='hia-current-generation-control-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve(strict=True)
        for name, raw in self.sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o644)

    def captured(self):
        return {n: (self.root / n).read_bytes() for n in frozen.CURRENT}

    def test_actual_store_group_keeps_new_physical_and_retained_views_separate(self):
        restored, history = current.restore(self.captured(), root=self.root)
        self.assertEqual({n: current.pin(restored[n]) for n in frozen.CURRENT},
                         frozen.PREDECESSORS)
        self.assertEqual(history['review']['complete_current'][generation.SERVICE],
                         generation.CURRENT[generation.SERVICE])
        self.assertEqual(history['captures'][generation.SERVICE],
                         self.sources[generation.SERVICE])
        prior = history['retained_history']
        self.assertEqual(current.pin(prior['captures'][generation.SERVICE]),
                         generation.PRIOR[generation.SERVICE])
        self.assertFalse(history['review']['physical_capture_rewritten'])
        self.assertFalse(history['review']['prior_projection_is_physical_source'])
        self.assertFalse(history['review']['current_source_generation']
                         ['current_product_execution_qualified'])
        current.verify_unchanged(history)

    def test_actual_registry_reaches_the_unchanged_complete_caller_predecessor(self):
        name = generation.REGISTRY
        original = current.reviewed_source(self.root, name, self.sources[name])
        self.assertEqual(generation.pin(original), {
            'bytes': 23966,
            'sha256': 'ee84fb3f778adcab884906cc7c41c52adecdd1f5ed794da9f4d49a2a1cda5b90'})
        self.assertEqual((self.root / name).read_bytes(), self.sources[name])

    def test_each_current_member_cannot_be_missing_changed_or_partly_reverted(self):
        for name in generation.CHANGED_INPUTS:
            path = self.root / name
            for mode in ('missing', 'changed', 'prior'):
                with self.subTest(path=name, mode=mode):
                    if mode == 'missing':
                        path.unlink()
                    else:
                        path.write_bytes(self.sources[name] + b'\n' if mode == 'changed'
                                         else self.prior[name])
                    try:
                        with self.assertRaises((ValueError, OSError)):
                            generation.prepare(self.root)
                    finally:
                        path.write_bytes(self.sources[name])

    def test_each_new_authority_and_reader_is_an_actual_selected_root_input(self):
        for name in (generation.SELF, generation.FIXTURE, generation.ENGINE,
                     generation.BOOTSTRAP, generation.STORE_READER):
            path = self.root / name
            for missing in (False, True):
                with self.subTest(path=name, missing=missing):
                    if missing:
                        path.unlink()
                    else:
                        path.write_bytes(self.sources[name] + b'\n')
                    try:
                        with self.assertRaises((ValueError, OSError)):
                            generation.prepare(self.root)
                    finally:
                        path.write_bytes(self.sources[name])

    def test_a_projected_service_cannot_be_supplied_as_its_physical_capture(self):
        with self.assertRaises(ValueError):
            generation.prepare(self.root, {generation.SERVICE: self.prior[generation.SERVICE]})
        def forged(path):
            return self.prior[generation.SERVICE] if path == self.root / generation.SERVICE else path.read_bytes()
        with self.assertRaises(ValueError):
            generation.prepare(self.root, take=forged)

    def test_changed_actual_files_and_modes_are_refused_at_terminal(self):
        for name in (*generation.CHANGED_INPUTS, generation.FIXTURE):
            _, history = generation.prepare(self.root)
            path = self.root / name
            with self.subTest(path=name, change='bytes'):
                path.write_bytes(self.sources[name] + b'\n')
                try:
                    with self.assertRaises(ValueError):
                        generation.verify_unchanged(history)
                finally:
                    path.write_bytes(self.sources[name])
            _, history = generation.prepare(self.root)
            with self.subTest(path=name, change='mode'):
                path.chmod(0o600)
                try:
                    with self.assertRaises(ValueError):
                        generation.verify_unchanged(history)
                finally:
                    path.chmod(0o644)

    def test_changed_prior_data_or_report_cannot_relabel_current_sources(self):
        _, history = current.restore(self.captured(), root=self.root)
        saved = deepcopy(history['review'])
        history['review']['complete_current'][generation.SERVICE] = generation.PRIOR[generation.SERVICE]
        with self.assertRaises(ValueError):
            current.verify_unchanged(history)
        history['review'] = saved
        current.verify_unchanged(history)
        inner = history['generation_history']
        inner.prior_sources[generation.SERVICE] += b'\n'
        with self.assertRaises(ValueError):
            generation.verify_unchanged(inner)

    def test_unknown_service_argument_borrows_no_current_authority(self):
        def forbidden(path):
            self.fail('unknown source borrowed physical authority: ' + str(path))
        value, history = current.restore({generation.SERVICE: b'unknown source'},
                                         root=self.root, take=forbidden)
        self.assertEqual(value, {generation.SERVICE: b'unknown source'})
        self.assertIsNone(history)

    def test_the_old_complete_domain_needs_no_new_selected_root_authorities(self):
        for name, raw in self.prior.items():
            (self.root / name).write_bytes(raw)
        for name in (generation.SELF, generation.FIXTURE):
            (self.root / name).unlink()
        restored, history = current.restore(self.captured(), root=self.root)
        self.assertEqual({n: current.pin(restored[n]) for n in frozen.CURRENT},
                         frozen.PREDECESSORS)
        self.assertNotIn('generation_history', history)
        current.verify_unchanged(history)

    def test_explicit_original_test_view_changes_only_the_five_reviewed_files(self):
        stage = self.root.parent / (self.root.name + '-prior')
        self.addCleanup(lambda: __import__('shutil').rmtree(stage, ignore_errors=True))
        with generation.original_source_view(self.root, stage, sorted(self.sources)) as (view, report, history):
            changed = []
            for name, raw in self.sources.items():
                projected = (view / name).read_bytes()
                if projected != raw:
                    changed.append(name)
            self.assertEqual(set(changed), set(generation.PRIOR))
            self.assertEqual(generation.pin((view / generation.STORE_READER).read_bytes()),
                             generation.PRIOR[generation.STORE_READER])
            self.assertFalse(report['physical_capture_rewritten'])
            self.assertFalse(report['prior_projection_is_physical_source'])
            self.assertTrue(report['reader_projected_for_original_source_controls'])
            self.assertEqual((self.root / generation.SERVICE).read_bytes(),
                             self.sources[generation.SERVICE])
        self.assertTrue(report['terminal_reread_identical'])


if __name__ == '__main__':
    unittest.main()
