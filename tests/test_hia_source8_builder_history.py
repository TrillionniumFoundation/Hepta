"""Real physical and explicit prior controls for Source8 builder integration."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from tools import hia_current_source_generation as generation
from tools import hia_frozen_component_sources as frozen
from tools import hia_source8_builder_history as history

ROOT = Path(__file__).resolve().parents[1]


class Source8BuilderHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        actual = (ROOT / history.BUILDER).read_bytes()
        _, leaf = history.prepare(ROOT, {history.BUILDER: actual})
        cls.sources = dict(leaf.captures)
        cls.prior = leaf.prior_sources[history.BUILDER]
        _, complete = generation.prepare(ROOT)
        cls.complete_sources = dict(complete.captures)

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='hia-source8-builder-history-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve(strict=True)
        self.install(self.sources)

    def install(self, sources):
        for name, raw in sources.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o644)

    def prepare(self, *, take=Path.read_bytes):
        return history.prepare(self.root,
            {history.BUILDER: self.sources[history.BUILDER]}, take=take)

    def test_complete_inverse_and_forward_preserve_physical_builder(self):
        projected, saved = self.prepare()
        self.assertEqual(projected, {history.BUILDER: self.prior})
        self.assertEqual(history.pin(self.prior), history.PRIOR)
        self.assertEqual(saved.captures, self.sources)
        self.assertEqual((self.root / history.BUILDER).read_bytes(),
                         self.sources[history.BUILDER])
        relation = json.loads(self.sources[history.FIXTURE])
        self.assertEqual(frozen.history_inverse(self.sources[history.BUILDER],
            relation['files'][history.BUILDER], history.PRIOR), self.prior)
        self.assertEqual(len(self.sources[history.BUILDER]) - len(self.prior), 217)
        review = saved.review()
        self.assertTrue(review['full_inverse_and_forward_replay'])
        self.assertEqual(review['actual_builder'], history.CURRENT)
        self.assertEqual(review['explicit_prior_builder'], history.PRIOR)
        self.assertEqual(review['introduced_inputs'], history.INTRODUCED_INPUTS)
        self.assertFalse(review['physical_capture_rewritten'])
        self.assertFalse(review['current_product_execution_qualified'])

    def test_all_four_new_dependencies_are_required_complete_actual_files(self):
        self.assertEqual(len(history.INTRODUCED_INPUTS), 4)
        for name in history.INTRODUCED_INPUTS:
            path = self.root / name
            for missing in (False, True):
                with self.subTest(path=name, missing=missing):
                    path.unlink() if missing else path.write_bytes(self.sources[name] + b'\n')
                    try:
                        with self.assertRaises((OSError, ValueError)):
                            self.prepare()
                    finally:
                        path.write_bytes(self.sources[name])

    def test_reader_fixture_and_frozen_engine_are_required_actual_inputs(self):
        for name in (history.SELF, history.FIXTURE, history.ENGINE):
            path = self.root / name
            for missing in (False, True):
                with self.subTest(path=name, missing=missing):
                    path.unlink() if missing else path.write_bytes(self.sources[name] + b'\n')
                    try:
                        with self.assertRaises((OSError, ValueError)):
                            self.prepare()
                    finally:
                        path.write_bytes(self.sources[name])

    def test_every_bound_file_and_mode_are_rechecked_at_terminal(self):
        for name in self.sources:
            path = self.root / name
            for change in ('bytes', 'mode'):
                with self.subTest(path=name, change=change):
                    _, saved = self.prepare()
                    if change == 'bytes':
                        path.write_bytes(self.sources[name] + b'\n')
                    else:
                        path.chmod(0o600)
                    try:
                        with self.assertRaises((OSError, ValueError)):
                            history.verify_unchanged(saved)
                    finally:
                        path.write_bytes(self.sources[name])
                        path.chmod(0o644)

    def test_legal_previous_builder_cannot_replace_physical_current_late(self):
        _, saved = self.prepare()
        (self.root / history.BUILDER).write_bytes(self.prior)
        with self.assertRaises(ValueError):
            saved.prior_take(self.root / history.BUILDER)
        with self.assertRaises(ValueError):
            history.verify_unchanged(saved)

    def test_projected_bytes_cannot_be_passed_as_physical_input(self):
        with self.assertRaises(ValueError):
            history.prepare(self.root, {history.BUILDER: self.prior})
        def forged(path):
            return self.prior if path == self.root / history.BUILDER else path.read_bytes()
        with self.assertRaises(ValueError):
            self.prepare(take=forged)
        (self.root / history.BUILDER).write_bytes(self.prior)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_lazy_prior_read_rechecks_all_four_physical_dependencies(self):
        _, saved = self.prepare()
        self.assertEqual(saved.prior_take(self.root / history.BUILDER), self.prior)
        for name in history.INTRODUCED_INPUTS:
            path = self.root / name
            path.write_bytes(self.sources[name] + b'\n')
            try:
                with self.subTest(path=name), self.assertRaises(ValueError):
                    saved.prior_take(self.root / history.BUILDER)
            finally:
                path.write_bytes(self.sources[name])

    def test_mutating_prior_or_capture_cannot_relabel_source(self):
        _, saved = self.prepare()
        saved.prior_sources[history.BUILDER] += b'\n'
        with self.assertRaises(ValueError):
            history.verify_unchanged(saved)
        _, saved = self.prepare()
        saved.captures[history.BUILDER] = self.prior
        with self.assertRaises(ValueError):
            history.verify_unchanged(saved)

    def test_import_snapshot_rejects_disk_change_before_first_prepare(self):
        path = self.root / history.SELF
        spec = importlib.util.spec_from_file_location('_hia_source8_builder_control', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        path.write_bytes(self.sources[history.SELF] + b'\n')
        with self.assertRaises(ValueError):
            module.prepare(self.root, {history.BUILDER: self.sources[history.BUILDER]})
        path.write_bytes(self.sources[history.SELF])
        _, saved = module.prepare(self.root, {history.BUILDER: self.sources[history.BUILDER]})
        module.verify_unchanged(saved)
        path.write_bytes(self.sources[history.SELF] + b'\n')
        with self.assertRaises(ValueError):
            module.verify_unchanged(saved)

    def test_current_generation_uses_explicit_two_step_builder_history(self):
        self.install(self.complete_sources)
        projected, saved = generation.maybe_prepare(
            self.root, {history.BUILDER: self.sources[history.BUILDER]})
        self.assertEqual(generation.pin(projected[history.BUILDER]),
                         generation.PRIOR[history.BUILDER])
        self.assertEqual(saved.captures[history.BUILDER],
                         self.sources[history.BUILDER])
        self.assertEqual(saved.source8_builder_history.prior_take(self.root / history.BUILDER),
                         self.prior)
        self.assertEqual(saved.review()['source8_builder_history']['actual_builder'],
                         history.CURRENT)
        for name in history.INTRODUCED_INPUTS:
            self.assertEqual(saved.captures[name], self.sources[name])
        generation.verify_unchanged(saved)

    def test_current_generation_refuses_each_new_dependency_missing_or_late(self):
        self.install(self.complete_sources)
        for name in history.INTRODUCED_INPUTS:
            path = self.root / name
            with self.subTest(path=name):
                _, saved = generation.prepare(self.root)
                path.unlink()
                try:
                    with self.assertRaises((OSError, ValueError)):
                        generation.prepare(self.root)
                    with self.assertRaises((OSError, ValueError)):
                        generation.verify_unchanged(saved)
                finally:
                    path.write_bytes(self.sources[name])

    def test_existing_current_builder_does_not_need_new_history_authorities(self):
        self.install(self.complete_sources)
        (self.root / history.BUILDER).write_bytes(self.prior)
        for name in (history.SELF, history.FIXTURE):
            (self.root / name).unlink()
        projected, saved = generation.prepare(
            self.root, {history.BUILDER: self.prior})
        self.assertEqual(generation.pin(projected[history.BUILDER]),
                         generation.PRIOR[history.BUILDER])
        self.assertIsNone(saved.source8_builder_history)
        self.assertNotIn(history.SELF, saved.captures)
        self.assertNotIn(history.FIXTURE, saved.captures)
        generation.verify_unchanged(saved)

    def test_original_fixed_authorities_and_current_ten_file_are_unchanged(self):
        self.assertEqual(generation.CURRENT[history.BUILDER], history.PRIOR)
        self.assertEqual(generation.FIXTURE_SHA256,
            '0f425262209c2408a387c00bae2d6698cbfaa614e90c9ad4401e5857cf743467')
        self.assertEqual(sha256((ROOT / generation.FIXTURE).read_bytes()).hexdigest(),
                         generation.FIXTURE_SHA256)
        self.assertEqual(sha256((ROOT / 'tests/test_hia_current_source_generation.py')
            .read_bytes()).hexdigest(),
            '7e20ebeb2969bc434646bcab8e0084a041a732c61fc9ad2dedc72975b69965ad')
        self.assertEqual(sha256((ROOT / history.ENGINE).read_bytes()).hexdigest(),
                         history.ENGINE_SHA256)


if __name__ == '__main__':
    unittest.main()
