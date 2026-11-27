"""Physical source and explicit historical-view controls for Page integration."""
from __future__ import annotations

from hashlib import sha256
import importlib.util
import base64
import zlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import hia_artifact_page_source_history as history

ROOT = Path(__file__).resolve().parents[1]


class ArtifactPageSourceHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'selected'
        self.root.mkdir()
        # Only the isolated control root is prepared from the exact published
        # Page domain. The current repository and physical product remain intact.
        corpus_raw = (ROOT / 'tests/fixtures/hia_artifact_page_source_control_corpus_v1.json').read_bytes()
        self.assertEqual(sha256(corpus_raw).hexdigest(), '86e23831df3e86a99881868dac8f4abdf9ecd1b21d76c3e70b63ef29c4fa965b')
        corpus = json.loads(corpus_raw)
        self.assertEqual(set(corpus['files']), set(history.CURRENT))
        for name in (*history.CURRENT, history.SELF, history.FIXTURE):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if name in history.CURRENT:
                data = zlib.decompress(base64.b64decode(
                    corpus['files'][name]['zlib_base64'], validate=True))
                self.assertEqual(history._pin(data), history.CURRENT[name])
            else:
                data = (ROOT / name).read_bytes()
            target.write_bytes(data)
        self.physical = {name: (self.root / name).read_bytes() for name in history.CURRENT}

    def test_complete_three_files_reverse_and_forward_with_physical_capture(self):
        projected, review = history.prepare(self.root, self.physical)
        self.assertEqual(set(projected), set(history.CURRENT))
        for name, actual in self.physical.items():
            self.assertEqual(history._pin(projected[name]), history.PREDECESSORS[name])
            self.assertEqual(review.captures[name], history.CURRENT[name])
            self.assertEqual((self.root / name).read_bytes(), actual)
            self.assertEqual(review.prior_take(self.root / name), projected[name])
        self.assertTrue(review.review['terminal_unchanged'])
        self.assertEqual(set(review.captures), {*history.CURRENT, history.SELF, history.FIXTURE})

    def test_explicit_take_captures_only_actual_bytes(self):
        observed = {}
        def take(path):
            value = Path(path).read_bytes()
            observed[Path(path).relative_to(self.root).as_posix()] = value
            return value
        projected, review = history.prepare(self.root, self.physical, take=take)
        for name in history.CURRENT:
            self.assertEqual(review.prior_take(self.root / name), projected[name])
            self.assertEqual(observed[name], self.physical[name])
        review.verify_unchanged()

    def test_selected_root_cannot_borrow_missing_or_bad_authorities(self):
        for name in (history.SELF, history.FIXTURE):
            path = self.root / name
            original = path.read_bytes()
            for action in ('missing', 'bad'):
                with self.subTest(name=name, action=action):
                    if action == 'missing':
                        path.unlink()
                    else:
                        path.write_bytes(original + b'\n')
                    with self.assertRaises((ValueError, OSError)):
                        history.prepare(self.root, self.physical)
                    path.write_bytes(original)

    def test_all_actual_authorities_and_inputs_are_reread_at_terminal(self):
        for name in (*history.CURRENT, history.SELF, history.FIXTURE):
            with self.subTest(name=name):
                _, review = history.prepare(self.root, self.physical)
                path = self.root / name
                before = path.read_bytes()
                path.write_bytes(before + b'\n')
                with self.assertRaises(ValueError):
                    review.verify_unchanged()
                with self.assertRaises(ValueError):
                    _ = review.review
                path.write_bytes(before)

    def test_late_change_to_a_valid_predecessor_still_refuses(self):
        projected, review = history.prepare(self.root, self.physical)
        name = next(iter(history.CURRENT))
        (self.root / name).write_bytes(projected[name])
        with self.assertRaises(ValueError):
            review.prior_take(self.root / name)
        with self.assertRaises(ValueError):
            review.verify_unchanged()

    def test_supplied_current_bytes_cannot_replace_physical_input(self):
        name = next(iter(history.CURRENT))
        (self.root / name).write_bytes(self.physical[name] + b'\n')
        with self.assertRaises(ValueError):
            history.prepare(self.root, self.physical)

    def test_unknown_whole_source_receives_no_history_exception(self):
        name = next(iter(history.CURRENT))
        unknown = self.physical[name] + b'\n'
        projected, review = history.prepare(self.root, {name: unknown})
        self.assertIsNone(review)
        self.assertEqual(projected[name], unknown)
        self.assertNotEqual(history._pin(unknown), history.PREDECESSORS[name])

    def test_original_domain_does_not_read_new_authority(self):
        projected, _ = history.prepare(self.root, self.physical)
        for name in (history.SELF, history.FIXTURE):
            (self.root / name).unlink()
        def forbidden(_):
            self.fail('old domain borrowed a new history authority')
        original, review = history.prepare(self.root, projected, take=forbidden)
        self.assertEqual(original, projected)
        self.assertIsNone(review)

    def test_loaded_source_cannot_change_before_first_prepare_or_after(self):
        module_path = Path(self.temp.name) / 'executed.py'
        original = (ROOT / history.SELF).read_bytes()
        module_path.write_bytes(original)
        spec = importlib.util.spec_from_file_location('_page_history_actual_snapshot', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        altered = original + b'\n'
        module_path.write_bytes(altered)
        (self.root / history.SELF).write_bytes(altered)
        with self.assertRaises(ValueError):
            module.prepare(self.root, self.physical)
        module_path.write_bytes(original)
        (self.root / history.SELF).write_bytes(original)
        _, admitted = module.prepare(self.root, self.physical)
        module_path.write_bytes(altered)
        (self.root / history.SELF).write_bytes(altered)
        with self.assertRaises(ValueError):
            admitted.verify_unchanged()

    def test_prior_take_rejects_outside_and_noncanonical_paths(self):
        _, review = history.prepare(self.root, self.physical)
        name = next(iter(history.CURRENT))
        for path in (Path(name), self.root / '..' / 'selected' / name,
                     Path(self.temp.name) / 'outside.py'):
            with self.subTest(path=str(path)), self.assertRaises(ValueError):
                review.prior_take(path)


if __name__ == '__main__':
    unittest.main()
