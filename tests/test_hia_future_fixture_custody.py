"""Retained Future campaigns must be reproducible without the old custody root."""
from hashlib import sha256
from pathlib import Path
import shutil
import tempfile
import unittest

from tools import materialize_hia_future_original_fixtures as fixtures
from tools.qualify_hia_future_value_integration import EXPECTED_FIXTURES, EXPECTED_HELPERS


class FutureFixtureCustodyTests(unittest.TestCase):
    def test_materialized_bytes_cover_the_original_qualification_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'originals'
            report = fixtures.materialize(output)
            self.assertEqual(report['fixture_count'], 41)
            self.assertFalse(report['behavior_qualified'])
            self.assertFalse(report['whole_native_delivery_qualified'])
            self.assertEqual(len(EXPECTED_FIXTURES), 33)
            self.assertEqual(len(EXPECTED_HELPERS), 2)
            for name, expected in EXPECTED_FIXTURES.items():
                path = output / 'future-public-inherited-qa/final-v5' / name
                self.assertEqual(sha256(path.read_bytes()).hexdigest(), expected)
                self.assertEqual(path.stat().st_mode & 0o777, 0o400)
            for name, expected in EXPECTED_HELPERS.items():
                self.assertEqual(sha256((output / name).read_bytes()).hexdigest(), expected)
            self.assertEqual((output / fixtures.ORACLE_NAME).read_bytes(),
                             (fixtures.ROOT / 'hepta/hia_background_optimizer.py').read_bytes())
            self.assertEqual(sha256((output / 'future-public-observers-qa/iterator-producer-native-v2/producer.flat').read_bytes()).hexdigest(),
                             '631ac1dcf9e23a1f2290c4fca718641bc65a581ce5b8e4c336c07a31dc1b42c4')

    def test_altered_archive_or_original_oracle_creates_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'fixture-source'
            shutil.copytree(fixtures.FIXTURES, source)
            for name in ('fixtures.tar.gz', 'hia_background_optimizer.py.txt'):
                path = source / name
                original = path.read_bytes()
                path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                output = root / ('output-' + name)
                try:
                    with self.subTest(source=name), self.assertRaises(ValueError):
                        fixtures.materialize(output, source)
                    self.assertFalse(output.exists())
                finally:
                    path.write_bytes(original)

    def test_existing_directory_and_symlink_targets_remain_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            occupied = root / 'occupied'
            occupied.mkdir()
            (occupied / 'sentinel').write_bytes(b'preserve existing content')
            alias = root / 'alias'
            alias.symlink_to(occupied, target_is_directory=True)
            for output in (occupied, alias):
                with self.subTest(output=output.name), self.assertRaises(FileExistsError):
                    fixtures.materialize(output)
            self.assertTrue(alias.is_symlink())
            self.assertEqual(list(occupied.iterdir()), [occupied / 'sentinel'])
            self.assertEqual((occupied / 'sentinel').read_bytes(), b'preserve existing content')


if __name__ == '__main__':
    unittest.main()
