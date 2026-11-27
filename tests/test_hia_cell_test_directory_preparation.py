"""Real filesystem controls for the explicit original Cell test preparation."""
import os
from pathlib import Path
import tempfile
import unittest

from tests.hia_cell_test_directory_preparation import _PreparedTempfile


class CellTestDirectoryPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cell-owned-preparation-")
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_original_call_uses_private_physical_directory(self):
        original = tempfile.TemporaryDirectory
        prepared = _PreparedTempfile(self.root)
        with prepared.TemporaryDirectory(prefix="hia-cell-native-", dir="/dev/shm") as name:
            p = Path(name)
            self.assertEqual(p.parent, self.root)
            (p / "actual").write_bytes(b"physical")
            self.assertEqual((p / "actual").read_bytes(), b"physical")
            self.assertEqual(p.stat().st_mode & 0o777, 0o700)
            self.assertEqual(prepared.calls[0]["requested"]["dir"], "/dev/shm")
        self.assertIs(tempfile.TemporaryDirectory, original)
        self.assertEqual(len(prepared.calls), 1)
        prepared.verify()

    def test_other_call_shapes_cannot_be_redirected(self):
        prepared = _PreparedTempfile(self.root)
        for kwargs in ({"prefix": "other", "dir": "/dev/shm"},
                       {"prefix": "hia-cell-native-", "dir": "/tmp"},
                       {"prefix": "hia-cell-native-", "dir": "/dev/shm", "suffix": "x"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                prepared.TemporaryDirectory(**kwargs)
        with self.assertRaises(ValueError):
            prepared.TemporaryDirectory("x", prefix="hia-cell-native-", dir="/dev/shm")
        self.assertEqual(prepared.calls, [])

    def test_symlinked_directory_is_rejected(self):
        link = self.root / "link"
        target = self.root / "target"
        target.mkdir(mode=0o700)
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ValueError):
            _PreparedTempfile(link)

    def test_existing_wide_directory_is_refused_without_repair(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            _PreparedTempfile(self.root)
        self.assertEqual(self.root.stat().st_mode & 0o777, 0o755)

    def test_late_directory_mode_change_is_refused(self):
        prepared = _PreparedTempfile(self.root)
        self.root.chmod(0o750)
        with self.assertRaises(ValueError):
            prepared.TemporaryDirectory(prefix="hia-cell-native-", dir="/dev/shm")
        self.assertEqual(prepared.calls, [])

    def test_replaced_directory_identity_is_refused(self):
        prepared = _PreparedTempfile(self.root)
        prior = self.root.with_name(self.root.name + "-prior")
        self.root.rename(prior)
        self.root.mkdir(mode=0o700)
        try:
            with self.assertRaises(ValueError):
                prepared.verify()
        finally:
            self.root.rmdir()
            prior.rename(self.root)


if __name__ == "__main__":
    unittest.main()
