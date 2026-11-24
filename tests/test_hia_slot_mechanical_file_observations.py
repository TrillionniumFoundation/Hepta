"""Exercise actual C file revalidation after immutable capsule admission."""
from pathlib import Path
import gc
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import weakref

from hepta.native.slot_mechanical_build import supported_profile

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
          "st_mode", "st_uid", "st_nlink")

def observed(path, *, canonical=1):
    raw = path.read_bytes()
    status = path.stat()
    return (str(path), raw, tuple(getattr(status, name) for name in FIELDS),
            2 << 20, canonical, "observed content changed", "observed identity changed")

def load(binary):
    spec = importlib.util.spec_from_file_location("file_probe._hia_slot_mechanical", binary)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

@unittest.skipUnless(supported_profile(), "requires the supported Slot mechanical ABI")
class SlotMechanicalFileObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        output = cls.root / "build"
        subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools/build_hia_slot_mechanical.py"),
                        "--output", str(output)], cwd=ROOT, check=True, capture_output=True)
        build = json.loads((output / "report.json").read_bytes())
        assert build["extension_receipt_verified"]
        receipt = Path(build["identity_path"])
        cls.binary = receipt.parent / json.loads(receipt.read_bytes())["binary"]["name"]
        cls.extension = load(cls.binary)

    def file(self, folder, name="input", content=b"original"):
        path = folder / name
        path.write_bytes(content)
        path.chmod(0o600)
        return path

    def test_fresh_reads_do_not_call_python_io_or_manifest_parsers(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            path = self.file(Path(directory), content=bytes(range(251)) * 1100)
            os.utime(path, ns=(-1, -1))
            captured = self.extension.admission_files((observed(path),))
            def forbidden(*args, **kwargs):
                raise AssertionError("Python runtime admission was used")
            with patch("os.open", forbidden), patch("os.read", forbidden), \
                 patch("os.fstat", forbidden), patch("pathlib.Path.resolve", forbidden), \
                 patch("json.loads", forbidden):
                self.assertIsNone(self.extension.admission_check(captured))
            self.assertFalse(gc.is_tracked(captured))

    def test_content_identity_permissions_and_link_drift_refuse_without_fd_leak(self):
        for mutation in ("same-size", "append", "replace-same-bytes", "chmod", "hardlink", "symlink", "directory", "fifo"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=self.root) as directory:
                folder = Path(directory); path = self.file(folder)
                captured = self.extension.admission_files((observed(path),))
                before = len(os.listdir("/proc/self/fd"))
                if mutation == "same-size": path.write_bytes(b"modified")
                elif mutation == "append": path.write_bytes(b"original-more")
                elif mutation == "replace-same-bytes":
                    replacement = self.file(folder, "replacement")
                    replacement.replace(path)
                elif mutation == "chmod": path.chmod(0o666)
                elif mutation == "hardlink": os.link(path, folder / "second")
                else:
                    path.unlink()
                    if mutation == "symlink": path.symlink_to(self.file(folder, "target"))
                    elif mutation == "directory": path.mkdir()
                    else: os.mkfifo(path, 0o600)
                with self.assertRaises((ValueError, OSError)):
                    self.extension.admission_check(captured)
                self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_canonical_paths_reject_ancestor_alias_but_helper_policy_preserves_it(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            folder = Path(directory); actual = folder / "actual"; actual.mkdir()
            source = self.file(actual)
            alias = folder / "alias"; alias.symlink_to(actual, target_is_directory=True)
            helper = self.extension.admission_files((observed(alias / "input", canonical=0),))
            self.assertIsNone(self.extension.admission_check(helper))
            with self.assertRaises(ValueError):
                self.extension.admission_files((observed(alias / "input", canonical=1),))
            strict = self.extension.admission_files((observed(source),))
            moved = folder / "moved"; actual.rename(moved)
            actual.symlink_to(moved, target_is_directory=True)
            with self.assertRaises(ValueError):
                self.extension.admission_check(strict)

    def test_capsule_does_not_retain_a_module_or_accept_mutable_provider_objects(self):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            row = observed(self.file(Path(directory)))
            module = load(self.binary)
            module.file_observations = module.admission_files((row,))
            ref = weakref.ref(module)
            del module
            gc.collect()
            self.assertIsNone(ref())
            invalid = [(), [row], (row[:1] + (bytearray(row[1]),) + row[2:],),
                       (row[:2] + ((True, *row[2][1:]),) + row[3:],),
                       ((row[0] + "\x00", *row[1:]),)]
            for rows in invalid:
                with self.subTest(rows_type=type(rows).__name__), self.assertRaises((TypeError, ValueError)):
                    self.extension.admission_files(rows)
            with self.assertRaises(ValueError):
                self.extension.admission_check(object())
