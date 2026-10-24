"""ELF identity positive and fail-closed controls; no cross-toolchain required."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from tools.validate_cross import aarch64_elf_identity


class CrossElfIdentityTests(unittest.TestCase):
    @staticmethod
    def make_elf(*, machine=183, elf_type=3, elf_class=2, endian=1,
                 version=1, magic=b"\x7fELF", cut=64):
        data = bytearray(64)
        data[:4] = magic
        data[4:7] = bytes((elf_class, endian, version))
        data[16:18] = elf_type.to_bytes(2, "little")
        data[18:20] = machine.to_bytes(2, "little")
        return bytes(data[:cut])

    def test_exec_and_pie_detected_without_file_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cross-output"
            for kind in (2, 3):
                with self.subTest(kind=kind):
                    path.write_bytes(self.make_elf(elf_type=kind))
                    with mock.patch("subprocess.run", side_effect=AssertionError("file tool invoked")):
                        identity = aarch64_elf_identity(path)
                    self.assertIn("AArch64", identity)
                    self.assertIn("ELF64", identity)

    def test_invalid_binary_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad-elf"
            bad = [b"", b"\x7fELF", self.make_elf(magic=b"JUNK"),
                   self.make_elf(elf_class=1), self.make_elf(endian=2),
                   self.make_elf(version=0), self.make_elf(machine=62),
                   self.make_elf(elf_type=1), self.make_elf(cut=19)]
            for i, content in enumerate(bad):
                with self.subTest(i=i):
                    path.write_bytes(content)
                    with self.assertRaises(RuntimeError):
                        aarch64_elf_identity(path)

    def test_old_external_file_lookup_fails_in_clean_path(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "cross-output"
            path.write_bytes(self.make_elf())
            with mock.patch.dict(os.environ, {"PATH": str(Path(temp) / "missing")}):
                with self.assertRaises(FileNotFoundError):
                    subprocess.run(["file", str(path)], check=True)
                self.assertIn("AArch64", aarch64_elf_identity(path))


if __name__ == "__main__":
    unittest.main()
