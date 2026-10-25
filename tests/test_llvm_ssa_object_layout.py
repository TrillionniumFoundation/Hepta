"""Real Clang object-format boundary tests; not target ABI or Hepta proof."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.llvm_ssa_target import _TARGETS, _qualified_header

_FIXTURE = """define i32 @hepta_target_probe(i32 %x) {
entry:
  %value = add i32 %x, 1
  ret i32 %value
}
"""


@unittest.skipUnless(shutil.which("clang"), "Clang IR cross-target backend is required")
class NativeObjectLayoutTests(unittest.TestCase):
    def test_real_five_target_objects_and_25_corruptions(self):
        positive = 0
        negative = 0
        with tempfile.TemporaryDirectory(prefix="hepta-object-structure-") as folder:
            root = Path(folder)
            source = root / "fixture.ll"
            source.write_text(_FIXTURE, encoding="utf-8")
            for target, (fmt, machine) in sorted(_TARGETS.items()):
                with self.subTest(target=target):
                    artifact = root / (target + ".o")
                    built = subprocess.run(
                        ["clang", "--target=" + target, "-x", "ir", "-O3",
                         "-c", str(source), "-o", str(artifact)],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(built.returncode, 0, built.stderr)
                    original = artifact.read_bytes()
                    self.assertTrue(_qualified_header(original, target))
                    positive += 1
                    corrupted = [original[:40]]
                    if fmt == "ELF64":
                        table = int.from_bytes(original[40:48], "little")
                        size = int.from_bytes(original[58:60], "little")
                        count = int.from_bytes(original[60:62], "little")
                        corrupted.append(original[:table + size * count - 1])
                        modified = bytearray(original)
                        modified[40:48] = (len(original) + 200).to_bytes(8, "little")
                        corrupted.append(bytes(modified))
                        modified = bytearray(original)
                        modified[58:60] = (2).to_bytes(2, "little")
                        corrupted.append(bytes(modified))
                        modified = bytearray(original)
                        modified[60:62] = (4000).to_bytes(2, "little")
                        corrupted.append(bytes(modified))
                    elif fmt == "COFF":
                        count = int.from_bytes(original[2:4], "little")
                        corrupted.append(original[:20 + 40 * count - 1])
                        modified = bytearray(original)
                        modified[2:4] = (2000).to_bytes(2, "little")
                        corrupted.append(bytes(modified))
                        modified = bytearray(original)
                        modified[8:12] = (len(original) + 10).to_bytes(4, "little")
                        corrupted.append(bytes(modified))
                        corrupted.append(b"\x64\x86\x01\x00" + b"\x00" * 16)
                    else:
                        commands = int.from_bytes(original[20:24], "little")
                        corrupted.append(original[:32 + commands - 1])
                        modified = bytearray(original)
                        modified[20:24] = (len(original) + 1).to_bytes(4, "little")
                        corrupted.append(bytes(modified))
                        modified = bytearray(original)
                        modified[36:40] = (4).to_bytes(4, "little")
                        corrupted.append(bytes(modified))
                        modified = bytearray(original)
                        modified[16:20] = (0).to_bytes(4, "little")
                        corrupted.append(bytes(modified))
                    for bad in corrupted:
                        self.assertFalse(_qualified_header(bad, target),
                                         (target, fmt, len(bad)))
                        negative += 1
        self.assertEqual(positive, 5)
        self.assertEqual(negative, 25)


if __name__ == "__main__":
    unittest.main()
