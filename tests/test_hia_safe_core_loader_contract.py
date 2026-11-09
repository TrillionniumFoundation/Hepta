"""Reject loader layouts that a sorted section model would silently normalize.

The independent fixture pins both lookup-table formats before mutation, so a
distribution's default GNU-ld hash style cannot hide the header-order defect.
Mutated images are inspected only; these regressions never load them.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine, compile_program_machine
from hepta.hia_safe_core import validate_safe_core_artifact
from hepta.hia_safe_core_elf import _ELF, bind_final_artifact, SafeCoreELFRejected
from tests.test_hia_program import arithmetic


AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class SafeCoreLoaderContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-loader-contract-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.core = verify_program(arithmetic("int.add.wrap", "u32"))
        cls.image = emit_program_machine(cls.core)
        object_path = cls.root / "fixture.o"
        object_path.write_bytes(cls.image.object_bytes)
        final_path = cls.root / "fixture.so"
        subprocess.run([shutil.which("ld"), "-m", "elf_x86_64", "-shared", "-z", "defs",
                        "-z", "noexecstack", "-z", "relro", "-z", "now", "--build-id=none",
                        "--hash-style=both", str(object_path), "-lc", "-o", str(final_path)],
                       check=True, capture_output=True, timeout=20)
        cls.data = final_path.read_bytes()
        cls.phoff = struct.unpack_from("<Q", cls.data, 32)[0]
        phnum = struct.unpack_from("<H", cls.data, 56)[0]
        cls.headers = [cls.phoff + 56 * i for i in range(phnum)]
        cls.loads = [at for at in cls.headers if struct.unpack_from("<I", cls.data, at)[0] == 1]

    def swapped(self, first, second):
        data = bytearray(self.data)
        data[first:first + 56], data[second:second + 56] = (
            self.data[second:second + 56], self.data[first:first + 56])
        return bytes(data)

    def test_real_direct_linker_pins_both_lookup_tables(self):
        destination = self.root / "direct.so"
        report = compile_program_machine(self.image, program=self.core,
                                         output=destination, linker="ld")
        self.assertIn("--hash-style=both", report["flags"])
        parsed = _ELF(destination.read_bytes(), 3)
        self.assertIn(".hash", parsed.by_name)
        self.assertIn(".gnu.hash", parsed.by_name)
        proof = validate_safe_core_artifact(self.core, self.image.object_bytes, destination.read_bytes())
        self.assertTrue(proof["ok"])

    def test_unsorted_load_headers_reject_before_solver_identity(self):
        self.assertGreaterEqual(len(self.loads), 3)
        # One reversed pair changes the loader's first/last mapping bounds;
        # another is tolerated by some loaders. Both violate the ELF contract.
        for first, second in ((self.loads[0], self.loads[-1]), (self.loads[0], self.loads[1])):
            with self.subTest(first=first, second=second):
                data = self.swapped(first, second)
                with patch("hepta.hia_safe_core._solver_identity",
                           side_effect=AssertionError("out-of-profile loader layout reached the solver")):
                    with self.assertRaisesRegex(SafeCoreELFRejected, "PT_LOAD.*order"):
                        validate_safe_core_artifact(self.core, self.image.object_bytes, data)

    def test_non_load_headers_can_change_order_without_changing_the_image(self):
        others = [at for at in self.headers if struct.unpack_from("<I", self.data, at)[0] != 1]
        self.assertGreaterEqual(len(others), 2)
        changed = self.swapped(others[0], others[1])
        reference = bind_final_artifact(self.image.object_bytes, self.data, "calculate")
        observed = bind_final_artifact(self.image.object_bytes, changed, "calculate")
        self.assertEqual(observed["text"], reference["text"])
        self.assertEqual(observed["entry"], reference["entry"])
        self.assertEqual(observed["calls"], reference["calls"])
        self.assertNotEqual(observed["binding"]["final_image_sha256"],
                            reference["binding"]["final_image_sha256"])


if __name__ == "__main__":
    unittest.main()
