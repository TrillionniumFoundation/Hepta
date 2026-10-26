"""Fixed AArch64 QEMU driver for HIA v3 overlap-safe byte-move corpus.

Static source/ABI tests are intentionally runnable without QEMU; running the
emitted target binary still requires the repository's pinned LLVM/QEMU tools.
No physical-device or general target soundness claim follows.
"""
from __future__ import annotations

import copy
import unittest

from hepta.hia_program import verify_program
from hepta.hia_program_aarch64 import (
    HIAProgramAArch64Rejected, _OVERLAP_CASES, _runtime_source)
from tests.test_hia_overlap_move import move_program


class HIAOverlapAArch64Tests(unittest.TestCase):
    def test_exact_core_to_real_reviewed_runtime_driver_source(self):
        checked = verify_program(move_program())
        source, required = _runtime_source(checked.as_dict(), "overlap_move")
        self.assertEqual(required, {"move_bytes"})
        self.assertEqual(len(_OVERLAP_CASES), 8)
        self.assertEqual(source.count("if (move_bytes("), len(_OVERLAP_CASES))
        self.assertIn("extern hepta_u8 move_bytes(", source)
        self.assertIn("successful_allocations != 8", source)
        self.assertIn("releases != 8", source)
        self.assertIn("outstanding != 0", source)
        self.assertIn("denied_allocations != 0", source)
        self.assertIn("static int smoke(void)", source)
        self.assertIn("void _start(void)", source)
        self.assertIn("if (!memory_primitives_ok())", source)

    def test_wrong_source_function_or_abi_rejected(self):
        good = move_program()
        missing = copy.deepcopy(good)
        missing["functions"][0]["name"] = "not_move_bytes"
        invalid = copy.deepcopy(good)
        invalid["functions"][0]["params"][0]["type"] = "u8"
        for payload in (missing, invalid):
            with self.subTest(kind=payload["functions"][0]["name"]):
                with self.assertRaisesRegex(HIAProgramAArch64Rejected, "E_HIA_PROGRAM_AARCH64"):
                    _runtime_source(payload, "overlap_move")

    def test_unknown_mode_never_silently_becomes_matrix(self):
        doc = verify_program(move_program()).as_dict()
        for mode in ("legacy", "overlap_bounds_trap", "", None, 0):
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(HIAProgramAArch64Rejected, "E_HIA_PROGRAM_AARCH64"):
                    _runtime_source(doc, mode)


if __name__ == "__main__":
    unittest.main()
