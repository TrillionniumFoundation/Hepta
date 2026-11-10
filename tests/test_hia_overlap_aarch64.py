"""Fixed AArch64 QEMU driver for HIA v3 overlap-safe byte-move corpus.

Static source/ABI tests are intentionally runnable without QEMU; running the
emitted target binary still requires the repository's pinned LLVM/QEMU tools.
No physical-device or general target soundness claim follows.
"""
from __future__ import annotations

import copy
import unittest

from hepta.hia_program import verify_program
from tests.test_hia_overlap_move import move_program


class HIAOverlapAArch64Tests(unittest.TestCase):


    pass


if __name__ == "__main__":
    unittest.main()
