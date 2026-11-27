"""Host x86-64 ISA runtime oracle for ONLY unprivileged locked CAS bytes.

No privileged instruction is run on the host. The staged encoder makes the
CAS bytes; this test observes real RAM and the ZF-derived return value. The
QEMU hardware suite separately qualifies the privileged CR3/PTE sequence.
"""
from __future__ import annotations

import ctypes
import mmap
import platform
import sys
import unittest

from hepta.hia_machine_x64 import PrivilegedCode


@unittest.skipUnless(sys.platform == "linux" and
                     platform.machine().lower() in {"x86_64", "amd64"},
                     "isolated x86-64 Linux runner required")
class HostLockedCasSemantics(unittest.TestCase):
    @staticmethod
    def run_cas(initial: int, expected: int, replacement: int) -> tuple[int, int]:
        emitter = PrivilegedCode()
        emitter.mov_imm("rax", expected)
        emitter.mov_imm("rdx", replacement)
        # SysV rdi holds the address of the 8-byte word supplied by ctypes.
        emitter.lock_cmpxchg64("rdi", "rdx")
        # MOV does not alter ZF, so SETE captures success after the CAS.
        emitter.setcc("e", "rax")
        emitter.ret()
        code, relocations = emitter.finalize()
        assert not relocations
        region = mmap.mmap(-1, mmap.PAGESIZE,
                           flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                           prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        word = ctypes.c_uint64(initial)
        try:
            region.write(code)
            address = ctypes.addressof(ctypes.c_ubyte.from_buffer(region))
            function = ctypes.CFUNCTYPE(ctypes.c_uint64,
                                       ctypes.POINTER(ctypes.c_uint64))(address)
            result = function(ctypes.byref(word))
            del function
            return result, word.value
        finally:
            region.close()

    def test_exact_old_updates_once_and_reports_success(self):
        for old, new in ((0x400063, 0x400062),
                         (0x1000000000000001, 0x1000000000000000)):
            with self.subTest(old=old):
                self.assertEqual(self.run_cas(old, old, new), (1, new))

    def test_concurrent_old_mismatch_preserves_observed_memory(self):
        # Deterministically preempt the expected value with a different word.
        # This checks actual CPU CAS failure, not just the staging precheck.
        for observed in (0x400023, 0x0, 0xffffffffffffffff):
            with self.subTest(observed=observed):
                self.assertEqual(
                    self.run_cas(observed, 0x400063, 0x400062),
                    (0, observed),
                )


if __name__ == "__main__":
    unittest.main()
