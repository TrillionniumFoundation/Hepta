"""Direct encoder stage: x86-64 atomic bytes and unprivileged native behavior.

This is not a HIA source compiler, a kernel privilege verifier, a QEMU
hardware test, MMIO ordering, or a full SMP memory-model proof.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ctypes
import mmap
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

from hepta.hia_machine_x64 import Code, MachineEncodingError
from hepta.hia_machine_x64_kernel import KernelCode


class AtomicInstructionVectors(unittest.TestCase):
    VECTORS = (
        ("lock_cmpxchg", ("rbx", 32, "rdx"), "f0480fb19320000000",
         r"lock cmpxchg\s+%rdx,0x20\(%rbx\)"),
        ("lock_cmpxchg", ("r12", -16, "r15"), "f04d0fb1bc24f0ffffff",
         r"lock cmpxchg\s+%r15,-0x10\(%r12\)"),
        ("lock_xadd", ("rdi", 8, "rcx"), "f0480fc18f08000000",
         r"lock xadd\s+%rcx,0x8\(%rdi\)"),
        ("lock_xadd", ("rbp", 0, "r8"), "f04c0fc18500000000",
         r"lock xadd\s+%r8,0x0\(%rbp\)"),
        ("mfence", (), "0faef0", r"\bmfence"),
        ("lfence", (), "0faee8", r"\blfence"),
        ("sfence", (), "0faef8", r"\bsfence"),
    )

    def test_exact_bytes_and_independent_objdump(self):
        for method, args, expected, pattern in self.VECTORS:
            with self.subTest(method=method, args=args):
                code = KernelCode()
                getattr(code, method)(*args)
                raw, relocations = code.finalize()
                self.assertEqual(raw.hex(), expected)
                self.assertEqual(relocations, [])
                with tempfile.TemporaryDirectory() as root:
                    binary = Path(root) / "candidate.bin"
                    binary.write_bytes(raw)
                    result = subprocess.run(
                        ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", str(binary)],
                        text=True, capture_output=True, check=True,
                        env={**os.environ, "LC_ALL": "C"},
                    )
                    self.assertRegex(result.stdout, pattern)
                    self.assertNotIn("(bad)", result.stdout)

    def test_register_matrix_displacements(self):
        registers = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15")
        for base in registers:
            for src in registers:
                for name in ("lock_cmpxchg", "lock_xadd"):
                    code = KernelCode()
                    getattr(code, name)(base, -(1 << 31), src)
                    image, relocs = code.finalize()
                    self.assertIn(len(image), (9, 10))
                    self.assertEqual(image[:1], b"\xf0")
                    self.assertEqual(image[-4:], b"\x00\x00\x00\x80")
                    self.assertEqual(relocs, [])

    def test_invalid_operands_preserve_existing_bytes(self):
        for name in ("lock_cmpxchg", "lock_xadd"):
            for argpos in (0, 2):
                for bad in ("eax", "cr3", "rip", "[rax]", None, 0, True):
                    args = ["rdi", 0, "rsi"]
                    args[argpos] = bad
                    code = KernelCode()
                    code.mfence()
                    original = code.finalize()
                    with self.assertRaises(MachineEncodingError):
                        getattr(code, name)(*args)
                    self.assertEqual(code.finalize(), original)
            for bad in (True, None, 1.1, 1 << 31, -(1 << 31) - 1):
                code = KernelCode()
                with self.assertRaises(MachineEncodingError):
                    getattr(code, name)("rdi", bad, "rsi")
                self.assertEqual(code.finalize(), (b"", []))

    def test_ordinary_code_still_excludes_kernel_only_methods(self):
        for name in ("lock_cmpxchg", "lock_xadd", "mfence", "lfence", "sfence"):
            self.assertFalse(hasattr(Code, name))
            self.assertTrue(hasattr(KernelCode, name))


@unittest.skipUnless(platform.system() == "Linux" and
                     platform.machine().lower() in ("x86_64", "amd64"),
                     "native userspace lock oracle only on Linux x86-64")
class AtomicNativeExecution(unittest.TestCase):
    def _execute(self, code, observer):
        raw, relocations = code.finalize()
        self.assertEqual(relocations, [])
        page = mmap.PAGESIZE
        self.assertLess(len(raw), page)
        image = mmap.mmap(-1, page, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        try:
            image[:len(raw)] = raw
            view = ctypes.c_char.from_buffer(image)
            address = ctypes.addressof(view)
            del view
            libc = ctypes.CDLL(None, use_errno=True)
            mprotect = libc.mprotect
            mprotect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
            mprotect.restype = ctypes.c_int
            rc = mprotect(address, page, mmap.PROT_READ | mmap.PROT_EXEC)
            self.assertEqual(rc, 0, f"W^X mapping transition failed, errno={ctypes.get_errno()}")
            observer(address)
        finally:
            image.close()

    def test_cmpxchg_success_and_stale_expected_refusal(self):
        code = KernelCode()
        code.mov_rr("rax", "rsi")
        code.lock_cmpxchg("rdi", 0, "rdx")
        code.ret()
        def observe(address):
            cas = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p,
                                   ctypes.c_uint64, ctypes.c_uint64)(address)
            value = ctypes.c_uint64(0)
            ptr = ctypes.byref(value)
            self.assertEqual(cas(ptr, 0, 7), 0)
            self.assertEqual(value.value, 7)
            self.assertEqual(cas(ptr, 0, 9), 7)
            self.assertEqual(value.value, 7)
            self.assertEqual(cas(ptr, 7, 9), 7)
            self.assertEqual(value.value, 9)
        self._execute(code, observe)

    def test_lock_xadd_four_thread_contention(self):
        code = KernelCode()
        code.lock_xadd("rdi", 0, "rsi")
        code.mov_rr("rax", "rsi")
        code.ret()
        def observe(address):
            xadd = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p,
                                    ctypes.c_uint64)(address)
            value = ctypes.c_uint64(0)
            def worker(_):
                return [xadd(ctypes.byref(value), 1) for i in range(250)]
            with ThreadPoolExecutor(max_workers=4) as workers:
                batches = list(workers.map(worker, range(4)))
            old_values = [n for batch in batches for n in batch]
            self.assertEqual(value.value, 1000)
            self.assertEqual(sorted(old_values), list(range(1000)))
        self._execute(code, observe)


if __name__ == "__main__":
    unittest.main()
