"""Deterministic differential tests for bytewise VM operations (not native HIA)."""
import ctypes
import random
import sys
import unittest

from hepta.hia_bounded_memory import fill_bytes, move_bytes, _CHUNK


class BoundedByteMemoryTests(unittest.TestCase):
    def test_fill_boundaries_and_unchanged_prefix_suffix(self):
        for extent in (0, 1, 4095, 4096, 4097, 8193, 65536):
            for offset, count in ((0, 0), (extent, 0), (0, extent),
                                  (extent // 2, extent - extent // 2)):
                before = bytearray((i * 19 + 3) % 256 for i in range(extent))
                expected = before.copy()
                expected[offset:offset + count] = bytes((0xAB,)) * count
                fill_bytes(before, offset, count, 0xAB)
                self.assertEqual(before, expected)

    def test_memmove_both_overlap_directions_and_zero(self):
        sizes = (0, 1, 2, 4095, 4096, 4097, 8193, 32771)
        for size in sizes:
            original = bytearray((i * 7 + 31) % 256 for i in range(size))
            candidates = ((0, 0, size), (size, size, 0),
                          (1, 0, max(0, size - 1)) if size else (0, 0, 0),
                          (0, 1, max(0, size - 1)) if size else (0, 0, 0),
                          (size // 2, 0, size - size // 2))
            for dst, src, count in candidates:
                with self.subTest(size=size, dst=dst, src=src, count=count):
                    got, oracle = original.copy(), original.copy()
                    oracle[dst:dst + count] = original[src:src + count]
                    move_bytes(got, dst, src, count)
                    self.assertEqual(got, oracle)

    def test_seeded_reference_differential(self):
        rng = random.Random(20261026)
        for i in range(600):
            size = rng.randrange(0, 17_000)
            original = bytearray(rng.randbytes(size))
            start = rng.randrange(size + 1)
            count = rng.randrange(size - start + 1)
            dst = rng.randrange(size - count + 1)
            got, oracle = original.copy(), original.copy()
            oracle[dst:dst + count] = original[start:start + count]
            move_bytes(got, dst, start, count)
            self.assertEqual(got, oracle, (i, size, dst, start, count))
            fill_offset = rng.randrange(size + 1)
            fill_count = rng.randrange(size - fill_offset + 1)
            value = rng.randrange(256)
            oracle[fill_offset:fill_offset + fill_count] = bytes((value,)) * fill_count
            fill_bytes(got, fill_offset, fill_count, value)
            self.assertEqual(got, oracle, (i, "fill", size))

    def test_bounds_and_types_fail_closed_before_mutation(self):
        for args in ((4, 0), (0, 4), (-1, 1), (1, -1), (True, 1)):
            value = bytearray(b"abc")
            with self.subTest(args=args), self.assertRaises(ValueError):
                fill_bytes(value, *args, 2)
            self.assertEqual(value, bytearray(b"abc"))
        for dest, src, length in ((4, 0, 0), (0, 3, 1), (2, 2, 2)):
            value = bytearray(b"abc")
            with self.subTest(dest=dest, src=src), self.assertRaises(ValueError):
                move_bytes(value, dest, src, length)
            self.assertEqual(value, bytearray(b"abc"))
        self.assertEqual(_CHUNK, 4096)


    def test_actual_linux_libc_memmove_memset_differential(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("independent native libc comparison targets Linux")
        libc = ctypes.CDLL(None)
        memmove = libc.memmove
        memmove.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
        memmove.restype = ctypes.c_void_p
        memset = libc.memset
        memset.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t)
        memset.restype = ctypes.c_void_p
        rng = random.Random(20261026)
        for trial in range(1000):
            size = rng.randrange(1, 32768)
            initial = rng.randbytes(size)
            actual, native = bytearray(initial), bytearray(initial)
            src = rng.randrange(size + 1)
            count = rng.randrange(size - src + 1)
            dst = rng.randrange(size - count + 1)
            move_bytes(actual, dst, src, count)
            ptr = (ctypes.c_ubyte * size).from_buffer(native)
            if count:
                memmove(ctypes.byref(ptr, dst), ctypes.byref(ptr, src), count)
            self.assertEqual(actual, native, ("memmove", trial, dst, src, count))
            offset = rng.randrange(size + 1)
            fill_count = rng.randrange(size - offset + 1)
            value = rng.randrange(256)
            fill_bytes(actual, offset, fill_count, value)
            if fill_count:
                memset(ctypes.byref(ptr, offset), value, fill_count)
            self.assertEqual(actual, native, ("memset", trial, offset, fill_count))


if __name__ == "__main__":
    unittest.main()
