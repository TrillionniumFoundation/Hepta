"""Extra guards for bounded O(log N) fill and nonoverlapping direct byte moves.

These qualify the Python VM helper, not the full HIA compiler or native LLVM.
"""
from __future__ import annotations

import platform
import random
import tracemalloc
import unittest

from hepta.hia_bounded_memory import fill_bytes, move_bytes


class FastMemoryHelperTests(unittest.TestCase):
    def test_doubling_fill_matches_reference_preserving_surroundings(self):
        rng = random.Random(20261026)
        for size in (0, 1, 4095, 4096, 4097, 8193, 65536, 2**20):
            for begin in (0, size // 2, size):
                remaining = size - begin
                for count in (0, remaining // 2, remaining):
                    payload = bytearray(rng.randbytes(size))
                    expected = payload.copy()
                    value = rng.randrange(256)
                    expected[begin:begin + count] = bytes((value,)) * count
                    fill_bytes(payload, begin, count, value)
                    self.assertEqual(payload, expected, (size, begin, count))

    def test_nonoverlap_move_is_exact_with_zero_and_adjacent_ranges(self):
        rng = random.Random(20261027)
        for length in (0, 1, 2, 4096, 65536, 2**20):
            data = bytearray(rng.randbytes(length))
            for source, target, count in (
                (0, length // 2, length // 2),
                (length // 2, 0, length - length // 2),
                (0, 0, 0),
                (length, length, 0),
            ):
                if max(source, target) + count > length:
                    continue
                if count and not (target + count <= source or source + count <= target):
                    continue
                expected, current = data.copy(), data.copy()
                expected[target:target + count] = data[source:source + count]
                move_bytes(current, target, source, count)
                self.assertEqual(current, expected, (length, source, target, count))

    @unittest.skipUnless(platform.python_implementation() == 'CPython', 'CPython tracemalloc profile')
    def test_large_fill_and_nonoverlap_move_use_bounded_host_scratch(self):
        size = 4 * 1024 * 1024
        for kind in ('fill', 'move'):
            data = bytearray(size)
            tracemalloc.start()
            try:
                if kind == 'fill':
                    fill_bytes(data, 0, size, 0xA7)
                    self.assertEqual(data[0], 0xA7)
                    self.assertEqual(data[-1], 0xA7)
                else:
                    data[:size // 2] = b'Z' * (size // 2)
                    tracemalloc.reset_peak()
                    move_bytes(data, size // 2, 0, size // 2)
                    self.assertEqual(data[-1], ord('Z'))
                _, peak = tracemalloc.get_traced_memory()
                # Bound refers only to helper temporaries; the owned 4MiB input
                # is allocated before tracing. This does not bound process RSS.
                self.assertLess(peak, 64 * 1024, (kind, peak))
            finally:
                tracemalloc.stop()

    def test_rejected_values_never_partially_mutate(self):
        for method, args in (
            (fill_bytes, (0, 5, 1)),
            (fill_bytes, (0, 2, True)),
            (fill_bytes, (0, -1, 3)),
            (move_bytes, (3, 0, 1)),
            (move_bytes, (1, 0, True)),
            (move_bytes, (-1, 0, 2)),
        ):
            data = bytearray(b'abc')
            with self.assertRaises(ValueError):
                method(data, *args)
            self.assertEqual(data, bytearray(b'abc'))


if __name__ == '__main__':
    unittest.main()
