import unittest
from hepta.hia_result_cache import CacheError, ResultCache, oracle


class ArithmeticKernel:
    """State-machine-only double; the qualification runner separately requires real HIA."""
    sha256 = "ab" * 32
    def __init__(self): self.calls = 0
    def evaluate(self, n, seed):
        self.calls += 1
        return oracle(n, seed)


class ResultCacheTests(unittest.TestCase):
    def setUp(self):
        self.kernel = ArithmeticKernel()
        self.cache = ResultCache(self.kernel, 515, [3, 79, 251], slots=2)
    def tearDown(self): self.cache.close()
    def test_oracle_handles_u32_wrap_and_nonperiod_tail(self):
        for n in [0, 1, 255, 256, 515, 65521]:
            for seed in [0, 3, 0xffffffff]:
                self.assertEqual(oracle(n, seed), sum(((i+seed)&0xffffffff)&255 for i in range(n)))
    def test_prepare_executes_and_reuse_does_not_execute_again(self):
        self.cache.prepare(0, 1)
        self.assertEqual(self.cache.run(0, 1, "cached"), oracle(515, 3))
        self.assertEqual(self.kernel.calls, 1)
    def test_quota_refuses_before_kernel(self):
        self.cache.prepare(0, 1); self.cache.prepare(1, 1)
        before = self.kernel.calls
        with self.assertRaises(CacheError): self.cache.prepare(2, 1)
        self.assertEqual(self.kernel.calls, before)
    def test_data_mutation_invalidates_and_rejects_stale(self):
        self.cache.prepare(0, 1); self.cache.mutate(0, 2, 4)
        self.assertEqual(self.cache.ready(), [])
        with self.assertRaises(CacheError): self.cache.run(0, 1, "cached")
        with self.assertRaises(CacheError): self.cache.run(0, 2, "cached")
        self.cache.prepare(0, 2)
        self.assertEqual(self.cache.run(0, 2, "cached"), oracle(515, 4))
    def test_generation_retirement_requires_reprepare(self):
        self.cache.prepare(0, 1); self.cache.advance_generation(2)
        self.assertEqual(self.cache.ready(), [])
        with self.assertRaises(CacheError): self.cache.read(0, 1)
        with self.assertRaises(CacheError): self.cache.advance_generation(2)
    def test_corrupt_code_identity_is_refused(self):
        self.cache.prepare(0, 1); self.cache.arena[0] ^= 1
        with self.assertRaises(CacheError): self.cache.read(0, 1)
    def test_corrupt_value_is_refused(self):
        self.cache.prepare(0, 1); self.cache.arena[63] ^= 1
        with self.assertRaises(CacheError): self.cache.read(0, 1)
    def test_exact_integer_admission(self):
        for bad in [True, -1, 3, "0"]:
            with self.assertRaises(CacheError): self.cache.prepare(bad, 1)
        with self.assertRaises(CacheError): self.cache.prepare(0, True)
        with self.assertRaises(CacheError): self.cache.mutate(0, 1, 5)
    def test_retirement_zeroes_slot(self):
        self.cache.prepare(0, 1); self.cache.retire(0, 1)
        self.assertEqual(self.cache.arena, bytearray(128))
    def test_close_is_idempotent_and_refuses_operations(self):
        self.cache.prepare(0, 1); self.cache.close(); self.cache.close()
        self.assertEqual(self.cache.snapshot()["allocated_payload_bytes"], 0)
        with self.assertRaises(CacheError): self.cache.run(0, 1, "direct")

if __name__ == "__main__": unittest.main()
