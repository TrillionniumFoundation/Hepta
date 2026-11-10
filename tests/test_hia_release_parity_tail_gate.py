"""Independent finite cohort regressions for the HIA release p99 acceptance gate.

These use synthetic batch timing samples only. They do not measure native speed,
qualify compiler refinement, or establish parity with optimized Rust.
"""
from __future__ import annotations

import unittest



class ReleaseParityTailGateTests(unittest.TestCase):
    @staticmethod
    def cohort(*, slow_phase=None, last_sample_ns=100):
        # Twenty samples make p95 the 19th and p99 the 20th observation.
        # A single HIA tail spike thus cannot be hidden inside median/p95.
        spec = {
            "backends": ["c", "cpp", "rust", "hia"],
            "training_sizes": [64], "training_seeds": [11],
            "holdout_sizes": [257], "holdout_seeds": [13],
            "samples": 20,
            "performance_gate": {
                "hia_median_ratio_maximum": 1.1,
                "hia_tail_ratio_maximum": 1.2,
                "all_baselines_and_sizes_required": True,
            },
        }
        rows = []
        for phase, n, seed in (("training", 64, 11), ("holdout", 257, 13)):
            for backend in spec["backends"]:
                times = [100] * 20
                if backend == "hia" and phase == slow_phase:
                    times[-1] = last_sample_ns
                rows.append({
                    "phase": phase, "backend": backend,
                    "n": n, "seed": seed, "times_ns": times,
                })
        return rows, spec







if __name__ == "__main__":
    unittest.main()
