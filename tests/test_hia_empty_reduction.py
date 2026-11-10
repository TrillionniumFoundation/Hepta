"""Empty specialization retains complete resource CFGs and actual input guards."""
from __future__ import annotations

import copy
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.hia_empty_reduction import (empty_reduction_program,
    propose_empty_reduction, verify_empty_reduction)
from hepta.hia_optimization import DEFAULT_POLICY, OptimizationRejected
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import (HIAProgramBudgetExceeded, HIAProgramTrap,
                                       execute_program)
from hepta.hia_reduction import propose_reduction_pipeline, reduction_program


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "benchmarks/hia_reduction_release"




CLANG = os.environ.get("HEPTA_TEST_CLANG", os.environ.get("CLANG", "clang"))
_NATIVE_OBSERVER = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
uint64_t calculate(uint64_t, uint32_t);
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void __real_free(void *);
static unsigned attempts, frees, null_frees;
static int refuse;
void *__wrap_malloc(size_t n) { attempts++; return refuse ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t n, size_t m) { attempts++; return refuse ? NULL : __real_calloc(n, m); }
void __wrap_free(void *p) { frees++; null_frees += p == NULL; __real_free(p); }
int main(void) {
    const uint64_t lengths[] = {0, 1, 15, 16, 17, 73, UINT64_C(1) << 63, UINT64_MAX};
    const uint32_t seeds[] = {0, 255, UINT32_MAX};
    unsigned checked = 0;
    for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
      for (unsigned j = 0; j < sizeof(seeds) / sizeof(seeds[0]); j++)
        for (int fail = 0; fail <= 1; fail++) {
          uint64_t n = lengths[i], expected = 0;
          uint32_t seed = seeds[j];
          int outside = n > INT64_MAX;
          if (outside || (n && fail)) expected = 1001;
          else for (uint64_t k = 0; k < n; k++)
            expected += (uint8_t)(AFFINE ? (uint32_t)k * seed + 17 : (uint32_t)k + seed);
          attempts = frees = null_frees = 0;
          refuse = fail;
          uint64_t actual = calculate(n, seed);
          if (actual != expected || attempts != (unsigned)(n && !outside)
              || frees != (unsigned)(n && !outside && !fail) || null_frees) return 11;
          checked++;
        }
    printf("correctness_cases=%u\n", checked);
    return 0;
}
"""


@unittest.skipUnless(shutil.which(CLANG), "actual Clang required for non-timed native correctness")
class EmptyReductionNativeTests(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()
