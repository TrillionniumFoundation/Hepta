"""Exercise the native test assertion with an authored report, not a native run.

The count is taken from the actual scalar input inventory. Empty positive rows
and the pass label below are fixtures solely for reaching the stale assertion.
They are not retained native qualification evidence.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tests.test_hia_selfhost_language_coverage import (
    SelfhostLanguageNativeTests, scalar_cases,
)

case = SelfhostLanguageNativeTests("test_every_positive_program_runs_under_both_hia_compilers")
case.report = {"status": "SELFHOST_LANGUAGE_COVERAGE_PASS", "checks": {}, "positive": [],
               "reference": {"scalar_cases": len(scalar_cases())}}
print("Assertion-only authored report; native qualification performed: false", flush=True)
print("Actual scalar inventory:", len(scalar_cases()), flush=True)
case.test_every_positive_program_runs_under_both_hia_compilers()
print("Native test count assertion agrees with actual scalar inventory")
