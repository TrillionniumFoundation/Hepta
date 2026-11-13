"""Run declared regression tests with complete, nonempty and anomaly-free gates.

This is a hosted test supervisor, not native execution evidence by itself.
The test modules and their existing native/cold/environment requirements remain
unchanged. Skips and expected failures are observations, never qualification.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))


def run_suite(suite, *, stream=None):
    expected = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2, stream=stream).run(suite)
    complete = expected > 0 and result.testsRun == expected
    clean = not (result.errors or result.failures or result.skipped
                 or result.expectedFailures or result.unexpectedSuccesses)
    return complete and clean and result.wasSuccessful()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tests", nargs="+", help="existing unittest module, class or method names")
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromNames(args.tests)
    raise SystemExit(0 if run_suite(suite) else 1)


if __name__ == "__main__":
    main()
