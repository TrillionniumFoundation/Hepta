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


def load_declared_suite(selectors):
    """Require every named group to contribute distinct executable tests.

    unittest silently accepts a module/class whose last test was removed.
    An aggregate nonzero count cannot prove that all declared groups ran.
    Fail discovery before entering even the valid groups in a partial plan.
    """
    suite = unittest.TestSuite()
    planned = []
    for selector in selectors:
        loader = unittest.TestLoader()
        selected = loader.loadTestsFromName(selector)
        if loader.errors:
            raise ValueError("test discovery failed for " + selector
                             + "\n" + "\n".join(loader.errors))
        if selected.countTestCases() == 0:
            raise ValueError("empty test selector: " + selector)
        pending = [selected]
        while pending:
            test = pending.pop()
            if isinstance(test, unittest.TestSuite):
                pending.extend(reversed(list(test)))
            elif isinstance(test, unittest.TestCase):
                identity = test.id()
                if type(identity) is not str or not identity:
                    raise ValueError("noncanonical test identity: " + selector)
                planned.append(identity)
            else:
                raise ValueError("non-TestCase discovered: " + selector)
        suite.addTest(selected)
    if not planned or len(planned) != len(set(planned)):
        raise ValueError("empty or overlapping test plan")
    return suite, tuple(planned)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tests", nargs="+", help="existing unittest module, class or method names")
    args = parser.parse_args()
    try:
        suite, _ = load_declared_suite(args.tests)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
    raise SystemExit(0 if run_suite(suite) else 1)


if __name__ == "__main__":
    main()
