"""Finite owner gate plus the existing exact-identity legacy regressions."""
import argparse
import unittest
from experiments.normal_loader_extraction.gate import FOCUSED, CONSUMERS, identities


def run(include_consumers=False):
    suite = unittest.defaultTestLoader.loadTestsFromNames(
        ['experiments.owned_loader.test_owner'] + FOCUSED + (CONSUMERS if include_consumers else []))
    names = list(identities(suite))
    expected = 291 if include_consumers else 159
    if len(names) != len(set(names)) or len(names) != expected:
        raise AssertionError((expected, len(names), names))
    print('Planned unique test identities:', names, flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if (not result.wasSuccessful() or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses or result.testsRun != expected):
        raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--include-consumers', action='store_true')
    run(parser.parse_args().include_consumers)
