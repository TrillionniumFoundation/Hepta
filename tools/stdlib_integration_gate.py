#!/usr/bin/env python3
"""Require every inherited and composed public test, without skips or duplicates."""
from pathlib import Path
import os
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
EXPECTED = {'test_stdlib_bytes': 13, 'test_stdlib_ordering': 12,
            'test_stdlib_utf8': 12, 'test_stdlib_base64': 11,
            'test_stdlib_integration': 12}


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def main():
    if not __debug__:
        raise RuntimeError('Do not disable assertions with Python -O')
    backend = os.environ.get('HEPTA_INTEGRATION_BACKEND', 'c')
    assert backend in ('c', 'rust'), backend
    for name in ('BYTES', 'ORDERING', 'UTF8', 'BASE64'):
        key = f'HEPTA_{name}_BACKEND'
        if key in os.environ:
            assert os.environ[key] == backend, f'{key} disagrees with selected backend'
        os.environ[key] = backend
    suite = unittest.TestSuite()
    for name, count in EXPECTED.items():
        component = unittest.defaultTestLoader.loadTestsFromName(name)
        assert component.countTestCases() == count, (name, component.countTestCases())
        suite.addTest(component)
    identities = [test.id() for test in flatten(suite)]
    assert len(identities) == len(set(identities)) == 60
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    assert result.testsRun == 60, result.testsRun
    assert result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses
    print(f'PASS: 60 unique public methods, zero skips, backend={backend}', flush=True)


if __name__ == '__main__':
    main()
