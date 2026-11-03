"""Exact planned identities; no missing or skipped tests count as qualification."""
import argparse
import unittest

FOCUSED = [
    'experiments.normal_loader_extraction.test_hooks',
    'experiments.loader_consumer_audit.test_contract',
    'experiments.legacy_loader_ops.test_differential',
    'experiments.loader_api.test_contract',
    'experiments.request_load.test_context',
    'experiments.loader_budget.test_characterization',
]
CONSUMERS = [
    'tests.test_modules', 'tests.test_project_protocol', 'tests.test_protocol_v3',
    'tests.test_workspace', 'tests.test_workspace_query_cli', 'tests.test_agent_semantics',
    'tests.test_crossfile_workspace_crashes', 'tests.test_crossfile_protocol_v2',
    'tests.test_protocol',
]


def identities(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from identities(item)
        else:
            yield item.id()


def run(include_consumers=False):
    suite = unittest.defaultTestLoader.loadTestsFromNames(FOCUSED + (CONSUMERS if include_consumers else []))
    names = list(identities(suite))
    expected = 259 if include_consumers else 127
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
