"""Structured policy controls plus every prior loader and consumer control."""
import argparse
import unittest
from experiments.normal_loader_extraction.gate import FOCUSED, CONSUMERS, identities


def run(include_consumers=False):
    suite = unittest.defaultTestLoader.loadTestsFromNames(
        ['experiments.policy_failures.test_review_regressions','experiments.policy_failures.test_parity','experiments.policy_failures.test_policy','experiments.policy_failures.test_origins','experiments.cli_admission_audit.test_contract','experiments.cli_admission_audit.test_calibration','experiments.package_copy.test_owner','experiments.package_copy.test_review_regressions','experiments.shallow_authority.test_package_audit','experiments.shallow_authority.test_review_regressions','experiments.shallow_authority.test_owner','experiments.authority_maps.test_review_regressions','experiments.authority_maps.test_owner','experiments.loader_transform.test_authority_audit','experiments.loader_transform.test_review_regressions','experiments.loader_transform.test_owner','experiments.assembly_copy.test_review_regressions','experiments.assembly_copy.test_owner','experiments.parser_appends.test_owner','experiments.ast_structure.test_owner','experiments.owned_tokens.test_owner','experiments.graph_loader.test_owner',
         'experiments.owned_loader.test_owner'] + FOCUSED + (CONSUMERS if include_consumers else []))
    names = list(identities(suite))
    expected = 720 if include_consumers else 588
    if len(names) != len(set(names)) or len(names) != expected:
        raise AssertionError((expected,len(names),names))
    print('Planned unique test identities:', names, flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if (not result.wasSuccessful() or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses or result.testsRun != expected):
        raise SystemExit(1)


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--include-consumers',action='store_true')
    run(parser.parse_args().include_consumers)
