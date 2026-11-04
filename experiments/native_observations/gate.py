"""Exact no-skip aggregate; local mode explicitly omits seven Rust consumers."""
import argparse
import unittest

INHERITED = [
    'experiments.c_char_boundary.test_prototype',
    'experiments.c_char_boundary.test_integration_gaps',
    'experiments.c_char_boundary.test_build_plan',
    'experiments.loader_budget.test_characterization',
    'experiments.loader_budget.test_prototype',
    'experiments.request_load.test_context', 'tests.test_modules',
    'tests.test_c_import', 'tests.test_c_import_capture',
    'tests.test_c_import_prototypes', 'tests.test_c_import_typedefs']
NEW = ['experiments.native_observations.test_observer',
       'experiments.native_observations.test_native',
       'experiments.native_observations.test_review_regressions']
OMIT_LOCAL = {
    'experiments.c_char_boundary.test_prototype.CharPrototypeTests.test_actual_rust_reference',
    'tests.test_modules.ModuleTests.test_aliases_and_private_internal_helpers_execute',
    'tests.test_modules.ModuleTests.test_same_local_names_in_multiple_modules_are_distinct',
    'tests.test_modules.ModuleTests.test_nested_paths_and_shared_dependency_are_deduplicated',
    'tests.test_modules.ModuleTests.test_public_struct_crosses_module_and_private_type_rejected',
    'tests.test_modules.PackageTests.test_local_library_dependency_executes_locked',
    'tests.test_modules.PackageTests.test_cli_package_check',
}


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite): yield from flatten(item)
        else: yield item


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--local',action='store_true');args=parser.parse_args()
    inherited=list(flatten(unittest.defaultTestLoader.loadTestsFromNames(INHERITED)))
    new=list(flatten(unittest.defaultTestLoader.loadTestsFromNames(NEW)))
    assert len(inherited)==len({t.id() for t in inherited})==164
    assert len(new)==len({t.id() for t in new})==38
    tests=inherited+new;ids=[t.id() for t in tests]
    assert len(ids)==len(set(ids))==202
    assert OMIT_LOCAL <= set(ids)
    if args.local: tests=[t for t in tests if t.id() not in OMIT_LOCAL]
    expected=195 if args.local else 202
    assert len(tests)==expected
    print('Planned identities:',[t.id() for t in tests],flush=True)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(tests))
    if (not result.wasSuccessful() or result.testsRun!=expected or result.skipped
            or result.expectedFailures or result.unexpectedSuccesses):
        raise SystemExit('aggregate did not execute every planned control without skips')


if __name__=='__main__':main()
