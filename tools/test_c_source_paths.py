"""Run the finite C filename regression suite with an exact test inventory."""
from pathlib import Path
import argparse
import shutil
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

MODULES = ('tests.test_c_source_paths', 'tests.test_c_backend',
           'tests.test_c_owned_backend', 'tests.test_parser', 'tests.test_checker',
           'tests.test_debug_info')
RUST_DEPENDENT = frozenset(
    'tests.test_c_owned_backend.COwnedBackendTests.' + name for name in (
        'test_owned_generic_library_executes_both_result_paths_and_allocations',
        'test_nested_enum_payload_cleanup_releases_only_the_live_variant',
        'test_copy_generics_arrays_recursive_calls_and_unused_abstract_body',
        'test_aggregate_and_specialization_names_cannot_collide_with_source_names',
        'test_internal_slice_cache_does_not_collide_with_generic_nominal_types',
        'test_borrowed_scalar_and_slice_return_chains_mutate_correct_region',
        'test_separate_struct_fields_remain_disjoint_in_owned_profile',
        'test_allocation_in_loops_is_consumed_before_each_backedge',
        'test_unit_enum_payload_preserves_effects',
        'test_partial_moves_restore_and_consuming_error_paths_run_on_both_backends',
        'test_selected_borrow_origin_retains_only_its_declared_argument',
        'test_copy_fields_materialize_before_later_aggregate_argument_effects',
        'test_qualification_validator_rejects_incomplete_or_inflated_evidence',
    )) | frozenset({
        'tests.test_debug_info.DebugInfoTests.test_both_cli_backends_retain_real_debug_sources',
        'tests.test_debug_info.DebugInfoTests.test_debug_profiles_require_an_explicit_retained_destination',
    })


def flatten(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from flatten(test)
        else:
            yield test


class ExactResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started = []

    def startTest(self, test):
        self.started.append(test.id())
        super().startTest(test)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--without-rust', action='store_true',
                        help='explicitly run only 186 local controls, not the complete hosted gate')
    args = parser.parse_args()
    if not shutil.which('gcc') or not shutil.which('readelf'):
        parser.error('real GCC and GNU readelf are required')
    all_tests = list(flatten(unittest.defaultTestLoader.loadTestsFromNames(MODULES)))
    all_ids = [test.id() for test in all_tests]
    if len(all_ids) != 201 or len(set(all_ids)) != 201 or not RUST_DEPENDENT <= set(all_ids):
        raise SystemExit('Expected exactly 201 unique controls and the declared Rust inventory')
    omitted = RUST_DEPENDENT if args.without_rust else frozenset()
    planned = [test for test in all_tests if test.id() not in omitted]
    ids = [test.id() for test in planned]
    print('OMITTED_RUST_CONTROLS:', sorted(omitted), flush=True)
    print('PLANNED_TEST_IDS:', ids, flush=True)
    result = unittest.TextTestRunner(verbosity=2, resultclass=ExactResult).run(unittest.TestSuite(planned))
    if (not result.wasSuccessful() or result.skipped or result.expectedFailures
            or result.unexpectedSuccesses or result.started != ids or result.testsRun != len(ids)):
        raise SystemExit('Exact test inventory did not pass without skips/xfails/xpasses')
    print('LOCAL_PARTIAL_PASS' if args.without_rust else 'COMPLETE_HOSTED_PASS', len(ids), flush=True)


if __name__ == '__main__':
    main()
