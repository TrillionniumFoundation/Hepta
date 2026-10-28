#!/usr/bin/python3
"""Build final review files only after real integrated terminal evidence exists."""
import hashlib
import json
from pathlib import Path
import re

PREP = Path('/tmp/hepta-next-evidence-preparation-20261028')
STAGE = Path('/tmp/hepta-next-evidence-staging-20261028')
DEST = STAGE / 'evidence/audits/p0_p7_partial_records_incremental'
FULL = Path('/tmp/hepta-next-integrated-d942f18b-20261028')
ROOT = Path('/workspace/scratch/4bc91e0ee48c/hepta-followup-integration')
COMMIT = 'd942f18b07c8811aa1418b6f67fabc23212317d1'
TREE = '44823c1858d52e9043edebb83f2414d91087d743'
SNAPSHOT = '4a64e1a353585d0ee88985e4942c008bd82ec1482be7ce1158a60f24f550e8db'


def read(path):
    return json.loads(Path(path).read_text())


def describe(path):
    path = Path(path)
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def write(relative, value):
    path = DEST / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def main():
    completion = read(FULL / 'execution-completion.json')
    summary = read(FULL / 'summary.json')
    unit = completion['unit']
    rust = completion['cargo_test']
    assert summary['ok'] is True and completion['observed_runner_returncode'] == 0
    assert summary['git_commit'] == completion['git_commit'] == COMMIT
    assert completion['runner_and_validation_stages_completed'] is True
    assert completion['source_unchanged'] and completion['tools_unchanged']
    assert unit['returncode'] == rust['returncode'] == 0
    assert unit['failures'] == unit['errors'] == unit['skipped'] == 0
    assert unit['tests_run'] == unit['unique_canonical_method_count'] == unit['canonical_method_count']
    assert not unit['duplicate_canonical_methods']
    assert rust['failed'] == rust['ignored'] == rust['measured'] == rust['filtered_out'] == 0
    raw = (FULL / 'unit-discovery/stderr.log').read_text()
    footer = re.search(r'(?m)^Ran ([0-9]+) tests in ([0-9.]+)s\n\nOK\n?\Z', raw)
    assert footer and int(footer.group(1)) == unit['tests_run']

    partial_outer = read('/tmp/hepta-partial-record-final-d942f18b-20261028/report.json')
    partial = read('/tmp/hepta-partial-record-final-d942f18b-20261028/qualification/report.json')
    cpp_outer = read('/tmp/hepta-cpp-constexpr-final-d942f18b-20261028/report.json')
    cpp = read('/tmp/hepta-cpp-constexpr-final-d942f18b-20261028/native-80/report.json')
    two = read('/tmp/hepta-partial-two-owner-20261028/attempt-01/report.json')
    review = read('/tmp/hepta-next-native-review-20261028/corrected-attempt/review.json')
    two_review = read('/tmp/hepta-next-native-review-20261028/two-owner-review/review.json')
    assert all(x['passed'] for x in [partial_outer, partial, cpp_outer, two, review, two_review])
    assert cpp['ok'] is True
    assert all(x['source_before']['commit'] == COMMIT and x['source_unchanged'] and x['tools_unchanged']
               for x in [partial_outer, cpp_outer, two])
    assert len(partial['differential']) == 94 and len(partial['budgets']) == 11
    assert sum(len(x['cases']) for x in partial['native'].values()) == 188
    assert len(partial['negative_controls']) == 2
    assert cpp['case_count'] == 80 and cpp['native_result_executions'] == 160
    assert two['counts'] == {'requests': 32, 'python_executions': 64, 'rust_executions': 32,
                             'positive_native_executions': 64, 'negative_native_executions': 4}

    copies = [
        (FULL / 'execution-completion.json', 'integrated/execution-completion.json'),
        (FULL / 'summary.json', 'integrated/summary.json'),
        (FULL / 'unit-discovery/stderr.log', 'integrated/unit.stderr.log'),
        (FULL / 'unit-discovery/stdout.log', 'integrated/unit.stdout.log'),
        (FULL / 'cargo-test/stdout.log', 'integrated/cargo.stdout.log'),
        (FULL / 'cargo-test/stderr.log', 'integrated/cargo.stderr.log'),
        (FULL / 'canonical-unittest-ids.txt', 'integrated/canonical-unittest-ids.txt'),
        (Path('/tmp/hepta-partial-record-final-d942f18b-20261028/report.json'), 'native/partial-records-outer.json'),
        (Path('/tmp/hepta-partial-record-final-d942f18b-20261028/qualification/report.json'), 'native/partial-records.json'),
        (Path('/tmp/hepta-cpp-constexpr-final-d942f18b-20261028/report.json'), 'native/cpp-constexpr-outer.json'),
        (Path('/tmp/hepta-cpp-constexpr-final-d942f18b-20261028/native-80/report.json'), 'native/cpp-constexpr.json'),
        (Path('/tmp/hepta-partial-two-owner-20261028/attempt-01/report.json'), 'native/two-owner-cancel.json'),
        (Path('/tmp/hepta-partial-two-owner-20261028/seal.json'), 'native/two-owner-final-seal.json'),
        (Path('/tmp/hepta-next-native-review-20261028/corrected-attempt/review.json'), 'reviews/independent-native.json'),
        (Path('/tmp/hepta-next-native-review-20261028/two-owner-review/review.json'), 'reviews/independent-two-owner.json'),
        (Path('/tmp/hepta-next-freeze-20261028/published-freeze.json'), 'source/executed-source.json'),
        (Path('/tmp/hepta-next-freeze-20261028/freeze.json'), 'source/local-freeze.json'),
        (Path('/tmp/hepta-cpp-constexpr-audit-20261028/evidence-index-final-d942f18b.json'), 'development/cpp-evidence-index.json'),
        (Path('/tmp/hepta-next-delivery-review-preparation-20261028/review.json'), 'reviews/readme-initial-review.json'),
        (Path('/tmp/hepta-next-delivery-review-preparation-20261028/incremental-doc-wording.md'), 'reviews/incremental-doc-wording.md'),
        (PREP / 'documentation-clarification-plan.json', 'source/documentation-clarification-plan.json'),
        (PREP / 'package_completed.py', 'reproduction/package_completed.py'),
        (PREP / 'make_final_delivery.py', 'reproduction/make_final_delivery.py'),
    ]
    copied = []
    for source, relative in copies:
        destination = DEST / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = source.read_bytes()
        with destination.open('xb') as stream:
            stream.write(data)
        assert source.read_bytes() == destination.read_bytes()
        copied.append({'original': describe(source), 'published_relative_path': relative,
                       'copied_without_rewriting': True})
    write('source/exact-copy-map.json', {'schema': 'hepta.evidence.exact-copy-map.v1', 'files': copied})

    old = read(ROOT / 'evidence/audits/p0_p7_original_type_followup/current-status.json')
    stages = old['stages']
    updates = {
        'P0': (['Composite v3 has a distinct namespace; existing v1/v2 fingerprints and exact admission boundaries remain regression obligations.'],
               ['Continue same-version registry/admission/backend agreement for each added feature; no whole-language refinement follows from registry agreement.']),
        'P1': (['Composite v3 adds linear partial-record construction, field movement/reinitialization and declaration constraints, normalized to primitive v7.',
                '94-case production-path qualification and a separate 32-case two-live-payload cleanup/cancellation qualification passed on the exact executed implementation.'],
               ['General typed addresses/layouts and address-based partial initialization', 'Escaping stored loans and arbitrary recursive heap ADTs',
                'Concurrent scheduling, atomics and channels in the same standalone Core']),
        'P2': (['New partial-record Core agrees across nominal/Core Python, the retained independent Rust VM and actual LLVM execution for the fixed corpora.',
                'Missing-free, wrong-value and wrong-release-order controls demonstrate independent rejection of those observable mismatches.'], None),
        'P3': ([], None),
        'P4': (['Captured concrete C++20 constexpr selection with complete template-pattern and stable local-member identity checks.',
                '80 defined boundary cases and 160 original-C++/standalone-HIA native calls agree; target links no original C++ implementation.'], None),
        'P5': ([], None),
        'P6': (['Bounded process-local incremental primitive v1-v7 checking implemented; structured/unsupported/policy-changed inputs fall back to full verification.',
                'Development comparison: 957 candidates, 56 accepted and 901 rejected, no full/incremental outcome/byte/diagnostic differences.'],
               ['Complete diagnostics and broader dependency contracts as the language grows',
                'Representative independent maintenance tasks under equal declared budgets',
                'Actual success/cost benefit: prior real-model trials did not pass their benefit criteria']),
        'P7': ([], None),
    }
    for stage in stages:
        added, remaining = updates[stage['id']]
        stage['implemented_scope'] += added
        if remaining is not None:
            stage['remaining_conditions'] = remaining
        stage['complete'] = False
    clarification = read(PREP / 'documentation-clarification-plan.json')
    status = {
        'schema': 'hepta.audit.p0-p7-partial-records-incremental-status.v1',
        'whole_project_blockers_closed': False, 'all_p0_p7_stages_complete': False,
        'review_pr': 'https://github.com/TrillionniumFoundation/Hepta/pull/338',
        'tested_implementation': {'commit': COMMIT, 'tree': TREE, 'source_snapshot_sha256': SNAPSHOT,
                                  'source_files': 1065, 'changed_paths': 24, 'new_paths': 15},
        'delivery_source': {'expected_snapshot_sha256': clarification['expected_delivery_snapshot_sha256'],
                            'documentation_only_differences': [clarification['relative_path']],
                            'executable_source_tests_examples_tools_changed_after_validation': False,
                            'full_suite_relabelled_to_delivery_commit': False},
        'integrated_validation': {'status': 'passed', 'python_tests': unit['tests_run'],
            'python_unique_methods': unit['unique_canonical_method_count'], 'python_skips': 0,
            'python_failures': 0, 'python_errors': 0, 'python_footer_seconds': unit['footer_elapsed_seconds'],
            'python_command_seconds': unit['command_duration_seconds'], 'rust_passed': rust['passed'],
            'rust_failed': 0, 'rust_ignored': 0, 'rust_harnesses': rust['harness_summary_count'],
            'rust_command_seconds': rust['command_duration_seconds'], 'source_unchanged': True,
            'tools_unchanged': True, 'completion': 'integrated/execution-completion.json',
            'metadata_and_build_preflights_counted_as_tests': False},
        'finite_native_qualifications': {
            'partial_records': {'cases': 94, 'budget_cases': 11, 'budget_stops': 10, 'budget_returns': 1,
                                'positive_native_executions': 188, 'native_negative_controls': 2,
                                'production_compile_api_used': True, 'report': 'native/partial-records.json'},
            'two_owner_cancellation': {**two['counts'], 'positive_native_two_live_payload_observations': 24,
                                      'production_compile_api_used': False,
                                      'route': two['llvm_route'], 'report': 'native/two-owner-cancel.json'},
            'cpp_constexpr': {'cases': 80, 'native_result_calls': 160, 'translation_units': 2,
                             'template_instances': 7, 'constexpr_selections': 13,
                             'original_cpp_implementation_linked_in_target': False,
                             'report': 'native/cpp-constexpr.json'}},
        'closed_in_this_increment': [
            {'id': 'P1_PARTIAL_RECORD_TYPESTATES', 'scope': 'finite nominal records over primitive v7', 'status': 'implemented_and_executed'},
            {'id': 'P1_UNUSED_PARTIAL_DECLARATIONS', 'scope': 'six exact original counterexamples; symbolic generic constraints and work limits', 'status': 'rejected_with_regressions'},
            {'id': 'P1_TWO_LIVE_PAYLOAD_CANCELLATION_ORDER', 'scope': 'four explicit cleanup/cooperative cancellation modes, fixed 32 inputs', 'status': 'native_observed_and_wrong_order_controls_detected'},
            {'id': 'P4_CAPTURED_CONSTEXPR', 'scope': 'closed captured Clang shape and defined unsigned concrete instances', 'status': 'implemented_and_native_differential_passed'},
            {'id': 'P4_FULL_PATTERN_AND_MEMBER_IDENTITY', 'scope': 'cross-file template conflict and stable local-member binding controls', 'status': 'fixed_and_regression_passed'},
            {'id': 'P6_LOCAL_INCREMENTAL_ADMISSION', 'scope': 'locally verified primitive v1-v7 snapshots; public consumers still fully check', 'status': 'implemented_and_regression_passed'},
        ],
        'stages': stages,
        'claims': {'whole_language_soundness_proved': False, 'llvm_refinement_proved': False,
                   'arbitrary_c_cpp_migration_qualified': False, 'rust_performance_superiority_proved': False,
                   'real_model_productivity_benefit_proved': False, 'gpu_executed': False,
                   'physical_board_executed': False, 'all_19_gates_requalified': False,
                   'remote_ci_completion_claimed': False, 'merged': False},
        'historical_evidence_rule': 'Earlier successes, failures, regressions and interrupted attempts retain their actual source identities.',
        'prior_review': '../p0_p7_original_type_followup/current-status.json',
        'source_identity_rule': 'Executed d942 implementation, later documentation clarification and evidence publication are separately identified.',
        'original_108762ba_archive_included': False, 'raw_model_payload_included': False,
    }
    write('current-status.json', status)
    text = (PREP / 'README.template.md').read_text()
    substitutions = {'UNIT_COUNT': unit['tests_run'], 'RUST_COUNT': rust['passed'],
                     'RUST_HARNESSES': rust['harness_summary_count'],
                     'UNIT_FOOTER_SECONDS': unit['footer_elapsed_seconds'],
                     'UNIT_COMMAND_SECONDS': round(unit['command_duration_seconds'], 6),
                     'RUST_COMMAND_SECONDS': round(rust['command_duration_seconds'], 6)}
    for key, value in substitutions.items():
        text = text.replace('@@' + key + '@@', str(value))
    assert '@@' not in text
    with (DEST / 'README.md').open('x', encoding='utf-8') as stream:
        stream.write(text)
    print(json.dumps({'staged_review': str(DEST), 'python_passed': unit['tests_run'],
                      'rust_passed': rust['passed'], 'native_qualifications': 3,
                      'whole_project_blockers_closed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
