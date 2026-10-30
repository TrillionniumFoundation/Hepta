"""Build the docs/evidence-only delivery from immutable execution records."""
from pathlib import Path
import datetime
import hashlib
import json
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REPO = ROOT / 'hepta-integration'
HEAD = '44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304'
TREE = '835555fb35dbdcf867724ef7a0bb1a6616270217'
DEST = REPO / 'evidence/hia_next_integrated_20261030'


def save(path, value):
    with path.open('x') as output:
        json.dump(value, output, ensure_ascii=False, indent=2, sort_keys=True)
        output.write('\n')


def main():
    if DEST.exists():
        raise ValueError('refuse to overwrite delivery')
    for name in ['compiler-review.json', 'migration-review.json', 'optimization-ci-review.json']:
        if not (HERE / 'reviews' / name).is_file():
            raise ValueError('missing report review: ' + name)
    DEST.mkdir()
    shutil.copytree(HERE / 'root-readback', DEST / 'root-readback')
    shutil.copytree(HERE / 'reviews', DEST / 'reviews')
    shutil.copy2(HERE / 'assemble_and_readback.py', DEST / 'assemble_and_readback.py')
    shutil.copy2(HERE / 'readback_ci_followup.py', DEST / 'readback_ci_followup.py')
    shutil.copy2(HERE / 'finalize_delivery.py', DEST / 'finalize_delivery.py')
    shutil.copy2(HERE / 'verify_delivery.py', DEST / 'verify_delivery.py')
    shutil.copy2(HERE / 'INTEGRATED_README.md', DEST / 'README.md')
    shutil.copy2(HERE / 'HIA_NEXT_STRICT_RESULTS_20261030.md', REPO / 'docs/HIA_NEXT_STRICT_RESULTS_20261030.md')
    publication = DEST / 'source-publication'
    publication.mkdir()
    for path in sorted((ROOT / 'hia-github-publication-20261030').iterdir()):
        if path.is_file() and path.suffix != '.pack':
            # These precede this delivery and retain their then-observed status.
            shutil.copy2(path, publication / path.name)
    shutil.copy2(HERE / 'SOURCE_REF_BEFORE_DELIVERY.json', publication / 'SOURCE_REF_BEFORE_DELIVERY.json')
    contract = json.loads((REPO / 'docs/HIA_SAFETY_CONTRACT.json').read_text())
    ci = json.loads((REPO / 'evidence/hia_next_ci_20261030/VERIFY.json').read_text())
    root_review = json.loads((DEST / 'root-readback/FINAL_RESULT.json').read_text())
    if not ci['latest_required_source_verified'] or not root_review['passed']:
        raise ValueError('current independent readback missing')
    result = {
        'schema': 'hepta.hia.next.strict-results.v1',
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'implementation': {'commit': HEAD, 'tree': TREE,
            'branch': 'work/hia-p0-p7-integrated-20261030',
            'full_ci_executed_on_this_exact_commit': True,
            'focused_native_and_model_records_bind_this_exact_commit': True},
        'delivery': {'branch': 'delivery/hia-p0-p7-44e34b7-20261030',
            'parent': HEAD, 'scope': 'documentation and inert evidence only',
            'qualified_as_new_execution_commit': False,
            'publication_receipt_location': 'external post-publication receipt; cannot self-reference final commit'},
        'all_P0_P7_strict_conditions_met': False,
        'ci': {'run_id': 41061115481, 'job_id': 124080797698, 'conclusion': 'success',
            'url': 'https://github.com/TrillionniumFoundation/Hepta/actions/runs/41061115481',
            'integrated_gates_passed': 8, 'python_unique_methods': 4266,
            'rust_tests': 116, 'rust_result_blocks': 21, 'rust_running_harnesses': 20, 'rust_doc_tests_harnesses': 1,
            'matrix_selectors': 447, 'matrix_capabilities': 45,
            'critical_groups': 77, 'critical_unique_modules': 187, 'critical_unique_selectors': 1846,
            'overlapping_test_denominators_additive': False,
            'test_failures': 0, 'test_errors': 0, 'test_skips': 0,
            'workflow_conditionally_skipped_alternative_or_failure_steps': [20, 21, 22, 25],
            'tracked_files': 6685, 'external_inputs': 440,
            'canonical_contract_sha256': 'bd58291c3bc3470840a6b22b9f712fe1766629e3cbae8bd83291da16c911f018',
            'artifact_id': 12982148935, 'artifact_bytes': 1318884,
            'artifact_sha256': 'fd29bbd98ac293e51e1c2acc234d5ef0157333c634b6f390e2e95a6a356c8c6e'},
        'stages': {
            'P0': {'status': 'closed_within_declared_candidate_scope', 'strict_gate_met_within_declared_scope': True,
                'evidence': '../hia_next_ci_20261030/README.md',
                'scope': 'both original PR ancestors, one integrated implementation, explicit routes/authority, fresh exact-commit CI'},
            'P1': {'status': 'finite_resource_scope_extended', 'strict_full_condition_met': False,
                'evidence': '../hia_next_resource_20261030/README.md',
                'profile': 'raw-byte-dag-finite-heap-v1', 'rust_processes': 296,
                'complete_bound_machine_python_observations': 253, 'stopped_observations_with_live_payload': 53,
                'missing': ['source-to-Core and Core-to-native refinement', 'general recursion/loops/concurrency',
                    'RSS/stack/CPU bounds', 'cleanup theorem for every failure path']},
            'P2': {'status': 'explicit_finite_Rust_profile_authoritative', 'strict_full_condition_met': False,
                'default_source_nominal_native_authority_switched': False,
                'python_semantic_admission_required_for_finite_profile': False,
                'evidence': '../hia_next_resource_20261030/README.md',
                'missing': ['independent verification and differential coverage for full declared language admission scope',
                    'explicit broader authority transition with reproducible regressions']},
            'P3': {'status': 'real_changed_body_C_component_revalidated', 'strict_full_condition_met': False,
                'evidence': '../hia_next_migration_context_20261030/README.md',
                'component': 'stb_divide', 'versions': ['0.93', '0.94'], 'active_functions': 6,
                'common_defined_input_pairs': 119, 'common_native_observations': 2856, 'common_VM_observations': 1428,
                'historical_CPP_foreign_SIGABRT': 6,
                'missing': ['general C++ migration and hardware ABI qualification', 'foreign termination recovery',
                    'long-term upstream maintenance', 'complete measured human cost']},
            'P4': {'status': 'complete_negative_economic_observation', 'strict_full_condition_met': False,
                'evidence': '../hia_next_stb_ndu_20261030/README.md',
                'current_formal_execution_complete': True, 'cold_candidate_net_benefit': False,
                'performance_timing_qualified': False,
                'missing': ['positive necessary-cost-inclusive benefit on valuable qualified workloads']},
            'P5': {'status': 'independent_NDU_increment_not_established', 'strict_full_condition_met': False,
                'evidence': '../hia_next_stb_ndu_20261030/README.md', 'native_NDU_requests': 32,
                'same_model_DP_identical_choices': 32, 'modeled_regret_ns': 0,
                'native_runtime_net_increment': False, 'native_build_inclusive_net_increment': False,
                'safety_authority': 'DENY_ALL',
                'missing': ['exceed strong fixed, feedback greedy and light planner with matched information, budget and cache']},
            'P6': {'status': 'bounded_context_reentrancy_and_map_repeat_verified', 'strict_full_condition_met': False,
                'evidence': '../hia_next_migration_context_20261030/README.md', 'actual_context_methods': 46,
                'missing': ['general active calls', 'arbitrary foreign callbacks', 'persistent state migration',
                    'general reclamation and failure recovery']},
            'P7': {'status': 'model_calibration_failed_main_refused', 'strict_full_condition_met': False,
                'evidence': '../hia_next_agent_v12_20261030/README.md', 'capacity_controls_passed': 19,
                'independent_CLI_tokenizer_calls': 95, 'calibration_correct': 0, 'calibration_tasks': 3,
                'model_requests': 9, 'model_responses': 9, 'public_output_schema_passed': 9,
                'input_tokens': 21025, 'output_tokens': 2279, 'total_tokens': 23304,
                'human_answer_repairs': 0, 'unknown_usage_requests': 0,
                'main_CLI_actual_returncode': 1, 'main_engine_constructed': False, 'main_cells': 0,
                'new_independent_holdout': False, 'AI_productivity_advantage_proved': False,
                'missing': ['model prerequisite qualification', 'real independent development and maintenance comparison against mature workflows']},
        },
        'unproved_claims': contract['unproved_claims'],
        'historical_failures_preserved': True,
        'old_results_relabelled_as_current': False,
        'full_human_and_agent_development_review_cost': None,
        'unknown_cost_treated_as_zero': False,
        'cost_scopes': {'nested_intervals_additive': False, 'standalone_arm_totals_additive': False,
            'new_archive_and_readback_work_counted_as_model_or_native_success': False},
        'root_copied_package_readback': root_review,
    }
    save(DEST / 'RESULT.json', result)
    report = REPO / 'docs/HIA_NEXT_STRICT_RESULTS_20261030.md'
    save(DEST / 'REPORT_REVIEW_RESOLUTION.json', {
        'schema': 'hepta.hia.next.report-review-resolution.v1',
        'report_sha256': hashlib.sha256(report.read_bytes()).hexdigest(),
        'resolutions': [
            'Rust 21 result blocks distinguished from 20 Running harnesses and one Doc-tests.',
            'Finite heap refusal limited to unsupported allocation bounds, payload overflow and work limits; scalar Unknown retained.',
            'Core input document digest distinguished from outer typed arguments and nonexistent inner VM argument hash.',
            'P4 shared-host performance_timing_qualified=false stated explicitly.',
        ],
        'execution_records_changed_by_report_edits': False,
        'source_or_formal_protocol_changed_by_report_edits': False,
    })
    print(json.dumps({'result': str(DEST / 'RESULT.json'), 'all_strict_conditions_met': False,
        'report_sha256': hashlib.sha256(report.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
