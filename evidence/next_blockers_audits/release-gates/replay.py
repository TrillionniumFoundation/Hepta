#!/usr/bin/env python3
"""Unit-style evidence-validator audit, never native qualification evidence."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', default='/workspace/scratch/0817a147930b/Hepta-release-audit')
    parser.add_argument('--performance', type=Path)
    parser.add_argument('--resources', type=Path)
    parser.add_argument('--output', type=Path, default=Path('/tmp/hepta-release-gate-independent-audit.json'))
    args = parser.parse_args()
    root = Path(args.repo)
    source = root / 'tools/release_check.py'
    before = source.read_bytes()
    sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location('release_under_audit', source)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    source_root = Path('/workspace/scratch/0817a147930b/Hepta-work')
    paths = {
        'stateful_c_module': source_root / 'evidence/next_blockers_audits/c-ring-fixed-feature/report.json',
        'independent_resource_ir': source_root / 'evidence/owned_generics/resource_qualification.json',
        'bounded_concurrency': source_root / 'artifacts/next-blockers/group-timeouts.json',
    }
    if args.performance:
        paths['representative_performance'] = args.performance
    if args.resources:
        paths['independent_resource_ir'] = args.resources
    reports = {name: json.loads(path.read_text()) for name, path in paths.items()}
    observations = []

    def validate(name, value):
        # Match main()'s real outer-status policy as well as its inner validator.
        if name in {'independent_resource_ir', 'stateful_c_module'}:
            if value.get('ok') is not True:
                raise ValueError('outer ok missing')
        elif value.get('status') != 'passed':
            raise ValueError('outer status not passed')
        if name == 'stateful_c_module':
            # Historical report is only a structural fixture; never promote it
            # to a current-source qualification by changing recorded hashes.
            with patch.object(gate, 'snapshot', return_value=reports[name]['source_snapshot_before']):
                with patch.object(gate, 'ROOT', source_root):
                    gate.require_qualification(name, value)
        else:
            with patch.object(gate, 'ROOT', source_root):
                gate.require_qualification(name, value)

    def case(name, label, mutate=None, expected='rejected'):
        value = copy.deepcopy(reports[name])
        if mutate:
            mutate(value)
        result = {'gate': name, 'case': label, 'expected': expected,
                  'mutated_report_sha256': sha(json.dumps(value, sort_keys=True).encode())}
        try:
            validate(name, value)
        except Exception as exc:
            result.update(actual='rejected', diagnostic=type(exc).__name__ + ': ' + str(exc))
        else:
            result['actual'] = 'accepted'
        result['matched'] = result['actual'] == expected
        observations.append(result)

    for name in reports:
        case(name, 'unmodified_historical_structural_fixture', expected='accepted')
        case(name, 'outer_failure', lambda r: r.update(ok=False, status='failed'))
    n = 'stateful_c_module'
    case(n, 'original_native_build_missing', lambda r: r.pop('original_build'))
    case(n, 'original_native_build_failed', lambda r: r['original_build'].update(exit_code=1))
    case(n, 'translated_native_build_failed', lambda r: r['migration']['native_build'].update(ok=False, status='not_run'))
    case(n, 'owned_client_native_build_missing', lambda r: r['owned_client'].pop('native_build'))
    case(n, 'performance_native_build_failed', lambda r: r['performance']['build'].update(exit_code=1))
    case(n, 'both_layout_values_null', lambda r: r.update(layout_probe={key:{'gcc':None,'rust':None} for key in r['layout_probe']}))
    case(n, 'nested_full_C_support_claim', lambda r: r['migration']['claims'].update(all_c_or_cpp_supported=True))
    case(n, 'nested_ownership_inference_claim', lambda r: r['migration']['record_views'].update(ownership_inference=True))
    case(n, 'state_and_storage_checks_omitted', lambda r: r['execution'].update(checks=[]))
    case(n, 'all_measurements_same_execution_arm', lambda r: [m.update(execution_order=['original_C'] * 14) for m in r['performance']['measurements']])
    case(n, 'positive_outer_with_missing_decl', lambda r: r['migration']['coverage'].update(active_project_declarations=21))
    case(n, 'top_false_soundness_claim', lambda r: r.update(source_equivalence_proved=True))
    n = 'independent_resource_ir'
    case(n, 'eleven_duplicate_negative_controls', lambda r: r.update(adversarial_checks=[copy.deepcopy(r['adversarial_checks'][0])] * 11))
    case(n, 'negative_controls_no_diagnostics', lambda r: r.update(adversarial_checks=[{'ok':True}] * 11))
    case(n, 'native_codegen_IR_claim_inflated', lambda r: r.update(native_codegen_uses_resource_ir=True))
    case(n, 'IR_refinement_claim_inflated', lambda r: r.update(source_to_ir_refinement_proved=True))
    case(n, 'nested_IR_claim_inflated', lambda r: r['projects'][0]['resource_verifier']['claims'].update(external_contracts_proved=True))
    case(n, 'verifier_not_run_but_ok', lambda r: r['projects'][0]['resource_verifier'].update(status='not_run'))
    case(n, 'native_backend_failure_but_gate_ok', lambda r: r['projects'][0]['native_gate']['backend'].update(ok=False, status='not_run'))
    case(n, 'native_execution_artifact_identity_erased', lambda r: r['projects'][0]['execution'].pop('executable_sha256'))
    case(n, 'generic_body_counter_reduced', lambda r: r['projects'][2]['resource_verifier'].update(generic_functions_checked=5))
    n = 'bounded_concurrency'
    case(n, 'live_tasks_after_cancellation', lambda r: r['scenarios'][2]['runs'][0]['metrics'].update(active_tasks=3))
    case(n, 'no_pipeline_values_received', lambda r: r['scenarios'][0]['runs'][0]['metrics'].update(received_sum=0))
    case(n, 'negative_elapsed_duration', lambda r: r['scenarios'][0]['runs'][0].update(elapsed_ms=-1))
    case(n, 'unbounded_peak_queue', lambda r: r['scenarios'][0]['runs'][0]['metrics'].update(peak_queued=1000))
    case(n, 'deadline_no_timeout', lambda r: r['scenarios'][4]['runs'][0]['metrics'].update(send_timeouts=0))
    if args.performance:
        n = 'representative_performance'
        case(n, 'all_raw_samples_duplicate_one_profile', lambda r: r['measurements'].update(samples=[copy.deepcopy(r['measurements']['samples'][0])] * len(r['measurements']['samples'])))
        case(n, 'raw_sample_negative_nanoseconds', lambda r: r['measurements']['samples'][0].update(elapsed_ns=-1, ns_per_operation=-1))
        case(n, 'timing_summary_values_omitted', lambda r: [row.update(implementations={k:{} for k in row['implementations']}) for row in r['measurements']['summary']])
        case(n, 'observed_slowdowns_erased', lambda r: r['measurements'].update(all_observed_slowdowns=[]))
        case(n, 'function_byte_evidence_empty', lambda r: r['function_bytes'].update(functions={}))
        case(n, 'native_C_build_failed', lambda r: r['builds']['hepta_c'].update(ok=False, status='not_run'))
        case(n, 'correctness_input_counts_erased', lambda r: r['correctness'].update(counts=[]))
        case(n, 'missing_profile_rejected', lambda r: r['correctness']['implementations'].remove('hepta_c_unroll'))

    from experiments.crossfile_eval.workspace_crash_evidence import validate_crash_case
    from experiments.crossfile_eval.records import seal_record
    crash_path = Path('/tmp/hepta-workspace-crashes-strict-20261024-01.json')
    if crash_path.exists():
        crash = json.loads(crash_path.read_text())
        # No hash mocking: per-case validator checks the actual historical
        # embedded compiler/profile. Matrix is expected to reject stale source.
        try:
            gate.require_qualification('production_workspace_crashes', crash)
        except Exception as exc:
            observations.append({'gate':'production_workspace_crashes','case':'historical_source_matrix',
                                 'actual':'rejected','expected':'rejected','matched':True,'diagnostic':str(exc)})
        else:
            observations.append({'gate':'production_workspace_crashes','case':'historical_source_matrix',
                                 'actual':'accepted','expected':'rejected','matched':False})
        for run in crash['runs']:
            validate_crash_case(run)
        changes = {
            'native_check_erased': lambda r: r['session']['events'][4].update(result={}),
            'worker_did_not_die': lambda r: r['session']['events'][5].update(process_returncode=0),
            'recovery_not_run': lambda r: r['session']['events'][7].update(ok=False),
            'native_cases_incomplete': lambda r: r['score'].update(passed=0),
            'bounded_claim_inflated': lambda r: r['claims'].update(power_failure_durability_proved=True),
            'namespace_erased': lambda r: r['session']['events'][7].update(namespace_required=False),
        }
        for label, mutate in changes.items():
            run = copy.deepcopy(crash['runs'][0]); mutate(run); run = seal_record(run)
            result = {'gate':'workspace_crash_case','case':label,'expected':'rejected','mutated_record_sha256':run['record_sha256']}
            try:
                validate_crash_case(run)
            except Exception as exc:
                result.update(actual='rejected',diagnostic=str(exc))
            else:
                result['actual']='accepted'
            result['matched']=result['actual']==result['expected'];observations.append(result)
    after = source.read_bytes()
    report = {'schema':'hepta.release-gate-independent-audit.v1','scope':'validator_tests_only_not_native_qualification',
              'source_path':str(source),'source_sha256_before':sha(before),'source_sha256_after':sha(after),
              'source_unchanged':before==after,
              'stateful_snapshot_mock':'original historical source snapshot only; tests validator structure, not current qualification',
              'input_reports':{k:{'path':str(v),'sha256':sha(v.read_bytes())} for k,v in paths.items()},
              'observations':observations,'unexpected_acceptances':sum(not o['matched'] and o['actual']=='accepted' for o in observations),
              'native_tests_performed':False}
    args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'output':str(args.output),'cases':len(observations),'unexpected_acceptances':report['unexpected_acceptances'],'source_unchanged':report['source_unchanged']}))


if __name__=='__main__':
    main()
