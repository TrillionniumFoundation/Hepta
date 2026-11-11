"""Read original terminal files; never launch, resume, repair or rerun a job.

This acceptance adds no product success. It requires the original v8 full PASS,
the original guardian's exact-source receipt and a naturally closed lifecycle.
UNKNOWN/missing records and killed surviving descendants remain HOLD.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

from driver import ROOT, DEPENDENCIES, validate_request, read_json, stable_file, require
from driver import materialization_ok, preparation_ok, original_prerequisite_selection, wire
from driver import verify_fixture_supply


REQUIRED_GATES = frozenset((
    'source_bound_prerequisites_admitted', 'prerequisites_preserved',
    'json_preflight_complete_module', 'agent_journal_source_and_native',
    'composite_types_helpers_and_complete_nominal_lowering', 'journal_selected_ordinary_callers',
    'json_wire_complete_module', 'ordinary_json_wire_entry_complete_module',
    'worker_report_complete_module', 'machine_plan_complete_module', 'linked_observer_complete_module',
    'machine_plan_selected_ordinary_callers', 'json_wire_selected_ordinary_callers',
    'json_wire_cache_complete_module', 'cli_complete_module_and_retained_cold_bundle',
    'machine_encoding_complete_component_and_original_callers', 'original_selected_caller_denominators_preserved',
))
ALLOWED_EVENTS = frozenset(('qualification_started', 'owned_child_observed',
                            'qualification_exit_observed', 'owned_child_reaped'))


def natural_guardian(value):
    require(value.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and value.get('status') == 'GUARDIAN_FULL_RETAINED_PASS'
            and value.get('external_controller_seconds') == 10800
            and value.get('cold_180_second_gate_modified') is False
            and value.get('input_identity_preserved') is True
            and value.get('lifecycle_implementation_sha256') == DEPENDENCIES['process_owner_impl.py'],
            'original guardian did not qualify the complete exact-source run')
    lifecycle = value.get('lifecycle', {})
    cleanup = lifecycle.get('cleanup', {})
    events = lifecycle.get('events')
    require(lifecycle.get('status') == 'OWNED_PROCESS_COMPLETED'
            and lifecycle.get('qualification_seconds') == 10800
            and lifecycle.get('returncode') == 0 and lifecycle.get('exit_observed_before_deadline') is True
            and lifecycle.get('timed_out') is False and lifecycle.get('subreaper_enabled') is True
            and lifecycle.get('qualification_started') is True
            and lifecycle.get('interrupted_signals') == [] and not lifecycle.get('owner_error')
            and lifecycle.get('event_overflow') is False,
            'external lifecycle is missing, interrupted, failed or timed out')
    require(type(events) is list and bool(events)
            and all(type(event) is dict and event.get('kind') in ALLOWED_EVENTS for event in events),
            'owned descendants were killed or their event history is incomplete')
    require(cleanup.get('attempted') is True and cleanup.get('complete') is True
            and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
            and cleanup.get('remaining_direct_children') == [],
            'original kernel reap/ECHILD/empty-child proof is incomplete')


def verify(request):
    validate_request(request)
    guardian, guardian_pin = read_json(ROOT / 'guard/guardian.json')
    natural_guardian(guardian)
    expected_inputs = guardian.get('source_identities_before')
    require(type(expected_inputs) is dict and expected_inputs
            and guardian.get('source_identities_after') == expected_inputs, 'guardian before/after input identity differs')
    for path, expected in expected_inputs.items():
        stable_file(path, expected)
    for path, expected in guardian.get('logs', {}).items():
        require(Path(path).parent == ROOT / 'guard', 'guardian log names an unexpected path')
        stable_file(path, expected)
    source = request['source']
    outcome, outcome_pin = read_json(ROOT / 'q/QUALIFICATION.json')
    require(guardian.get('qualification', {}).get('path') == outcome_pin['path']
            and guardian['qualification'].get('sha256') == outcome_pin['sha256'],
            'guardian does not bind this original v8 result')
    require(outcome.get('schema') == 'hepta.hia.native-rewrite-qualification.v5'
            and outcome.get('harness_revision') == 'v8' and outcome.get('status') == 'FULL_RETAINED_PASS'
            and outcome.get('cold_qualified') is True and outcome.get('source_preserved') is True
            and outcome.get('harness_preserved') is True
            and outcome.get('full_retained_regression_requested') is True
            and outcome.get('full_retained_regression_executed') is True
            and outcome.get('full_retained_regression_qualified') is True
            and outcome.get('whole_native_delivery_qualified') is False,
            'exact original v8 full result is incomplete')
    identity = outcome.get('source_identity', {})
    require(identity.get('head') == source['commit'] and identity.get('tree') == source['tree']
            and identity.get('raw_git_tree_blobs_and_modes_checked') is True, 'v8 source identity differs')
    gates = outcome.get('mandatory_v8_gates')
    require(type(gates) is dict and set(gates) == REQUIRED_GATES
            and all(value is True for value in gates.values()), 'v8 mandatory gate is absent or not true')
    steps = outcome.get('steps')
    require(type(steps) is list and steps and all(step.get('passed') is True for step in steps),
            'an original workflow step did not pass')
    full = outcome.get('full_retained_regression', {})
    require(full.get('passed') is True and full.get('completed') is True and full.get('discovery') is True
            and full.get('exact_loaded_executed_ids') is True
            and type(full.get('tests_run')) is int and full['tests_run'] > 0,
            'complete retained discovery was not executed successfully')
    require(full.get('result', {}).get('path') == str(ROOT / 'q/full-retained-regression.json'),
            'full discovery result names another file')
    discovery, discovery_pin = read_json(full['result']['path'], full['result']['sha256'])
    loaded, executed = discovery.get('loaded_test_ids'), discovery.get('executed_test_ids')
    require(type(loaded) is list and loaded and all(type(name) is str for name in loaded)
            and executed == loaded and len(loaded) == discovery.get('expected_test_count')
            == discovery.get('tests_run') == full['tests_run'] and discovery.get('successful') is True
            and all(discovery.get(key) == [] for key in ('errors', 'failures', 'skipped',
                      'expected_failures', 'unexpected_successes')), 'complete test IDs or zero-anomaly contract differs')
    materialized, materialized_pin = read_json(ROOT / 'source-materialization.json')
    materialization_ok(materialized, request)
    prep, prep_pin = read_json(ROOT / 'p/preparation.json')
    environment, environment_pin = read_json(ROOT / 'p/environment.json')
    preparation_ok(prep, environment, request)
    original_prerequisite_selection(prep, request)
    supplied_fixtures = verify_fixture_supply(request)
    cold_manifest = outcome.get('cold_source_manifest')
    require(type(cold_manifest) is dict and len(cold_manifest) == 682
            and cold_manifest.get('docs/HIA_SELFHOST_CORE_SUPPORT.json') == source['contract_sha256'],
            'full result cold closure differs')
    cold_path = outcome.get('cold_report', {})
    require(cold_path.get('path') == str(ROOT / 'q/cold.json'), 'cold report names another file')
    cold, cold_pin = read_json(cold_path['path'], cold_path['sha256'])
    require(cold.get('status') == 'COLD_SELFHOST_REPLAY_PASS' and cold.get('source_manifest') == cold_manifest
            and type(cold.get('checks')) is dict and cold['checks']
            and all(value is True for value in cold['checks'].values()), 'original cold result did not pass')
    return {'schema': 'hia.v67.full-qualification-terminal-acceptance.v1',
            'status': 'EXACT_SOURCE_FULL_RETAINED_PASS_WITH_NATURAL_GUARDIAN',
            'head': source['commit'], 'tree': source['tree'],
            'guardian': guardian_pin, 'qualification': outcome_pin, 'full_discovery': discovery_pin,
            'source_materialization': materialized_pin, 'preparation': prep_pin,
            'source_bound_three_fixture_supply': supplied_fixtures,
            'environment': environment_pin, 'cold': cold_pin,
            'tests_run': full['tests_run'], 'complete_loaded_executed_ids': True,
            'no_skips_expected_failures_or_exclusions': True,
            'remaining_direct_children': [], 'forced_live_child_cleanup_accepted': False,
            'original_product_limits_modified': False, 'test_or_product_execution_performed_by_verifier': False,
            'whole_native_delivery_qualified': False,
            'h_transport_job_status_independently_observed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--request-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.output == ROOT / 'ACCEPTANCE.json', 'terminal acceptance must use the new dedicated output')
    request, record = read_json(args.request, args.request_sha256)
    result = {'schema': 'hia.v67.full-qualification-terminal-acceptance.v1', 'status': 'HOLD',
              'request': record, 'test_or_product_execution_performed_by_verifier': False,
              'whole_native_delivery_qualified': False}
    try:
        result.update(verify(request))
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error))
    with args.output.open('xb') as stream:
        stream.write(wire(result))
    print(json.dumps({'status': result['status'], 'output': str(args.output)}))
    return 0 if result['status'] == 'EXACT_SOURCE_FULL_RETAINED_PASS_WITH_NATURAL_GUARDIAN' else 1


if __name__ == '__main__':
    raise SystemExit(main())
