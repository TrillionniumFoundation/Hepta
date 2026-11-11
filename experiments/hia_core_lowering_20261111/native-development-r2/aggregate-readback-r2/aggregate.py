"""Read all three actual development phase originals; never relabel a cold or single-owner pass."""
import argparse
import json
import math
from pathlib import Path
import time
import traceback
from development_common import (
    CANDIDATE, CANDIDATE_TREE, PREPARE_ROOT, ROOTS, candidate_snapshot,
    digest, inspect_bundle, natural_owner, require, save, validate_group, verify_binding)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    request_raw = args.request.read_bytes()
    request = json.loads(request_raw)
    require(request['schema'] == 'hia.core-lowering-development-aggregate-request.v1'
            and request['candidate_commit'] == CANDIDATE
            and request['candidate_tree'] == CANDIDATE_TREE,
            'exact aggregate candidate is required')
    groups = ['component', 'original-machine', 'original-core']
    require([r['group'] for r in request['phases']] == groups,
            'all three original groups are mandatory')
    root = args.output.resolve()
    root.mkdir(mode=0o700, parents=False)
    (root / 'request.original.json').write_bytes(request_raw)
    started = time.monotonic()
    report = {
        'schema': 'hia.core-lowering-three-owned-development-groups.v1', 'status': 'STARTED',
        'scope': 'EXPLICIT_DEVELOPMENT_ONLY',
        'candidate_commit': CANDIDATE, 'candidate_tree': CANDIDATE_TREE,
        'single_default_qualifier_executed': False,
        'default_complete_qualifier_once_180_seconds_pass': False,
        'matching_source_cold_qualified': False,
        'independent_phase_owner_limits_seconds': [180, 180, 180],
        'original_compile_limits_seconds': {'wall': 20, 'CPU': 10},
        'original_caller_budgets_unchanged': True,
        'public_control_modes': 27, 'ABI_modes_including_private_fixture': 28,
        'hosted_object_primitives': 18, 'Emitter_still_hosted': True,
        'default_activated': False, 'whole_native_delivery': False, 'phases': [],
    }
    before, held = None, []
    try:
        source = PREPARE_ROOT / 'source'
        before = candidate_snapshot(source)
        report['source_before'] = save(root, 'source-before.json', before)
        original = inspect_bundle(PREPARE_ROOT / 'bundle/manifest.json', source)
        all_modes, totals, method_ids = set(), {'0': 0, '1': 0, '2': 0}, []
        owner_seconds, worker_seconds, preparation_identities = [], [], set()
        for phase in request['phases']:
            group = phase['group']
            require(phase['root'] == str(ROOTS[group]) and phase['job_id'],
                    'fixed phase root and actual job identity are required')
            pins = phase['files']
            require(type(pins) is list and len({p['path'] for p in pins}) == len(pins),
                    'unique original phase file bindings required')
            by_name = {}
            for pin in pins:
                path = Path(pin['path'])
                require(ROOTS[group] in path.parents, 'phase input escaped its original root')
                raw = verify_binding(pin)
                held.append(pin)
                by_name[path.relative_to(ROOTS[group]).as_posix()] = raw
            required = {'control.json', 'report.json', 'lifecycle.json', 'request.json',
                        'qualifier/report.json', 'source-before.json', 'source-after.json'}
            require(set(by_name) == required, 'complete original phase receipt population differs')
            control = json.loads(by_name['control.json'])
            worker = json.loads(by_name['report.json'])
            life = json.loads(by_name['lifecycle.json'])
            selected = json.loads(by_name['qualifier/report.json'])
            frozen = json.loads(by_name['request.json'])
            require(control['status'] == 'PASS' and control['phase'] == group
                    and control['candidate_commit'] == CANDIDATE
                    and control['candidate_tree'] == CANDIDATE_TREE
                    and control['lifecycle']['supervisor_returncode'] == 0
                    and control['lifecycle']['receipt_sha256'] == digest(by_name['lifecycle.json'])
                    and set(control['lifecycle']) == set(life) | {'supervisor_returncode', 'receipt_sha256'}
                    and {k: v for k, v in control['lifecycle'].items()
                         if k not in {'supervisor_returncode', 'receipt_sha256'}} == life
                    and life.get('qualification_seconds') == 180 and life.get('cleanup_seconds') == 3
                    and control['inner_report_sha256'] == digest(by_name['report.json'])
                    and control['natural_owner_success'] is True
                    and control['natural_owner_cleanup'] is True
                    and natural_owner(life) and life.get('status') == 'OWNED_PROCESS_COMPLETED'
                    and life.get('returncode') == 0, 'actual phase did not finish naturally')
            require(worker['status'] == 'EXPLICIT_DEVELOPMENT_GROUP_PASS_NOT_COMPLETE_QUALIFICATION'
                    and worker['group'] == group and worker['candidate_commit'] == CANDIDATE
                    and worker['candidate_tree'] == CANDIDATE_TREE
                    and worker['source_stable'] is True and worker['inputs_stable'] is True
                    and worker['qualifier_returncode'] == 0
                    and worker['qualifier_report']['sha256'] == digest(by_name['qualifier/report.json']),
                    'actual complete phase report differs')
            require(json.loads(by_name['source-before.json']) == before
                    and json.loads(by_name['source-after.json']) == before,
                    'phases did not execute the same complete exact source')
            require(frozen['phase'] == group and frozen['candidate_commit'] == CANDIDATE
                    and frozen['candidate_tree'] == CANDIDATE_TREE
                    and frozen['group'] == phase['group_identity'],
                    'actual frozen group request differs')
            for pin in frozen['input_bindings']:
                verify_binding(pin)
                held.append(pin)
            checked = validate_group(selected, group, phase['group_identity'], source, original)
            all_modes.update(checked['actual_modes'])
            for key in totals:
                totals[key] += checked['actual_native_step_statuses'][key]
            method_ids.extend(selected['groups'][0]['executed_ids'])
            preparation_identities.add((worker['preparation_job_id'], worker['preparation_report_sha256']))
            owner_seconds.append(control['seconds'])
            worker_seconds.append(worker['qualifier_seconds'])
            report['phases'].append({'group': group, 'job_id': phase['job_id'],
                'files': pins, 'validation': checked, 'owner_seconds': control['seconds'],
                'qualifier_seconds': worker['qualifier_seconds']})
        abi = json.loads((source / 'hepta/hia_core_lowering_abi.json').read_bytes())
        require(len(preparation_identities) == 1 and len(method_ids) == 113
                and len(set(method_ids)) == 113, 'original three-group population or preparation differs')
        require(set(abi['modes']) == all_modes and len(all_modes) == 28
                and all(totals.values()), 'complete 27 product modes and private28 witness not observed')
        require(all(type(n) in (int, float) and math.isfinite(n) and n >= 0 for n in owner_seconds + worker_seconds),
                'actual measured development costs are missing')
        report['actual_methods'] = 113
        report['actual_modes'] = sorted(all_modes)
        report['actual_native_step_statuses'] = totals
        report['actual_owner_seconds_sum'] = sum(owner_seconds)
        report['actual_qualifier_seconds_sum'] = sum(worker_seconds)
        report['preparation_identity'] = list(next(iter(preparation_identities)))
        report['status'] = 'EXPLICIT_DEVELOPMENT_THREE_GROUPS_PASS_NOT_COLD_QUALIFIED'
    except BaseException:
        report['status'] = 'HOLD'
        report['exception'] = traceback.format_exc()
    finally:
        try:
            if before is not None:
                after = candidate_snapshot(PREPARE_ROOT / 'source')
                report['source_after'] = save(root, 'source-after.json', after)
                require(after == before, 'complete source changed during aggregate readback')
            for pin in held:
                verify_binding(pin)
        except BaseException:
            report['status'] = 'HOLD'
            report['final_identity_error'] = traceback.format_exc()
        report['readback_seconds'] = time.monotonic() - started
        save(root, 'report.json', report)
        print(json.dumps({k: report.get(k) for k in ('schema', 'scope', 'status',
            'actual_methods', 'actual_owner_seconds_sum', 'actual_qualifier_seconds_sum',
            'readback_seconds', 'exception', 'final_identity_error')}, sort_keys=True), flush=True)
    return 0 if report['status'] == 'EXPLICIT_DEVELOPMENT_THREE_GROUPS_PASS_NOT_COLD_QUALIFIED' else 1

if __name__ == '__main__':
    raise SystemExit(main())
