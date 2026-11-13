"""Exactly one fresh local evidence owner; all original failures retained."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
if 'v92_view_common' in sys.modules:
    c = sys.modules['v92_view_common']
else:
    spec = importlib.util.spec_from_file_location('v92_view_common', ROOT / 'control/common.py')
    c = importlib.util.module_from_spec(spec); sys.modules[spec.name] = c; spec.loader.exec_module(c)
io, require = c.io, c.require
op = c.module('v92_view_operation', ROOT / 'control/operation.py')

def bound_closed(guard, request, policy):
    life, cleanup = guard.get('lifecycle', {}), guard.get('lifecycle', {}).get('cleanup', {})
    require(guard.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
            and guard.get('command') == request['command'] and guard.get('cwd') == request['cwd']
            and guard.get('external_controller_seconds') == 900
            and guard.get('lifecycle_implementation_sha256') == policy['lifecycle_implementation_sha256']
            and guard.get('source_identities_before') == request['source_identities']
            and life.get('qualification_seconds') == 900 and life.get('cleanup_seconds') == 3,
            'current guardian is not bound to exact source/request/900+3')
    return (life.get('subreaper_enabled') is True and life.get('event_overflow') is False
            and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
            and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children') == []
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == [])

def natural(guard, request, returncode):
    life = guard['lifecycle']
    return (returncode == 0 and guard.get('status') == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and guard.get('input_identity_preserved') is True
            and guard.get('source_identities_after') == request['source_identities']
            and guard.get('qualification') is None and guard.get('whole_native_delivery_qualified') is False
            and life.get('status') == 'OWNED_PROCESS_COMPLETED' and life.get('returncode') == 0
            and life.get('exit_observed_before_deadline') is True and life.get('timed_out') is False
            and life.get('interrupted_signals') == [] and life.get('owner_error') is None
            and not any(x.get('kind') == 'owned_child_sigkill' for x in life.get('events', [])))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider-references-sha256', required=True)
    parser.add_argument('--proxy-configuration-sha256', required=True)
    args = parser.parse_args()
    policy, policy_pin, policy_raw = c.policy_read(); roots = op.volume_roots(policy)
    runtime = c.seal(Path(sys.executable).resolve(), 64 << 20)
    require(all(runtime[k] == policy['runtime'][k] for k in ('path', 'bytes', 'sha256', 'identity'))
            and list(sys.version_info[:3]) == [3, 12, 14], 'fixed system interpreter identity differs')
    original_inputs = c.inputs(policy)
    source_admission = c.module('v92_actual_source20_gate', ROOT / 'controls/launch_controls.py').actual_source_gate()
    refs, refs_pin, proxy, proxy_pin = c.private_inputs(policy, args.provider_references_sha256,
                                                     args.proxy_configuration_sha256)
    environment = io.configured_environment(proxy)
    require(not any(os.path.lexists(path) for path in roots.values()), 'fresh output roots required; no replay')
    devices = {}; capacity = {}; budgets = {}
    for key, root in roots.items():
        require(root.is_absolute() and root.parent == Path(policy['volumes'][key]['parent']), 'fixed output parent differs')
        with c.held_parent(root) as (fd, _):
            parent_stat = os.fstat(fd)
            require(parent_stat.st_dev == policy['volumes'][key]['parent_device'], 'output volume device differs')
            devices[key] = parent_stat.st_dev
        probe = c.VolumeBudget(root.parent, policy['volumes'][key]['limits'])
        capacity[key] = probe.capacity()
    require(devices['tmp'] != devices['workspace'], 'distinct fixed volume capacity proof no longer applies')
    # The single 720-second deadline includes mkdir, owner, both full reads and
    # final publication. No finalizer budget reset is allowed.
    began = time.monotonic(); deadline = began + 720
    clock = {'schema': 'hia.v92-three-part-single-clock.v1', 'policy_sha256': policy_pin['sha256'],
             'start': began, 'deadline': deadline, 'seconds': 720}
    for key, root in roots.items():
        c.mkdir(root); budgets[key] = c.VolumeBudget(root, policy['volumes'][key]['limits'])
    for path in (roots['tmp'] / 'guard', roots['tmp'] / 'selected', roots['workspace'] / 'readback'):
        c.mkdir(path)
    parent = roots['workspace']; parent_budget = budgets['workspace']
    c.create(parent / 'POLICY.original.json', policy_raw, raw=True, budget=parent_budget, category='parent', deadline=deadline)
    c.create(parent / 'CAPACITY-BEFORE.json', capacity, budget=parent_budget, category='parent', deadline=deadline)
    c.create(parent / 'ACTUAL-SOURCE20-ADMISSION.json', source_admission, budget=parent_budget, category='parent', deadline=deadline)
    clock_pin = c.create(parent / 'CLOCK.json', clock, budget=parent_budget, category='parent', deadline=deadline)
    c.create(parent / 'PARENT-INPUTS-BEFORE.json', original_inputs, budget=parent_budget, category='parent', deadline=deadline)
    c.create(parent / 'PRIVATE-INPUT-RECEIPTS.json', {'refs': refs_pin, 'proxy': proxy_pin,
              'values_not_published': True}, budget=parent_budget, category='parent', deadline=deadline)
    command = [runtime['path'], '-I', '-S', '-B', str(ROOT / 'control/worker.py'),
               '--provider-references-sha256', refs_pin['sha256'], '--proxy-configuration-sha256', proxy_pin['sha256']]
    identities = {name: row['sha256'] for name, row in original_inputs.items()}
    identities.update({str(ROOT / 'POLICY.json'): policy_pin['sha256'], runtime['path']: runtime['sha256'],
                       refs_pin['path']: refs_pin['sha256'], proxy_pin['path']: proxy_pin['sha256'],
                       clock_pin['path']: clock_pin['sha256']})
    request = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 900,
               'command': command, 'cwd': str(ROOT), 'source_identities': identities}
    request_raw = io.wire(request); require(len(request_raw) <= 262144, 'original guardian request bound exceeded')
    request_path = roots['tmp'] / 'guard/request.json'
    request_pin = c.create(request_path, request_raw, raw=True, budget=budgets['tmp'], category='parent', deadline=deadline)
    launch = [runtime['path'], '-I', '-S', '-B', str(ROOT / 'control/guardian.py'),
              '--config', str(request_path), '--config-sha256', request_pin['sha256'],
              '--implementation', str(ROOT / 'control/process_owner_impl.py')]
    c.create(parent / 'LAUNCH-INTENT.json', {'command': launch, 'cwd': str(ROOT), 'environment': environment,
             'controller_seconds': 900, 'cleanup_seconds': 3, 'complete_seconds': 720, 'clock': clock,
             'network_retries': 0, 'one_owner_invocation': True, 'source_identities': identities},
             budget=parent_budget, category='parent', deadline=deadline)
    final = {'schema': 'hia.v92-three-container-view-final.v1', 'status': 'HOLD', 'closed_owner': False,
             'natural_owner': False, 'whole_available_originals_independently_read': False,
             'original_CI_failure_preserved': True, 'original_receiver_HOLD_preserved': True,
             'product_execution': False, 'whole_reconstruction_file_created': False,
             'private_inputs_not_published': True, 'complete_observed_output_custody': False,
             'clock': clock, 'errors': []}
    try:
        io.check_deadline(deadline)
        with (roots['tmp'] / 'supervisor.stdout.log').open('xb') as stdout, (roots['tmp'] / 'supervisor.stderr.log').open('xb') as stderr:
            done = subprocess.run(launch, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                  stdout=stdout, stderr=stderr, check=False)
        c.create(parent / 'LAUNCH-RETURN.json', {'returncode': done.returncode, 'elapsed': time.monotonic() - began,
                 'owner_replayed': False}, category='parent', budget=parent_budget)
        # The boundary receipt and our request are read before child evidence.
        guard, guard_pin, _ = c.document(roots['tmp'] / 'guard/guardian.json')
        actual_request, actual_request_pin, actual_raw = c.document(request_path, 262144)
        require(actual_request == request and actual_request_pin == request_pin and actual_raw == request_raw,
                'actual closed owner request changed')
        final['closed_owner'] = bound_closed(guard, request, policy)
        require(final['closed_owner'], 'unknown current ownership; do not read child outputs')
        final['guardian'] = guard_pin; final['natural_owner'] = natural(guard, request, done.returncode)
        io.check_deadline(deadline)
        originals, totals = op.observed_outputs(policy, roots, deadline)
        final['complete_observed_output_custody'] = True
        # Reconstruct budgets from all actual bytes, including guardian outputs.
        budgets = {key: c.VolumeBudget(root, policy['volumes'][key]['limits'], totals[key]) for key, root in roots.items()}
        parent_budget = budgets['workspace']
        c.create(parent / 'PARENT-ORIGINALS.json', {'all_observed_files_complete': True, 'files': originals,
                 'cutoff_before_parent_validation_receipts': True, 'after_current_bound_ECHILD': True},
                 budget=parent_budget, category='parent', deadline=deadline)
        require(final['natural_owner'], 'closed original reader did not exit naturally successfully')
        require(not os.path.lexists(parent / 'WORKER-FINALIZATION-HOLD.json'), 'worker final publication failed')
        worker, worker_pin, _ = c.document(parent / 'WORKER-RESULT.json', deadline=deadline)
        require(worker.get('status') == 'COMPLETE_THREE_CONTAINER_VIEW_READ_NOT_QUALIFICATION'
                and worker.get('errors') == [] and worker.get('clock') == clock
                and worker.get('policy') == policy_pin and worker.get('private_refs') == refs_pin
                and worker.get('private_proxy') == proxy_pin and worker.get('source_inputs_preserved') is True
                and worker.get('product_execution') is False and worker.get('whole_reconstructed_file_written') is False,
                'complete current worker result differs')
        io.require_elapsed(worker.get('elapsed_from_single_clock'), 720)
        require([x['ordinal'] for x in worker['parts']] == [0, 1, 2]
                and all(x['download']['status'] == 'ONE_GET_TWO_FULL_SEALS_PASS'
                        and x['download']['get_attempts'] == 1 for x in worker['parts']), 'three one-GET transport seals missing')
        containers, specs = op.read_containers(policy, roots, deadline)
        require(containers == worker['containers'], 'independent complete container evidence differs')
        original = op.read_original(policy, roots, budgets, specs, deadline, verify=True)
        require(original == worker['original'], 'independent original bodies or captured originals differ')
        c.create(parent / 'PARENT-INDEPENDENT-READBACK.json', {'containers': containers, 'original': original,
                 'complete_body_read': True, 'not_product_qualification': True},
                 budget=parent_budget, category='parent', deadline=deadline)
        after = c.inputs(policy, deadline); require(after == original_inputs, 'frozen source changed through final readback')
        refs_after, rp, proxy_after, pp = c.private_inputs(policy, refs_pin['sha256'], proxy_pin['sha256'])
        require(refs_after == refs and rp == refs_pin and proxy_after == proxy and pp == proxy_pin, 'private input identity changed')
        worker_after, worker_after_pin, _ = c.document(parent / 'WORKER-RESULT.json', deadline=deadline)
        require(worker_after == worker and worker_after_pin == worker_pin, 'worker result changed during independent readback')
        c.create(parent / 'PARENT-INPUTS-AFTER.json', after, budget=parent_budget, category='parent', deadline=deadline)
        for budget in budgets.values(): budget.capacity()
        final.update(status='THREE_CONTAINERS_ALL_ORIGINAL_BODIES_READ_ONLY_PASS', worker=worker_pin,
                     whole_available_originals_independently_read=True,
                     missing_expected_originals=original['index']['missing_expected'],
                     elapsed_single_clock=time.monotonic() - began)
        io.require_elapsed(final['elapsed_single_clock'], 720)
    except BaseException as error:
        final['status'] = 'HOLD'; final['errors'].append(io.safe_error(error))
    final['elapsed_single_clock'] = time.monotonic() - began
    try:
        c.create(parent / 'FINAL.json', final, budget=parent_budget, category='parent',
                 deadline=deadline if final['status'] != 'HOLD' else None)
        if final['status'] != 'HOLD': io.check_deadline(deadline)
    except BaseException as error:
        final['status'] = 'HOLD'; final['errors'].append(io.safe_error(error))
        # Small emergency receipt; no child traversal or retry follows failure.
        c.create(parent / 'FINAL-PUBLICATION-HOLD.json', final)
    print(json.dumps({'status': final['status'], 'closed_owner': final['closed_owner'],
                      'original_failures_preserved': True, 'product_executed': False}), flush=True)
    return 0 if final['status'] == 'THREE_CONTAINERS_ALL_ORIGINAL_BODIES_READ_ONLY_PASS' and not final['errors'] else 1

if __name__ == '__main__':
    try: raise SystemExit(main())
    except SystemExit: raise
    except BaseException as error:
        print(json.dumps({'status': 'PRELAUNCH_OR_PARENT_HOLD', 'error': io.safe_error(error)}), flush=True)
        raise SystemExit(1)
