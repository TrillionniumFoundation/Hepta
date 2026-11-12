"""Create-only outer request. Root review precedes its one invocation.

Original run_owned provides 180 seconds plus 3 seconds cleanup. Each child
uses the same unchanged owner with the declared 20/5/20/5 limits. No stage,
unknown request, previous source run or existing product is retried here.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sys
import time
import traceback

CONTROL = Path(__file__).resolve().parent
ROOT = CONTROL.parent
sys.path.insert(0, str(CONTROL))
from common import require, read_file, pin, save
from support import (read_policy, frozen, private_directory, environment, load_owner,
                     owner_paths, closed_owner, natural_owner, capture_closed, stage_command)
from original_current_compiler import json_original
from case_contract import RUNTIME_IDS, LIFETIME_IDS, EXPECTED_HIA_RETURNS, EXPECTED_C_PUMP_CALLS
from verify import c_image, hia_image, finite_cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    raw, request_pin = read_file(args.request, 262144)
    require(request_pin['sha256'] == args.sha256, 'fixed unique launch request differs')
    request = json_original(raw)
    policy_path = ROOT / request['policy_path']
    policy, policy_pin = read_policy(policy_path, request['policy_sha256'])
    require(request['schema'] == 'hia.cli-json.C-runtime-lifetime-request.v1'
            and request['operation_key'] == policy['operation_key']
            and request['operation_root'] == policy['operation_root']
            and request['qualification_seconds'] == 180 and request['cleanup_seconds'] == 3,
            'new operation identity or original limit differs')
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and list(sys.version_info[:3]) == [3, 12, 14]
            and str(Path(sys.executable).resolve()) == policy['python']['path'],
            'actual launcher interpreter differs')
    before = frozen(policy)
    folder = Path(policy['operation_root'])
    require(not os.path.lexists(folder), 'create-only actual directory already exists; reconcile it')
    disk = shutil.disk_usage(folder.parent)
    space = os.statvfs(folder.parent)
    require(disk.free >= 128 << 20 and space.f_favail >= 4096,
            'new finite evidence resource admission failed')
    private_directory(folder)
    private_directory(folder / 'owned')
    private_directory(folder / 'work')
    # The child creates its temporary directory only after its actual entry.
    work = folder / 'work'
    env = environment(work / 'temporary')
    command = [policy['python']['path'], '-I', '-S', '-B', str(CONTROL / 'worker.py'),
               '--policy', str(policy_path), '--policy-sha256', policy_pin['sha256']]
    paths = owner_paths(folder / 'owned', 'outer')
    final = {'schema': 'hia.cli-json.C-runtime-lifetime-terminal.v1', 'status': 'HOLD',
        'operation_key': policy['operation_key'], 'request_sha256': args.sha256,
        'policy_sha256': policy_pin['sha256'], 'owner_attempted': False, 'closed_owner': False,
        'natural_owner': False, 'complete_original_inventory': False, 'source_preserved': False,
        'runtime_expected_ids': list(RUNTIME_IDS), 'lifetime_expected_ids': list(LIFETIME_IDS),
        'original17_executed': False, 'original46_executed': False, 'full_graph_qualified': False,
        'body_driver_qualified': False, 'fresh_cold': False, 'default_changed': False,
        'started_ns': time.monotonic_ns()}
    save(folder / 'INPUTS-BEFORE.json', before)
    save(folder / 'RESOURCE-PREFLIGHT.json', {'disk_free': disk.free, 'inode_free': space.f_favail,
         'required_free_bytes': 128 << 20, 'evidence_maximum_bytes': 64 << 20,
         'point_in_time_only': True})
    save(folder / 'INTENT.json', {'command': command, 'cwd': str(ROOT), 'env': env, 'paths': paths,
         'qualification_seconds': 180, 'cleanup_seconds': 3,
         'all_C_runtime_HIA_lifetime_and_worker_readback_inside_single_owner': True})
    try:
        owner = load_owner()
        final['owner_attempted'] = True
        wrapper = owner.run_owned(command, cwd=str(ROOT), env=env,
            **{key: Path(value) for key, value in paths.items()}, qualification_seconds=180, cleanup_seconds=3)
        save(folder / 'WRAPPER.json', wrapper)
        require(wrapper.get('cleanup', {}).get('complete') is True
                and wrapper.get('cleanup', {}).get('observed_echild') is True
                and wrapper.get('cleanup', {}).get('leader_reaped') is True
                and wrapper.get('cleanup', {}).get('remaining_direct_children') == [],
                'outer owner unknown; no child-output reads permitted')
        life_raw, life_pin = read_file(Path(paths['receipt_path']), 4 << 20)
        request_raw, owner_request_pin = read_file(Path(paths['receipt_path'] + '.request.json'), 262144)
        life = closed_owner(wrapper, life_raw, request_raw, command=command, cwd=ROOT,
                            env=env, paths=paths, seconds=180, parent=os.getpid())
        final.update(closed_owner=True, owner_original=life_pin, owner_request_original=owner_request_pin)
        # Failure raw originals are observed and retained before success is
        # required. A failed stage does not cause downstream stages to run.
        inventory = capture_closed(work, 64 << 20)
        final['actual_original_inventory'] = save(folder / 'CLOSED-ORIGINALS.json', inventory)
        final['complete_original_inventory'] = inventory['status'] == 'COMPLETE_ACTUAL_ORIGINALS'
        natural_owner(wrapper, life)
        final['natural_owner'] = True
        require(final['complete_original_inventory'], 'closed finite original inventory is incomplete')
        report_raw, report_pin = read_file(work / 'REPORT.json', 4 << 20)
        report = json_original(report_raw)
        require(report['schema'] == 'hia.cli-json.C-runtime-lifetime-worker.v1'
                and report['status'] == 'FINITE_C_RUNTIME_LIFETIME_PASS_PENDING_OUTER_CLOSURE'
                and report['policy_sha256'] == policy_pin['sha256'] and report['errors'] == []
                and report['expected_stages'] == report['attempted_stages'] == report['completed_stages']
                    == ['c-compile', 'runtime', 'hia-compile', 'lifetime']
                and report['source_preserved'] is True and report['inner_closure_confirmed'] is True
                and report['runtime_ids'] == list(RUNTIME_IDS) and report['lifetime_ids'] == list(LIFETIME_IDS)
                and report['actual_lifetime_entry_returns'] == sum(EXPECTED_HIA_RETURNS)
                and report['actual_c_pump_calls'] == sum(EXPECTED_C_PUMP_CALLS),
                'full finite worker failed or changed its population')
        c_join = c_image(policy, work)
        hia_join = hia_image(policy, work)
        for label, seconds in (('c-compile', 20), ('runtime', 5), ('hia-compile', 20), ('lifetime', 5)):
            observed = report['owners'][label]
            intent_raw, _ = read_file(work / 'owners' / (label + '.INTENT.json'), 262144)
            intent = json_original(intent_raw)
            require(intent == observed['intent']
                    and intent['command'] == stage_command(policy, policy_path, policy_pin['sha256'],
                                                          label, dso=c_join, image=hia_join)
                    and intent['cwd'] == str(ROOT)
                    and intent['env'] == environment(work / 'temporary', compiler=label == 'c-compile'),
                    'actual inner intent/independently derived command differs')
            inner_paths = owner_paths(work / 'owners', label)
            raw_life, _ = read_file(Path(inner_paths['receipt_path']), 4 << 20)
            raw_request, _ = read_file(Path(inner_paths['receipt_path'] + '.request.json'), 262144)
            raw_wrapper, _ = read_file(work / 'owners' / (label + '.WRAPPER.json'), 4 << 20)
            require(json_original(raw_wrapper) == observed['wrapper'], 'actual inner wrapper differs')
            inner = closed_owner(observed['wrapper'], raw_life, raw_request,
                command=intent['command'], cwd=ROOT, env=intent['env'], paths=inner_paths,
                seconds=seconds, parent=life['qualification_pid'])
            natural_owner(observed['wrapper'], inner)
            require(intent['seconds'] == seconds and intent['cleanup_seconds'] == 3,
                    'actual inner limit differs')
        runtime_join = finite_cases(policy, policy_pin['sha256'], work, 'runtime', c_join)
        lifetime_join = finite_cases(policy, policy_pin['sha256'], work, 'lifetime', c_join, hia_join)
        final.update(status='FINITE_C_RUNTIME_LIFETIME_PASS', worker_report=report_pin,
                     c_compile=c_join, hia_compile=hia_join, runtime=runtime_join, lifetime=lifetime_join)
    except BaseException:
        final['status'] = 'HOLD'
        final['error'] = traceback.format_exc()
    finally:
        if final['closed_owner']:
            try:
                after = frozen(policy)
                save(folder / 'INPUTS-AFTER.json', after)
                final['source_preserved'] = before == after
                require(final['source_preserved'] and read_file(args.request, 262144)[1] == request_pin
                        and read_file(policy_path, 2 << 20)[1] == policy_pin,
                        'complete frozen inputs/request changed during one invocation')
            except BaseException:
                final['status'] = 'HOLD'; final['preservation_error'] = traceback.format_exc()
        else:
            final['preservation_error'] = 'OWNER_UNKNOWN: no child or source reread after unconfirmed closure'
        final['elapsed_ns'] = time.monotonic_ns() - final['started_ns']
        save(folder / 'FINAL.json', final)
    print(json.dumps({'status': final['status'], 'closed_owner': final['closed_owner'],
                      'natural_owner': final['natural_owner'], 'output': str(folder),
                      'elapsed_ns': final['elapsed_ns']}))
    return 0 if final['status'] == 'FINITE_C_RUNTIME_LIFETIME_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
