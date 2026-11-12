"""One finite C/runtime/lifetime sequence inside the original 180/3 owner."""
from __future__ import annotations

import argparse
from hashlib import sha256
import os
from pathlib import Path
import sys
import time
import traceback

CONTROL = Path(__file__).resolve().parent
ROOT = CONTROL.parent
sys.path.insert(0, str(CONTROL))
from common import require, read_file, pin, save
from support import (read_policy, frozen, private_directory, environment,
                     load_owner, run_step, stage_command)
from original_current_compiler import current_compiler
from verify import c_image, hia_image, finite_cases
from case_contract import RUNTIME_IDS, LIFETIME_IDS, UNEXECUTED_SCOPES


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    args = parser.parse_args()
    policy, policy_pin = read_policy(args.policy, args.policy_sha256)
    work = Path(policy['operation_root']) / 'work'
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and str(Path(sys.executable).resolve()) == policy['python']['path']
            and list(sys.version_info[:3]) == [3, 12, 14]
            and dict(os.environ) == environment(work / 'temporary'),
            'actual finite worker runtime/environment differs')
    require(work.is_dir() and not any(work.iterdir()), 'new finite work directory required')
    for name in ('temporary', 'owners', 'c-build', 'hia-build', 'runtime', 'lifetime'):
        private_directory(work / name)
    report = {'schema': 'hia.cli-json.C-runtime-lifetime-worker.v1', 'status': 'HOLD',
        'policy_sha256': args.policy_sha256, 'expected_stages': ['c-compile', 'runtime', 'hia-compile', 'lifetime'],
        'attempted_stages': [], 'completed_stages': [], 'owners': {}, 'joins': {},
        'errors': [], 'source_preserved': False, 'inner_closure_confirmed': True,
        'runtime_ids': list(RUNTIME_IDS), 'lifetime_ids': list(LIFETIME_IDS),
        'original17_executed': False, 'original46_executed': False,
        'body_driver_qualified': False, 'fresh_cold': False,
        'unexecuted_scopes': list(UNEXECUTED_SCOPES), 'started_ns': time.monotonic_ns()}
    before = None
    try:
        before = frozen(policy)
        save(work / 'INPUTS-BEFORE.json', before)
        compiler_origin = current_compiler(Path(policy['compiler_origin_root']), policy, read_file)
        save(work / 'CURRENT-COMPILER-ORIGINAL-VERIFIER.json', compiler_origin)
        report['compiler_origin'] = {
            'original_verifier_schema': compiler_origin['schema'],
            'original_verifier_status': compiler_origin['status'],
            'scope': 'Existing current-v89 B3 provenance only; no integer or CLI qualification inherited',
            'record': pin(work / 'CURRENT-COMPILER-ORIGINAL-VERIFIER.json', 4 << 20)}
        owner = load_owner()

        def stage(label, command, seconds, *, compiler=False):
            report['attempted_stages'].append(label)
            report['inner_closure_confirmed'] = False
            step = run_step(owner, work / 'owners', label, command, cwd=ROOT,
                            env=environment(work / 'temporary', compiler=compiler), seconds=seconds)
            report['inner_closure_confirmed'] = True
            report['owners'][label] = step
            require(step['status'] == 'NATURAL_CLOSED_PASS', 'finite stage failed: ' + label)
            return step

        stage('c-compile', stage_command(policy, args.policy, args.policy_sha256, 'c-compile'),
              20, compiler=True)
        built_c = c_image(policy, work)
        report['joins']['c-compile'] = save(work / 'C-BUILD-JOIN.json', built_c)
        report['completed_stages'].append('c-compile')

        stage('runtime', stage_command(policy, args.policy, args.policy_sha256, 'runtime', dso=built_c), 5)
        runtime = finite_cases(policy, args.policy_sha256, work, 'runtime', built_c)
        report['joins']['runtime'] = save(work / 'RUNTIME-JOIN.json', runtime)
        report['completed_stages'].append('runtime')

        stage('hia-compile', stage_command(policy, args.policy, args.policy_sha256, 'hia-compile'), 20)
        built_hia = hia_image(policy, work)
        report['joins']['hia-compile'] = save(work / 'HIA-BUILD-JOIN.json', built_hia)
        report['completed_stages'].append('hia-compile')

        stage('lifetime', stage_command(policy, args.policy, args.policy_sha256,
                                        'lifetime', dso=built_c, image=built_hia), 5)
        lifetime = finite_cases(policy, args.policy_sha256, work, 'lifetime', built_c, built_hia)
        report['joins']['lifetime'] = save(work / 'LIFETIME-JOIN.json', lifetime)
        report['completed_stages'].append('lifetime')
        report.update(status='FINITE_C_RUNTIME_LIFETIME_PASS_PENDING_OUTER_CLOSURE',
            actual_dso_sha256=built_c['image']['sha256'], actual_hia_image_sha256=built_hia['image']['sha256'],
            runtime_cases=len(RUNTIME_IDS), lifetime_cases=len(LIFETIME_IDS),
            actual_lifetime_entry_returns=lifetime['hia_entry_returns'],
            actual_c_pump_calls=lifetime['c_pump_calls_including_refusals'])
    except BaseException:
        report['errors'].append(traceback.format_exc())
        report['status'] = 'HOLD'
    finally:
        if report['inner_closure_confirmed']:
            try:
                after = frozen(policy)
                save(work / 'INPUTS-AFTER.json', after)
                report['source_preserved'] = before == after
                require(report['source_preserved'] and read_file(args.policy, 2 << 20)[1] == policy_pin,
                        'finite complete source/policy/system input identity changed')
            except BaseException:
                report['errors'].append(traceback.format_exc())
                report['status'] = 'HOLD'
        else:
            report['errors'].append('INNER_OWNER_UNKNOWN: no source/output read after unconfirmed closure')
            report['status'] = 'HOLD'
        report['elapsed_ns'] = time.monotonic_ns() - report['started_ns']
        save(work / 'REPORT.json', report)
    print(__import__('json').dumps({'status': report['status'], 'completed_stages': report['completed_stages'],
                                  'elapsed_ns': report['elapsed_ns']}))
    return 0 if report['status'] == 'FINITE_C_RUNTIME_LIFETIME_PASS_PENDING_OUTER_CLOSURE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
