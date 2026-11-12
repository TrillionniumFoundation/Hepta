"""Two explicit compilation operations; neither executes on import.

The C operation is a new development frontend/link request. The HIA operation
uses the unchanged original compile_stage and its original 20/10/1MiB child.
No build_seed, source generator or matching-cold qualification is called.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import resource
import sys
import traceback

CONTROL = Path(__file__).resolve().parent
ROOT = CONTROL.parent
sys.path.insert(0, str(CONTROL))
from common import require, read_file, pin, save
from support import read_policy, environment


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--stage', choices=('c', 'hia'), required=True)
    args = parser.parse_args()
    policy, policy_pin = read_policy(args.policy, args.policy_sha256)
    require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
            and str(Path(sys.executable).resolve()) == policy['python']['path']
            and list(sys.version_info[:3]) == [3, 12, 14], 'exact isolated compiler driver required')
    work = Path(policy['operation_root']) / 'work'
    if args.stage == 'c':
        command = policy['c_command']
        require(command[0] == policy['c_toolchain']['gcc']
                and command[-2:] == ['-o', str(work / 'c-build/cli-json.so')],
                'fixed actual C command differs')
        limits = {'cpu_seconds_per_compiler_process': 10, 'core_bytes': 0,
                  'file_bytes_per_file': 1 << 20, 'wall_seconds_in_original_owner': 20}
        save(work / 'c-build/EXEC-INTENT.json', {
            'schema': 'hia.cli-json.C-frontend-exec-intent.v1', 'command': command,
            'cwd': str(ROOT), 'environment': environment(work / 'temporary', compiler=True),
            'limits': limits, 'policy_sha256': args.policy_sha256,
            'scope': 'NEW_DEVELOPMENT_C_FRONTEND_AND_LINK; no HIA or retained JSON body is called'})
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        os.chdir(ROOT)
        os.execve(command[0], command, environment(work / 'temporary', compiler=True))
        raise AssertionError('execve unexpectedly returned')

    report = {'schema': 'hia.cli-json.original-lifetime-compile.v1', 'status': 'HOLD',
              'policy_sha256': args.policy_sha256, 'compile_stage_attempts': 0,
              'fresh_cold': False, 'source_generated_in_this_request': False}
    try:
        original = Path(policy['compiler_origin_root'])
        sys.path.insert(0, str(original / 'compiler-source'))
        from tools import qualify_hia_selfhost as compiler
        for name, row in policy['compiler_helpers'].items():
            actual = pin(original / row['path'], row['bytes'])
            require(actual['sha256'] == row['sha256'] and actual['size'] == row['bytes'],
                    'original compiler helper differs: ' + name)
        require(str(Path(compiler.__file__).resolve()) == str(original / 'compiler-source/tools/qualify_hia_selfhost.py')
                and compiler.NATIVE_OBSERVER is None and compiler.NATIVE_LINKED_OBSERVER is None
                and compiler.CAPACITY == 1 << 20, 'original native compiler route differs')
        source, source_pin = read_file(ROOT / policy['lifetime_source']['path'], 1 << 20)
        require(source_pin['size'] == policy['lifetime_source']['bytes']
                and source_pin['sha256'] == policy['lifetime_source']['sha256'],
                'actual source-qualified lifetime HIA bytes differ')
        image = original / policy['compiler']['path']
        image_pin = pin(image, 1 << 20)
        require(image_pin['sha256'] == policy['compiler']['sha256'], 'current original B3 differs')
        report.update(source=source_pin, compiler=image_pin, compile_stage_attempts=1)
        produced, receipt = compiler.compile_stage(work / 'hia-build', 'cli-lifetime', image, source)
        report.update(status='ORIGINAL_COMPILE_RETURNED_PENDING_INDEPENDENT_JOIN',
                      produced=str(produced), returned_receipt=receipt)
    except BaseException:
        report['error'] = traceback.format_exc()
    finally:
        save(work / 'hia-build/REPORT.json', report)
    return 0 if report['status'] == 'ORIGINAL_COMPILE_RETURNED_PENDING_INDEPENDENT_JOIN' else 1


if __name__ == '__main__':
    raise SystemExit(main())
