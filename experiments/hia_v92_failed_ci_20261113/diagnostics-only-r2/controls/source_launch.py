"""One source-only twelve-control owner; read child originals only after bound ECHILD."""
from hashlib import sha256
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import traceback

spec = importlib.util.spec_from_file_location('source12_launch_common', Path(__file__).with_name('source_common.py'))
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--request-sha256', required=True)
    args = parser.parse_args()
    raw = C.read(args.request, 1 << 20)
    C.require(sha256(raw).hexdigest() == args.request_sha256, 'source request SHA differs')
    request = json.loads(raw)
    C.require(request['schema'] == 'hia.v92.diagnostic-relocation.source12-request.v1'
              and request['qualification_seconds'] == 20 and request['cleanup_seconds'] == 3,
              'source-only operation budget differs')
    C.require(sys.version == request['runtime']['version']
              and str(Path(sys.executable).resolve()) == request['runtime']['executable'],
              'source runtime identity differs')
    before = C.check_inputs(request)
    root = Path(request['output_root'])
    C.require(root.is_absolute() and root.parent.resolve(strict=True) == root.parent
              and not os.path.lexists(root), 'fresh source-only output root required')
    capacity = os.statvfs(root.parent)
    C.require(capacity.f_bavail * capacity.f_frsize >= request['minimum_free_bytes']
              and capacity.f_favail >= request['minimum_free_inodes'], 'source/IO storage reserve unavailable')
    os.umask(0o077)
    root.mkdir(mode=0o700)
    C.create(root / 'REQUEST.original.json', raw)
    C.create(root / 'PARENT-INPUTS-BEFORE.json', before)
    final = {'schema': 'hia.v92.diagnostic-source12-final.v1', 'status': 'HOLD', 'closed': False,
             'source_request_sha256': args.request_sha256,
             'qualification_seconds': 20, 'cleanup_seconds': 3,
             'synthetic_only': True, 'network_requests': 0, 'product_executed': False,
             'old_local_R4_owner_status': 'UNKNOWN_NOT_RECLASSIFIED',
             'capacity_before': {'bytes': capacity.f_bavail * capacity.f_frsize, 'inodes': capacity.f_favail},
             'errors': []}
    command = [request['runtime']['executable'], '-I', '-S', '-B', request['worker_path'],
               '--request', str(args.request), '--request-sha256', args.request_sha256, '--output', str(root)]
    env = request['environment']
    closed = natural = False
    try:
        owner = C.load('source12_original_369_owner', request['owner_path'])
        wrapper = owner.run_owned(command, cwd=root, env=env,
                                  stdout_path=root / 'stdout.log', stderr_path=root / 'stderr.log',
                                  receipt_path=root / 'owner.json', qualification_seconds=20, cleanup_seconds=3)
        C.create(root / 'OWNER-WRAPPER.json', wrapper)
        receipt_raw = C.read(root / 'owner.json', 4 << 20)
        bound_raw = C.read(root / 'owner.json.request.json', 262144)
        receipt, bound = json.loads(receipt_raw), json.loads(bound_raw)
        owner_sha = next(row['sha256'] for row in request['inputs'] if row['path'] == request['owner_path'])
        C.require(receipt.get('schema') == wrapper.get('schema') == bound.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
                  and receipt.get('request_sha256') == sha256(bound_raw).hexdigest()
                  and wrapper.get('receipt_sha256') == sha256(receipt_raw).hexdigest()
                  and receipt.get('implementation_sha256') == bound.get('implementation_sha256') == owner_sha
                  and receipt.get('supervisor_pid') == wrapper.get('supervisor_pid')
                  and all(wrapper.get(key) == value for key, value in receipt.items())
                  and bound.get('command') == command and bound.get('cwd') == str(root)
                  and bound.get('env') == env
                  and bound.get('stdout_path') == str(root / 'stdout.log')
                  and bound.get('stderr_path') == str(root / 'stderr.log')
                  and bound.get('receipt_path') == str(root / 'owner.json')
                  and bound.get('qualification_seconds') == receipt.get('qualification_seconds') == 20
                  and bound.get('cleanup_seconds') == receipt.get('cleanup_seconds') == 3,
                  'exact wrapper/raw owner/request/command binding differs')
        cleanup = receipt.get('cleanup', {})
        closed = (receipt.get('subreaper_enabled') is True and receipt.get('qualification_started') is True
                  and cleanup.get('attempted') is True and cleanup.get('complete') is True
                  and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
                  and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == []
                  and cleanup.get('remaining_direct_children') == [])
        final['closed'] = closed
        C.require(closed, 'bound source owner has not established ECHILD; child originals remain unread')
        natural = (wrapper.get('supervisor_returncode') == 0 and receipt.get('returncode') == 0
                   and receipt.get('status') == 'OWNED_PROCESS_COMPLETED'
                   and receipt.get('timed_out') is False and receipt.get('exit_observed_before_deadline') is True
                   and receipt.get('event_overflow') is False and receipt.get('interrupted_signals') == []
                   and receipt.get('owner_error') is None
                   and all(event.get('kind') in {'qualification_started', 'owned_child_observed',
                       'qualification_exit_observed', 'owned_child_reaped'} for event in receipt.get('events', []))
                   and {'qualification_started', 'qualification_exit_observed', 'owned_child_reaped'}
                       <= {event.get('kind') for event in receipt.get('events', [])})
        final['natural'] = natural
        report = json.loads(C.read(root / 'REPORT.json', 4 << 20))
        final['report'] = C.file_pin(root / 'REPORT.json', 4 << 20)
        C.require(natural and report.get('status') == 'SOURCE12_SYNTHETIC_IO_PASS_NOT_ARTIFACT_RECOVERY'
                  and report.get('expected_ids') == report.get('loaded_ids') == report.get('executed_ids')
                      == report.get('success_ids') == request['expected_ids']
                  and report.get('exception') is None and report.get('inputs_unchanged') is True
                  and all(report.get(key) == [] for key in ('failures', 'errors', 'skips', 'expected_failures',
                        'unexpected_successes', 'loader_errors', 'forbidden_attempts')),
                  'complete source12 report and natural owner required')
        final['status'] = 'SOURCE12_SYNTHETIC_IO_PASS_NOT_ARTIFACT_RECOVERY'
    except BaseException as exc:
        final['errors'].append({'type': type(exc).__name__, 'traceback': traceback.format_exc()})
    finally:
        if closed:
            try:
                after = C.check_inputs(request)
                C.create(root / 'PARENT-INPUTS-AFTER.json', after)
                C.require(after == before, 'frozen source inputs changed')
                inventory = C.output_inventory(root)
                C.create(root / 'ORIGINALS.json', inventory)
                final['originals'] = C.file_pin(root / 'ORIGINALS.json', 4 << 20)
                final['all_original_bodies_read_after_bound_echild'] = True
            except BaseException as exc:
                final['status'] = 'HOLD'
                final['errors'].append({'type': type(exc).__name__, 'traceback': traceback.format_exc()})
        else:
            final['child_outputs_not_read_or_enumerated'] = True
        if final['errors']:
            final['status'] = 'HOLD'
        C.create(root / 'FINAL.json', final)
    print(json.dumps({'status': final['status'], 'closed': closed, 'natural': natural,
                      'product_executed': False, 'output': str(root)}), flush=True)
    return 0 if final['status'] == 'SOURCE12_SYNTHETIC_IO_PASS_NOT_ARTIFACT_RECOVERY' else 1


if __name__ == '__main__':
    raise SystemExit(main())
