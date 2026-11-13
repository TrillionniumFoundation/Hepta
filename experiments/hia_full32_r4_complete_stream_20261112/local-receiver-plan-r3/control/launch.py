"""One Root-reviewed local evidence-consumer invocation and closed finalization.

Private provider references are external input, supplied only at the authorized
launch. They never enter public request bodies, environment values or logs.
"""
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
spec = importlib.util.spec_from_file_location('full32_stream_local_io', ROOT / 'control/local_io.py')
io = importlib.util.module_from_spec(spec); spec.loader.exec_module(io)

def read_doc(path, maximum=16 << 20, deadline=None):
    pin, raw = io.seal(path, maximum, body=True, deadline=deadline)
    return io.json_value(raw), pin, raw

def source_inputs(policy, deadline=None):
    output = {}
    for name, expected in policy['inputs'].items():
        actual = io.seal(ROOT / name, 64 << 20, deadline=deadline)
        io.require(actual['bytes'] == expected['bytes'] and actual['sha256'] == expected['sha256'],
                   'complete frozen consumer input differs')
        output[str(ROOT / name)] = actual
    return output

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider-references-sha256', required=True)
    parser.add_argument('--proxy-configuration-sha256', required=True)
    args = parser.parse_args()
    policy, policy_pin, policy_raw = read_doc(ROOT / 'POLICY.json')
    limits = policy['limits']
    io.require(policy['schema'] == 'hia.full32.ten-range-local-consumer-policy.v1'
               and limits['controller_seconds'] == 900 and limits['cleanup_seconds'] == 3
               and limits['worker_seconds'] == 720 and len(policy['parts']) == 10
               and policy['product_execution_permitted'] is False, 'fixed consumer-only scope differs')
    proxy_path = Path(policy['proxy_configuration_path'])
    proxy_configuration, proxy_pin = io.read_private_proxy(proxy_path, policy['operation_root'],
                                                           args.proxy_configuration_sha256)
    env = io.configured_environment(proxy_configuration)  # Only a public, credential-free environment is serialized.
    runtime = io.seal(Path(sys.executable).resolve(), 64 << 20)
    io.require(all(runtime[k] == policy['runtime'][k] for k in ('path', 'bytes', 'sha256', 'identity'))
               and list(sys.version_info[:3]) == [3, 12, 14], 'fixed local consumer runtime differs')
    inputs = source_inputs(policy)
    private = Path(policy['provider_references_path'])
    refs, refs_pin, _ = read_doc(private, 65536)
    io.require(refs_pin['sha256'] == args.provider_references_sha256
                == policy['sealed_provider_references']['sha256']
               and refs_pin['bytes'] == policy['sealed_provider_references']['bytes']
               and refs_pin['identity'][3] == os.geteuid() and stat.S_IMODE(refs_pin['identity'][2]) == 0o600
               and refs['schema'] == 'hia.full32.ten-official-provider-references.v1'
               and refs['receiver_run_id'] == policy['receiver']['run_id']
               and [r['ordinal'] for r in refs['parts']] == list(range(10))
               and [r['artifact_id'] for r in refs['parts']] == [r['artifact']['id'] for r in policy['parts']],
               'private official reference set or exact opaque seal differs')
    for item in refs['parts']:
        io.require(set(item) == {'ordinal', 'artifact_id', 'url'}, 'provider input fields differ')
        io.provider_host(item['url'])
    operation = Path(policy['operation_root'])
    io.require(operation.parent == Path('/tmp') and not os.path.lexists(operation), 'fresh operation only; never replay')
    capacity = os.statvfs(operation.parent)
    io.require(capacity.f_bavail * capacity.f_frsize >= limits['minimum_free_bytes']
               and capacity.f_favail >= limits['minimum_free_inodes'], 'initial consumer capacity gate not met')
    operation.mkdir(mode=0o700)
    (operation / 'guard').mkdir(mode=0o700)
    io.create(operation / 'POLICY.original.json', policy_raw, raw=True)
    io.create(operation / 'PARENT-INPUTS-BEFORE.json', inputs)
    io.create(operation / 'CAPACITY-BEFORE.json', {'free_bytes': capacity.f_bavail * capacity.f_frsize,
        'free_inodes': capacity.f_favail, 'device': operation.lstat().st_dev,
        'new_local_consumer_only': True, 'remote_original_8GiB_100000_gate_changed': False})
    io.create(operation / 'PRIVATE-INPUT-RECEIPT.json', {'path': str(private), 'bytes': refs_pin['bytes'],
        'sha256': refs_pin['sha256'], 'identity': refs_pin['identity'], 'URLs_not_serialized': True})
    io.create(operation / 'PRIVATE-PROXY-RECEIPT.json', {**proxy_pin, 'content_never_published': True,
        'original_authentication_and_NO_PROXY_preserved': True, 'same_original_trust_paths': True})
    command = [runtime['path'], '-I', '-S', '-B', str(ROOT / 'control/worker.py'),
               '--provider-references', str(private), '--proxy-configuration', str(proxy_path),
               '--proxy-configuration-sha256', proxy_pin['sha256']]
    identities = {name: row['sha256'] for name, row in inputs.items()}
    identities.update({str(ROOT / 'POLICY.json'): policy_pin['sha256'], runtime['path']: runtime['sha256'],
                        str(private): refs_pin['sha256'], str(proxy_path): proxy_pin['sha256']})
    config = {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 900,
              'command': command, 'cwd': str(ROOT), 'source_identities': identities}
    config_raw = io.wire(config)
    io.require(len(config_raw) <= 262144, 'unchanged original guardian request bound exceeded')
    io.create(operation / 'guard/request.json', config_raw, raw=True)
    launch = [runtime['path'], '-I', '-S', '-B', str(ROOT / 'control/guardian.py'),
              '--config', str(operation / 'guard/request.json'), '--config-sha256', hashlib.sha256(config_raw).hexdigest(),
              '--implementation', str(ROOT / 'control/process_owner_impl.py')]
    io.create(operation / 'LAUNCH-INTENT.json', {'command': launch, 'cwd': str(ROOT), 'environment': env,
        'controller_seconds': 900, 'cleanup_seconds': 3, 'worker_total_seconds': 720,
        'network_retries': 0, 'one_guardian_invocation': True, 'source_inputs': identities})
    final = {'schema': 'hia.full32.ten-range-local-consumer-final.v1', 'status': 'HOLD',
             'closed_owner': False, 'natural_owner': False, 'complete_observed_output_custody': False,
             'actual_stream_all_body_pass': False, 'original_results_reclassified': False,
             'product_execution_performed': False, 'original_receiver_HOLD_retained': True,
             'private_URLs_captured': False, 'errors': []}
    final['private_proxy_configuration'] = {**proxy_pin, 'content_never_published': True}
    began = time.monotonic()
    worker_deadline = None
    try:
        with (operation / 'supervisor.stdout.log').open('xb') as stdout, (operation / 'supervisor.stderr.log').open('xb') as stderr:
            completed = subprocess.run(launch, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, check=False)
        io.create(operation / 'LAUNCH-RETURN.json', {'returncode': completed.returncode,
            'elapsed_seconds': time.monotonic() - began, 'replayed': False})
        guardian, guardian_pin, _ = read_doc(operation / 'guard/guardian.json')
        life = guardian.get('lifecycle', {}); cleanup = life.get('cleanup', {})
        io.require(guardian.get('schema') == 'hepta.hia.external-qualification-guardian.v1'
                   and guardian.get('command') == command and guardian.get('cwd') == str(ROOT)
                   and guardian.get('external_controller_seconds') == 900
                   and guardian.get('lifecycle_implementation_sha256') == policy['lifecycle_implementation_sha256']
                   and guardian.get('source_identities_before') == identities
                   and life.get('qualification_seconds') == 900 and life.get('cleanup_seconds') == 3,
                   'this actual guardian input/command/deadline binding differs')
        final['closed_owner'] = (life.get('subreaper_enabled') is True and life.get('event_overflow') is False
            and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
            and cleanup.get('leader_reaped') is True and cleanup.get('remaining_direct_children') == []
            and cleanup.get('deadline_exceeded') is False and cleanup.get('errors') == [])
        io.require(final['closed_owner'], 'do not read child evidence before bound ECHILD')
        final['guardian'] = guardian_pin
        worker, worker_pin, _ = read_doc(operation / 'WORKER-RESULT.json')
        io.require_elapsed(worker.get('elapsed_seconds'), 720)
        worker_started = worker.get('started_monotonic')
        worker_deadline = worker.get('deadline_monotonic')
        io.require_elapsed(worker_started, time.monotonic())
        io.require_elapsed(worker_deadline, time.monotonic() + 720)
        io.require(worker_started >= began and worker_deadline == worker_started + 720,
                   'same worker clock/deadline is not bound to this invocation')
        io.require(not os.path.lexists(operation / 'WORKER-FINALIZATION-HOLD.json'),
                   'worker final result publication failed')
        io.check_deadline(worker_deadline)
        final['worker'] = worker_pin
        final['worker_started_monotonic'] = worker_started
        final['worker_deadline_monotonic'] = worker_deadline
        final['natural_owner'] = (completed.returncode == 0
            and guardian.get('status') == 'EXTERNAL_OWNED_PROCESS_COMPLETED'
            and guardian.get('input_identity_preserved') is True and guardian.get('source_identities_after') == identities
            and guardian.get('qualification') is None and guardian.get('whole_native_delivery_qualified') is False
            and life.get('status') == 'OWNED_PROCESS_COMPLETED' and life.get('returncode') == 0
            and life.get('exit_observed_before_deadline') is True and life.get('timed_out') is False
            and life.get('interrupted_signals') == [] and life.get('owner_error') is None
            and not any(x.get('kind') == 'owned_child_sigkill' for x in life.get('events', [])))
        # A closed nonzero worker receives bounded observed-file custody only
        # while the same deadline permits it. Earlier deadline refusal leaves
        # every file in place and complete_observed_output_custody stays false.
        originals, total = [], 0
        for path in sorted(operation.rglob('*')):
            value = path.lstat()
            io.require(not stat.S_ISLNK(value.st_mode), 'unexpected child output symlink')
            if stat.S_ISDIR(value.st_mode):
                continue
            actual = io.seal(path, limits['part_artifact_bytes'], deadline=worker_deadline)
            total += actual['bytes']
            io.require(len(originals) < 1024 and total <= limits['part_artifact_bytes']
                       + limits['captured_original_bytes'] + limits['metadata_bytes'], 'observed output bound exceeded')
            originals.append(actual)
        io.create(operation / 'PARENT-ORIGINAL-CATALOG.json', {'all_observed_files_fully_read': True,
            'files': originals, 'bytes': total, 'after_current_ECHILD': True,
            'temporary_previous_parts_have_explicit_disposal_receipts': True}, deadline=worker_deadline)
        final['complete_observed_output_custody'] = True
        after = source_inputs(policy, worker_deadline)
        proxy_after = io.seal(proxy_path, 65536, deadline=worker_deadline)
        io.require(proxy_after == proxy_pin, 'private proxy changed during parent complete readback')
        io.require(worker.get('proxy_configuration_after') == proxy_pin
                   and worker.get('proxy_configuration') == {**proxy_pin, 'content_never_published': True,
                       'original_authentication_and_NO_PROXY_preserved': True},
                   'worker private proxy input/after identity does not match this guardian')
        io.create(operation / 'PARENT-INPUTS-AFTER.json', after, deadline=worker_deadline)
        io.require(after == inputs, 'frozen consumer source/metadata changed')
        worker_after, worker_after_pin, _ = read_doc(operation / 'WORKER-RESULT.json', deadline=worker_deadline)
        io.require(worker_after == worker and worker_after_pin == worker_pin, 'worker result changed during parent readback')
        io.require(worker.get('errors') == []
                   and worker.get('status') == 'COMPLETE_PHYSICAL_STREAM_READ_ONLY_NOT_FULL32'
                   and worker.get('policy', {}).get('sha256') == policy_pin['sha256']
                   and worker.get('all_parts_complete') is True
                   and worker.get('all_original_ZIP_members_physically_read') is True
                   and worker.get('all_inner_members_physically_read') is True
                   and worker.get('source_inputs_preserved') is True
                   and worker.get('original_bytes_or_compression_changed') is False
                   and worker.get('historical_results_reclassified') is False
                   and [p['ordinal'] for p in worker.get('parts', [])] == list(range(10)),
                   'complete finite stream result did not pass')
        io.require(worker['outer']['whole_ZIP_bytes'] == policy['original_artifact']['bytes']
                   and worker['outer']['whole_ZIP_sha256'] == policy['original_artifact']['sha256']
                   and worker['outer']['members'] == policy['expected_outer']['members']
                   and worker['inner']['TAR_members'] == policy['expected_inner']['members']
                   and worker['inner']['regular_files'] == policy['expected_inner']['regular_files']
                   and worker['inner']['regular_bytes'] == policy['expected_inner']['regular_bytes'],
                   'whole physical original denominator differs')
        for key, expected_lines in (('outer_actual_records', policy['expected_outer']['members']),
                                    ('inner_actual_records', policy['expected_inner']['members'])):
            row = worker[key]
            actual, raw_lines = io.seal(Path(row['path']), 32 << 20, body=True, deadline=worker_deadline)
            io.require(actual == {k: row[k] for k in actual} and raw_lines.endswith(b'\n')
                       and len(raw_lines.splitlines()) == row['complete_lines'] == expected_lines,
                       'complete actual member read-record original differs')
        io.require(len(worker['captured_originals']) == 2, 'both whole omitted originals required')
        for row in worker['captured_originals']:
            actual = io.seal(Path(row['actual_complete_copy']['path']), limits['captured_original_bytes'], deadline=worker_deadline)
            io.require(actual == row['actual_complete_copy'] and row['whole_original'] is True
                       and row['truncated'] is False, 'actual whole omitted-original copy differs')
        final['actual_stream_all_body_pass'] = True
        io.require(final['natural_owner'], 'consumer is not a natural successful operation')
        io.check_deadline(worker_deadline)
        final['all_complete_readback_elapsed_from_worker_start'] = time.monotonic() - worker_started
        io.require_elapsed(final['all_complete_readback_elapsed_from_worker_start'], 720)
        final['status'] = 'ALL_TEN_RANGES_AND_ALL_ORIGINAL_BODIES_READ_ONLY_PASS'
    except BaseException as error:
        final['status'] = 'HOLD'; final['errors'].append(io.safe_error(error))
    final['elapsed_seconds'] = time.monotonic() - began
    try:
        io.create(operation / 'FINAL.json', final,
                  deadline=worker_deadline if final['status'] == 'ALL_TEN_RANGES_AND_ALL_ORIGINAL_BODIES_READ_ONLY_PASS' else None)
        if final['status'] == 'ALL_TEN_RANGES_AND_ALL_ORIGINAL_BODIES_READ_ONLY_PASS':
            io.check_deadline(worker_deadline)
    except BaseException as error:
        final['status'] = 'HOLD'; final['errors'].append(io.safe_error(error))
        final['elapsed_seconds'] = time.monotonic() - began
        io.create(operation / 'FINAL-PUBLICATION-HOLD.json', final)
    print(json.dumps({'status': final['status'], 'closed_owner': final['closed_owner'],
                      'original_receiver_HOLD_retained': True, 'output': str(operation)}))
    return 0 if final['status'] == 'ALL_TEN_RANGES_AND_ALL_ORIGINAL_BODIES_READ_ONLY_PASS' and not final['errors'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
