"""Independently bind three official receiver artifacts and recover one failed ZIP.

This is a custody reader. It imports no project code and performs no product,
supplier, native, or qualification execution. All outputs are create-only.
"""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import stat
import time
import traceback
import zipfile

ROOT = Path('/workspace/scratch/e26ed3e2edcf/core-full32-failed-parts-recovery-r1')
DATA = Path('/tmp/hia-full32-failed-original-recovery-r1-20261112-e26e')
CONTROL = 'b43a354a91c7b2bb858edab40ffe4c8cb1fc24ca'
HEAD = 'ffa984c803c1f7c06649ed16262ee378d8cc48f3'
POLICY_SHA = 'afeb641caf510559f32731c44db4ef997437bdd8a597c602625c4f63420aeafb'
RUN = 43286445040
JOB = 131421001396
STATUS = 'SEALED_CONTIGUOUS_PARTS_VERIFIED_NOT_QUALIFICATION'
EXPECTED = [
    (13975176148, 327270425, '82654c34e79edd40cfe35c0197d8d809b37e3e91dd5cdcf62d7ee44d8197c8cb'),
    (13975640766, 327270441, '06215d458226c74b5a7019918edef0f06c58c3d3ebac1be1cf049bded2782cc9'),
    (13975830617, 164397655, '2928fbf1a74b2ddcf5bd18c37bd8a9268e93fb5b62336b36e4e5f16f064ced9e'),
]
ORIGINAL_ID = 13974465966
ORIGINAL_BYTES = 818594350
ORIGINAL_SHA = '9da285831263db03d5e24e26e427f867763f39d1d607ccf34f21ef519163785d'
NAMES = {
    'FINAL.json', 'PART.json', 'slice.bin', 'controls/context.json',
    'controls/setup.json', 'controls/guard--request.json',
    'controls/guard--guardian.json', 'controls/guard--child.stdout.log',
    'controls/guard--child.stderr.log', 'controls/supervisor.stdout.log',
    'controls/supervisor.stderr.log', 'controls/recovery.json',
    'controls/recovery-terminal.json',
    'controls/api--artifact-13974465966.metadata.original.json',
}
checks = []


def require(value, label):
    if not value:
        raise AssertionError(label)
    checks.append(label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o400)


def sdk(name):
    raw = json.loads((ROOT / name).read_bytes())
    require(raw.get('isError') is False, name + ': successful SDK response')
    return json.loads(raw['structuredContent']['content'])


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha(raw), 'git_blob': blob(raw)}


def main():
    started = time.monotonic_ns()
    policy_raw = (ROOT / 'policy.json').read_bytes()
    require(sha(policy_raw) == POLICY_SHA, 'frozen policy SHA')
    policy = json.loads(policy_raw)
    expected_artifact = policy['artifact']
    require(expected_artifact['id'] == ORIGINAL_ID and
            expected_artifact['bytes'] == ORIGINAL_BYTES and
            expected_artifact['sha256'] == ORIGINAL_SHA and
            expected_artifact['workflow_terminal'] == 'failure',
            'exact original failed artifact context')
    run = sdk('terminal-run.sdk.json')
    jobs = sdk('terminal-jobs.sdk.json')
    artifacts = sdk('terminal-artifacts.sdk.json')
    require(run['id'] == RUN and run['run_attempt'] == 1 and
            run['event'] == 'create' and run['head_sha'] == HEAD and
            run['head_branch'] == policy['trigger_branch'] and
            run['status'] == 'completed' and run['conclusion'] == 'success',
            'one exact provider receiver terminal success')
    require(jobs['total_count'] == 1 and len(jobs['jobs']) == 1,
            'one receiver job')
    job = jobs['jobs'][0]
    require(job['id'] == JOB and job['run_id'] == RUN and
            job['run_attempt'] == 1 and job['head_sha'] == HEAD and
            job['status'] == 'completed' and job['conclusion'] == 'success' and
            all(x['status'] == 'completed' and x['conclusion'] == 'success'
                for x in job['steps']), 'all receiver steps actually succeeded')
    require(artifacts['total_count'] == len(artifacts['artifacts']) == 3 and
            len({x['id'] for x in artifacts['artifacts']}) == 3,
            'exact three unique official part artifacts')
    by_id = {x['id']: x for x in artifacts['artifacts']}
    outer = []
    metadata = []
    for ordinal, (artifact_id, size, digest) in enumerate(EXPECTED):
        official = by_id[artifact_id]
        require(official['size_in_bytes'] == size < 512 << 20 and
                official['digest'] == 'sha256:' + digest and
                official['expired'] is False and
                official['name'] == 'hia-v89-full32-failed-original-part-%02d-%d-1' % (ordinal, RUN) and
                official['workflow_run']['id'] == RUN and
                official['workflow_run']['head_sha'] == HEAD and
                official['workflow_run']['head_branch'] == policy['trigger_branch'],
                'official artifact %d size/digest/run/head/name' % ordinal)
        path = DATA / ('part-%02d.artifact.zip' % ordinal)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                    before.st_size == size and stat.S_IMODE(before.st_mode) == 0o400,
                    'official artifact %d regular sealed local input' % ordinal)
            require(hashlib.file_digest(stream, 'sha256').hexdigest() == digest,
                    'official artifact %d complete raw SHA' % ordinal)
            stream.seek(0)
            small = {}
            entries = []
            with zipfile.ZipFile(stream) as archive:
                require(len(archive.infolist()) == 14 and set(archive.namelist()) == NAMES,
                        'official artifact %d exact 14-member ZIP inventory' % ordinal)
                for info in archive.infolist():
                    name = info.filename
                    require(not name.startswith('/') and
                            '..' not in PurePosixPath(name).parts and
                            not info.is_dir() and
                            not stat.S_ISLNK(info.external_attr >> 16),
                            'official artifact %d member safe: %s' % (ordinal, name))
                    if name == 'slice.bin':
                        require(info.file_size == policy['parts'][ordinal]['bytes'],
                                'slice %d directory size' % ordinal)
                        continue
                    require(info.file_size <= 4 << 20, 'bounded metadata: ' + name)
                    raw = archive.read(info)
                    require(len(raw) == info.file_size, 'metadata exact size/CRC: ' + name)
                    small[name] = raw
                    entries.append({'name': name, 'crc32': '%08x' % info.CRC,
                                    **pin(raw)})
            require(identity(before) == identity(os.fstat(stream.fileno())) == identity(path.lstat()),
                    'official artifact %d input identity stable' % ordinal)
        metadata.append(small)
        outer.append({'ordinal': ordinal, 'artifact_id': artifact_id, 'bytes': size,
                      'sha256': digest, 'path': str(path), 'identity': identity(before),
                      'metadata': entries})

    require(all(m['FINAL.json'] == metadata[0]['FINAL.json'] for m in metadata),
            'three raw FINAL files identical')
    final = json.loads(metadata[0]['FINAL.json'])
    require(final['schema'] == 'hia.actions.v88-full-original-parts-final.v1' and
            final['status'] == STATUS and final['errors'] == [] and
            final['missing_originals'] == [], 'final exact status and no custody errors')
    for key in ['closed_echild', 'complete_local_multipart_readback',
                'source_inputs_preserved', 'original_full_ZIP_retained_private',
                'private_slice_copies_relocated_not_duplicated']:
        require(final[key] is True, 'final true: ' + key)
    for key in ['new_product_execution', 'full_5400_retained_suite_executed',
                'historical_results_reclassified', 'old_runs_replayed',
                'original_ZIP_bytes_or_compression_changed', 'original_ZIP_members_decompressed']:
        require(final[key] is False, 'final false: ' + key)
    require(final['artifact'] == expected_artifact and
            final['expected_parts'] == policy['parts'] and len(final['parts']) == 3,
            'final exact original and three ranges')
    for key in ['private_partition_readback', 'public_partition_readback']:
        require(final[key] == {'bytes': ORIGINAL_BYTES, 'exact_contiguous_partition': True,
                               'sha256': ORIGINAL_SHA}, 'remote full readback: ' + key)
    require(final['original_zip']['bytes'] == ORIGINAL_BYTES and
            final['original_zip']['sha256'] == ORIGINAL_SHA, 'remote original full ZIP pin')
    ctx = json.loads(metadata[0]['controls/context.json'])
    require(ctx == final['context'] and ctx['actual_control_checkout'] == CONTROL and
            ctx['actual_workflow_commit'] == HEAD and ctx['policy_sha256'] == POLICY_SHA and
            ctx['repository'] == policy['repository'] and ctx['run_id'] == RUN and
            ctx['run_attempt'] == 1 and ctx['event'] == 'create' and
            ctx['event_ref_type'] == 'branch' and ctx['event_ref'] == policy['trigger_branch'],
            'exact frozen current control and workflow context')
    require(ctx['root'] == '/home/runner/work/_temp/' + policy['work_root_name'] and
            ctx['public_root'] == '/home/runner/work/_temp/' + policy['public_root_name'] and
            ctx['original_product_commit'] == expected_artifact['checkout_commit'] and
            ctx['original_product_tree'] == expected_artifact['checkout_tree'] and
            ctx['qualification_executed'] is False and ctx['token_or_signed_URL_in_context'] is False,
            'fixed runtime roots and explicit artifact-carrier field semantics')
    require(ctx['python']['version'].split()[0] == '3.14.4' and
            ctx['python']['resolved'] == ctx['python']['binary']['path'] and
            ctx['runner']['runtime_equivalence_to_original_CI_claimed'] is False,
            'actual receiver Python 3.14.4, no cross-runtime claim')
    checkout = '/home/runner/work/Hepta/Hepta/control/'
    expected_sources = {checkout + policy['control_prefix'] + '/' + n: p['sha256']
                        for n, p in policy['control_files'].items()}
    expected_sources[checkout + policy['control_prefix'] + '/policy.json'] = POLICY_SHA
    expected_sources.update({checkout + n: p['sha256']
                             for n, p in policy['unchanged_original_workflows'].items()})
    require(ctx['control_sources'] == expected_sources, 'exact checked-out control source set')
    require(len(final['captured_controls']) == 11 and
            len({x['name'] for x in final['captured_controls']}) == 11,
            'exact unique eleven captured controls')
    captured_names = set()
    for item in final['captured_controls']:
        name = 'controls/' + item['name'].replace('/', '--')
        captured_names.add(name)
        require(all(m[name] == metadata[0][name] for m in metadata),
                'three identical control bodies: ' + name)
        raw = metadata[0][name]
        require(item['original']['path'] == ctx['root'] + '/' + item['name'] and
                item['original']['bytes'] == len(raw) and item['original']['sha256'] == sha(raw) and
                len(item['copies']) == 3, 'original captured control binding: ' + name)
        for ordinal, copy in enumerate(item['copies']):
            require(copy['path'] == ctx['public_root'] + '/part-%02d/%s' % (ordinal, name) and
                    copy['bytes'] == len(raw) and copy['sha256'] == sha(raw) and
                    copy['identity'][5:7] == [1, len(raw)] and
                    stat.S_ISREG(copy['identity'][2]),
                    'public captured control binding: %d %s' % (ordinal, name))
    require(captured_names == NAMES - {'FINAL.json', 'PART.json', 'slice.bin'},
            'all small control originals covered exactly')
    setup = json.loads(metadata[0]['controls/setup.json'])
    request = json.loads(metadata[0]['controls/guard--request.json'])
    guardian = json.loads(metadata[0]['controls/guard--guardian.json'])
    worker = json.loads(metadata[0]['controls/recovery-terminal.json'])
    require(metadata[0]['controls/recovery-terminal.json'] == metadata[0]['controls/recovery.json'],
            'raw recovery and terminal reports identical')
    for key, name in [('setup', 'controls/setup.json'),
                      ('guardian', 'controls/guard--guardian.json'),
                      ('worker', 'controls/recovery-terminal.json')]:
        require(final[key]['bytes'] == len(metadata[0][name]) and
                final[key]['sha256'] == sha(metadata[0][name]), 'final original pin: ' + key)
    command = [ctx['python']['resolved'], '-I', '-S', '-B',
               ctx['root'] + '/control/worker.py', '--root', ctx['root'],
               '--policy-sha256', POLICY_SHA]
    identities = dict(expected_sources)
    identities.update({ctx['root'] + '/control/' + n: p['sha256']
                       for n, p in policy['control_files'].items()})
    identities[ctx['root'] + '/control/policy.json'] = POLICY_SHA
    identities[ctx['root'] + '/context.json'] = sha(metadata[0]['controls/context.json'])
    identities[ctx['python']['resolved']] = ctx['python']['binary']['sha256']
    require(setup['context'] == ctx and setup['command'] == command and
            setup['controller_seconds'] == 900 and setup['cleanup_seconds'] == 3 and
            setup['capacity_before']['free_bytes'] >= 8 << 30 and
            setup['capacity_before']['free_inodes'] >= 100000 and
            setup['source_identities'] == identities and
            setup['guardian_config_sha256'] == sha(metadata[0]['controls/guard--request.json']),
            'setup exact source/request/runtime and original capacity thresholds')
    require(request == {'schema': 'hia-external-guardian-request.v1',
                        'controller_seconds': 900, 'command': command, 'cwd': ctx['root'],
                        'source_identities': identities}, 'exact full guardian request')
    require(guardian['schema'] == 'hepta.hia.external-qualification-guardian.v1' and
            guardian['command'] == command and guardian['cwd'] == ctx['root'] and
            guardian['external_controller_seconds'] == 900 and
            guardian['status'] == 'EXTERNAL_OWNED_PROCESS_COMPLETED' and
            guardian['lifecycle_implementation_sha256'] == policy['control_files']['process_owner_impl.py']['sha256'] and
            guardian['source_identities_before'] == identities == guardian['source_identities_after'] and
            guardian['input_identity_preserved'] is True and
            guardian['cold_180_second_gate_modified'] is False,
            'guardian original owner implementation, command and complete stable identities')
    require({p: row['sha256'] for p, row in final['source_inputs_final'].items()} == identities,
            'final source input set unchanged')
    life = guardian['lifecycle']
    require(life['schema'] == 'hepta.hia.external-qualification-guardian.v1.lifecycle' and
            life['qualification_seconds'] == 900 and life['cleanup_seconds'] == 3 and
            life['status'] == 'OWNED_PROCESS_COMPLETED' and life['returncode'] == 0 and
            life['timed_out'] is False and life['qualification_started'] is True and
            life['exit_observed_before_deadline'] is True and life['subreaper_enabled'] is True and
            life['event_overflow'] is False and life['interrupted_signals'] == [] and
            life.get('owner_error') is None,
            'natural original 900/3 lifecycle without timeout/overflow/interruption')
    cleanup = life['cleanup']
    require(cleanup['attempted'] is True and cleanup['complete'] is True and
            cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True and
            cleanup['deadline_exceeded'] is False and cleanup['remaining_direct_children'] == [] and
            cleanup['errors'] == [], 'complete bound ECHILD and no remaining children/errors')
    require([x['kind'] for x in life['events']] == ['qualification_started', 'owned_child_observed',
            'qualification_exit_observed', 'owned_child_reaped'], 'four natural events, no kill')
    for suffix in ['stdout', 'stderr']:
        require(guardian['logs'][ctx['root'] + '/guard/child.' + suffix + '.log'] ==
                sha(metadata[0]['controls/guard--child.' + suffix + '.log']),
                'guardian actual child ' + suffix + ' bytes')
    require(worker['artifact'] == expected_artifact and worker['source'] == policy['source'] and
            worker['root'] == ctx['root'] and worker['policy_sha256'] == POLICY_SHA and
            worker['status'] == 'SEALED_PARTS_PENDING_NATURAL_GUARDIAN' and
            0 < worker['elapsed_ns'] < 720 * 10**9 and
            worker['proxy_policy'] == 'USE_CONFIGURED_ENVIRONMENT_PROXIES', 'bound worker completed transfer')
    for key in ['project_code_executed', 'qualification_executed', 'old_runs_replayed',
                'original_product_statuses_reclassified', 'original_ZIP_members_decompressed',
                'token_or_signed_URL_recorded']:
        require(worker[key] is False, 'worker false: ' + key)
    for key in ['zip_before', 'zip_after']:
        require(worker[key]['bytes'] == ORIGINAL_BYTES and worker[key]['sha256'] == ORIGINAL_SHA and
                worker[key]['actual_bytes_independently_read'] == ORIGINAL_BYTES and
                worker[key]['identity'] == final['original_zip']['identity'], 'worker complete original: ' + key)
    partition = worker['partition']
    require(partition['exact_contiguous_partition'] is True and partition['total_bytes'] == ORIGINAL_BYTES and
            partition['concatenated_sha256'] == ORIGINAL_SHA and len(partition['parts']) == 3,
            'worker complete exact original partition')
    api_raw = metadata[0]['controls/api--artifact-13974465966.metadata.original.json']
    api = json.loads(api_raw)
    require(api['id'] == ORIGINAL_ID and api['size_in_bytes'] == ORIGINAL_BYTES and
            api['digest'] == 'sha256:' + ORIGINAL_SHA and
            api['workflow_run']['id'] == expected_artifact['run_id'] and
            api['workflow_run']['head_sha'] == expected_artifact['checkout_commit'] and
            len(api_raw) == worker['official_metadata']['bytes'] and
            sha(api_raw) == worker['official_metadata']['sha256'], 'actual official original metadata')
    require(len(worker['API_attempts']) == 2 and len(worker['GET_attempts']) == 1 and
            all(x['attempt'] == 1 and x['retries'] == 0 for x in worker['API_attempts'] + worker['GET_attempts']) and
            worker['GET_attempts'][0]['bytes'] == ORIGINAL_BYTES and
            worker['GET_attempts'][0]['sha256'] == ORIGINAL_SHA and
            worker['GET_attempts'][0]['authorization_sent'] is False,
            'one anonymous original GET, no retries')

    # Save exact small originals only after the independently bound current owner closes.
    for ordinal, small in enumerate(metadata):
        for name, raw in small.items():
            save(ROOT / ('part-%02d-originals' % ordinal) / name, raw)
    storage = os.statvfs(DATA)
    capacity = {'free_bytes': storage.f_bavail * storage.f_frsize, 'free_inodes': storage.f_favail}
    require(capacity['free_bytes'] >= ORIGINAL_BYTES + (512 << 20) and capacity['free_inodes'] >= 100,
            'fresh local reconstruction capacity, separate from remote preflight')
    output = DATA / ('artifact-%d.original.zip' % ORIGINAL_ID)
    partial = output.with_suffix(output.suffix + '.partial')
    require(not output.exists() and not partial.exists(), 'new create-only reconstruction output')
    count = 0
    whole = hashlib.sha256()
    read_parts = []
    with partial.open('xb') as destination:
        for ordinal, item in enumerate(outer):
            part = json.loads(metadata[ordinal]['PART.json'])
            expected = policy['parts'][ordinal]
            require(part['schema'] == 'hia.v88-original-zip-part.v1' and part['status'] == STATUS and
                    part['artifact'] == expected_artifact and part['control_commit'] == CONTROL and
                    part['workflow_commit'] == HEAD and part['policy_sha256'] == POLICY_SHA and
                    part['run_id'] == RUN and part['run_attempt'] == 1 and
                    part['qualification_executed'] is False and part['expected'] == expected and
                    expected['ordinal'] == ordinal and expected['offset'] == count,
                    'part %d exact manifest and contiguous range' % ordinal)
            observed = part['observed']
            require(observed == final['parts'][ordinal] and observed['kind'] == 'SEALED_ORIGINAL_RANGE' and
                    observed['publication'] == 'SAME_INODE_RELOCATION_AFTER_CLOSED_ECHILD' and
                    observed['private_slice_name_removed'] is True and
                    observed['source']['identity'][:7] == observed['retained']['identity'][:7] and
                    observed['source']['sha256'] == observed['retained']['sha256'] and
                    observed['source']['bytes'] == observed['retained']['bytes'] == expected['bytes'] and
                    observed['retained']['path'] == ctx['public_root'] + '/part-%02d/slice.bin' % ordinal,
                    'part %d same-inode relocation and final exact observed manifest' % ordinal)
            original = partition['parts'][ordinal]
            require({k: original[k] for k in expected} == expected and
                    original['original']['sha256'] == observed['source']['sha256'] and
                    original['original']['identity'] == observed['source']['identity'],
                    'part %d worker range and original identity joined' % ordinal)
            digest = hashlib.sha256()
            size = 0
            path = Path(item['path'])
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, 'rb') as incoming:
                require(identity(os.fstat(incoming.fileno())) == item['identity'], 'part input identity before reread')
                with zipfile.ZipFile(incoming) as archive:
                    info = archive.getinfo('slice.bin')
                    with archive.open(info) as source:
                        while block := source.read(1 << 20):
                            size += len(block)
                            if size > expected['bytes']:
                                raise AssertionError('slice overflow')
                            digest.update(block)
                            whole.update(block)
                            destination.write(block)
                    require(size == expected['bytes'] and digest.hexdigest() == observed['retained']['sha256'],
                            'part %d full payload CRC/SHA/size' % ordinal)
                require(identity(os.fstat(incoming.fileno())) == item['identity'] == identity(path.lstat()),
                        'part input identity after reread')
            read_parts.append({'ordinal': ordinal, 'offset': count, 'bytes': size,
                               'sha256': digest.hexdigest(), 'crc32': '%08x' % info.CRC})
            count += size
        destination.flush()
        os.fsync(destination.fileno())
    require(count == ORIGINAL_BYTES and whole.hexdigest() == ORIGINAL_SHA and
            partial.stat().st_size == ORIGINAL_BYTES, 'full original reconstructed exact bytes and SHA')
    os.chmod(partial, 0o400)
    os.rename(partial, output)
    with output.open('rb') as incoming:
        before = identity(os.fstat(incoming.fileno()))
        require(hashlib.file_digest(incoming, 'sha256').hexdigest() == ORIGINAL_SHA,
                'independent full reconstructed original readback SHA')
        require(before == identity(os.fstat(incoming.fileno())) == identity(output.lstat()),
                'reconstructed output identity stable')
    report = {
        'schema': 'hepta.failed-full32-independent-multipart-reconstruction.v1',
        'status': 'COMPLETE_ORIGINAL_FAILED_ZIP_RECONSTRUCTED_AND_BOUND',
        'original_artifact': expected_artifact, 'actual_full32_inputs': policy['actual_full32_inputs'],
        'receiver': {'run_id': RUN, 'job_id': JOB, 'attempt': 1, 'event': 'create',
                     'head': HEAD, 'control': CONTROL, 'policy_sha256': POLICY_SHA,
                     'provider_conclusion': 'success'},
        'original_path': str(output), 'original_bytes': count, 'original_sha256': whole.hexdigest(),
        'original_local_identity': before, 'parts': read_parts, 'official_part_artifacts': outer,
        'complete_metadata_files_read': sum(len(x) for x in metadata),
        'complete_identical_control_bodies': 11, 'same_final_raw': pin(metadata[0]['FINAL.json']),
        'bound_owner_900_cleanup3_natural0_ECHILD': True,
        'worker_elapsed_ns': worker['elapsed_ns'], 'original_failure_preserved': True,
        'fresh_local_capacity_before': capacity, 'remote_capacity_before': setup['capacity_before'],
        'checks': checks, 'check_count': len(checks), 'elapsed_ns': time.monotonic_ns() - started,
        'original_inner_members_audited': False,
        'product_executed_by_receiver_or_this_reader': False,
        'full32_or_full5400_pass_claimed': False,
    }
    save(ROOT / 'RECONSTRUCTION-AUDIT.json', wire(report))
    print(json.dumps({k: report[k] for k in ['status', 'original_path', 'original_bytes',
          'original_sha256', 'check_count', 'worker_elapsed_ns', 'elapsed_ns']}, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        failure = {'schema': 'hepta.failed-full32-independent-reconstruction-error.v1',
                   'status': 'HOLD', 'error_type': type(error).__name__, 'message': str(error),
                   'traceback': traceback.format_exc(), 'completed_checks': checks,
                   'product_executed': False, 'partials_preserved': True}
        path = ROOT / 'RECONSTRUCTION-r1-ERROR.json'
        if not path.exists():
            save(path, wire(failure))
        raise
