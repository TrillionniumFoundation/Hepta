"""Read fixed source-authoring originals as bounded base64 frames; never run products."""
from __future__ import annotations
import argparse
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys

PREFIX = 'experiments/hia_core_emitter_20261111/actions-source-authoring-r1'
TRIGGER = 'codex/hia-core-emitter-authoring-r2-run-20261112-e26e'
ROOT_NAME = 'hia-core-emitter-source-authoring-r2'
CANDIDATE = '80ec04ae7489209b122c874531d194c67b30dfed'
TREE = '963e980c2486e1f7c74fa42bc8132ef6b1b8b690'
MAX_RAW = 4 << 20
FRAME_BYTES = 8192

def require(value):
    if not value:
        raise RuntimeError('fixed read-only diagnostic identity differs')

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def marker(kind, value):
    print('HIA_CORE_EMITTER_' + kind + ' ' + json.dumps(value, sort_keys=True), flush=True)

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def read_regular(path, maximum):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
            and before.st_nlink == 1 and before.st_size <= maximum)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        require(identity(os.fstat(stream.fileno())) == identity(before))
        raw = stream.read(before.st_size)
        require(len(raw) == before.st_size and identity(os.fstat(stream.fileno())) == identity(before)
                and identity(path.lstat()) == identity(before))
    return raw

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    args = parser.parse_args()
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    control = workspace / 'control' / PREFIX
    root = temp / ROOT_NAME
    require(not any(path.is_symlink() for path in (root, root / 'guard', root / 'evidence',
                                                  temp, *temp.parents)))
    require(Path(__file__).resolve().parent == control
            and re.fullmatch(r'[0-9a-f]{40}', args.control_commit) is not None
            and read_regular(workspace / 'control/.git/HEAD', 256).decode().strip() == args.control_commit
            and os.environ.get('GITHUB_REPOSITORY') == 'TrillionniumFoundation/Hepta'
            and os.environ.get('GITHUB_EVENT_NAME') == 'create'
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1'
            and os.environ.get('GITHUB_REF') == 'refs/heads/' + TRIGGER
            and os.environ.get('HIA_CORE_EMITTER_WORKFLOW_SHA') == os.environ.get('GITHUB_SHA')
            and not os.environ.get('GITHUB_TOKEN') and not os.environ.get('GH_TOKEN'))
    policy_raw = read_regular(control / 'policy.json', 1 << 20)
    policy = json.loads(policy_raw)
    require(sha256(policy_raw).hexdigest() == args.policy_sha256
            and policy['schema'] == 'hia.core-emitter-actions-policy.v1'
            and policy['trigger_branch'] == TRIGGER
            and policy['candidate'] == {'commit': CANDIDATE, 'tree': TREE, 'leaves': 4023}
            and policy['controller_seconds'] == 180 and policy['cleanup_seconds'] == 3)
    own = read_regular(Path(__file__).resolve(), 1 << 20)
    require(len(own) == policy['controls']['diagnostics.py']['bytes']
            and sha256(own).hexdigest() == policy['controls']['diagnostics.py']['sha256'])
    paths = {}
    for stage in ('prepare', 'run', 'finalize'):
        for channel in ('stdout', 'stderr'):
            name = 'stage/' + stage + '.' + channel + '.log'
            paths[name] = temp / ('hia-core-emitter-authoring-' + stage + '.' + channel + '.log')
    for name in ('setup.json', 'context.json', 'guard/request.json', 'FINAL.json',
                 'guard/guardian.json', 'evidence/report.json',
                 'guard/child.stdout.log', 'guard/child.stderr.log'):
        paths[name] = root / name
    cache, observations = {}, {}
    consumed = 0
    def original(name):
        nonlocal consumed
        if name in observations:
            return cache.get(name)
        path = paths[name]
        try:
            before = path.lstat()
            if before.st_size > MAX_RAW - consumed:
                observations[name] = {'status': 'OMITTED_RAW_BUDGET', 'stat_size': before.st_size,
                                      'raw_bytes_read': 0, 'sha256': None}
                return None
            reservation = before.st_size
            consumed += reservation
            raw = read_regular(path, reservation)
            cache[name] = raw
            observations[name] = {'status': 'COMPLETE_ORIGINAL_READ', 'bytes': len(raw),
                                  'sha256': sha256(raw).hexdigest()}
            return raw
        except FileNotFoundError:
            observations[name] = {'status': 'MISSING', 'raw_bytes_read': 0, 'sha256': None}
            return None
        except BaseException as error:
            observations[name] = {'status': 'READ_REFUSED', 'error_type': type(error).__name__,
                                  'sha256': None}
            return None
    marker('DIAGNOSTIC_BEGIN', {'schema': 'hia.core-emitter-actions-diagnostic.v1',
        'control_commit': args.control_commit, 'workflow_commit': os.environ['GITHUB_SHA'],
        'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_attempt': 1,
        'policy_sha256': args.policy_sha256, 'maximum_original_raw_bytes': MAX_RAW,
        'fixed_file_count': len(paths), 'directory_scans': 0, 'product_execution': False,
        'original_exit_status_modified': False, 'frames_are_original_bytes': True})
    closed = False
    closure_error = None
    # Only fixed metadata files may be read to establish the operation boundary.
    # No path supplied by a report is ever opened by this diagnostic.
    try:
        setup_raw = original('setup.json')
        context_raw = original('context.json')
        config_raw = original('guard/request.json')
        guardian_raw = original('guard/guardian.json')
        require(all(value is not None for value in
                    (setup_raw, context_raw, config_raw, guardian_raw)))
        setup, value, config, guardian = map(json.loads,
            (setup_raw, context_raw, config_raw, guardian_raw))
        require(setup['schema'] == 'hia.core-emitter-actions-setup.v1'
                and setup['status'] == 'PREPARED_NOT_EXECUTED'
                and context_raw == wire(setup['context']) and value == setup['context']
                and value['schema'] == 'hia.core-emitter-actions-context.v1'
                and value['actual_control_commit'] == args.control_commit
                and value['workflow_commit'] == os.environ['GITHUB_SHA']
                and value['run_id'] == int(os.environ['GITHUB_RUN_ID']) and value['run_attempt'] == 1
                and value['source'] == str(workspace / 'source')
                and value['root'] == str(root) and value['evidence'] == str(root / 'evidence')
                and value['candidate_commit'] == CANDIDATE and value['candidate_tree'] == TREE
                and value['candidate_leaves'] == 4023
                and value['policy_sha256'] == args.policy_sha256
                and value['controller_seconds'] == 180 and value['cleanup_seconds'] == 3)
        input_pins = {str(control / name): pin['sha256']
                      for name, pin in policy['controls'].items()}
        input_pins[str(control / 'policy.json')] = args.policy_sha256
        require(value['control_sources'] == input_pins)
        input_pins.update({str(root / 'control' / name): pin['sha256']
                           for name, pin in policy['controls'].items()})
        input_pins[str(root / 'control/policy.json')] = args.policy_sha256
        input_pins[str(root / 'context.json')] = sha256(context_raw).hexdigest()
        input_pins[value['python']['resolved']] = value['python']['binary']['sha256']
        input_pins[value['git']['resolved']] = value['git']['binary']['sha256']
        command = [value['python']['resolved'], '-I', '-S', '-B',
                   str(root / 'control/authoring.py'), '--source', str(workspace / 'source'),
                   '--output', str(root / 'evidence'), '--context', str(root / 'context.json'),
                   '--policy-sha256', args.policy_sha256]
        require(setup['source_identities'] == input_pins and setup['command'] == command
                and setup['controller_seconds'] == 180 and setup['cleanup_seconds'] == 3
                and sha256(config_raw).hexdigest() == setup['guardian_config_sha256']
                and config == {'schema': 'hia-external-guardian-request.v1',
                    'controller_seconds': 180, 'command': command, 'cwd': str(root),
                    'source_identities': input_pins})
        life = guardian['lifecycle']
        require(guardian['schema'] == 'hepta.hia.external-qualification-guardian.v1'
                and guardian['command'] == command and guardian['cwd'] == str(root)
                and guardian['external_controller_seconds'] == 180
                and guardian['source_identities_before'] == input_pins
                and guardian['lifecycle_implementation_sha256'] ==
                    policy['controls']['process_owner_impl.py']['sha256']
                and life['schema'] == 'hepta.hia.external-qualification-guardian.v1.lifecycle'
                and life['subreaper_enabled'] is True and life['qualification_started'] is True
                and life['qualification_seconds'] == 180 and life['cleanup_seconds'] == 3)
        cleanup = life['cleanup']
        require(cleanup['attempted'] is True and cleanup['complete'] is True
                and cleanup['observed_echild'] is True and cleanup['leader_reaped'] is True
                and cleanup['deadline_exceeded'] is False and cleanup['errors'] == []
                and cleanup['remaining_direct_children'] == [])
        closed = True
    except BaseException as error:
        closure_error = type(error).__name__
    marker('DIAGNOSTIC_BOUNDARY', {'closed_current_operation_ECHILD': closed,
                                   'error_type': closure_error,
                                   'natural_success_inferred': False})
    gated = {'guard/guardian.json', 'evidence/report.json',
             'guard/child.stdout.log', 'guard/child.stderr.log'}
    printed_bytes = 0
    for name in paths:
        if name in gated and not closed:
            pin = observations.get(name, {})
            marker('ORIGINAL_UNAVAILABLE', {'name': name,
                'status': 'CLOSED_CURRENT_OPERATION_NOT_PROVEN',
                'observed_sha256': pin.get('sha256'), 'observed_bytes': pin.get('bytes'),
                'original_bytes_printed': 0})
            continue
        raw = original(name)
        record = observations[name]
        if raw is None:
            marker('ORIGINAL_UNAVAILABLE', {'name': name, **record})
            continue
        printed_bytes += len(raw)
        count = (len(raw) + FRAME_BYTES - 1) // FRAME_BYTES
        marker('ORIGINAL_BEGIN', {'name': name, 'bytes': len(raw),
            'sha256': record['sha256'], 'frame_bytes': FRAME_BYTES, 'frame_count': count})
        for index, offset in enumerate(range(0, len(raw), FRAME_BYTES)):
            part = raw[offset:offset + FRAME_BYTES]
            marker('ORIGINAL_FRAME', {'name': name, 'index': index, 'offset': offset,
                'bytes': len(part), 'sha256': sha256(part).hexdigest(),
                'base64': base64.b64encode(part).decode('ascii')})
        marker('ORIGINAL_END', {'name': name, 'bytes': len(raw),
            'sha256': record['sha256'], 'frame_count': count})
    marker('DIAGNOSTIC_END', {'original_raw_byte_budget_reserved': consumed,
        'verified_original_bytes_read': sum(len(raw) for raw in cache.values()),
        'original_raw_bytes_printed': printed_bytes,
        'maximum_raw_bytes': MAX_RAW, 'closed_current_operation_ECHILD': closed,
        'fixed_file_observations': observations, 'original_exit_status_modified': False,
        'qualification_claimed': False})
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except BaseException as error:
        if isinstance(error, SystemExit):
            raise
        marker('DIAGNOSTIC_CONTROL_REFUSED', {'error_type': type(error).__name__,
                                            'original_exit_status_modified': False})
        raise SystemExit(1)
