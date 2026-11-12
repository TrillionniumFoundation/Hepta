"""Read fixed native-development originals as bounded base64 frames; never run products."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys

PREFIX = 'experiments/hia_json_pretty_20261112/installed-development-r1'
TRIGGER = 'codex/hia-json-pretty-installed-run-r1-20261112-e26e'
ROOT_NAME = 'hia-json-pretty-installed-development-r1'
CANDIDATE = '325d28bf8857696132b22a86dab0d551a3ce87bf'
TREE = '5739697d49188ce0e4cc809980d42a314a0a2787'
MAX_RAW = 4 << 20
FRAME_BYTES = 8192

def require(value, message='fixed read-only diagnostic identity differs'):
    if not value:
        raise RuntimeError(message)

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def marker(kind, value):
    print('HIA_JSON_PRETTY_' + kind + ' ' + json.dumps(value, sort_keys=True), flush=True)

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def _directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)

@contextmanager
def _checked_parent(path):
    """Retain the complete absolute directory chain without following symlinks."""
    path = Path(path)
    require(path.is_absolute() and path.anchor == '/' and '..' not in path.parts
            and len(path.parts) > 1, 'noncanonical controlled IO path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = [os.open('/', flags)]
    links = []
    def stable():
        for parent, name, child, expected in links:
            require(_directory_identity(os.fstat(child)) == expected
                    and _directory_identity(os.stat(name, dir_fd=parent,
                                                     follow_symlinks=False)) == expected,
                    'controlled IO directory chain changed')
    try:
        for name in path.parts[1:-1]:
            parent = descriptors[-1]
            child = os.open(name, flags, dir_fd=parent)
            descriptors.append(child)
            info = os.fstat(child)
            require(stat.S_ISDIR(info.st_mode), 'controlled IO ancestor is not a directory')
            links.append((parent, name, child, _directory_identity(info)))
        stable()
        yield descriptors[-1], path.parts[-1], stable
        stable()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)

def _read_extent(descriptor, size):
    chunks, remaining = [], size
    while remaining:
        block = os.read(descriptor, min(1 << 20, remaining))
        if not block:
            break
        chunks.append(block)
        remaining -= len(block)
    require(remaining == 0, 'controlled IO original ended before its declared extent')
    return b''.join(chunks)

def read_regular(path, maximum, reserve=None, *, allow_omission=False):
    with _checked_parent(path) as (parent, name, stable):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                    and before.st_nlink == 1 and before.st_size >= 0)
            require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == identity(before))
            stable()
            if allow_omission and before.st_size > maximum:
                return None, before.st_size
            require(before.st_size <= maximum)
            if reserve is not None:
                reserve(before.st_size)
            raw = _read_extent(descriptor, before.st_size)
            require(identity(os.fstat(descriptor)) == identity(before)
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        == identity(before))
            stable()
            return (raw, before.st_size) if allow_omission else raw
        finally:
            os.close(descriptor)

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
            and os.environ.get('HIA_JSON_PRETTY_WORKFLOW_SHA') == os.environ.get('GITHUB_SHA')
            and not os.environ.get('GITHUB_TOKEN') and not os.environ.get('GH_TOKEN'))
    policy_raw = read_regular(control / 'policy.json', 1 << 20)
    policy = json.loads(policy_raw)
    require(sha256(policy_raw).hexdigest() == args.policy_sha256
            and policy['schema'] == 'hia.json-pretty-actions-policy.v1'
            and policy['trigger_branch'] == TRIGGER
            and policy['candidate'] == {'commit': CANDIDATE, 'tree': TREE, 'leaves': 4027}
            and policy['controller_seconds'] == 180 and policy['cleanup_seconds'] == 3)
    own = read_regular(Path(__file__).resolve(), 1 << 20)
    require(len(own) == policy['controls']['diagnostics.py']['bytes']
            and sha256(own).hexdigest() == policy['controls']['diagnostics.py']['sha256'])
    paths = {}
    for stage in ('prepare', 'run', 'finalize'):
        for channel in ('stdout', 'stderr'):
            name = 'stage/' + stage + '.' + channel + '.log'
            paths[name] = temp / ('hia-json-pretty-native-' + stage + '.' + channel + '.log')
    for name in ('setup.json', 'context.json', 'guard/request.json', 'FINAL.json',
                 'guard/guardian.json', 'evidence/report.json',
                 'guard/child.stdout.log', 'guard/child.stderr.log', 'evidence/native-cases.json',
                 'evidence/native-child.stdout.log', 'evidence/native-child.stderr.log',
                 'evidence/installation/package-report.json', 'evidence/installation/installed-cases.json',
                 'evidence/installation/installed-child.stdout.log',
                 'evidence/installation/installed-child.stderr.log'):
        paths[name] = root / name
    cache, observations = {}, {}
    consumed = 0
    def original(name):
        nonlocal consumed
        if name in observations:
            return cache.get(name)
        path = paths[name]
        try:
            def reserve(size):
                nonlocal consumed
                require(0 <= size <= MAX_RAW - consumed)
                consumed += size
            raw, declared_size = read_regular(path, MAX_RAW - consumed, reserve,
                                              allow_omission=True)
            if raw is None:
                observations[name] = {'status': 'OMITTED_RAW_BUDGET', 'stat_size': declared_size,
                                      'raw_bytes_read': 0, 'sha256': None}
                return None
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
    marker('DIAGNOSTIC_BEGIN', {'schema': 'hia.json-pretty-actions-diagnostic.v1',
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
        require(setup['schema'] == 'hia.json-pretty-actions-setup.v1'
                and setup['status'] == 'PREPARED_NOT_EXECUTED'
                and context_raw == wire(setup['context']) and value == setup['context']
                and value['schema'] == 'hia.json-pretty-actions-context.v1'
                and value['actual_control_commit'] == args.control_commit
                and value['workflow_commit'] == os.environ['GITHUB_SHA']
                and value['run_id'] == int(os.environ['GITHUB_RUN_ID']) and value['run_attempt'] == 1
                and value['source'] == str(workspace / 'source')
                and value['root'] == str(root) and value['evidence'] == str(root / 'evidence')
                and value['candidate_commit'] == CANDIDATE and value['candidate_tree'] == TREE
                and value['candidate_leaves'] == 4027
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
             'guard/child.stdout.log', 'guard/child.stderr.log', 'evidence/native-cases.json',
             'evidence/native-child.stdout.log', 'evidence/native-child.stderr.log',
             'evidence/installation/package-report.json', 'evidence/installation/installed-cases.json',
             'evidence/installation/installed-child.stdout.log',
             'evidence/installation/installed-child.stderr.log'}
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
