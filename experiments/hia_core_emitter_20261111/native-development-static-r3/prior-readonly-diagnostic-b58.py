"""Print only fixed new-development originals after each exact owner is closed.

This reader changes no product or phase exit status. It records absent, refused,
unclosed and budget-omitted files explicitly. A diagnostic frame is custody, not
a native or cold PASS. Original files remain in the fixed uploaded root.
"""
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import PREFIX, REPO, blob, document, identity, read, require, wire, closed_owner

TRIGGER = 'codex/hia-core-emitter-native-development-run-r1-20261112-e26e'
ROOT_NAME = 'hia-core-emitter-native-development-r1'
STAGES = ('prepare', 'run-preparation', 'admit-preparation', 'run-tests', 'finalize')
MAX_RAW = 8 << 20
MAX_STDOUT = 12 << 20
FRAME_BYTES = 24576
printed_stdout = 0

def marker(kind, value):
    global printed_stdout
    line = ('HIA_CORE_EMITTER_NATIVE_' + kind + ' '
            + json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    require(printed_stdout + len(line) <= MAX_STDOUT, 'fixed native diagnostic stdout bound exhausted')
    sys.stdout.buffer.write(line)
    sys.stdout.buffer.flush()
    printed_stdout += len(line)

def read_fixed_original(path, maximum, reserve):
    """Read through retained no-follow directory descriptors, never through aliases."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and len(path.parts) > 1,
            'noncanonical fixed diagnostic path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptors = [os.open('/', flags)]
    links = []
    def directory_identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
    def stable_directories():
        for parent, name, child, wanted in links:
            require(directory_identity(os.fstat(child)) == wanted
                    and directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == wanted,
                    'fixed diagnostic directory chain changed')
    try:
        for name in path.parts[1:-1]:
            parent = descriptors[-1]
            child = os.open(name, flags, dir_fd=parent)
            descriptors.append(child)
            observed = os.fstat(child)
            require(stat.S_ISDIR(observed.st_mode), 'diagnostic ancestor is not a directory')
            links.append((parent, name, child, directory_identity(observed)))
        parent, name = descriptors[-1], path.parts[-1]
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=parent)
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid == os.geteuid() and before.st_size >= 0,
                'diagnostic original is not an owned single-link regular file')
        require(identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(before),
                'diagnostic original changed before descriptor read')
        stable_directories()
        if before.st_size > maximum:
            return None, {'bytes': before.st_size}
        reserve(before.st_size)
        chunks, count = [], 0
        while count < before.st_size:
            part = os.read(descriptor, min(1 << 20, before.st_size - count))
            if not part:
                break
            chunks.append(part)
            count += len(part)
        require(count == before.st_size and identity(os.fstat(descriptor)) == identity(before)
                and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(before),
                'diagnostic original changed during descriptor read')
        stable_directories()
        raw = b''.join(chunks)
        return raw, {'path': str(path), 'bytes': count, 'sha256': sha256(raw).hexdigest(),
                     'git_blob_sha1': blob(raw), 'posix_mode': stat.S_IMODE(before.st_mode),
                     'identity': list(identity(before))}
    finally:
        for descriptor in reversed(descriptors):
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
    require(Path(__file__).resolve().parent == control
            and re.fullmatch('[0-9a-f]{40}', args.control_commit) is not None
            and read(workspace / 'control/.git/HEAD', 256)[0].decode().strip() == args.control_commit
            and os.environ.get('GITHUB_REPOSITORY') == REPO
            and os.environ.get('GITHUB_EVENT_NAME') == 'create'
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1'
            and os.environ.get('GITHUB_REF') == 'refs/heads/' + TRIGGER
            and os.environ.get('HIA_CORE_EMITTER_NATIVE_WORKFLOW_SHA') == os.environ.get('GITHUB_SHA')
            and not os.environ.get('GITHUB_TOKEN') and not os.environ.get('GH_TOKEN')
            and not any(value for name, value in os.environ.items()
                        if name.startswith(('GIT_', 'LD_'))),
            'fixed native diagnostic execution context differs')
    require(not any(path.is_symlink() for path in (root, temp, *temp.parents,
                root / 'preparation-guard', root / 'tests-guard', root / 'preparation', root / 'callers')),
            'diagnostic root ancestor is a symlink')
    raw, pin = read(control / 'policy.json', 1 << 20)
    policy = json.loads(raw)
    require(pin['sha256'] == args.policy_sha256
            and policy['schema'] == 'hia.core-emitter-native-actions-policy.v1'
            and policy['trigger_branch'] == TRIGGER
            and policy['phase_controller_seconds'] == 180 and policy['cleanup_seconds'] == 3,
            'frozen native diagnostic policy differs')
    for name in ('common.py', 'diagnostics.py'):
        own, own_pin = read(control / name, 1 << 20)
        require(own_pin['bytes'] == policy['controls'][name]['bytes']
                and own_pin['sha256'] == policy['controls'][name]['sha256'],
                'fixed diagnostic source differs')

    paths, gated = {}, {}
    for stage in STAGES:
        for stream in ('stdout', 'stderr'):
            logical = 'stage/' + stage + '.' + stream + '.log'
            paths[logical] = temp / ('hia-core-emitter-native-' + stage + '.' + stream + '.log')
    for name in ('context.json', 'PREPARED.json', 'preparation-setup.json', 'tests-setup.json',
                 'PREPARATION-ACCEPTANCE.json', 'FINAL.json'):
        paths[name] = root / name
    for phase in ('preparation', 'tests'):
        for name in ('request.json', 'guardian.json', 'child.stdout.log', 'child.stderr.log'):
            logical = phase + '-guard/' + name
            paths[logical] = root / logical
            if name != 'request.json':
                gated[logical] = phase
    for name in ('preparation/report.json', 'preparation/final-HIA_SELFHOST_LANGUAGE_COVERAGE.json',
                 'preparation/final-HIA_SELFHOST_CORE_SUPPORT.json'):
        paths[name] = root / name
        gated[name] = 'preparation'
    for name in ('callers/report.json', 'callers/component.unittest.log',
                 'callers/original-machine.unittest.log', 'callers/original-core.unittest.log',
                 'callers/component-fixture/installed-control/report.json',
                 'callers/component-fixture/installed-control/processes.json',
                 'callers/component-fixture/installed-control/installed-execution.stdout',
                 'callers/component-fixture/installed-control/installed-execution.stderr'):
        paths[name] = root / name
        gated[name] = 'tests'
    require(len(paths) == 35, 'fixed native diagnostic file denominator differs')

    cache, observations = {}, {}
    reserved = 0
    def original(name):
        nonlocal reserved
        if name in observations:
            return cache.get(name)
        path = paths[name]
        try:
            def reserve(size):
                nonlocal reserved
                require(0 <= size <= MAX_RAW - reserved, 'diagnostic raw budget exhausted')
                reserved += size
            raw, pin = read_fixed_original(path, MAX_RAW - reserved, reserve)
            if raw is None:
                observations[name] = {'status': 'OMITTED_RAW_BUDGET', 'stat_size': pin['bytes'],
                                      'raw_bytes_read': 0, 'sha256': None}
                return None
            cache[name] = raw
            observations[name] = {'status': 'COMPLETE_ORIGINAL_READ', 'bytes': pin['bytes'],
                                  'sha256': pin['sha256'], 'git_blob_sha1': pin['git_blob_sha1']}
            return raw
        except FileNotFoundError:
            observations[name] = {'status': 'MISSING', 'raw_bytes_read': 0, 'sha256': None}
        except BaseException as error:
            observations[name] = {'status': 'READ_REFUSED', 'error_type': type(error).__name__,
                                  'sha256': None}
        return None

    marker('DIAGNOSTIC_BEGIN', {'schema': 'hia.core-emitter-native-diagnostic.v1',
        'control_commit': args.control_commit, 'workflow_commit': os.environ['GITHUB_SHA'],
        'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_attempt': 1,
        'policy_sha256': args.policy_sha256, 'candidate': policy['candidate'],
        'maximum_original_raw_bytes': MAX_RAW, 'maximum_stdout_bytes': MAX_STDOUT,
        'frame_bytes': FRAME_BYTES, 'fixed_file_count': len(paths), 'directory_scans': 0,
        'product_execution': False, 'original_exit_status_modified': False,
        'frames_are_original_bytes': True})
    closed, errors = {}, {}
    for phase in ('preparation', 'tests'):
        closed[phase] = False
        try:
            context_raw = original('context.json')
            setup_raw = original(phase + '-setup.json')
            config_raw = original(phase + '-guard/request.json')
            guardian_raw = original(phase + '-guard/guardian.json')
            require(all(value is not None for value in (context_raw, setup_raw, config_raw, guardian_raw)),
                    'bound owner metadata is missing')
            context, setup, config, guardian = map(json.loads,
                                                  (context_raw, setup_raw, config_raw, guardian_raw))
            require(context['schema'] == 'hia.core-emitter-native-actions-context.v1'
                    and context['actual_control_commit'] == args.control_commit
                    and context['workflow_commit'] == os.environ['GITHUB_SHA']
                    and context['run_id'] == int(os.environ['GITHUB_RUN_ID'])
                    and context['run_attempt'] == 1 and context['repository'] == REPO
                    and context['candidate'] == policy['candidate']
                    and context['source'] == str(workspace / 'source') and context['root'] == str(root)
                    and context['policy_sha256'] == args.policy_sha256
                    and context_raw == wire(setup['context']) and setup['context'] == context
                    and setup['schema'] == 'hia.core-emitter-native-phase-setup.v1'
                    and setup['phase'] == phase and setup['controller_seconds'] == 180
                    and setup['cleanup_seconds'] == 3 and setup['cwd'] == str(root),
                    'current bound phase context differs')
            python = context['python']['resolved']
            if phase == 'preparation':
                command = [python, '-I', '-S', '-B', str(root / 'control/preparation.py'),
                           '--root', str(root), '--source', str(workspace / 'source'),
                           '--policy-sha256', args.policy_sha256]
            else:
                command = [python, '-I', '-B',
                           str(workspace / 'source/tools/qualify_hia_core_lowering_callers.py'),
                           '--development-manifest', str(root / 'preparation/bundle/manifest.json'),
                           '--evidence', str(root / 'callers')]
            require(setup['command'] == command
                    and sha256(config_raw).hexdigest() == setup['guardian_config_sha256']
                    and config == {'schema': 'hia-external-guardian-request.v1', 'controller_seconds': 180,
                                   'command': command, 'cwd': str(root),
                                   'source_identities': setup['source_identities']},
                    'fixed phase request/command identity differs')
            controls = {str(control / name): value['sha256'] for name, value in policy['controls'].items()}
            controls[str(control / 'policy.json')] = args.policy_sha256
            require(context['control_sources'] == controls, 'fixed control source set differs')
            controls.update({str(root / 'control' / name): value['sha256']
                             for name, value in policy['controls'].items()})
            controls[str(root / 'control/policy.json')] = args.policy_sha256
            controls[str(root / 'context.json')] = sha256(context_raw).hexdigest()
            require(all(setup['source_identities'].get(path) == digest for path, digest in controls.items()),
                    'phase did not bind every frozen original control')
            closed_owner(guardian, setup, root, root / (phase + '-guard'))
            closed[phase] = True
        except BaseException as error:
            errors[phase] = type(error).__name__
    marker('DIAGNOSTIC_BOUNDARY', {'closed_current_phase_ECHILD': closed,
                                  'error_type_by_phase': errors, 'natural_success_inferred': False})
    printed = 0
    for name in paths:
        if name in gated and not closed[gated[name]]:
            known = observations.get(name, {})
            marker('ORIGINAL_UNAVAILABLE', {'name': name,
                'status': 'CLOSED_CURRENT_PHASE_NOT_PROVEN', 'phase': gated[name],
                'observed_sha256': known.get('sha256'), 'observed_bytes': known.get('bytes'),
                'original_bytes_printed': 0})
            continue
        raw = original(name)
        record = observations[name]
        if raw is None:
            marker('ORIGINAL_UNAVAILABLE', {'name': name, **record})
            continue
        count = (len(raw) + FRAME_BYTES - 1) // FRAME_BYTES
        marker('ORIGINAL_BEGIN', {'name': name, 'bytes': len(raw), 'sha256': record['sha256'],
                                  'git_blob_sha1': record['git_blob_sha1'],
                                  'frame_bytes': FRAME_BYTES, 'frame_count': count})
        for index, offset in enumerate(range(0, len(raw), FRAME_BYTES)):
            block = raw[offset:offset + FRAME_BYTES]
            marker('ORIGINAL_FRAME', {'name': name, 'index': index, 'offset': offset,
                'bytes': len(block), 'sha256': sha256(block).hexdigest(),
                'base64': base64.b64encode(block).decode('ascii')})
        marker('ORIGINAL_END', {'name': name, 'bytes': len(raw), 'sha256': record['sha256'],
                               'frame_count': count})
        printed += len(raw)
    marker('DIAGNOSTIC_END', {'original_raw_byte_budget_reserved': reserved,
        'verified_original_bytes_read': sum(len(raw) for raw in cache.values()),
        'original_raw_bytes_printed': printed, 'maximum_raw_bytes': MAX_RAW,
        'maximum_stdout_bytes': MAX_STDOUT, 'closed_current_phase_ECHILD': closed,
        'fixed_file_observations': observations, 'original_exit_status_modified': False,
        'native_or_cold_qualification_claimed': False})
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
