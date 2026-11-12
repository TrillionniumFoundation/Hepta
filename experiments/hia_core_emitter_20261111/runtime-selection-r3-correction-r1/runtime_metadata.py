"""Record and narrowly seal newly installed distribution identity files.

This is controller-external provisioning. It never changes the system-runtime
predicate, project files, product gates, package versions, or global umask.
Only a current-user, single-link METADATA/RECORD leaf in the exact four newly
installed distributions may lose its group/other write bits. Every original
byte, inode, uid/gid, size, mtime, and other mode bit must remain unchanged.
The r1 failure did not record which stat predicate failed; this new observation
does not retroactively identify the old runner's precise failing file.
"""
from __future__ import annotations
import argparse
import base64
from hashlib import sha1, sha256
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (PREFIX, REPO, create, identity, parent_descriptor, read,
                    require, wire)

TRIGGER = 'codex/hia-core-emitter-native-development-run-r3-20261112-e26e'
PACKAGES = {'setuptools': '78.1.1', 'wheel': '0.46.3',
            'z3-solver': '4.15.4.0', 'jsonschema': '4.26.0'}
STAGES = ('before', 'after', 'admit')
MAX_FILE = 8 << 20
MAX_REPORT = 128 << 10
MAX_STDOUT = 192 << 10
FRAME = 8192
NAME = 'hia-core-emitter-runtime-metadata-r3-'

# Fixed identities: the original controller selects all matching vendored entries too.
OWN_DIST_INFO = {'setuptools': 'setuptools-78.1.1.dist-info',
 'wheel': 'wheel-0.46.3.dist-info',
 'z3-solver': 'z3_solver-4.15.4.0.dist-info',
 'jsonschema': 'jsonschema-4.26.0.dist-info'}
FIXED_METADATA_FILES = {'setuptools': ('setuptools/_vendor/autocommand-2.2.2.dist-info/METADATA',
                'setuptools/_vendor/autocommand-2.2.2.dist-info/RECORD',
                'setuptools/_vendor/backports.tarfile-1.2.0.dist-info/METADATA',
                'setuptools/_vendor/backports.tarfile-1.2.0.dist-info/RECORD',
                'setuptools/_vendor/importlib_metadata-8.0.0.dist-info/METADATA',
                'setuptools/_vendor/importlib_metadata-8.0.0.dist-info/RECORD',
                'setuptools/_vendor/inflect-7.3.1.dist-info/METADATA',
                'setuptools/_vendor/inflect-7.3.1.dist-info/RECORD',
                'setuptools/_vendor/jaraco.collections-5.1.0.dist-info/METADATA',
                'setuptools/_vendor/jaraco.collections-5.1.0.dist-info/RECORD',
                'setuptools/_vendor/jaraco.context-5.3.0.dist-info/METADATA',
                'setuptools/_vendor/jaraco.context-5.3.0.dist-info/RECORD',
                'setuptools/_vendor/jaraco.functools-4.0.1.dist-info/METADATA',
                'setuptools/_vendor/jaraco.functools-4.0.1.dist-info/RECORD',
                'setuptools/_vendor/jaraco.text-3.12.1.dist-info/METADATA',
                'setuptools/_vendor/jaraco.text-3.12.1.dist-info/RECORD',
                'setuptools/_vendor/more_itertools-10.3.0.dist-info/METADATA',
                'setuptools/_vendor/more_itertools-10.3.0.dist-info/RECORD',
                'setuptools/_vendor/packaging-24.2.dist-info/METADATA',
                'setuptools/_vendor/packaging-24.2.dist-info/RECORD',
                'setuptools/_vendor/platformdirs-4.2.2.dist-info/METADATA',
                'setuptools/_vendor/platformdirs-4.2.2.dist-info/RECORD',
                'setuptools/_vendor/tomli-2.0.1.dist-info/METADATA',
                'setuptools/_vendor/tomli-2.0.1.dist-info/RECORD',
                'setuptools/_vendor/typeguard-4.3.0.dist-info/METADATA',
                'setuptools/_vendor/typeguard-4.3.0.dist-info/RECORD',
                'setuptools/_vendor/typing_extensions-4.12.2.dist-info/METADATA',
                'setuptools/_vendor/typing_extensions-4.12.2.dist-info/RECORD',
                'setuptools/_vendor/wheel-0.45.1.dist-info/METADATA',
                'setuptools/_vendor/wheel-0.45.1.dist-info/RECORD',
                'setuptools/_vendor/zipp-3.19.2.dist-info/METADATA',
                'setuptools/_vendor/zipp-3.19.2.dist-info/RECORD',
                'setuptools-78.1.1.dist-info/METADATA',
                'setuptools-78.1.1.dist-info/RECORD'),
 'wheel': ('wheel-0.46.3.dist-info/METADATA', 'wheel-0.46.3.dist-info/RECORD'),
 'z3-solver': ('z3_solver-4.15.4.0.dist-info/METADATA', 'z3_solver-4.15.4.0.dist-info/RECORD'),
 'jsonschema': ('jsonschema-4.26.0.dist-info/METADATA', 'jsonschema-4.26.0.dist-info/RECORD')}
EXPECTED_METADATA_ORIGINALS = sum(map(len, FIXED_METADATA_FILES.values()))
SETUPTOOLS_WHEEL_SHA256 = 'c3a9c4211ff4c309edb8b8c4f1cbfa7ae324c4ba9f91ff254e3d305b9fd54561'

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def stat_fields(info):
    return {'identity': list(identity(info)), 'dev': info.st_dev, 'ino': info.st_ino,
            'uid': info.st_uid, 'gid': info.st_gid, 'nlink': info.st_nlink,
            'size': info.st_size, 'mode': info.st_mode, 'posix_mode': stat.S_IMODE(info.st_mode),
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns,
            'regular': stat.S_ISREG(info.st_mode), 'directory': stat.S_ISDIR(info.st_mode),
            'symlink': stat.S_ISLNK(info.st_mode)}

def predicate(info):
    values = {'uid_in_root_or_current': info.st_uid in (0, os.geteuid()),
              'link_count_at_least_one': info.st_nlink >= 1,
              'no_group_or_other_write': not bool(stat.S_IMODE(info.st_mode) & 0o022)}
    return {**values, 'all': all(values.values())}

def chain(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'noncanonical observation path')
    result = []
    current = Path('/')
    for piece in ('', *path.parts[1:]):
        if piece:
            current = current / piece
        info = current.lstat()
        row = {'path': str(current), 'identity': list(identity(info)),
               'kind': ('directory' if stat.S_ISDIR(info.st_mode) else
                        'symlink' if stat.S_ISLNK(info.st_mode) else
                        'regular' if stat.S_ISREG(info.st_mode) else 'other')}
        if stat.S_ISLNK(info.st_mode):
            row['link_target'] = os.readlink(current)
        result.append(row)
    return result

def digest_descriptor(fd, expected_size):
    os.lseek(fd, 0, os.SEEK_SET)
    digest = sha256()
    git = sha1(b'blob ' + str(expected_size).encode() + b'\0')
    count = 0
    while count < expected_size:
        data = os.read(fd, min(65536, expected_size - count))
        require(bool(data), 'short metadata read')
        count += len(data)
        digest.update(data)
        git.update(data)
    require(os.read(fd, 1) == b'', 'metadata grew during read')
    return {'bytes': count, 'sha256': digest.hexdigest(), 'git_blob_sha1': git.hexdigest()}

def observe_file(path, maximum=MAX_FILE, *, repair=False, expected=None, observation=None):
    lexical = Path(os.path.abspath(path))
    row = {} if observation is None else observation
    row.update({'lexical_path': str(lexical), 'mode_change_attempted': False})
    lexical_chain = chain(lexical)
    row['lexical_lstat_chain'] = lexical_chain
    resolved = lexical.resolve(strict=True)
    row['resolved_path'] = str(resolved)
    with parent_descriptor(resolved) as (parent, name):
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        row['before'] = stat_fields(before)
        row['predicate_before'] = predicate(before)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum,
                'metadata or runtime input is not a bounded regular file')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            require(identity(os.fstat(fd)) == identity(before), 'file changed before descriptor read')
            row['original'] = digest_descriptor(fd, before.st_size)
            require(identity(os.fstat(fd)) == identity(before)
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(before),
                    'file changed during read')
            if expected is not None:
                require(expected['resolved_path'] == str(resolved)
                        and expected['original'] == row['original']
                        and expected['after']['identity'] == list(identity(before)),
                        'post-install original changed before admission')
            if repair and not row['predicate_before']['all']:
                require(lexical == resolved and before.st_uid == os.geteuid()
                        and before.st_nlink == 1 and row['predicate_before']['uid_in_root_or_current']
                        and row['predicate_before']['link_count_at_least_one']
                        and stat.S_IMODE(before.st_mode) & 0o022,
                        'only current-user single-link metadata write bits may be tightened')
                row['mode_change_attempted'] = True
                os.fchmod(fd, stat.S_IMODE(before.st_mode) & ~0o022)
            after = os.fstat(fd)
            row['after'] = stat_fields(after)
            row['predicate_after'] = predicate(after)
            row['after_original'] = digest_descriptor(fd, after.st_size)
            unchanged = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns')
            require(all(getattr(before, key) == getattr(after, key) for key in unchanged)
                    and row['original'] == row['after_original']
                    and (after.st_mode == (before.st_mode & ~0o022) if row['mode_change_attempted']
                         else identity(after) == identity(before))
                    and identity(os.fstat(fd)) == identity(after)
                    and identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity(after),
                    'metadata sealing changed more than permitted mode bits or file drifted')
            row['bytes_and_nonmode_identity_unchanged'] = True
        finally:
            os.close(fd)
    row['lexical_lstat_chain_after'] = chain(lexical)
    return row

def context(args):
    require(sys.version_info[:3] == (3, 14, 4) and platform.python_implementation() == 'CPython'
            and sys.platform == 'linux', 'actual fixed development Python differs')
    require(not os.environ.get('GITHUB_TOKEN') and not os.environ.get('GH_TOKEN')
            and not any(value for key, value in os.environ.items() if key.startswith(('GIT_', 'LD_'))),
            'token or Git/loader environment not permitted')
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    own = Path(__file__).resolve().parent
    require(own == workspace / 'control' / PREFIX
            and read(workspace / 'control/.git/HEAD', 256)[0].decode().strip() == args.control_commit,
            'frozen controller checkout differs')
    raw, _ = read(own / 'policy.json', 1 << 20)
    require(sha256(raw).hexdigest() == args.policy_sha256, 'runtime diagnostic policy differs')
    policy = json.loads(raw)
    require(policy['trigger_branch'] == TRIGGER and policy['control_prefix'] == PREFIX,
            'runtime diagnostic event policy differs')
    for name in ('common.py', 'runtime_metadata.py'):
        source, _ = read(own / name, 1 << 20)
        require(pin(source) == policy['controls'][name], 'runtime diagnostic source differs')
    event = json.loads(read(Path(os.environ['GITHUB_EVENT_PATH']), 1 << 20)[0])
    require(os.environ.get('GITHUB_REPOSITORY') == REPO
            and os.environ.get('GITHUB_EVENT_NAME') == 'create'
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1'
            and event.get('ref_type') == 'branch' and event.get('ref') == TRIGGER
            and event.get('repository', {}).get('full_name') == REPO
            and os.environ.get('GITHUB_REF') == 'refs/heads/' + TRIGGER,
            'unique new runtime diagnostic event differs')
    workflow = os.environ.get('GITHUB_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', workflow) is not None
            and os.environ.get('GITHUB_WORKFLOW_SHA') == workflow
            and os.environ.get('HIA_CORE_EMITTER_NATIVE_WORKFLOW_SHA') == workflow,
            'actual new workflow source differs')
    temp = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    return temp, {'repository': REPO, 'control_commit': args.control_commit,
                  'workflow_commit': workflow, 'policy_sha256': args.policy_sha256,
                  'run_id': int(os.environ['GITHUB_RUN_ID']), 'run_attempt': 1,
                  'trigger_branch': TRIGGER}


def selected_metadata(dist, package, observation):
    files = list(dist.files or ())
    chosen = sorted(item for item in files if item.name in ('METADATA', 'RECORD')
                    and item.parent.name.endswith('.dist-info'))
    entries = [str(item) for item in chosen]
    own = [str(item) for item in chosen if item.parent.as_posix() == OWN_DIST_INFO[package]]
    observation.update({'package': package, 'actual_version': dist.version,
                        'selected_distribution_directory': OWN_DIST_INFO[package],
                        'controller_metadata_entries': entries,
                        'own_distribution_entries': own,
                        'vendored_metadata_entries': [entry for entry in entries if entry not in own]})
    expected_own = [OWN_DIST_INFO[package] + '/' + name for name in ('METADATA', 'RECORD')]
    require(own == expected_own, 'selected distribution own metadata pair differs')
    require(len(entries) == len(set(entries)), 'duplicate controller metadata entry')
    require(tuple(entries) == FIXED_METADATA_FILES[package],
            'fixed complete controller metadata inventory differs')
    return chosen


def compact_report(report):
    # Lossless dictionary encoding only; every observation is retained.
    records = []
    indices = {}
    chain_names = {'lexical_lstat_chain', 'lexical_lstat_chain_after', 'lstat_chain'}
    def visit(value):
        if isinstance(value, list):
            return [visit(item) for item in value]
        if not isinstance(value, dict):
            return value
        result = {}
        for name, item in value.items():
            if name in chain_names:
                references = []
                for observation in item:
                    key = json.dumps(observation, sort_keys=True, separators=(',', ':'))
                    if key not in indices:
                        indices[key] = len(records)
                        records.append(observation)
                    references.append(indices[key])
                result[name] = {'record_indices': references}
            else:
                result[name] = visit(item)
        return result
    result = visit(report)
    result['lstat_chain_encoding'] = 'exact-observation-record-indices.v1'
    result['lstat_observation_records'] = records
    return result


def report_bytes(report):
    return (json.dumps(compact_report(report), sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8')

def emit(report, destination):
    raw = report_bytes(report)
    require(len(raw) <= MAX_REPORT, 'fixed metadata diagnostic report too large')
    stored = create(destination, raw)
    require({key: stored[key] for key in pin(raw)} == pin(raw), 'metadata report readback differs')
    lines = ['HIA_CORE_EMITTER_RUNTIME_METADATA_BEGIN ' + json.dumps(
        {'stage': report['stage'], 'operation': report['operation'], **pin(raw),
         'frame_bytes': FRAME, 'frame_count': (len(raw) + FRAME - 1) // FRAME}, sort_keys=True)]
    for index, offset in enumerate(range(0, len(raw), FRAME)):
        block = raw[offset:offset + FRAME]
        lines.append('HIA_CORE_EMITTER_RUNTIME_METADATA_FRAME ' + json.dumps(
            {'index': index, 'offset': offset, 'bytes': len(block),
             'sha256': sha256(block).hexdigest(), 'base64': base64.b64encode(block).decode('ascii')},
            sort_keys=True))
    lines.append('HIA_CORE_EMITTER_RUNTIME_METADATA_END ' + json.dumps(
        {'stage': report['stage'], **pin(raw), 'status': report['status']}, sort_keys=True))
    output = ('\n'.join(lines) + '\n').encode()
    require(len(output) <= MAX_STDOUT, 'fixed metadata stdout bound exceeded')
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=STAGES)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--control-commit', required=True)
    args = parser.parse_args()
    temp, operation = context(args)
    report = {'schema': 'hia.core-emitter-runtime-metadata-provisioning.v2',
              'stage': args.stage, 'operation': operation, 'status': 'HOLD',
              'current_uid': os.getuid(), 'current_euid': os.geteuid(),
              'current_gid': os.getgid(), 'current_egid': os.getegid(),
              'lstat_identity_field_order': ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink',
                                             'size', 'mtime_ns', 'ctime_ns'],
              'system_runtime_predicate_unchanged': True, 'fixed_packages': PACKAGES,
              'old_run_exact_failing_stat_unknown': True, 'project_or_system_binary_modified': False,
              'phase_owner_or_product_executed': False, 'rows': [], 'errors': [],
              'distributions': [], 'expected_metadata_original_count': EXPECTED_METADATA_ORIGINALS,
              'fixed_metadata_files': FIXED_METADATA_FILES, 'own_dist_info': OWN_DIST_INFO,
              'setuptools_wheel_sha256': SETUPTOOLS_WHEEL_SHA256}
    expected = {}
    try:
        report['python'] = {}
        observe_file(Path(sys.executable), 64 << 20, observation=report['python'])
        location = Path(os.environ['pythonLocation'])
        report['pythonLocation'] = {'path': str(location), 'lstat_chain': chain(location)}
        if args.stage == 'admit':
            previous_raw, previous_pin = read(temp / (NAME + 'after.json'), MAX_REPORT)
            previous = json.loads(previous_raw)
            require(previous['operation'] == operation and previous['stage'] == 'after'
                    and previous['fixed_packages'] == PACKAGES
                    and previous['fixed_metadata_files'] == {k: list(v) for k, v in FIXED_METADATA_FILES.items()}
                    and previous['own_dist_info'] == OWN_DIST_INFO
                    and previous['complete_controller_metadata_originals'],
                    'post-install runtime metadata observation incomplete')
            report['post_install_report_original'] = previous_pin
            expected = {(row['package'], row['distribution_entry']): row for row in previous['rows']}
            require(len(previous['rows']) == len(expected) == EXPECTED_METADATA_ORIGINALS
                    and set(expected) == {(package, entry) for package, entries in FIXED_METADATA_FILES.items()
                                          for entry in entries},
                    'post-install complete controller metadata denominator differs')
        for package, version in PACKAGES.items():
            try:
                dist = importlib.metadata.distribution(package)
                selection = {'package': package}
                report['distributions'].append(selection)
                chosen = selected_metadata(dist, package, selection)
                for item in chosen:
                    row = {'package': package, 'expected_version': version, 'actual_version': dist.version,
                           'metadata_name': item.name, 'distribution_entry': str(item),
                           'own_distribution_metadata': item.parent.as_posix() == OWN_DIST_INFO[package]}
                    report['rows'].append(row)
                    try:
                        require(args.stage == 'before' or dist.version == version,
                                'fresh pinned package version differs')
                        observe_file(Path(dist.locate_file(item)), repair=args.stage == 'admit',
                                     expected=expected.get((package, str(item))), observation=row)
                        row['status'] = 'OBSERVED'
                    except BaseException as error:
                        row['status'] = 'HOLD'
                        row['error'] = {'type': type(error).__name__, 'message': str(error)[:2048]}
            except BaseException as error:
                report['errors'].append({'package': package, 'type': type(error).__name__,
                                         'message': str(error)[:2048]})
        report['complete_controller_metadata_originals'] = (len(report['rows']) == EXPECTED_METADATA_ORIGINALS
            and len({(row['package'], row['distribution_entry']) for row in report['rows']}) == EXPECTED_METADATA_ORIGINALS
            and not report['errors'] and all(
            row.get('status') == 'OBSERVED' for row in report['rows']))
        report['own_metadata_original_count'] = sum(bool(row['own_distribution_metadata']) for row in report['rows'])
        report['vendored_metadata_original_count'] = len(report['rows']) - report['own_metadata_original_count']
        report['original_metadata_predicate_passes'] = report['complete_controller_metadata_originals'] and all(
            row['predicate_after']['all'] for row in report['rows'])
        report['first_metadata_predicate_rejection'] = next((
            {'package': row['package'], 'path': row['resolved_path'], 'stat': row['after'],
             'predicate': row['predicate_after']} for row in report['rows']
            if row.get('status') == 'OBSERVED' and not row['predicate_after']['all']), None)
        if args.stage == 'before':
            report['status'] = 'BEFORE_REINSTALL_OBSERVED'
        elif args.stage == 'after':
            report['status'] = 'AFTER_REINSTALL_OBSERVED'
        elif report['original_metadata_predicate_passes'] and report['python']['predicate_after']['all']:
            report['status'] = 'FIXED_METADATA_READY_FOR_UNCHANGED_CONTROLLER'
    except BaseException as error:
        report['status'] = 'HOLD'
        report['errors'].append({'type': type(error).__name__, 'message': str(error)[:2048]})
    emit(report, temp / (NAME + args.stage + '.json'))
    return 0 if report['status'] != 'HOLD' else 1

if __name__ == '__main__':
    raise SystemExit(main())
