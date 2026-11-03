#!/usr/bin/env python3
"""Copy a bounded, no-follow, allowlisted evidence snapshot into a fresh upload tree.

This is not an adversarial OS sandbox. Only this helper writes the new staging
folder, and no untrusted process runs after staging in the isolated CI job.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import stat

MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
DENY = {'authority': 'DENY_ALL', 'native_admission': False, 'production_admission': False,
        'performance_qualified': False, 'timing_performed': False, 'quota_equivalence': False}
LOG_NAMES = {'layout-tests.log', 'layout-run.log'}


class UnsafeEvidence(ValueError):
    pass


def allowed_artifact_paths():
    names = {'REGISTRATION.json', 'RESULT.json'}
    for workload in ('linear', 'affine'):
        names.update(workload + '/' + name for name in ('PROPOSAL.json', 'CHECK.json', 'REFERENCE_PROOF.json'))
        for arm in ('reference', 'deferred'):
            names.update(workload + '/' + arm + suffix for suffix in
                ('.core.json', '.ll', '.llvm.json', '.o', '.text.bin', '.asm', '.symbols', '.trace.o', '.shrink-wrap.mir.txt'))
    return names


def _absolute(path):
    path = Path(os.path.abspath(path))
    # abspath normalizes CLI paths; names from directory listings are never
    # joined without being checked against the exact allowlist.
    return path


def _directory(path):
    """Open every absolute directory component without following links."""
    path = _absolute(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _read(parent, name, remaining):
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise UnsafeEvidence('nonordinary_or_linked_file')
    if before.st_size > MAX_FILE_BYTES or before.st_size > remaining:
        raise UnsafeEvidence('evidence_byte_limit')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        if _identity(os.fstat(fd)) != _identity(before):
            raise UnsafeEvidence('file_changed_before_read')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(before.st_size + 1)
        if len(data) != before.st_size or _identity(os.fstat(fd)) != _identity(before):
            raise UnsafeEvidence('file_changed_during_read')
        if _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _identity(before):
            raise UnsafeEvidence('file_path_changed')
        return data
    finally:
        os.close(fd)


def safe_read_file(path, remaining=None):
    path = _absolute(path)
    parent = _directory(path.parent)
    try:
        return _read(parent, path.name, MAX_TOTAL_BYTES if remaining is None else remaining)
    finally:
        os.close(parent)


def snapshot_tree(root, allowed=None):
    """Return detached regular bytes, rejecting links and unsafe/incomplete reads."""
    permitted = None if allowed is None else set(allowed)
    if permitted is not None and any(not name or name.startswith('/') or '..' in Path(name).parts for name in permitted):
        raise UnsafeEvidence('invalid_allowlist')
    files, total = {}, 0
    root_fd = _directory(root)
    def walk(fd, prefix):
        nonlocal total
        before = os.fstat(fd)
        names = sorted(os.listdir(fd))
        for name in names:
            relative = prefix + name
            entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(entry.st_mode):
                if permitted is not None and not any(p.startswith(relative + '/') for p in permitted):
                    raise UnsafeEvidence('unexpected_directory')
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    if _identity(os.fstat(child)) != _identity(entry):
                        raise UnsafeEvidence('directory_changed_before_read')
                    walk(child, relative + '/')
                    if _identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != _identity(entry):
                        raise UnsafeEvidence('directory_path_changed')
                finally:
                    os.close(child)
            else:
                if permitted is not None and relative not in permitted:
                    raise UnsafeEvidence('unexpected_artifact')
                data = _read(fd, name, MAX_TOTAL_BYTES - total)
                files[relative] = data
                total += len(data)
        if names != sorted(os.listdir(fd)) or _identity(os.fstat(fd)) != _identity(before):
            raise UnsafeEvidence('directory_changed_during_snapshot')
    try:
        walk(root_fd, '')
        # Reopen the original path without following links to detect replacement.
        again = _directory(root)
        try:
            if _identity(os.fstat(again)) != _identity(os.fstat(root_fd)):
                raise UnsafeEvidence('root_path_changed')
        finally:
            os.close(again)
        return files
    finally:
        os.close(root_fd)


def _new_directory(path):
    path = _absolute(path)
    parent = _directory(path.parent)
    try:
        os.mkdir(path.name, 0o700, dir_fd=parent)
        return os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)


def _write(root_fd, relative, data):
    parts = Path(relative).parts
    if not parts or relative.startswith('/') or any(p in {'.', '..'} for p in parts):
        raise UnsafeEvidence('invalid_destination_name')
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        out = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        with os.fdopen(out, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def stage(source, destination, logs=None):
    source, destination = _absolute(source), _absolute(destination)
    if source == destination or source in destination.parents or destination in source.parents:
        raise UnsafeEvidence('source_destination_overlap')
    output_fd = _new_directory(destination)
    report = {'schema': 'hepta.hia.deferred-evidence-staging.v1', 'status': 'refused',
              'files': {}, 'missing': [], **DENY}
    try:
        files = {}
        try:
            try:
                raw = snapshot_tree(source, allowed_artifact_paths())
            except FileNotFoundError:
                # Only a genuinely absent source is an expected pre-run failure;
                # disappearance of a file inside an existing source is unsafe.
                parent = _directory(source.parent)
                try:
                    try:
                        os.stat(source.name, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:
                        report['missing'].append('source')
                        raw = {}
                    else:
                        raise UnsafeEvidence('source_snapshot_incomplete')
                finally:
                    os.close(parent)
            files.update({'evidence/' + name: data for name, data in raw.items()})
            logs = {} if logs is None else logs
            if type(logs) is not dict or set(logs) - LOG_NAMES:
                raise UnsafeEvidence('unexpected_log_name')
            total = sum(map(len, files.values()))
            for name, path in sorted(logs.items()):
                path = _absolute(path)
                parent = _directory(path.parent)
                try:
                    try:
                        data = _read(parent, path.name, MAX_TOTAL_BYTES - total)
                    except FileNotFoundError:
                        report['missing'].append(name)
                        continue
                    files['logs/' + name] = data
                    total += len(data)
                finally:
                    os.close(parent)
        except (UnsafeEvidence, OSError, ValueError) as error:
            # No original bytes have been written yet. Do not echo a hostile
            # pathname, symlink target, file content or exception string.
            report['reason'] = 'unsafe_or_unreadable_evidence'
            report['error_type'] = type(error).__name__
        else:
            for name, data in sorted(files.items()):
                _write(output_fd, name, data)
                report['files'][name] = {'sha256': sha256(data).hexdigest(), 'bytes': len(data)}
            report['status'] = 'staged'
            report['reason'] = 'bounded_detached_regular_file_snapshot_only'
        _write(output_fd, 'STAGING.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
        return report
    finally:
        os.close(output_fd)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--destination', required=True)
    parser.add_argument('--test-log', required=True)
    parser.add_argument('--run-log', required=True)
    args = parser.parse_args()
    result = stage(args.source, args.destination, {'layout-tests.log': args.test_log, 'layout-run.log': args.run_log})
    print(json.dumps({'status': result['status'], **DENY}))
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write('safe_to_upload=true\n')
    if result['status'] != 'staged':
        raise SystemExit(1)
