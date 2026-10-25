"""FD-copy publication under a checked private-parent POSIX profile.

Not crash atomic. Malicious same-UID/privileged writers, hostile mounts and
post-return mutation are outside this profile. mkdir does not return an inode
handle: we bind the opened directory, not claim proof of mkdir's original inode.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import secrets


class PublicationRejected(ValueError):
    code = 'E_C_PROJECT_PUBLISH'


def _reject(reason):
    raise PublicationRejected(reason)


def _identity(st):
    return st.st_dev, st.st_ino


def _version(st):
    return (_identity(st), st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _close_once(fds):
    """Attempt every distinct owned fd once; close errors may be after-effect."""
    errors = []
    seen = set()
    for fd in fds:
        if fd is None or fd in seen:
            continue
        seen.add(fd)
        try:
            os.close(fd)
        except OSError as error:
            errors.append({'fd': fd, 'error': type(error).__name__, 'state': 'unknown_no_retry'})
    return errors


def _digest_fd(fd, expected_size):
    if os.fstat(fd).st_size != expected_size:
        _reject('Artifact size differs from validated length')
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256(); size = 0
    while size <= expected_size:
        data = os.read(fd, min(65536, expected_size + 1 - size))
        if not data:
            break
        h.update(data); size += len(data)
        if size > expected_size:
            _reject('Artifact grew beyond validated length')
    if size != expected_size:
        _reject('Artifact ended before validated length')
    return {'sha256': h.hexdigest(), 'bytes': size}


def _parent_chain(parent, flags):
    """Anchor and check every component; never chmod an existing directory."""
    uid = os.geteuid()
    fds = []; bindings = []
    try:
        fd = os.open('/', flags); fds.append(fd)
        parts = parent.parts[1:]
        for index in range(len(parts) + 1):
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid):
                _reject('Untrusted ancestor owner/type')
            if info.st_mode & 0o022:
                # Root-owned sticky namespaces (e.g. /tmp) cannot rename an
                # owned child for a different UID; same-UID attacks excluded.
                if not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX
                        and index < len(parts)):
                    _reject('Writable untrusted ancestor')
            if index == len(parts):
                if info.st_uid != uid or info.st_mode & 0o022:
                    _reject('Output parent must be privately writable by current UID')
                return fds, bindings
            name = parts[index]
            child = os.open(name, flags, dir_fd=fd)
            fds.append(child); bindings.append((fd, name, child)); fd = child
    except BaseException as exc:
        close_errors = _close_once(reversed(fds))
        exc.cleanup = {'confirmed': not close_errors, 'remaining_entries': [],
                       'errors': [], 'fd_close_errors': close_errors,
                       'output_creation_attempted': False}
        raise


def _check_bindings(bindings):
    for parent, name, fd in bindings:
        entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(entry.st_mode) or _identity(entry) != _identity(os.fstat(fd)):
            _reject('Directory path identity changed')


def publish_no_replace(stage: Path, destination: Path, *, expected: dict) -> dict:
    """Copy validated bytes from retained source FDs; commit manifest last.

    expected comes from caller validation BEFORE publication, including the
    serialized manifest. It is not recomputed from mutable stage paths here.
    """
    required_ops = (os.open, os.mkdir, os.stat, os.unlink, os.rmdir, os.link)
    if (os.name != 'posix' or not hasattr(os, 'geteuid')
            or any(op not in os.supports_dir_fd for op in required_ops)
            or os.listdir not in os.supports_fd
            or os.stat not in os.supports_follow_symlinks
            or any(not hasattr(os, flag) for flag in ('O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK'))):
        _reject('Required POSIX no-follow/fd capabilities unavailable')
    stage, destination = Path(stage).absolute(), Path(destination).absolute()
    if '..' in stage.parts or '..' in destination.parts or destination.name in ('', '.', '..'):
        _reject('Ambiguous publication path')
    if stage.parent != destination.parent or stage == destination:
        _reject('Stage and output must be distinct siblings in trusted parent')
    required = {'source.hepta', 'bridge.rs', 'generated.rs', 'migration.json'}
    if (not isinstance(expected, dict) or not required.issubset(expected)
            or set(expected) - required - {'libtranslated.so'}):
        _reject('Invalid expected artifact inventory')
    frozen = {}
    for name, item in expected.items():
        if (not isinstance(item, dict) or type(item.get('bytes')) is not int or item['bytes'] < 0
                or not isinstance(item.get('sha256'), str) or len(item['sha256']) != 64
                or any(c not in '0123456789abcdef' for c in item['sha256'])):
            _reject('Invalid expected artifact digest')
        frozen[name] = {'bytes': item['bytes'], 'sha256': item['sha256']}
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parents, bindings = _parent_chain(destination.parent, flags)
    parent_fd = parents[-1]; stage_fd = None; out_fd = None
    sources = {}; source_fds = []; outputs = {}; output_expected = {}; created = False
    possible_manifest_fd = None
    primary_error = None
    cleanup = {'confirmed': False, 'remaining_entries': [], 'errors': []}
    try:
        stage_fd = os.open(stage.name, flags, dir_fd=parent_fd)
        st = os.fstat(stage_fd)
        if st.st_uid != os.geteuid() or st.st_mode & 0o022:
            _reject('Stage must be privately writable by current UID')
        if set(os.listdir(stage_fd)) != set(frozen):
            _reject('Unexpected or missing staged artifacts')
        for name in sorted(frozen):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=stage_fd)
            source_fds.append(fd)
            sources[name] = (fd, os.fstat(fd))
            if not stat.S_ISREG(sources[name][1].st_mode):
                _reject('Staged artifact is not regular')
            if _digest_fd(fd, frozen[name]['bytes']) != frozen[name] or _version(os.fstat(fd)) != _version(sources[name][1]):
                _reject('Staged artifact does not match validated bytes')
        _check_bindings(bindings)
        os.mkdir(destination.name, 0o700, dir_fd=parent_fd); created = True
        out_fd = os.open(destination.name, flags, dir_fd=parent_fd)
        out_identity = _identity(os.fstat(out_fd))
        if os.listdir(out_fd):
            _reject('New output directory contains foreign entries')

        def check_output(names):
            _check_bindings(bindings)
            current = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(current.st_mode) or _identity(current) != out_identity:
                _reject('Output path changed')
            if set(os.listdir(out_fd)) != set(names):
                _reject('Output contains unexpected entries')
            for name in names:
                actual = os.stat(name, dir_fd=out_fd, follow_symlinks=False)
                if not stat.S_ISREG(actual.st_mode) or _identity(actual) != _identity(os.fstat(outputs[name])):
                    _reject('Output artifact identity changed')
                if _digest_fd(outputs[name], output_expected[name]['bytes']) != output_expected[name]:
                    _reject('Output artifact bytes changed')

        for name in sorted(frozen, key=lambda n: (n == 'migration.json', n)):
            check_output(outputs)
            # Revalidate retained originals before each publication, especially
            # manifest. Never derive identity from their mutable names.
            for source_name, (source, before) in sources.items():
                if (_version(os.fstat(source)) != _version(before)
                        or _digest_fd(source, frozen[source_name]['bytes']) != frozen[source_name]):
                    _reject('Retained source changed during publication')
            source, before = sources[name]
            # Final manifest is a commit marker, never a partially written file.
            # Build its ready inode only inside our anchored private output.
            entry = ('.hepta-manifest-ready-' + secrets.token_hex(16)
                     if name == 'migration.json' else name)
            target = os.open(entry, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=out_fd)
            outputs[entry] = target
            output_expected[entry] = frozen[name]
            if not stat.S_ISREG(os.fstat(target).st_mode):
                _reject('Created target is not regular')
            os.lseek(source, 0, os.SEEK_SET)
            remaining = frozen[name]['bytes']
            if os.fstat(source).st_size != remaining:
                _reject('Copy source size changed')
            while True:
                data = os.read(source, min(65536, remaining + 1))
                if not data:
                    if remaining:
                        _reject('Copy source ended early')
                    break
                if len(data) > remaining:
                    _reject('Copy source grew beyond validated length')
                remaining -= len(data)
                view = memoryview(data)
                while view:
                    written = os.write(target, view)
                    if written <= 0:
                        _reject('Copy made no write progress')
                    view = view[written:]
            if (_version(os.fstat(source)) != _version(before)
                    or _digest_fd(target, frozen[name]['bytes']) != frozen[name]):
                _reject('Copy differs from validated source')
            os.fsync(target)
            if name == 'migration.json':
                check_output(outputs)
                # This link source is NOT a mutable external stage pathname:
                # it is our retained, validated ready inode in the same private
                # target directory. Concurrent malicious same-UID writers are
                # excluded by the profile, not claimed defeated by stat/link.
                # Register the possible alias BEFORE the syscall: a successful
                # link may be followed immediately by an async exception.
                possible_manifest_fd = target
                os.link(entry, name, src_dir_fd=out_fd, dst_dir_fd=out_fd,
                        follow_symlinks=False)
                outputs[name] = target
                output_expected[name] = frozen[name]
                check_output(outputs)
                os.unlink(entry, dir_fd=out_fd)
                del outputs[entry]
                del output_expected[entry]
        check_output(outputs)
        os.fsync(out_fd); os.fsync(parent_fd)
        check_output(outputs)
        return {'profile': 'private-parent-posix-retained-fd-copy', 'artifacts': frozen,
                'manifest_last': True, 'crash_atomic': False}
    except BaseException as exc:
        primary_error = exc
        if out_fd is not None:
            # The marker is a consistency barrier. Do not remove any data if
            # final-marker absence cannot be confirmed in one cleanup attempt.
            marker_absent = False
            try:
                marker = os.stat('migration.json', dir_fd=out_fd, follow_symlinks=False)
                if (possible_manifest_fd is None
                        or _identity(marker) != _identity(os.fstat(possible_manifest_fd))):
                    cleanup['errors'].append('unowned final marker remains')
                else:
                    os.unlink('migration.json', dir_fd=out_fd)
                    try:
                        os.stat('migration.json', dir_fd=out_fd, follow_symlinks=False)
                        cleanup['errors'].append('final marker reappeared')
                    except FileNotFoundError:
                        marker_absent = True
            except FileNotFoundError:
                marker_absent = True
            except OSError as error:
                cleanup['errors'].append(type(error).__name__ + ': final marker cleanup uncertain')
            cleanup['final_marker_absence_confirmed'] = marker_absent
            owned_entries = reversed(list(outputs.items())) if marker_absent else ()
            for name, fd in owned_entries:
                if name == 'migration.json':
                    continue  # Marker already handled; never retry a denial.
                try:
                    current = os.stat(name, dir_fd=out_fd, follow_symlinks=False)
                    if _identity(current) != _identity(os.fstat(fd)):
                        cleanup['errors'].append('replaced output: ' + name)
                    else:
                        os.unlink(name, dir_fd=out_fd)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    cleanup['errors'].append(type(error).__name__ + ': ' + name)
            try:
                cleanup['remaining_entries'] = os.listdir(out_fd)
            except OSError as error:
                cleanup['errors'].append(type(error).__name__ + ': enumerate cleanup')
            try:
                current = os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
                if (_identity(current) == _identity(os.fstat(out_fd))
                        and not cleanup['remaining_entries'] and not cleanup['errors']):
                    os.rmdir(destination.name, dir_fd=parent_fd)
                else:
                    cleanup['errors'].append('output directory changed or nonempty')
            except OSError as error:
                cleanup['errors'].append(type(error).__name__ + ': directory')
        elif created:
            cleanup['errors'].append('created directory not safely acquired')
        cleanup['confirmed'] = not cleanup['errors'] and not cleanup['remaining_entries']
        exc.cleanup = cleanup
        raise
    finally:
        close_errors = _close_once(list(outputs.values()) + source_fds
                                   + [out_fd, stage_fd] + list(reversed(parents)))
        if close_errors:
            cleanup['confirmed'] = False
            cleanup['fd_close_errors'] = close_errors
            if primary_error is not None:
                # Preserve primary failure and any existing publication cleanup
                # evidence; do not mask it with a later close failure.
                primary_error.cleanup = cleanup
            else:
                # Bytes/marker may have committed already. Keep dependencies
                # intact, return no success, and report uncertain teardown.
                cleanup['final_marker_absence_confirmed'] = False
                cleanup['complete_marker_may_remain'] = True
                error = PublicationRejected('Descriptor teardown could not be confirmed')
                error.cleanup = cleanup
                raise error
