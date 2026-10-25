"""Preselected private /tmp probe execution, then byte-bound evidence archival.

No compiler or subprocess is launched here. Paths in original receipts are never
rewritten to the archive location. Admission failure has no fallback directory.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile

from hepta import c_project_publish as publisher

MAX_FILES = 4096
MAX_ENTRIES = 8192


def control_root(artifact):
    artifact=Path(artifact)
    return artifact.with_name(artifact.name+'-control')


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def admission(root):
    root = Path(root)
    if root.parent != Path('/tmp') or root.is_symlink():
        raise ValueError('Probe root must be preselected fresh /tmp child')
    info = root.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Probe root is not current-UID private700 directory')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fds, bindings = publisher._parent_chain(root, flags)
    primary = None
    try:
        publisher._check_bindings(bindings)
        proof = [{'dev': os.fstat(fd).st_dev, 'ino': os.fstat(fd).st_ino,
                  'uid': os.fstat(fd).st_uid, 'mode': stat.S_IMODE(os.fstat(fd).st_mode)} for fd in fds]
    except BaseException as error:
        primary = error
        raise
    finally:
        errors = publisher._close_once(reversed(fds))
        if errors:
            if primary is not None:
                primary.fd_close_errors = errors
            else:
                raise RuntimeError('Private-root admission FD cleanup unknown: ' + repr(errors))
    return {'private_root': str(root), 'directory_chain': proof,
            'profile': 'preselected-private-tmp-no-fallback', 'admitted': True}


def worker_root(argv):
    if argv.count('--work-root') != 1:
        raise ValueError('Worker requires one explicit private output root')
    index = argv.index('--work-root')
    if index + 1 >= len(argv):
        raise ValueError('Missing worker root')
    root = Path(argv[index + 1])
    admission(root)
    return root


def inventory(root, limit):
    result = {}; total = 0; entries = 0
    for path in Path(root).rglob('*'):
        entries += 1
        if entries > MAX_ENTRIES:
            raise ValueError('Evidence entry-count budget exceeded')
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('Nonregular evidence: ' + str(path))
        if stat.S_ISREG(info.st_mode):
            if len(result) >= MAX_FILES:
                raise ValueError('Evidence file-count budget exceeded')
            total += info.st_size
            if total > limit:
                raise ValueError('Evidence byte budget exceeded')
            result[str(path.relative_to(root))] = {'bytes': info.st_size,
                                                  'identity': (info.st_dev, info.st_ino)}
    return dict(sorted(result.items()))


def evidence_files(root, limit):
    """Reject aggregate sizes before hashing; each FD read stays length-bounded."""
    before = inventory(root, limit)
    result = {}
    for name, metadata in before.items():
        fd = os.open(Path(root)/name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        primary = None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != metadata['identity']:
                raise ValueError('Evidence identity changed before bounded hash')
            result[name] = publisher._digest_fd(fd, metadata['bytes'])
        except BaseException as error:
            primary = error
            raise
        finally:
            errors = publisher._close_once([fd])
            if errors:
                if primary is not None:
                    primary.fd_close_errors = errors
                else:
                    raise RuntimeError('Evidence hash FD cleanup unknown: ' + repr(errors))
    if inventory(root, limit) != before:
        raise ValueError('Evidence changed during bounded hash')
    return result


def copy_archive(root, destination, limit):
    root, destination = Path(root), Path(destination)
    before = inventory(root, limit)
    if 'archive-placement.json' in before:
        raise ValueError('Worker evidence uses reserved archive receipt name')
    if destination.exists() or destination.is_symlink():
        raise ValueError('Stale archive destination')
    destination.mkdir(parents=True)
    records = {}
    for name, metadata in before.items():
        source = root/name; target = destination/name
        target.parent.mkdir(parents=True, exist_ok=True)
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        target_fd = None
        primary = None
        try:
            info = os.fstat(source_fd)
            if (not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != metadata['identity']
                    or info.st_size != metadata['bytes']):
                raise ValueError('Evidence source changed before archive')
            expected = publisher._digest_fd(source_fd, metadata['bytes'])
            os.lseek(source_fd, 0, os.SEEK_SET)
            target_fd = os.open(target, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            remaining = metadata['bytes']
            while True:
                data = os.read(source_fd, min(65536, remaining + 1))
                if not data:
                    if remaining:
                        raise ValueError('Short evidence source during archive')
                    break
                if len(data) > remaining:
                    raise ValueError('Evidence source grew during archive')
                remaining -= len(data)
                view = memoryview(data)
                while view:
                    written = os.write(target_fd, view)
                    if written <= 0:
                        raise ValueError('Archive write made no progress')
                    view = view[written:]
            observed = publisher._digest_fd(target_fd, metadata['bytes'])
            after = publisher._digest_fd(source_fd, metadata['bytes'])
            if expected != observed or expected != after:
                raise ValueError('Evidence archive digest mismatch')
            os.fsync(target_fd)
            records[name] = {'original_path': str(source), 'archive_path': str(target),
                             'before': expected, 'after_source': after, 'after_archive': observed}
        except BaseException as error:
            primary = error
            raise
        finally:
            errors = publisher._close_once([target_fd, source_fd])
            if errors:
                if primary is not None:
                    primary.fd_close_errors = errors
                else:
                    raise RuntimeError('Archive FD cleanup unknown: ' + repr(errors))
    if inventory(root, limit) != before:
        raise ValueError('Evidence inventory changed during archive')
    if set(inventory(destination, limit)) != set(before):
        raise ValueError('Unexpected archive entries')
    return records


def run_private(artifact, invoke, *, limit):
    """Invoke one existing supervised probe, archive afterwards, never rerun it."""
    artifact = Path(artifact)
    if artifact.exists() or artifact.is_symlink():
        raise ValueError('Stale probe archive; refusing a rerun')
    control = control_root(artifact)
    if control.exists() or control.is_symlink():
        raise ValueError('Stale probe control directory; refusing a rerun')
    # Create an independent terminal-record location BEFORE archive work or any
    # native invocation. Never recover archive errors by repeating its mkdir.
    control.mkdir(parents=True)
    root = Path(tempfile.mkdtemp(prefix='hepta-private-probe-', dir='/tmp'))
    receipt = {'schema': 'hepta.private-probe-archive.v1', 'private_root': str(root),
               'archive_root': str(artifact), 'worker_invocations': 0,
               'control_root': str(control),
               'qualified_archive': False, 'private_removed': False,
               'report_paths_rewritten': False, 'byte_limit': limit,
               'file_count_limit': MAX_FILES, 'entry_count_limit': MAX_ENTRIES,
               'runtime_disk_cap_enforced': False,
               'byte_limit_scope': 'Post-run evidence admission, not runtime disk-write cap'}
    status = 1
    try:
        proof = admission(root); write(root/'private-root-admission.json', proof)
        receipt['admission'] = proof
        receipt['worker_invocations'] = 1
        status = invoke(root)
        owned_path = root/'owned-process-receipt.json'
        owned = json.loads(owned_path.read_text()) if owned_path.is_file() else {}
        confirmed = owned.get('cleanup', {}).get('confirmed') is True
        receipt['owned_process_cleanup_confirmed'] = confirmed
        receipt['files'] = copy_archive(root, artifact, limit)
        if confirmed:
            shutil.rmtree(root)  # Own root after confirmed process cleanup/archive.
            receipt['private_removed'] = not root.exists()
            receipt['qualified_archive'] = status == 0 and receipt['private_removed']
        else:
            # Snapshot only, not a stable/qualified seal; never delete a root
            # potentially used by a live process. Preserve the failure evidence.
            receipt['archive_snapshot_only'] = True
            receipt['private_root_retained'] = True
            status = 1
    except BaseException as error:
        receipt['error'] = type(error).__name__ + ': ' + str(error)
        receipt['execution_or_filesystem_denied'] = isinstance(error, PermissionError) or isinstance(error.__cause__, PermissionError)
        receipt['private_root_retained'] = root.exists()
        if hasattr(error, 'fd_close_errors'):
            receipt['fd_close_errors'] = error.fd_close_errors
        status = 1
    # No archive mkdir or path-dependent recovery operation is attempted here.
    # The independent control directory was created before native/archive work.
    data=json.dumps(receipt,indent=2,sort_keys=True)+'\n'
    with (control/'archive-placement.json').open('x') as stream:
        stream.write(data)
    return status
