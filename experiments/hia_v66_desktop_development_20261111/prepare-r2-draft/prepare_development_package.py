"""Prepare exact source bytes in a new private development root without Git/network.

This is a declared-source materialization, not a complete Git object database.
The published checked contract is stale and is deliberately preserved unchanged.
"""
from hashlib import sha1, sha256
import importlib
import importlib.metadata
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

ROOT = Path('/home/qian-qi/he26v66devr2')
SOURCE = ROOT / 's'
PYTHON = Path('/home/qian-qi/hia-e26e-python314-linux-r1/venv/bin/python')
B3 = Path('/home/qian-qi/he26v65r2/q/cold.cold/qualification.evidence/B3.image.bin')
B3_SHA = '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
HEAD = 'e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6'
TREE = 'bfcbb39e22371cbb2292c89a2fa1ca010353a56f'
MANIFEST_SHA = '7a45af0a08d837c3ecba97cd47b54e1a3eb8838c838d03a14a82d58df3e799af'
ARCHIVE_SHA = 'f0f0a0fd570fa2d260d95f25193b1d9571d9614bbc7ab1c22607f23112ae5428'
ARCHIVE_BLOB = 'ff3ff3b9fe91d76952d2a4e84e0f33c5a09a1ede'
ARCHIVE_SIZE = 5829996
MEMBERS = 1666
DECODED_BYTES = 30794542
MANIFEST = ROOT / 'inputs/canonical-e09-development-package.json'
ARCHIVE = ROOT / 'inputs/e09-program-and-declared-source.tar.xz'
os.umask(0o077)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def identity(s):
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def read_regular(path, expected=None, mode=None):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
                and before.st_nlink == 1, 'not a private regular file: ' + str(path))
        if mode is not None:
            require(stat.S_IMODE(before.st_mode) == mode, 'file mode differs: ' + str(path))
        raw = f.read()
        require(identity(before) == identity(os.fstat(f.fileno())),
                'file changed while reading: ' + str(path))
    require(identity(before) == identity(path.lstat()), 'file binding changed: ' + str(path))
    digest = sha256(raw).hexdigest()
    require(expected is None or digest == expected, 'file digest differs: ' + str(path))
    return raw, {'path': str(path), 'bytes': len(raw), 'sha256': digest,
                 'mode': oct(before.st_mode), 'uid': before.st_uid, 'nlink': before.st_nlink}


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(path, raw, mode=0o600):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), mode)
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    check, _ = read_regular(path, sha256(raw).hexdigest(), mode)
    require(check == raw, 'created bytes differ: ' + str(path))


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def save(report):
    target = ROOT / 'preparation.json'
    temporary = ROOT / 'preparation.next.json'
    create(temporary, wire(report))
    os.replace(temporary, target)
    sync_dir(ROOT)


def safe_path(value):
    require(type(value) is str and value and '\0' not in value
            and not value.startswith('/') and '\\' not in value,
            'invalid archive path')
    p = PurePosixPath(value)
    require(p.parts and str(p) == value and all(v not in ('', '.', '..', '.git') for v in p.parts),
            'noncanonical archive path: ' + value)
    return p


def hexadecimal(value, length):
    return type(value) is str and len(value) == length and all(c in '0123456789abcdef' for c in value)


def read_manifest(raw):
    require(len(raw) == 473051 and sha256(raw).hexdigest() == MANIFEST_SHA,
            'manifest identity differs')
    m = json.loads(raw)
    require(m['schema'] == 'hepta.hia.canonical-development-source-package.v1'
            and m['canonical_commit'] == HEAD and m['canonical_tree'] == TREE,
            'canonical source identity differs')
    require(m['complete_git_object_closure'] is False
            and m['complete_declared_source_closure'] is True
            and m['source_contract_checked_document_current'] is False
            and m['native_or_cold_qualification_claimed'] is False,
            'development package scope differs')
    require(m['member_count'] == MEMBERS and m['non_experimental_members'] == 1642
            and m['decoded_bytes'] == DECODED_BYTES and m['declared_source_count'] == 661,
            'source population differs')
    require(m['archive'] == {'path': ARCHIVE.name, 'size': ARCHIVE_SIZE,
                            'sha256': ARCHIVE_SHA, 'git_blob_sha1': ARCHIVE_BLOB},
            'archive declaration differs')
    rows = m['files']
    require(type(rows) is list and len(rows) == MEMBERS, 'member list differs')
    by_path = {}
    for row in rows:
        require(type(row) is dict and set(row) == {'path', 'mode', 'size', 'git_blob_sha1', 'sha256'},
                'member declaration keys differ')
        name = str(safe_path(row['path']))
        require(name not in by_path and row['mode'] in ('100644', '100755')
                and type(row['size']) is int and 0 <= row['size'] <= DECODED_BYTES
                and hexadecimal(row['git_blob_sha1'], 40) and hexadecimal(row['sha256'], 64),
                'invalid member declaration: ' + name)
        by_path[name] = row
    require(sum(r['size'] for r in rows) == DECODED_BYTES, 'decoded source size differs')
    declared = m['declared_source_paths']
    require(type(declared) is list and len(declared) == 661
            and len(set(declared)) == 661 and set(declared) <= set(by_path),
            'declared source closure differs')
    expected_dirs = set()
    for name in by_path:
        expected_dirs.update(str(p) for p in PurePosixPath(name).parents if str(p) != '.')
    require(not expected_dirs.intersection(by_path), 'file/directory collision in package')
    return m, by_path, expected_dirs


def verify_bytes(raw, row):
    require(len(raw) == row['size'] and sha256(raw).hexdigest() == row['sha256']
            and sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob_sha1'],
            'canonical member bytes differ: ' + row['path'])


def make_source_dirs(root, expected_dirs):
    root.mkdir(mode=0o700)
    for name in sorted(expected_dirs, key=lambda p: (p.count('/'), p)):
        (root / name).mkdir(mode=0o700)


def synchronize_tree(root):
    for directory, children, files in os.walk(root, topdown=False, followlinks=False):
        sync_dir(directory)
    sync_dir(root.parent)


def extract_package(raw, by_path, expected_dirs):
    require(len(raw) == ARCHIVE_SIZE and sha256(raw).hexdigest() == ARCHIVE_SHA
            and sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == ARCHIVE_BLOB,
            'archive bytes differ')
    make_source_dirs(SOURCE, expected_dirs)
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as archive:
        for member in archive:
            require(len(seen) < MEMBERS, 'unexpected extra archive member')
            name = str(safe_path(member.name))
            require(name in by_path and name not in seen and member.isfile()
                    and not member.issym() and not member.islnk(), 'unexpected archive member: ' + name)
            row = by_path[name]
            mode = int(row['mode'], 8) & 0o777
            require(member.size == row['size'] and member.mode == mode
                    and member.uid == 0 and member.gid == 0 and member.mtime == 0,
                    'archive member metadata differs: ' + name)
            stream = archive.extractfile(member)
            require(stream is not None, 'missing archive file bytes')
            with stream:
                data = stream.read(row['size'] + 1)
            verify_bytes(data, row)
            create(SOURCE / name, data, mode)
            seen.add(name)
    require(seen == set(by_path), 'archive is missing declared members')
    synchronize_tree(SOURCE)


def scan_source(root, by_path, expected_dirs, label, read_only=False):
    seen_files, seen_dirs, rows = set(), set(), []
    require(root.is_dir() and not root.is_symlink(), 'source root is not a real directory')
    for directory, dirs, files in os.walk(root, followlinks=False):
        d = Path(directory)
        ds = d.lstat()
        require(stat.S_ISDIR(ds.st_mode) and ds.st_uid == os.geteuid()
                and stat.S_IMODE(ds.st_mode) == (0o500 if read_only else 0o700),
                'source directory identity differs: ' + str(d))
        for name in dirs:
            p = d / name
            require(not p.is_symlink(), 'source directory symlink')
            seen_dirs.add(p.relative_to(root).as_posix())
        for name in files:
            p = d / name
            relative = p.relative_to(root).as_posix()
            require(relative in by_path and relative not in seen_files, 'extra source file: ' + relative)
            row = by_path[relative]
            mode = int(row['mode'], 8) & 0o777
            raw, facts = read_regular(p, row['sha256'], mode & ~0o222 if read_only else mode)
            verify_bytes(raw, row)
            rows.append({'path': relative, 'mode': row['mode'], 'observed_mode': facts['mode'],
                         'size': len(raw), 'sha256': facts['sha256'], 'git_blob_sha1': row['git_blob_sha1'],
                         'uid': facts['uid'], 'nlink': facts['nlink']})
            seen_files.add(relative)
    require(seen_files == set(by_path) and seen_dirs == expected_dirs,
            'source filesystem membership differs')
    raw = wire({'schema': 'hia.declared-source-materialization-scan.v1',
                'canonical_commit': HEAD, 'canonical_tree': TREE, 'complete_git_object_closure': False,
                'manifest_sha256': MANIFEST_SHA, 'root': str(root), 'read_only': read_only,
                'files': sorted(rows, key=lambda r: r['path'])})
    evidence = ROOT / 'preparation-evidence' / (label + '.json')
    create(evidence, raw)
    sync_dir(evidence.parent)
    return {'path': str(root), 'member_count': len(rows), 'all_canonical_bytes_modes_verified': True,
            'read_only': read_only, 'complete_git_object_closure': False,
            'scan': str(evidence), 'scan_bytes': len(raw), 'scan_sha256': sha256(raw).hexdigest()}


def copy_source(target, by_path, expected_dirs):
    make_source_dirs(target, expected_dirs)
    for name, row in sorted(by_path.items()):
        mode = int(row['mode'], 8) & 0o777
        raw, _ = read_regular(SOURCE / name, row['sha256'], mode)
        verify_bytes(raw, row)
        create(target / name, raw, mode)
    synchronize_tree(target)


def seal_source():
    for directory, dirs, files in os.walk(SOURCE, topdown=False, followlinks=False):
        for name in files:
            p = Path(directory) / name
            s = p.lstat()
            require(stat.S_ISREG(s.st_mode), 'special published source member')
            os.chmod(p, stat.S_IMODE(s.st_mode) & ~0o222)
        os.chmod(directory, 0o500)
    synchronize_tree(SOURCE)


def old_inputs():
    pins = json.loads((ROOT / 'control/old-input-pins.json').read_bytes())
    return [read_regular(Path(path), digest)[1] for path, digest in sorted(pins.items())]


def main():
    report = {'schema': 'hia.desktop-package-development-preparation.v1',
              'status': 'PREPARATION_HOLD', 'root': str(ROOT), 'source': str(SOURCE),
              'canonical_commit': HEAD, 'canonical_tree': TREE,
              'source_manifest': str(MANIFEST), 'source_manifest_sha256': MANIFEST_SHA,
              'complete_git_object_closure': False, 'source_contract_checked_document_current': False,
              'tests_requested': False, 'qualification_requested': False,
              'whole_native_delivery_qualified': False, 'cold_180_second_gate_modified': False,
              'old_source_checkouts_accessed': False, 'network_or_git_requested': False,
              'outer_guardian_acceptance_required': True,
              'outer_acceptance': 'natural exit0; identities preserved; ECHILD; no signals/errors/overflow/owned_child_sigkill'}
    try:
        require(Path(sys.executable).resolve() == PYTHON.resolve(), 'wrong Python')
        require(not any(os.path.lexists(p) for p in (SOURCE, ROOT/'wire-r7/s', ROOT/'cli/s')),
                'source destination already exists')
        report['old_inputs_before'] = old_inputs()
        report['compiler_original_before'] = read_regular(B3, B3_SHA)[1]
        report['compiler_copy'] = read_regular(ROOT/'inputs/B3.image.bin', B3_SHA)[1]
        dependencies = {}
        expected = {'z3-solver': '4.15.4.0', 'jsonschema': '4.25.1', 'setuptools': '78.1.1',
                    'wheel': '0.46.3', 'zstandard': '0.25.0'}
        for module, distribution in [('z3','z3-solver'),('jsonschema','jsonschema'),
                                     ('setuptools','setuptools'),('wheel','wheel'),('zstandard','zstandard')]:
            imported = importlib.import_module(module)
            version = importlib.metadata.version(distribution)
            require(version == expected[distribution], 'dependency version differs: ' + distribution)
            dependencies[distribution] = {'version': version, 'imported': True,
                                          'file': getattr(imported, '__file__', None)}
        report['python'] = {'executable': str(PYTHON), 'version': sys.version,
                            'sha256': read_regular(PYTHON.resolve())[1]['sha256']}
        require(report['python']['sha256'] == 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493',
                'interpreter pin differs')
        report['dependencies'] = dependencies
        manifest_raw, report['manifest_input'] = read_regular(MANIFEST, MANIFEST_SHA)
        manifest, by_path, directories = read_manifest(manifest_raw)
        archive_raw, report['archive_input'] = read_regular(ARCHIVE, ARCHIVE_SHA)
        report['checked_contract_state'] = manifest['checked_contract_state']
        report['source_population'] = {'members': MEMBERS, 'declared_source_count': 661,
                                       'decoded_bytes': DECODED_BYTES, 'non_experimental_members': 1642}
        save(report)
        print(json.dumps({'stage': 'PACKAGE_VALIDATED', 'members': MEMBERS,
                          'network_or_git_requested': False}), flush=True)
        extract_package(archive_raw, by_path, directories)
        report['published_before_seal'] = scan_source(SOURCE, by_path, directories, 'published-before')
        save(report)
        report['candidate_sources'] = {}
        for name in ('wire-r7', 'cli'):
            target = ROOT / name / 's'
            copy_source(target, by_path, directories)
            report['candidate_sources'][name] = scan_source(target, by_path, directories, name + '-source')
            save(report)
        seal_source()
        report['published_after_seal'] = scan_source(SOURCE, by_path, directories, 'published-after', True)
        report['old_inputs_after'] = old_inputs()
        report['compiler_original_after'] = read_regular(B3, B3_SHA)[1]
        require(report['old_inputs_before'] == report['old_inputs_after'], 'old input facts changed')
        require(report['compiler_original_before'] == report['compiler_original_after'], 'old compiler changed')
        require(read_regular(MANIFEST, MANIFEST_SHA)[0] == manifest_raw
                and read_regular(ARCHIVE, ARCHIVE_SHA)[0] == archive_raw, 'package input changed')
        nested = ROOT.parent / 'he26v65r2/q/cold.cold/qualification.json'
        report['old_nested_report_stat'] = {'path': str(nested), 'exists': nested.exists()}
        if nested.exists():
            report['old_nested_report_stat'].update(bytes=nested.stat().st_size, regular=nested.is_file())
        report['old_nested_report_prior_wording_correction'] = 'Earlier empty bounded read did not establish absence.'
        report['status'] = 'DEVELOPMENT_SOURCE_MATERIALIZED_PENDING_OUTER_GUARDIAN'
        save(report)
        print(json.dumps({'status': report['status'], 'source': str(SOURCE),
                          'wire_source': str(ROOT/'wire-r7/s'), 'cli_source': str(ROOT/'cli/s'),
                          'source_manifest': str(MANIFEST), 'complete_git_object_closure': False}), flush=True)
        return 0
    except BaseException as error:
        report.update(status='PREPARATION_HOLD', error_type=type(error).__name__, error=str(error))
        try:
            save(report)
        except BaseException:
            pass
        raise


if __name__ == '__main__':
    raise SystemExit(main())
