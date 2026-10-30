#!/usr/bin/env python3
"""Archive immutable round-4 raw evidence as data, then read back every member.

Preparation of this script does not authorize execution. Run only after the
coordinator confirms that all model work has ended, with an explicit --execute.
The script never imports, launches, or extracts a program from the raw trees.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import lzma
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import time


WORKSPACE = Path('/workspace/scratch/5567a9db5cf4')
RAW_PARENT = WORKSPACE / 'round4-validation'
REPOSITORY = WORKSPACE / 'hepta-work'
JOBS = {
    'strong': ('strong-benchmark01', 'hia_optimizer_eval'),
    'runtime': ('runtime-cost01', 'hia_stateful_eval'),
}
BLOCK = 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def fingerprint(item):
    return (item.st_dev, item.st_ino, item.st_mode, item.st_size,
            item.st_mtime_ns, item.st_ctime_ns)


def stat_record(item):
    return {
        'device': item.st_dev, 'inode': item.st_ino,
        'mode': stat.S_IMODE(item.st_mode), 'bytes': item.st_size,
        'mtime_ns': item.st_mtime_ns, 'ctime_ns': item.st_ctime_ns,
        'uid': item.st_uid, 'gid': item.st_gid,
    }


def collect(root_name):
    root = RAW_PARENT / root_name
    require(root.resolve(strict=True) == root, 'raw root traverses a symlink')
    directories, files = {}, {}

    def visit(path):
        item = path.lstat()
        name = path.relative_to(RAW_PARENT).as_posix()
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,
                'unsafe archive name: ' + name)
        if stat.S_ISDIR(item.st_mode):
            directories[name] = (path, item)
            for child in sorted(path.iterdir(), key=lambda p: p.name):
                visit(child)
        else:
            require(stat.S_ISREG(item.st_mode), 'non-regular raw member: ' + str(path))
            files[name] = (path, item)

    visit(root)
    for extension in ('.stdout', '.stderr'):
        visit(RAW_PARENT / (root_name + extension))
    require(root_name in directories, 'raw input is not a directory')
    return directories, files


def open_bound(path, expected):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        require(fingerprint(os.fstat(fd)) == fingerprint(expected),
                'raw identity changed before read: ' + str(path))
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def digest_stream(stream):
    digest, count = sha256(), 0
    while True:
        data = stream.read(BLOCK)
        if not data:
            return count, digest.hexdigest()
        count += len(data)
        digest.update(data)


def digest_bound(path, expected):
    with open_bound(path, expected) as stream:
        count, digest = digest_stream(stream)
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(expected),
                'raw identity changed while hashing: ' + str(path))
    require(count == expected.st_size, 'raw length changed: ' + str(path))
    return digest


class HashingReader:
    def __init__(self, stream):
        self.stream, self.digest, self.count = stream, sha256(), 0

    def read(self, amount=-1):
        data = self.stream.read(amount)
        self.digest.update(data)
        self.count += len(data)
        return data


def header(name, item, directory=False):
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.size = 0 if directory else item.st_size
    info.mode, info.uid, info.gid = stat.S_IMODE(item.st_mode), item.st_uid, item.st_gid
    info.uname = info.gname = ''
    info.mtime = item.st_mtime_ns // 1_000_000_000
    info.pax_headers = {'mtime': '{}.{:09d}'.format(
        item.st_mtime_ns // 1_000_000_000, item.st_mtime_ns % 1_000_000_000)}
    return info


def assert_input_unchanged(root_name, directories, files):
    later_dirs, later_files = collect(root_name)
    for before, after, kind in ((directories, later_dirs, 'directory'),
                                (files, later_files, 'file')):
        require(set(before) == set(after), 'raw ' + kind + ' inventory changed')
        for name in before:
            require(fingerprint(before[name][1]) == fingerprint(after[name][1]),
                    'raw ' + kind + ' changed: ' + name)


def write_exclusive(path, payload):
    with path.open('xb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def archive_one(key):
    started_utc = datetime.now(timezone.utc).isoformat()
    started = time.monotonic_ns()
    root_name, family = JOBS[key]
    output = REPOSITORY / 'experiments' / family / 'round4_20261030'
    require(output.resolve(strict=True) == output and output.is_dir(),
            'output directory missing or traverses a symlink')
    final_archive, final_manifest = output / 'trial01.tar.xz', output / 'ARCHIVE.json'
    require(not os.path.lexists(final_archive) and not os.path.lexists(final_manifest),
            'refusing to overwrite an archive or ARCHIVE.json')
    directories, files = collect(root_name)
    file_records = []
    for name, (path, item) in sorted(files.items()):
        file_records.append({'member': name, 'source_path': str(path),
                             'bytes': item.st_size, 'sha256': digest_bound(path, item),
                             'source_stat': stat_record(item)})
    expected = {row['member']: row for row in file_records}
    hashing_finished = time.monotonic_ns()
    archive_published = manifest_published = False
    with tempfile.TemporaryDirectory(prefix='.round4-raw-archive-', dir=output) as stage_name:
        stage = Path(stage_name)
        staged_archive, staged_manifest = stage / 'trial01.tar.xz', stage / 'ARCHIVE.json'
        staged_identity = None
        try:
            with tarfile.open(staged_archive, 'w:xz', format=tarfile.PAX_FORMAT, preset=6) as archive:
                for name, (_, item) in sorted(directories.items()):
                    archive.addfile(header(name, item, directory=True))
                for name, (path, item) in sorted(files.items()):
                    with open_bound(path, item) as source:
                        reader = HashingReader(source)
                        archive.addfile(header(name, item), reader)
                        require(reader.count == item.st_size
                                and reader.digest.hexdigest() == expected[name]['sha256'],
                                'bytes changed while archiving: ' + name)
                        require(fingerprint(os.fstat(source.fileno())) == fingerprint(item),
                                'raw identity changed while archiving: ' + name)
            with staged_archive.open('rb') as stream:
                os.fsync(stream.fileno())
                archive_bytes, archive_sha = digest_stream(stream)
            compression_finished = time.monotonic_ns()
            seen, verified_files, verified_dirs = set(), 0, 0
            verified_bytes = 0
            with lzma.open(staged_archive, 'rb') as decoded:
                with tarfile.open(fileobj=decoded, mode='r:') as archive:
                    for member in archive:
                        name = member.name.rstrip('/') if member.isdir() else member.name
                        require(name not in seen, 'duplicate archive member: ' + name)
                        seen.add(name)
                        if member.isdir():
                            require(name in directories and member.size == 0,
                                    'unexpected archive directory: ' + name)
                            verified_dirs += 1
                        else:
                            require(member.isfile() and name in expected,
                                    'unexpected or non-regular archive member: ' + name)
                            with archive.extractfile(member) as stream:
                                count, digest = digest_stream(stream)
                            require(count == member.size == expected[name]['bytes']
                                    and digest == expected[name]['sha256'],
                                    'archive member readback differs: ' + name)
                            verified_files += 1
                            verified_bytes += count
                # Consume to the XZ EOF so decoder checksum/trailer failures
                # cannot hide behind the tar end marker. Never extract to disk.
                while decoded.read(BLOCK):
                    pass
            require(seen == set(expected) | set(directories), 'archive member set differs')
            assert_input_unchanged(root_name, directories, files)
            verification_finished = time.monotonic_ns()
            staged_identity = staged_archive.stat()
            os.link(staged_archive, final_archive)  # Atomic, fails if name already exists.
            archive_published = True
            sync_directory(output)
            archive_publication_finished = time.monotonic_ns()
            manifest = {
                'schema': 'hepta.hia.round4.complete-raw-archive.v1',
                'kind': key, 'recorded_utc': started_utc,
                'source_root': str(RAW_PARENT / root_name),
                'sibling_logs': [root_name + '.stdout', root_name + '.stderr'],
                'archive': {'name': final_archive.name, 'bytes': archive_bytes,
                            'sha256': archive_sha, 'format': 'pax tar + xz',
                            'compression_preset': 6},
                'files': file_records,
                'directories': [{'member': name, 'source_stat': stat_record(item)}
                                for name, (_, item) in sorted(directories.items())],
                'file_count': len(files), 'directory_count': len(directories),
                'raw_file_bytes': sum(row['bytes'] for row in file_records),
                'roundtrip': {'passed': True, 'all_member_names_match': True,
                              'every_file_size_and_sha256_matches': True,
                              'source_inventory_and_identity_unchanged': True,
                              'xz_stream_consumed_to_eof': True,
                              'verified_files': verified_files,
                              'verified_directories': verified_dirs,
                              'verified_raw_file_bytes': verified_bytes},
                'costs': {
                    'source_inventory_and_hash_ns': hashing_finished - started,
                    'compression_fsync_and_archive_hash_ns': compression_finished - hashing_finished,
                    'complete_readback_and_source_recheck_ns': verification_finished - compression_finished,
                    'archive_publication_ns': archive_publication_finished - verification_finished,
                    'collection_and_roundtrip_wall_ns': archive_publication_finished - started,
                    'intervals_are_sequential_and_nonoverlapping': True,
                    'interpreter_startup_imports_and_argument_parsing_included': False,
                    'final_manifest_encoding_write_publication_and_cleanup_included': False,
                    'not_added_to_registered_experiment_gate': True,
                },
                'audit_script': {'path': str(Path(__file__).resolve()),
                                 'sha256': sha256(Path(__file__).read_bytes()).hexdigest()},
                'python': {'executable': sys.executable, 'version': sys.version},
                'scope': {'raw_files_only': True, 'raw_programs_executed': False,
                          'readout_or_audit_overwritten': False, 'performance_retimed': False,
                          'model_called': False, 'deployment_authority': False},
            }
            write_exclusive(staged_manifest,
                            (json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + '\n').encode())
            os.link(staged_manifest, final_manifest)
            manifest_published = True
            sync_directory(output)
            return {'kind': key, 'archive': str(final_archive), 'manifest': str(final_manifest),
                    'file_count': len(files), 'directory_count': len(directories),
                    'raw_bytes': manifest['raw_file_bytes'], 'archive_bytes': archive_bytes,
                    'archive_sha256': archive_sha,
                    'manifest_sha256': sha256(final_manifest.read_bytes()).hexdigest(),
                    'collection_and_roundtrip_wall_ns': manifest['costs']['collection_and_roundtrip_wall_ns'],
                    'roundtrip_passed': True}
        except BaseException:
            # Only remove this attempt's own archive if the complete manifest
            # has not been published. Existing caller files are never touched.
            if archive_published and not manifest_published and staged_identity is not None:
                try:
                    present = final_archive.lstat()
                    if (present.st_dev, present.st_ino) == (staged_identity.st_dev, staged_identity.st_ino):
                        final_archive.unlink()
                except FileNotFoundError:
                    pass
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', choices=('strong', 'runtime', 'all'), required=True)
    parser.add_argument('--execute', action='store_true',
                        help='Required explicit execution switch; coordinator must first end model work.')
    args = parser.parse_args()
    if not args.execute:
        parser.error('--execute is required; static preparation is not authorization')
    keys = list(JOBS) if args.dataset == 'all' else [args.dataset]
    for key in keys:
        print(json.dumps(archive_one(key), sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
