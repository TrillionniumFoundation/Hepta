"""Archive and independently read back already closed finite-run originals.

This program runs no compiler, image, product or test. Tar uid/gid/mtime are
normalized; exact original identities and file/directory modes are recorded.
"""
from __future__ import annotations
from hashlib import sha256, sha1
import importlib.util
import json
import lzma
import os
from pathlib import Path
import stat
import tarfile
import time
import traceback

SOURCE = Path('/tmp/hia-core-compare-native-development-r3')
OUTPUT = Path('/workspace/scratch/e26ed3e2edcf/core-numeric-native-actual-r3')
COMMON = Path('/workspace/scratch/e26ed3e2edcf/core-numeric-native-plan-r3/control/common.py')
spec = importlib.util.spec_from_file_location('numeric_custody_fixed_paths', COMMON)
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)


def save(name, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with (OUTPUT / name).open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


class HashingReader:
    def __init__(self, stream, size):
        self.stream = stream
        self.digest = sha256()
        self.git = sha1(b'blob ' + str(size).encode() + b'\0')
        self.count = 0

    def read(self, count=-1):
        raw = self.stream.read(count)
        self.digest.update(raw)
        self.git.update(raw)
        self.count += len(raw)
        return raw


def main():
    started = time.monotonic()
    result = {'schema': 'hepta.hia.numeric-finite-original-custody.v1', 'status': 'HOLD',
              'source_commit': '4c2b702ba78fe3bb2d31de0e9812c0141e163881',
              'execution_authorization_commit': '99337722fdb3cb11845b8625b6fa2131be752aa8',
              'archive_is_not_product_execution': True, 'product_rerun': False}
    try:
        final = json.loads((SOURCE / 'FINAL.json').read_bytes())
        life_raw = (SOURCE / 'lifecycle.json').read_bytes()
        common.natural_owner(json.loads((SOURCE / 'wrapper.json').read_bytes()), life_raw)
        assert final['status'] == 'FINITE_NATIVE_DEVELOPMENT_PASS'
        assert json.loads(life_raw)['cleanup']['remaining_direct_children'] == []
        entries = []
        for path in sorted(SOURCE.rglob('*')):
            observed = path.lstat()
            assert stat.S_ISREG(observed.st_mode) or stat.S_ISDIR(observed.st_mode)
            is_file = stat.S_ISREG(observed.st_mode)
            if is_file:
                assert observed.st_nlink == 1
            entries.append({'path': path.relative_to(SOURCE).as_posix(),
                            'kind': 'file' if is_file else 'directory',
                            'mode': stat.S_IMODE(observed.st_mode),
                            'size': observed.st_size if is_file else 0,
                            'original_identity': common.identity(observed)})
        entries.sort(key=lambda item: (item['kind'] == 'file', item['path']))
        files = [item for item in entries if item['kind'] == 'file']
        assert len(files) == 229 and sum(item['size'] for item in files) == 290642150
        archive = OUTPUT / 'ALL-ORIGINALS.tar.xz'
        compressed_started = time.monotonic()
        with lzma.open(archive, 'xb', format=lzma.FORMAT_XZ, check=lzma.CHECK_SHA256, preset=6) as output:
            with tarfile.open(fileobj=output, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
                for item in entries:
                    path = SOURCE / item['path']
                    info = tarfile.TarInfo(item['path'])
                    info.mode = item['mode']
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ''
                    if item['kind'] == 'directory':
                        assert common.identity(path.lstat()) == item['original_identity']
                        info.type = tarfile.DIRTYPE
                        tar.addfile(info)
                        continue
                    info.type = tarfile.REGTYPE
                    info.size = item['size']
                    with common.parent_fd(path) as (parent, name):
                        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                        with os.fdopen(fd, 'rb') as stream:
                            assert common.identity(os.fstat(stream.fileno())) == item['original_identity']
                            reader = HashingReader(stream, item['size'])
                            tar.addfile(info, reader)
                            assert reader.count == item['size'] and stream.read(1) == b''
                            assert common.identity(os.fstat(stream.fileno())) == item['original_identity']
                            assert common.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == item['original_identity']
                            item['sha256'] = reader.digest.hexdigest()
                            item['git_blob_sha1'] = reader.git.hexdigest()
        result['compression_seconds'] = time.monotonic() - compressed_started
        save('ORIGINAL-MANIFEST.json', {'schema': 'hepta.hia.numeric-actual-original-manifest.v1',
             'source_root': str(SOURCE), 'root_mode': stat.S_IMODE(SOURCE.stat().st_mode),
             'regular_files': len(files), 'raw_bytes': sum(item['size'] for item in files),
             'normalized_tar_fields': ['uid=0', 'gid=0', 'mtime=0', 'uname empty', 'gname empty'],
             'entries': entries})
        digest = sha256()
        with archive.open('rb') as stream:
            while raw := stream.read(1048576):
                digest.update(raw)
        index = json.loads((SOURCE / 'native/trace/INDEX.json').read_bytes())
        expected_trace = ['native/trace/' + item['path'] for item in index['chunks']]
        trace_seen = []
        trace_digest = sha256()
        restored_bytes = 0
        restore_started = time.monotonic()
        with lzma.open(archive, 'rb') as stream:
            with tarfile.open(fileobj=stream, mode='r|') as tar:
                for ordinal, info in enumerate(tar):
                    item = entries[ordinal]
                    assert info.name.rstrip('/') == item['path'] and info.mode == item['mode']
                    assert info.uid == info.gid == info.mtime == 0
                    if item['kind'] == 'directory':
                        assert info.isdir()
                        continue
                    assert info.isfile() and info.size == item['size']
                    member = tar.extractfile(info)
                    verify = HashingReader(member, info.size)
                    is_trace = item['path'] in expected_trace
                    if is_trace:
                        assert item['path'] == expected_trace[len(trace_seen)]
                        trace_seen.append(item['path'])
                    while raw := verify.read(1048576):
                        restored_bytes += len(raw)
                        if is_trace:
                            trace_digest.update(raw)
                    assert verify.count == item['size']
                    assert verify.digest.hexdigest() == item['sha256']
                    assert verify.git.hexdigest() == item['git_blob_sha1']
                assert ordinal + 1 == len(entries)
            while stream.read(1048576):
                pass  # Consume and verify the complete XZ footer/checksum.
        assert trace_seen == expected_trace
        assert trace_digest.hexdigest() == final['actual_trace']['raw_sha256']
        assert restored_bytes == 290642150
        for item in entries:
            assert common.identity((SOURCE / item['path']).lstat()) == item['original_identity']
        result.update(status='ALL_ORIGINAL_BYTES_AND_MODES_RESTORED',
            archive_path=str(archive), archive_bytes=archive.stat().st_size,
            archive_sha256=digest.hexdigest(), original_files=229, original_directories=12,
            original_raw_bytes=290642150, archive_entries=len(entries),
            restored_raw_bytes=restored_bytes, trace_bytes=252282240,
            trace_sha256=trace_digest.hexdigest(), trace_chunks=len(trace_seen),
            original_identities_preserved=True, restore_seconds=time.monotonic()-restore_started)
    except BaseException:
        result['status'] = 'HOLD'
        result['error'] = traceback.format_exc()
    finally:
        result['seconds'] = time.monotonic() - started
        save('ARCHIVE-READBACK.json', result)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'ALL_ORIGINAL_BYTES_AND_MODES_RESTORED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
