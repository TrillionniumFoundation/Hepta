"""Complete safe ZIP byte/CRC/mode readback; never executes restored files."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import stat
import time
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def write_json(path, value):
    path.open('x').write(json.dumps(value, indent=2, sort_keys=True) + '\n')


def main():
    started = time.monotonic_ns()
    folder = ROOT / 'actual'
    archive = folder / 'namespace-r20-expired-sections.zip'
    transfer = json.loads((folder / 'TRANSFER.json').read_bytes())
    before = archive.stat()
    archive_identity = identity(archive.read_bytes())
    assert archive_identity == {key: transfer[key] for key in ('bytes', 'sha256', 'git_blob')}
    output = folder / 'raw'
    assert not output.exists(), 'read-only reconcile existing restore before any repeat'
    output.mkdir()
    rows = []
    seen = set()
    with zipfile.ZipFile(archive) as stream:
        entries = stream.infolist()
        assert len(entries) == 46 and sum(entry.file_size for entry in entries) == 8003833
        for entry in entries:
            relative = PurePosixPath(entry.filename)
            assert entry.filename not in seen
            assert not relative.is_absolute() and '..' not in relative.parts
            assert relative.as_posix() == entry.filename and '\\' not in entry.filename and '\0' not in entry.filename
            assert not entry.is_dir() and entry.create_system == 3
            unix_mode = entry.external_attr >> 16
            assert stat.S_ISREG(unix_mode) and stat.S_IMODE(unix_mode) in (0o644, 0o700, 0o755, 0o500)
            assert not (entry.flag_bits & 1)
            seen.add(entry.filename)
            target = output.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            git = hashlib.sha1(b'blob ' + str(entry.file_size).encode() + b'\0')
            crc = 0
            count = 0
            with stream.open(entry) as source, target.open('xb') as destination:
                while block := source.read(1024 * 1024):
                    count += len(block)
                    assert count <= entry.file_size
                    digest.update(block)
                    git.update(block)
                    crc = zlib.crc32(block, crc)
                    destination.write(block)
            assert count == entry.file_size and (crc & 0xffffffff) == entry.CRC
            target.chmod(stat.S_IMODE(unix_mode))
            expected = {'bytes': count, 'sha256': digest.hexdigest(), 'git_blob': git.hexdigest()}
            assert identity(target.read_bytes()) == expected
            actual = target.lstat()
            assert stat.S_ISREG(actual.st_mode) and stat.S_IMODE(actual.st_mode) == stat.S_IMODE(unix_mode)
            assert actual.st_nlink == 1
            rows.append({'path': entry.filename, **expected, 'crc32': '%08x' % entry.CRC,
                         'compressed_bytes': entry.compress_size, 'header_offset': entry.header_offset,
                         'external_attr': entry.external_attr, 'zip_unix_mode': oct(unix_mode),
                         'mode': stat.S_IMODE(unix_mode), 'create_system': entry.create_system,
                         'zip_datetime': list(entry.date_time)})
    assert identity(archive.read_bytes()) == archive_identity
    after = archive.stat()
    assert (before.st_dev, before.st_ino, before.st_size, before.st_mode, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_mtime_ns, after.st_ctime_ns)
    write_json(folder / 'ZIP-MEMBERS.json', rows)
    directories = [path.relative_to(output).as_posix() for path in sorted(output.rglob('*')) if path.is_dir()]
    report = {'status': 'PASS_COMPLETE_ZIP_CRC_BYTES_GIT_SHA_MODE_READBACK', 'archive': archive_identity,
              'members': len(rows), 'raw_bytes': sum(row['bytes'] for row in rows),
              'regular_file_modes': sorted(set(row['mode'] for row in rows)),
              'directories_recorded_in_original_zip': 0, 'constructed_parent_directories': directories,
              'directory_modes_are_original_evidence': False,
              'all_member_bytes_read_and_crc_checked': True, 'all_restored_bytes_readback_equal': True,
              'archive_bytes_and_inode_stats_unchanged': True,
              'elapsed_ns': time.monotonic_ns() - started,
              'product_executions': 0, 'qualification': False}
    write_json(folder / 'CUSTODY-READBACK.json', report)
    print(json.dumps({key: value for key, value in report.items() if key != 'constructed_parent_directories'}))


if __name__ == '__main__':
    main()
