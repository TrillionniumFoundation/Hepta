"""Complete bounded ZIP CRC/readback; does not run project code."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import stat
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / 'namespace-single-fresh.zip'
EXPECTED_BYTES = 2127371
EXPECTED_SHA = 'fd5d85e2ebd6a3ffe2814b249530af54be48e1cca5f527f55b4a76f56ab4a731'

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def main():
    archive_raw = ARCHIVE.read_bytes()
    before = pin(archive_raw)
    assert before['bytes'] == EXPECTED_BYTES and before['sha256'] == EXPECTED_SHA
    output = ROOT / 'raw'
    output.mkdir(mode=0o700, exist_ok=False)
    members, names = [], set()
    with zipfile.ZipFile(ARCHIVE) as archive:
        infos = archive.infolist()
        assert len(infos) == 27 and sum(row.file_size for row in infos) == 11917163
        assert os.statvfs(ROOT).f_bavail * os.statvfs(ROOT).f_frsize >= sum(row.file_size for row in infos) + (128 << 20)
        for info in infos:
            name = info.filename
            relative = PurePosixPath(name)
            assert name and str(relative) == name and not relative.is_absolute()
            assert '..' not in relative.parts and '.' not in relative.parts and '\\' not in name
            assert name not in names and not info.is_dir() and not info.flag_bits & 1
            names.add(name)
            unix_mode = info.external_attr >> 16
            assert stat.S_ISREG(unix_mode) and stat.S_IMODE(unix_mode) == 0o644
            raw = archive.read(info)
            assert len(raw) == info.file_size and (zlib.crc32(raw) & 0xffffffff) == info.CRC
            target = output / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(stat.S_IMODE(unix_mode))
            assert target.read_bytes() == raw and stat.S_IMODE(target.stat().st_mode) == stat.S_IMODE(unix_mode)
            members.append({'member': name, **pin(raw), 'crc32': '%08x' % info.CRC,
                'compressed_bytes': info.compress_size, 'zip_compression': info.compress_type,
                'zip_unix_mode': unix_mode, 'mode': stat.S_IMODE(unix_mode),
                'create_system': info.create_system, 'flag_bits': info.flag_bits,
                'header_offset': info.header_offset, 'date_time': info.date_time})
    assert pin(ARCHIVE.read_bytes()) == before
    result = {'schema': 'hepta.namespace-fresh-original-zip-custody.v1',
        'status': 'COMPLETE_CRC_ALL_MEMBERS_AND_RESTORED_BYTES_MODES_PASS',
        'archive': before, 'members': members, 'files': 27, 'logical_bytes': 11917163,
        'original_directory_records': 0,
        'created_directory_modes': 'Local extraction scaffolding only; not original ZIP directory evidence.',
        'artifact_id': 14114048735, 'run_id': 43595690951, 'job_id': 132449559860,
        'harness_commit': 'ce4a685248b49dab31b9740ced57b0c84a8363e8',
        'product_executions_in_verifier': 0}
    path = ROOT / 'ZIP-MANIFEST.json'
    path.open('x').write(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'manifest': pin(path.read_bytes()), 'files': 27, 'logical_bytes':11917163, 'status': result['status']}))

if __name__ == '__main__':
    main()
