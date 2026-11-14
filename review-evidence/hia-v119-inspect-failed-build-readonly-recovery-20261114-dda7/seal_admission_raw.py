"""Lossless admission custody. Standard library only; no product imports."""
from pathlib import Path
import base64
import hashlib
import json
import os
import stat
import time
import zlib

ROOT = Path(__file__).resolve().parent
DEST = ROOT / 'admission-raw-custody-r1'

def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def metadata(path):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode):
        raise AssertionError('nonregular original: '+str(path))
    return {'device': value.st_dev, 'inode': value.st_ino,
            'mode': stat.S_IMODE(value.st_mode), 'bytes': value.st_size,
            'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns}

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True)+'\n').encode()

def write(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
    os.chmod(path, 0o644)

def main():
    started = time.monotonic_ns()
    rows = []
    for name in ('admission-attempt-r1', 'admission-outer-r1'):
        for path in sorted((ROOT/name).rglob('*')):
            if path.is_dir() and not path.is_symlink():
                continue
            before = metadata(path)
            raw = path.read_bytes()
            if before != metadata(path):
                raise AssertionError('original changed during capture')
            rows.append({'path': path.relative_to(ROOT).as_posix(), 'stat': before,
                         'pin': pin(raw), 'base64': base64.b64encode(raw).decode()})
    if not rows:
        raise AssertionError('empty original admission')
    actual = json.loads((ROOT/'admission-attempt-r1/RESULT.json').read_bytes())
    if actual['status'] != 'READ_ONLY_BUILD_ADMISSION_PASS':
        raise AssertionError('actual admission did not pass')
    payload = encoded({'schema': 'hepta.hia.inspect-admission-complete-raw.v1',
                       'original_parent_status': 'FAIL',
                       'admission_status': actual['status'], 'files': rows})
    archive = zlib.compress(payload, 9)
    if zlib.decompress(archive) != payload:
        raise AssertionError('full archive roundtrip differs')
    for row in json.loads(zlib.decompress(archive))['files']:
        raw = base64.b64decode(row['base64'], validate=True)
        path = ROOT/row['path']
        if pin(raw) != row['pin'] or path.read_bytes() != raw or metadata(path) != row['stat']:
            raise AssertionError('full logical readback differs')
    DEST.mkdir()
    (DEST/'chunks').mkdir()
    write(DEST/'RAW.zlib', archive)
    chunks = []
    for number, offset in enumerate(range(0, len(archive), 196608)):
        raw = archive[offset:offset+196608]
        envelope = encoded({'schema': 'hepta.hia.inspect-admission-raw-chunk.v1',
                            'ordinal': number, 'offset': offset, 'raw': pin(raw),
                            'base64': base64.b64encode(raw).decode()})
        relative = 'chunks/part-'+str(number).zfill(3)+'.json'
        write(DEST/relative, envelope)
        chunks.append({'path': relative, 'offset': offset, 'raw': pin(raw),
                       'transport': pin(envelope)})
    report = {'schema': 'hepta.hia.inspect-admission-raw-custody.v1',
              'status': 'FULL_STREAM_AND_LOGICAL_READBACK_PASS',
              'original_parent_status_unchanged': 'FAIL',
              'admission_status': actual['status'],
              'logical_files': len(rows), 'logical_bytes': sum(x['pin']['bytes'] for x in rows),
              'payload': pin(payload), 'archive': pin(archive), 'chunks': chunks,
              'full_zlib_decode': True, 'all_bytes_and_modes_equal_originals': True,
              'original_stat_unchanged': True, 'duplicate_restore_directory_created': False,
              'new_product_execution': 0, 'elapsed_ns': time.monotonic_ns()-started}
    write(DEST/'MANIFEST.json', encoded(report))
    print(json.dumps({k: report[k] for k in ('status','logical_files','logical_bytes','archive','elapsed_ns')}, sort_keys=True))

if __name__ == '__main__':
    main()
