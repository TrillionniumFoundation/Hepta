"""Decode the actual immutable Git response and compare every author member."""
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import zlib

HERE = Path(__file__).resolve().parent
AUTHOR = Path('/tmp/hia-patch-terminal-quarantine-author-r1-dda7')
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': '100644'}


def main():
    raw = (HERE / 'CAPSULE-ACTUAL-GET.json').read_bytes()
    assert pin(raw)['git_blob'] == 'dce991e025674df9906bee0bb8261a516b43ce54'
    wrapper = json.loads(raw)
    compressed = base64.b64decode(wrapper['data'], validate=True)
    assert pin(compressed) == wrapper['compressed']
    decoder = zlib.decompressobj()
    payload = decoder.decompress(compressed) + decoder.flush()
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    assert pin(payload) == wrapper['payload']
    restored = json.loads(payload)
    for name, row in restored['files'].items():
        relative = PurePosixPath(name)
        assert not relative.is_absolute() and '..' not in relative.parts and str(relative) == name
        content = row['text'].encode('utf-8')
        assert pin(content) == row['pin']
        path = AUTHOR / name
        info = path.lstat()
        before = {key: getattr(info, key) for key in FIELDS}
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o644
        assert before == row['stat'] and path.read_bytes() == content
        assert {key: getattr(path.lstat(), key) for key in FIELDS} == before
    for name, mode in restored['directories'].items():
        relative = PurePosixPath(name)
        assert not relative.is_absolute() and '..' not in relative.parts and str(relative) == name
        info = (AUTHOR / name).lstat()
        assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == mode
    report = {'schema': 'hepta.hia.patch-terminal-quarantine.actual-git-readback.v1',
              'status': 'PASS_ACTUAL_GIT_COMPLETE_AUTHOR_DECODE',
              'actual_capsule': pin(raw), 'files': len(restored['files']),
              'directories': len(restored['directories']),
              'logical_bytes': sum(row['pin']['bytes'] for row in restored['files'].values()),
              'all_original_member_bytes_modes_and_seven_stats_compared': True,
              'products': 0, 'project_imports': 0, 'candidate_execution': 0,
              'original_product_status': 'FAIL native-11', 'whole': False}
    output = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    with (HERE / 'ACTUAL-GET-READBACK.json').open('xb') as stream:
        stream.write(output)
    print(json.dumps({'report': pin(output), 'status': report['status'],
                      'files': report['files'], 'logical_bytes': report['logical_bytes']}))


if __name__ == '__main__':
    main()
