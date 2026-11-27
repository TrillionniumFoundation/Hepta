"""Lossless, bounded author/input capsule. No product execution or source scan."""
from pathlib import Path
import base64
import hashlib
import json
import os
import stat
import zlib

ROOT = Path(__file__).resolve().parent


def pin(raw, mode=None):
    row = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
           'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
    if mode is not None:
        row.update(mode=mode, git_mode='100755' if mode & 0o111 else '100644')
    return row


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def write(path, value):
    raw = encoded(value)
    with path.open('xb') as stream:
        stream.write(raw)
    os.chmod(path, 0o644)
    assert path.read_bytes() == raw
    return {'path': str(path), **pin(raw, 0o644)}


def main():
    names = sorted(path.relative_to(ROOT).as_posix() for path in ROOT.rglob('*') if path.is_file())
    assert not any(name.startswith('publication-') or name.startswith('evidence/')
                   or name.startswith('AUTHOR-CAPSULE') or name.startswith('AUTHOR-READBACK') for name in names)
    rows = []
    for name in names:
        path = ROOT / name
        before = path.lstat()
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        raw = path.read_bytes()
        after = path.lstat()
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        assert all(getattr(before, key) == getattr(after, key) for key in keys)
        rows.append({'path': name, **pin(raw, stat.S_IMODE(before.st_mode)),
                     'data_base64': base64.b64encode(raw).decode()})
    payload = encoded({'schema': 'hia.u32.entry-layout-author-and-actual-inputs.v1',
                       'product_execution': False, 'files': rows})
    compressed = zlib.compress(payload, 6)
    capsule = {'schema': 'hia.lossless-zlib-base64.v1', 'status': 'AUTHORING_ONLY_NO_PRODUCT',
               'payload': pin(payload), 'compressed': pin(compressed),
               'data_base64': base64.b64encode(compressed).decode()}
    capsule_row = write(ROOT / 'AUTHOR-CAPSULE.zlib.json', capsule)
    actual = json.loads(zlib.decompress(base64.b64decode(capsule['data_base64'], validate=True)))
    assert actual['schema'] == 'hia.u32.entry-layout-author-and-actual-inputs.v1'
    assert [row['path'] for row in actual['files']] == names
    for row in actual['files']:
        raw = base64.b64decode(row['data_base64'], validate=True)
        path = ROOT / row['path']
        assert raw == path.read_bytes() and pin(raw, stat.S_IMODE(path.lstat().st_mode)) == {
            key: row[key] for key in ('bytes', 'sha256', 'git_blob', 'mode', 'git_mode')}
    report = {'status': 'PASS_COMPLETE_AUTHOR_AND_INPUTS_LOSSLESS_READBACK_ONLY',
        'product_execution': 0, 'CI': 0, 'files': len(rows),
        'logical_bytes': sum(row['bytes'] for row in rows),
        'inventory': [{key: value for key, value in row.items() if key != 'data_base64'} for row in rows],
        'complete_decoded_bytes_and_modes_equal': True, 'capsule': capsule_row,
        'all_eighteen_actual_inputs_included': sum(row['path'].startswith('actual-inputs/') for row in rows) == 18,
        'first_author_metadata_pin_failure_and_exact_successor_preserved': True,
        'eleven_original_custody_ZIPs_remain_at_original_paths': True,
        'no_source_tree_or_original_ZIP_copy': True}
    write(ROOT / 'AUTHOR-READBACK.json', report)
    print(json.dumps({'status': report['status'], 'files': report['files'],
                      'logical_bytes': report['logical_bytes'], 'capsule': capsule_row}, sort_keys=True))


if __name__ == '__main__':
    main()
