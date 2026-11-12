"""Preserve every recovered original Proof result byte without rerunning it."""
from pathlib import Path
from hashlib import sha1, sha256
import base64
import json
import stat
import zlib

ROOT = Path(__file__).resolve().parent
OLD = ROOT.parent / 'v78-proof-contract-development-r1'


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def encode(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n').encode()


def stable_read(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError('non-regular recovery input: ' + str(path))
    raw = path.read_bytes()
    after = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, key) != getattr(after, key) for key in fields):
        raise ValueError('recovery input changed: ' + str(path))
    return raw, before.st_mode & 0o7777


def main():
    files = {}
    for family in ('checkpoint-r2', 'component-r5', 'original-callers-r1'):
        for path in sorted((OLD / family).rglob('*')):
            if '__pycache__' in path.parts:
                continue
            if path.is_symlink():
                raise ValueError('symlink in original records: ' + str(path))
            if not path.is_file():
                continue
            raw, mode = stable_read(path)
            try:
                content, encoding = raw.decode('utf-8'), 'utf-8'
            except UnicodeError:
                content, encoding = base64.b64encode(raw).decode('ascii'), 'base64'
            files['original/' + path.relative_to(OLD).as_posix()] = {
                **identity(raw), 'observed_recovery_posix_mode': oct(mode),
                'encoding': encoding, 'content': content}
    for name in ('ORIGINAL-PROOF-RECOVERY.json', 'recover_original_proof.py', 'package_original_proof.py'):
        raw, mode = stable_read(ROOT / name)
        files['recovery/' + name] = {**identity(raw), 'observed_recovery_posix_mode': oct(mode),
                                     'encoding': 'utf-8', 'content': raw.decode('utf-8')}
    packet = {'schema': 'hia.recovered-original-proof.complete-bytes.v80.r1',
              'files': files, 'file_count': len(files),
              'all_original_component_records_included': True,
              'only_excluded_paths': ['__pycache__'],
              'new_tests_executed': False, 'qualification_transferred': False,
              'whole_native': False}
    raw = encode(packet)
    compressed = zlib.compress(raw, 9)
    payload = base64.b64encode(compressed).decode('ascii')
    chunks = []
    width = 350000
    count = (len(payload) + width - 1) // width
    destination = ROOT / 'complete-original-capsule-r1'
    destination.mkdir()
    for number in range(count):
        text = encode({'schema': 'hia.recovered-original-proof.complete-bytes.chunk.v1',
                       'part': number, 'part_count': count,
                       'base64_offset': number * width,
                       'payload': payload[number * width:(number + 1) * width]})
        name = 'part-%03d.json' % number
        (destination / name).write_bytes(text)
        if (destination / name).read_bytes() != text:
            raise ValueError('new chunk readback differs')
        chunks.append({'path': name, **identity(text)})
    index = {'schema': 'hia.recovered-original-proof.complete-bytes.index.v80.r1',
             'source_original_cumulative_git_blob': '97c1542bd4d8a35a389168dc6e76273dbd575de7',
             'complete_packet': identity(raw), 'zlib_packet': identity(compressed),
             'base64_characters': len(payload), 'file_count': len(files),
             'text_files': sum(x['encoding'] == 'utf-8' for x in files.values()),
             'binary_files': sum(x['encoding'] == 'base64' for x in files.values()),
             'original_total_bytes': sum(x['bytes'] for x in files.values()),
             'chunks': chunks,
             'manifest': {p: {k: v for k, v in x.items() if k != 'content'} for p, x in files.items()},
             'git_acknowledgements': 'Not yet acquired at packaging time.',
             'new_tests_executed': False, 'whole_native': False}
    encoded = encode(index)
    (destination / 'INDEX.json').write_bytes(encoded)
    rebuilt = ''.join(json.loads((destination / x['path']).read_bytes())['payload'] for x in chunks)
    if zlib.decompress(base64.b64decode(rebuilt, validate=True)) != raw:
        raise ValueError('all chunk decode differs')
    print(json.dumps({'file_count': len(files), 'raw_bytes': len(raw),
                      'compressed_bytes': len(compressed), 'chunks': count,
                      'index': identity(encoded), 'directory': str(destination)}, sort_keys=True))


if __name__ == '__main__':
    main()
