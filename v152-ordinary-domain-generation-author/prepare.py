"""Capture two frozen source-authoring roots only; no project import or product."""
import base64
import hashlib
import json
import os
import stat
import zlib
from pathlib import Path

ROOT = Path('/workspace/hia-cli-owner-bundle-domain-generation-custody-r1-20261115-dda7')
AUTHORS = {
    'domain': Path('/workspace/hia-cli-owner-bundle-domain-author-r2-20261115-dda7'),
    'generation': Path('/workspace/hia-cli-owner-bundle-generation-author-r1-20261115-dda7'),
}
HANDOFFS = {'domain': '255d764b02491e41a217d1f7727e33b81f3c4eee',
            'generation': 'ac9e7a27f261edfcb65e80f8ede40f3d0d751f27'}
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def seven(path):
    s = Path(path).lstat()
    return {k: getattr(s, k) for k in FIELDS}


def pin(raw, mode='100644'):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'mode': mode}


def read(path):
    p = Path(path)
    before = seven(p)
    assert stat.S_ISREG(before['st_mode']) and before['st_nlink'] == 1
    assert before['st_size'] <= 16 << 20
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        assert before == {k: getattr(os.fstat(fd), k) for k in FIELDS}
        with os.fdopen(fd, 'rb', closefd=False) as f:
            raw = f.read(before['st_size'] + 1)
        assert len(raw) == before['st_size']
        assert before == seven(p) == {k: getattr(os.fstat(fd), k) for k in FIELDS}
    finally:
        os.close(fd)
    assert raw.decode('utf-8').encode('utf-8') == raw
    return raw, {'path': str(p), 'pin': pin(raw, '100755' if before['st_mode'] & 0o111 else '100644'),
                 'stat': before}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def write(name, value):
    p = ROOT / name
    p.parent.mkdir(parents=True, exist_ok=True)
    raw = encoded(value)
    with p.open('xb') as f:
        assert f.write(raw) == len(raw)
    return {'logical': name, **read(p)[1]}


files = {}
directories = {}
inodes = set()


def walk(label, root, directory):
    before = seven(directory)
    assert stat.S_ISDIR(before['st_mode'])
    relative = directory.relative_to(root).as_posix()
    key = label if relative == '.' else label + '/' + relative
    directories[key] = before
    names = sorted(p.name for p in directory.iterdir())
    for name in names:
        path = directory / name
        if stat.S_ISDIR(path.lstat().st_mode):
            walk(label, root, path)
        else:
            raw, descriptor = read(path)
            inode = (descriptor['stat']['st_dev'], descriptor['stat']['st_ino'])
            assert inode not in inodes
            inodes.add(inode)
            files[label + '/' + path.relative_to(root).as_posix()] = {
                'descriptor': descriptor, 'text': raw.decode('utf-8')}
    assert before == seven(directory)
    assert names == sorted(p.name for p in directory.iterdir())


for label, author in AUTHORS.items():
    assert read(author / 'HANDOFF.json')[1]['pin']['git_blob'] == HANDOFFS[label]
    walk(label, author, author)
assert len(files) == 50
assert sum(name.startswith('domain/') for name in files) == 16
assert sum(name.startswith('generation/') for name in files) == 34
logical_bytes = sum(row['descriptor']['pin']['bytes'] for row in files.values())
assert logical_bytes == 6235152
payload = encoded({'schema': 'hepta.hia.cli-owner-selection.domain-generation-author.v1',
                   'roots': {name: str(path) for name, path in AUTHORS.items()},
                   'directories': directories, 'files': files,
                   'project_imports': 0, 'source_copy': 0, 'generation': 0, 'products': 0})
compressed = zlib.compress(payload, 6)
decoder = zlib.decompressobj()
decoded = decoder.decompress(compressed) + decoder.flush()
assert decoded == payload and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
parts = []
for offset in range(0, len(compressed), 196608):
    block = compressed[offset:offset + 196608]
    parts.append(write('parts/%04d.json' % len(parts), {
        'schema': 'hepta.hia.zlib-part.v1', 'index': len(parts), 'offset': offset,
        'compressed_whole': pin(compressed), 'piece': pin(block),
        'data': base64.b64encode(block).decode('ascii')}))
index = write('INDEX.json', {'schema': 'hepta.hia.cli-owner-selection.domain-generation-index.v1',
                            'payload': pin(payload), 'compressed': pin(compressed),
                            'parts': parts, 'files': len(files), 'logical_bytes': logical_bytes})
members = write('MEMBERS.json', {'roots': {name: str(path) for name, path in AUTHORS.items()},
                                'directories': directories,
                                'files': {name: row['descriptor'] for name, row in files.items()},
                                'files_count': len(files)})
for name, row in files.items():
    assert read(row['descriptor']['path']) == (row['text'].encode('utf-8'), row['descriptor'])
for name, expected in directories.items():
    label, _, tail = name.partition('/')
    assert seven(AUTHORS[label] / tail) == expected
local = write('LOCAL-READBACK.json', {
    'status': 'PASS_COMPLETE_AUTHOR_SOURCE_LOCAL_INVERSE', 'payload': pin(payload),
    'compressed': pin(compressed), 'files': len(files), 'parts': len(parts),
    'logical_bytes': logical_bytes, 'strict_zlib_eof': True,
    'all_full_bytes_modes_sevenstats_pathsets': True,
    'source_copy_generation_project_imports_products': 0})
leaves = parts + [index, members, local,
                  {'logical': 'prepare.py', **read(__file__)[1]},
                  {'logical': 'readback_actual_git.py', **read(ROOT / 'readback_actual_git.py')[1]}]
write('PUBLICATION-INPUTS.json', {'repository': 'TrillionniumFoundation/Hepta', 'leaves': leaves})
print(json.dumps({'files': len(files), 'parts': len(parts), 'logical_bytes': logical_bytes,
                  'compressed': pin(compressed)}, sort_keys=True))
