"""Decode exact Git GET payloads and compare the complete two frozen author roots."""
import base64
import hashlib
import json
import os
import stat
import zlib
from pathlib import Path

ROOT = Path('/workspace/hia-cli-owner-bundle-domain-generation-custody-r1-20261115-dda7')
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
    return raw, before


def current(descriptor):
    raw, before = read(descriptor['path'])
    assert before == descriptor['stat']
    assert pin(raw, '100755' if before['st_mode'] & 0o111 else '100644') == descriptor['pin']
    return raw


publication = json.loads(read(ROOT / 'PUBLICATION-INPUTS.json')[0])
actual = {}
for index, descriptor in enumerate(publication['leaves']):
    raw = read(ROOT / 'GIT' / ('%03d-GET.txt' % index))[0]
    assert pin(raw, descriptor['pin']['mode']) == descriptor['pin']
    assert current(descriptor) == raw
    assert json.loads(read(ROOT / 'GIT' / ('%03d-ACK.json' % index))[0])['sha'] == descriptor['pin']['git_blob']
    assert json.loads(read(ROOT / 'GIT' / ('%03d-VERIFIED.json' % index))[0])['full_get_exact'] is True
    assert descriptor['logical'] not in actual
    actual[descriptor['logical']] = raw
archive_index = json.loads(actual['INDEX.json'])
blocks = []
offset = 0
for index, descriptor in enumerate(archive_index['parts']):
    part = json.loads(actual[descriptor['logical']])
    block = base64.b64decode(part['data'], validate=True)
    assert part['index'] == index and part['offset'] == offset
    assert part['compressed_whole'] == archive_index['compressed']
    assert pin(block) == part['piece']
    blocks.append(block)
    offset += len(block)
compressed = b''.join(blocks)
assert pin(compressed) == archive_index['compressed']
decoder = zlib.decompressobj()
payload = decoder.decompress(compressed) + decoder.flush()
assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
assert pin(payload) == archive_index['payload']
value = json.loads(payload)
members = json.loads(actual['MEMBERS.json'])
assert value['roots'] == members['roots'] and value['directories'] == members['directories']
assert set(value['files']) == set(members['files'])
assert len(value['files']) == archive_index['files'] == 50
total = 0
for name, row in value['files'].items():
    assert row['descriptor'] == members['files'][name]
    raw = row['text'].encode('utf-8')
    assert current(row['descriptor']) == raw
    total += len(raw)
assert total == archive_index['logical_bytes'] == 6235152
current_files = []
current_directories = {}


def walk(label, root, directory):
    before = seven(directory)
    assert stat.S_ISDIR(before['st_mode'])
    relative = directory.relative_to(root).as_posix()
    name = label if relative == '.' else label + '/' + relative
    current_directories[name] = before
    entries = sorted(directory.iterdir())
    for child in entries:
        if stat.S_ISDIR(child.lstat().st_mode):
            walk(label, root, child)
        else:
            current_files.append(label + '/' + child.relative_to(root).as_posix())
    assert before == seven(directory) and entries == sorted(directory.iterdir())


for label, name in value['roots'].items():
    root = Path(name)
    walk(label, root, root)
assert current_directories == value['directories']
assert sorted(current_files) == sorted(value['files'])
for row in value['files'].values():
    assert seven(row['descriptor']['path']) == row['descriptor']['stat']
report = {
    'status': 'PASS_COMPLETE_ACTUAL_GIT_AUTHOR_SOURCE_RESTORE', 'files': 50,
    'logical_bytes': total, 'parts': len(blocks), 'payload': archive_index['payload'],
    'compressed': archive_index['compressed'], 'strict_zlib_eof': True,
    'all_actual_GET_ACK_and_original_bytes_modes_stats_pathsets': True,
    'source_copy_generation_project_imports_products': 0, 'no_qualification_inherited': True}
raw = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
with (ROOT / 'ACTUAL-GIT-READBACK.json').open('xb') as stream:
    assert stream.write(raw) == len(raw)
print(json.dumps({'report': pin(raw), 'files': 50, 'logical_bytes': total}, sort_keys=True))
