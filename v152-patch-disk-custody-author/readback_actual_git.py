"""Verify only the small authored capsule from complete saved Git GET payloads."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import zlib

ROOT = Path('/workspace/hia-patch-disk-custody-author-capsule-r1-dda7')
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')

def seven(value):
    result = value if isinstance(value, os.stat_result) else Path(value).lstat()
    return {key: getattr(result, key) for key in FIELDS}

def pin(raw, mode='100644'):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), 'mode': mode}

def read(path):
    before = seven(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        held = os.fstat(fd)
        assert stat.S_ISREG(held.st_mode) and held.st_nlink == 1 and held.st_size <= 16 << 20
        assert seven(held) == before
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(held.st_size + 1)
        assert len(raw) == held.st_size
        assert seven(os.fstat(fd)) == before == seven(path)
    finally:
        os.close(fd)
    return raw, before

def current(desc):
    raw, observed = read(desc['path'])
    assert observed == desc['stat']
    mode = '100755' if observed['st_mode'] & 0o111 else '100644'
    assert pin(raw, mode) == desc['pin']
    return raw

publication = json.loads(read(ROOT / 'PUBLICATION-INPUTS.json')[0])
actual = {}
for index, desc in enumerate(publication['leaves']):
    fetched = read(ROOT / 'GIT' / f'{index:03d}-GET.txt')[0]
    assert pin(fetched, desc['pin']['mode']) == desc['pin']
    assert current(desc) == fetched
    assert json.loads(read(ROOT / 'GIT' / f'{index:03d}-ACK.json')[0])['sha'] == desc['pin']['git_blob']
    verified = json.loads(read(ROOT / 'GIT' / f'{index:03d}-VERIFIED.json')[0])
    assert verified['full_get_exact'] is True and verified['sha'] == desc['pin']['git_blob']
    actual[desc['logical']] = fetched

transport = json.loads(actual['AUTHOR-CAPSULE.json'])
compressed = base64.b64decode(transport['data'], validate=True)
assert pin(compressed) == transport['compressed_pin']
decoder = zlib.decompressobj()
raw = decoder.decompress(compressed) + decoder.flush()
assert decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data
assert pin(raw) == transport['payload_pin']
payload = json.loads(raw)
members = json.loads(actual['MEMBERS.json'])
assert payload['roots'] == members['roots']
assert set(payload['files']) == set(members['files'])
assert len(payload['files']) == members['files_count'] == 21
total = 0
for name, value in payload['files'].items():
    assert value['descriptor'] == members['files'][name]
    restored = value['text'].encode('utf-8')
    assert current(value['descriptor']) == restored
    total += len(restored)
assert total == members['logical_bytes'] == 209877
for row in payload['roots'].values():
    root = Path(row['path'])
    assert seven(root) == row['stat']
    assert sorted(item.name for item in root.iterdir()) == row['files']
for value in payload['files'].values():
    assert seven(value['descriptor']['path']) == value['descriptor']['stat']

report = {
    'status': 'PASS_COMPLETE_ACTUAL_GIT_AUTHOR_CAPSULE_READBACK',
    'source': 'Four exact saved full Git GET payloads; no computed-hash payload substitution.',
    'transport_pin': pin(actual['AUTHOR-CAPSULE.json']),
    'manifest_pin': pin(actual['MEMBERS.json']),
    'payload_pin': pin(raw), 'compressed_pin': pin(compressed),
    'files': len(payload['files']), 'logical_bytes': total,
    'strict_zlib_eof': True, 'all_current_full_bytes_modes_sevenstats_pathsets': True,
    'new_sealer_or_control_or_product_executions': 0,
    'legacy_bulk_plan_or_raw_read': False,
    'scope': 'Authoring only; no actual bounded seal qualification or archive custody claim.',
}
encoded = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
with (ROOT / 'ACTUAL-GIT-READBACK.json').open('xb') as stream:
    stream.write(encoded)
print(json.dumps({'report': pin(encoded), 'files': len(payload['files']), 'logical_bytes': total}, sort_keys=True))
