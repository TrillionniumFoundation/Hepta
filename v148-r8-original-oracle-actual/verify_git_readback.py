#!/usr/bin/env python3
"""Read already-returned immutable Git objects; no project or payload execution."""
import base64
import hashlib
import json
from pathlib import Path
import stat
import zlib

ROOT = Path('/tmp/hia-r8-original-oracle-custody-r2-dda7')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def fetched(name):
    stem = ''.join(c if c.isalnum() or c in '_-' else '_' for c in name)
    obj = json.loads((ROOT / 'git-receipts' / (stem + '.GET.json')).read_bytes())
    assert not obj.get('isError')
    return obj['structuredContent']['content'].encode('utf-8')


def main():
    index_raw = fetched('INDEX.json')
    assert index_raw == (ROOT / 'INDEX.json').read_bytes()
    index = json.loads(index_raw)
    chunks = []
    offset = 0
    for ordinal, part in enumerate(index['parts']):
        raw = fetched(part['path'])
        assert pin(raw) == part['identity']
        obj = json.loads(raw)
        assert obj['index'] == ordinal and obj['offset'] == offset == part['offset']
        chunk = base64.b64decode(obj['base64'], validate=True)
        assert pin(chunk) == obj['decoded_part'] == part['decoded_part']
        assert obj['complete_archive'] == index['compressed_zlib']
        chunks.append(chunk)
        offset += len(chunk)
    packed = b''.join(chunks)
    assert pin(packed) == index['compressed_zlib']
    decoder = zlib.decompressobj()
    raw = decoder.decompress(packed, index['capsule_json']['bytes'] + 1)
    assert decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data
    assert pin(raw) == index['capsule_json']
    capsule = json.loads(raw)
    assert len(capsule['files']) == index['logical_files'] == 33
    assert capsule['directories'] == index['directories']
    expected = {r['logical_path']: r for r in index['files']}
    seen = set()
    total = 0
    for row in capsule['files']:
        name = row['logical_path']
        assert name not in seen and name in expected
        assert name and not name.startswith('/') and '..' not in Path(name).parts
        seen.add(name)
        desc = {k: v for k, v in row.items() if k != 'content_base64'}
        assert desc == expected[name]
        content = base64.b64decode(row['content_base64'], validate=True)
        assert pin(content) == row['identity']
        p = Path(row['path'])
        before = p.lstat()
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        actual = p.read_bytes()
        after = p.lstat()
        fields = ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        assert [getattr(before, k) for k in fields] == row['seven_stats'] == [getattr(after, k) for k in fields]
        assert stat.S_IMODE(after.st_mode) == row['mode'] and actual == content
        total += len(content)
    assert seen == set(expected) and total == index['logical_bytes']
    report = {'schema': 'hepta.r8.original-oracle.Git-decoded-readback.v1',
              'status': 'PASS_COMPLETE_ORIGINAL_METADATA_BYTES_MODES_AND_STATS',
              'fetched_parts': len(index['parts']), 'decoded_files': len(seen),
              'decoded_logical_bytes': total, 'compressed_bytes': len(packed),
              'original_stage_files': 29, 'custody_author_history_files': 3, 'reference_catalogs': 1,
              'input_payload_bytes_decoded_or_claimed_in_capsule': 0,
              'products': 0, 'original_oracle_owner_in_retained_stage': 1, 'CI': 0, 'refs': 0}
    out = ROOT / 'GIT-DECODED-READBACK.json'
    with out.open('x') as stream:
        stream.write(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'report': report, 'identity': pin(out.read_bytes())}, sort_keys=True))


if __name__ == '__main__':
    main()
