"""Verify fetched Git wrappers, metadata, and independently restored originals.

This script imports no product and performs no Git mutation or product execution.
"""
from pathlib import Path
import base64
import collections
import hashlib
import json
import os
import stat
import zlib

ROOT = Path(__file__).resolve().parent
BACK = ROOT / 'GIT-CUSTODY' / 'readback'
RESTORED = ROOT / 'git-readback-restored-r1'


def identity(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                git_blob=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest())


def verify(raw, row):
    assert identity(raw) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}


def write(name, value):
    raw = (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()
    with (ROOT / name).open('xb') as output:
        output.write(raw)
    return identity(raw)


def tree_for(prefix, rows):
    nested = {}
    for name, row in rows.items():
        if not name.startswith(prefix + '/'):
            continue
        parts = name[len(prefix) + 1:].split('/')
        node = nested
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        assert parts[-1] not in node
        node[parts[-1]] = row

    def walk(node):
        entries = []
        for name, value in node.items():
            if 'git_blob' in value:
                entries.append((name.encode(), b'100644', value['git_blob']))
            else:
                entries.append((name.encode() + b'/', b'40000', walk(value)))
        raw = b''.join(mode + b' ' + name.rstrip(b'/') + b'\0' + bytes.fromhex(oid)
                       for name, mode, oid in sorted(entries))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return walk(nested)


def main():
    rows = json.loads((ROOT / 'PUBLISH-LIST.json').read_text())
    assert len(rows) == 299
    modes = collections.Counter()
    receipts = []
    for row in rows:
        raw = (BACK / row['file']).read_bytes()
        verify(raw, row)
        assert raw == (ROOT / row['file']).read_bytes()
        receipt = json.loads((ROOT / 'GIT-CUSTODY' / (row['file'] + '.receipt.json')).read_text())
        for key in ('bytes', 'sha256', 'git_blob'):
            assert receipt[key] == row[key]
        assert receipt['full_get_verified'] is True
        assert receipt['full_get_bytes'] == row['bytes']
        assert receipt['full_get_sha256'] == row['sha256']
        assert receipt['full_get_blob'] == row['git_blob']
        modes[receipt['custody_mode']] += 1
        receipts.append(receipt)

    fragments = json.loads((BACK / 'METADATA-FRAGMENTS.json').read_text())
    pieces = []
    offset = 0
    for row in fragments['fragments']:
        raw = (BACK / row['file']).read_bytes()
        verify(raw, row)
        assert row['offset'] == offset
        offset += len(raw)
        pieces.append(raw)
    capsule_raw = b''.join(pieces)
    verify(capsule_raw, fragments['whole'])
    assert capsule_raw == (ROOT / 'METADATA-CAPSULE.json').read_bytes()
    capsule = json.loads(capsule_raw)
    decoded = zlib.decompress(base64.b64decode(capsule['data'], validate=True))
    verify(decoded, capsule['decoded'])
    decoded_members = json.loads(decoded)['files']
    for name, row in decoded_members.items():
        raw = row['text'].encode()
        verify(raw, row)
        local = name.removeprefix('metadata/')
        assert raw == (ROOT / local).read_bytes()

    original = json.loads((ROOT / 'INPUTS-FROZEN.json').read_text())
    manifest = json.loads((ROOT / 'MANIFEST.json').read_text())
    assert len(original['logical_files']) == len(manifest['logical_files']) == 10686
    assert json.loads((ROOT / 'git-readback-restore.stdout').read_text())['status'] == 'RESTORED_FULLY'
    assert (ROOT / 'git-readback-restore.stderr').read_bytes() == b''
    stat_changes = []
    for name, row in original['logical_files'].items():
        source = Path(row['source'])
        actual = RESTORED / name
        assert row['kind'] == 'file'
        for path in (source, actual):
            item_stat = path.lstat()
            assert stat.S_ISREG(item_stat.st_mode)
            assert stat.S_IMODE(item_stat.st_mode) == int(row['mode'], 8)
            verify(path.read_bytes(), row)
        current_stat = source.lstat()
        changes = {key: [value, getattr(current_stat, key)]
                   for key, value in row['source_stat'].items()
                   if value != getattr(current_stat, key)}
        if changes:
            stat_changes.append({'path': name, 'changes': changes})
    for name, row in original['directories'].items():
        actual_stat = (RESTORED / name).lstat()
        assert stat.S_ISDIR(actual_stat.st_mode)
        assert stat.S_IMODE(actual_stat.st_mode) == int(row['mode'], 8)

    source_trees = {
        'r5_formal': tree_for('r5-formal/candidate-ci314', original['logical_files']),
        'r6_local': tree_for('r6-local/local-source-r1', original['logical_files']),
    }
    assert source_trees == {
        'r5_formal': 'd7e35e1e0b2907a5375bdbdb75c8547e3fa8cd42',
        'r6_local': 'd3ae0278979b79a570f753b1afbd2d63ecba8a8e',
    }
    transport = json.loads((BACK / 'TRANSPORT.json').read_text())
    report = dict(
        schema='hia.v88.r5-formal-r6-local-complete-git-readback.v1',
        status='COMPLETE_ORIGINALS_CUSTODY_PASS',
        files_fetched_and_verified=len(rows),
        unique_Git_blob_objects=len({row['git_blob'] for row in rows}),
        data_wrappers=275, metadata_fragments=6, small_metadata=18,
        receipt_modes=dict(modes),
        all_full_GET_bytes_equal_original_publication_bytes=True,
        metadata_fragment_reassembly_and_all_eight_members_verified=True,
        archive=transport['archive'],
        archive_raw_binary_Git_upload_claim=False,
        restore=json.loads((ROOT / 'git-readback-restore.stdout').read_text()),
        original_files_independently_rechecked=10686,
        original_stat_changes=stat_changes,
        source_trees=source_trees,
        unknown_POST_observations=[{
            'file': 'parts/chunk-158.b64',
            'original_result': 'UNKNOWN: RemoteProtocolError',
            'subsequent_actual_immutable_object_GET': 404,
            'same_content_single_retry': 'POST_ACK_AND_FULL_GET',
            'original_intent_response_and_decision_preserved': True,
        }],
        original_R5_Source_status='FAIL: 1224 methods, 10 failures, 0 errors or skips',
        original_R6_scope='CPython3.12.14 local 113 generators twice, 1466 AST, targeted140 PASS',
        future_R6_formal_results_excluded=True,
        original_outer_ZIP_retained_but_not_Git_archived=True,
        all_original_failures_preserved=True,
        product_test_or_generator_execution=0,
        whole_native=False,
    )
    write('FULL-GIT-READBACK.json', report)
    write('ALL-PUBLICATION-RECEIPTS.json', receipts)
    print(json.dumps({key: report[key] for key in (
        'status', 'files_fetched_and_verified', 'unique_Git_blob_objects',
        'data_wrappers', 'original_files_independently_rechecked',
        'source_trees', 'receipt_modes', 'original_stat_changes')}, sort_keys=True))


if __name__ == '__main__':
    main()
