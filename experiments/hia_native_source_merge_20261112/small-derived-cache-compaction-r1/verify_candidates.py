"""Verify four already-recoverable derived files. Never delete or download."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path('/workspace/scratch/e26ed3e2edcf/root')
OUT = Path(__file__).resolve().parent


def identity(s):
    return {k: getattr(s, 'st_' + k) for k in ('dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}


def read(path):
    s = path.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink == 1
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        assert identity(os.fstat(fd)) == identity(s)
        parts = []
        total = 0
        while total < s.st_size:
            raw = os.read(fd, min(1 << 20, s.st_size - total))
            assert raw
            parts.append(raw); total += len(raw)
        assert not os.read(fd, 1)
        assert identity(os.fstat(fd)) == identity(s) == identity(path.lstat())
        return b''.join(parts), identity(s)
    finally:
        os.close(fd)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def pin(path, raw=None):
    if raw is None:
        raw, before = read(path)
    else:
        before = identity(path.lstat())
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw), 'git_blob': blob(raw), 'identity': before}


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    assert read(path)[0] == raw
    return pin(path, raw)


def compare_stream(candidate, chunks, expected_bytes, expected_sha):
    before = candidate.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == expected_bytes
    fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    count = 0; digest = hashlib.sha256()
    try:
        assert identity(os.fstat(fd)) == identity(before)
        for raw in chunks:
            assert os.pread(fd, len(raw), count) == raw
            count += len(raw); digest.update(raw)
        assert count == expected_bytes and digest.hexdigest() == expected_sha
        assert identity(os.fstat(fd)) == identity(before) == identity(candidate.lstat())
    finally:
        os.close(fd)
    return {'path': str(candidate), 'bytes': count, 'sha256': digest.hexdigest(),
            'identity': identity(before), 'every_reconstructed_byte_compared': True,
            'new_large_output_written': False, 'unlink_performed': False}


def main():
    D = ROOT / 'core-unpack-v83-native-r1/canonical-package-r1'
    manifest_raw, _ = read(D / 'MANIFEST.json'); manifest = json.loads(manifest_raw)
    bundle_raw, _ = read(D / 'BUNDLE.json'); bundle = json.loads(bundle_raw)
    assert list(bundle) == ['files', 'manifest'] and len(bundle['files']) == 39
    assert bundle['manifest'] == manifest and len(manifest['parts']) == 35
    latest_tree_path = ROOT / 'v89-derived-part-compaction-r1/publication/TREE.provider.json'
    latest_tree_raw, _ = read(latest_tree_path); latest = json.loads(latest_tree_raw)
    assert latest['sha'] == '5278577aff3a2f94ebe123f4ecb08f078105d96a' and latest['truncated'] is False
    latest_rows = {r['path']: r for r in latest['tree'] if r['type'] == 'blob'}
    assert len(latest_rows) == 5827
    prefix = 'experiments/hia_native_source_merge_20261112/core-unpack-v83-r1/native-originals-r1/'
    retained_files = []
    reconstructed_files = []
    decoded_parts = []
    for ordinal, part in enumerate(manifest['parts']):
        assert part['path'] == f'archive/part-{ordinal:04}.b64'
        path = D / Path(part['path']).name
        encoded, _ = read(path)
        assert len(encoded) == part['bytes'] and sha(encoded) == part['sha256']
        decoded = base64.b64decode(encoded[:-1], validate=True)
        assert base64.b64encode(decoded) + b'\n' == encoded and len(decoded) == part['decoded_bytes']
        decoded_parts.append(decoded)
    for item in bundle['files']:
        assert list(item) == ['path', 'text'] and item['path'].startswith(prefix)
        relative = item['path'][len(prefix):]
        if relative.startswith('archive/'):
            local = D / Path(relative).name
        elif relative == 'MANIFEST.json':
            local = D / relative
        else:
            assert relative in ('AUDIT.json', 'DOWNLOAD.json', 'PROVIDER.original.json')
            local = D.parent / relative
        data, _ = read(local)
        assert data == item['text'].encode()
        tree_row = latest_rows[item['path']]
        assert tree_row['sha'] == blob(data) and tree_row['size'] == len(data)
        retained_files.append({'canonical_path': item['path'], **pin(local, data)})
        reconstructed_files.append({'path': item['path'], 'text': data.decode()})
    # Preserve original JSON key order explicitly. MANIFEST.json has equivalent
    # data but its pretty serialization is not assumed to have the same order.
    ordered_manifest_json = json.dumps(bundle['manifest'], ensure_ascii=False, separators=(',', ':'))
    rebuilt = {'files': reconstructed_files, 'manifest': json.loads(ordered_manifest_json)}
    encoded_stream = (s.encode() for s in json.JSONEncoder(ensure_ascii=False, separators=(',', ':')).iterencode(rebuilt))
    def bundle_chunks():
        yield from encoded_stream
        yield b'\n'
    bundle_check = compare_stream(D / 'BUNDLE.json', bundle_chunks(), 18079544,
                                  'e5b736e02bcc6a55b64cf72c818acc5fa3289e7f7e44e111b2ff2af894107965')
    archive_check = compare_stream(D / 'all-originals.tar.xz', iter(decoded_parts),
                                   manifest['archive_bytes'], manifest['archive_sha256'])
    assert archive_check['bytes'] == 13511720
    bundle_recipe = {'schema': 'hia.cold.v83-derived-bundle-lossless-recipe.v1',
        'source_canonical': 'd9cbad14d4c5e769b5a105a3f5b0a10ceeef1919',
        'source_tree': latest['sha'], 'canonical_prefix': prefix,
        'retained_files_in_exact_bundle_order': retained_files,
        'ordered_manifest_json': ordered_manifest_json,
        'manifest_value_must_equal_retained_MANIFEST': True,
        'serialization': {'ensure_ascii': False, 'sort_keys': False, 'separators': [',', ':'], 'trailing_newline': True},
        'bundle': bundle_check, 'xz': archive_check,
        'restore_bundle': "Read the 39 retained files in the recorded order, construct {'files': [{'path': canonical_path, 'text': exact_utf8_text}, ...], 'manifest': json.loads(ordered_manifest_json)}, encode using the stated JSON options and one newline, then require the exact recorded byte count/SHA. Never claim original inode/ctime for a new copy.",
        'restore_xz': 'Decode and concatenate original 35 base64 parts in MANIFEST order and verify complete original XZ SHA; do not recompress.',
        'all_39_retained_files_remain': True, 'new_network_GET': False}
    recipe_pin = save(OUT / 'V83-RESTORE-RECIPE.json', bundle_recipe)

    C = ROOT / 'checkpoint-v92-r2'
    cp_manifest_raw, _ = read(C / 'ARCHIVE.json'); cm = json.loads(cp_manifest_raw)
    cp_pub = ROOT / 'checkpoint-v92-r2-publication'
    cp_proof_raw, _ = read(cp_pub / 'FINAL-READBACK.json'); cp_proof = json.loads(cp_proof_raw)
    cp_plan_raw, _ = read(cp_pub / 'PLAN.json'); cp_plan = json.loads(cp_plan_raw)
    assert cp_proof['root_checkpoint'] == '8f6c9a4971f910f5f73b685be4f266397630da9b' and cp_proof['new20_blobs_full_remote_equal'] is True
    assert cp_plan['expected_tree'] == cp_proof['root_tree']
    published = {r['local']: (i, r) for i, r in enumerate(cp_plan['new_files'])}
    cp_parts = []; cp_decoded = []
    for ordinal, part in enumerate(cm['parts']):
        path = C / part['path']; encoded, _ = read(path)
        assert part['offset'] == sum(len(x) for x in cp_decoded)
        assert len(encoded) == part['bytes'] and sha(encoded) == part['sha256'] and blob(encoded) == part['git_blob']
        data = base64.b64decode(encoded[:-1], validate=True)
        assert base64.b64encode(data) + b'\n' == encoded and len(data) == part['raw_bytes']
        i, expected = published[str(path)]
        assert expected['sha256'] == sha(encoded) and expected['git_blob'] == blob(encoded)
        receipt_path = cp_pub / f'blob-{i}-GET.json'
        receipt_raw, _ = read(receipt_path); receipt = json.loads(receipt_raw)
        assert receipt['whole_body_equals_local'] is True
        assert receipt['expected_blob'] == blob(encoded) and receipt['bytes'] == len(encoded) and receipt['sha256'] == sha(encoded)
        assert receipt['ack']['isError'] is False and receipt['ack']['structuredContent']['sha'] == blob(encoded)
        cp_parts.append({'ordinal': ordinal, **pin(path, encoded), 'remote_readback_receipt': pin(receipt_path, receipt_raw), 'receipt': receipt})
        cp_decoded.append(data)
    assert len(cp_decoded) == 16
    checkpoint_check = compare_stream(C / 'root-originals.tar.gz', iter(cp_decoded), cm['archive']['bytes'], cm['archive']['sha256'])
    assert checkpoint_check['bytes'] == 5186391

    I = Path('/tmp/hia-core-integer-current-v89-native-actual-r2-publication-20261112-e26e')
    im_raw, _ = read(I / 'ARCHIVE.json'); im = json.loads(im_raw)
    prior_restore_raw, _ = read(I / 'RESTORE-READBACK.json'); prior_restore = json.loads(prior_restore_raw)
    journal_path = Path('/tmp/hia-integer-native-current-r2-actual-git-mutations.jsonl')
    journal_raw, _ = read(journal_path); journal = [json.loads(line) for line in journal_raw.splitlines()]
    last = [r for r in journal if r['kind'] == 'commit_readback'][-1]['handoff']
    assert last['commit'] == '4c473fa7a1c2adf52655bda2da3b57a4f3c0883e' and last['tree'] == '235b194321c4c663ad1211b3c5b95b9e1cb1bc8f'
    assert last['unique_full_readback'] == 82 and last['restoration_all_members_verified'] is True
    reads = {r['path']: r for r in journal if r['kind'] == 'blob_readback_equal'}
    assert prior_restore['full_byte_restore'] is True and prior_restore['all_member_size_mode_SHA_verified'] is True
    actual_restored = Path('/tmp/hia-core-integer-current-v89-native-actual-r2-restored-20261112-e26e.tar.gz')
    iparts = []; idecoded = []
    for ordinal, part in enumerate(im['parts']):
        path = I / part['path']; encoded, _ = read(path)
        assert part['offset'] == sum(len(x) for x in idecoded)
        assert len(encoded) == part['text_bytes'] and sha(encoded) == part['text_sha256'] and blob(encoded) == part['git_blob_sha1']
        data = base64.b64decode(encoded[:-1], validate=True)
        assert base64.b64encode(data) + b'\n' == encoded
        assert len(data) == part['raw_bytes'] and sha(data) == part['raw_sha256']
        assert reads[part['path']]['expected'] == blob(encoded) and reads[part['path']]['bytes'] == len(encoded)
        iparts.append({'ordinal': ordinal, **pin(path, encoded), 'prior_full_remote_readback_row': reads[part['path']]})
        idecoded.append(data)
    assert len(idecoded) == 42
    integer_check = compare_stream(actual_restored, iter(idecoded), im['archive']['bytes'], im['archive']['sha256'])
    assert integer_check['bytes'] == 21994804
    preserved_duplicate = compare_stream(I / 'complete-actual-originals.tar.gz', iter(idecoded), im['archive']['bytes'], im['archive']['sha256'])
    candidates = [bundle_check, archive_check, checkpoint_check, integer_check]
    patterns = [r['path'] for r in candidates]
    rg = ['rg', '-l', '-F']
    for pattern in patterns:
        rg += ['-e', pattern]
    for pattern in ('*REQUEST*.json', '*POLICY*.json', '*LAUNCH*.json', '*PINS*.json', '*INPUT*.json', '*CONFIG*.json'):
        rg += ['-g', pattern]
    rg += ['-g', '!**/full32-custody-repair-r3/controls-actual-r1/**',
           '/workspace/scratch/e26ed3e2edcf', '/tmp']
    search = subprocess.run(rg, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    search_record = {'argv': rg, 'returncode': search.returncode,
                     'matched_files': search.stdout.decode().splitlines(), 'stderr': search.stderr.decode(),
                     'scope': 'Readable uppercase-named request/policy/launch/pins/input/config JSON files under the two roots. Known mode000 permission-test subtree excluded; compressed/binary contents and arbitrary running-process handles not searched.'}
    # Unknown read errors remain explicit. This report proposes no deletion.
    report = {'schema': 'hia.cold.small-derived-cache-candidates-readback.v1',
        'status': 'LOSSLESS_RECONSTRUCTION_PROVED_ROOT_FINAL_REVIEW_REQUIRED',
        'unlink_performed': False, 'network_GET_performed': False, 'product_or_tests_executed': False,
        'workspace_candidates': [bundle_check, archive_check, checkpoint_check],
        'workspace_reclaim_bytes_after_approval': sum(r['bytes'] for r in candidates[:3]),
        'tmp_candidates': [integer_check], 'tmp_reclaim_bytes_after_approval': integer_check['bytes'],
        'v83': {'canonical': bundle_recipe['source_canonical'], 'tree': latest['sha'],
            'tree_original_pin': pin(latest_tree_path, latest_tree_raw),
            'all39_retained_files_local_full_SHA_and_Git_blob_join': True,
            'fresh_39_remote_body_GET_claimed': False,
            'historical_remote_body_journal_not_located': True,
            'local_remaining_parts_and_metadata_suffice_to_restore': True,
            'all35_parts_and_4_original_documents_remain': True,
            'recipe': recipe_pin, 'manifest': pin(D / 'MANIFEST.json', manifest_raw),
            'no171MB_decompression_claimed_this_review': True},
        'checkpoint': {'canonical': cp_proof['root_checkpoint'], 'tree': cp_proof['root_tree'],
            'manifest': pin(C / 'ARCHIVE.json', cp_manifest_raw),
            'prior_complete_remote_readback_proof': pin(cp_pub / 'FINAL-READBACK.json', cp_proof_raw),
            'prior_publication_plan': pin(cp_pub / 'PLAN.json', cp_plan_raw),
            'all16_remaining_parts': cp_parts, 'new31MB_original_member_reread_claimed': False},
        'integer': {'canonical': last['commit'], 'tree': last['tree'], 'prefix': last['prefix'],
            'manifest': pin(I / 'ARCHIVE.json', im_raw),
            'full_remote_readback_journal': pin(journal_path, journal_raw),
            'prior_complete_109_member_restore': pin(I / 'RESTORE-READBACK.json', prior_restore_raw),
            'all42_remaining_parts': iparts, 'complete_duplicate_archive_preserved': preserved_duplicate,
            'original_actual_root_preserved': im['actual_operation_root'],
            'new340MB_original_member_reread_claimed': False},
        'active_reference_search': search_record,
        'necessary_root_final_conditions': [
            'Persist this proof, verifier and exact V83 restoration recipe before removal; full readback required.',
            'Freshly confirm only the four listed candidate identities and no active consumer/reference requires those derived paths; mode000/search limitations do not imply whole-filesystem coverage.',
            'Retain every listed base64 part, manifest, original log/source/result, original actual directory and the integer other complete archive.',
            'Do not delete or rewrite any previous UNKNOWN publication or the historic unconfirmed part002. No product/qualification result is altered.'
        ]}
    pin_report = save(OUT / 'CANDIDATES-READBACK.json', report)
    print(json.dumps({'proof': pin_report, 'recipe': recipe_pin,
                      'workspace_bytes': report['workspace_reclaim_bytes_after_approval'],
                      'tmp_bytes': report['tmp_reclaim_bytes_after_approval'],
                      'reference_search_returncode': search.returncode,
                      'reference_matches': search_record['matched_files'],
                      'reference_search_errors': bool(search_record['stderr'])}))


if __name__ == '__main__':
    main()
