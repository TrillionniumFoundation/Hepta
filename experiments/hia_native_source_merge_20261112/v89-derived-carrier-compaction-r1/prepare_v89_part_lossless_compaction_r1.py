"""Prepare an exact lossless representation of two redundant transport ZIPs.

Never deletes. Original source ZIP, every execution original and every existing
metadata record remain in place. Each complete transport can be rebuilt from
literal original prefix/suffix plus an exact range of the retained source ZIP.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import zipfile
import zlib

sys.dont_write_bytecode = True
sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/root')
from audit_cli_r2b_actual_publication import read, pin, js, save, identity, blob

ROOT = Path('/workspace/scratch/e26ed3e2edcf/root')
BASE = ROOT / 'v89-ci-original-full-43247845814-r2'
OUT = ROOT / 'v89-derived-part-compaction-r1'
SOURCE = BASE / 'artifact-13960883405.original.zip'
CHUNK = 1 << 20


def open_original(path):
    before = identity(path.lstat())
    assert stat.S_ISREG(before['mode']) and before['nlink'] == 1
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    assert identity(os.fstat(fd)) == before
    return fd, before


def stable(fd, path, before):
    assert identity(os.fstat(fd)) == before == identity(path.lstat())


def digest_fd(fd, count):
    digest = hashlib.sha256()
    for offset in range(0, count, CHUNK):
        data = os.pread(fd, min(CHUNK, count - offset), offset)
        assert len(data) == min(CHUNK, count - offset)
        digest.update(data)
    return digest.hexdigest()


def literals(name, raw):
    path = OUT / (name + '.base64')
    encoded = base64.b64encode(raw) + b'\n'
    with path.open('xb') as stream:
        stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
    assert base64.b64decode(read(path)[:-1], validate=True) == raw
    return {'path': path.name, 'encoded': pin(path), 'raw_bytes': len(raw),
            'raw_sha256': hashlib.sha256(raw).hexdigest()}


def main():
    assert not (OUT / 'RECIPE.json').exists()
    old = js(BASE / 'RECONSTRUCTION-AUDIT.json')
    source_meta = js(OUT / 'run-43247845814-artifacts.provider.json')['artifacts']
    carrier_meta = js(OUT / 'run-43274640670-artifacts.provider.json')['artifacts']
    assert len(source_meta) == 1 and source_meta[0]['id'] == 13960883405
    source_meta = source_meta[0]
    assert source_meta['size_in_bytes'] == old['original_bytes'] == 652195421
    assert source_meta['digest'] == 'sha256:' + old['original_sha256'] == 'sha256:477587001905c3f6e63c2c15fa94a6200777b6b477cf7d98a68d024d65e6a332'
    assert source_meta['workflow_run']['id'] == 43247845814
    assert {r['id'] for r in carrier_meta} == {13970725292, 13970275706}
    metadata = {r['id']: r for r in carrier_meta}
    source_fd, source_before = open_original(SOURCE)
    recipes = []
    try:
        assert source_before['size'] == 652195421
        assert digest_fd(source_fd, source_before['size']) == old['original_sha256']
        for ordinal, expected in enumerate(old['official_part_artifacts']):
            path = Path(expected['path'])
            assert path == BASE / f'part-{ordinal:02}.artifact.zip'
            part, meta = old['parts'][ordinal], metadata[expected['artifact_id']]
            assert meta['workflow_run']['id'] == old['receiver_run'] == 43274640670
            assert meta['size_in_bytes'] == expected['bytes'] and meta['digest'] == 'sha256:' + expected['sha256']
            fd, before = open_original(path)
            try:
                assert before['size'] == expected['bytes']
                with os.fdopen(os.dup(fd), 'rb') as file, zipfile.ZipFile(file) as archive:
                    infos = archive.infolist()
                    assert len(infos) == len({r.filename for r in infos}) == 14
                    assert all(not r.is_dir() and not r.flag_bits & 1 and r.compress_type == zipfile.ZIP_STORED for r in infos)
                    member = next(r for r in infos if r.filename == 'slice.bin')
                    assert member.file_size == member.compress_size == part['bytes']
                    raw_header = os.pread(fd, 30, member.header_offset)
                    header = struct.unpack('<IHHHHHIIIHH', raw_header)
                    assert header[0] == 0x04034b50 and header[2] == member.flag_bits and header[3] == 0
                    name = os.pread(fd, header[-2], member.header_offset + 30)
                    assert name == b'slice.bin'
                    start = member.header_offset + 30 + header[-2] + header[-1]
                    end = start + member.file_size
                    assert 0 < start < end < before['size']
                    prefix = os.pread(fd, start, 0)
                    suffix = os.pread(fd, before['size'] - end, end)
                    assert len(prefix) == start and len(suffix) == before['size'] - end
                    assert len(prefix) + len(suffix) < 1 << 20
                    complete = hashlib.sha256(prefix); payload = hashlib.sha256(); crc = 0
                    for offset in range(0, part['bytes'], CHUNK):
                        size = min(CHUNK, part['bytes'] - offset)
                        source = os.pread(source_fd, size, part['offset'] + offset)
                        actual = os.pread(fd, size, start + offset)
                        assert len(source) == len(actual) == size and source == actual
                        complete.update(source); payload.update(source); crc = zlib.crc32(source, crc)
                    complete.update(suffix)
                    assert payload.hexdigest() == part['sha256'] and (crc & 0xffffffff) == member.CRC
                    assert complete.hexdigest() == expected['sha256']
                    retained = []
                    for item in infos:
                        if item.filename == 'slice.bin':
                            continue
                        raw = archive.read(item)  # Complete CRC verification of every other member.
                        retained_path = BASE / f'part-{ordinal:02}-originals' / item.filename
                        assert raw == read(retained_path)
                        retained.append({'member': item.filename, 'bytes': len(raw),
                            'sha256': hashlib.sha256(raw).hexdigest(), 'CRC32': item.CRC,
                            'retained_original': pin(retained_path)})
                    assert len(retained) == 13
                stable(fd, path, before); stable(source_fd, SOURCE, source_before)
                recipes.append({'ordinal': ordinal, 'artifact_id': expected['artifact_id'],
                    'transport_path': str(path), 'transport_bytes': before['size'],
                    'transport_sha256': complete.hexdigest(), 'transport_identity': before,
                    'prefix': literals(f'part-{ordinal:02}-prefix', prefix),
                    'source_range': {**part, 'container_data_offset': start, 'CRC32': member.CRC},
                    'suffix': literals(f'part-{ordinal:02}-suffix', suffix),
                    'complete_original_members': 14, 'retained_non_payload_originals': retained,
                    'every_original_transport_byte_compared_to_reconstruction': True})
            finally:
                os.close(fd)
        stable(source_fd, SOURCE, source_before)
    finally:
        os.close(source_fd)
    assert [(r['source_range']['offset'], r['source_range']['bytes']) for r in recipes] == [(0, 327155712), (327155712, 325039709)]
    result = {'schema': 'hia.root.lossless-derived-v89-part-recipe.v1',
        'status': 'EXACT_WHOLE_TRANSPORT_RECONSTRUCTION_PROVED_NOT_DELETED',
        'source_original': {'path': str(SOURCE), 'bytes': source_before['size'],
            'sha256': old['original_sha256'], 'identity_at_compaction': source_before},
        'source_original_remains_in_place': True, 'parts': recipes,
        'total_redundant_carrier_bytes': sum(r['transport_bytes'] for r in recipes),
        'total_unique_literal_bytes': sum(r[k]['raw_bytes'] for r in recipes for k in ('prefix', 'suffix')),
        'fresh_official_metadata': [pin(OUT / n) for n in ('run-43247845814-artifacts.provider.json', 'run-43274640670-artifacts.provider.json')],
        'all_original_control_bodies_remain': True, 'all_actual_execution_originals_remain': True,
        'stored_payloads_are_byte_identical_ranges_of_retained_original': True,
        'restore_identity_note': 'Exact bytes and original file mode/mtime can be restored to a fresh destination. Inode, ctime and any prior identity are historical observations and must not be claimed for the restored copy.',
        'unlink_performed': False, 'Git_persistence_required_before_unlink': True,
        'current_frozen_input_exclusion_required_before_unlink': True,
        'original_qualification_results_changed': False, 'legacy_product_deleted': False}
    save(OUT / 'RECIPE.json', result)
    print(json.dumps({'status': result['status'], 'carriers': 2,
        'carrier_bytes': result['total_redundant_carrier_bytes'],
        'literal_bytes': result['total_unique_literal_bytes'], 'recipe': pin(OUT / 'RECIPE.json')}))


if __name__ == '__main__':
    main()
