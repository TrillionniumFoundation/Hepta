"""Seal and fully read back the already-closed SOURCE129 original files."""
from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import time

import read_actual as reader

HERE = Path(__file__).resolve().parent
V92 = Path('/tmp/hia-core-integer-native-integration-v92-r1-20261112-e26e')
ROOT = Path('/workspace/scratch/e26ed3e2edcf/root')
PREFIX = 'experiments/hia_core_integer_20261112/integer-wire-v92-source129-actual-r1/'


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    with path.open('xb') as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())
    return data


def bytes_pin(data):
    return {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}


def main():
    started = time.monotonic()
    audit = reader.document(HERE / 'AUDIT-r1.json')
    assert audit['status'] == 'CUSTODY_AND_SOURCE129_QUALIFICATION_PASS'
    assert audit['source129_qualification_pass'] is True and audit['failed_checks'] == []
    root_actual_path = ROOT / 'integer-wire-source129-v92-r1-invocation/READBACK.json'
    root_actual = reader.document(root_actual_path)
    assert root_actual['request_commit'] == reader.PUBLISHED_REQUEST_COMMIT
    root_rows = root_actual['actual_originals']
    peer_rows = [{key: row[key] for key in reader.PIN_FIELDS} for row in audit['actual_files']]
    assert root_rows == peer_rows
    assert root_actual['expected'] == root_actual['loaded'] == root_actual['executed'] == 129
    assert root_actual['seconds'] == audit['worker']['seconds'] == 176.8102772669954
    assert root_actual['negative_returncodes'] == [row['returncode'] for row in audit['negative_processes']] == [1, 2, 1, 2]
    root_peer = {
        'schema': 'hepta.v92.source129.root-peer-original-join.v1',
        'status': 'PASS', 'root_audit': reader.pin(root_actual_path),
        'peer_audit': reader.pin(HERE / 'AUDIT-r1.json'),
        'all_264_original_full_pins_equal_in_order': True,
        'all_129_ids_verified_by_independent_reader': True,
        'original_72_commands_and_four_negative_processes': True,
        'worker_seconds': root_actual['seconds'], 'product_rerun': False,
        'native_cold_installed_whole_claim': False}
    save(HERE / 'ROOT-PEER-JOIN.json', root_peer)

    selected = {('actual/' + row['relative_path']): Path(row['path']) for row in audit['actual_files']}
    for name in ('REQUEST.json', 'SOURCE129-PREEXEC.json', 'SOURCE-CANDIDATE.json', 'ROOT-STOP-CHAIN-STATIC-REVIEW.json'):
        selected['request/' + name] = V92 / name
    selected['request/CANONICAL.json'] = V92 / 'source129-publication/CANONICAL.json'
    selected['request/MANIFEST.json'] = V92 / 'source129-publication/files/MANIFEST.json'
    for name in ('common.py', 'child.py', 'worker.py', 'launch.py'):
        selected['control/' + name] = V92 / 'control' / name
    selected['control/original-process-owner.py'] = Path(reader.document(reader.REQUEST)['process_owner']['path'])
    for subdir in ('v92-source129-canonical-review-r1', 'integer-wire-source129-v92-r1-invocation'):
        base = ROOT / subdir
        for file in sorted(base.rglob('*')):
            if file.is_file():
                selected['root/' + subdir + '/' + file.relative_to(base).as_posix()] = file
    for name in ('freeze_v92_candidate.py', 'freeze_v92_source129.py', 'review_v92_stop_chain.py',
                 'run_integer_wire_source129_v92_r1_once.py'):
        selected['root/' + name] = ROOT / name
    for name in ('read_actual.py', 'READ-INTENT-r1.json', 'AUDIT-r1.json', 'ROOT-PEER-JOIN.json', 'seal_archive.py'):
        selected['peer/' + name] = HERE / name

    files = []
    for name, path in sorted(selected.items()):
        data, observed = reader.read_file(path)
        if name.startswith('actual/'):
            expected = next(row for row in peer_rows if row['path'] == str(path))
            assert observed == expected
        files.append({'member': name, 'kind': 'file', **observed})
    manifest = {'schema': 'hepta.v92.source129.complete-original-archive.v1',
        'scope': 'Actual source129, exact frozen inputs and independent/root readback originals; no native or cold qualification.',
        'request_commit': reader.PUBLISHED_REQUEST_COMMIT,
        'candidate_commit': 'a06112e0b5de9ff70cf3546b29cc7bf5498d6697',
        'candidate_tree_before_derivation': 'bada9276d3ee60376bcf98748052fce55bd7f605',
        'actual_root': str(reader.ACTUAL), 'actual_file_count': len(peer_rows),
        'actual_file_bytes': sum(row['size'] for row in peer_rows),
        'actual_directories': audit['actual_directories'],
        'transport_headers': 'Deterministic zero mtime tar headers; all exact original identity nanoseconds/modes/owners preserved in this manifest.',
        'old_stop_chain_HOLD_originals': {'unchanged_canonical_commit': reader.PUBLISHED_REQUEST_COMMIT,
            'prefix': 'experiments/hia_core_integer_20261112/integer-wire-v92-source129-r1/history/pre-stop-chain-fix-r1/'},
        'file_count': len(files), 'raw_bytes': sum(row['size'] for row in files), 'files': files}
    manifest_raw = save(HERE / 'ORIGINAL-ARCHIVE-MANIFEST.json', manifest)
    archive = HERE / 'SOURCE129-COMPLETE-ORIGINALS.tar.gz'
    with archive.open('xb') as file:
        with gzip.GzipFile(filename='', fileobj=file, mode='wb', compresslevel=6, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as bundle:
                for row in files:
                    data, observed = reader.read_file(row['path'])
                    assert observed == {key: row[key] for key in reader.PIN_FIELDS}
                    info = tarfile.TarInfo(row['member'])
                    info.size = len(data)
                    info.mode = row['mode']
                    info.uid, info.gid = row['uid'], row['gid']
                    info.mtime = 0
                    bundle.addfile(info, io.BytesIO(data))
                info = tarfile.TarInfo('ORIGINAL-ARCHIVE-MANIFEST.json')
                info.size, info.mode, info.mtime = len(manifest_raw), 0o644, 0
                bundle.addfile(info, io.BytesIO(manifest_raw))
        file.flush()
        os.fsync(file.fileno())
    verified = []
    with tarfile.open(archive, 'r:gz') as bundle:
        members = bundle.getmembers()
        assert [member.name for member in members] == [row['member'] for row in files] + ['ORIGINAL-ARCHIVE-MANIFEST.json']
        for member, row in zip(members, files):
            assert member.isfile() and member.size == row['size'] and member.mode == row['mode']
            assert member.uid == row['uid'] and member.gid == row['gid']
            data = bundle.extractfile(member).read()
            assert bytes_pin(data) == {key: row[key] for key in ('size', 'sha256', 'git_blob_sha1')}
            assert data == reader.read_file(row['path'])[0]
            verified.append({'member': member.name, **bytes_pin(data)})
        assert bundle.extractfile(members[-1]).read() == manifest_raw
    archive_bytes = archive.read_bytes()
    transport = HERE / 'publication/files/transport'
    transport.mkdir(parents=True, exist_ok=False)
    parts = []
    for index, offset in enumerate(range(0, len(archive_bytes), 300000)):
        data = archive_bytes[offset:offset + 300000]
        encoded = base64.b64encode(data) + b'\n'
        name = 'part-' + str(index).zfill(3) + '.b64'
        with (transport / name).open('xb') as target:
            target.write(encoded)
        assert base64.b64decode(encoded, validate=False) == data
        parts.append({'path': 'transport/' + name, 'offset': offset,
                      'decoded': bytes_pin(data), 'stored': bytes_pin(encoded)})
    rebuilt = b''.join(base64.b64decode((HERE / 'publication/files' / row['path']).read_bytes(), validate=False) for row in parts)
    assert rebuilt == archive_bytes
    receipt = {'schema': 'hepta.v92.source129.complete-original-archive-readback.v1',
        'status': 'PASS', 'archive': {'path': str(archive), **bytes_pin(archive_bytes)},
        'original_file_count': len(files), 'archive_member_count': len(files) + 1,
        'raw_file_bytes': sum(row['size'] for row in files), 'manifest': bytes_pin(manifest_raw),
        'all_members_full_raw_equal_to_local_originals': True, 'duplicate_or_extra_members': [],
        'all_actual_264_originals_preserved': True, 'parts_complete_exact_reconstruction': True,
        'parts': parts, 'verified_members': verified, 'seconds': time.monotonic() - started,
        'product_or_native_rerun': False}
    save(HERE / 'ARCHIVE-READBACK.json', receipt)
    summary = {key: value for key, value in audit.items()
               if key not in {'checks', 'actual_files', 'actual_directories', 'commands', 'negative_processes'}}
    summary['archive'] = receipt['archive']
    summary['archive_members'] = receipt['archive_member_count']
    summary['request_canonical'] = reader.PUBLISHED_REQUEST_COMMIT
    summary['root_actual_readback'] = reader.pin(root_actual_path)
    summary['actual_original_full_pin_join_equal_to_root'] = True
    save(HERE / 'AUDIT-SUMMARY.json', summary)
    publication = HERE / 'publication/files'
    for name in ('read_actual.py', 'seal_archive.py', 'ORIGINAL-ARCHIVE-MANIFEST.json',
                 'ARCHIVE-READBACK.json', 'AUDIT-SUMMARY.json', 'ROOT-PEER-JOIN.json'):
        data = (HERE / name).read_bytes()
        with (publication / name).open('xb') as target:
            target.write(data)
    listing = []
    for path in sorted(publication.rglob('*')):
        if path.is_file():
            data = path.read_bytes()
            listing.append({'path': PREFIX + path.relative_to(publication).as_posix(),
                            'local': str(path), 'mode': '100644', 'type': 'blob', **bytes_pin(data)})
    save(HERE / 'publication/FILES.json', listing)
    print(json.dumps({'archive': receipt['archive'], 'raw_files': len(files), 'members': len(files) + 1,
                      'raw_bytes': manifest['raw_bytes'], 'parts': len(parts), 'publication_files': len(listing)}))


if __name__ == '__main__':
    main()
