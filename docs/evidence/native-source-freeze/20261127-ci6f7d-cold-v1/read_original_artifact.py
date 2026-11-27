"""Read and preserve the exact original GitHub Actions cold failure artifact."""
from pathlib import Path
from hashlib import sha256
import argparse
import gzip
import io
import json
import struct
import tarfile
import zipfile

ARTIFACT_ID = 15204175387
ARCHIVE_BYTES = 204180596
ARCHIVE_SHA256 = 'e542fe544d5756e536f654c8b2f288fea6bd84f65b4cc35e3645b11c1c72fb13'
HEAD = '6f7dfb2defd8852d2fe58e02ff8c5cf78c5e7807'
PREFIX = 'verified-native-cold.native-cold/'


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    digest = sha256()
    size = 0
    with args.artifact.open('rb') as stream:
        for raw in iter(lambda: stream.read(1 << 20), b''):
            size += len(raw)
            digest.update(raw)
    assert size == ARCHIVE_BYTES and digest.hexdigest() == ARCHIVE_SHA256
    output = args.output
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    members = []
    captured = {}
    with zipfile.ZipFile(args.artifact) as archive:
        for item in archive.infolist():
            assert not item.is_dir() and item.filename.startswith(PREFIX)
            relative = item.filename[len(PREFIX):]
            assert all(part not in ('', '.', '..') for part in relative.split('/'))
            raw = archive.read(item)
            assert len(raw) == item.file_size
            members.append({'path': item.filename, **pin(raw), 'zip_crc32': item.CRC})
            if ('qualification/' not in relative and relative.endswith((
                    '.json', '.receipt', '.resources.jsonl', '.exec.trace', '.stderr', '.stdout'))):
                captured[relative] = raw
    by_path = {row['path']: row for row in members}
    assert len(by_path) == len(members) == 1425
    def report(name):
        return json.loads(captured[name])
    build, export, chain = (report(name) for name in (
        'build/qualification.json', 'export/qualification.json', 'chain/qualification.json'))
    campaign = report('campaign.json')
    for row in (build, export, chain, campaign):
        assert row['source_head'] == HEAD
    assert build['passed'] and export['passed']
    assert not chain['passed'] and not chain['whole_cold_qualified'] and not campaign['passed']
    assert len(chain['commands']) == 1 and chain['commands'][0]['returncode'] == 1
    assert chain['commands'][0]['observed_entry_process_terminal'] is True
    assert chain['qualification_wall_limit_seconds'] == 180
    assert chain['cleanup_wall_limit_seconds'] == 3
    receipt = captured['chain/cold/process-owner.receipt']
    words = struct.unpack_from('<32Q', receipt)
    assert receipt[:8] == b'HIACOR01'
    assert words[6:8] == (180, 3000000000) and words[9:11] == ((1 << 64) - 9, 1)
    assert words[12:16] == (1, 1, 0, 0)
    assert words[17] == words[21] == words[24] == 0 and words[22] == 1
    assert len(receipt) == 256 + words[16]*40 + words[18]*48
    assert words[19] <= words[23] <= words[20]
    archives = [row for row in members if row['path'].endswith('.hiaqar') and row['bytes']]
    assert len(archives) == 25
    summary = {
        'schema': 'hepta.hia.github-native-cold-failure-readback.v1',
        'source_head': HEAD, 'run_id': 46008392381, 'job_id': 140537280980,
        'artifact_id': ARTIFACT_ID, 'artifact': {'bytes': size, 'sha256': digest.hexdigest()},
        'passed': False, 'pre7_passed': True, 'source_export_passed': True,
        'full_cold_passed': False, 'whole_native_delivery_qualified': False,
        'post_release_install_rebuild_started': False,
        'original_reports_modified': False,
        'pre7': {k: build[k] for k in ('native_nested_ns', 'native_cleanup_ns',
            'wall_elapsed_ns', 'installed_count', 'total_nodes')},
        'source_export': {k: export[k] for k in ('current_source_count', 'source_bytes',
            'all_exported_files_exact', 'native_only_copy', 'no_compiled_images', 'no_legacy_language_files')},
        'native_budget_seconds': words[6], 'native_cleanup_budget_ns': words[7],
        'native_nested_ns': words[19] - words[4],
        'native_cleanup_ns': words[23] - words[19],
        'outer_elapsed_ns': chain['commands'][0]['elapsed_ns'],
        'leader_exit': words[9] - (1 << 64), 'leader_exit_raw_u64': words[9], 'timeout': bool(words[10]),
        'bounded_cleanup_and_no_remaining_identities': True,
        'owner_receipt': pin(receipt), 'owner_header_words': list(words),
        'actual_bootstrap': build['bootstrap'],
        'nonempty_archives_not_a_seal_admission_claim': archives,
        'complete_artifact_member_count': len(members),
        'complete_artifact_uncompressed_bytes': sum(row['bytes'] for row in members),
        'original_cold_command': chain['commands'][0],
    }
    manifest = {'schema': 'hepta.hia.github-artifact-member-pins.v1',
                'artifact_id': ARTIFACT_ID, 'artifact': summary['artifact'], 'members': members}
    (output/'artifact-members.json').write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
    (output/'readback.json').write_text(json.dumps(summary, indent=2, sort_keys=True)+'\n')
    captured['MANIFEST.json'] = (json.dumps({name: pin(raw) for name, raw in sorted(captured.items())},
                                          indent=2, sort_keys=True)+'\n').encode()
    raw_tar = io.BytesIO()
    with tarfile.open(fileobj=raw_tar, mode='w', format=tarfile.USTAR_FORMAT) as stream:
        for name, raw in sorted(captured.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(raw), 0o400, 0
            stream.addfile(entry, io.BytesIO(raw))
    packed = gzip.compress(raw_tar.getvalue(), mtime=0)
    (output/'original-ci-evidence.tar.gz').write_bytes(packed)
    print(json.dumps({'passed': False, 'full_cold_passed': False,
        'readback_complete': True, 'source_head': HEAD,
        'native_nested_ns': summary['native_nested_ns'],
        'native_cleanup_ns': summary['native_cleanup_ns'],
        'retained_original_members': len(captured), 'evidence_archive': pin(packed),
        'full_artifact': summary['artifact']}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
