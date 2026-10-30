#!/usr/bin/env python3
"""Read only the two completed packages after session interruption.

No corpus execution, original record mutation, source checkout or network use.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha1, sha256
import json
import lzma
from pathlib import Path
import re
import stat
import tarfile

ROOT = Path('/workspace/scratch/b484d4086829')
OUTPUT = Path(__file__).resolve().parent / 'frozen-packages-readback.json'
PACKAGES = [
    ('integration-convergence-e0-evidence',
     'af42f862078debb66f7dfdcbb8e390eec2793facdd8dfb87e176b9ec5a7da5c3',
     'integration-405-independent-review/integration-e0-independent-review.tar.gz',
     '2338edcc21bbb3f4b757f749b20ce5c4c5672b17e3375ebe0eb99dd3ede3844d'),
    ('guard-fix-evidence',
     '440cf608255a741c34c7d8581ada2f458fe20802882bd8bbad4a4b3b5f28a5f6',
     'guard-fix-independent-review/guard-fix-independent-review-40ae.tar.gz',
     'd6da0b8d6ab3063fbef51e1cb75d19f3b3201ec8cf1e4f317b614173992fd961'),
]
SIGNED_URL = re.compile(rb'https?://[^\s<>"\']*[?&](?:sig|signature|token|access_token|x-amz-signature)=', re.I)


def identity(path: Path):
    assert path.is_file() and not path.is_symlink(), str(path)
    size = path.stat().st_size
    h, git = sha256(), sha1(b'blob ' + str(size).encode() + b'\0')
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
            git.update(chunk)
    return {'bytes': size, 'sha256': h.hexdigest(), 'git_blob': git.hexdigest(),
            'mode': oct(stat.S_IMODE(path.stat().st_mode))}


def assert_identity(actual, expected, context):
    assert all(actual[k] == expected[k] for k in ('bytes', 'sha256', 'git_blob')), context


def main():
    assert not OUTPUT.exists(), 'Never overwrite a readback receipt'
    started = datetime.now(timezone.utc).isoformat()
    results = []
    for folder, archive_digest, peer_name, peer_digest in PACKAGES:
        directory = ROOT / folder
        map_path = directory / 'publication-files.json'
        publication = json.loads(map_path.read_text())
        archive_path = Path(publication['archive']['path'])
        assert publication['archive']['sha256'] == archive_digest
        assert_identity(identity(archive_path), publication['archive'], 'whole archive')
        manifest_path = directory / 'archive-manifest.json'
        manifest = json.loads(manifest_path.read_text())
        original = manifest['inputs']
        assert len(original) == manifest['input_count']
        assert sum(v['bytes'] for v in original.values()) == manifest['input_bytes']
        assert all('private-transport' not in name and '__pycache__' not in name for name in original)
        assert all(not name.endswith('/official-full-release-147d39.zip') for name in original)
        assert original[peer_name]['sha256'] == peer_digest
        assert sum(name == peer_name for name in original) == 1

        # Check persistence of every original input without changing it.
        for name, expected in original.items():
            actual = identity(ROOT / name)
            assert actual == expected, 'persisted original: ' + name
        expected_members = dict(original)
        expected_members[str(manifest_path.relative_to(ROOT))] = identity(manifest_path)
        seen = set()
        signed_url_findings = []
        with tarfile.open(archive_path, 'r:xz') as archive:
            for member in archive:
                assert member.isfile() and member.name not in seen
                assert member.name in expected_members, member.name
                expected = expected_members[member.name]
                assert member.size == expected['bytes'] and member.mode == int(expected['mode'], 8)
                h, git = sha256(), sha1(b'blob ' + str(member.size).encode() + b'\0')
                carry = b''
                with archive.extractfile(member) as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        h.update(chunk)
                        git.update(chunk)
                        if SIGNED_URL.search(carry + chunk):
                            signed_url_findings.append(member.name)
                        carry = (carry + chunk)[-8192:]
                assert h.hexdigest() == expected['sha256'] and git.hexdigest() == expected['git_blob']
                seen.add(member.name)
        assert seen == set(expected_members)
        assert not signed_url_findings, 'signed transport URL in archived member; do not publish'

        expanded = 0
        with lzma.open(archive_path, 'rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                expanded += len(chunk)
        original_readback = json.loads((directory / 'archive-readback.json').read_text())
        assert original_readback['member_count'] == len(seen)
        assert original_readback['uncompressed_tar_bytes'] == expanded
        offset = 0
        with archive_path.open('rb') as stream:
            for part in publication['archive_parts']:
                assert part['offset'] == offset
                raw = stream.read(part['bytes'])
                assert len(raw) == part['bytes']
                assert sha256(raw).hexdigest() == part['sha256']
                assert sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == part['git_blob']
                offset += len(raw)
            assert stream.read(1) == b''
        assert offset == publication['archive']['bytes']
        for entry in publication['payload_files']:
            assert_identity(identity(Path(entry['local_path'])), entry, entry['local_path'])
        results.append({'directory': folder, 'source_head': publication['source_head'],
            'source_tree': publication['source_tree'], 'publication_map': identity(map_path),
            'archive': identity(archive_path), 'member_count': len(seen),
            'all_original_inputs_retained_and_unchanged': True, 'original_input_count': len(original),
            'all_archive_paths_modes_sizes_and_both_hashes_match': True,
            'full_xz_stream_eof_and_integrity_check_consumed': True,
            'uncompressed_tar_bytes': expanded, 'parts_verified': len(publication['archive_parts']),
            'payload_files_verified': len(publication['payload_files']),
            'private_transport_paths_present': False,
            'signed_transport_urls_detected_in_direct_member_bytes': False,
            'nested_peer_archive_exact_digest_verified': peer_digest,
            'nested_peer_archive_copies': 1, 'complete_147_zip_duplicated': False,
            'qualification_claims_relabelled': False})
        print(json.dumps({'package': folder, 'members': len(seen), 'status': 'passed'}), flush=True)
    result = {'schema': 'hepta.interruption-recovery-frozen-package-readback.v1',
        'started_utc': started, 'finished_utc': datetime.now(timezone.utc).isoformat(),
        'producer_sha256': identity(Path(__file__).resolve())['sha256'], 'packages': results,
        'new_test_or_native_executions': 0, 'original_files_modified': 0,
        'new_archives_or_part_files_written': 0, 'remote_writes_or_readbacks': 0,
        'scope': 'Byte persistence and frozen-package integrity only. Existing original qualification and independent audit scopes are unchanged.'}
    OUTPUT.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
