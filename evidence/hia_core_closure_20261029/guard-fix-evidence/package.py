#!/usr/bin/env python3
"""Archive completed guard-fix observations with exact original identities."""
from hashlib import sha1, sha256
import json
import lzma
from pathlib import Path
import stat
import tarfile
import time

WORKSPACE = Path('/workspace/scratch/b484d4086829')
OUTPUT = Path(__file__).resolve().parent
ARCHIVE = OUTPUT / 'guard-fix-40ae-public-b121.tar.xz'
REPOSITORY_PREFIX = 'evidence/hia_core_closure_20261029/guard-fix-evidence'
ROOTS = ['guard-fix-validation-20261030', 'ndu-restoration-20261030']
FILES = [
    'guard-fix-evidence/README.md', 'guard-fix-evidence/package.py',
    'integration-convergence-e0-evidence/restore.py',
    'integration-convergence-e0-evidence/runtime-restoration-links.json',
    'guard-fix-independent-review/publication-files.json',
    'integration-405-147-20261030/public-generic-lld-selected-red.json',
    'integration-405-147-20261030/run-public-safety340.py',
    'integration-405-147-20261030/candidate-public-environment.json',
    'integration-405-147-20261030/candidate-public-safety-environment.json',
    'progress-publication-20261029/guardfix-40ae-source-publication.json',
    'integration-ci-e0b9012-failure/official-artifact-metadata.json',
    'integration-ci-e0b9012-failure/triage.json',
    'integration-ci-e0b9012-failure/hia-six-e0b9012-original-failure.zip',
    'integration-ci-e0b9012-failure/original-members/safety.json',
    'toolchains/retained-ndu-147/recursive/transport-identity.json',
    'toolchains/retained-ndu-147/finite/transport-identity.json',
    'toolchains/retained-ndu-147/stream/transport-identity.json',
]


def identity(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular immutable input required: ' + str(path))
    size = path.stat().st_size
    digest, blob = sha256(), sha1(b'blob ' + str(size).encode() + b'\0')
    with path.open('rb') as stream:
        while raw := stream.read(1024 * 1024):
            digest.update(raw)
            blob.update(raw)
    return {'bytes': size, 'sha256': digest.hexdigest(), 'git_blob': blob.hexdigest(),
            'mode': oct(stat.S_IMODE(path.stat().st_mode))}


def save(name, document):
    path = OUTPUT / name
    if path.exists():
        raise ValueError('never overwrite a packaging record: ' + str(path))
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + '\n')
    return path


def main():
    if ARCHIVE.exists():
        raise ValueError('never overwrite an evidence archive')
    clock = time.monotonic()
    peer_map = json.loads((WORKSPACE / 'guard-fix-independent-review/publication-files.json').read_text())
    peer_archive = next(row for row in peer_map['files']
                        if row['name'] == 'guard-fix-independent-review-40ae.tar.gz')
    assert peer_archive['sha256'] == 'd6da0b8d6ab3063fbef51e1cb75d19f3b3201ec8cf1e4f317b614173992fd961'
    peer_files = peer_map['files']
    for row in peer_files:
        actual = identity(Path(row['path']))
        assert all(actual[key] == row[key] for key in ('bytes', 'sha256', 'git_blob'))
    paths = {WORKSPACE / name for name in FILES}
    paths.update(Path(row['path']) for row in peer_files)
    for root in ROOTS:
        paths.update(path for path in (WORKSPACE / root).rglob('*')
                     if path.is_file() and '__pycache__' not in path.parts)
    before = {str(path.relative_to(WORKSPACE)): identity(path) for path in sorted(paths)}
    required = WORKSPACE / 'guard-fix-validation-20261030'
    for name in ['public-b121-related13/receipt.json', 'public-b121-safety340/receipt.json']:
        assert json.loads((required / name).read_text())['ok'] is True
    assert json.loads((required / 'public-b121-controlled-delay/receipt.json').read_text())['expected_outcome_observed'] is True
    manifest = {'schema': 'hepta.guard-fix-evidence-manifest.v1',
                'parent_head': 'e0b9012a249167b5bc5b0f3bd243899344621080',
                'local_head': '40ae7fa8c8d8c82cec0861e4f946e264329a984a',
                'public_head': 'b121c9b4a57a8a58e53360d1d67387d953348f57',
                'shared_tree': '8e39b41544b5fde725a6ed57cc104bfa2f3fa257',
                'inputs': before, 'input_count': len(before),
                'input_bytes': sum(row['bytes'] for row in before.values()),
                'excluded_reproducible_import_caches': ['__pycache__'],
                'original_official_e0_failure_and_distinct_generic_red_retained': True,
                'actual_public_b121_gates': {'related_ordinary_methods': 13,
                    'controlled_delay_ordinary_methods': 1, 'canonical_safety_ordinary_methods': 340},
                'selected_gates_are_overlapping': True,
                'new_native_executions_by_packaging': 0,
                'old40ae_observations_relabelled_as_public': False,
                'hosted_ci_pass_or_later_p0_qualification_claim': False}
    manifest_path = save('archive-manifest.json', manifest)
    archive_inputs = dict(before)
    archive_inputs[str(manifest_path.relative_to(WORKSPACE))] = identity(manifest_path)
    print(json.dumps({'phase': 'archive', 'members': len(archive_inputs),
                      'input_bytes': manifest['input_bytes']}), flush=True)
    with tarfile.open(ARCHIVE, 'w:xz', preset=9, format=tarfile.PAX_FORMAT) as archive:
        for name, expected in sorted(archive_inputs.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = expected['bytes'], int(expected['mode'], 8), 0
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            with (WORKSPACE / name).open('rb') as stream:
                archive.addfile(info, stream)
    print(json.dumps({'phase': 'readback', 'compressed_bytes': ARCHIVE.stat().st_size}), flush=True)
    seen = []
    with tarfile.open(ARCHIVE, 'r:xz') as archive:
        for member in archive:
            assert member.isfile() and member.name in archive_inputs and member.name not in seen
            expected = archive_inputs[member.name]
            assert member.size == expected['bytes'] and member.mode == int(expected['mode'], 8)
            digest, blob = sha256(), sha1(b'blob ' + str(member.size).encode() + b'\0')
            with archive.extractfile(member) as stream:
                while raw := stream.read(1024 * 1024):
                    digest.update(raw)
                    blob.update(raw)
            assert digest.hexdigest() == expected['sha256'] and blob.hexdigest() == expected['git_blob']
            seen.append(member.name)
    assert set(seen) == set(archive_inputs)
    expanded = 0
    with lzma.open(ARCHIVE, 'rb') as stream:
        while raw := stream.read(1024 * 1024):
            expanded += len(raw)
    assert before == {name: identity(WORKSPACE / name) for name in before}
    archive_identity = identity(ARCHIVE)
    parts, offset = [], 0
    digest = sha256()
    blob = sha1(b'blob ' + str(archive_identity['bytes']).encode() + b'\0')
    with ARCHIVE.open('rb') as stream:
        while raw := stream.read(4 * 1024 * 1024):
            name = ARCHIVE.name + '.part' + str(len(parts) + 1).zfill(3)
            parts.append({'name': name, 'repository_path': REPOSITORY_PREFIX + '/' + name,
                          'local_archive': str(ARCHIVE), 'offset': offset, 'bytes': len(raw),
                          'sha256': sha256(raw).hexdigest(),
                          'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                          'mode': '100644'})
            digest.update(raw)
            blob.update(raw)
            offset += len(raw)
    assert offset == archive_identity['bytes']
    assert digest.hexdigest() == archive_identity['sha256'] and blob.hexdigest() == archive_identity['git_blob']
    receipt_path = save('archive-readback.json', {
        'schema': 'hepta.guard-fix-archive-readback.v1',
        'archive': {'path': str(ARCHIVE), **archive_identity},
        'member_count': len(seen), 'all_paths_modes_sizes_sha256_git_blobs_match': True,
        'full_xz_stream_eof_and_check_consumed': True, 'uncompressed_tar_bytes': expanded,
        'original_inputs_unchanged': True, 'original_input_count': len(before),
        'ordered_parts_cover_archive_exactly': True, 'part_count': len(parts),
        'wall_seconds': time.monotonic() - clock, 'new_native_or_test_executions': 0})
    part_path = save('archive-parts.json', {'schema': 'hepta.evidence-archive-offset-parts.v1',
        'archive': {'path': str(ARCHIVE), **archive_identity}, 'chunk_bytes': 4 * 1024 * 1024,
        'parts': parts, 'part_count': len(parts), 'physical_part_files_created': False,
        'ordered_ranges_cover_original_exactly': True,
        'publication_method': 'Read exact offset/length from local_archive; downloaded named parts restore through included restore.py.'})
    files = []
    for path in (OUTPUT / 'README.md', OUTPUT / 'package.py', manifest_path, receipt_path, part_path,
                 WORKSPACE / 'integration-convergence-e0-evidence/restore.py'):
        files.append({'local_path': str(path), 'repository_path': REPOSITORY_PREFIX + '/' + path.name,
                      **identity(path), 'mode': '100755' if path.stat().st_mode & 0o111 else '100644'})
    publication_path = save('publication-files.json', {
        'schema': 'hepta.guard-fix-publication.v1', 'source_head': manifest['public_head'],
        'historical_local_head': manifest['local_head'], 'source_tree': manifest['shared_tree'],
        'payload_files': files, 'archive_parts': parts,
        'archive': {'path': str(ARCHIVE), **archive_identity}, 'also_publish_this_map': True,
        'map_repository_path': REPOSITORY_PREFIX + '/publication-files.json',
        'no_remote_writes_by_this_agent': True, 'remote_publication_verified_by_packager': False,
        'qualification_scope': 'Actual local40ae/publicb121 observations; original e0 failures retained; later P0/hosted gates separate.'})
    print(json.dumps({'complete': True, 'archive_bytes': archive_identity['bytes'],
                      'archive_sha256': archive_identity['sha256'], 'members': len(seen),
                      'parts': len(parts), 'manifest_sha256': identity(publication_path)['sha256']}), flush=True)


if __name__ == '__main__':
    main()
