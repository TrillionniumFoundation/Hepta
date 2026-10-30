#!/usr/bin/env python3
"""Freeze completed convergence evidence; never execute or rewrite a corpus."""
from hashlib import sha1, sha256
import io
import json
import lzma
from pathlib import Path
import stat
import tarfile
import time

WORKSPACE = Path('/workspace/scratch/b484d4086829')
OUTPUT = Path(__file__).resolve().parent
ARCHIVE = OUTPUT / 'core-rust-convergence-f654-e0.tar.xz'
REPOSITORY_PREFIX = 'evidence/hia_core_closure_20261029/integration-convergence-e0-evidence'
ROOTS = [
    'core-rust-integration-validation', 'core-rust-public-validation',
    'core-rust-public-safety340', 'integration-405-147-20261030',
    'integration-405-p3-validation', 'public-405-p3-validation',
    'integration-ci-e0b9012-failure', 'ndu-restoration-20261030',
]
FILES = [
    'integration-convergence-e0-evidence/README.md',
    'integration-convergence-e0-evidence/package.py',
    'integration-convergence-e0-evidence/restore.py',
    'integration-405-independent-review/ndu-147-reuse-locator.json',
    'integration-405-independent-review/integration-e0-publication-files.json',
    'progress-publication-20261029/integration-f654-source-export.json',
    'progress-publication-20261029/integration-f654-source-publication.json',
    'progress-publication-20261029/integration-pr-receipt.json',
    'progress-publication-20261029/integration-pr-initial-body.md',
    'progress-publication-20261029/integration-source-application-job-124060656375.log',
    'progress-publication-20261029/integration-source-application-ci-failure-jobs.json',
    'progress-publication-20261029/qemu-restoration-20261030.json',
    'progress-publication-20261029/z3-restoration-20261030.json',
    'progress-publication-20261029/llvm20-restoration-publication.json',
    'llvm-restoration-20261029-evening/summary.json',
    'llvm-restoration-20261029-evening/publication-metadata.json',
    'llvm-restoration-20261029-evening/metadata-archive-receipt.json',
    'llvm-restoration-20261029-evening/llvm20-env.sh',
    'hosted-147d39-evidence/full-release/publication-metadata.json',
    'hosted-147d39-evidence/full-release/raw-parts.json',
    'progress-publication-20261029/full147-final-tree-readback.json',
    'progress-publication-20261029/full147-actual-remote-stream-readback.json',
    'toolchains/retained-ndu-147/recursive/transport-identity.json',
    'toolchains/retained-ndu-147/finite/transport-identity.json',
    'toolchains/retained-ndu-147/stream/transport-identity.json',
    'integration-convergence-e0-evidence/runtime-restoration-links.json',
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
    peer_map = json.loads((WORKSPACE / 'integration-405-independent-review/integration-e0-publication-files.json').read_text())
    peer_archive = peer_map['archive']
    assert peer_archive['sha256'] == '2338edcc21bbb3f4b757f749b20ce5c4c5672b17e3375ebe0eb99dd3ede3844d'
    for row in peer_map['files']:
        actual = identity(Path(row['path']))
        assert all(actual[key] == row[key] for key in ('bytes', 'sha256', 'git_blob'))
    paths = {WORKSPACE / name for name in FILES}
    paths.update(Path(row['path']) for row in peer_map['files'])
    for root in ROOTS:
        paths.update(path for path in (WORKSPACE / root).rglob('*')
                     if path.is_file() and '__pycache__' not in path.parts)
    before = {str(path.relative_to(WORKSPACE)): identity(path) for path in sorted(paths)}
    manifest = {'schema': 'hepta.convergence-e0-evidence-manifest.v1',
                'local_head': 'f6540186aa34c991b2082d59cd998b857f78ced4',
                'public_head': 'e0b9012a249167b5bc5b0f3bd243899344621080',
                'shared_tree': '7adcc2a0333b48374b4add2d8132d1998c5cc48c',
                'inputs': before, 'input_count': len(before),
                'input_bytes': sum(row['bytes'] for row in before.values()),
                'excluded_reproducible_import_caches': ['__pycache__'],
                'official_e0_safety_outcome': {'ordinary_passes': 339, 'failed_subtests': 1},
                'local_public_e0_safety_outcome': {'ordinary_passes': 340, 'failed_subtests': 0},
                'historical_failed_controls_retained': True,
                'new_native_executions_by_packaging': 0,
                'giant_toolchain_installations_or_original_ndu_zip_duplicated': False,
                'later_guard_fix_or_p0_executions_relabelled': False}
    manifest_path = save('archive-manifest.json', manifest)
    archive_inputs = dict(before)
    manifest_name = str(manifest_path.relative_to(WORKSPACE))
    archive_inputs[manifest_name] = identity(manifest_path)
    print(json.dumps({'phase': 'archive', 'members': len(archive_inputs),
                      'input_bytes': manifest['input_bytes']}), flush=True)
    with tarfile.open(ARCHIVE, 'w:xz', preset=9, format=tarfile.PAX_FORMAT) as archive:
        for name, expected in sorted(archive_inputs.items()):
            path = WORKSPACE / name
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = expected['bytes'], int(expected['mode'], 8), 0
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            with path.open('rb') as stream:
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
    # Consume the compression stream through EOF, including its trailing check.
    expanded = 0
    with lzma.open(ARCHIVE, 'rb') as stream:
        while raw := stream.read(1024 * 1024):
            expanded += len(raw)
    after = {name: identity(WORKSPACE / name) for name in before}
    assert before == after
    archive_identity = identity(ARCHIVE)
    parts = []
    offset = 0
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
    receipt = {'schema': 'hepta.convergence-e0-archive-readback.v1',
               'archive': {'path': str(ARCHIVE), **archive_identity},
               'member_count': len(seen), 'all_paths_modes_sizes_sha256_git_blobs_match': True,
               'full_xz_stream_eof_and_check_consumed': True, 'uncompressed_tar_bytes': expanded,
               'original_inputs_unchanged': before == after, 'original_input_count': len(before),
               'ordered_parts_cover_archive_exactly': True, 'part_count': len(parts),
               'wall_seconds': time.monotonic() - clock, 'new_native_or_test_executions': 0}
    receipt_path = save('archive-readback.json', receipt)
    part_path = save('archive-parts.json', {'schema': 'hepta.evidence-archive-offset-parts.v1',
        'archive': {'path': str(ARCHIVE), **archive_identity}, 'chunk_bytes': 4 * 1024 * 1024,
        'parts': parts, 'part_count': len(parts), 'physical_part_files_created': False,
        'ordered_ranges_cover_original_exactly': True,
        'publication_method': 'Read each exact offset/length from local_archive; uploaded part bytes must match both digests. Restore expects the downloaded named part files.'})
    files = []
    for path in (OUTPUT / 'README.md', OUTPUT / 'package.py', OUTPUT / 'restore.py', OUTPUT / 'runtime-restoration-links.json',
                 manifest_path, receipt_path, part_path):
        files.append({'local_path': str(path), 'repository_path': REPOSITORY_PREFIX + '/' + path.name,
                      **identity(path), 'mode': '100755' if path.stat().st_mode & 0o111 else '100644'})
    publication = {'schema': 'hepta.convergence-e0-publication.v1',
                   'source_head': manifest['public_head'], 'historical_local_head': manifest['local_head'],
                   'source_tree': manifest['shared_tree'], 'payload_files': files,
                   'archive_parts': parts, 'archive': {'path': str(ARCHIVE), **archive_identity},
                   'also_publish_this_map': True,
                   'map_repository_path': REPOSITORY_PREFIX + '/publication-files.json',
                   'no_remote_writes_by_this_agent': True,
                   'remote_publication_verified_by_packager': False,
                   'qualification_scope': 'Actual f654/public e0 local corpus only; original official e0 safety failure retained; later fixes separate.'}
    publication_path = save('publication-files.json', publication)
    print(json.dumps({'complete': True, 'archive_bytes': archive_identity['bytes'],
                      'archive_sha256': archive_identity['sha256'], 'members': len(seen),
                      'parts': len(parts), 'manifest_sha256': identity(publication_path)['sha256']}), flush=True)


if __name__ == '__main__':
    main()
