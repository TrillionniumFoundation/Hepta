#!/usr/bin/env python3
"""Freeze completed public5a0d evidence without rerunning qualification."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha1, sha256
import json
import lzma
from pathlib import Path
import stat
import tarfile
import time

ROOT = Path('/workspace/scratch/b484d4086829')
OUTPUT = Path(__file__).resolve().parent
PREFIX = 'evidence/hia_core_closure_20261030/returned-local-view-public5a0d'
HEAD = '5a0d1997b0bba8f8cb674b317ae1f56f0afcb22a'
TREE = '88478a74708cf63edf7f9304c0b4ceb820b04d01'
ROOTS = [
    'returned-local-view-public349-20261030',
    'returned-local-view-public-20261030',
    'returned-local-view-composition-20261030/source-export-final',
    'ndu-restoration-20261030',
]
FILES = [
    'returned-local-view-package-20261030/publication-files-final.json',
    'progress-publication-20261029/p0-local-view-0d-source-publication.json',
    'progress-publication-20261029/convergence-guards-localviews-evidence-publication.json',
    'progress-publication-20261029/convergence-guard-p0-actual-remote-readback.json',
    'progress-publication-20261029/verify-remote-convergence-packages.py',
    'progress-publication-20261029/qemu-restoration-20261030.json',
    'progress-publication-20261029/z3-restoration-20261030.json',
    'progress-publication-20261029/llvm20-restoration-publication.json',
    'progress-publication-20261029/full147-final-tree-readback.json',
    'progress-publication-20261029/full147-actual-remote-stream-readback.json',
    'integration-convergence-e0-evidence/runtime-restoration-links.json',
    'integration-convergence-e0-evidence/restore.py',
    'integration-405-147-20261030/run-public-safety340.py',
    'guard-fix-validation-20261030/run-public-safety340.py',
    'toolchains/retained-ndu-147/recursive/transport-identity.json',
    'toolchains/retained-ndu-147/finite/transport-identity.json',
    'toolchains/retained-ndu-147/stream/transport-identity.json',
]


def identity(path):
    path = Path(path)
    assert path.is_file() and not path.is_symlink(), str(path)
    size = path.stat().st_size
    digest, blob = sha256(), sha1(b'blob ' + str(size).encode() + b'\0')
    with path.open('rb') as stream:
        for raw in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(raw)
            blob.update(raw)
    return {'bytes': size, 'sha256': digest.hexdigest(), 'git_blob': blob.hexdigest(),
            'mode': oct(stat.S_IMODE(path.stat().st_mode))}


def save(name, value):
    path = OUTPUT / name
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--review-map', type=Path, required=True)
    options = parser.parse_args()
    archive_path = OUTPUT / 'returned-local-view-public5a0d.tar.xz'
    assert not archive_path.exists(), 'Never overwrite a frozen package'
    started, clock = datetime.now(timezone.utc).isoformat(), time.monotonic()
    qualifier = ROOT / 'returned-local-view-public349-20261030/qualification-public'
    receipt = json.loads((qualifier / 'receipt.json').read_text())
    same9 = json.loads((qualifier / 'returned-local-view-details/summary.json').read_text())
    union = json.loads((ROOT / 'returned-local-view-public349-20261030/public-method-scope-union.json').read_text())
    legacy = json.loads((ROOT / 'returned-local-view-public-20261030/source-regressions68/summary.json').read_text())
    assert receipt['ok'] and same9['ok'] and legacy['ok']
    assert receipt['actual_public_head'] == legacy['source_head'] == HEAD
    assert receipt['tree'] == legacy['source_tree'] == TREE
    assert receipt['method_count'] == 349 and receipt['capability_count'] == 36
    assert union['unique_ordinary_method_count_across_these_two_runs'] == 417
    assert union['overlap_between_actual_two_runs'] == 0
    assert same9['counts'] == {'source_refusals': 18, 'core_refusals': 5, 'rust_refusals': 5,
                              'rust_observations': 86, 'direct_llvm_calls': 33,
                              'allocator_observer_calls': 2, 'bounded_compiler_processes': 6}
    review_map_path = options.review_map.resolve(strict=True)
    review_map = json.loads(review_map_path.read_text())
    rows = review_map.get('files')
    if not isinstance(rows, list):
        rows = review_map.get('payload_files')
    assert isinstance(rows, list) and rows
    review = json.loads((review_map_path.parent / 'review.json').read_text())
    assert review['ok'] and review['public349_methods'] == 349 and review['public349_capabilities'] == 36
    assert review['new_native_test_lowering_verification_or_oracle_invocations_in_this_auditor'] == 0
    paths = {ROOT / name for name in FILES}
    paths.update({OUTPUT / 'README.md', Path(__file__).resolve(), review_map_path})
    for row in rows:
        path = Path(row.get('local_path', row.get('path')))
        actual = identity(path)
        assert actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256']
        assert actual['git_blob'] == row.get('git_blob', row.get('git_blob_sha1'))
        paths.add(path)
    for name in ROOTS:
        paths.update(path for path in (ROOT / name).rglob('*')
                     if path.is_file() and '__pycache__' not in path.parts)
    before = {str(path.relative_to(ROOT)): identity(path) for path in sorted(paths)}
    assert all('private-transport' not in name for name in before)
    assert all(not name.endswith('/official-full-release-147d39.zip') for name in before)
    manifest = {'schema': 'hepta.returned-local-view-public5a0d-evidence-manifest.v1',
        'public_head': HEAD, 'source_tree': TREE, 'public_parent': 'b121c9b4a57a8a58e53360d1d67387d953348f57',
        'same_tree_local_head': '0d077885cc4be0b8ee96a012d7d6d2e51d1d2ace',
        'source_identity_roles_kept_distinct': True, 'inputs': before, 'input_count': len(before),
        'input_bytes': sum(row['bytes'] for row in before.values()),
        'actual_public_canonical_methods': 349, 'canonical_capabilities': 36,
        'actual_disjoint_public_existing_methods': 68, 'unique_actual_method_ids': 417,
        'new_nine_records_are_subset_of_same349': True, 'same349_new9_counts': same9['counts'],
        'new_native_or_test_executions_by_packaging': 0,
        'historical_local_or_hosted_records_relabelled': False,
        'new_standalone_rust_crate_qualification': False,
        'excluded_reproducible_import_caches': ['__pycache__'],
        'complete_147_zip_or_toolchain_installation_duplicated': False,
        'broad_P0_P7_closed': False, 'rust_production_authority': False,
        'optimization_policy': 'no_change'}
    manifest_path = save('archive-manifest.json', manifest)
    archive_inputs = dict(before)
    archive_inputs[str(manifest_path.relative_to(ROOT))] = identity(manifest_path)
    print(json.dumps({'phase': 'archive', 'members': len(archive_inputs),
                      'input_bytes': manifest['input_bytes']}), flush=True)
    with tarfile.open(archive_path, 'w:xz', preset=6, format=tarfile.PAX_FORMAT) as archive:
        for name, expected in sorted(archive_inputs.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = expected['bytes'], int(expected['mode'], 8), 0
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            with (ROOT / name).open('rb') as stream:
                archive.addfile(info, stream)
    seen = set()
    with tarfile.open(archive_path, 'r:xz') as archive:
        for member in archive:
            assert member.isfile() and member.name not in seen and member.name in archive_inputs
            expected = archive_inputs[member.name]
            assert member.size == expected['bytes'] and member.mode == int(expected['mode'], 8)
            digest, blob = sha256(), sha1(b'blob ' + str(member.size).encode() + b'\0')
            with archive.extractfile(member) as stream:
                for raw in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(raw)
                    blob.update(raw)
            assert digest.hexdigest() == expected['sha256'] and blob.hexdigest() == expected['git_blob']
            seen.add(member.name)
    assert seen == set(archive_inputs)
    expanded = 0
    with lzma.open(archive_path, 'rb') as stream:
        for raw in iter(lambda: stream.read(1024 * 1024), b''):
            expanded += len(raw)
    assert before == {name: identity(ROOT / name) for name in before}
    whole = identity(archive_path)
    parts, offset = [], 0
    total_sha, total_git = sha256(), sha1(b'blob ' + str(whole['bytes']).encode() + b'\0')
    with archive_path.open('rb') as stream:
        for raw in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            name = archive_path.name + '.part' + str(len(parts) + 1).zfill(3)
            parts.append({'name': name, 'repository_path': PREFIX + '/' + name,
                'local_archive': str(archive_path), 'offset': offset, 'bytes': len(raw),
                'sha256': sha256(raw).hexdigest(),
                'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                'mode': '100644'})
            offset += len(raw)
            total_sha.update(raw)
            total_git.update(raw)
    assert offset == whole['bytes'] and total_sha.hexdigest() == whole['sha256'] and total_git.hexdigest() == whole['git_blob']
    readback_path = save('archive-readback.json', {
        'schema': 'hepta.returned-local-view-public5a0d-archive-readback.v1',
        'archive': {'path': str(archive_path), **whole}, 'member_count': len(seen),
        'all_paths_modes_sizes_sha256_git_blobs_match': True,
        'full_xz_stream_eof_and_integrity_check_consumed': True, 'uncompressed_tar_bytes': expanded,
        'original_input_count': len(before), 'original_inputs_unchanged': True,
        'ordered_parts_cover_archive_exactly': True, 'part_count': len(parts),
        'started_utc': started, 'finished_utc': datetime.now(timezone.utc).isoformat(),
        'wall_seconds': time.monotonic() - clock, 'new_native_or_test_executions': 0})
    parts_path = save('archive-parts.json', {'schema': 'hepta.evidence-archive-offset-parts.v1',
        'archive': {'path': str(archive_path), **whole}, 'chunk_bytes': 4 * 1024 * 1024,
        'parts': parts, 'part_count': len(parts), 'physical_part_files_created': False,
        'ordered_ranges_cover_original_exactly': True,
        'publication_method': 'Read exact offset and length from local_archive; restore from downloaded named parts with restore.py.'})
    files = []
    for path in [OUTPUT / 'README.md', Path(__file__).resolve(), manifest_path, readback_path,
                 parts_path, ROOT / 'integration-convergence-e0-evidence/restore.py']:
        files.append({'local_path': str(path), 'repository_path': PREFIX + '/' + path.name,
                      **identity(path), 'mode': '100755' if path.stat().st_mode & 0o111 else '100644'})
    publication = save('publication-files.json', {
        'schema': 'hepta.returned-local-view-public5a0d-publication.v1', 'source_head': HEAD,
        'source_tree': TREE, 'payload_files': files, 'archive_parts': parts,
        'archive': {'path': str(archive_path), **whole}, 'also_publish_this_map': True,
        'map_repository_path': PREFIX + '/publication-files.json',
        'no_remote_writes_by_this_agent': True, 'remote_publication_verified_by_packager': False,
        'qualification_scope': 'Actual public5a0d canonical349 and disjoint68 only; nine detailed methods are inside the same349. Historical and subsequent sources remain separate.'})
    print(json.dumps({'complete': True, 'archive_bytes': whole['bytes'], 'archive_sha256': whole['sha256'],
                      'members': len(seen), 'parts': len(parts),
                      'publication_map_sha256': identity(publication)['sha256']}), flush=True)


if __name__ == '__main__':
    main()
