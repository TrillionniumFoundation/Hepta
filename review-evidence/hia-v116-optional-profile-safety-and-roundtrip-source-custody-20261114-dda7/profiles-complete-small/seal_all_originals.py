"""Losslessly seal frozen R1/R2/R3 originals without following symlinks or running product code."""
from pathlib import Path
import base64
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile
import time

HERE = Path(__file__).resolve().parent
WORK = HERE.parent
OUT = HERE / 'complete-custody-r1'
CHUNK = 524288


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def digests(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def save(path, raw):
    with path.open('xb') as f:
        f.write(raw)
    assert path.read_bytes() == raw
    return {'path': str(path), **digests(raw)}


def stable(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_nlink)


def read_pin(path):
    initial = path.lstat()
    assert stat.S_ISREG(initial.st_mode), path
    sha = hashlib.sha256()
    git = hashlib.sha1(b'blob ' + str(initial.st_size).encode() + b'\0')
    size = 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        assert stable(os.fstat(fd)) == stable(initial), path
        while True:
            raw = os.read(fd, 1048576)
            if not raw:
                break
            size += len(raw)
            sha.update(raw)
            git.update(raw)
        assert stable(os.fstat(fd)) == stable(initial), path
    finally:
        os.close(fd)
    assert stable(path.lstat()) == stable(initial) and size == initial.st_size, path
    return {'bytes': size, 'sha256': sha.hexdigest(), 'git_blob': git.hexdigest()}


def tree_rows(root, prefix):
    rows = []
    def visit(path, name):
        st = path.lstat()
        row = {'path': name, 'original': str(path), 'mode': stat.S_IMODE(st.st_mode),
               'mode_source': 'ACTUAL_LOCAL_LSTAT', 'mtime_ns': st.st_mtime_ns,
               'device': st.st_dev, 'inode': st.st_ino, 'nlink': st.st_nlink}
        if stat.S_ISLNK(st.st_mode):
            row.update(kind='symlink', target_base64=base64.b64encode(os.fsencode(os.readlink(path))).decode())
        elif stat.S_ISREG(st.st_mode):
            row.update(kind='file', **read_pin(path))
        elif stat.S_ISDIR(st.st_mode):
            row.update(kind='directory')
        else:
            raise ValueError(f'unsupported original filesystem member: {path}')
        rows.append(row)
        if row['kind'] == 'directory':
            for child in sorted(path.iterdir(), key=lambda p: os.fsencode(p.name)):
                visit(child, name + '/' + child.name)
    visit(root, prefix)
    return rows


def selected_inputs():
    inputs = []
    for revision in ('r1', 'r2', 'r3'):
        scope = WORK / ('v112-profile-resources-' + revision)
        inputs.append((scope / 'evidence', revision + '/evidence'))
        for path in sorted(scope.iterdir()):
            if path.is_file() and path.suffix in ('.py', '.json', '.patch', '.diff', '.md'):
                inputs.append((path, revision + '/authoring-root/' + path.name))
            elif path.is_dir() and (path.name == 'authoring' or path.name.startswith('handoff-')):
                inputs.append((path, revision + '/' + path.name))
    inputs.append((HERE / 'terminal-custody-r1', 'r3/terminal-custody-r1'))
    return inputs


def add(tar, name, path=None, raw=None):
    size = path.stat().st_size if path is not None else len(raw)
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o644
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ''
    if path is not None:
        with path.open('rb') as f:
            tar.addfile(info, f)
    else:
        tar.addfile(info, io.BytesIO(raw))


def main():
    start = time.monotonic_ns()
    OUT.mkdir(exist_ok=False)
    inputs = selected_inputs()
    save(OUT / 'INTENT.json', encoded({'schema': 'hepta.frozen-originals-cas-intent.v1',
        'scope': 'ALL_ACTUAL_R1_R2_R3_EVIDENCE_AND_FROZEN_AUTHORING',
        'inputs': [{'path': str(p), 'archive_prefix': prefix} for p, prefix in inputs],
        'no_product_execution': True, 'originals_not_modified_or_deleted': True,
        'no_second_expanded_restore': True, 'symlinks_recorded_never_followed': True}))
    rows = []
    for path, prefix in inputs:
        rows.extend(tree_rows(path, prefix))
    assert len({x['path'] for x in rows}) == len(rows)
    pool = {}
    for row in rows:
        if row['kind'] == 'file':
            prior = pool.setdefault(row['sha256'], row)
            assert (prior['bytes'], prior['git_blob']) == (row['bytes'], row['git_blob'])
    counts = {kind: sum(r['kind'] == kind for r in rows) for kind in ('file', 'directory', 'symlink')}
    manifest = {'schema': 'hepta.full-optional-profile-originals-cas.v1', 'rows': rows,
        'logical_counts': counts, 'logical_regular_bytes': sum(r.get('bytes', 0) for r in rows),
        'unique_regular_files': len(pool), 'unique_regular_bytes': sum(r['bytes'] for r in pool.values()),
        'source_trees': {'r1': '60162b6c8cf5c0c375d3223fc28d6b66a0d5212a',
            'r2': '3d8c3ff40f59d6f436bed1a193da8d5ebbe544f1',
            'r3': '24754374b90df56de475e67274ceb9280f6882fa'},
        'source_packets': ['44533fa6a7d40c07947229587184f109be8f5d2a',
            'e2e991a1b4d4d67817d9060c826902f5d87b8898', '256cfbe8906a1d8b08d5e320f96baa1c407392cb'],
        'all_actual_failures_preserved': True, 'matching_cold_positive': False,
        'scope_boundaries': ['R2 original43 was never started; R3 original43 ran once.',
            'R2 two report tests and 140 case journal retained in R2 scope; not repeated for setup-only R3.',
            'Original Source packaging TemporaryDirectory cleanup removed its temporary wheels; no claim to nonexistent products.',
            'Actual retained original43 installed-control trees and all images/full buffers/journals are included.',
            'Original symlink targets and real directory modes are recorded; CAS archive contains only regular objects.',
            'No whole CLI/native or matching-current-source cold qualification is asserted.']}
    raw_manifest = encoded(manifest)
    manifest_pin = save(OUT / 'MANIFEST.json', raw_manifest)
    archive = OUT / 'COMPLETE-ORIGINALS.tar.gz'
    with archive.open('xb') as dest:
        with gzip.GzipFile(fileobj=dest, mode='wb', compresslevel=1, mtime=0, filename='') as gz:
            with tarfile.open(fileobj=gz, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
                add(tar, 'MANIFEST.json', raw=raw_manifest)
                for sha, row in sorted(pool.items()):
                    add(tar, 'objects/' + sha, path=Path(row['original']))
    observed = set()
    with gzip.open(archive, 'rb') as gz:
        with tarfile.open(fileobj=gz, mode='r|') as tar:
            for member in tar:
                assert member.isfile() and member.mode == 0o644
                stream = tar.extractfile(member)
                if member.name == 'MANIFEST.json':
                    assert member.name not in observed
                    assert stream.read() == raw_manifest
                else:
                    assert member.name.startswith('objects/')
                    sha = member.name[8:]
                    assert sha in pool and member.name not in observed
                    expected = pool[sha]
                    digest = hashlib.sha256()
                    git = hashlib.sha1(b'blob ' + str(member.size).encode() + b'\0')
                    size = 0
                    while raw := stream.read(1048576):
                        size += len(raw)
                        digest.update(raw)
                        git.update(raw)
                    assert size == member.size == expected['bytes']
                    assert digest.hexdigest() == sha and git.hexdigest() == expected['git_blob']
                observed.add(member.name)
        while gz.read(1048576):
            pass
    assert observed == {'MANIFEST.json'} | {'objects/' + sha for sha in pool}
    after = []
    for path, prefix in inputs:
        after.extend(tree_rows(path, prefix))
    assert rows == after
    archive_pin = read_pin(archive)
    parts = []
    with archive.open('rb') as f:
        while raw := f.read(CHUNK):
            name = f'part-{len(parts):04d}.b64'
            text = base64.b64encode(raw)
            assert base64.b64decode(text, validate=True) == raw
            p = save(OUT / name, text)
            parts.append({'index': len(parts), 'name': name, **p, 'decoded': digests(raw)})
    with archive.open('rb') as f:
        for part in parts:
            raw = base64.b64decode((OUT / part['name']).read_bytes(), validate=True)
            assert raw == f.read(len(raw))
        assert f.read(1) == b''
    index = {'schema': 'hepta.full-originals-base64-parts.v1', 'archive': archive_pin,
        'manifest': manifest_pin, 'parts': parts, 'encoding': 'each UTF8 base64 part decodes independently; concatenate decoded bytes in numeric order',
        'no_linefeeds_in_part_text': True, 'chunk_decoded_bytes': CHUNK}
    index_pin = save(OUT / 'INDEX.json', encoded(index))
    proof = {'schema': 'hepta.optional-profiles-complete-custody-verification.v1',
        'status': 'FULL_CAS_AND_GZIP_STREAM_READBACK_PASS', 'elapsed_ns': time.monotonic_ns() - start,
        'logical_counts': counts, 'logical_regular_bytes': manifest['logical_regular_bytes'],
        'unique_files': len(pool), 'unique_bytes': manifest['unique_regular_bytes'], 'archive': archive_pin,
        'archive_members': len(observed), 'originals_before_after_all_equal': True,
        'all_logical_files_resolve_to_verified_objects': True, 'all_actual_file_and_directory_modes_recorded': True,
        'symlink_targets_recorded_not_followed': True, 'stream_gzip_crc_complete': True,
        'parts': len(parts), 'parts_strict_decode_recompose_original_archive': True,
        'manifest': manifest_pin, 'index': index_pin, 'no_product_execution': True,
        'no_second_expanded_restore': True, 'no_originals_deleted': True,
        'matching_current_source_cold_positive': False, 'whole_cli_native': False}
    proof_pin = save(OUT / 'VERIFICATION.json', encoded(proof))
    print(json.dumps({'proof': proof_pin, 'logical_counts': counts,
        'logical_bytes': manifest['logical_regular_bytes'], 'unique_bytes': manifest['unique_regular_bytes'],
        'archive': archive_pin, 'parts': len(parts), 'elapsed_seconds': proof['elapsed_ns'] / 1e9}))


if __name__ == '__main__':
    main()
