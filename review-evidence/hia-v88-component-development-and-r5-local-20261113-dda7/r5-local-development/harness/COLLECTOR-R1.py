"""Preserve complete local R5 generation, both Source observations and preimages."""
from __future__ import annotations

import base64
from hashlib import sha1, sha256
import io
import json
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time

ROOT = Path(__file__).resolve().parent
WORK = ROOT.parent
OUT = ROOT / 'local-custody-r1'


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def safe(path):
    value = PurePosixPath(path)
    assert str(value) == path and not value.is_absolute() and '..' not in value.parts
    return path


def main():
    started = time.monotonic()
    OUT.mkdir(exist_ok=False)
    originals = {}
    def add(name, path):
        safe(name)
        assert name not in originals and not path.is_symlink() and stat.S_ISREG(path.stat().st_mode)
        originals[name] = path
    for name in ('local-generation-r1/evidence', 'joint-source-controls-r1/evidence',
                 'joint-source-controls-r2/evidence'):
        for path in sorted((ROOT / name).rglob('*')):
            if path.is_file():
                add('r5/' + path.relative_to(ROOT).as_posix(), path)
    for path in sorted(ROOT.iterdir()):
        if path.is_file() and path.suffix in ('.py', '.json', '.log'):
            add('r5/' + path.name, path)
    integration = WORK / 'v86-launcher-integration-r1'
    for path in sorted(integration.iterdir()):
        if path.is_file():
            add('integration/' + path.name, path)
    repair = WORK / 'v87-machine-plan-custody-repair-r1'
    for path in sorted(repair.rglob('*')):
        relative = path.relative_to(repair)
        if relative.parts[0] == 'source' or not path.is_file():
            continue
        add('machine-plan-repair/' + relative.as_posix(), path)
    pool = {}
    rows = []
    for name, path in sorted(originals.items()):
        raw = path.read_bytes()
        record = identity(raw)
        key = record['sha256']
        if key in pool:
            assert pool[key] == raw
        else:
            pool[key] = raw
        rows.append({'path': name, 'mode': stat.S_IMODE(path.stat().st_mode),
                     'object': 'objects/' + key + '.bin', **record})
    generation = json.loads((ROOT / 'local-generation-r1/evidence/raw/LOCAL-RESULT.json').read_bytes())
    failed = json.loads((ROOT / 'joint-source-controls-r1/evidence/raw/RESULT.json').read_bytes())
    final = json.loads((ROOT / 'joint-source-controls-r2/evidence/raw/RESULT.json').read_bytes())
    assert generation['status'] == 'LOCAL_GENERATION_PASS'
    assert failed['status'] == 'FAIL' and 'tests' not in failed and failed['source_unchanged']
    assert final['status'] == 'PASS' and final['source_unchanged']
    assert final['tests']['tests_run'] == final['tests']['expected'] == 97
    manifest = {'schema': 'hia.local-r5-custody-manifest.v1',
        'scope': 'LOCAL312_DEVELOPMENT_NOT_FORMAL_SOURCE_OR_NATIVE_QUALIFICATION',
        'source_tree': '91896bc788b306a44db3b1016a2ebcc140f2e121',
        'generation': {'owners': 113, 'passes': 2, 'python_ast_files': 1466,
                       'authored_paths': 366, 'conflicts_resolved': 122, 'source_tests_executed': 0},
        'source_controls': {'r1': 'pre-execution discovery expected77/actual97 refusal; zero methods',
                            'r2': 'all97 executed PASS;194 ordered start/stop events; source unchanged',
                            'complete1224_discovered_not_executed_here': True,
                            'frozen_main530_development973_missing': []},
        'references': {'full_original_source_commits': ['f33d8da316de8fdf27b504371f1a5310997ff548',
            'a733926a2786a3d4a37304bd2d18ebb2eac57ac9'],
            'r4_product': 'd79eb096ddcce6c317b2c316a4773ce76a37bab9',
            'r5_harness': '29b1145e37db05d5efa62d75c4d1dd5916f1f8b4',
            'formal_r5_source_run': 43415454682, 'formal_result_inherited': False},
        'all_original_files': len(rows), 'all_original_bytes': sum(r['bytes'] for r in rows),
        'unique_objects': len(pool), 'unique_bytes': sum(map(len, pool.values())),
        'files': rows, 'whole_native': False}
    (OUT / 'MANIFEST.json').write_bytes(canonical(manifest))
    archive = OUT / 'originals.tar.gz'
    with archive.open('xb') as output:
        import gzip
        with gzip.GzipFile(filename='', fileobj=output, mode='wb', compresslevel=6, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                for name, raw in [('MANIFEST.json', canonical(manifest))] + [
                        ('objects/' + key + '.bin', value) for key, value in sorted(pool.items())]:
                    info = tarfile.TarInfo(name)
                    info.size = len(raw)
                    info.mode = 0o644
                    info.mtime = 0
                    tar.addfile(info, io.BytesIO(raw))
    restored = {}
    with tarfile.open(archive, mode='r:gz') as tar:
        for member in tar:
            assert member.isfile() and member.mode == 0o644 and member.name not in restored
            restored[member.name] = tar.extractfile(member).read()
    assert json.loads(restored.pop('MANIFEST.json')) == manifest
    assert set(restored) == {'objects/' + key + '.bin' for key in pool}
    for row in rows:
        raw = restored[row['object']]
        assert identity(raw) == {key: row[key] for key in ('bytes', 'sha256', 'git_blob')}
        original = originals[row['path']]
        assert raw == original.read_bytes()
        assert stat.S_IMODE(original.stat().st_mode) == row['mode']
    raw_archive = archive.read_bytes()
    chunk_dir = OUT / 'chunks'
    chunk_dir.mkdir()
    chunks = []
    for index, start in enumerate(range(0, len(raw_archive), 524288)):
        raw = raw_archive[start:start + 524288]
        value = {'schema': 'hia.binary-archive.base64-chunk.v1', 'index': index, 'offset': start,
                 **identity(raw), 'encoding': 'base64', 'data': base64.b64encode(raw).decode()}
        wrapped = canonical(value)
        path = 'chunks/' + str(index).zfill(3) + '.json'
        (OUT / path).write_bytes(wrapped)
        chunks.append({'path': path, **identity(wrapped), 'raw': identity(raw), 'offset': start})
    index = {'schema': 'hia.local-r5-custody-transport.v1', 'encoding': 'gzip-tar-objects+base64-json',
             'archive': identity(raw_archive), 'manifest': identity(canonical(manifest)),
             'logical_members': len(rows), 'unique_objects': len(pool), 'chunks': chunks,
             'raw_binary_git_blob_is_computed_not_uploaded': True, 'all_git_uploads_pending': True,
             'whole_native': False}
    (OUT / 'TRANSPORT.json').write_bytes(canonical(index))
    readback = {'schema': 'hia.local-r5-original-readback.v1',
        'status': 'LOCAL_COMPLETE_ARCHIVE_READBACK_PASS_GIT_UPLOAD_PENDING',
        'archive': identity(raw_archive), 'logical_members': len(rows), 'unique_objects': len(pool),
        'all_original_members_bytes_modes_sha256_git_equal': True,
        'gzip_crc_and_tar_regular_member_set': True, 'source_test_or_product_execution': 0,
        'elapsed_seconds': time.monotonic() - started, 'git_full_readback': False,
        'whole_native': False}
    (OUT / 'LOCAL-READBACK.json').write_bytes(canonical(readback))
    print(json.dumps({**readback, 'chunks': len(chunks)}, indent=2))


if __name__ == '__main__':
    main()
