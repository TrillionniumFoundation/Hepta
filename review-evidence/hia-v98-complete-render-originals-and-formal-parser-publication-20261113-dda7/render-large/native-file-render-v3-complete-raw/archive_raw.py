"""Lossless deterministic CAS custody of the exact frozen v3 raw inventory."""
from pathlib import Path, PurePosixPath
import base64
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile
import time
import zlib

ROOT = Path(__file__).resolve().parent
SOURCE = Path('/workspace/scratch/dda74a4fae35/v96-native-file-render-r1')
HANDOFF = SOURCE / 'handoff-r1'
OUT = ROOT / 'attempt-r1'


def identity(raw, mode=None):
    value = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
             'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
    if mode is not None:
        value['mode'] = '100755' if mode & 0o111 else '100644'
    return value


def check(raw, expected):
    actual = identity(raw)
    assert all(actual[k] == expected[k] for k in actual)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def put(path, raw):
    with path.open('xb') as f:
        f.write(raw)
    assert path.read_bytes() == raw


def main():
    OUT.mkdir(exist_ok=False)
    start = time.monotonic_ns()
    plan = json.loads((HANDOFF / 'PUBLICATION-PLAN.json').read_bytes())
    index = plan['capsules']['evidence']
    full = bytearray()
    for part in index['parts']:
        assert part['offset'] == len(full)
        raw = (HANDOFF / part['path']).read_bytes()
        check(raw, part)
        full.extend(raw)
    check(bytes(full), index['complete'])
    wrapped = json.loads(full)
    decoded = zlib.decompress(base64.b64decode(wrapped['payload'], validate=True))
    check(decoded, wrapped['decoded'])
    original = json.loads(decoded)
    files = original['raw_inventory']
    assert len(files) == 2891 and sum(row['bytes'] for row in files.values()) == 136108610
    manifest = {'schema': 'hia.file-render-v3.complete-raw-CAS.v1',
        'source_recipe': '7af2ddf86cc8dc1e6684a27d8813875957f1eb26',
        'minimum_originals_index': '9d85f452ad6e0b5825a998a8defcbcaded98a8da',
        'source_tree': '0a59f35ad40399f44287ece9011d6323c4535ce3',
        'logical_files': len(files), 'logical_bytes': sum(row['bytes'] for row in files.values()),
        'files': files,
        'scope': 'Every path in the already-frozen raw_inventory, including large native/VM buffers, images and all first failures. Later handoff/ACK files are a separate43-leaf recipe.',
        'product_executions': 0, 'new_qualification': False}
    manifest_raw = encoded(manifest)
    put(OUT / 'RAW-MANIFEST.json', manifest_raw)
    objects = {}
    aliases = {}
    for name, expected in sorted(files.items()):
        path = PurePosixPath(name)
        assert not path.is_absolute() and '..' not in path.parts and str(path) == name
        actual = SOURCE / name
        mode = actual.lstat().st_mode
        assert stat.S_ISREG(mode)
        raw = actual.read_bytes()
        assert identity(raw, mode) == expected
        digest = expected['sha256']
        if digest not in objects:
            objects[digest] = actual
        else:
            assert raw == objects[digest].read_bytes()
        aliases.setdefault(digest, []).append(name)
    archive = OUT / 'COMPLETE-RAW.tar.gz'
    with archive.open('xb') as target:
        with gzip.GzipFile(filename='', mode='wb', fileobj=target, compresslevel=1, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
                for name, raw in [('RAW-MANIFEST.json', manifest_raw)]:
                    item = tarfile.TarInfo(name); item.size = len(raw); item.mode = 0o644
                    item.uid = item.gid = item.mtime = 0
                    tar.addfile(item, io.BytesIO(raw))
                for digest, path in sorted(objects.items()):
                    raw = path.read_bytes()
                    assert hashlib.sha256(raw).hexdigest() == digest
                    item = tarfile.TarInfo('objects/' + digest); item.size = len(raw); item.mode = 0o644
                    item.uid = item.gid = item.mtime = 0
                    tar.addfile(item, io.BytesIO(raw))
    restored = OUT / 'restored'
    restored.mkdir()
    seen = set()
    with tarfile.open(archive, 'r:gz') as tar:
        for item in tar:
            assert item.isreg() and item.uid == item.gid == item.mtime == 0 and item.mode == 0o644
            assert item.name not in seen; seen.add(item.name)
            raw = tar.extractfile(item).read()
            assert len(raw) == item.size
            if item.name == 'RAW-MANIFEST.json':
                assert raw == manifest_raw
                continue
            assert item.name.startswith('objects/')
            digest = item.name[8:]
            assert digest in aliases and hashlib.sha256(raw).hexdigest() == digest
            for name in aliases[digest]:
                target = restored / name
                target.parent.mkdir(parents=True, exist_ok=True)
                put(target, raw)
                target.chmod(0o755 if files[name]['mode'] == '100755' else 0o644)
    assert seen == {'RAW-MANIFEST.json'} | {'objects/' + digest for digest in objects}
    actual_paths = {p.relative_to(restored).as_posix() for p in restored.rglob('*') if p.is_file()}
    assert actual_paths == set(files)
    for name, expected in files.items():
        for parent in (SOURCE, restored):
            actual = parent / name
            assert identity(actual.read_bytes(), actual.stat().st_mode) == expected
    raw = archive.read_bytes()
    assert raw[:10] == bytes.fromhex('1f8b08000000000004ff')
    result = {'schema': 'hia.file-render-v3.complete-raw-custody-readback.v1', 'status': 'PASS',
        'logical_files': len(files), 'logical_bytes': manifest['logical_bytes'],
        'unique_CAS_objects': len(objects), 'unique_bytes': sum(path.stat().st_size for path in objects.values()),
        'archive': identity(raw), 'manifest': identity(manifest_raw),
        'all_gzip_tar_objects_full_readback': True,
        'all2891_real_restored_paths_bytes_modes_SHA_Git_match': True,
        'all2891_original_paths_unchanged': True,
        'elapsed_ns': time.monotonic_ns() - start,
        'restore_directory': str(restored), 'original_directory': str(SOURCE),
        'new_product_executions': 0, 'new_qualification': False, 'Git_archive_persisted': False}
    put(OUT / 'REPORT.json', encoded(result))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
