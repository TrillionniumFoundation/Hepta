"""Lossless evidence custody only; never import or execute product code."""
from pathlib import Path, PurePosixPath
import base64, gzip, hashlib, io, json, os, stat, tarfile, time

ROOT = Path('/workspace/scratch/dda74a4fae35')
HERE = ROOT / 'v119-inspect-stages-custody-r1'
GEN = ROOT / 'v119-inspect-generation-only-r1'
SRC = ROOT / 'v119-inspect-source10-r1'


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def shape(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_exact(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode), path
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        assert shape(os.fstat(fd)) == shape(before), path
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(before.st_size + 1)
        assert len(raw) == before.st_size and shape(os.fstat(fd)) == shape(before), path
    finally:
        os.close(fd)
    assert shape(path.lstat()) == shape(before), path
    return raw, before


def files_under(base, part):
    result, stack = [], [base / part]
    while stack:
        for item in sorted(stack.pop().iterdir()):
            current = item.lstat()
            if stat.S_ISDIR(current.st_mode):
                if item != GEN / 'attempt-r1/source':
                    stack.append(item)
            else:
                assert stat.S_ISREG(current.st_mode), item
                result.append(item)
    return sorted(result)


def publish(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw
    return pin(raw)


def main():
    started = time.monotonic_ns()
    attempt = HERE / 'attempt-r1'
    assert not attempt.exists()
    attempt.mkdir(mode=0o700)
    (attempt / 'chunks').mkdir(mode=0o700)
    logical, objects, snapshots, source_counts = [], {}, {}, {}

    def capture(path, logical_name):
        assert not PurePosixPath(logical_name).is_absolute()
        assert '..' not in PurePosixPath(logical_name).parts
        raw, before = read_exact(path)
        identity = pin(raw)
        key = identity['sha256']
        if key in objects:
            assert objects[key] == raw
        objects[key] = raw
        snapshots[str(path)] = {'stat': shape(before), 'pin': identity}
        logical.append({'path': logical_name, 'mode': stat.S_IMODE(before.st_mode),
                        'identity': identity, 'object': 'objects/' + key})

    for label, base, count in (('generation', GEN, 69), ('source10', SRC, 28)):
        paths = files_under(base, 'attempt-r1') + files_under(base, 'outer-execution-r1')
        assert len(paths) == count, (label, len(paths))
        source_counts[label] = {'files': len(paths), 'bytes': sum(x.stat().st_size for x in paths)}
        for path in sorted(paths):
            capture(path, label + '/' + path.relative_to(base).as_posix())
    generated = {
        'examples/hia_bootstrap/inspect_program.hepta': '0900041a821aac7d7c7250095fe130378f0356ba',
        'hepta/hia_inspect_program_ports.py': '98e75bf3ce731163778df851bc3a44f5a5741cec',
        'hepta/hia_inspect_program_data.py': '8b4bdd58f278780bcdaa95cb3e3f5902082bf641'}
    for name, blob in generated.items():
        path = GEN / 'attempt-r1/source' / name
        assert pin(read_exact(path)[0])['git_blob'] == blob
        capture(path, 'generated-source/' + name)
    capture(SRC / 'SOURCE10-R2-ACTUAL-READBACK.json', 'source10/SOURCE10-R2-ACTUAL-READBACK.json')
    logical.sort(key=lambda row: row['path'])
    assert len(logical) == len({row['path'] for row in logical}) == 101
    index = {'schema': 'hepta.hia.inspect-stages-lossless-cas.v1',
        'scope': 'complete generation and Source10 raw, excluding the reproducible complete source tree',
        'files': logical, 'logical_files': len(logical),
        'logical_bytes': sum(row['identity']['bytes'] for row in logical),
        'objects': len(objects), 'unique_bytes': sum(map(len, objects.values())),
        'original_directories_unchanged': True, 'source10_fixture_temporary_directory':
        'The original successful tempfile context removed its private fixture; no replacement fixture is reconstructed.',
        'whole_cli_native': False, 'matching_current_cold': False}
    index_raw = encoded(index)
    index_pin = publish(attempt / 'INDEX.json', index_raw)
    archive = attempt / 'RAW-CAS.tar.gz'
    expected = {'INDEX.json': index_raw, **{'objects/' + key: objects[key] for key in sorted(objects)}}
    with archive.open('xb') as target:
        with gzip.GzipFile(filename='', mode='wb', fileobj=target, mtime=0, compresslevel=1) as zipped:
            with tarfile.open(fileobj=zipped, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
                for name, raw in expected.items():
                    item = tarfile.TarInfo(name)
                    item.size = len(raw); item.mode = 0o644
                    item.uid = item.gid = item.mtime = 0
                    item.uname = item.gname = ''
                    tar.addfile(item, io.BytesIO(raw))
    seen = set()
    with gzip.open(archive, 'rb') as zipped:
        with tarfile.open(fileobj=zipped, mode='r|') as tar:
            for item in tar:
                assert item.isfile() and item.name in expected and item.name not in seen
                assert item.mode == 0o644 and item.uid == item.gid == item.mtime == 0
                assert tar.extractfile(item).read() == expected[item.name]
                seen.add(item.name)
        while zipped.read(1048576):
            pass
    assert seen == set(expected)
    for row in logical:
        assert pin(expected[row['object']]) == row['identity']
    for name, record in snapshots.items():
        raw, after = read_exact(Path(name))
        assert shape(after) == record['stat'] and pin(raw) == record['pin']
    archive_raw = archive.read_bytes()
    chunk_rows, rebuilt = [], bytearray()
    for offset in range(0, len(archive_raw), 196608):
        part = archive_raw[offset:offset+196608]
        name = 'chunks/part-%03d.json' % len(chunk_rows)
        transport = encoded({'schema': 'hepta.hia.lossless-archive-chunk.v1',
            'offset': offset, 'identity': pin(part), 'encoding': 'base64',
            'data': base64.b64encode(part).decode()})
        transport_pin = publish(attempt / name, transport)
        back = json.loads(transport)
        actual = base64.b64decode(back['data'], validate=True)
        assert pin(actual) == back['identity'] and len(rebuilt) == offset
        rebuilt.extend(actual)
        chunk_rows.append({'path': name, 'offset': offset, 'raw': pin(part), 'transport': transport_pin})
    assert bytes(rebuilt) == archive_raw
    manifest = {'schema': 'hepta.hia.inspect-stages-custody-manifest.v1',
        'status': 'COMPLETE_LOCAL_LOSSLESS_READBACK_PASS_GIT_PENDING',
        'archive': pin(archive_raw), 'index': index_pin, 'chunks': chunk_rows,
        'logical_files': len(logical), 'logical_bytes': index['logical_bytes'],
        'unique_objects': len(objects), 'unique_bytes': index['unique_bytes'],
        'tar_members': len(seen), 'complete_gzip_crc_read': True,
        'every_object_full_byte_equal': True, 'all_logical_mode_and_identity_mappings_checked': True,
        'all_original_raw_bytes_modes_stats_unchanged': True, 'no_restore_directory_materialized': True,
        'source_counts': source_counts, 'generated_sources': generated,
        'generation_status': 'GENERATION_ONLY_PASS', 'source10_status': 'SOURCE10_ONLY_PASS',
        'product_execution_during_custody': 0, 'product_source_edits': 0,
        'started_ns': started, 'finished_ns': time.monotonic_ns()}
    manifest_pin = publish(attempt / 'MANIFEST.json', encoded(manifest))
    print(json.dumps({'status': manifest['status'], 'manifest': manifest_pin,
        'archive': manifest['archive'], 'logical_files': len(logical),
        'logical_bytes': index['logical_bytes'], 'unique_objects': len(objects),
        'unique_bytes': index['unique_bytes'], 'chunks': len(chunk_rows),
        'elapsed_seconds': (manifest['finished_ns']-started)/1e9}, indent=2))


if __name__ == '__main__':
    main()
