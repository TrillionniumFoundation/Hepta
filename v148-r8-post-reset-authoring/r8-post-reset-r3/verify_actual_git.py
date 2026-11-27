"""Read the actual full-GET author transport; never import the project."""
from pathlib import Path
import base64
import gzip
import hashlib
import io
import json
import stat
import tarfile
import time

ROOT = Path(__file__).resolve().parent
GET = ROOT / 'actual-get'
STAT_KEYS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def inverse(value, changes):
    value = json.loads(json.dumps(value))
    for row in reversed(changes):
        target = value
        for key in row['path'][:-1]:
            target = target[key]
        key = row['path'][-1]
        if row['operation'] == 'add':
            assert target[key] == row['after']
            del target[key]
        elif row['operation'] == 'remove':
            assert key not in target
            target[key] = row['before']
        else:
            assert target[key] == row['after']
            target[key] = row['before']
    return value


def main():
    start = time.monotonic_ns()
    index_raw = (GET / 'INDEX.json').read_bytes()
    manifest_raw = (GET / 'MANIFEST.json').read_bytes()
    assert pin(index_raw)['git_blob'] == '6e2b10ed71acd8a236be1480deb0e01f8f9e9c72'
    assert pin(manifest_raw)['git_blob'] == '57bba71e85f81a37b8171ed2b91728eda3c5791b'
    index, manifest = json.loads(index_raw), json.loads(manifest_raw)
    assert pin(manifest_raw) == index['manifest']
    archive, wrappers = bytearray(), []
    for ordinal, row in enumerate(index['parts']):
        wire = (GET / row['name']).read_bytes()
        assert pin(wire) == row['wrapper']
        part = json.loads(wire)
        assert part['archive'] == index['archive'] and part['part'] == ordinal
        assert part['offset'] == row['offset'] == len(archive)
        raw = base64.b64decode(part['base64'], validate=True)
        assert pin(raw) == row['payload'] == part['payload']
        archive.extend(raw)
        wrappers.append({'name': row['name'], 'identity': pin(wire)})
    assert len(wrappers) == index['count'] == 15
    archive = bytes(archive)
    assert pin(archive) == index['archive']
    seen_files, seen_dirs, bodies = set(), set(), {}
    with gzip.GzipFile(fileobj=io.BytesIO(archive), mode='rb') as stream:
        with tarfile.open(fileobj=stream, mode='r|') as tar:
            for member in tar:
                assert member.uid == member.gid == member.mtime == 0
                if member.name == 'MANIFEST.json':
                    assert tar.extractfile(member).read() == manifest_raw
                elif member.isdir():
                    assert member.name in manifest['directories'] and member.name not in seen_dirs
                    assert member.mode == manifest['directories'][member.name]['mode']
                    path = Path(manifest['directories'][member.name]['origin'])
                    assert stat.S_ISDIR(path.lstat().st_mode)
                    assert stat.S_IMODE(path.lstat().st_mode) == member.mode
                    seen_dirs.add(member.name)
                else:
                    assert member.isfile() and member.name not in seen_files and member.name in manifest['files']
                    row = manifest['files'][member.name]
                    raw = tar.extractfile(member).read()
                    assert pin(raw) == row['identity'] and member.mode == row['mode']
                    path = Path(row['origin'])
                    before = path.lstat()
                    assert stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == row['mode']
                    assert [getattr(before, key) for key in STAT_KEYS] == row['new_seven_stats']
                    assert path.read_bytes() == raw
                    assert [getattr(path.lstat(), key) for key in STAT_KEYS] == row['new_seven_stats']
                    seen_files.add(member.name)
                    bodies[member.name] = raw
        while stream.read(1 << 20):
            pass
    assert seen_files == set(manifest['files']) and seen_dirs == set(manifest['directories'])
    assert len(seen_files) == index['file_count'] == 162
    assert sum(len(raw) for raw in bodies.values()) == manifest['logical_bytes'] == 16292926
    source_proof = json.loads(bodies['r3/R3-SOURCE-PROJECTION.json'])
    for row in source_proof['seven_scripts']:
        after = bodies['r3/' + row['path']]
        for change in reversed(row['replacements']):
            assert after.count(change['after'].encode()) == change['count']
            after = after.replace(change['after'].encode(), change['before'].encode())
        assert after == bodies['before-r2/' + row['path']]
    for name, inverse_name in [('EXECUTION-PLAN.json', 'R3-PLAN-INVERSE.json'),
                               ('ORACLE-RESTORE-PLAN.json', 'R3-ORACLE-INVERSE.json')]:
        proof = json.loads(bodies['r3/' + inverse_name])
        back = inverse(json.loads(bodies['r3/' + name]), proof['changes'])
        assert encoded(back) == bodies['before-r2/' + name]
    for name in ('run_controls.py', 'r8_common.py', 'restore_oracles.py', 'r8_private_reference.py'):
        assert bodies['r3/' + name] == bodies['before-r2/' + name]
    for name, row in manifest['files'].items():
        assert [getattr(Path(row['origin']).lstat(), key) for key in STAT_KEYS] == row['new_seven_stats']
    report = {'schema': 'hepta.r8.post-reset.r3-actual-Git-readback.v1',
              'status': 'PASS_FULL_GET_DECODE_AND_ORIGINAL_AUTHOR_INVERSES',
              'index': pin(index_raw), 'manifest': pin(manifest_raw), 'archive': pin(archive),
              'actual_full_GET_parts': wrappers, 'parts': 15, 'files': len(seen_files),
              'directories': len(seen_dirs), 'logical_bytes': manifest['logical_bytes'],
              'every_member_complete_bytes_SHA_Git_mode': True,
              'every_current_origin_bytes_mode_new_seven_stats_equal': True,
              'whole_seven_script_inverse_equal': True, 'whole_two_plan_inverse_equal': True,
              'four_common_files_complete_bytes_equal': True, 'full_gzip_CRC': True,
              'binder': 0, 'products': 0, 'source_or_input_payload_copies': 0,
              'restored_binary_executions': 0, 'old_stats_inherited': False,
              'elapsed_ns': time.monotonic_ns() - start}
    (ROOT / 'ACTUAL-GIT-READBACK.json').write_bytes(encoded(report))
    print(json.dumps({'status': report['status'], 'files': report['files'],
                      'parts': 15, 'logical_bytes': report['logical_bytes'],
                      'report': pin(encoded(report))}, sort_keys=True))


if __name__ == '__main__':
    main()
