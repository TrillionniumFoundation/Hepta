"""Preserve complete emitter-development originals and exact published source records."""
from __future__ import annotations
import base64
import gzip
from hashlib import sha1, sha256
import io
import json
from pathlib import Path
import stat
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(data):
    return {'bytes': len(data), 'sha256': sha256(data).hexdigest(),
            'blob': sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}


def main():
    rows, objects, originals = {}, {}, {}

    def add(name, path):
        mode = path.lstat().st_mode
        assert stat.S_ISREG(mode) and name not in rows, name
        data = path.read_bytes()
        row = identity(data)
        row.update(mode='100755' if mode & 0o111 else '100644', object='objects/' + row['sha256'])
        rows[name] = row
        objects.setdefault(row['object'], data)
        originals[path] = row

    roots = {
        'emitter-development': ROOT / 'v83-selfhost-emit-development-r1',
        'assembly-source-publication': ROOT / 'v84-assembly-scope-union-r1',
        'derived-archive-recovery': ROOT / 'v83-root-derived-archive-reclamation-r1',
        'inactive-base-recovery': ROOT / 'v83-inactive-base-reclamation-r2',
        'prior-audit-publication': ROOT / 'v83-joint-audit-publication-r1',
    }
    for prefix, directory in roots.items():
        for path in sorted(directory.rglob('*')):
            if not path.is_file() or '__pycache__' in path.parts:
                continue
            relative = path.relative_to(directory)
            if relative.parts[0] == 'source':
                continue
            add(prefix + '/' + relative.as_posix(), path)

    emitter = roots['emitter-development']
    candidate = json.loads((emitter / 'CANDIDATE.json').read_bytes())
    for name, delta in candidate['changed_paths'].items():
        path = emitter / 'source' / name
        assert identity(path.read_bytes()) == {k: delta['after'][k] for k in ('bytes', 'sha256', 'blob')}
        add('emitter-source-delta/' + name, path)
    union = roots['assembly-source-publication']
    release = json.loads((union / 'SOURCE-RELEASE.json').read_bytes())
    for name, delta in release['delta'].items():
        path = union / 'source' / name
        assert identity(path.read_bytes()) == {k: delta['after'][k] for k in ('bytes', 'sha256', 'blob')}
        add('assembly-source-delta/' + name, path)

    recovery = json.loads((roots['inactive-base-recovery'] / 'PLAN.json').read_bytes())
    retained = []
    for number, target in enumerate(recovery['targets']):
        source = Path(target['source'])
        for name, expected in sorted(target['retained'].items()):
            path = source / name
            assert identity(path.read_bytes()) == {k: expected[k] for k in ('bytes', 'sha256', 'blob')}
            key = 'retained-inactive-deltas/' + str(number) + '/' + name
            add(key, path)
            assert rows[key]['mode'] == expected['mode']
        retained.append({'source': str(source), 'retained_files': len(target['retained']),
                         'original_tree': target['original_tree'],
                         'archive_prefix': 'retained-inactive-deltas/' + str(number) + '/'})
    for name in ('package_originals.py', 'restore_originals.py', 'DECISION.json', 'README.md'):
        add('author/' + name, HERE / name)
    contents = {'schema': 'hia.root-emitter-originals.contents.v84.r1', 'members': rows,
        'source_reconstruction': [
            {'base_commit': candidate['base_commit'], 'base_tree': candidate['base_tree'],
             'candidate_tree': candidate['candidate_tree'],
             'manifest': 'emitter-development/CANDIDATE-SOURCE-MANIFEST.json',
             'replacement_prefix': 'emitter-source-delta/'},
            {'commit': release['commit'], 'tree': release['source_tree'],
             'manifest': 'assembly-source-publication/FINAL-SOURCE-MANIFEST.json'}],
        'retained_inactive_source_recovery': retained,
        'all_selected_original_files_retained': True, 'all_initial_driver_failures_retained': True,
        'git_source_reconstruction_requires_recorded_immutable_base': True,
        'emitter_candidate_adopted': False, 'qualification_transferred': False,
        'current_source_cold': False, 'whole_native': False, 'production_files_deleted': 0}
    manifest_raw = wire(contents)
    archive_path = HERE / 'COMPLETE-ORIGINALS.tar.gz'
    with archive_path.open('xb') as destination:
        with gzip.GzipFile(filename='', mode='wb', fileobj=destination, mtime=0, compresslevel=6) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for name, data in [('CONTENTS.json', manifest_raw), *sorted(objects.items())]:
                    member = tarfile.TarInfo(name)
                    member.mode = 0o644
                    member.mtime = 0
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
    visited = set()
    with tarfile.open(archive_path, mode='r:gz') as archive:
        for member in archive:
            assert member.isfile() and member.mode == 0o644 and member.name not in visited
            expected = manifest_raw if member.name == 'CONTENTS.json' else objects[member.name]
            assert archive.extractfile(member).read() == expected
            visited.add(member.name)
    assert visited == {'CONTENTS.json', *objects}
    for path, expected in originals.items():
        assert identity(path.read_bytes()) == {k: expected[k] for k in ('bytes', 'sha256', 'blob')}
        assert ('100755' if path.stat().st_mode & 0o111 else '100644') == expected['mode']
    raw = archive_path.read_bytes()
    parts = []
    decoded = bytearray()
    for number, start in enumerate(range(0, len(raw), 360000)):
        fragment = raw[start:start + 360000]
        encoded = base64.b64encode(fragment)
        parts.append({'number': number, 'path': f'archive-{number:03d}.base64.part',
                      'raw_offset': start, 'raw_bytes': len(fragment),
                      'raw_sha256': sha256(fragment).hexdigest(),
                      **identity(encoded), 'chars': len(encoded), 'mode': '100644'})
        decoded.extend(base64.b64decode(encoded, validate=True))
    assert decoded == raw
    index = {'schema': 'hia.root-emitter-originals.index.v84.r1', 'archive': identity(raw),
             'manifest': identity(manifest_raw), 'parts': parts, 'logical_files': len(rows),
             'logical_bytes': sum(row['bytes'] for row in rows.values()),
             'unique_objects': len(objects), 'unique_bytes': sum(map(len, objects.values())),
             'full_archive_readback_equal': True, 'all_original_bytes_and_modes_unchanged': True,
             'emitter_candidate_adopted': False, 'whole_native': False, 'current_source_cold': False}
    (HERE / 'CONTENTS.json').write_bytes(manifest_raw)
    (HERE / 'INDEX.json').write_bytes(wire(index))
    print(json.dumps({k: v for k, v in index.items() if k != 'parts'}, sort_keys=True))


if __name__ == '__main__':
    main()
