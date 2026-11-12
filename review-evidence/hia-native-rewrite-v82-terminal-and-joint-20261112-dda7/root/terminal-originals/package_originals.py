"""Preserve complete actual 3.14 raw archives and the third recoverable source reclamation."""
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
    return (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'blob': sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}


def main():
    rows, objects, before, exclusions = {}, {}, {}, []

    def add(key, path):
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode):
            raise ValueError('ordinary original evidence required: '+str(path))
        data = path.read_bytes()
        row = identity(data)
        row.update(mode='100755' if mode & 0o111 else '100644', object='objects/'+row['sha256'])
        if key in rows:
            raise ValueError('duplicate logical evidence path')
        rows[key] = row
        objects.setdefault(row['object'], data)
        before[path] = row

    sources = {
        'artifacts-native314': ROOT/'v82-service-artifacts-development-r3/ci-r1/actual314-r1',
        'artifacts-source314': ROOT/'v82-service-artifacts-development-r3/ci-r1/actual-source314-r1',
        'reclamation-third': ROOT/'v82-inactive-root-base-reclamation-r3',
    }
    for prefix, directory in sources.items():
        for path in sorted(directory.rglob('*')):
            if not path.is_file() or '__pycache__' in path.parts:
                continue
            relative = path.relative_to(directory)
            if relative.parts[0] in ('source', 'raw'):
                continue
            if path.name == 'ORIGINAL-ARTIFACT.zip':
                exclusions.append({'path': prefix+'/'+relative.as_posix(),
                    'reason': 'Unique complete ZIP retained locally and in Actions; exact download identity and full CRC/byte/source review are included. Whole outer ZIP Git storage is not claimed.'})
                continue
            add(prefix+'/'+relative.as_posix(), path)
    # Save actual retained bytes for every unique source change that remains
    # after reclamation; recovery needs no unpublished scratch-only delta.
    retained_rows = []
    for revision in ('r3',):
        directory = ROOT/('v82-inactive-root-base-reclamation-'+revision)
        plan = json.loads((directory/'PLAN.json').read_bytes())
        for number, target in enumerate(plan['targets']):
            source = Path(target['source'])
            for name, expected in sorted(target['retained'].items()):
                path = source/name
                actual = identity(path.read_bytes())
                if any(actual[k] != expected[k] for k in actual):
                    raise ValueError('retained source delta differs: '+str(path))
                key = 'retained-inactive-source-deltas/'+revision+'/'+str(number)+'/'+name
                add(key, path)
                if rows[key]['mode'] != expected['mode']:
                    raise ValueError('retained source delta mode differs')
            retained_rows.append({'revision': revision, 'source': str(source),
                'original_tree': target['original_tree'],
                'original_file_count': target['original_file_count'],
                'retained_files': len(target['retained']),
                'archive_prefix': 'retained-inactive-source-deltas/'+revision+'/'+str(number)+'/',
                'base_commit': plan['base_git_commit'], 'base_tree': plan['base_git_tree']})
    for name in ('NATIVE314-ORIGINAL-JOB.log', 'SOURCE314-ORIGINAL-JOB.log', 'summarize_actual.py'):
        add('actual-job-originals/'+name, ROOT/'v82-service-artifacts-development-r3/ci-r1'/name)
    add('frozen-source/FINAL-SOURCE-MANIFEST.json', ROOT/'v82-service-artifacts-development-r3/FINAL-SOURCE-MANIFEST.json')
    add('author/package_originals.py', Path(__file__))
    contents = {'schema': 'hia.root-terminal-originals.contents.v82.r1',
        'members': rows, 'excluded_unique_outer_zips': exclusions,
        'retained_source_recovery': retained_rows,
        'old_source_bodies_preserved': True, 'old_failures_preserved': True,
        'qualification_transferred': False, 'whole_native': False, 'current_source_cold': False}
    raw_manifest = wire(contents)
    archive_path = HERE/'COMPLETE-ORIGINALS.tar.gz'
    with archive_path.open('xb') as stream:
        with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for name, data in [('CONTENTS.json', raw_manifest), *sorted(objects.items())]:
                    member = tarfile.TarInfo(name)
                    member.mode = 0o644
                    member.size = len(data)
                    member.mtime = 0
                    archive.addfile(member, io.BytesIO(data))
    verified = set()
    with tarfile.open(archive_path, 'r:gz') as archive:
        for member in archive:
            if not member.isfile() or member.name in verified or member.mode != 0o644:
                raise ValueError('archive shape differs')
            data = archive.extractfile(member).read()
            expected = raw_manifest if member.name == 'CONTENTS.json' else objects[member.name]
            if data != expected:
                raise ValueError('complete archive readback differs')
            verified.add(member.name)
    if verified != {'CONTENTS.json', *objects}:
        raise ValueError('complete archive inventory differs')
    for path, expected in before.items():
        if identity(path.read_bytes()) != {k: expected[k] for k in ('bytes','sha256','blob')}:
            raise ValueError('original changed during preservation: '+str(path))
    raw = archive_path.read_bytes()
    parts = []
    for number, start in enumerate(range(0, len(raw), 1048576)):
        fragment = raw[start:start+1048576]
        encoded = base64.b64encode(fragment)
        name = f'archive-{number:03d}.base64.part'
        (HERE/name).write_bytes(encoded)
        parts.append({'number': number, 'path': name, 'local_path': str(HERE/name),
            'raw_bytes': len(fragment), 'raw_sha256': sha256(fragment).hexdigest(), **identity(encoded), 'chars': len(encoded), 'mode': '100644'})
    if b''.join(base64.b64decode((HERE/row['path']).read_bytes(), validate=True) for row in parts) != raw:
        raise ValueError('full archive fragment reassembly differs')
    index = {'schema': 'hia.root-terminal-originals.index.v82.r1',
        'archive': identity(raw), 'manifest': identity(raw_manifest), 'parts': parts,
        'logical_files': len(rows), 'logical_bytes': sum(row['bytes'] for row in rows.values()),
        'unique_objects': len(objects), 'unique_bytes': sum(map(len, objects.values())),
        'full_archive_readback_equal': True, 'all_originals_unchanged': True,
        'retained_source_recovery': retained_rows, 'scope': contents,
        'whole_outer_zip_binary_git_preservation_claimed': False,
        'whole_native': False, 'current_source_cold': False}
    (HERE/'CONTENTS.json').write_bytes(raw_manifest)
    (HERE/'INDEX.json').write_bytes(wire(index))
    print(json.dumps({key: value for key, value in index.items()
        if key not in ('scope','parts','retained_source_recovery')}, sort_keys=True))


if __name__ == '__main__':
    main()
