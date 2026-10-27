"""Verify retained bytes without extracting archives or re-executing evidence.

This validates the local bundle inventory, not the truth of a hostile
producer's execution claims or the correctness of the entire compiler.
"""
from pathlib import Path
import hashlib
import json
import tarfile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fail(condition, message):
    if not condition:
        raise ValueError(message)


def verify(root):
    manifest = json.loads((root / 'MANIFEST.json').read_text())
    fail(manifest['schema'] == 'hepta.seven-stage.bundle.v1', 'unknown manifest')
    for name, identity in manifest['files'].items():
        relative = Path(name)
        fail(not relative.is_absolute() and '..' not in relative.parts, 'unsafe member path')
        path = root / relative
        fail(path.is_file() and not path.is_symlink(), 'missing regular evidence: ' + name)
        fail(path.stat().st_size == identity['bytes'] and digest(path) == identity['sha256'],
             'evidence bytes differ: ' + name)
    count = 0
    for name in manifest['archive_manifests']:
        data = json.loads((root / name).read_text())
        archive = root / data['archive']
        fail(archive.name == data['archive'] and archive.is_file(), 'unsafe archive path')
        fail(digest(archive) == data['sha256'] and archive.stat().st_size == data['bytes'],
             'archive identity differs')
        actual = []
        with tarfile.open(archive, 'r:xz') as stream:
            for member in stream:
                relative = Path(member.name)
                fail(not relative.is_absolute() and '..' not in relative.parts, 'unsafe archive entry')
                if member.isfile():
                    with stream.extractfile(member) as payload:
                        sha = hashlib.file_digest(payload, 'sha256').hexdigest()
                    actual.append({'name': member.name, 'kind': 'file', 'bytes': member.size, 'sha256': sha})
                elif member.issym():
                    actual.append({'name': member.name, 'kind': 'symlink', 'target': member.linkname})
                else:
                    raise ValueError('unexpected archive member type')
        fail(actual == data['members'], 'archive payload inventory differs')
        count += len(actual)
    qualification = json.loads((root / 'qualification.json').read_text())
    fail(qualification['git_commit'] == manifest['tested_source_commit'], 'tested commit differs')
    fail(qualification['source_snapshot_before'] == qualification['source_snapshot_after'], 'source drift')
    fail(qualification['unchanged_source'] is True, 'source identity failed')
    print(json.dumps({'ok': True, 'files': len(manifest['files']), 'archived_members': count,
                      'tested_source_commit': manifest['tested_source_commit'],
                      'qualified_all_gates': qualification['ok'],
                      'scope': 'retained byte identity; not a new execution or universal correctness proof'}))


if __name__ == '__main__':
    verify(Path(__file__).resolve().parent)
