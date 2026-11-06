"""Freeze terminal policy evidence, preserving original file bytes exactly."""
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import zipfile


BASE = Path('/workspace/scratch/22f6defbc03d')
STAGE = BASE / 'ndu-policy-evidence-stage'
DEST = STAGE / 'reports/hia-ndu-policy-closure-20261106'
PACKAGING = BASE / 'ndu-policy-packaging'
SOURCE_COMMIT = 'a07c5ecae52436234af370779cc440686dbe4139'
SOURCE_TREE = '273e7c458713ede9593c03267245a5bf756fc4f7'
CHUNK_BYTES = 524288
SELECTION = (
    'policy-final-v1',
    'policy-registration-final-v1.json.gz',
    'policy-final-v1.stdout.log',
    'policy-final-v1.stderr.log',
    'final-reference',
    'final-reference.log',
    'native-final',
    'combined-local-qualification.json',
    'source-object-import-receipt.json',
    'published-source-commits.json',
    'progress-preflight.json',
    'new-ci-audit',
)
SECRET = re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{35,}')


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def identity(data):
    return {'bytes': len(data), 'sha256': sha256(data),
            'git_blob_sha': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def checked_payload(data, path):
    if SECRET.search(data):
        raise ValueError('Potential credential in selected evidence; upload refused: ' + path)
    if data.startswith((b'\x7fELF', b'MZ\x90\x00', b'\xcf\xfa\xed\xfe')):
        raise ValueError('Executable excluded from evidence: ' + path)


def main():
    started = utc()
    if shutil.disk_usage(BASE).free < 1_200_000_000:
        raise RuntimeError('Insufficient free space for archive and independent restore')
    DEST.mkdir(parents=True, exist_ok=False)
    (DEST / 'raw').mkdir()
    PACKAGING.mkdir(exist_ok=False)
    selected = []
    for name in SELECTION:
        path = BASE / name
        if path.is_dir():
            selected.extend(p for p in path.rglob('*') if p.is_file())
        elif path.is_file():
            selected.append(path)
        else:
            raise FileNotFoundError(path)
    selected.sort(key=lambda p: p.relative_to(BASE).as_posix())
    names = [p.relative_to(BASE).as_posix() for p in selected]
    if len(set(names)) != len(names):
        raise ValueError('Duplicate selected path')
    if any(p.is_symlink() for p in selected):
        raise ValueError('Symlink input refused')
    if any(p.suffix in ('.rs', '.pem', '.key', '.env', '.so', '.dll', '.dylib') for p in selected):
        raise ValueError('Source, credential, or binary member excluded')
    members = []
    nested_zip_members = []
    gzip_members = 0
    for path, name in zip(selected, names):
        data = path.read_bytes()
        checked_payload(data, name)
        if path.suffix == '.gz':
            checked_payload(gzip.decompress(data), name + ' (expanded)')
            gzip_members += 1
        elif path.suffix == '.zip':
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for member in archive.infolist():
                    part = PurePosixPath(member.filename)
                    if member.is_dir() or part.is_absolute() or '..' in part.parts:
                        raise ValueError('Unsafe nested CI artifact member')
                    nested = archive.read(member)
                    checked_payload(nested, name + ':' + member.filename)
                    if part.suffix not in ('.json', '.jsonl', '.log'):
                        raise ValueError('Unexpected nested CI artifact type')
                    nested_zip_members.append({'path': member.filename, 'bytes': len(nested), 'sha256': sha256(nested)})
        members.append({'path': name, 'bytes': len(data), 'sha256': sha256(data)})
    archive_path = PACKAGING / 'policy-raw.tar.xz'
    print(json.dumps({'stage': 'input-frozen', 'members': len(members), 'bytes': sum(m['bytes'] for m in members),
                      'compression': 'xz preset 6', 'time_utc': utc()}), flush=True)
    with lzma.open(archive_path, 'xb', preset=6) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for path, record in zip(selected, members):
                data = path.read_bytes()
                if len(data) != record['bytes'] or sha256(data) != record['sha256']:
                    raise ValueError('Input changed after freeze: ' + record['path'])
                member = tarfile.TarInfo(record['path'])
                member.size = len(data)
                member.mode = 0o644
                member.uid = member.gid = member.mtime = 0
                member.uname = member.gname = ''
                archive.addfile(member, io.BytesIO(data))
    raw_archive = archive_path.read_bytes()
    manifest = {
        'schema': 'hepta.ndu.policy-terminal-archive.v1',
        'source_commit': SOURCE_COMMIT, 'source_tree': SOURCE_TREE,
        'archive': archive_path.name, 'archive_bytes': len(raw_archive),
        'archive_sha256': sha256(raw_archive), 'member_count': len(members),
        'member_bytes': sum(m['bytes'] for m in members), 'members': members,
        'original_member_bytes_changed': False,
        'tar_headers': 'normalized regular files, mode 0644, uid/gid/mtime zero; original file bytes unchanged',
        'authority': 'DENY_ALL',
    }
    write_json(DEST / 'policy-raw-manifest.json', manifest)
    parts = []
    for index, start in enumerate(range(0, len(raw_archive), CHUNK_BYTES)):
        path = DEST / 'raw' / f'policy-raw-{index:03d}.tar.xz.part'
        data = raw_archive[start:start + CHUNK_BYTES]
        path.write_bytes(data)
        parts.append({'file': path.name, **identity(data)})
    write_json(DEST / 'policy-raw-parts.json', parts)
    for path, record in zip(selected, members):
        data = path.read_bytes()
        if len(data) != record['bytes'] or sha256(data) != record['sha256']:
            raise ValueError('Original input changed during packaging: ' + record['path'])
    with tarfile.open(archive_path, 'r:xz') as archive:
        verified = []
        expected = {r['path']: r for r in members}
        for member in archive:
            if not member.isfile() or member.name not in expected or member.name in verified:
                raise ValueError('Unexpected or duplicate archive member')
            data = archive.extractfile(member).read()
            record = expected[member.name]
            if len(data) != record['bytes'] or sha256(data) != record['sha256']:
                raise ValueError('Archive member mismatch: ' + member.name)
            verified.append(member.name)
        if set(verified) != set(expected):
            raise ValueError('Archive members missing')
    registration_equal = gzip.decompress((BASE / 'policy-registration-final-v1.json.gz').read_bytes()) == gzip.decompress((BASE / 'policy-final-v1/REGISTRATION.json.gz').read_bytes())
    audit = {
        'schema': 'hepta.ndu.policy-archive-preflight.v1',
        'started_at_utc': started, 'completed_at_utc': utc(),
        'source_commit': SOURCE_COMMIT, 'source_tree': SOURCE_TREE,
        'selection': list(SELECTION), 'original_file_count': len(members),
        'original_file_bytes': manifest['member_bytes'],
        'archive_bytes': manifest['archive_bytes'], 'archive_sha256': manifest['archive_sha256'],
        'parts': len(parts), 'maximum_part_bytes': max(p['bytes'] for p in parts),
        'original_files_unchanged_before_and_after_packaging': True,
        'all_archive_member_hashes_verified': True,
        'gzip_payloads_checked': gzip_members, 'registration_expanded_bytes_equal': registration_equal,
        'nested_ci_zip_members': nested_zip_members,
        'archive_contains_full_source_repository_or_model_weights': False,
        'archive_contains_executables': False,
        'credential_pattern_matches': 0,
        'original_experiments_or_timings_rerun': False,
        'historical_archive_reuploaded': False,
        'authority': 'DENY_ALL',
    }
    write_json(DEST / 'ARCHIVE_AUDIT.json', audit)
    plan = []
    for path in sorted((DEST / 'raw').iterdir()):
        plan.append({'absolute_path': str(path), 'path': path.relative_to(STAGE).as_posix(), **identity(path.read_bytes())})
    write_json(BASE / 'ndu-policy-raw-upload-plan.json', plan)
    print(json.dumps({'stage': str(DEST), 'archive': str(archive_path),
                      'archive_bytes': len(raw_archive), 'members': len(members), 'parts': len(parts),
                      'manifest_bytes': (DEST / 'policy-raw-manifest.json').stat().st_size,
                      'sha256': manifest['archive_sha256']}), flush=True)


if __name__ == '__main__':
    main()
