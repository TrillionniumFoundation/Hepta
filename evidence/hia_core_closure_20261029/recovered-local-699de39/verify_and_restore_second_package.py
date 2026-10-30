from __future__ import annotations

from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import tarfile

BASE = Path(__file__).resolve().parent
PACKAGE = BASE / 'second-package'
ARCHIVE = PACKAGE / 'final-699de39-evidence.tar.gz'
EXPECTED_SHA = '5f460c4e1e2165b1752d4cc6c5143ef86d483459e7697043573a715ee66da0a2'
CONTROL_NAMES = {'MANIFEST.json', 'QUALIFICATION_STATUS.json', 'ALLOWLIST.json', 'EXTRA_ALLOWLIST.json', 'CREDENTIAL_SCAN.json'}

def identity(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def save(path, value):
    with path.open('x') as output:
        output.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')

def safe_name(name):
    path = PurePosixPath(name)
    assert not path.is_absolute() and '..' not in path.parts and '.' not in path.parts
    assert path.as_posix() == name.rstrip('/') and '\\' not in name and '\0' not in name

before = identity(ARCHIVE)
assert before['bytes'] == 16084731 and before['sha256'] == EXPECTED_SHA
seen = {}
controls = {}
payload_bytes = 0
with ARCHIVE.open('rb') as raw, gzip.GzipFile(fileobj=raw, mode='rb') as compressed:
    with tarfile.open(fileobj=compressed, mode='r|') as archive:
        for member in archive:
            safe_name(member.name)
            assert member.name not in seen
            assert member.uid == 0 and member.gid == 0 and member.mtime == 0
            assert not member.mode & ~0o777
            row = {'mode_octal': format(member.mode, '04o'), 'bytes': member.size}
            if member.isdir():
                assert member.name.startswith('payload/')
                row['kind'] = 'directory'
            else:
                assert member.isfile()
                row['kind'] = 'file'
                sha = hashlib.sha256()
                git = hashlib.sha1(b'blob ' + str(member.size).encode() + b'\0')
                total = 0
                collected = []
                with archive.extractfile(member) as data:
                    while chunk := data.read(1024 * 1024):
                        total += len(chunk)
                        sha.update(chunk)
                        git.update(chunk)
                        if member.name in CONTROL_NAMES:
                            collected.append(chunk)
                assert total == member.size
                row.update({'sha256': sha.hexdigest(), 'git_blob_sha1': git.hexdigest()})
                if member.name in CONTROL_NAMES:
                    controls[member.name] = b''.join(collected)
                else:
                    assert member.name.startswith('payload/')
                    payload_bytes += member.size
            seen[member.name] = row
        padding_count = 0
        while padding := archive.fileobj.read(1024 * 1024):
            padding_count += len(padding)
            assert not any(padding) and padding_count <= 16 * 1024 * 1024
    assert compressed.read() == b''

assert set(controls) == CONTROL_NAMES
manifest = json.loads(controls['MANIFEST.json'])
assert hashlib.sha256(controls['MANIFEST.json']).hexdigest() == '0fe533c7ca5dbc024e540894900712dbbd296fdb4e498fcbaf97fb00f8e29207'
assert manifest['source_commit'] == '699de39a8e92e0f083df316ecc5333fb3ecf8571'
assert manifest['source_tree'] == '592b6114f659fb18b13ad3fa5ed5e213ecdb92b5'
assert manifest['source_before'] == manifest['source_after'] and manifest['source_stable'] is True
assert len(manifest['files']) == manifest['file_count'] == 476
assert payload_bytes == manifest['total_file_bytes'] == 36992139
expected = set(CONTROL_NAMES)
for row in manifest['files']:
    name = row['archive_path']
    assert name == 'payload/' + row['path'] and name not in expected
    expected.add(name)
    actual = seen[name]
    assert actual['kind'] == 'file'
    assert all(actual[key] == row[key] for key in ('bytes', 'sha256', 'git_blob_sha1', 'mode_octal'))
for row in manifest['directories']:
    name = 'payload/' + row['path']
    assert name not in expected
    expected.add(name)
    assert seen[name]['kind'] == 'directory' and seen[name]['mode_octal'] == row['mode_octal']
assert set(seen) == expected and len(seen) == 509
assert json.loads(controls['QUALIFICATION_STATUS.json']) == manifest['completion_observations']
status = json.loads(controls['QUALIFICATION_STATUS.json'])
assert status['integrated']['actual_status'] == 'passed'
assert status['production_authority'] == 'Python' and status['optimization_policy'] == 'no_change'
assert status['whole_project_blockers_closed'] is False
assert len(status['unproved_claims']) == 8 and not any(status['unproved_claims'].values())
first = [row for row in manifest['files'] if row['path'].startswith('final-run-independent-review-699de39/')]
second = [row for row in manifest['files'] if row['path'].startswith('final-run-independent-review-699de39-attempt02/')]
assert len(first) == 0 and len(second) == 9

# Restore only after the complete path/type/mode/content inventory has passed.
# All writes remain inside this distinct recovery namespace, never the source checkout.
restored = PACKAGE / 'restored'
restored.mkdir(exist_ok=False)
with tarfile.open(ARCHIVE, 'r:gz') as archive:
    for member in archive:
        target = restored.joinpath(*PurePosixPath(member.name).parts)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open('xb') as output:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
            assert identity(target) == {key: seen[member.name][key] for key in ('bytes', 'sha256', 'git_blob_sha1')}
        os.chmod(target, member.mode)
assert identity(ARCHIVE) == before
summary = {'schema': 'hepta.recovered-second-archive-review.v1',
    'finished_utc': datetime.now(timezone.utc).isoformat(),
    'archive': before, 'archive_unchanged': True,
    'source_commit': manifest['source_commit'], 'source_tree': manifest['source_tree'],
    'original_payload_files': 476, 'original_payload_bytes': payload_bytes,
    'original_empty_files': sum(row['bytes'] == 0 for row in manifest['files']),
    'directory_members': len(manifest['directories']), 'generated_controls': len(CONTROL_NAMES),
    'tar_members': len(seen), 'all_member_paths_types_modes_lengths_sha256_git_blobs_match': True,
    'gzip_eof_and_crc_consumed': True,
    'independent_first_audit_files_in_this_archive': 0,
    'independent_second_audit_files_in_this_archive': 9,
    'first_audit_original_public_location': 'https://github.com/TrillionniumFoundation/Hepta/tree/2b13d233bf6070a8e2a5850b04c5e7361384fa41/evidence/hia_core_closure_20261029/first-attempt-699de39',
    'first_audit_retention_claim_corrected_by_this_receipt': True,
    'archive_relabelled_as_third_package': False,
    'restored_under': str(restored),
    'native_or_language_tests_executed': False,
    'recovered_existing_local_integrated_status': status['integrated']['actual_status'],
    'production_authority': 'Python', 'optimization_policy': 'no_change',
    'whole_project_blockers_closed': False}
save(BASE / 'second-package-readback.json', summary)
save(BASE / 'second-package-member-inventory.json', {'members': seen})
print(json.dumps(summary, ensure_ascii=False))
