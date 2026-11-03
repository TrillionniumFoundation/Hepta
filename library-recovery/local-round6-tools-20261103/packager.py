#!/usr/bin/env python3
"""Assemble an explicit, newly recovered public evidence selection, without running project code."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path('/workspace/scratch/bf7d454bbc83')
BASE = ROOT / 'round6-recovered-ci-publication'
RECOVERY = ROOT / 'round6-recovery'
REPO = ROOT / 'hepta-round6-integration'
PREFIX = 'evidence/hia_round6_ci_recovered_20261029'
DEST = BASE / PREFIX
SOURCE = '9fa9e957a9ebc7b34b4018fd4b83d863ebbc717b'
TREE = 'debee7040ed2ffac2cbaf953c28c1e2ca3fc8407'
PART_SIZE = 6 * 1024 * 1024
HOST_IDS = {12895024720, 12895059622, 12895154469, 12895373880, 12895769232,
            12895828761, 12895828804, 12895848132, 12895953380, 12896132805,
            12896501561, 12896610720, 12896725048, 12896875120, 12897305216}
ZIP_PATHS = {'host/artifacts/' + str(i) + '/original.zip' for i in HOST_IDS}
ZIP_PATHS.add('integrated/artifact-12898192961.zip')

def digest(data):
    return hashlib.sha256(data).hexdigest()

def safe_name(name):
    p = PurePosixPath(name)
    if (not isinstance(name, str) or not name or p.is_absolute() or '..' in p.parts
            or '\\' in name or ':' in p.parts[0] or p.as_posix() != name):
        raise ValueError('unsafe relative path: ' + str(name))
    if set(p.parts) & {'private-quarantine', 'private-transfer', '.git'}:
        raise ValueError('private/non-evidence path: ' + name)
    return p

def write_json(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(value, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write('\n')

def git(*args):
    p = subprocess.run(['git', '-C', str(REPO), *args], capture_output=True, check=True)
    return p.stdout

def source_state():
    return {'head': git('rev-parse', 'HEAD').decode().strip(),
            'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
            'status': git('status', '--porcelain=v1').decode(),
            'tracked_tree_sha256': digest(git('ls-tree', '-r', '-z', '--full-tree', SOURCE))}

def zip_inventory(name, data):
    members, seen, folded = [], set(), set()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            member = info.filename
            safe_name(member)
            mode = info.external_attr >> 16
            if (info.is_dir() or stat.S_IFMT(mode) != stat.S_IFREG or mode & 0o7000
                    or info.flag_bits & 1 or member in seen or member.casefold() in folded):
                raise ValueError('nonregular, unsafe or duplicate ZIP member: ' + member)
            if info.file_size > 64 * 1024 * 1024:
                raise ValueError('member exceeds explicit reviewed size budget')
            h, size = hashlib.sha256(), 0
            with z.open(info) as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    size += len(chunk)
                    h.update(chunk)
            if size != info.file_size:
                raise ValueError('member size differs: ' + member)
            seen.add(member); folded.add(member.casefold())
            members.append({'path': member, 'bytes': size, 'sha256': h.hexdigest(),
                            'mode': stat.S_IMODE(mode)})
    artifact_id = '12898192961' if name.startswith('integrated/') else PurePosixPath(name).parts[2]
    return {'archive': name, 'destination': 'expanded-ci/' + artifact_id,
            'member_count': len(members), 'bytes': sum(m['bytes'] for m in members),
            'members': members}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection-sha256', required=True)
    args = parser.parse_args()
    raw_selection = (BASE / 'INPUT_SELECTION.json').read_bytes()
    if digest(raw_selection) != args.selection_sha256:
        raise ValueError('input selection hash differs')
    selection = json.loads(raw_selection)
    if selection['source_commit'] != SOURCE or selection['source_tree'] != TREE:
        raise ValueError('wrong source selection')
    before = source_state()
    if before['head'] != SOURCE or before['tree'] != TREE or before['status']:
        raise ValueError('source worktree must remain clean at exact public source')
    rows = selection['files']
    if len(rows) != selection['file_count'] or sum(r['bytes'] for r in rows) != selection['bytes']:
        raise ValueError('selection totals differ')
    payloads, index_rows, expansions, seen = {}, [], [], set()
    for row in sorted(rows, key=lambda row: row['archive_relative']):
        name = safe_name(row['archive_relative']).as_posix()
        component = row['component']
        relative = safe_name(row['component_relative']).as_posix()
        if component not in {'metadata', 'host', 'integrated', 'verified'} or name != component + '/' + relative:
            raise ValueError('component mapping differs')
        if name in seen:
            raise ValueError('duplicate selected file')
        seen.add(name)
        root = RECOVERY / component
        p = root / relative
        if not p.is_file() or p.is_symlink() or not p.resolve().is_relative_to(root.resolve()):
            raise ValueError('nonregular/out-of-component evidence file: ' + name)
        data = p.read_bytes()
        if len(data) != row['bytes'] or digest(data) != row['sha256']:
            raise ValueError('frozen input bytes differ: ' + name)
        # The very same verified bytes feed all indexes, ZIP inspection and TAR.
        payloads[name] = data
        index_rows.append({'path': name, 'bytes': len(data), 'sha256': digest(data), 'mode': 0o644})
        if name.endswith('.zip'):
            if name not in ZIP_PATHS:
                raise ValueError('unapproved original ZIP: ' + name)
            expansions.append(zip_inventory(name, data))
    if {name for name in seen if name.endswith('.zip')} != ZIP_PATHS:
        raise ValueError('the sixteen approved original ZIPs must be present')
    if len(expansions) != 16 or sum(x['member_count'] for x in expansions) != 5087:
        raise ValueError('reviewed original ZIP inventory differs')
    # Published selection has no filesystem-control instructions beyond the
    # original relative mapping and hashes. It is separately provenance-bound.
    public_selection = {**selection, 'input_selection_sha256': args.selection_sha256,
                        'old_complete_package_restored': False}
    write_json(DEST / 'RECOVERY-SELECTION.json', public_selection)
    index = {'schema': 'hepta.hia-round6-ci-recovered.raw-index.v1',
             'source_commit': SOURCE, 'source_tree': TREE,
             'file_count': len(index_rows), 'bytes': sum(r['bytes'] for r in index_rows),
             'files': index_rows, 'zip_expansions': expansions,
             'source_snapshot': before,
             'scope': 'New explicit assembly of recovered original bytes plus newly labelled recovery observations and reviews. The former unpublished 397-file package was lost and is not reconstructed.',
             'original_file_bytes_modified': False, 'private_original_verified_zip_included': False,
             'project_code_executed': False}
    write_json(DEST / 'RAW-INDEX.json', index)
    work = BASE / 'work'; work.mkdir(exist_ok=True)
    archive_path = work / 'recovered-raw-evidence.tar.xz'
    with archive_path.open('xb') as raw:
        with lzma.LZMAFile(raw, 'wb', format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for row in index_rows:
                    data = payloads[row['path']]
                    member = tarfile.TarInfo(row['path']); member.size = len(data)
                    member.mode = 0o644; member.mtime = 0; member.uid = member.gid = 0
                    member.uname = member.gname = ''
                    archive.addfile(member, io.BytesIO(data))
    parts = []; part_dir = DEST / 'parts'; part_dir.mkdir(exist_ok=False)
    joined, total = hashlib.sha256(), 0
    with archive_path.open('rb') as stream:
        part_number = 0
        while True:
            data = stream.read(PART_SIZE)
            if not data:
                break
            part_number += 1
            name = 'parts/raw-evidence.tar.xz.part' + str(part_number).zfill(3)
            with (DEST / name).open('xb') as f:
                f.write(data)
            parts.append({'path': name, 'bytes': len(data), 'sha256': digest(data)})
            joined.update(data); total += len(data)
    index_raw = (DEST / 'RAW-INDEX.json').read_bytes()
    archive_record = {'schema': 'hepta.hia-round6-ci-recovered.archive.v1',
                      'source_commit': SOURCE, 'source_tree': TREE,
                      'archive_format': 'tar.xz', 'part_size_limit': PART_SIZE,
                      'parts': parts, 'bytes': total, 'sha256': joined.hexdigest(),
                      'file_count': index['file_count'], 'uncompressed_file_bytes': index['bytes'],
                      'index': {'path': 'RAW-INDEX.json', 'bytes': len(index_raw), 'sha256': digest(index_raw)},
                      'original_public_ci_zip_count': 16, 'original_public_ci_member_count': 5087,
                      'newly_assembled_recovery': True, 'old_397_file_package_restored': False,
                      'private_original_verified_zip_included': False}
    write_json(DEST / 'ARCHIVE.json', archive_record)
    verify_argv = [sys.executable, str(DEST / 'RESTORE.py'), '--verify-only']
    verified = subprocess.run(verify_argv, capture_output=True)
    with (BASE / 'VERIFY_ONLY.stdout.log').open('xb') as f:
        f.write(verified.stdout)
    with (BASE / 'VERIFY_ONLY.stderr.log').open('xb') as f:
        f.write(verified.stderr)
    if verified.returncode != 0:
        raise RuntimeError('RESTORE --verify-only failed; original output retained')
    result = json.loads(verified.stdout)
    if not result['all_passed'] or result['source_commit'] != SOURCE or result['archive_sha256'] != archive_record['sha256']:
        raise ValueError('verification result does not bind this archive')
    with (DEST / 'VERIFY_ONLY.json').open('xb') as f:
        f.write(verified.stdout)
    after = source_state()
    if after != before:
        raise ValueError('source identity changed during evidence assembly')
    verification = {'schema': 'hepta.hia-round6-ci-recovered.assembly-verification.v1',
                    'created_at': datetime.now(timezone.utc).isoformat(),
                    'source_before': before, 'source_after': after,
                    'source_unchanged': True, 'archive_sha256': archive_record['sha256'],
                    'selection_sha256': args.selection_sha256,
                    'verify_command': verify_argv, 'returncode': verified.returncode,
                    'stdout_sha256': digest(verified.stdout), 'stderr_sha256': digest(verified.stderr),
                    'stderr_bytes': len(verified.stderr),
                    'same_first_verified_payload_bytes_used': True,
                    'restorer_expanded_ci_files': result['ci_expanded_files'],
                    'inner_zip_members_independently_read_during_packaging': 5087,
                    'project_tests_or_archived_programs_executed': False,
                    'remote_writes': False, 'old_complete_package_restored': False}
    write_json(DEST / 'ASSEMBLY-VERIFICATION.json', verification)
    print(json.dumps({'parts': len(parts), 'archive_bytes': total,
                      'archive_sha256': archive_record['sha256'], 'raw_files': index['file_count'],
                      'raw_bytes': index['bytes'], 'verify_only': result, 'source_unchanged': True}))

if __name__ == '__main__':
    main()
