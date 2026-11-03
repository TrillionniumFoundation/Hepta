#!/usr/bin/env python3
"""Compute Git blob/tree identities and a public backup without writing Git objects or refs."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path('/workspace/scratch/bf7d454bbc83')
BASE = ROOT / 'round6-recovered-ci-publication'
REPO = ROOT / 'hepta-round6-integration'
PREFIX = 'evidence/hia_round6_ci_recovered_20261029'
OUT = BASE / PREFIX
SOURCE = '9fa9e957a9ebc7b34b4018fd4b83d863ebbc717b'
TREE = 'debee7040ed2ffac2cbaf953c28c1e2ca3fc8407'
BRANCH = 'codex/evidence-hia-round6-ci-recovered-20261029'

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def git_object(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def write(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as f:
        json.dump(value, f, indent=2, sort_keys=True); f.write('\n')

def git(*args):
    return subprocess.run(['git', '-C', str(REPO), *args], check=True, capture_output=True).stdout

def main():
    assert git('rev-parse', 'HEAD').decode().strip() == SOURCE
    assert git('rev-parse', 'HEAD^{tree}').decode().strip() == TREE
    assert git('status', '--porcelain=v1') == b''
    source_flat_raw = git('ls-tree', '-r', '-z', '--full-tree', SOURCE)
    raw = git('ls-tree', '-r', '-t', '-z', '--full-tree', SOURCE)
    nodes = {'': {'entries': {}, 'original_sha': TREE}}
    original_files = {}
    for row in raw.split(b'\0'):
        if not row:
            continue
        header, name_raw = row.split(b'\t', 1)
        mode, kind, digest = header.decode('ascii').split(' ')
        name = name_raw.decode('utf-8')
        parent, _, leaf = name.rpartition('/')
        assert parent in nodes
        entry = {'mode': mode, 'type': kind, 'sha': digest, 'path': leaf}
        nodes[parent]['entries'][leaf] = entry
        if kind == 'tree':
            nodes[name] = {'entries': {}, 'original_sha': digest}
        else:
            original_files[name] = {'mode': mode, 'type': kind, 'sha': digest}
    assert len(original_files) == 6410
    original_tree_hashes = {path: node['original_sha'] for path, node in nodes.items()}

    def compute(path, verify_original=False):
        node = nodes[path]
        ordered = sorted(node['entries'].values(), key=lambda e: (e['path'] + ('/' if e['type'] == 'tree' else '')).encode())
        content = bytearray()
        for entry in ordered:
            if entry['type'] == 'tree':
                child = path + '/' + entry['path'] if path else entry['path']
                entry['sha'] = compute(child, verify_original)
            content.extend(format(int(entry['mode'], 8), 'o').encode() + b' ' + entry['path'].encode() + b'\0' + bytes.fromhex(entry['sha']))
        digest = git_object('tree', bytes(content))
        if verify_original:
            assert digest == original_tree_hashes[path], path
        node['computed_sha'] = digest
        node['serialized_bytes'] = len(content)
        node['ordered_entries'] = [dict(e) for e in ordered]
        return digest

    assert compute('', True) == TREE
    archive = json.loads((OUT / 'ARCHIVE.json').read_bytes())
    names = ['.gitattributes', 'RESTORE.py', 'READER-PROVENANCE.json', 'RECOVERY-SELECTION.json',
             'RAW-INDEX.json', 'ARCHIVE.json', 'VERIFY_ONLY.json', 'ASSEMBLY-VERIFICATION.json',
             'PACKAGE-SUMMARY.json', 'README.md'] + [row['path'] for row in archive['parts']]
    assert len(names) == len(set(names)) == 21
    assert {p.relative_to(OUT).as_posix() for p in OUT.rglob('*') if p.is_file()} == set(names)
    blobs = []
    payloads = {}
    for relative in sorted(names):
        p = OUT / relative
        assert p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(OUT.resolve())
        data = p.read_bytes(); payloads[relative] = data
        if relative == '.gitattributes':
            assert data == b'* -text\n'
        name = PREFIX + '/' + relative
        assert name not in original_files
        parent, _, leaf = name.rpartition('/')
        current = ''
        for part in parent.split('/'):
            new = current + '/' + part if current else part
            if new not in nodes:
                assert part not in nodes[current]['entries']
                nodes[new] = {'entries': {}, 'original_sha': None}
                nodes[current]['entries'][part] = {'mode': '040000', 'type': 'tree', 'path': part, 'sha': ''}
            current = new
        assert leaf not in nodes[parent]['entries']
        blob_sha = git_object('blob', data)
        nodes[parent]['entries'][leaf] = {'mode': '100644', 'type': 'blob', 'path': leaf, 'sha': blob_sha}
        blobs.append({'path': name, 'relative': relative, 'local_path': str(p), 'bytes': len(data),
                      'sha256': sha256(data), 'git_blob_sha1': blob_sha, 'mode': '100644', 'type': 'blob',
                      'encoding': 'base64' if relative.startswith('parts/') else 'utf-8'})
    final_tree = compute('')
    final_files = {}
    for path, node in nodes.items():
        for entry in node['entries'].values():
            if entry['type'] != 'tree':
                name = path + '/' + entry['path'] if path else entry['path']
                final_files[name] = {k: entry[k] for k in ('mode', 'type', 'sha')}
    assert all(final_files[path] == expected for path, expected in original_files.items())
    assert set(final_files) - set(original_files) == {row['path'] for row in blobs}
    assert len(final_files) == 6431
    changed = []
    for path, node in nodes.items():
        if node['computed_sha'] != original_tree_hashes.get(path):
            changed.append({'path': path, 'expected_tree_sha1': node['computed_sha'],
                            'base_tree_sha1': original_tree_hashes.get(path),
                            'serialized_tree_bytes': node['serialized_bytes'],
                            'entries': node['ordered_entries']})
    changed.sort(key=lambda x: -(len(x['path'].split('/')) if x['path'] else 0))
    assert {row['path'] for row in changed} == {'', 'evidence', PREFIX, PREFIX + '/parts'}
    assert git('ls-tree', '-r', '-z', '--full-tree', SOURCE) == source_flat_raw
    assert git('status', '--porcelain=v1') == b''
    frozen = {'schema': 'hepta.hia-round6-ci-recovered.publication-freeze.v1',
              'created_at': datetime.now(timezone.utc).isoformat(), 'source_commit': SOURCE,
              'source_tree': TREE, 'prefix': PREFIX, 'public_file_count': len(blobs),
              'public_bytes': sum(row['bytes'] for row in blobs), 'files': blobs,
              'source_paths_preserved': 6410, 'source_modes_and_git_blobs_unchanged': True,
              'source_ls_tree_sha256': sha256(source_flat_raw),
              'new_expected_root_tree_sha1': final_tree,
              'further_public_file_mutation_allowed': False,
              'old_397_file_package_restored': False}
    write(BASE / 'PACKAGE-FREEZE.json', frozen)
    plan = {'schema': 'hepta.hia-round6-ci-recovered.git-upload-plan.v1', 'repository': 'TrillionniumFoundation/Hepta',
            'branch': BRANCH, 'base_commit': SOURCE, 'base_tree': TREE, 'prefix': PREFIX,
            'sole_parent': SOURCE, 'commit_parents': [SOURCE],
            'commit_message': 'Archive newly recovered round-six CI evidence for 9fa9e957',
            'expected_root_tree_sha1': final_tree, 'source_paths_preserved': 6410,
            'final_file_paths': 6431, 'source_modes_and_blobs_unchanged': True,
            'blobs': blobs, 'blob_count': len(blobs), 'trees_bottom_up': changed,
            'tree_count': len(changed), 'git_objects_or_refs_written': False,
            'remote_operations_performed': False,
            'publication_order': ['Upload/verify all 21 blobs against planned Git SHA-1 and SHA-256.',
                                  'Create the four trees bottom-up and require the planned SHA-1 each time.',
                                  'Create a commit with exactly the sole source parent and expected root tree.',
                                  'Root may publish the explicitly named evidence branch and read it back.'],
            'public_directory': str(OUT)}
    write(BASE / 'UPLOAD-PLAN.json', plan)
    write(BASE / 'TREE-SHAS.json', {'schema': 'hepta.hia-round6-ci-recovered.tree-identities.v1',
                                  'source_tree': TREE, 'new_root_tree': final_tree,
                                  'trees': [{k: row[k] for k in ('path', 'expected_tree_sha1', 'base_tree_sha1')} for row in changed]})
    backup = Path('/tmp/hepta-round6-recovered-publication-20261029.tar')
    with tarfile.open(backup, mode='x', format=tarfile.PAX_FORMAT) as tar:
        for relative in sorted(names):
            import io
            data = payloads[relative]
            member = tarfile.TarInfo(PREFIX + '/' + relative)
            member.size = len(data); member.mode = 0o644; member.mtime = 0
            member.uid = member.gid = 0; member.uname = member.gname = ''
            tar.addfile(member, io.BytesIO(data))
    with backup.open('rb') as f:
        backup_sha = hashlib.file_digest(f, 'sha256').hexdigest()
    handoff = {'schema': 'hepta.hia-round6-ci-recovered.packaging-handoff.v1',
               'source_commit': SOURCE, 'source_tree': TREE, 'branch': BRANCH,
               'prefix': PREFIX, 'sole_parent': SOURCE, 'public_files': len(blobs),
               'public_bytes': frozen['public_bytes'], 'raw_files': archive['file_count'],
               'raw_bytes': archive['uncompressed_file_bytes'], 'archive_bytes': archive['bytes'],
               'archive_sha256': archive['sha256'], 'parts': len(archive['parts']),
               'expected_root_tree': final_tree, 'source_paths_preserved': 6410,
               'verify_only_passed': True, 'project_code_executed': False,
               'git_writes_performed': False,
               'temporary_publication_backup': {'path': str(backup), 'bytes': backup.stat().st_size,
                                                'sha256': backup_sha,
                                                'scope': 'Only the 21 public publication files, outside the public raw archive; no additional tests or evidence denominator.'},
               'records': []}
    for name in ('PACKAGE-FREEZE.json', 'UPLOAD-PLAN.json', 'TREE-SHAS.json'):
        data = (BASE / name).read_bytes()
        handoff['records'].append({'path': name, 'bytes': len(data), 'sha256': sha256(data)})
    write(BASE / 'HANDOFF.json', handoff)
    print(json.dumps(handoff))

if __name__ == '__main__':
    main()
