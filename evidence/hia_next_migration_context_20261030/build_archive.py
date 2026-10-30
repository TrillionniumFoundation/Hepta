#!/usr/bin/env python3
"""Package existing immutable records. No qualification or target execution."""
from __future__ import annotations
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import time

ROOT = Path('/workspace/scratch/f0c12f106c89')
REPO = ROOT / 'hepta-integration'
HERE = Path(__file__).resolve().parent
LAUNCH = ROOT / 'p3-p6-integrated-launches-20261030'
HEAD = '44e34b7a9ecd6bf1b3ad6093d21bba10d2a18304'
TREE = '835555fb35dbdcf867724ef7a0bb1a6616270217'
MAX_MEMBER = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def wire(value):
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'


def read(path):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_MEMBER, 'nonregular/oversized input: ' + str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(MAX_MEMBER + 1)
        ended = os.fstat(stream.fileno())
    after = path.lstat()
    signature = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(signature(before) == signature(opened) == signature(ended) == signature(after)
            and len(data) == before.st_size, 'input changed during read: ' + str(path))
    return data, stat.S_IMODE(before.st_mode)


def git(*args, input=None):
    return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=REPO, input=input)


def safe(name):
    require(type(name) is str and 0 < len(name) < 512 and '\\' not in name and ':' not in name
            and all(part not in ('', '.', '..') for part in name.split('/'))
            and all(ord(c) >= 32 for c in name), 'unsafe archive name')


def main():
    started = time.monotonic_ns()
    attempt = {'status': 'started', 'source_head': HEAD, 'new_native_executions': 0,
               'new_model_executions': 0, 'source_modified': False}
    (HERE / 'PACKAGE_BUILD.json').write_bytes(wire(attempt))
    try:
        require(git('rev-parse', 'HEAD').decode().strip() == HEAD
                and git('rev-parse', 'HEAD^{tree}').decode().strip() == TREE
                and not git('status', '--porcelain', '--untracked-files=all'), 'frozen clean source required')
        prepared = json.loads((HERE / 'MANIFEST.draft.json').read_bytes())
        members = {}
        for name, row in prepared['current_members'].items():
            members[name] = {'path': Path(row['source_path']), 'expected': row}
        histories = []
        for directory in prepared['historical_directories_to_preserve']:
            folder = Path(directory['path'])
            paths = sorted(folder.rglob('*'))
            count = size = 0
            for path in paths:
                require(not path.is_symlink(), 'historical symlink cannot be packaged')
                if path.is_dir():
                    continue
                require(path.is_file(), 'historical special file cannot be packaged')
                name = 'historical/' + folder.name + '/' + str(path.relative_to(folder))
                members[name] = {'path': path}
                count += 1
                size += path.stat().st_size
            require(count == directory['regular_files_observed'] and size == directory['logical_bytes_observed'],
                    'historical directory denominator changed')
            histories.append({'prefix': 'historical/' + folder.name, 'members': count, 'bytes': size})
        for name in ('SUMMARY.json', 'MANIFEST.json', 'DELIVERY.json'):
            path = ROOT / 'p3-integrated-50c4067-evidence' / name
            members['historical-cpp-package-reference/' + name] = {'path': path}

        current = json.loads((LAUNCH / 'run/source-before.json').read_bytes())
        q = json.loads((LAUNCH / 'run/p3/qualification/qualification.json').read_bytes())
        original = json.loads((ROOT / 'p3-stb-exact-ffe4a127/qualification/qualification.json').read_bytes())
        source_paths = set(q['source_before']['files']) | {
            name for name in current['files'] if name.startswith(('hepta/', 'tools/'))}
        source_paths.update(json.loads((LAUNCH / 'PLAN.json').read_bytes())['focused_source_sha256'])
        source_paths.update(('docs/HIA_STB_DIVIDE_CHANGED_BODY_UPDATE.md', 'docs/HIA_FINITE_NATIVE_CONTEXT.md'))
        context_paths = ['hepta/hia_finite_context.py', 'tests/test_hia_finite_context.py',
                         'tests/test_hia_finite_context_oracle_reuse.py']
        binding_paths = ['tools/qualify_hia_stb_divide_update.py', 'tests/test_hia_stb_divide_update.py',
                         'tests/fixtures/c_migration/stb_divide_vm_readback.json']
        specifications = [
            ('current-44e34b7a', HEAD, sorted(source_paths), current['files']),
            ('original-p3-ffe4a127', original['source_before']['head'], sorted(original['source_before']['files']),
             {name: value['sha256'] for name, value in original['source_before']['files'].items()}),
            ('context-before-73922c1', git('rev-parse', '73922c1').decode().strip(), context_paths, None),
            ('context-fix-eeb41d7d', 'eeb41d7d13a77933f9ed198946c0f4a0c044285e',
             context_paths + ['tests/test_hia_finite_context_reentrancy.py'], None),
            ('readback-fix-0f2bc05b', '0f2bc05b85e514a43efbc73b4005405e7d78e7b3', binding_paths, None),
            ('owner-mode-96459326', '964593261439c564b54707eee4cb9c70514ccc8e', binding_paths, None),
        ]
        snapshots, object_kinds, blob_ids = {}, {}, set()
        for label, commit, selected, expected in specifications:
            tree = git('rev-parse', commit + '^{tree}').decode().strip()
            entries = {}
            for record in git('ls-tree', '-r', '-t', '-z', commit).split(b'\0'):
                if record:
                    attributes, path = record.split(b'\t', 1)
                    mode, kind, oid = attributes.decode().split()
                    entries[path.decode()] = (mode, kind, oid)
            object_kinds[commit] = 'commit'
            object_kinds[tree] = 'tree'
            recorded = {}
            for name in selected:
                safe(name)
                mode, kind, blob = entries[name]
                require(kind == 'blob' and mode in ('100644', '100755'), 'nonregular source object')
                blob_ids.add(blob)
                recorded[name] = {'mode': mode, 'git_blob': blob,
                                  'archive_member': 'source/' + label + '/files/' + name}
                parent = Path(name).parent
                while str(parent) != '.':
                    mode2, kind2, oid = entries[str(parent)]
                    require(kind2 == 'tree', 'source ancestor is not a Git tree')
                    object_kinds[oid] = 'tree'
                    parent = parent.parent
            snapshots[label] = {'head': commit, 'tree': tree, 'files': recorded}
        identifiers = sorted(set(object_kinds) | blob_ids)
        batch = git('cat-file', '--batch', input=('\n'.join(identifiers) + '\n').encode())
        objects = {}
        offset = 0
        for oid in identifiers:
            end = batch.index(b'\n', offset)
            got, kind, length = batch[offset:end].decode().split()
            length = int(length); offset = end + 1
            payload = batch[offset:offset + length]; offset += length
            require(got == oid and len(payload) == length and batch[offset:offset + 1] == b'\n'
                    and length <= MAX_MEMBER
                    and hashlib.sha1(kind.encode() + b' ' + str(length).encode() + b'\0' + payload).hexdigest() == oid,
                    'raw Git object mismatch')
            offset += 1
            objects[oid] = (kind, payload)
        require(offset == len(batch), 'unexpected Git object suffix')
        for label, commit, selected, expected in specifications:
            for name, entry in snapshots[label]['files'].items():
                kind, payload = objects[entry['git_blob']]
                require(kind == 'blob', 'source is not blob')
                if expected is not None:
                    require(sha(payload) == expected[name], 'source bytes differ from retained execution ledger')
                if label == 'current-44e34b7a':
                    current_bytes, mode = read(REPO / name)
                    require(current_bytes == payload and bool(mode & stat.S_IXUSR) == (entry['mode'] == '100755'),
                            'current worktree bytes/mode differ from Git')
                members[entry['archive_member']] = {'bytes_data': payload,
                    'mode': 0o755 if entry['mode'] == '100755' else 0o644}
        object_manifest = {}
        for oid, kind in object_kinds.items():
            actual_kind, payload = objects[oid]
            require(actual_kind == kind, 'raw commit/tree object kind differs')
            name = 'source/git/' + oid + '.raw'
            members[name] = {'bytes_data': payload, 'mode': 0o644}
            object_manifest[oid] = {'type': kind, 'archive_member': name}

        archive = HERE / 'executions.tar.xz'
        rows = []
        with lzma.open(archive, 'xb', preset=6) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                for name, origin in sorted(members.items()):
                    safe(name)
                    if 'path' in origin:
                        data, mode = read(origin['path'])
                    else:
                        data, mode = origin['bytes_data'], origin['mode']
                    identity = {'bytes': len(data), 'sha256': sha(data)}
                    if 'expected' in origin:
                        require(all(identity[key] == origin['expected'][key] for key in identity),
                                'retained current file changed')
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.uid, info.gid, info.mtime = len(data), mode, 0, 0, 0
                    tar.addfile(info, io.BytesIO(data))
                    rows.append({'path': name, **identity, 'mode': mode})
        archive_identity = {'bytes': archive.stat().st_size, 'sha256': sha(archive.read_bytes())}
        summary = json.loads((HERE / 'SUMMARY.json').read_bytes())
        summary['package_status'] = 'archive created; completed verification receipt is supplied separately'
        summary['archive'] = archive_identity
        summary['archive_members'] = len(rows)
        summary['archive_payload_bytes'] = sum(row['bytes'] for row in rows)
        summary['historical_directory_payloads'] = histories
        summary['preserved_source_snapshots'] = {label: {'head': value['head'], 'tree': value['tree'], 'files': len(value['files'])}
                                                  for label, value in snapshots.items()}
        summary_bytes = wire(summary)
        (HERE / 'SUMMARY.json').write_bytes(summary_bytes)
        manifest = {'schema': 'hepta.hia.p3-p6.evidence-archive.v1', 'source_head': HEAD, 'source_tree': TREE,
                    'archive': archive_identity, 'member_count': len(rows),
                    'payload_bytes': sum(row['bytes'] for row in rows), 'members': rows,
                    'source_snapshots': snapshots, 'raw_git_objects': object_manifest,
                    'historical_directories': histories, 'summary': {'bytes': len(summary_bytes), 'sha256': sha(summary_bytes)},
                    'new_target_execution': False, 'raw_staging_copies_created': False,
                    'scope': 'retained bytes, raw Git object bindings and finite observations; no toolchain or whole-language proof'}
        (HERE / 'MANIFEST.json').write_bytes(wire(manifest))
        require(git('rev-parse', 'HEAD').decode().strip() == HEAD and not git('status', '--porcelain', '--untracked-files=all'),
                'source moved during packaging')
        attempt.update(status='completed', archive=archive_identity, member_count=len(rows), payload_bytes=manifest['payload_bytes'],
                       source_snapshots=summary['preserved_source_snapshots'])
    except BaseException as error:
        attempt.update(status='failed', error={'type': type(error).__name__, 'message': str(error)})
        raise
    finally:
        attempt['wall_ns_before_receipt_encoding'] = time.monotonic_ns() - started
        (HERE / 'PACKAGE_BUILD.json').write_bytes(wire(attempt))
        print(json.dumps(attempt, sort_keys=True))


if __name__ == '__main__':
    main()
