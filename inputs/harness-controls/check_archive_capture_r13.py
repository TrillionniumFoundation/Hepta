"""Check actual archive bytes/modes and refusal paths; perform no Git or product execution."""
from __future__ import annotations

import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'archive-r13-controls-r1'
ENTRY = ROOT.parent / 'v89-union-r7-r2/registration-controls-r1/evidence/raw/hia-linux-stdio-source/installed/bin/hia'


def load(path, name, expected):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.oid('blob', path.read_bytes()) == expected
    return module


def main():
    old = load(ROOT / 'harness/tools/materialize_candidate_r12.py', 'original_r12_archive',
               'b02abdfd989cb0e20d6780739350233cdc69339e')
    new = load(ROOT / 'harness-r13/tools/materialize_candidate_r13.py', 'reviewed_r13_archive',
               'c3d1d71fb12d88723bcc3392b9f7091da387e472')
    OUT.mkdir(exist_ok=False)
    records = []
    payload = ENTRY.read_bytes()
    assert stat.S_IMODE(ENTRY.lstat().st_mode) == 0o755
    original_read = Path.read_bytes
    result = {'status': 'ARCHIVE_CONTROL_ONLY', 'product_tests_executed': 0,
              'native_execution_count': 0, 'whole_native': False}

    def prepare(module, label):
        capture = module.Capture(OUT / label, '')
        capture.basic = ''
        capture.raw.chmod(0o700)
        (capture.raw / 'installed').mkdir(mode=0o700)
        (capture.raw / 'installed/bin').mkdir(mode=0o755)
        (capture.raw / 'empty-private-directory').mkdir(mode=0o711)
        for name, data, mode in [('plain.bin', b'plain\x00bytes', 0o644),
                                 ('private.bin', b'private', 0o600),
                                 ('readonly.bin', b'readonly', 0o444),
                                 ('installed/bin/hia', payload, 0o755)]:
            path = capture.raw / name
            path.write_bytes(data)
            path.chmod(mode)
        uploads = []
        def local_transport(data):
            uploads.append(data)
            return {'blob': module.oid('blob', data), 'bytes': len(data),
                    'sha256': module.sha(data), 'full_readback_equal': True,
                    'control_transport_substituted': True, 'actual_Git_operation': False}
        capture.upload_blob = local_transport
        return capture, uploads

    def inspect(capture):
        compressed = (capture.evidence / 'FROZEN-SOURCE-EVIDENCE.tar.gz').read_bytes()
        manifest = json.loads((capture.evidence / 'EVIDENCE-MANIFEST.json').read_bytes())
        seen_files, seen_dirs = {}, {}
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(compressed)), mode='r:') as archive:
            for member in archive:
                assert member.uid == member.gid == member.mtime == 0
                if member.isdir():
                    seen_dirs[member.name.rstrip('/')] = member.mode
                else:
                    assert member.isfile()
                    seen_files[member.name] = (member.mode, archive.extractfile(member).read())
        return compressed, manifest, seen_files, seen_dirs

    old_capture, old_uploads = prepare(old, 'original-r12-counterexample')
    old.persist_evidence(old_capture, result)
    _, old_manifest, old_files, old_dirs = inspect(old_capture)
    mismatches = []
    for name, (mode, data) in old_files.items():
        actual = old_capture.raw / name
        assert data == actual.read_bytes()
        actual_mode = stat.S_IMODE(actual.lstat().st_mode)
        if mode != actual_mode:
            mismatches.append({'path': name, 'actual_mode': actual_mode, 'archive_mode': mode})
    assert {r['path'] for r in mismatches} == {'private.bin', 'readonly.bin', 'installed/bin/hia'}
    assert old_dirs == {} and 'directories' not in old_manifest
    records.append({'case': 'original-r12-mode-loss-reproduced', 'status': 'OBSERVED_ORIGINAL_MODE_LOSS',
                    'mismatches': mismatches, 'product_tests_executed': 0})

    archives = []
    for label in ('r13-roundtrip', 'r13-repeat'):
        capture, uploads = prepare(new, label)
        new.persist_evidence(capture, result)
        compressed, manifest, files, directories = inspect(capture)
        assert manifest['schema'] == 'hepta.combined-source-build-evidence.v2'
        assert manifest['root_mode'] == stat.S_IMODE(capture.raw.lstat().st_mode) == 0o700
        expected_files = {p.relative_to(capture.raw).as_posix():
                          (stat.S_IMODE(p.lstat().st_mode), p.read_bytes())
                          for p in capture.raw.rglob('*') if p.is_file()}
        expected_dirs = {p.relative_to(capture.raw).as_posix(): stat.S_IMODE(p.lstat().st_mode)
                         for p in capture.raw.rglob('*') if p.is_dir()}
        assert files == expected_files and directories == expected_dirs
        assert {r['path']: r['mode'] for r in manifest['directories']} == directories
        assert {r['path']: r['mode'] for r in manifest['members']} == {k: v[0] for k, v in files.items()}
        for row in manifest['members']:
            raw = files[row['path']][1]
            assert row['bytes'] == len(raw) and row['sha256'] == new.sha(raw)
            assert row['blob'] == new.oid('blob', raw)
        assert b''.join(uploads[:-1]) == compressed
        assert json.loads(uploads[-1]) == manifest
        restored = capture.root / 'restored'
        restored.mkdir()
        for name in directories:
            (restored / name).mkdir(parents=True, exist_ok=True)
        for name, (mode, raw) in files.items():
            target = restored / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(mode)
        for name, mode in sorted(directories.items(), key=lambda r: -len(r[0])):
            (restored / name).chmod(mode)
        restored.chmod(manifest['root_mode'])
        assert all((restored / name).read_bytes() == data and
                   stat.S_IMODE((restored / name).lstat().st_mode) == mode
                   for name, (mode, data) in files.items())
        assert all(stat.S_IMODE((restored / name).lstat().st_mode) == mode
                   for name, mode in directories.items())
        archives.append(compressed)
        records.append({'case': label, 'status': 'CONTROL_PASS', 'files': len(files),
                        'directories': len(directories), 'archive_sha256': new.sha(compressed),
                        'actual_installed_entry_mode': files['installed/bin/hia'][0],
                        'all_restored_bytes_and_permission_bits_equal': True})
    assert archives[0] == archives[1]

    for label in ('file-symlink', 'dangling-symlink', 'directory-symlink', 'fifo',
                  'mode-mutates-during-read', 'path-added-during-read'):
        capture, uploads = prepare(new, label)
        link = capture.raw / 'unreviewed'
        if label == 'file-symlink':
            link.symlink_to(capture.raw / 'plain.bin')
        elif label == 'dangling-symlink':
            link.symlink_to(capture.root / 'does-not-exist')
        elif label == 'directory-symlink':
            link.symlink_to(capture.raw / 'installed', target_is_directory=True)
        elif label == 'fifo':
            os.mkfifo(link)
        changed = []
        target = capture.raw / 'plain.bin'
        def read_with_change(path):
            data = original_read(path)
            if path == target and not changed and label.endswith('during-read'):
                changed.append(True)
                if label == 'mode-mutates-during-read':
                    path.chmod(0o600)
                else:
                    link.write_bytes(b'new path not in the original snapshot')
            return data
        error = None
        with patch.object(Path, 'read_bytes', read_with_change):
            try:
                new.persist_evidence(capture, result)
            except RuntimeError as caught:
                error = str(caught)
        assert error is not None and 'evidence' in error
        assert not uploads and not (capture.evidence / 'FROZEN-SOURCE-EVIDENCE.tar.gz').exists()
        records.append({'case': label, 'status': 'CONTROL_PASS', 'refusal': error,
                        'refused_before_archive_or_transport_publication': True})
    report = {'schema': 'hia.archive-capture-r13-controls.v1', 'status': 'ARCHIVE_CONTROLS_PASS',
        'cases': records, 'case_count': len(records), 'identical_input_deterministic_archive': True,
        'actual_Git_operations': 0, 'transport_substituted_only_in_this_control': True,
        'product_source_tests_executed': 0, 'native_executions': 0, 'cold_qualifications': 0,
        'old_mode_loss_retained_as_original_observation': True, 'whole_native': False}
    (OUT / 'RESULT.json').write_bytes(new.canonical(report))
    print(json.dumps({k: v for k, v in report.items() if k != 'cases'}, sort_keys=True))


if __name__ == '__main__':
    main()
