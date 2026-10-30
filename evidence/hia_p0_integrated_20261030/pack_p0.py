#!/usr/bin/env python3
"""Package completed evidence without changing source or executing payloads."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import time

BASE = Path('/workspace/scratch/f0c12f106c89')
OUT = Path(__file__).resolve().parent
REPO = BASE / 'hepta-integration'
HEAD = '50c4067399989e7194028576c38c0e783b78cf06'
MEMBERS = {}
LINKS = []


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def add(path, role, name=None):
    path = Path(path)
    if path.is_symlink():
        LINKS.append({'path': str(path), 'link_target': os.readlink(path), 'role': role})
        return
    if path.is_dir():
        for child in sorted(path.iterdir()):
            add(child, role)
        return
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('refuse special input: ' + str(path))
    name = name or 'workspace/' + path.relative_to(BASE).as_posix()
    if name in MEMBERS:
        return
    MEMBERS[name] = {'name': name, 'bytes': info.st_size, 'sha256': sha(path),
                     'mode': stat.S_IMODE(info.st_mode), 'original_path': str(path), 'role': role}


def main():
    start = time.monotonic_ns()
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO, text=True).strip()
    assert head == HEAD and not status
    runs = ['integrated-final-20261030', 'integrated-run02-20261030',
            'integrated-run03-20261030', 'integrated-run04-20261030']
    for name in runs + ['integrated-safety-50c40673', 'p0-ci-dependencies-20261030',
                         'p0-qemu-board-20261030', 'p2-independent-review',
                         'p7-independent-review', 'p7-v11-development', 'p3-development',
                         'p3-integrated-50c4067-launches']:
        add(BASE / name, 'original evidence; preserve outcomes and every retained failure')
    for name in ['run-integrated-final.sh', 'run-integrated-run02.sh', 'run-integrated-run03.sh',
                 'run-integrated-run04.sh', 'run-safety-matrix.py', 'monitor-integrated.py',
                 'snapshot-ci-deps.py', 'snapshot-qemu-board-deps.py',
                 'integrated-final-20261030.log', 'integrated-run02-20261030.log',
                 'integrated-run03-20261030.log', 'integrated-run04-20261030.log',
                 'p0-focused-tests.log', 'p0-native-configured-tests.log', 'p0-native-merged-tests.log',
                 'p0-final-matrix-protocol.log', 'p0-tool-pin-review-20261030.json',
                 'p0-evidence-archive-draft-20261030.json', 'p3-evidence-replay-root.log',
                 'install_hepta_rust.py', 'lean-bootstrap.log', 'qemu-bootstrap.log',
                 'local-reproducible-cache-cleanup.json', 'ndu-ranking-build.log',
                 'ndu-recursive-build.log', 'ndu-finite-build.log', 'ndu-stream-build.log']:
        add(BASE / name, 'launch, setup, development, review, or historical planning record')
    for relative in ['docs/HIA_SAFETY_CONTRACT.json', 'docs/HIA_SAFETY_CONTRACT.md',
                     'tools/qualify_hia_integrated.py', 'tools/qualify_hia_safety_contract.py',
                     'toolchain-lock.json', 'hepta/hia_schema.py',
                     'examples/boards/mps2_an386/board.json']:
        add(REPO / relative, 'selected frozen-source bytes; the complete repository is identified by commit')
    ci = json.loads((BASE / 'p0-ci-dependencies-20261030/SUMMARY.json').read_text())
    for row in ci['packages']:
        path = Path(row['archive']['path'])
        assert sha(path) == row['archive']['sha256']
        add(path, 'official authenticated package archive')
    qemu = json.loads((BASE / 'p0-qemu-board-20261030/package-input-inventory.json').read_text())
    for row in qemu['files']:
        if row['path'].endswith('.deb'):
            path = Path(row['path'])
            assert sha(path) == row['sha256']
            add(path, 'official authenticated package archive')
    profiles = []
    for profile in ('ranking', 'recursive', 'finite', 'stream'):
        rel = f'ndu-builds/{profile}/' + ('build-receipt.json' if profile == 'ranking' else 'identity.json')
        path = BASE / rel
        receipt = json.loads(path.read_text())
        add(path, 'actual bridge build/source identity receipt')
        binary = Path(receipt['binary'])
        assert sha(binary) == receipt['binary_sha256']
        add(binary, 'actual native bridge bytes; archived, never executed by the verifier')
        sets = []
        keys = ('original_source_files', 'build_inputs') if profile == 'ranking' else ('native_sources', 'bridge_sources')
        for key in keys:
            prefix = f'ndu-builds/{profile}/' if key == 'build_inputs' else f'ndu-upstreams/{profile}/'
            for relative, expected in receipt[key].items():
                source = BASE / prefix / relative
                assert sha(source) == expected
                add(source, 'exact receipt-bound bridge source bytes')
            sets.append({'receipt_key': key, 'member_prefix': 'workspace/' + prefix})
        profiles.append({'profile': profile, 'receipt': 'workspace/' + rel,
                         'binary': 'workspace/' + binary.relative_to(BASE).as_posix(), 'source_sets': sets})
    # P3 native payloads are archived separately by their producer. Keep small
    # actual reports/launch receipts here, not another copy of its large trees.
    p3_reports = ['p3-integrated-50c4067-musl125/qualification.json',
                  'p3-integrated-50c4067-maintenance126/update.json',
                  'p3-integrated-50c4067-maintenance126/successor/qualification.json',
                  'p3-integrated-50c4067-cpp-upgrade/report.json']
    for relative in p3_reports:
        add(BASE / relative, 'P3 report reference only; its complete payload is a separate archive')
    for path in sorted((BASE / 'p3-integrated-50c4067-launches').glob('*-attempt-*/launch.json')):
        record = json.loads(path.read_text())
        assert record['status'] == 'completed' and record['inputs_before']['head'] == record['inputs_after']['head'] == HEAD
    partial = json.loads((BASE / 'integrated-safety-50c40673/OUTER_CAPTURE_PARTIAL.json').read_text())
    assert partial['outer_diagnostic_stream_complete'] is False
    add(OUT / 'README.md', 'archive scope and verification instructions', 'README.md')
    add(Path(__file__), 'packaging provenance; not executed by offline verification', 'pack_p0.py')
    add(OUT / 'verify_evidence.py', 'verifier source snapshot; use the external trusted copy', 'verify_evidence.py')
    core = []
    for name in runs:
        core += ['workspace/' + name + '/' + filename for filename in
                 ('qualification.json', 'full_regression-execution.json')]
    core += ['workspace/' + runs[i] + '/intentional-interruption.json' for i in (0, 1)]
    core += ['workspace/integrated-safety-50c40673/' + f for f in
             ('qualification.json', 'MATRIX_LAUNCH.json', 'OUTER_CAPTURE_PARTIAL.json', 'EXTERNALS_AFTER_MATRIX.json')]
    for directory in ('p0-ci-dependencies-20261030', 'p0-qemu-board-20261030'):
        core += ['workspace/' + directory + '/' + f for f in ('run04-before.json', 'run04-after.json', 'matrix-after.json')]
    core += [row['receipt'] for row in profiles]
    manifest = {'schema': 'hepta.offline-evidence-manifest.v1', 'bundle_kind': 'p0',
                'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'frozen_source_head': HEAD, 'members': [MEMBERS[k] for k in sorted(MEMBERS)],
                'member_count': len(MEMBERS), 'total_member_bytes': sum(x['bytes'] for x in MEMBERS.values()),
                'core_json_members': core, 'bridge_profiles': profiles, 'observed_symlinks_not_followed': LINKS,
                'matrix_outer_diagnostic_capture_complete': False,
                'matrix_canonical_report_and_unittest_log_complete': True,
                'matrix_outer_original_token_count': 143944, 'matrix_outer_requested_budget_reported_by_parent': 8000,
                'matrix_outer_missing_bytes_reconstructed': False,
                'complete_environment_closure_proved': False,
                'source_archive_scope': 'selected frozen bytes and receipt-bound bridge sources; not the full source repository or toolchain',
                'p3_payload_scope': 'small reports and frozen launches only; original native payload belongs to the separate P3 package',
                'archive_format': 'ustar regular files in xz; uid/gid/mtime normalized; original file modes retained'}
    manifest_path = OUT / 'p0-evidence-20261030.manifest.json'
    archive = OUT / 'p0-evidence-20261030.tar.xz'
    with manifest_path.open('x') as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True); stream.write('\n')
    print(json.dumps({'phase': 'manifest_ready', 'members': len(MEMBERS),
                      'raw_bytes': manifest['total_member_bytes'], 'manifest_sha256': sha(manifest_path)}), flush=True)
    with archive.open('xb') as compressed:
        with tarfile.open(fileobj=compressed, mode='w:xz', format=tarfile.USTAR_FORMAT, preset=6) as tf:
            for name in sorted(MEMBERS):
                row = MEMBERS[name]
                info = tarfile.TarInfo(name); info.size = row['bytes']; info.mode = row['mode']
                info.uid = info.gid = info.mtime = 0
                with Path(row['original_path']).open('rb') as source:
                    tf.addfile(info, source)
    for row in MEMBERS.values():
        assert sha(row['original_path']) == row['sha256'], 'source bytes changed while packing'
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip() == HEAD
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO, text=True).strip()
    receipt = {'schema': 'hepta.local.p0-evidence-pack.v1', 'archive': str(archive),
               'archive_sha256': sha(archive), 'archive_bytes': archive.stat().st_size,
               'manifest': str(manifest_path), 'manifest_sha256': sha(manifest_path),
               'members': len(MEMBERS), 'raw_bytes': manifest['total_member_bytes'],
               'all_source_files_unchanged': True, 'source_head': HEAD, 'source_status': '',
               'raw_staging_copies_created': 0, 'staging_hardlinks_created': 0,
               'wall_ns': time.monotonic_ns() - start}
    with (OUT / 'p0-evidence-20261030.pack.json').open('x') as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True); stream.write('\n')
    print(json.dumps(receipt, indent=2), flush=True)


if __name__ == '__main__':
    main()
