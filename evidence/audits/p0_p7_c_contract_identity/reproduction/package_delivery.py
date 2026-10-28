#!/usr/bin/python3
"""Project exact completed evidence; preserve the first failed byte check."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile

PREP = Path('/tmp/hepta-c-contract-identity-publication-20261028')
STAGE = Path('/tmp/hepta-c-contract-delivery-staging-20261028')
REL = Path('evidence/audits/p0_p7_c_contract_identity')
BASE = Path('/tmp/hepta-c-contract-binding-audit-20261028')
DEV = Path('/tmp/hepta-c-contract-identity-fix-20261028/development-01')
TARGET = Path('/tmp/hepta-c-contract-targeted-e8c5da27-20261028')
TARGET_LAUNCH = Path(str(TARGET) + '-launch')
REPLAY = Path('/tmp/hepta-c-contract-replay-e8c5da27-20261028')
REPLAY_LAUNCH = Path(str(REPLAY) + '-launch')
PATH_REVIEW = Path('/tmp/hepta-c-contract-emission-review-e8c5da27-20261028')
PATH_INDEPENDENT = Path('/tmp/hepta-c-contract-rust-path-review-e8c5da27-20261028')
STATIC = Path('/tmp/hepta-c-contract-independent-review-20261028')
P6 = Path('/tmp/hepta-p6-incremental-bounded-audit-1739484b-20261028')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def read(path):
    return json.loads(path.read_text())


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as f:
        json.dump(data, f, sort_keys=True, indent=2)
        f.write('\n')


def pack(name, roots, destination):
    members, omitted, contents = [], [], []
    for prefix, root in roots:
        for path in sorted(root.rglob('*')):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            require(stat.S_ISREG(info.st_mode), 'Nonordinary archive input: ' + str(path))
            rel = Path(prefix) / path.relative_to(root)
            require(not rel.is_absolute() and '..' not in rel.parts, 'Unsafe member name')
            data = path.read_bytes()
            row = {'member': str(rel), 'original_path': str(path), 'bytes': len(data), 'sha256': sha(data)}
            if data.startswith(b'\x7fELF'):
                omitted.append(dict(row, reason='native binary explicitly identified; not included in text projection'))
                continue
            try:
                data.decode('utf-8')
            except UnicodeDecodeError:
                raise RuntimeError('Unclassified binary artifact: ' + str(path))
            members.append(row)
            contents.append((str(rel), data))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for member, data in contents:
            item = tarfile.TarInfo(member)
            item.size, item.mode, item.mtime, item.uid, item.gid = len(data), 0o644, 0, 0, 0
            tar.addfile(item, io.BytesIO(data))
    archive = gzip.compress(raw.getvalue(), mtime=0)
    out = destination / 'archives' / (name + '.tar.gz')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(archive)
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        actual = tar.getmembers()
        require(len(actual) == len(members), 'Roundtrip member count mismatch')
        for member, row in zip(actual, members):
            data = tar.extractfile(member).read()
            require(member.isfile() and member.name == row['member'] and len(data) == row['bytes']
                    and sha(data) == row['sha256'], 'Roundtrip member mismatch')
    manifest = {'schema': 'hepta.c-contract-identity.text-archive.v1', 'archive': out.name,
                'archive_bytes': len(archive), 'archive_sha256': sha(archive),
                'members': members, 'omitted_binaries': omitted,
                'receipts_rewritten': False, 'members_roundtrip_verified': True}
    write(out.with_name(name + '.manifest.json'), manifest)
    return {'name': name, 'bytes': len(archive), 'sha256': sha(archive), 'members': len(members), 'omitted': len(omitted)}


def main():
    target, target_launch = read(TARGET / 'report.json'), read(TARGET_LAUNCH / 'execution.json')
    replay, replay_launch = read(REPLAY / 'report.json'), read(REPLAY_LAUNCH / 'execution.json')
    comparison, independent = read(PATH_REVIEW / 'report.json'), read(PATH_INDEPENDENT / 'report.json')
    require(target['passed'] is True and target_launch['passed'] is True, 'Targeted regression not complete')
    require(target['outcome']['tests_run'] == 104 and target['source_unchanged'] and target['tools_unchanged'], 'Unexpected targeted qualification')
    require(target['source_before']['commit'] == 'e8c5da272560cf1243b7113faa5b9868d24b136c', 'Wrong executed implementation')
    require(replay['passed'] is False and replay_launch['passed'] is False and replay_launch['returncode'] == 1, 'Initial failed gate must remain retained')
    require(comparison['passed'] is True and comparison['original_replay_passed'] is False, 'Missing separate relocation review')
    require(independent['passed'] is True and independent['original_replay_passed'] is False
            and independent['new_clang_executions'] == independent['new_migration_executions']
            == independent['new_native_executions'] == 0, 'Independent relocation review scope mismatch')
    require(len(comparison['positive_cases']) == 2 and len(comparison['negative_cases']) == 2
            and len(comparison['negative_controls']) == 8, 'Unexpected comparison scope')
    require(not STAGE.exists(), 'Staging already exists')
    dest = STAGE / REL
    dest.mkdir(parents=True)
    archives = [
        pack('baseline-contracts', [('baseline', BASE)], dest),
        pack('development-fix', [('development', DEV)], dest),
        pack('targeted-regression', [('targeted', TARGET), ('launch', TARGET_LAUNCH)], dest),
        pack('original-input-replay', [('first-replay', REPLAY), ('first-launch', REPLAY_LAUNCH),
                                     ('path-comparison', PATH_REVIEW), ('independent-path-comparison', PATH_INDEPENDENT)], dest),
        pack('independent-static-review', [('review', STATIC)], dest),
        pack('p6-session-history', [('audit', P6)], dest),
    ]
    copies = {
        'baseline/report.json': BASE / 'report.json', 'baseline/seal.json': BASE / 'seal.json',
        'development/report.json': DEV / 'report.json',
        'regression/report.json': TARGET / 'report.json',
        'regression/execution.json': TARGET_LAUNCH / 'execution.json',
        'regression/stderr.log': TARGET / 'stderr.log',
        'regression/canonical-test-ids.txt': TARGET / 'canonical-test-ids.txt',
        'replay/first-report.json': REPLAY / 'report.json',
        'replay/first-execution.json': REPLAY_LAUNCH / 'execution.json',
        'replay/emission-path-review.json': PATH_REVIEW / 'report.json',
        'replay/independent-path-review.json': PATH_INDEPENDENT / 'report.json',
        'reviews/prelaunch-review.json': STATIC / 'review.json',
        'p6/history-summary.json': P6 / 'summary.json',
        'source/local-implementation.json': PREP / 'implementation-local.json',
        'source/remote-implementation.json': PREP / 'implementation-remote.json',
        'source/remote-verification.json': PREP / 'implementation-remote-verification.json',
        'reproduction/package_delivery.py': Path(__file__),
    }
    copy_map = []
    for name, original in copies.items():
        data = original.read_bytes()
        target_path = dest / name
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_bytes(data)
        require(target_path.read_bytes() == original.read_bytes(), 'Exact copy mismatch')
        copy_map.append({'path': str(REL / name), 'original_path': str(original), 'bytes': len(data), 'sha256': sha(data)})
    write(dest / 'source/exact-copy-map.json', {'schema': 'hepta.c-contract-identity.exact-copies.v1', 'copies': copy_map})
    write(dest / 'archive-summary.json', {'archives': archives, 'total_members': sum(a['members'] for a in archives),
          'omitted_binaries': sum(a['omitted'] for a in archives)})
    write(PREP / 'packaged-stage.json', {'stage': str(STAGE), 'evidence_prefix': str(REL), 'archives': archives})
    print(json.dumps({'stage': str(STAGE), 'archives': archives, 'exact_copies': len(copy_map)}))


if __name__ == '__main__':
    main()
