"""Preserve explicitly enumerated root records and complete source129 evidence."""
from pathlib import Path
import base64
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile

BASE = Path('/workspace/scratch/e26ed3e2edcf')
ROOT = BASE / 'root'
OUT = ROOT / 'checkpoint-v92-r1'
assert not OUT.exists()
selected = {}


def add(path, name):
    path = Path(path)
    assert name not in selected, name
    assert path.is_file(), str(path)
    selected[name] = path


def directory(path, prefix, exclude=()):
    path = Path(path)
    assert path.is_dir(), str(path)
    for item in sorted(path.rglob('*')):
        before = item.lstat()
        assert not stat.S_ISLNK(before.st_mode), str(item)
        if stat.S_ISREG(before.st_mode) and item.name not in exclude:
            add(item, prefix + '/' + item.relative_to(path).as_posix())


for name in (
    'HIA-STATUS-V92-R1.md', 'PR888-v92-r1-proposed.md', 'PR888-v92-r1-BODY-PIN.json',
    'build_PR888_v92_r1.py', 'build_checkpoint_v92_r1.py', 'V92-CURRENT-SOURCE-INVENTORY.json',
    'audit_v92_inventory.py', 'audit_source129_archive_v92_r1.py',
    'PR888-2105-RAW-READBACK.json', 'PR888-2105-READBACK.json', 'PR888-2105-UPDATE-ACK.json',
    'PR888-2105-UPDATE-INTENT.json', 'audit_cli_finite_r1_actual.py', 'audit_source129_v92_r1.py',
    'audit_wire04_source6_r1.py', 'audit_wire04_source6_r2.py', 'build_wire04_source6_r2_actual.py',
    'freeze_v92_candidate.py', 'freeze_v92_pure_after_source129.py', 'freeze_v92_source129.py',
    'git_object_helpers_v2.js', 'invoke_cli_finite_once.py', 'merge_wire04_into_v92.py',
    'prepare_integer_native_integration_v92.py', 'prepare_wire04_source6_r2.py',
    'review_cli_finite_inputs.py', 'review_full32_r4_gzip_source.py', 'review_v92_stop_chain.py',
    'run_integer_wire_source129_v92_r1_once.py',
):
    add(ROOT / name, 'workspace/root/' + name)
for name in (
    'agent-canonical-raw-2135-r1', 'agent-canonical-raw-v92-r1',
    'cli-c-runtime-lifetime-invocation-r1', 'cli-c-runtime-lifetime-review-r1',
    'full32-r4-gzip-review-authoring-history-r1', 'full32-r4-gzip-review-r1',
    'integer-wire-source129-v92-r1-invocation', 'v92-source129-canonical-review-r1',
    'v92-standard-ci-r1', 'wire04-source6-invocation-r1', 'wire04-source6-invocation-r2',
    'wire04-source6-review-r1', 'pr-v92-authoring-history-r1',
):
    directory(ROOT / name, 'workspace/root/' + name)
for item in sorted((ROOT / 'checkpoint-2105-r1').iterdir()):
    if item.is_file() and (item.name.endswith('ACK.json') or item.name.startswith(('REF-', 'PR-FINAL', 'PUBLISH-', 'READBACK'))):
        add(item, 'workspace/root/checkpoint-2105-r1/' + item.name)
for name in ('RAW-READBACK.json', 'ARCHIVE-ROOT-READBACK.json'):
    add(ROOT / 'source129-actual-canonical-readback-v92-r1' / name,
        'workspace/root/source129-actual-canonical-readback-v92-r1/' + name)

v92 = Path('/tmp/hia-core-integer-native-integration-v92-r1-20261112-e26e')
for name in ('SOURCE129-PREEXEC.json', 'REQUEST.json', 'SOURCE-CANDIDATE.json', 'ROOT-STOP-CHAIN-STATIC-REVIEW.json', 'WIRE04-MERGE.json', 'BASE.json'):
    add(v92 / name, 'external/v92-integration/' + name)
for name in ('candidate-publication', 'source129-publication', 'pure-after-source129-publication', 'history'):
    directory(v92 / name, 'external/v92-integration/' + name)
peer = Path('/tmp/hia-v92-source129-independent-actual-r1/publication')
for item in sorted(peer.iterdir()):
    if item.is_file():
        add(item, 'external/source129-publication/' + item.name)
directory(peer / 'journal', 'external/source129-publication/journal')
for item in sorted((peer / 'readback').iterdir()):
    if item.is_file() and (item.name.startswith(('COMMIT', 'TREE', 'RECONCILE'))):
        add(item, 'external/source129-publication/readback/' + item.name)

cli = Path('/tmp/hia-cli-json-c-runtime-lifetime-failure-r1-20261112-e26e')
for name in ('HANDOFF.json', 'AUDIT.json', 'ORIGINALS.json', 'ARCHIVE-READBACK.json'):
    add(cli / name, 'external/cli-finite-r1/' + name)
for name in ('READBACK.json', 'PLAN.json', 'BINARY-REST-FIRST-READ.json', 'COMMIT-ACK.json', 'COMMIT-INTENT.json', 'COMMIT-READBACK.sdk.json', 'TREE-ACK.json', 'TREE-INTENT.json'):
    add(cli / 'publication' / name, 'external/cli-finite-r1/publication/' + name)
ci = Path('/tmp/hia-v92-standard-ci-readonly-43324913647-r1')
for name in ('SOURCE-JOB-LOG.raw.json', 'SOURCE-JOB-READBACK.json', 'source-job-131554853815.original.log'):
    add(ci / name, 'external/v92-standard-ci/' + name)
directory(ci / 'cli-peer', 'external/v92-standard-ci/cli-peer')
cold = Path('/tmp/hia-full32-rust195-supply-r5-20261112-e26e/publication')
for name in ('CANONICAL-HANDOFF.json', 'PUBLICATION-READBACK.json', 'PUBLICATION-JOURNAL.original.jsonl', 'PERSISTENCE-STATE.json'):
    add(cold / name, 'external/full32-r5-publication/' + name)


def digest(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


members, bodies = [], {}
for name, path in sorted(selected.items()):
    for parent in path.parents:
        assert stat.S_ISDIR(parent.lstat().st_mode), str(parent)
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        assert identity(os.fstat(fd)) == identity(before)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read()
        assert identity(os.fstat(fd)) == identity(before) == identity(path.lstat())
    finally:
        os.close(fd)
    assert len(raw) == before.st_size
    row = {'path': name, 'original_path': str(path), 'mode': stat.S_IMODE(before.st_mode),
           'identity': identity(before), **digest(raw)}
    members.append(row)
    bodies[name] = raw
OUT.mkdir(mode=0o700)
archive = OUT / 'root-originals.tar.gz'
with archive.open('xb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as tar:
    for row in members:
        info = tarfile.TarInfo(row['path'])
        info.size, info.mode, info.mtime = row['bytes'], row['mode'], 0
        tar.addfile(info, io.BytesIO(bodies[row['path']]))
with tarfile.open(archive, 'r:gz') as tar:
    entries = tar.getmembers()
    assert len(entries) == len(members)
    for row, entry in zip(members, entries, strict=True):
        assert entry.isfile() and entry.name == row['path'] and entry.mode == row['mode']
        restored = tar.extractfile(entry).read()
        assert restored == bodies[row['path']]
raw = archive.read_bytes()
parts = []
for index, offset in enumerate(range(0, len(raw), 320 << 10)):
    chunk = raw[offset:offset + (320 << 10)]
    payload = base64.b64encode(chunk) + b'\n'
    name = f'root-originals-{index:03d}.base64'
    (OUT / name).open('xb').write(payload)
    parts.append({'path': name, 'offset': offset, 'raw_bytes': len(chunk), **digest(payload)})
assert b''.join(base64.b64decode((OUT / row['path']).read_bytes().strip(), validate=True) for row in parts) == raw
report = {'schema': 'hia.root.actual-progress-checkpoint.v3',
          'parent': '426e1ddc96d14b07b8b1e9e8303502dbb40c9b64',
          'parent_tree': 'eaf044cd76d149d6240ea115ff4e3b821a4e5664',
          'root_originals': members, 'file_count': len(members),
          'original_bytes': sum(row['bytes'] for row in members), 'archive': digest(raw), 'parts': parts,
          'all_originals_and_archive_members_read_back': True,
          'additional_source129_actual_blobs': 13,
          'source129_commit_current_404_and_original_ACK_successful_GET_preserved': True,
          'source129_actual_264_files_preserved_separately_without_rerun': True,
          'cold_unknown_blob_and_full_ZIP_custody_gaps_preserved': True,
          'large_official_ZIPs_in_this_checkpoint': False,
          'scope': 'Exact enumerated root/peer/publication records, plus the separately referenced complete 13-blob source129 archive. No source, runtime, CI, Full32 or native request is executed by this checkpoint.',
          'whole_native_rewrite_closed': False, 'default_activated': False, 'legacy_product_deleted': False}
(OUT / 'ARCHIVE.json').open('x').write(json.dumps(report, sort_keys=True, indent=2) + '\n')
for name in ('HIA-STATUS-V92-R1.md', 'PR888-v92-r1-proposed.md', 'PR888-v92-r1-BODY-PIN.json', 'build_checkpoint_v92_r1.py'):
    (OUT / name).open('xb').write((ROOT / name).read_bytes())
prefix = 'experiments/hia_native_source_merge_20261112/status-v92-r1/'
files = [{'path': prefix + path.name, 'local': str(path), 'mode': '100644', 'reuse_verified_blob': False, **digest(path.read_bytes())}
         for path in sorted(OUT.iterdir()) if path.name != 'root-originals.tar.gz']
original_files = json.loads((peer / 'FILES-FINAL.json').read_bytes())
assert len(original_files) == 13
for row in original_files:
    local = ROOT / 'source129-actual-canonical-readback-v92-r1' / Path(row['path']).name
    pin = digest(local.read_bytes())
    assert pin['bytes'] == row['size'] and pin['sha256'] == row['sha256'] and pin['git_blob'] == row['git_blob_sha1']
    files.append({'path': row['path'], 'local': str(local), 'mode': row['mode'], 'reuse_verified_blob': True, **pin})
assert len({row['path'] for row in files}) == len(files)
(OUT / 'FILES.json').open('x').write(json.dumps(files, sort_keys=True, indent=2) + '\n')
print(json.dumps({'files': len(files), 'new_blobs': sum(not row['reuse_verified_blob'] for row in files),
                  'reused_full_read_source129_blobs': 13, 'originals': len(members), 'original_bytes': report['original_bytes'],
                  'archive': report['archive'], 'parts': len(parts)}, sort_keys=True))
