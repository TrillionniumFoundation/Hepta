"""Seal enumerated root originals after the 19:30 checkpoint, without product execution."""
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
OUT = ROOT / 'checkpoint-2105-r1'
OUT.mkdir(mode=0o700)
names = [
    'HIA-STATUS-2105.md', 'PR888-2105-proposed.md', 'PR888-2105-BODY-PIN.json',
    'PR888-before-2105.original.json', 'PR888-before-2105.original.md',
    'PR888-2105-LEASE.json', 'PR888-1926-READBACK.json',
    'build_PR888_2105.py', 'build_checkpoint_2105.py',
    'prepare_integer_integration_v90_r1.py', 'freeze_integer_source108_r1.py',
    'freeze_integer_source108_r2.py', 'prepare_integer_source108_r2.py',
    'run_integer_source108_r1_once.py', 'run_integer_source108_r2_once.py',
    'prepare_v90_contract_derivation_r1.py', 'prepare_v90_workflow_contract_r1.py',
    'reconcile_v90_workflow_contract_r1.py', 'run_v90_contract_derivation_r1_once.py',
    'run_v90_workflow_contract_r1_once.py', 'run_apt_owner_source_io_r2_once.py',
    'prepare_wire_r2_root_launchers.py', 'run_wire89_diagnostic_r1_once.py',
    'run_wire89_diagnostic_r2_once.py', 'run_wire89_recorder_source5_r2_once.py',
    'prepare_cli_r4c_root_launcher.py', 'review_run_cli_r4c_source.py',
    'audit_cli_r4c_source_actual.py',
]
paths = [ROOT / name for name in names]
for name in (
    'v90-standard-ci-43289808798', 'v90-workflow-contract-pure-r1',
    'integer-integration-v91-candidate-publication-r1',
    'integer-source108-request-publication-r1', 'integer-source108-r2-candidate-publication',
    'integer-source108-r2-request-publication', 'integer-source108-r1-invocation',
    'integer-source108-r2-invocation', 'apt-owner-source-io-r2-review',
    'apt-owner-source-io-r2-invocation', 'wire89-diagnostic-r2-review',
    'wire89-recorder-source5-r2-invocation', 'wire89-diagnostic-r2-invocation',
    'cli-r4c-canonical-review', 'cli-r4c-source-actual-r1', 'full32-r4-pretrigger',
    'full32-r4-43305002328', 'v91-integer-source-pass-pure',
):
    directory = ROOT / name
    assert directory.is_dir(), str(directory)
    paths.extend(path for path in directory.rglob('*') if path.is_file())
for directory in (
    'core-integer-integration-v90-r1', 'core-integer-integration-v91-r2',
    'core-workflow-generator-contract-v90-r1', 'core-workflow-contract-derivation-v90-r1',
):
    paths.extend(path for path in (BASE / directory).iterdir() if path.is_file())
paths = sorted(set(paths), key=lambda path: path.relative_to(BASE).as_posix())


def digest(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(path):
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
    return {'path': path.relative_to(BASE).as_posix(), 'mode': stat.S_IMODE(before.st_mode),
            'identity': identity(before), **digest(raw)}, raw


members, bodies = [], {}
for path in paths:
    row, raw = read(path)
    members.append(row)
    bodies[row['path']] = raw
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
        assert restored == bodies[row['path']] and digest(restored) == {k: row[k] for k in ('bytes', 'sha256', 'git_blob')}
raw = archive.read_bytes()
parts = []
for index, offset in enumerate(range(0, len(raw), 320 << 10)):
    chunk = raw[offset:offset + (320 << 10)]
    payload = base64.b64encode(chunk) + b'\n'
    name = f'root-originals-{index:03d}.base64'
    (OUT / name).open('xb').write(payload)
    parts.append({'path': name, 'offset': offset, 'raw_bytes': len(chunk), **digest(payload)})
assert b''.join(base64.b64decode((OUT / row['path']).read_bytes().strip(), validate=True) for row in parts) == raw
report = {'schema': 'hia.root.actual-progress-checkpoint.v2',
          'parent': '210e6b20402b0c699af2a4f9269470a526c470c9',
          'parent_tree': 'a3f185605012809836cef762b75bacd21e941bb2',
          'root_originals': members, 'file_count': len(members),
          'original_bytes': sum(row['bytes'] for row in members), 'archive': digest(raw), 'parts': parts,
          'all_originals_and_archive_members_read_back': True,
          'large_official_ZIPs_in_this_checkpoint': False,
          'scope': 'Only this explicit root-original inventory. Agent canonical actual archives remain separate; no source checkout, official ZIP, product execution or missing receipt is reconstructed or implied.',
          'whole_native_rewrite_closed': False, 'default_activated': False, 'legacy_product_deleted': False}
(OUT / 'ARCHIVE.json').open('x').write(json.dumps(report, sort_keys=True, indent=2) + '\n')
for name in ('HIA-STATUS-2105.md', 'PR888-2105-proposed.md', 'PR888-2105-BODY-PIN.json', 'build_checkpoint_2105.py'):
    (OUT / name).open('xb').write((ROOT / name).read_bytes())
prefix = 'experiments/hia_native_source_merge_20261112/status-2105-r1/'
files = [{'path': prefix + path.name, 'local': str(path), 'mode': '100644', **digest(path.read_bytes())}
         for path in sorted(OUT.iterdir()) if path.name != 'root-originals.tar.gz']
(OUT / 'FILES.json').open('x').write(json.dumps(files, sort_keys=True, indent=2) + '\n')
print(json.dumps({'files': len(files), 'originals': len(members), 'original_bytes': report['original_bytes'],
                  'archive': report['archive'], 'parts': len(parts)}, sort_keys=True))
