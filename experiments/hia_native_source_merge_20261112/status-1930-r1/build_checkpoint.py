from pathlib import Path
import base64
import gzip
import hashlib
import io
import json
import stat
import tarfile

ROOT = Path('/workspace/scratch/e26ed3e2edcf/root')
OUT = ROOT / 'checkpoint-1930-r1'
OUT.mkdir()
paths = [
    ROOT / name for name in (
        'HIA-STATUS-1926.md', 'PR888-1926-proposed.md', 'PR888-before-1925.original.md',
        'PR888-1925-LEASE.json', 'PR888-1926-BODY-PIN.json', 'build_PR888_1926.py',
        'run_integer_native_current_r2_once.py', 'review_numeric_r3.py',
        'review_run_cli_r4b1_source.py', 'cli-r4b1-root-context.json',
        'cli-r4b1-canonical-readback.json', 'build_numeric_r3_audit.py',
        'build_full32_failed_multipart_r1.py')]
for directory in ('integer-native-current-r2-invocation', 'numeric-r3-pretrigger', 'cli-r4b1-source-actual-r1'):
    paths.extend(p for p in (ROOT / directory).iterdir() if p.is_file())
for directory, names in {
    'integer-native-current-r2-review': ['PRETRIGGER-LOCAL.json', 'CANONICAL-SELECTED-READBACK.json'],
    'numeric-r3-actual-43287029044': ['AUDIT.json', 'ZIP-MANIFEST.json', 'DERIVED-ORIGINALS.json',
        'DOWNLOAD-READBACK.json', 'audit_actual_r3.py', 'job-131423025805.original.log',
        'run.original.json', 'jobs.original.json', 'artifacts.original.json',
        'PURE-V90-PUBLISH-INTENT.json', 'PURE-V90-TREE-ACK.json', 'PURE-V90-COMMIT-ACK.json',
        'PURE-V90-READBACK.json', 'V90-CI-INTENT.json', 'V90-CI-CHILD-ACK.json', 'V90-CI-REF-ACK.json'],
    'carrier-ci-failure-43274637363': ['carrierRun.original.json', 'carrierJobs.original.json',
        'artifacts.original.json', 'job.original.log', 'WIRE-FAILURE-AUDIT.json', 'DOWNLOAD-READBACK.json'],
    'full32-r3-failed-original-parts-r1': ['CONTEXT.json', 'FILES.json', 'BLOB-RECONCILIATION.json',
        'A-TREE-ACK.json', 'A-COMMIT-ACK.json', 'A-READBACK.json', 'WORKFLOW-PIN.json', 'B-ACK.json',
        'PRETRIGGER.json', 'TRIGGER-INTENT.json', 'TRIGGER-ACK.json']
}.items():
    paths.extend(ROOT / directory / name for name in names)
paths.extend((ROOT / 'carrier-ci-failure-43274637363/selected-originals').rglob('*'))
paths = sorted({p for p in paths if p.is_file()}, key=lambda p: p.relative_to(ROOT).as_posix())

def digest(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}

def ident(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]

members, originals = [], {}
for p in paths:
    before = p.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    body = p.read_bytes()
    assert ident(before) == ident(p.lstat())
    name = p.relative_to(ROOT).as_posix()
    members.append({'path': name, 'mode': stat.S_IMODE(before.st_mode), **digest(body)})
    originals[name] = body
archive = OUT / 'root-originals.tar.gz'
with archive.open('xb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as tar:
    for row in members:
        info = tarfile.TarInfo(row['path'])
        info.size = row['bytes']; info.mode = row['mode']; info.mtime = 0
        tar.addfile(info, io.BytesIO(originals[row['path']]))
with tarfile.open(archive, 'r:gz') as tar:
    observed = tar.getmembers()
    assert len(observed) == len(members)
    for row, info in zip(members, observed, strict=True):
        assert info.isfile() and info.name == row['path'] and info.mode == row['mode']
        assert tar.extractfile(info).read() == originals[row['path']]
raw = archive.read_bytes()
parts = []
for i, offset in enumerate(range(0, len(raw), 384 << 10)):
    payload = base64.b64encode(raw[offset:offset + (384 << 10)]) + b'\n'
    name = f'root-originals-{i:03d}.base64'
    (OUT / name).open('xb').write(payload)
    parts.append({'path': name, 'offset': offset, 'raw_bytes': min(384 << 10, len(raw) - offset), **digest(payload)})
assert b''.join(base64.b64decode((OUT / x['path']).read_bytes(), validate=False) for x in parts) == raw
report = {'schema': 'hia.root.actual-progress-checkpoint.v1',
          'parent': '13b3db22940919748e9526c1665af9cb6c9376d4',
          'parent_tree': '858e58dea51a12759c3340533e6abc4cb13ed584',
          'root_originals': members, 'file_count': len(members),
          'original_bytes': sum(x['bytes'] for x in members), 'archive': digest(raw), 'parts': parts,
          'all_originals_and_archive_members_read_back': True,
          'large_official_ZIPs_in_this_checkpoint': False,
          'large_zip_scope': 'Numeric, current-v89, carrier and failed-full32 official ZIPs retain their separate exact local/provider custody and dedicated audits. This checkpoint is the enumerated complete set of root originals only.',
          'whole_native_rewrite_closed': False, 'default_activated': False, 'legacy_product_deleted': False}
(OUT / 'ARCHIVE.json').open('x').write(json.dumps(report, sort_keys=True, indent=2) + '\n')
for name in ('HIA-STATUS-1926.md', 'PR888-1926-proposed.md', 'PR888-1926-BODY-PIN.json'):
    (OUT / name).open('xb').write((ROOT / name).read_bytes())
prefix = 'experiments/hia_native_source_merge_20261112/status-1930-r1/'
files = [{'path': prefix + p.name, 'local': str(p), **digest(p.read_bytes())}
         for p in sorted(OUT.iterdir()) if p.name != 'root-originals.tar.gz']
(OUT / 'FILES.json').open('x').write(json.dumps(files, sort_keys=True, indent=2) + '\n')
print(json.dumps({'root_original_files': len(members), 'root_original_bytes': report['original_bytes'],
                  'archive': report['archive'], 'parts': len(parts), 'canonical_files': len(files)}, sort_keys=True))
