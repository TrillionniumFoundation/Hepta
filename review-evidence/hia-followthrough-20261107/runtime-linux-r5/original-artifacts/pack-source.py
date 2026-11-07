from pathlib import Path
import datetime
import gzip
import hashlib
import io
import json
import os
import stat
import sys
import tarfile

config = json.loads(sys.argv[1])
root = Path(config['root'])
assert root.is_dir() and root.resolve() == root
assert config['platform'] in ('linux', 'mac')
destination = root / ('runtime-942-' + config['platform'] + '-public-evidence-r1')
payloads = {}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def add(name, expected=None, length=None):
    assert Path(name).name == name and name not in ('', '.', '..')
    if name in payloads:
        raw, metadata = payloads[name]
    else:
        path = root / name
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            assert before.st_nlink == 1 and not before.st_mode & 0o022
            assert before.st_size <= 16 * 1024 * 1024
            raw = stream.read()
            after = os.fstat(stream.fileno())
            assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                    before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                                           after.st_mtime_ns, after.st_ctime_ns)
            assert len(raw) == before.st_size
        metadata = {'path': name, 'bytes': len(raw), 'sha256': sha(raw),
                    'source_mode': stat.S_IMODE(before.st_mode), 'source_owner': before.st_uid}
        payloads[name] = raw, metadata
    assert expected is None or sha(raw) == expected, name
    assert length is None or len(raw) == length, name
    return raw

reports = []
for name, expected in config['reports'].items():
    report = json.loads(add(name, expected))
    assert report['published_commit'] == '942d470d155c65ba7235eb19c5bbfd07f1ce2ad0'
    assert report['published_tree'] == 'a19f1dd724bdf80a388ddae17d828b01e5fc42f0'
    assert report['source_unchanged'] is True and report['completed_utc']
    assert report['qualified_files_sha256'] == 'f6f2061d675d02f75b86d7120fc657aa681531d46c6117052530a7522ddcf794'
    assert report['qualified_file_count'] == 959
    reports.append(report)
    for stage in report.get('stages', []) + report.get('retained_successful_stage_receipts', []) + report.get('rechecked_stages', []):
        path = Path(stage['log'])
        assert path.parent == root and stage['status'] == 'completed'
        add(path.name, stage['log_sha256'], stage['log_bytes'])
    for target in report['cargo_target_inventory']:
        assert target['target_count'] == 19 and target['matches_complete_pinned_target_source_inventory'] is True
        path = Path(target['metadata_path'])
        assert path.parent == root
        add(path.name, target['metadata_sha256'])
        add(path.with_suffix('.stderr').name, target['stderr_sha256'])

for name, expected in config['extras'].items():
    add(name, expected)
assert reports[0]['passed'] is False
if config['platform'] == 'linux':
    assert len(reports) == 2 and reports[1]['passed'] is True
    assert reports[1]['prior_failed_attempt']['sha256'] == next(iter(config['reports'].values()))
else:
    assert len(reports) == 1
    assert next(s for s in reports[0]['stages'] if s['name'] == 'release')['exit_code'] == 0

destination.mkdir(mode=0o700)
os.chmod(destination, 0o700)
archive_path = destination / ('runtime-942-' + config['platform'] + '-original-artifacts.tar.gz')
descriptor = os.open(archive_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, 'wb') as stream:
    os.fchmod(stream.fileno(), 0o600)
    with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w') as archive:
            for name, (raw, metadata) in sorted(payloads.items()):
                info = tarfile.TarInfo(name)
                info.mode = 0o600
                info.size = len(raw)
                info.mtime = 0
                archive.addfile(info, io.BytesIO(raw))
    stream.flush()
    os.fsync(stream.fileno())
archive_raw = archive_path.read_bytes()
manifest = {
    'schema': 'hepta.runtime.942-original-platform-artifacts.v1',
    'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'platform': config['platform'],
    'runtime_commit': '942d470d155c65ba7235eb19c5bbfd07f1ce2ad0',
    'runtime_tree': 'a19f1dd724bdf80a388ddae17d828b01e5fc42f0',
    'source_projection_sha256': reports[0]['qualified_files_sha256'],
    'scope': 'only retained static r5 artifacts; current source and target are not scanned or assigned to the old run',
    'current_source_read': False, 'target_read': False, 'production_modified': False,
    'original_report_passed_values': [r['passed'] for r in reports],
    'files': [metadata for _, metadata in sorted(payloads.values(), key=lambda x: x[1]['path'])],
    'archive_path': str(archive_path), 'archive_bytes': len(archive_raw),
    'archive_sha256': sha(archive_raw),
    'archive_metadata': 'new normalized headers; all member bytes retained verbatim',
}
manifest_path = destination / 'manifest.json'
encoded = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
descriptor = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, 'wb') as stream:
    os.fchmod(stream.fileno(), 0o600)
    stream.write(encoded)
    stream.flush()
    os.fsync(stream.fileno())
print(json.dumps({'manifest_path': str(manifest_path), 'manifest_bytes': len(encoded),
                  'manifest_sha256': sha(encoded), 'archive_path': str(archive_path),
                  'archive_bytes': len(archive_raw), 'archive_sha256': sha(archive_raw),
                  'files': len(payloads), 'current_source_read': False,
                  'production_modified': False}), flush=True)
