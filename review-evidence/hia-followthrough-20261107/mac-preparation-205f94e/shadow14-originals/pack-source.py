from pathlib import Path
import datetime
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile

root = Path('/Users/qianqi/work/hia-runtime-9f60-20261107-372e7da9')
destination = root / 'shadow14-public-evidence-pack-r1'
names = (
    'shadow14-isolated-http-r1/result.json',
    'shadow14-isolated-http-r1/http-events.jsonl',
    'shadow14-isolated-http-r2/result.json',
    'shadow14-isolated-http-r3/result.json',
    'shadow14-isolated-http-r3/http-events.jsonl',
)
assert os.getuid() == 501
assert root.is_dir() and root.resolve() == root
destination.mkdir(mode=0o700)
os.chmod(destination, 0o700)
files = []
payloads = []
for name in names:
    path = root / name
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_uid == 501
        assert before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o600
        assert before.st_size <= 8 * 1024 * 1024
        raw = stream.read()
        after = os.fstat(stream.fileno())
        assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                                       after.st_mtime_ns, after.st_ctime_ns)
        assert len(raw) == before.st_size
    payloads.append((name, raw))
    files.append({'path': name, 'bytes': len(raw),
                  'sha256': hashlib.sha256(raw).hexdigest(),
                  'source_mode': stat.S_IMODE(before.st_mode),
                  'source_owner': before.st_uid})

archive_path = destination / 'shadow14-original-five-files.tar.gz'
descriptor = os.open(archive_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(descriptor, 'wb') as stream:
    os.fchmod(stream.fileno(), 0o600)
    with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w') as archive:
            for name, raw in payloads:
                info = tarfile.TarInfo(name)
                info.mode = 0o600
                info.size = len(raw)
                info.mtime = 0
                archive.addfile(info, io.BytesIO(raw))
    stream.flush()
    os.fsync(stream.fileno())

archive_raw = archive_path.read_bytes()
manifest = {
    'schema': 'hepta.hia.shadow14-original-public-evidence.v1',
    'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'runtime_commit': '14dfb09aa3263ed35b4f88e8c301f8492d63fea7',
    'hepta_commit': '205f94ec811018f89fbf68c987c6ab8e826bb15b',
    'files': files,
    'archive_path': str(archive_path),
    'archive_bytes': len(archive_raw),
    'archive_sha256': hashlib.sha256(archive_raw).hexdigest(),
    'scope': 'exact five specified original probe files only; no private runtime configuration or credentials',
    'production_modified': False,
    'source_bytes_modified': False,
    'archive_metadata': 'new normalized archive headers; original file bytes retained verbatim',
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
                  'manifest_sha256': hashlib.sha256(encoded).hexdigest(),
                  'archive_path': str(archive_path), 'archive_bytes': len(archive_raw),
                  'archive_sha256': manifest['archive_sha256'], 'files': len(files),
                  'production_modified': False}), flush=True)
