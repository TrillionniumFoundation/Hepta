"""Create one exact, read-back-verified custody archive of completed Core authoring."""
from hashlib import sha256
import gzip
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import time
import traceback

EXPECTED_ROOT = Path('/home/qian-qi/he26corelowering-authoring-r3-custody-r1')
ORIGINAL = Path('/home/qian-qi/he26corelowering-authoring-r3')
PYTHON_SHA = 'b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493'

def digest(raw):
    return sha256(raw).hexdigest()

def create(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def capture(path):
    first = path.lstat()
    if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1:
        raise RuntimeError('expected regular private original: ' + str(path))
    def stamp(v):
        return (v.st_dev, v.st_ino, v.st_mode, v.st_nlink, v.st_uid, v.st_gid,
                v.st_size, v.st_mtime_ns, v.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        if stamp(os.fstat(stream.fileno())) != stamp(first):
            raise RuntimeError('original changed before reading')
        raw = stream.read(16 * 1024 * 1024 + 1)
        if stamp(os.fstat(stream.fileno())) != stamp(first):
            raise RuntimeError('original changed while reading')
    if len(raw) != first.st_size or stamp(path.lstat()) != stamp(first):
        raise RuntimeError('original changed after reading')
    return raw, first

request_raw = sys.stdin.buffer.read(1048577)
if len(request_raw) > 1048576:
    raise RuntimeError('custody request exceeds tool limit')
request = json.loads(request_raw)
if request['root'] != str(EXPECTED_ROOT) or request['original_root'] != str(ORIGINAL):
    raise RuntimeError('unexpected custody root')
if digest(Path(sys.executable).resolve().read_bytes()) != PYTHON_SHA:
    raise RuntimeError('pinned interpreter differs')
os.umask(0o077)
EXPECTED_ROOT.mkdir(mode=0o700)
create(EXPECTED_ROOT / 'request.original.json', request_raw)
started = time.monotonic()
report = {'schema': 'hepta.hia.core-lowering-authoring-custody.v1', 'status': 'HOLD',
          'original_job': '1a1cc1d4d4f-2564-e2d', 'original_candidate':
          'ca87109921632cf2b1a55b43cb28b60a36e55706',
          'source_generation_repeated': False, 'native_or_product_executed': False,
          'originals_deleted': False, 'members': []}
try:
    records, values = {}, {}
    for spec in request['files']:
        name = spec['path']
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or relative.as_posix() != name or name in records:
            raise RuntimeError('invalid or duplicate custody path')
        raw, info = capture(ORIGINAL / relative)
        if (spec['size'] is not None and len(raw) != spec['size']) or digest(raw) != spec['sha256']:
            raise RuntimeError('original identity differs: ' + name)
        records[name] = {'path': name, 'size': len(raw), 'sha256': digest(raw),
                         'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
        values[name] = raw
    if len(records) != request['expected_file_count']:
        raise RuntimeError('custody denominator differs')
    archive = EXPECTED_ROOT / 'originals.tar.gz'
    with archive.open('xb') as target:
        with gzip.GzipFile(filename='', mode='wb', compresslevel=6, fileobj=target, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as bundle:
                for name, row in sorted(records.items()):
                    item = tarfile.TarInfo(name)
                    item.size, item.mode, item.uid, item.gid = row['size'], row['mode'], row['uid'], row['gid']
                    item.mtime = 0
                    bundle.addfile(item, io.BytesIO(values[name]))
        target.flush()
        os.fsync(target.fileno())
    with tarfile.open(archive, 'r:gz') as bundle:
        members = bundle.getmembers()
        if len(members) != len(records) or {m.name for m in members} != set(records):
            raise RuntimeError('archive membership differs')
        for member in members:
            row = records[member.name]
            if not member.isfile() or (member.size, member.mode, member.uid, member.gid) != (
                    row['size'], row['mode'], row['uid'], row['gid']):
                raise RuntimeError('archive metadata differs')
            raw = bundle.extractfile(member).read()
            if raw != values[member.name] or digest(raw) != row['sha256']:
                raise RuntimeError('archive full member readback differs')
    for name, row in records.items():
        raw, info = capture(ORIGINAL / name)
        if raw != values[name] or (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid) != (
                row['mode'], row['uid'], row['gid']):
            raise RuntimeError('original changed after archival')
    archive_raw, info = capture(archive)
    report.update(status='EXACT_ORIGINAL_ARCHIVE_READBACK_PASS',
                  archive={'path': str(archive), 'size': len(archive_raw), 'sha256': digest(archive_raw)},
                  members=list(records.values()), member_count=len(records),
                  original_bytes=sum(r['size'] for r in records.values()),
                  original_bytes_and_modes_preserved=True,
                  full_archive_members_reopened_and_compared=True)
except BaseException:
    report['exception'] = traceback.format_exc()
finally:
    report['seconds'] = time.monotonic() - started
    create(EXPECTED_ROOT / 'report.json', wire(report))
    print(json.dumps(report, sort_keys=True), flush=True)
raise SystemExit(0 if report['status'] == 'EXACT_ORIGINAL_ARCHIVE_READBACK_PASS' else 1)
