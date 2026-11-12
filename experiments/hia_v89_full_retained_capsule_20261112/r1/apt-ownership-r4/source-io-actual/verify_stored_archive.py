"""Verify the complete stored archive without touching original absolute paths."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import io
import json
import stat
import tarfile

root = Path(__file__).resolve().parent
inventory = json.loads((root / 'ORIGINALS-INVENTORY.json').read_bytes())
audit = json.loads((root / 'AUDIT.json').read_bytes())
text = (root / 'all-originals.tar.gz.b64').read_bytes()
assert text.endswith(b'\n') and b'\n' not in text[:-1]
raw = base64.b64decode(text[:-1], validate=True)
assert base64.b64encode(raw) + b'\n' == text
assert len(raw) == audit['archive']['bytes']
assert hashlib.sha256(raw).hexdigest() == audit['archive']['sha256']
seen = set()
regular_bytes = 0
with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as tar:
    for member in tar:
        name = member.name
        path = PurePosixPath(name)
        assert not path.is_absolute() and '..' not in path.parts and str(path) == name and name not in seen
        seen.add(name)
        if member.isdir():
            row = inventory['directories'][name]
        else:
            assert member.isreg()
            row = inventory['files'][name]
            data = tar.extractfile(member).read()
            assert len(data) == row['bytes'] == member.size
            assert hashlib.sha256(data).hexdigest() == row['sha256']
            assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == row['git_blob']
            regular_bytes += len(data)
        meta = row['identity']
        assert member.mode == stat.S_IMODE(meta['st_mode'])
        assert member.uid == meta['st_uid'] and member.gid == meta['st_gid']
        expected_mtime = str(meta['st_mtime_ns'] // 1000000000) + '.' + f"{meta['st_mtime_ns'] % 1000000000:09d}"
        assert member.pax_headers['mtime'] == expected_mtime
assert seen == set(inventory['files']) | set(inventory['directories'])
assert regular_bytes == audit['archive_original_bytes']
result = {'schema': 'hia.apt-owned.actual-source-io-stored-restoration.v1',
          'status': 'COMPLETE_STORED_ARCHIVE_READBACK_PASS',
          'regular_files': len(inventory['files']), 'directories': len(inventory['directories']),
          'original_bytes': regular_bytes, 'gzip_bytes': len(raw),
          'gzip_sha256': hashlib.sha256(raw).hexdigest(),
          'absolute_original_files_read': False, 'special_files_extracted': False,
          'product_or_source_control_reexecuted': False}
output = root / 'STORED-RESTORATION.json'
with output.open('x') as stream:
    json.dump(result, stream, sort_keys=True, indent=2)
    stream.write('\n')
print(json.dumps(result, sort_keys=True))
