"""Check retained CI member bytes without extracting or executing them."""
from pathlib import Path
import gzip
import hashlib
import io
import json
import tarfile
import zlib

ROOT = Path(__file__).resolve().parent

def require(condition, message):
    if not condition:
        raise SystemExit(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def named_bytes(record):
    path = Path(record['path'])
    require(len(path.parts) == 1 and path.name not in ('', '.', '..'), 'invalid member name')
    raw = (ROOT / path).read_bytes()
    require(len(raw) == record['bytes'] and sha(raw) == record['sha256'], 'file identity mismatch: ' + path.name)
    return raw

summary = json.loads((ROOT / 'summary.json').read_text())
index_raw = gzip.decompress(named_bytes(summary['member_index']))
require(len(index_raw) == summary['member_index']['uncompressed_bytes'], 'index size mismatch')
require(sha(index_raw) == summary['member_index']['uncompressed_sha256'], 'index hash mismatch')
index = json.loads(index_raw)
require({k: v for k, v in index.items() if k != 'members'} ==
        {k: v for k, v in summary.items() if k not in ('member_index', 'verification')}, 'summary/index mismatch')
archive = b''.join(named_bytes(part) for part in summary['archive_parts'])
require(len(archive) == summary['archive_bytes'] and sha(archive) == summary['archive_sha256'], 'archive mismatch')
observed = {}
with tarfile.open(fileobj=io.BytesIO(archive), mode='r|xz') as stream:
    for member in stream:
        parts = member.name.split('/')
        require(member.isfile() and len(parts) == 2 and parts[0] == 'objects', 'invalid object entry')
        digest = parts[1]
        raw = stream.extractfile(member).read()
        require(sha(raw) == digest and digest not in observed, 'duplicate or invalid object')
        observed[digest] = (len(raw), zlib.crc32(raw))
require(len(observed) == index['unique_object_count'], 'object count mismatch')
require(sum(v[0] for v in observed.values()) == index['unique_object_bytes'], 'unique byte count mismatch')
require(len(index['members']) == index['member_count'] == 23715, 'member count mismatch')
require(len({row['path'] for row in index['members']}) == 23715, 'duplicate original member name')
for ordinal, row in enumerate(index['members']):
    require(row['index'] == ordinal, 'original member order mismatch')
    require(observed.get(row['sha256']) == (row['bytes'], row['zip_crc32']), 'original member mapping mismatch')
require(sum(row['bytes'] for row in index['members']) == index['member_bytes'], 'original byte count mismatch')
print(json.dumps({
    'status': 'PASS_RETAINED_MEMBER_BYTE_IDENTITY',
    'original_member_count': index['member_count'],
    'unique_object_count': len(observed),
    'archive_sha256': sha(archive),
    'original_zip_byte_stream_retained': False,
    'original_zip_digest_recomputed_by_this_reader': False,
    'proofs_rechecked_by_this_reader': False,
    'project_code_executions': 0,
    'native_image_executions': 0,
}, indent=2, sort_keys=True))
