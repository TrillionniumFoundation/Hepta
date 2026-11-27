"""Complete immutable GET readback; no project imports or execution."""
import base64
import hashlib
import json
from pathlib import Path
import stat
import zlib

ROOT = Path(__file__).absolute().parent
def pin(raw):
    return {'bytes': len(raw), 'mode': '100644', 'sha256': hashlib.sha256(raw).hexdigest(),
        'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()
def create(name, value):
    with (ROOT / name).open('xb') as stream:
        stream.write(encoded(value))
rows = json.loads((ROOT / 'PUBLICATION-INPUTS.json').read_bytes())
decoded = {}
for row in rows:
    fetched = json.loads((ROOT / 'GIT-ACK' / (row['file'] + '.GET.json')).read_bytes())
    posted = json.loads((ROOT / 'GIT-ACK' / (row['file'] + '.POST.json')).read_bytes())
    assert not fetched.get('isError') and not posted.get('isError')
    assert posted['structuredContent']['sha'] == row['pin']['git_blob']
    raw = fetched['structuredContent']['content'].encode()
    assert pin(raw) == row['pin'] and raw == (ROOT / row['file']).read_bytes()
    decoded[row['file']] = json.loads(raw)
capsule = decoded['SOURCE-TRANSPORT.json']
compressed = base64.b64decode(capsule['data'], validate=True)
assert pin(compressed) == capsule['compressed_pin']
payload_raw = zlib.decompress(compressed)
assert pin(payload_raw) == capsule['payload_pin']
payload = json.loads(payload_raw)
assert len(payload['files']) == 25
fields = lambda s: [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
for row in payload['files']:
    raw = row['text'].encode()
    assert pin(raw) == row['pin']
    path = Path(row['path']); before = path.lstat(); actual = path.read_bytes(); after = path.lstat()
    assert stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == row['posix_mode']
    assert raw == actual and fields(before) == fields(after) == row['seven_stats']
result = {'status': 'PASS_ACTUAL_GIT_FULL_READBACK', 'actual_ack_full_get_blobs': len(rows),
    'complete_decoded_files': 25, 'complete_decoded_bytes': len(payload_raw),
    'all_file_bytes_modes_seven_stats_equal': True, 'product_executions': 0,
    'payload_pin': pin(payload_raw), 'source_transport': rows[0]['pin']}
create('ACTUAL-GIT-READBACK.json', result)
leaves = rows + [{'file': name, 'pin': pin((ROOT / name).read_bytes())}
    for name in ('readback_actual_git.py', 'ACTUAL-GIT-READBACK.json')]
create('MOUNT-RECIPE.json', {'schema': 'hepta.immutable-git-recipe.v1',
    'scope': 'R5 code-position source-only repair and complete compile-only metadata diagnosis, no binder/products',
    'repository': 'TrillionniumFoundation/Hepta', 'leaves': leaves,
    'actual_source_transport_readback': result,
    'six_leaf_publication_pending_final_ACK_GET': True})
create('FOLLOWUP-PUBLICATION-INPUTS.json', [row for row in leaves if row not in rows] +
    [{'file': 'MOUNT-RECIPE.json', 'pin': pin((ROOT / 'MOUNT-RECIPE.json').read_bytes())}])
print(json.dumps(result, sort_keys=True))
