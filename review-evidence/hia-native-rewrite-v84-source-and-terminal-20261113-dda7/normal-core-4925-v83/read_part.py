"""Emit one bounded transport object; do not write redundant base64 to disk."""
import base64
from hashlib import sha256, sha1
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parent / 'evidence-r1'
report = json.loads((root / 'PACKING-RESULT.json').read_bytes())
index = int(sys.argv[1])
extent = 750000
parts = (report['archive_bytes'] + extent - 1) // extent
assert 0 <= index < parts
with (root / report['archive']).open('rb') as stream:
    stream.seek(index * extent)
    raw = stream.read(extent)
assert len(raw) == min(extent, report['archive_bytes'] - index * extent)
part = {'schema': 'hia.complete-originals.zip.lossless-part.v1',
    'scope': 'normal-core-4925-terminal-v83', 'archive': report['archive'],
    'archive_bytes': report['archive_bytes'], 'archive_sha256': report['archive_sha256'],
    'part': index, 'parts': parts, 'offset': index * extent, 'bytes': len(raw),
    'sha256': sha256(raw).hexdigest(), 'encoding': 'base64', 'data': base64.b64encode(raw).decode('ascii')}
text = json.dumps(part, sort_keys=True, separators=(',', ':')) + '\n'
wire = text.encode('utf-8')
metadata = {key: value for key, value in part.items() if key != 'data'}
metadata['transport_bytes'] = len(wire)
metadata['transport_sha256'] = sha256(wire).hexdigest()
metadata['transport_blob'] = sha1(b'blob ' + str(len(wire)).encode() + b'\0' + wire).hexdigest()
print(json.dumps({'wire': text, 'metadata': metadata}, separators=(',', ':')))
