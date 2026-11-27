"""Lossless completed text records; complete binary bytes remain in artifact."""
from pathlib import Path
from hashlib import sha256
import base64
import json
import sys
import zlib

root = Path(sys.argv[1])
files = {}
for folder in ('evidence', 'component', 'original55', 'default311'):
    for path in sorted((root / folder).rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        if path.suffix not in ('.json', '.txt', '.log', '.stdout', '.stderr'):
            continue
        raw = path.read_bytes()
        try:
            text = raw.decode('utf-8')
        except UnicodeError:
            continue
        files[path.relative_to(root).as_posix()] = {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(), 'text': text}
raw = (json.dumps({'schema': 'hia.agent-contract.development-text.v1', 'files': files,
    'scope': 'COMPLETE_SELECTED_TEXT_NOT_BINARY_CRC'}, sort_keys=True, separators=(',', ':')) + '\n').encode()
compressed = zlib.compress(raw, 6)
encoded = base64.b64encode(compressed).decode()
header = {'protocol': 'HIA_AGENT_CONTRACT_DEVELOPMENT_ZLIB_BASE64', 'record': 'begin',
    'raw_bytes': len(raw), 'raw_sha256': sha256(raw).hexdigest(), 'compressed_bytes': len(compressed),
    'compressed_sha256': sha256(compressed).hexdigest(), 'chunks': (len(encoded) + 10999) // 11000}
print(json.dumps(header, sort_keys=True))
for index, start in enumerate(range(0, len(encoded), 11000)):
    line = json.dumps({'protocol': header['protocol'], 'record': 'chunk', 'index': index,
                      'data': encoded[start:start + 11000]}, sort_keys=True)
    assert len(line.encode()) <= 12288
    print(line)
print(json.dumps({'protocol': header['protocol'], 'record': 'end', 'raw_sha256': header['raw_sha256']}, sort_keys=True))
