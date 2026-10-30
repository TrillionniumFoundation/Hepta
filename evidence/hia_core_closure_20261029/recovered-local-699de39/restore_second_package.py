"""Restore the original SECOND package from four verified raw parts; do not extract."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

def require(condition, message):
    if not condition:
        raise ValueError(message)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--evidence-directory', type=Path, default=Path(__file__).resolve().parent)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
config = json.loads((args.evidence_directory / 'known-original-identities.json').read_text())['second-package']
require(config['whole_bytes'] == 16084731, 'Unexpected original archive length')
require(config['whole_sha256'] == '5f460c4e1e2165b1752d4cc6c5143ef86d483459e7697043573a715ee66da0a2', 'Unexpected original archive digest')
require(len(config['parts']) == 4, 'Exactly four original parts are required')
output = args.output.absolute()
if output.exists() or output.is_symlink():
    raise SystemExit('Output must be a new path')
fd, temporary_name = tempfile.mkstemp(prefix=output.name + '.partial-', dir=output.parent)
temporary = Path(temporary_name)
try:
    total = 0
    whole = hashlib.sha256()
    with os.fdopen(fd, 'wb') as target:
        for number, (blob, length, expected_sha) in enumerate(config['parts'], 1):
            part = args.evidence_directory / 'second-package' / ('final-699de39-evidence.tar.gz.part%04d' % number)
            require(stat.S_ISREG(part.lstat().st_mode) and not part.is_symlink(), 'Part must be a regular file')
            raw = part.read_bytes()
            require(len(raw) == length and hashlib.sha256(raw).hexdigest() == expected_sha, 'Original part length/digest differs')
            require(hashlib.sha1(b'blob ' + str(length).encode() + b'\0' + raw).hexdigest() == blob, 'Original part Git blob differs')
            target.write(raw)
            whole.update(raw)
            total += length
    require((total, whole.hexdigest()) == (config['whole_bytes'], config['whole_sha256']), 'Ordered archive identity differs')
    require(temporary.stat().st_size == total, 'Written archive length differs')
    require(hashlib.sha256(temporary.read_bytes()).hexdigest() == whole.hexdigest(), 'Written archive digest differs')
    os.link(temporary, output)
    temporary.unlink()
    print(json.dumps({'restored_original_package': 'second', 'output': str(output),
                      'bytes': total, 'sha256': whole.hexdigest(), 'extracted': False}))
except BaseException:
    print('Recovery failed; unpromoted temporary bytes retained at ' + str(temporary))
    raise
