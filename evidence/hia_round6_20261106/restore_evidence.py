"""Reassemble the checked evidence archive from adjacent Git-tracked parts."""
from pathlib import Path
import argparse
import hashlib
import json
import os

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent
index = json.loads((root / 'EVIDENCE_ARCHIVE.json').read_bytes())
output = args.output.resolve()
output.parent.mkdir(parents=True, exist_ok=True)
temporary = output.with_name(output.name + '.assembling')
digest = hashlib.sha256()
size = 0
with temporary.open('xb') as destination:
    for part in index['parts']:
        relative = Path(part['path'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('invalid part path')
        data = (root / relative).read_bytes()
        if len(data) != part['bytes'] or hashlib.sha256(data).hexdigest() != part['sha256']:
            raise ValueError('part identity mismatch: ' + str(relative))
        destination.write(data)
        digest.update(data)
        size += len(data)
if size != index['archive_bytes'] or digest.hexdigest() != index['archive_sha256']:
    raise ValueError('assembled archive identity mismatch; temporary file retained')
# Link creation refuses an existing destination, including a concurrent writer.
os.link(temporary, output)
temporary.unlink()
print(json.dumps({'output': str(output), 'bytes': size, 'sha256': digest.hexdigest()}))
