"""Restore retained originals from an exported canonical package into a NEW directory."""
import argparse
import base64
import hashlib
import io
import json
import pathlib
import tarfile

parser = argparse.ArgumentParser()
parser.add_argument('package', type=pathlib.Path)
parser.add_argument('output', type=pathlib.Path)
args = parser.parse_args()
manifest = json.loads((args.package / 'MANIFEST.json').read_bytes())
chunks = []
offset = 0
for pin in manifest['parts']:
    name = pathlib.PurePosixPath(pin['path'])
    if name.is_absolute() or '..' in name.parts or '\\' in str(name):
        raise ValueError('Unsafe package part path')
    raw = (args.package / name).read_bytes()
    if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
        raise ValueError('Part text differs')
    chunk = base64.b64decode(raw.rstrip(b'\n'), validate=True)
    if len(chunk) != pin['decoded_bytes'] or pin['decoded_offset'] != offset \
            or hashlib.sha256(chunk).hexdigest() != pin['decoded_sha256']:
        raise ValueError('Decoded part differs')
    offset += len(chunk)
    chunks.append(chunk)
archive = b''.join(chunks)
if len(archive) != manifest['archive_bytes'] or hashlib.sha256(archive).hexdigest() != manifest['archive_sha256']:
    raise ValueError('Full archive differs')
args.output.mkdir(parents=False, exist_ok=False)
pins = {p['path']: p for p in manifest['original_files']}
seen = set()
with tarfile.open(fileobj=io.BytesIO(archive), mode='r:xz') as tar:
    for entry in tar:
        name = pathlib.PurePosixPath(entry.name)
        if not entry.isfile() or name.is_absolute() or '..' in name.parts or '\\' in entry.name \
                or entry.name in seen or entry.name not in pins:
            raise ValueError('Unexpected archive member')
        data = tar.extractfile(entry).read()
        pin = pins[entry.name]
        if len(data) != pin['bytes'] or hashlib.sha256(data).hexdigest() != pin['sha256'] or entry.mode != pin['mode']:
            raise ValueError('Original payload differs')
        dest = args.output / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open('xb') as stream:
            stream.write(data)
        dest.chmod(entry.mode)
        seen.add(entry.name)
if seen != set(pins):
    raise ValueError('Missing originals')
print(json.dumps({'status': 'RESTORED', 'files': len(seen), 'run_conclusion_preserved': manifest['original_run_conclusion']}))
