"""Read completed evidence into a lossless text capsule; never run project code."""
from pathlib import Path
from hashlib import sha1, sha256
import argparse
import base64
import json
import zlib

def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
        'git_blob_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--workspace', type=Path, required=True)
args = parser.parse_args()
work = args.workspace
result = {'schema': 'hia.front.split.completed-text.v81.r3',
    'scope': 'READ_ONLY_COMPLETED_TEXT_NO_ZIP_CRC_OR_NEW_TEST_CLAIM',
    'files': {}, 'all_file_identities': {}}
if work.exists():
    for path in sorted(work.rglob('*')):
        name = path.relative_to(work).as_posix()
        if name.startswith('source/') or not path.is_file() or path.is_symlink():
            continue
        if name in ('TEXT-CAPSULE.json', 'TEXT-CAPSULE.zlib.json'):
            raise ValueError('completed text capsule already exists')
        raw = path.read_bytes()
        result['all_file_identities'][name] = identity(raw)
        selected = (len(Path(name).parts) <= 3 and name.endswith(('.json', '.log'))
            and '-vm-frame-' not in name and not name.endswith('.source.json')
            and not Path(name).name.startswith(('source-', 'frozen-'))
            and Path(name).name not in ('ARTIFACT-FILES.json', 'BASE.json', 'ORIGINAL-R1-SOURCE-GUARD.json'))
        if selected:
            result['files'][name] = {**identity(raw), 'text': raw.decode('utf-8', 'strict')}
    frozen = work / 'driver-evidence/frozen-runtime-source.json'
    if frozen.exists():
        expected = json.loads(frozen.read_bytes())
        for name in ('examples/hia_bootstrap/core_verification.hiaasm',
                     'examples/hia_bootstrap/assembly_front.hiaasm',
                     'hepta/hia_core_verification_ports.py', 'hepta/hia_assembly_front_ports.py'):
            raw = (work / 'source' / name).read_bytes()
            row = identity(raw)
            if any(expected[name][key] != value for key, value in row.items()):
                raise ValueError('generated file differs from actual frozen source')
            result['files']['complete-generated/' + name] = {**row, 'text': raw.decode('utf-8'),
                'git_mode': expected[name]['git_mode'], 'posix_mode': expected[name]['posix_mode']}
else:
    work.mkdir(parents=True, exist_ok=False)
    result['original_evidence_missing'] = True
raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
packed = zlib.compress(raw, 9)
encoded = base64.b64encode(packed).decode()
capsule = {'schema': 'hia.front.completed-text-zlib.v1', 'payload_identity': identity(raw),
    'compressed_identity': identity(packed), 'base64': encoded}
body = (json.dumps(capsule, sort_keys=True, indent=2) + '\n').encode()
(work / 'TEXT-CAPSULE.json').write_bytes(raw)
(work / 'TEXT-CAPSULE.zlib.json').write_bytes(body)
print('HIA_SPLIT_FRONT_HEADER ' + json.dumps({'capsule': identity(body),
    'payload': identity(raw), 'chunks': (len(encoded) + 15999) // 16000}, sort_keys=True), flush=True)
for index, offset in enumerate(range(0, len(encoded), 16000)):
    print('HIA_SPLIT_FRONT_CHUNK ' + str(index) + ' ' + encoded[offset:offset + 16000], flush=True)
print('HIA_SPLIT_FRONT_COMPLETE ' + sha256(body).hexdigest(), flush=True)
