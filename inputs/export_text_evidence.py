"""Publish completed evidence text to logs; never import or execute project code."""
from __future__ import annotations
import argparse
import base64
from hashlib import sha1, sha256
import json
from pathlib import Path
import zlib

def identity(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output
    result = {'schema': 'hia.public-front.completed-text-capsule.v80.r1',
              'scope': 'READ_ONLY_COMPLETED_FILES_NO_ARCHIVE_OR_QUALIFICATION_CLAIM',
              'files': {}, 'all_file_identities': {}}
    if out.exists():
        for path in sorted(out.rglob('*')):
            if not path.is_file() or path.is_symlink():
                continue
            name = path.relative_to(out).as_posix()
            if name in ('TEXT-CAPSULE.json', 'TEXT-CAPSULE.zlib.json'):
                raise ValueError('text evidence already exists')
            raw = path.read_bytes()
            result['all_file_identities'][name] = identity(raw)
            parts = Path(name).parts
            selected = (len(parts) <= 2 and name.endswith(('.json', '.log')))
            if (name.endswith('.source.json') or name.startswith('source-')) and not name.endswith('.log'):
                selected = False
            if name.endswith('/source-before.json') or name.endswith('/source-after.json'):
                selected = False
            if name == 'ARTIFACT-FILES.json':
                selected = False
            if selected:
                result['files'][name] = dict(identity(raw), text=raw.decode('utf-8', 'strict'))
        frozen = out / 'frozen-source.json'
        if frozen.is_file():
            manifest = json.loads(frozen.read_bytes())
            for name in ('examples/hia_bootstrap/public_front.hiaasm',
                         'hepta/hia_public_front_ports.py'):
                path = args.source / name
                raw = path.read_bytes()
                expected = manifest[name]
                observed = identity(raw)
                if any(observed[key] != expected[key] for key in observed):
                    raise ValueError('generated source no longer matches frozen bytes')
                result['files']['complete-source/' + name] = dict(observed,
                    text=raw.decode('utf-8', 'strict'), git_mode=expected['git_mode'],
                    posix_mode=expected['posix_mode'])
    else:
        out.mkdir(parents=True, exist_ok=False)
        result['original_evidence_missing'] = True
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    payload = base64.b64encode(zlib.compress(raw, 9)).decode('ascii')
    capsule = {'schema': 'hia.zlib-source-capsule.v1', 'encoding': 'zlib+base64',
               'source_packet': dict(identity(raw), mode='100644'), 'payload': payload}
    body = (json.dumps(capsule, sort_keys=True, indent=2) + '\n').encode()
    (out / 'TEXT-CAPSULE.json').write_bytes(raw)
    (out / 'TEXT-CAPSULE.zlib.json').write_bytes(body)
    header = {'capsule': identity(body), 'packet': identity(raw),
              'payload_chars': len(payload), 'chunks': (len(payload) + 15999) // 16000}
    print('HIA_PUBLIC_FRONT_R1_HEADER ' + json.dumps(header, sort_keys=True), flush=True)
    for index, start in enumerate(range(0, len(payload), 16000)):
        print('HIA_PUBLIC_FRONT_R1_CHUNK ' + str(index) + ' ' + payload[start:start + 16000], flush=True)
    print('HIA_PUBLIC_FRONT_R1_COMPLETE ' + sha256(body).hexdigest(), flush=True)

if __name__ == '__main__':
    main()
