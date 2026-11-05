#!/usr/bin/env python3
"""Verify exact qualification repairs and their original frozen preimages."""
from pathlib import Path
import hashlib
import json

ROOT=Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def blob(data):
    return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()


def project_original(name, data):
    manifest=json.loads((ROOT/'tools/rust_fixture_repairs.json').read_text())
    identity=manifest['files'].get(name)
    if identity is None:
        return data
    if name.startswith('hepta/'):
        raise ValueError('Fixture repairs cannot change production source')
    if digest(data)!=identity['repaired_sha256'] or blob(data)!=identity['repaired_blob']:
        raise ValueError('Repaired qualification source changed: '+name)
    text=data.decode('utf-8')
    last=len(text)
    for edit in reversed(identity['edits']):
        start,end=edit['start'],edit['end']
        if not 0<=start<=end<=last or text[start:end]!=edit['after']:
            raise ValueError('Qualification inverse edit changed: '+name)
        text=text[:start]+edit['before']+text[end:]
        last=start
    restored=text.encode('utf-8')
    if digest(restored)!=identity['original_sha256'] or blob(restored)!=identity['original_blob']:
        raise ValueError('Qualification inverse no longer recovers original: '+name)
    return restored


def verify():
    manifest=json.loads((ROOT/'tools/rust_fixture_repairs.json').read_text())
    recovered={}
    for name in manifest['files']:
        recovered[name]=digest(project_original(name,(ROOT/name).read_bytes()))
    return {'complete_pass':True,'original_commit':manifest['original_commit'],
            'upstream_commit':manifest['upstream_commit'],'recovered_sha256':recovered}


if __name__=='__main__':print(json.dumps(verify(),sort_keys=True))
