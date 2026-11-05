#!/usr/bin/env python3
"""Bind exact #583 reads and the explicit Copy-only adaptation onto #706."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]


def fragments(source):
    start=source.index('        elif k == "index":',source.index('    def value('))
    end=source.index('        elif k == "unary":',start)
    length='                _, expression = self.sequence(arg, lines, allow_temporary=True)\n'
    if source.count(length)!=1:
        raise ValueError('Temporary-array len dispatch changed')
    return {'index_read':source[start:end], 'len_read':length}


def verify(source=None):
    manifest=json.loads((ROOT/'tools/array_adt_source_origins.json').read_text())
    data=(ROOT/'tests/c_array_values_origin.py').read_bytes()
    blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
    if blob!=manifest['origin_test_blob'] or hashlib.sha256(data).hexdigest()!=manifest['origin_test_sha256']:
        raise ValueError('Original array test module changed')
    if source is None:
        source=(ROOT/'hepta/c_backend.py').read_text()
    actual={name:hashlib.sha256(value.encode()).hexdigest() for name,value in fragments(source).items()}
    if actual!=manifest['origin_fragment_sha256']:
        raise ValueError('Original array-read fragments changed')
    adapted=manifest['adapted_sequence'];original=manifest['destination_sequence']
    if source.count(adapted)!=1:
        raise ValueError('Bounded Copy-array sequence adaptation changed')
    restored=source.replace(adapted,original)
    restored=restored.replace(fragments(source)['index_read'],'        elif k == "index":\n            expression = self.place(e, lines)\n')
    restored=restored.replace(fragments(source)['len_read'],'                _, expression = self.sequence(arg, lines)\n')
    if hashlib.sha256(restored.encode()).hexdigest()!=manifest['destination_backend_sha256']:
        raise ValueError('Inverse array-only integration does not recover destination backend')
    return {'complete_pass':True,'origin_commit':manifest['origin_commit'],'destination_commit':manifest['destination_commit'],'test_blob':blob,'fragments':actual,'destination_backend_sha256':manifest['destination_backend_sha256']}


if __name__=='__main__':print(json.dumps(verify(),sort_keys=True))
