#!/usr/bin/env python3
"""Bind the existing ordinary-store edits and recover the exact parent source."""
from pathlib import Path
import hashlib
import json

ROOT=Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def recover():
    manifest=json.loads((ROOT/'tools/store_adt_source_origins.json').read_text())
    for name,identity in manifest['origin_files'].items():
        data=(ROOT/name).read_bytes()
        blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        if blob!=identity['blob'] or sha(data)!=identity['sha256']:
            raise ValueError('Original store source changed: '+name)
    restored={}
    for name,identity in manifest['backends'].items():
        text=(ROOT/name).read_text()
        fragment=identity['origin_fragment']
        if text.count(fragment)!=1:
            raise ValueError('Original store fragment changed: '+name)
        text=text.replace(fragment,identity['destination_fragment'])
        if name=='hepta/c_backend.py':
            new='Effectful nested calls in index operands'
            if text.count(new)!=1:
                raise ValueError('Store diagnostic adaptation changed')
            text=text.replace(new,'Effectful nested calls in index/raw-store operands')
        if sha(text.encode())!=identity['destination_sha256']:
            raise ValueError('Inverse store integration differs from parent: '+name)
        restored[name]=text
    for name,digest in manifest['unchanged_parent_inputs'].items():
        if sha((ROOT/name).read_bytes())!=digest:
            raise ValueError('Inherited source changed: '+name)
    for name,identity in manifest['gate_adapters'].items():
        text=(ROOT/name).read_text()
        for after,before in identity['replacements']:
            if text.count(after)!=1:
                raise ValueError('Inherited gate adaptation changed: '+name)
            text=text.replace(after,before)
        if sha(text.encode())!=identity['destination_sha256']:
            raise ValueError('Inherited gate no longer recovers parent: '+name)
    return restored,manifest


def verify_inherited_arrays():
    import verify_array_adt_sources
    restored,_=recover()
    return verify_array_adt_sources.verify(source=restored['hepta/c_backend.py'])


def verify():
    import verify_numeric_adt_sources
    restored,manifest=recover()
    return {'complete_pass':True,'origin_commit':manifest['origin_commit'],
            'destination_commit':manifest['destination_commit'],
            'recovered_backends':{name:sha(text.encode()) for name,text in restored.items()},
            'unchanged_parent_inputs':len(manifest['unchanged_parent_inputs']),
            'arrays':verify_inherited_arrays(),'numeric':verify_numeric_adt_sources.verify()}


if __name__=='__main__':print(json.dumps(verify(),sort_keys=True))
