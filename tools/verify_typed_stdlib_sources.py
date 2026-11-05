#!/usr/bin/env python3
"""Bind the untouched compiler parent and exact source-library components."""
import hashlib
import json
from pathlib import Path
from verify_typed_fixture_repairs import project_original, verify as verify_fixture_repairs
ROOT=Path(__file__).resolve().parents[1]

def verify(root=ROOT):
    verify_fixture_repairs(root)
    manifest=json.loads((root/'tools/typed_stdlib_components.json').read_bytes())
    if manifest['base_commit']!='b45d6621b0435dd8da4aabf87250b275dbe03927' or manifest['library_supplier_commit']!='653b508336a470151b94f5e1c0448654c4782030':
        raise ValueError('Unexpected suppliers')
    if len(manifest['unchanged_base'])!=168 or len(manifest['library_components'])!=35:
        raise ValueError('Incomplete supplier inventory')
    def check(path, expected):
        data=project_original(path,(root/path).read_bytes(),root)
        actual={'git_blob':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),'sha256':hashlib.sha256(data).hexdigest()}
        if actual!={k:expected[k] for k in actual}:
            raise ValueError('Changed supplier: '+path)
    for field in ('unchanged_base','library_components'):
        for path,expected in manifest[field].items():check(path,expected)
    entry=manifest['packet_origin'];check(entry['path'],entry)
    return {'complete_pass':True,'base':manifest['base_commit'],'library_supplier':manifest['library_supplier_commit'],
            'unchanged_base_files':168,'unchanged_library_components':35,'unchanged_packet':entry['git_blob']}

if __name__=='__main__':print(json.dumps(verify(),sort_keys=True))
