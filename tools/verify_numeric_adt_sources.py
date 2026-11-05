#!/usr/bin/env python3
"""Verify exact numeric-only source transplants from published PR #579."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]


def fragments(source):
    a = source.index('        elif k == "cast":')
    b = source.index('        elif k == "call":', a)
    c = source.index('        if self.float_casts:')
    d = source.index('        return "\\n".join(lines)', c)
    state = '        self.float_casts = set()\n        self.float_conversions = set()\n'
    if source.count(state) != 1:
        raise ValueError('Numerical state initialization changed')
    return {'cast_dispatch': source[a:b], 'numeric_helpers': source[c:d], 'state': state}


def verify():
    manifest = json.loads((ROOT/'tools/numeric_adt_source_origins.json').read_text())
    checked = {}
    for name, identity in manifest['files'].items():
        data = (ROOT/name).read_bytes()
        blob = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        if blob != identity['git_blob'] or hashlib.sha256(data).hexdigest() != identity['sha256']:
            raise ValueError('Source transplant changed: '+name)
        checked[name] = blob
    code = (ROOT/'hepta/c_backend.py').read_text()
    actual = {name: hashlib.sha256(value.encode()).hexdigest() for name,value in fragments(code).items()}
    expected = {name: value['sha256'] for name,value in manifest['fragments'].items()}
    if actual != expected:
        raise ValueError('Numeric lowering fragments differ from the published origin')
    return {'complete_pass': True, 'origin_commit': manifest['origin_commit'], 'files': checked, 'fragments': actual}


if __name__ == '__main__':
    print(json.dumps(verify(),sort_keys=True))
