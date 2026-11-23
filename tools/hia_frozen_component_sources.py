"""Reconstruct reviewed component inputs from complete, hash-bound physical sources."""
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path


FIXTURE = 'tests/fixtures/hia_frozen_component_source_relations.json'
FIXTURE_SHA256 = 'ad1b83e1db693e7ebef817781b23116393712f65d23c308209508e4ac65a3bcc'


@lru_cache(maxsize=1)
def _relations(raw):
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError('frozen component source relation changed')
    return json.loads(raw)['files']


def reviewed_source(root, name, raw, *, take=Path.read_bytes):
    relation = _relations(take(root / FIXTURE)).get(name)
    if relation is None:
        return raw
    actual = sha256(raw).hexdigest()
    if actual == relation['reviewed_sha256']:
        return raw
    if actual != relation['physical_sha256']:
        raise ValueError('unreviewed physical component source: ' + name)
    restored = bytearray()
    end = 0
    for at, size, original in relation['splices']:
        if not end <= at <= at + size <= len(raw):
            raise ValueError('overlapping component source splice: ' + name)
        restored.extend(raw[end:at])
        restored.extend(original.encode('utf-8'))
        end = at + size
    restored.extend(raw[end:])
    if sha256(restored).hexdigest() != relation['reviewed_sha256']:
        raise ValueError('complete reviewed component source differs: ' + name)
    return bytes(restored)
