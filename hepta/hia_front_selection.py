"""Fresh regular-byte admission of a concrete HIA front image.

Only immutable code is cached. Every independent selection rereads all declared
bytes and performs final readback. Private manifest/image bounds do not change
the accepted program or assembly input domains.
"""
from __future__ import annotations
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
from .hia_json_preflight_native import MAX_IMAGE_BYTES, _unique_manifest_pairs

@dataclass(frozen=True, eq=False)
class Admission:
    owner: object
    checker_owner: object

def _ordinary_opener(path, flags):
    return os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)

def regular_bytes(path, maximum):
    with open(path, 'rb', opener=_ordinary_opener) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError('front admission requires a bounded ordinary file')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode')
    if (len(raw) > maximum or len(raw) != before.st_size
            or any(getattr(before, field) != getattr(after, field) for field in fields)):
        raise ValueError('front admission input changed while being read')
    return raw

@lru_cache(maxsize=6)
def _mapped(factory, image, image_sha256, source_sha256):
    owner = factory(image, image_sha256)
    owner._bind_manifest_source(source_sha256)
    return owner

def admit(manifest_path, source_path, schema, selector, factory):
    from .hia_native_helpers import pinned_image
    pinned = pinned_image(manifest_path, source_path, schema, factory)
    path = Path(manifest_path).resolve(strict=True)
    raw = regular_bytes(path, 16384)
    record = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))
    if (type(record) is not dict or set(record) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or record['schema'] != schema or type(record['image_path']) is not str
            or any(type(record[key]) is not str or len(record[key]) != 64
                   or any(c not in '0123456789abcdef' for c in record[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('front manifest identity differs')
    name = record['image_path']
    if not name or name in ('.', '..') or Path(name).name != name or any(ord(c) < 32 for c in name):
        raise ValueError('front executable must have its sibling basename')
    source = regular_bytes(source_path, MAX_IMAGE_BYTES)
    image_path = (path.parent / name).resolve(strict=True)
    image = regular_bytes(image_path, MAX_IMAGE_BYTES)
    if (sha256(source).hexdigest() != record['source_sha256']
            or sha256(image).hexdigest() != record['image_sha256']):
        raise ValueError('front source or executable identity differs')
    owner = pinned if pinned is not None else _mapped(
        factory, image, record['image_sha256'], record['source_sha256'])
    if (owner.admitted_source_sha256 != record['source_sha256']
            or owner.image_sha256 != record['image_sha256']
            or regular_bytes(path, 16384) != raw
            or regular_bytes(source_path, MAX_IMAGE_BYTES) != source
            or regular_bytes(image_path, MAX_IMAGE_BYTES) != image):
        raise ValueError('front admission inputs changed')
    from .hia_checker_identity import hold_native_owner
    return Admission(owner, hold_native_owner(selector, owner, raw, source))
