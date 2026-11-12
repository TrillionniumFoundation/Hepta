"""Explicit source/ABI/bridge/compiler-bound numeric comparison companion.

Selection is captured together with the Core owner for one ordinary emit.
It does not activate by default. Invalid explicit admission fails closed;
foreign/subclass/rebound-target dispatch remains the original outer operation.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path

from . import hia_core_compare_native as primitive
from .hia_json_preflight_native import (
    NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs)

SELECTOR = 'HEPTA_HIA_CORE_COMPARE_MANIFEST'
SCHEMA = 'hepta.hia.core-compare-native.v1'
ABI_SOURCE = 'hepta/hia_core_compare_abi.json'
HIA_SOURCE = 'examples/hia_bootstrap/core_compare.hiaasm'
BRIDGE_SOURCE = 'hepta/hia_core_compare_native.py'
SELECTION_SOURCE = 'hepta/hia_core_compare_selection.py'
SOURCES = {'control': _source_resource_path(HIA_SOURCE)}
MANIFEST_KEYS = {'schema', 'source_sha256', 'abi_sha256', 'bridge_sha256',
                 'selection_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}


def _json(raw):
    return json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def checked_abi(raw):
    value = _json(raw)
    expected = {
        'schema': 'hepta.hia.core-compare-abi.v1', 'protocol': 'HIACMP01',
        'input_bytes': 256, 'output_bytes': 128, 'workspace_bytes': 512,
        'window_limbs': 32, 'limb_bits': 32, 'integer_size_limit': None,
        'integer_descriptor': 'uint64 limb count; scalar bit6 sign, bits0..5 top limb width',
        'relations': {'LT': 0, 'EQ': 1, 'GT': 2, 'UNORDERED': 3},
        'predicates': {'eq': 1, 'ne': 2, 'lt': 3, 'le': 4, 'gt': 5, 'ge': 6},
        'exact_types': ['bool', 'int', 'float'],
        'float_format': 'IEEE-754 binary64 little-endian bit transport',
        'ordinary_Core_images_and_protocol_unchanged': True,
        'CPython_object_runtime_still_hosted': True}
    if (type(value) is not dict or set(value) != set(expected)
            or any(type(value[key]) is not type(item) for key, item in expected.items())
            or any(type(row) is not dict or any(type(number) is not int for number in row.values())
                   for row in (value['relations'], value['predicates']))
            or any(type(item) is not str for item in value['exact_types'])
            or value != expected):
        raise ValueError('native numeric comparison ABI source differs')
    return value


def current_inputs():
    return {
        HIA_SOURCE: _source_resource_path(HIA_SOURCE).read_bytes(),
        ABI_SOURCE: _source_resource_path(ABI_SOURCE).read_bytes(),
        BRIDGE_SOURCE: Path(primitive.__file__).read_bytes(),
        SELECTION_SOURCE: Path(__file__).read_bytes(),
    }


@dataclass(frozen=True)
class _Admitted:
    source_sha256: str
    abi_sha256: str
    bridge_sha256: str
    selection_sha256: str
    image_sha256: str
    compiler_sha256: str
    manifest_sha256: str


def _manifest(raw, source_hashes, compiler_sha):
    value = _json(raw)
    if (type(value) is not dict or set(value) != MANIFEST_KEYS
            or value['schema'] != SCHEMA or value['image_path'] != 'core-compare.image.bin'
            or any(not _digest(value[key]) for key in MANIFEST_KEYS - {'schema', 'image_path'})
            or value['compiler_sha256'] != compiler_sha
            or any(value[field] != source_hashes[relative] for field, relative in (
                ('source_sha256', HIA_SOURCE), ('abi_sha256', ABI_SOURCE),
                ('bridge_sha256', BRIDGE_SOURCE), ('selection_sha256', SELECTION_SOURCE)))):
        raise ValueError('native numeric comparison source/compiler identity differs')
    return value


@lru_cache(maxsize=3)
def _load(path, raw, abi_raw, hashes, compiler_sha):
    sources = dict(hashes)
    checked_abi(abi_raw)
    manifest = _manifest(raw, sources, compiler_sha)
    image_path = Path(path).parent / manifest['image_path']
    with image_path.open('rb') as stream:
        image_raw = stream.read(1048577)
    image = NativeHiaJsonImage(image_raw, manifest['image_sha256'])
    image._bind_manifest_source(manifest['source_sha256'])
    owner = primitive.NativeNumericCompare(image)
    owner._admitted_compare = _Admitted(
        manifest['source_sha256'], manifest['abi_sha256'], manifest['bridge_sha256'],
        manifest['selection_sha256'], manifest['image_sha256'], compiler_sha,
        sha256(raw).hexdigest())
    return owner


def installed_compare(path, compiler_sha):
    if not _digest(compiler_sha):
        raise ValueError('Core compiler identity is required for numeric comparison')
    path = Path(path).resolve(strict=True)
    with path.open('rb') as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError('native numeric comparison manifest exceeds its bound')
    inputs = current_inputs()
    hashes = {name: sha256(data).hexdigest() for name, data in inputs.items()}
    checked_abi(inputs[ABI_SOURCE])
    _manifest(raw, hashes, compiler_sha)
    return _load(str(path), raw, inputs[ABI_SOURCE], tuple(sorted(hashes.items())), compiler_sha)


def selected_compare(compiler_sha):
    path = os.environ.get(SELECTOR)
    return installed_compare(path, compiler_sha) if path else None


def implementation_identity(owner):
    admitted = owner._admitted_compare
    expected = {
        HIA_SOURCE: admitted.source_sha256, ABI_SOURCE: admitted.abi_sha256,
        BRIDGE_SOURCE: admitted.bridge_sha256, SELECTION_SOURCE: admitted.selection_sha256}
    actual = {name: sha256(raw).hexdigest() for name, raw in current_inputs().items()}
    if actual != expected:
        raise ValueError('numeric comparison source changed after scope admission')
    if (owner.image.image_sha256 != admitted.image_sha256
            or owner.image.admitted_source_sha256 != admitted.source_sha256):
        raise ValueError('numeric comparison admitted image identity differs')
    values = [SCHEMA, admitted.manifest_sha256, admitted.compiler_sha256, admitted.image_sha256]
    for name in sorted(expected):
        values.extend((name, expected[name]))
    return '\0'.join(values).encode('ascii')
