"""Explicit source/ABI/bridge/compiler-bound exact integer companion.

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

from . import hia_core_integer_native as primitive
from .hia_json_preflight_native import (
    NativeHiaJsonImage, _source_resource_path, _unique_manifest_pairs)

SELECTOR = 'HEPTA_HIA_CORE_INTEGER_MANIFEST'
SCHEMA = 'hepta.hia.core-integer-native.v1'
ABI_SOURCE = 'hepta/hia_core_integer_abi.json'
HIA_SOURCE = 'examples/hia_bootstrap/core_integer.hiaasm'
BRIDGE_SOURCE = 'hepta/hia_core_integer_native.py'
SELECTION_SOURCE = 'hepta/hia_core_integer_selection.py'
SOURCES = {'control': _source_resource_path(HIA_SOURCE)}
MANIFEST_KEYS = {'schema', 'source_sha256', 'abi_sha256', 'bridge_sha256',
                 'selection_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}


def _json(raw):
    return json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def _same_typed_value(actual, expected):
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return (set(actual) == set(expected)
                and all(_same_typed_value(actual[key], value) for key, value in expected.items()))
    if type(expected) is list:
        return (len(actual) == len(expected)
                and all(_same_typed_value(left, right) for left, right in zip(actual, expected)))
    return actual == expected


def checked_abi(raw):
    value = _json(raw)
    expected = {'schema': 'hepta.hia.core-integer-abi.v1',
     'protocol': 'HIAINT01',
     'input_bytes': 256,
     'output_bytes': 256,
     'workspace_bytes': 640,
     'header_bytes': 128,
     'limb_bits': 32,
     'window_limbs': 32,
     'operations': {'ADD': 1, 'SUB': 2, 'NEG': 3, 'INVERT': 4},
     'entry_statuses': {'DONE': 0, 'READ': 1, 'WRITE': 2, 'REFUSAL': 4294967293},
     'integer_value_policy_cap': None,
     'descriptor': 'comparison-compatible exact-int (kind=2, magnitude_limb_count, sign_bit6 | '
                   'top_limb_width)',
     'representable_input_limb_max': 4611686018427387902,
     'representable_limit_reason': '(max_operand_words+1)*4 and all byte offsets must fit u64; not a '
                                   'new value-domain policy limit',
     'result': "HIA-generated little-endian two's-complement bytes; one extra full output word; DONE "
               'chooses exact minimal signed-byte extent',
     'INIT_input_header': ['magic',
                           '0',
                           '0',
                           'operation',
                           'left_kind',
                           'left_words',
                           'left_sign_top',
                           'right_kind',
                           'right_words',
                           'right_sign_top',
                           'zero[6]'],
     'READ_output_header': ['magic', 'sequence', '1', 'side', 'start_words', 'count_words', 'zero[10]'],
     'READ_ACK_input_header': ['magic',
                               '1',
                               'sequence',
                               'side',
                               'start_words',
                               'count_words',
                               'zero[10]'],
     'WRITE_output_header': ['magic', 'sequence', '2', 'start_words', 'count_words', 'zero[11]'],
     'WRITE_ACK_input_header': ['magic', '2', 'sequence', 'start_words', 'count_words', 'zero[11]'],
     'DONE_output_header': ['magic',
                            'sequence',
                            '0',
                            'operation',
                            'canonical_bytes',
                            'emitted_words',
                            'negative',
                            'emitted_bytes',
                            'zero[8]'],
     'READ_ACK_payload': 'count_words*4 source bytes then zero padding to 128 bytes',
     'WRITE_payload': 'count_words*4 result bytes then zero padding to 128 bytes',
     'other_payloads': 'all 128 bytes zero',
     'exact_types': ['int'],
     'bool_subclass_float_foreign_and_inplace': 'retained original target dispatch; never silently '
                                                'coerced to int',
     'ordinary_Core_packet_bytes_unchanged': 128,
     'ordinary_Core_images_unchanged': True,
     'Python_object_registry_allocation_materialization_and_refcount_still_hosted': True,
     'status': 'OPTIONAL_CORE_COMPANION_DEVELOPMENT'}
    if not _same_typed_value(value, expected):
        raise ValueError('native exact integer ABI source differs')
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
            or value['schema'] != SCHEMA or value['image_path'] != 'core-integer.image.bin'
            or any(not _digest(value[key]) for key in MANIFEST_KEYS - {'schema', 'image_path'})
            or value['compiler_sha256'] != compiler_sha
            or any(value[field] != source_hashes[relative] for field, relative in (
                ('source_sha256', HIA_SOURCE), ('abi_sha256', ABI_SOURCE),
                ('bridge_sha256', BRIDGE_SOURCE), ('selection_sha256', SELECTION_SOURCE)))):
        raise ValueError('native exact integer source/compiler identity differs')
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
    owner = primitive.NativeInteger(image)
    owner._admitted_integer = _Admitted(
        manifest['source_sha256'], manifest['abi_sha256'], manifest['bridge_sha256'],
        manifest['selection_sha256'], manifest['image_sha256'], compiler_sha,
        sha256(raw).hexdigest())
    return owner


def installed_integer(path, compiler_sha):
    if not _digest(compiler_sha):
        raise ValueError('Core compiler identity is required for exact integer')
    path = Path(path).resolve(strict=True)
    with path.open('rb') as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError('native exact integer manifest exceeds its bound')
    inputs = current_inputs()
    hashes = {name: sha256(data).hexdigest() for name, data in inputs.items()}
    checked_abi(inputs[ABI_SOURCE])
    _manifest(raw, hashes, compiler_sha)
    return _load(str(path), raw, inputs[ABI_SOURCE], tuple(sorted(hashes.items())), compiler_sha)


def selected_integer(compiler_sha):
    path = os.environ.get(SELECTOR)
    return None if path is None else installed_integer(path, compiler_sha)


def implementation_identity(owner):
    admitted = owner._admitted_integer
    expected = {
        HIA_SOURCE: admitted.source_sha256, ABI_SOURCE: admitted.abi_sha256,
        BRIDGE_SOURCE: admitted.bridge_sha256, SELECTION_SOURCE: admitted.selection_sha256}
    actual = {name: sha256(raw).hexdigest() for name, raw in current_inputs().items()}
    if actual != expected:
        raise ValueError('exact integer source changed after scope admission')
    if (owner.image.image_sha256 != admitted.image_sha256
            or owner.image.admitted_source_sha256 != admitted.source_sha256):
        raise ValueError('exact integer admitted image identity differs')
    values = [SCHEMA, admitted.manifest_sha256, admitted.compiler_sha256, admitted.image_sha256]
    for name in sorted(expected):
        values.extend((name, expected[name]))
    return '\0'.join(values).encode('ascii')
