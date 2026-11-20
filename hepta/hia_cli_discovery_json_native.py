"""Explicit immutable-source discovery JSON image and its mechanical byte ABI.

The HIA image selects the version, filters fields, sorts metadata, constructs
pretty and canonical JSON, and computes the catalog SHA. This module does not
construct JSON values or call the retained capabilities/catalog implementations.
It does not replace the ordinary CLI or its arbitrary mutable Python providers.
"""
from __future__ import annotations

import ctypes
from functools import lru_cache
from hashlib import sha256
import json
from pathlib import Path
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path

SOURCE_NAME = 'examples/hia_bootstrap/cli_discovery_json.hepta'
SOURCE = _source_resource_path(SOURCE_NAME)
SCHEMA = 'hepta.hia.cli-discovery-json-native.v1'
MAGIC = int.from_bytes(b'HCLJSON1', 'little')
WORK_BYTES = 131072
JSON_BYTES = 65536
CAPACITY = 1048576
REFUSALS = {
    0xffffffff: 'invalid discovery request frame',
    0xfffffffe: 'discovery output is too short',
    0xfffffffd: 'discovery requires an exact primitive schema',
    0xfffffffc: 'discovery workspace is too short',
    0xfffffffb: 'discovery static metadata bound was exceeded',
}


class DiscoveryRefused(ValueError):
    """An actual HIA refusal, not an original CLI parser diagnostic."""
    def __init__(self, status):
        self.status = status
        super().__init__(REFUSALS[status])


def request(operation, schema=None):
    """Pack fields only; validation/default selection remain in HIA.

    ``schema`` is exact bytes or None in this new buffer API. It is not the
    pre-existing opcode_catalog Python-object API and makes no claim about
    custom mapping keys, mutated metadata objects, or replacement callbacks.
    """
    if type(operation) is not int or not 0 <= operation < 1 << 64:
        raise TypeError('discovery operation must be an exact u64')
    if schema is not None and type(schema) is not bytes:
        raise TypeError('discovery schema must be exact bytes or None')
    payload = b'' if schema is None else schema
    if len(payload) > CAPACITY - 32:
        raise ValueError('discovery request exceeds the fixed buffer profile')
    return struct.pack('<4Q', MAGIC, operation, int(schema is not None), len(payload)) + payload


class NativeCliDiscoveryJson(NativeHiaJsonImage):
    """Pinned executable, distinct buffers for every invocation, no fallback."""
    def observe(self, wire, *, output_bytes=JSON_BYTES, workspace_bytes=WORK_BYTES,
                output_fill=0, workspace_fill=0):
        if (type(wire) is not bytes or len(wire) > CAPACITY
                or any(type(value) is not int or not 0 <= value <= CAPACITY
                       for value in (output_bytes, workspace_bytes))
                or any(type(value) is not int or not 0 <= value <= 255
                       for value in (output_fill, workspace_fill))):
            raise ValueError('outside the discovery byte-buffer ABI')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(bytes([output_fill]) * output_bytes, max(1, output_bytes))
        workspace = ctypes.create_string_buffer(bytes([workspace_fill]) * workspace_bytes,
                                               max(1, workspace_bytes))
        result = self._entry(source, len(wire), output, output_bytes, workspace, workspace_bytes)
        if bytes(source.raw[:len(wire)]) != wire:
            raise RuntimeError('discovery image modified its read-only input')
        if (type(result) is not int or result > 0xffffffff
                or result not in REFUSALS and result > output_bytes):
            raise RuntimeError('invalid discovery HIA return')
        return result, bytes(output.raw[:output_bytes]), bytes(workspace.raw[:workspace_bytes])

    def render(self, wire):
        result, output, _workspace = self.observe(wire)
        if result in REFUSALS:
            raise DiscoveryRefused(result)
        return output[:result]

    def capabilities_json(self):
        return self.render(request(1))

    def catalog_json(self, schema=None):
        return self.render(request(2, schema))


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate discovery manifest field')
        value[key] = item
    return value


def _manifest(raw, source_sha):
    def constant(_value):
        raise ValueError('nonfinite discovery manifest value')
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=constant)
    if (type(value) is not dict or set(value) != {'schema', 'source_sha256', 'image_path',
            'image_sha256', 'compiler_sha256'} or value['schema'] != SCHEMA
            or any(type(value[name]) is not str or len(value[name]) != 64
                   or any(c not in '0123456789abcdef' for c in value[name])
                   for name in ('source_sha256', 'image_sha256', 'compiler_sha256'))
            or value['source_sha256'] != source_sha
            or type(value['image_path']) is not str or not value['image_path']
            or Path(value['image_path']).name != value['image_path']
            or value['image_path'] in ('.', '..')):
        raise ValueError('invalid or stale discovery manifest')
    return value


@lru_cache(maxsize=3)
def _captured(image, source_sha, image_sha):
    owner = NativeCliDiscoveryJson(image, image_sha)
    owner.admitted_source_sha256 = source_sha
    return owner


def installed_cli_discovery_json(manifest_path):
    """Fresh source, manifest, and image readback precede every selection.

    Source comes from this checkout or this package's own _data. A selected
    missing/drifted resource cannot choose the retained Python implementation.
    Held owners retain their captured immutable image independently of disk.
    """
    from . import hia_native_helpers
    selected = hia_native_helpers.pinned_image(
        manifest_path, SOURCE, SCHEMA, NativeCliDiscoveryJson)
    if selected is not None:
        return selected
    path = Path(manifest_path).resolve(strict=True)
    source = SOURCE.read_bytes()
    source_sha = sha256(source).hexdigest()
    with path.open('rb') as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError('discovery manifest exceeds its fixed bound')
    value = _manifest(raw, source_sha)
    image_path = path.parent / value['image_path']
    with image_path.open('rb') as stream:
        image = stream.read(CAPACITY + 1)
    if not image or len(image) > CAPACITY or sha256(image).hexdigest() != value['image_sha256']:
        raise ValueError('discovery executable bytes differ from the selected manifest')
    if SOURCE.read_bytes() != source or path.read_bytes() != raw or image_path.read_bytes() != image:
        raise ValueError('discovery source or publication changed during selection')
    owner = _captured(image, source_sha, value['image_sha256'])
    if (owner.image_sha256 != value['image_sha256']
            or owner.admitted_source_sha256 != source_sha):
        raise ValueError('discovery captured owner identity changed')
    return owner
