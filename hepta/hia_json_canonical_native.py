"""Explicit HIA JSON wire-to-canonical-wire code; no foreign value graph.

Only the integer/string/bool/null HIA JSON subset is admitted. Integer lexemes
are normalized without host big integers; this library is not a general JSON
floating-number encoder, Python object serializer, semantic Core checker or
runtime rewrite. UTF-8 wire, node and root-depth limits are explicit.
"""
from __future__ import annotations
import ctypes
import os
from pathlib import Path
import struct

from .hia_json_decode_native import arena_sizes
from .hia_json_preflight_native import (NativeHiaJsonImage, _installed_json_image,
    MAX_BYTES, MAX_NODES, MAX_DEPTH)

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/json_canonical.hepta')
SCHEMA = 'hepta.hia.json-canonical-native.v1'


class NativeJsonCanonicalizer(NativeHiaJsonImage):
    def canonicalize(self, wire: bytes, *, max_nodes: int, max_depth: int) -> bytes:
        if (type(wire) is not bytes or len(wire) > MAX_BYTES
                or type(max_nodes) is not int or not 1 <= max_nodes <= MAX_NODES
                or type(max_depth) is not int or not 0 <= max_depth <= MAX_DEPTH):
            raise ValueError('outside native HIA JSON canonical profile')
        arena_size, key_size = arena_sizes(len(wire), max_nodes, max_depth)
        # Canonical UTF-8 spelling cannot exceed the accepted input length:
        # syntax whitespace/escape spellings can only shrink, key sorting does
        # not change size, and the only integer spelling change is -0 -> 0.
        output_size = max(len(wire), key_size)
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(output_size)
        workspace = ctypes.create_string_buffer(arena_size)
        struct.pack_into('<QQ', workspace, 48, max_nodes, max_depth)
        result = self._entry(source, len(wire), output, output_size, workspace, arena_size)
        if result == 0xfffffffe:
            raise OverflowError('HIA JSON exceeds node/depth budget before canonicalization')
        if result == 0xfffffffc:
            raise ValueError('HIA JSON canonicalizer: duplicate decoded object key')
        if result == 0xffffffff:
            raise ValueError('HIA JSON canonicalizer: invalid JSON syntax or Unicode')
        if result == 0xfffffffd:
            raise RuntimeError('native HIA JSON canonicalizer rejected its scratch profile')
        if not 0 < result <= min(len(wire), output_size):
            raise RuntimeError('invalid native HIA JSON canonical return')
        return output.raw[:result]


def installed_canonicalizer(manifest_path: str) -> NativeJsonCanonicalizer:
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeJsonCanonicalizer)


def selected_canonical_wire(text: str, *, max_nodes: int, max_depth: int) -> bytes | None:
    """Return None when unselected/outside profile, never after a selected error.

    This is called only after existing Core structure checks. It does not
    bypass their foreign integer limits, validate receipts or select code from
    submitted payloads. The default encoder stays unchanged when unselected.
    """
    path = os.environ.get('HEPTA_HIA_JSON_CANONICAL_MANIFEST')
    if not path or not 1 <= max_nodes <= MAX_NODES or not 0 <= max_depth <= MAX_DEPTH:
        return None
    wire = text.encode('utf-8')
    if len(wire) > MAX_BYTES:
        return None
    return installed_canonicalizer(path).canonicalize(wire, max_nodes=max_nodes, max_depth=max_depth)
