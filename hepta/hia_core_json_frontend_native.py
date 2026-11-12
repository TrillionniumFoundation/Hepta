"""HIA primitive JSON-Core -> assembly representation, without host parsing.

Output must subsequently pass the native HIA compiler's real semantic checks.
This bridge is not semantic admission, general linking or production activation.
"""
from __future__ import annotations
import ctypes
from pathlib import Path
import struct

from .hia_json_decode_native import arena_sizes
from .hia_json_preflight_native import (NativeHiaJsonImage, _installed_json_image,
    MAX_BYTES, MAX_NODES, MAX_DEPTH)

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/core_json_frontend.hepta')
SCHEMA = 'hepta.hia.core-json-frontend-native.v1'
OUTPUT_LIMIT = 1 << 20


class NativeCoreJsonFrontend(NativeHiaJsonImage):
    def render(self, wire: bytes, *, max_nodes: int = MAX_NODES,
               max_depth: int = MAX_DEPTH, output_profile: str = 'flat') -> bytes:
        if (type(wire) is not bytes or len(wire) > MAX_BYTES
                or type(max_nodes) is not int or not 1 <= max_nodes <= MAX_NODES
                or type(max_depth) is not int or not 0 <= max_depth <= MAX_DEPTH
                or type(output_profile) is not str or output_profile not in ('flat', 'elf', 'exec')):
            raise ValueError('outside HIA JSON Core representation profile')
        workspace_size, key_size = arena_sizes(len(wire), max_nodes, max_depth)
        output_size = max(OUTPUT_LIMIT, key_size)
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(output_size)
        workspace = ctypes.create_string_buffer(workspace_size)
        struct.pack_into('<QQ', workspace, 48, max_nodes, max_depth)
        struct.pack_into('<Q', workspace, 40, ('flat', 'elf', 'exec').index(output_profile))
        result = self._entry(source, len(wire), output, output_size, workspace, workspace_size)
        if result == 0xfffffffe:
            raise OverflowError('HIA JSON Core node/depth budget exceeded')
        if result == 0xfffffffa:
            raise OverflowError('HIA JSON Core assembly exceeds unchanged 1 MiB compiler input')
        if result in (0xffffffff, 0xfffffffc, 0xfffffffb):
            raise ValueError('invalid JSON, duplicate key or outside primitive v8 Core representation')
        if result == 0xfffffffd:
            raise RuntimeError('HIA JSON Core frontend rejected scratch profile')
        if not 0 < result <= OUTPUT_LIMIT:
            raise RuntimeError('invalid HIA JSON Core frontend return')
        return output.raw[:result]


def installed_frontend(manifest_path: str) -> NativeCoreJsonFrontend:
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeCoreJsonFrontend)
