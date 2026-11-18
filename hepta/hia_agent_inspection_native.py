"""Pinned native exact selector and immutable Core subtree renderer."""
from __future__ import annotations

import ctypes
import struct

from .hia_agent_store import _agent_resource_path, reject
from .hia_json_decode_native import arena_sizes
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_program import MAX_BYTES, MAX_DEPTH, MAX_NODES

SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_inspection.hepta')
SCHEMA = 'hepta.hia.agent-inspection-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_INSPECTION_MANIFEST'
SELECTOR_BYTES = 512
HEADER = struct.Struct('<3Q')
TAIL = HEADER.size + 2 * SELECTOR_BYTES
REFUSALS = {
    4294967288: 'function view requires an exact function',
    4294967289: 'function is not in this program',
    4294967290: 'block is not in this function',
}


class NativeAgentInspection(NativeHiaJsonImage):
    def view(self, canonical_core, view, selector):
        if (type(canonical_core) is not bytes or not 0 < len(canonical_core) <= MAX_BYTES
                or view not in ('function', 'block')):
            raise ValueError('invalid native HIA Agent inspection profile')
        fn = selector.get('function', '').encode('utf-8', 'surrogatepass')
        block = selector.get('block', '').encode('utf-8', 'surrogatepass')
        if len(fn) > SELECTOR_BYTES or len(block) > SELECTOR_BYTES:
            raise ValueError('invalid native HIA Agent inspection selector extent')
        arena_size, parser_size = arena_sizes(len(canonical_core), MAX_NODES, MAX_DEPTH)
        source = ctypes.create_string_buffer(canonical_core)
        output = ctypes.create_string_buffer(max(parser_size, len(canonical_core)))
        arena = ctypes.create_string_buffer(arena_size + TAIL)
        HEADER.pack_into(arena, arena_size, 1 if view == 'function' else 2, len(fn), len(block))
        at = arena_size + HEADER.size
        arena[at:at + len(fn)] = fn
        at += SELECTOR_BYTES
        arena[at:at + len(block)] = block
        width = self._entry(source, len(canonical_core), output, len(output), arena, len(arena))
        if width in REFUSALS:
            reject('E_HIA_SELECTOR', REFUSALS[width])
        if not 0 < width <= len(canonical_core):
            raise ValueError('invalid native HIA Agent inspection reply')
        return output.raw[:width]


def installed_agent_inspection(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentInspection)
