"""Private native HIADATA1-to-wire codec; ordinary Agent object APIs are unchanged.

HIA validates the tree, sorts decoded string keys, escapes UTF-8, converts decimal
binary64 spans and prints finite values. Python owns immutable code and buffers.
The producer must be the admitted Agent-data HIA decoder. This ABI does not admit
arbitrary Python objects or replace default decode_data's earlier error order.
"""
from __future__ import annotations

import ctypes
import struct
import sys

from .hia_agent_store import _agent_resource_path
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_program_tools import HIAEditRejected

SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_json_wire.hepta')
SCHEMA = 'hepta.hia.agent-json-wire-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_JSON_WIRE_MANIFEST'
MAX_BYTES = 8 << 20
MAX_NODES = 262144
MAX_DEPTH = 128
MAX_ARENA_BYTES = 64 + MAX_NODES * 56 + MAX_BYTES
PRIVATE_BYTES = 16384
REQUEST_MAGIC = int.from_bytes(b'HIAJWRQ1', 'little')
NONE = (1 << 64) - 1
BAD_ABI = 0xfffffffd
BAD_ARENA = 0xfffffffc
NONFINITE = 0xfffffffb
INTEGER_LIMIT = 0xfffffffa
OUTPUT_LIMIT = 0xfffffff9
DEPTH_LIMIT = 0xfffffff8
STATUSES = frozenset((BAD_ABI, BAD_ARENA, NONFINITE, INTEGER_LIMIT, OUTPUT_LIMIT, DEPTH_LIMIT))


def request_state(wire, arena, int_max_str_digits):
    """Bound allocations and copy opaque producer bytes; no hosted tree admission."""
    if (type(wire) is not bytes or len(wire) > MAX_BYTES
            or type(arena) is not bytes or not 120 <= len(arena) <= MAX_ARENA_BYTES):
        raise ValueError('outside native HIA Agent JSON wire profile')
    limit = sys.get_int_max_str_digits() if int_max_str_digits is None else int_max_str_digits
    if type(limit) is not int or not 0 <= limit <= NONE:
        raise ValueError('invalid private integer digit limit')
    count, = struct.unpack_from('<Q', arena, 8)
    if count > MAX_NODES:
        raise ValueError('outside native HIA Agent JSON wire allocation profile')
    private = len(arena) + count * 8
    state = ctypes.create_string_buffer(private + PRIVATE_BYTES)
    ctypes.memmove(state, arena, len(arena))
    struct.pack_into('<6Q', state, private + 16000, REQUEST_MAGIC, 1, MAX_BYTES, limit, 0, 0)
    return state, private


class NativeAgentJsonWire(NativeHiaJsonImage):
    """Immutable executable, fresh output/tree/numeric workspace on every call."""

    def diagnostic(self, wire: bytes, arena: bytes, *, int_max_str_digits=None):
        state, private = request_state(wire, arena, int_max_str_digits)
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(MAX_BYTES)
        result = self._entry(source, len(wire), output, MAX_BYTES, state, len(state))
        status, failed_node = struct.unpack_from('<2Q', state, private + 16048)
        if 0 < result <= MAX_BYTES:
            if status != 0 or failed_node != NONE:
                raise RuntimeError('invalid native HIA Agent JSON wire success')
            return result, ctypes.string_at(output, result), failed_node
        if result not in STATUSES or result == BAD_ABI or status != result:
            raise RuntimeError('invalid native HIA Agent JSON wire return')
        # No partial native output is exposed on refusal.
        return result, b'', failed_node

    def render_arena(self, wire: bytes, arena: bytes, *, int_max_str_digits=None) -> bytes:
        result, output, _ = self.diagnostic(wire, arena, int_max_str_digits=int_max_str_digits)
        if result <= MAX_BYTES:
            return output
        if result == INTEGER_LIMIT:
            raise HIAEditRejected('E_HIA_EDIT: invalid bounded JSON')
        if result == OUTPUT_LIMIT:
            raise HIAEditRejected('E_HIA_EDIT: JSON encoding exceeds byte budget')
        if result == DEPTH_LIMIT:
            raise HIAEditRejected('E_HIA_EDIT: JSON input exceeds nesting depth before encoding')
        if result == NONFINITE:
            raise ValueError('nonfinite JSON number')
        raise ValueError('invalid native HIA Agent JSON wire arena')

    def render_decoded(self, wire: bytes, decoder, *, int_max_str_digits=None) -> bytes:
        """Private codec composition, not the public decode_data admission API."""
        from .hia_agent_data_json_native import NativeAgentDataJson
        if type(decoder) is not NativeAgentDataJson:
            raise ValueError('actual native HIA Agent-data decoder required')
        arena = decoder.arena(wire, max_nodes=MAX_NODES, max_depth=MAX_DEPTH)
        return self.render_arena(wire, arena, int_max_str_digits=int_max_str_digits)


def installed_agent_json_wire(manifest_path: str) -> NativeAgentJsonWire:
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeAgentJsonWire)
