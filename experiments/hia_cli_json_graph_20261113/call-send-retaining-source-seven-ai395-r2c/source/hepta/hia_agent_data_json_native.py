"""Explicit native Agent-data syntax/tree decoder with a hosted value bridge.

Unlike Core's integer JSON protocol, tag 7 preserves fractional/exponent number
lexemes. HIA owns grammar, UTF-8, duplicate keys, hierarchy and node/depth gates.
Python owns code/buffer custody and objects. Decimal conversion is hosted unless
the independent HEPTA_HIA_AGENT_BINARY64_MANIFEST image is explicitly selected.
"""
import math
import os
import struct
from .hia_agent_store import _agent_resource_path
from .hia_json_decode_native import NativeJsonDecoder, HEADER, RECORD, MAGIC as INTEGER_MAGIC, materialize
from .hia_json_preflight_native import MAX_NODES, _installed_json_image

SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_data_json.hiaasm')
SCHEMA = 'hepta.hia.agent-data-json-native.v1'
MAGIC = int.from_bytes(b'HIADATA1', 'little')
SELECTOR = 'HEPTA_HIA_AGENT_DATA_JSON_MANIFEST'


def finite_float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError('nonfinite JSON number')
    return value


def materialize_data(arena, wire, *, parse_float=None):
    """Bridge an already decoded arena, not JSON text syntax.

    Keep the integer protocol disjoint; the original Core decoder never accepts
    the new magic/tag. Shared tree/ownership validation remains mandatory.
    """
    def invalid():
        raise ValueError('invalid HIA Agent-data JSON arena')
    if type(arena) is not bytes or len(arena) < 64 or type(wire) is not bytes:
        invalid()
    magic, count, base, end, used, size, version, reserved = HEADER.unpack_from(arena)
    if (magic != MAGIC or not 1 <= count <= MAX_NODES or base != 64 + count * 56
            or not base <= end == used == len(arena) or size != len(wire)
            or version != 1 or reserved):
        invalid()
    translated = bytearray(arena)
    struct.pack_into('<Q', translated, 0, INTEGER_MAGIC)
    for index in range(count):
        at = 64 + index * 56
        kind, _, _, start, length, _, _ = RECORD.unpack_from(arena, at)
        if kind > 7:
            invalid()
        if kind in (3, 7):
            if start > len(wire) or not 1 <= length <= len(wire) - start:
                invalid()
            fractional = any(c in b'.eE' for c in wire[start:start + length])
            if fractional != (kind == 7):
                invalid()
            if kind == 7:
                struct.pack_into('<Q', translated, at, 3)
    floating = finite_float if parse_float is None else parse_float
    if parse_float is None:
        selected = os.environ.get('HEPTA_HIA_AGENT_BINARY64_MANIFEST')
        if selected:
            from .hia_agent_binary64_native import installed_agent_binary64
            floating = installed_agent_binary64(selected).convert
    def number(text):
        return floating(text) if any(c in text for c in '.eE') else int(text)
    # Release the mutable translation before building the foreign graph; three
    # complete arena copies need not coexist with the maximum-node object tree.
    translated = bytes(translated)
    return materialize(translated, wire, parse_int=number)


class NativeAgentDataJson(NativeJsonDecoder):
    def decode(self, wire, *, max_nodes=262144, max_depth=128, parse_float=None):
        try:
            arena = self.arena(wire, max_nodes=max_nodes, max_depth=max_depth)
        except OverflowError as exc:
            # Agent's previous structural preflight uses ValueError, not an
            # arithmetic overflow exception, for structural budget refusal.
            raise ValueError('HIA JSON preflight: node/depth budget exceeded') from exc
        return materialize_data(arena, wire, parse_float=parse_float)


def installed_agent_data_json(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentDataJson)
