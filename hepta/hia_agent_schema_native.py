"""Pinned native admission against the existing Agent input schemas."""
from __future__ import annotations

import ctypes
import struct

from .hia_agent_store import MAX_INPUT_BYTES, _agent_resource_path, canonical_digest, wire
from .hia_json_decode_native import arena_sizes
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image


SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_schema.hepta')
SCHEMA = 'hepta.hia.agent-schema-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_SCHEMA_MANIFEST'



class NativeAgentSchema(NativeHiaJsonImage):
    def accepts(self, arguments, role, catalog_digest):
        return self.accepts_wire(wire(arguments), role, catalog_digest)

    def accepts_wire(self, raw, role, catalog_digest):
        if type(role) is not int or role < 1 or not canonical_digest(catalog_digest):
            raise ValueError('invalid native Agent catalog binding')
        if type(raw) is not bytes or len(raw) > MAX_INPUT_BYTES:
            raise ValueError('invalid native Agent schema payload')
        arena_size, parser_size = arena_sizes(len(raw), 262144, 128)
        source = ctypes.create_string_buffer(raw)
        parser = ctypes.create_string_buffer(parser_size)
        arena = ctypes.create_string_buffer(max(128, arena_size) + 8192)
        struct.pack_into('<Q64s', arena, 0, role, catalog_digest.encode('ascii'))
        result = self._entry(source, len(raw), parser, len(parser), arena, len(arena))
        if result not in (0, 1):
            raise ValueError('native Agent schema could not authenticate or decode input')
        return result == 0


def installed_agent_schema(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentSchema)
