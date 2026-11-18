"""Pinned HIA artifact page selection for the ordinary Agent read caller."""
from __future__ import annotations

import ctypes
import struct

from .hia_agent_store import MAX_ARTIFACT_BYTES, _agent_resource_path
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image


SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_read_page.hepta')
SCHEMA = 'hepta.hia.agent-read-page-native.v1'
REQUEST = struct.Struct('<8s2Q')
RESPONSE = struct.Struct('<8s4Q')
END_OF_ARTIFACT = (1 << 64) - 1
MAX_PAGE_BYTES = 65536


class NativeAgentReadPage(NativeHiaJsonImage):
    def read_page(self, artifact, offset, limit):
        if (type(artifact) is not bytes or len(artifact) > MAX_ARTIFACT_BYTES
                or type(offset) is not int or not 0 <= offset < 1 << 63
                or type(limit) is not int or not 0 < limit <= MAX_PAGE_BYTES):
            raise ValueError('outside native HIA Agent artifact page profile')
        header = REQUEST.pack(b'HIAARP01', offset, limit)
        source = ctypes.create_string_buffer(len(header) + len(artifact))
        ctypes.memmove(source, header, len(header))
        ctypes.memmove(ctypes.byref(source, len(header)), artifact, len(artifact))
        output = ctypes.create_string_buffer(RESPONSE.size + 4 * ((limit + 2) // 3))
        width = self._entry(source, len(source), output, len(output), None, 0)
        if not RESPONSE.size <= width <= len(output):
            raise ValueError('native HIA Agent artifact page rejected the input')
        tag, kind, used, next_offset, size = RESPONSE.unpack_from(output)
        if (tag != b'HIAARO01' or kind not in (0, 1) or size + RESPONSE.size != width
                or used > min(limit, max(0, len(artifact) - offset))
                or size != (4 * ((used + 2) // 3) if kind else used)
                or next_offset != (offset + used if offset + used < len(artifact)
                                   else END_OF_ARTIFACT)):
            raise ValueError('invalid native HIA Agent artifact page response')
        encoding, codec = ('base64', 'ascii') if kind else ('utf8', 'utf-8')
        return (encoding, output[RESPONSE.size:width].decode(codec),
                None if next_offset == END_OF_ARTIFACT else next_offset)


def installed_agent_read_page(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentReadPage)
