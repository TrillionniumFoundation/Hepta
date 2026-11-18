"""Pinned HIA artifact page selection for the ordinary Agent read caller."""
from __future__ import annotations

import ctypes
import struct

from .hia_agent_store import MAX_ARTIFACT_BYTES, _agent_resource_path, canonical_digest, wire
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image


SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_read_page.hepta')
SCHEMA = 'hepta.hia.agent-read-page-native.v1'
REQUEST = struct.Struct('<8s2Q')
CURSOR_REQUEST = struct.Struct('<8s3Q')
RESPONSE = struct.Struct('<8s4Q')
END_OF_ARTIFACT = (1 << 64) - 1
MAX_PAGE_BYTES = 65536
CURSOR_BYTES = 69
MAX_REFERENCE_BYTES = 512


class NativeAgentReadPage(NativeHiaJsonImage):
    def read_page(self, artifact, offset, limit):
        return self._read_page(artifact, offset, limit)[:3]

    def read_issued_page(self, artifact, offset, limit, reference):
        """Page an already authenticated stored artifact and bind its next offset."""
        return self._read_page(artifact, offset, limit, reference=wire(reference))

    def _read_page(self, artifact, offset, limit, *, reference=None):
        if (type(artifact) is not bytes or len(artifact) > MAX_ARTIFACT_BYTES
                or type(offset) is not int or not 0 <= offset < 1 << 63
                or type(limit) is not int or not 0 < limit <= MAX_PAGE_BYTES):
            raise ValueError('outside native HIA Agent artifact page profile')
        if reference is None:
            header = REQUEST.pack(b'HIAARP01', offset, limit)
            workspace, reserved, tag_expected = None, 0, b'HIAARO01'
        else:
            if not 0 < len(reference) <= MAX_REFERENCE_BYTES:
                raise ValueError('outside native HIA Agent issued reference profile')
            header = CURSOR_REQUEST.pack(b'HIAARC01', offset, limit, len(reference)) + reference
            workspace = ctypes.create_string_buffer(len(reference) + 4128)
            reserved, tag_expected = CURSOR_BYTES, b'HIAARO02'
        source = ctypes.create_string_buffer(len(header) + len(artifact))
        ctypes.memmove(source, header, len(header))
        ctypes.memmove(ctypes.byref(source, len(header)), artifact, len(artifact))
        output = ctypes.create_string_buffer(RESPONSE.size + reserved + 4 * ((limit + 2) // 3))
        width = self._entry(source, len(source), output, len(output), workspace,
                            len(workspace) if workspace is not None else 0)
        if not RESPONSE.size <= width <= len(output):
            raise ValueError('native HIA Agent artifact page rejected the input')
        tag, kind, used, next_offset, size = RESPONSE.unpack_from(output)
        has_next = next_offset != END_OF_ARTIFACT
        header_size = RESPONSE.size + (reserved if has_next else 0)
        if (tag != tag_expected or kind not in (0, 1) or size + header_size != width
                or used > min(limit, max(0, len(artifact) - offset))
                or size != (4 * ((used + 2) // 3) if kind else used)
                or next_offset != (offset + used if offset + used < len(artifact)
                                   else END_OF_ARTIFACT)):
            raise ValueError('invalid native HIA Agent artifact page response')
        cursor = None
        if has_next and reserved:
            cursor = output[RESPONSE.size:header_size].decode('ascii')
            if not cursor.startswith('page-') or not canonical_digest(cursor[5:]):
                raise ValueError('invalid native HIA Agent artifact cursor')
        encoding, codec = ('base64', 'ascii') if kind else ('utf8', 'utf-8')
        return encoding, output[header_size:width].decode(codec), next_offset if has_next else None, cursor


def installed_agent_read_page(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentReadPage)
