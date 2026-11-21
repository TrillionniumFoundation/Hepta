"""Move the pinned HIA Worker read plan into the existing Store transport."""

import ctypes
from dataclasses import dataclass
import struct

from .hia_agent_store import _agent_resource_path, wire
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image


SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_read_request.hepta')
SCHEMA = 'hepta.hia.agent-read-request-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_READ_REQUEST_MANIFEST'
HEADER = struct.Struct('<8s7Q64s')
BIND_PAGE = struct.Struct('<8s2Q')
BOUND_METADATA_BYTES = 1024
PLAN_CAPACITY = 8192
WORKSPACE_BYTES = 32768


@dataclass(frozen=True)
class RetainedReadPlan:
    frame: bytes
    reference: bytes
    artifact_query: bytes
    cursor_query: bytes
    admission: bytes

    @property
    def cursor(self):
        return self.cursor_query[56:] if self.cursor_query else None

    @property
    def digest(self):
        return self.admission[24:88].decode('ascii')


class NativeAgentReadRequest(NativeHiaJsonImage):
    def _request(self, raw):
        source = ctypes.create_string_buffer(raw, len(raw))
        output = ctypes.create_string_buffer(PLAN_CAPACITY)
        scratch = ctypes.create_string_buffer(WORKSPACE_BYTES)
        used = self._entry(source, len(raw), output, len(output), scratch, len(scratch))
        if not HEADER.size <= used <= len(output) or source.raw != raw:
            raise ValueError('native HIA retained read plan refused its admitted inputs')
        if any(output.raw[used:]):
            raise ValueError('native HIA retained read plan wrote beyond its extent')
        return output.raw[:used]

    def prepare(self, arguments, catalog_sha256):
        output = self._request(wire(arguments))
        used = len(output)
        tag, flags, limit, ref, artifact, cursor, admission, extent, catalog = HEADER.unpack_from(output)
        if (tag != b'HIAARD01' or flags > 3
                or bool(flags & 1) != ('max_bytes' in arguments)
                or limit != arguments.get('max_bytes', 0)
                or catalog != catalog_sha256.encode('ascii')
                or extent != used or used != HEADER.size + ref + artifact + cursor + admission
                or not 1 <= ref <= 512 or not 57 <= artifact <= 248
                or not (cursor == 0 or 57 <= cursor <= 2104)
                or bool(flags & 2) != bool(cursor)
                or bool(cursor) != ('cursor' in arguments)
                or not 90 <= admission <= 488):
            raise ValueError('invalid HIA retained read plan binding')
        first = HEADER.size
        second = first + ref
        third = second + artifact
        fourth = third + cursor
        return RetainedReadPlan(output, output[first:second], output[second:third],
                                output[third:fourth], output[fourth:used])

    def page_prelude(self, plan, cursor_row):
        row = cursor_row if cursor_row is not None else b''
        payload = BIND_PAGE.pack(b'HIAARP02', len(plan.frame), len(row)) + plan.frame + row
        prelude = self._request(payload)
        if (len(prelude) != BOUND_METADATA_BYTES + len(plan.reference)
                or prelude[BOUND_METADATA_BYTES:] != plan.reference):
            raise ValueError('invalid native HIA bound page prelude')
        return prelude


def installed_agent_read_request(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentReadRequest)
