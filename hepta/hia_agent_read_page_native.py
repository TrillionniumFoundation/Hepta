"""Pinned HIA artifact page selection for the ordinary Agent read caller."""
from __future__ import annotations

import ctypes
import struct
import subprocess

from .hia_agent_store import MAX_ARTIFACT_BYTES, _agent_resource_path, canonical_digest, wire
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image


SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_read_page.hepta')
SCHEMA = 'hepta.hia.agent-read-page-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_READ_PAGE_MANIFEST'
REQUEST = struct.Struct('<8s2Q')
CURSOR_REQUEST = struct.Struct('<8s3Q')
RESPONSE = struct.Struct('<8s4Q')
END_OF_ARTIFACT = (1 << 64) - 1
MAX_PAGE_BYTES = 65536
CURSOR_BYTES = 69
MAX_REFERENCE_BYTES = 512


class NativeAgentReadPage(NativeHiaJsonImage):
    def matches_standalone(self, executable):
        return executable.startswith(b'\x7fELF') and executable.count(self._mapping[:]) == 1

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
            workspace_size, reserved, tag_expected = 0, 0, b'HIAARO01'
        else:
            if not 0 < len(reference) <= MAX_REFERENCE_BYTES:
                raise ValueError('outside native HIA Agent issued reference profile')
            header = CURSOR_REQUEST.pack(b'HIAARC01', offset, limit, len(reference)) + reference
            workspace_size = len(reference) + 4128
            reserved, tag_expected = CURSOR_BYTES, b'HIAARO02'
        capacity = RESPONSE.size + reserved + 4 * ((limit + 2) // 3)
        from .hia_native_helpers import pinned_agent_read_page_executable

        executable = pinned_agent_read_page_executable()
        if executable is None:
            source = ctypes.create_string_buffer(len(header) + len(artifact))
            ctypes.memmove(source, header, len(header))
            ctypes.memmove(ctypes.byref(source, len(header)), artifact, len(artifact))
            output = ctypes.create_string_buffer(capacity)
            scratch = ctypes.create_string_buffer(workspace_size) if workspace_size else None
            width = self._entry(source, len(source), output, capacity, scratch, workspace_size)
        else:
            from .hia_scalar_reference_native import sealed_reference_bytes

            with (sealed_reference_bytes(executable) as program,
                  sealed_reference_bytes(header, artifact) as contents):
                child = subprocess.run(['/proc/self/fd/' + str(program)], stdin=contents,
                                       pass_fds=(program,), capture_output=True, env={'PATH': ''})
            if child.returncode or child.stderr:
                raise ValueError('standalone HIA Agent artifact page rejected the input')
            output = child.stdout
            width = len(output)
        if not RESPONSE.size <= width <= capacity:
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
