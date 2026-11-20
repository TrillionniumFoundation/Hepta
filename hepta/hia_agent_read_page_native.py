"""Pinned HIA artifact page selection for the ordinary Agent read caller."""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
import os
import struct
import subprocess

from .hia_agent_store import MAX_ARTIFACT_BYTES, _agent_resource_path, canonical_digest, reject, wire
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image


SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_read_page.hepta')
SCHEMA = 'hepta.hia.agent-read-page-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_READ_PAGE_MANIFEST'
REQUEST = struct.Struct('<8s2Q')
CURSOR_REQUEST = struct.Struct('<8s3Q')
BOUND_REQUEST = struct.Struct('<8s6Q64s')
BOUND_RESPONSE = struct.Struct('<8s3Q')
BOUND_METADATA_BYTES = 1024
RESPONSE = struct.Struct('<8s4Q')
END_OF_ARTIFACT = (1 << 64) - 1
MAX_PAGE_BYTES = 65536
CURSOR_BYTES = 69
MAX_REFERENCE_BYTES = 512


@contextmanager
def capture_retained_page(store, reference, *, bound=False):
    """Transfer verified Store bytes directly to the pager's input file."""
    encoded = wire(reference)
    if not 0 < len(encoded) <= MAX_REFERENCE_BYTES:
        raise ValueError('outside native HIA Agent issued reference profile')
    offset = (BOUND_METADATA_BYTES if bound else CURSOR_REQUEST.size) + len(encoded)
    fd = os.memfd_create('hia-retained-artifact-page', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.ftruncate(fd, offset)
        os.lseek(fd, offset, os.SEEK_SET)
        store.write_retained_artifact(reference, fd)
        size = os.fstat(fd).st_size - offset
        if not 0 <= size <= MAX_ARTIFACT_BYTES:
            raise ValueError('outside native HIA Agent artifact page profile')
        yield fd, size, encoded
    finally:
        os.close(fd)


class NativeAgentReadPage(NativeHiaJsonImage):
    def matches_standalone(self, executable):
        return executable.startswith(b'\x7fELF') and executable.count(self._mapping[:]) == 1

    def read_page(self, artifact, offset, limit):
        return self._read_page(artifact, offset, limit)[:3]

    def read_issued_page(self, artifact, offset, limit, reference):
        """Page an already authenticated stored artifact and bind its next offset."""
        return self._read_page(artifact, offset, limit, reference=wire(reference))

    def read_captured_page(self, capture, offset, limit, executable):
        fd, size, reference = capture
        self._validate_window(size, offset, limit)
        header = CURSOR_REQUEST.pack(b'HIAARC01', offset, limit, len(reference)) + reference
        output = self._captured_page(executable, fd, header)
        return self._decode_page(output, len(output), size, offset, limit,
                                 CURSOR_BYTES, b'HIAARO02')

    def read_captured_bound_page(self, capture, ref, cursor, row, max_bytes, executable):
        """Pass a retained typed Store row directly to the standalone page owner."""
        fd, size, reference = capture
        identity = ref['id'].encode('ascii')
        requested = cursor.encode('utf8') if row is not None else b''
        observed = row if row is not None else b''
        flags = int(max_bytes is not None) | (2 * int(cursor is not None))
        limit = 0 if max_bytes is None else max_bytes
        if type(limit) is not int or not 0 <= limit < 1 << 64:
            limit = (1 << 64) - 1
        header = BOUND_REQUEST.pack(b'HIAARB01', flags, limit, len(reference), len(identity),
                                    len(requested), len(observed), ref['sha256'].encode('ascii'))
        header += identity + requested + observed
        if len(header) > BOUND_METADATA_BYTES:
            raise ValueError('outside native HIA Agent cursor frame profile')
        output = self._captured_page(executable, fd, header.ljust(BOUND_METADATA_BYTES, b'\0') + reference)
        if output == b'HIAARU03' + bytes(32):
            reject('E_HIA_CURSOR', 'cursor is not bound to this exact artifact')
        if len(output) < BOUND_RESPONSE.size + RESPONSE.size:
            raise ValueError('invalid HIA Agent bounded page response')
        tag, offset, limit, retain_size = BOUND_RESPONSE.unpack_from(output)
        if tag != b'HIAARO04' or retain_size not in (0, 277 + len(identity)):
            raise ValueError('invalid HIA Agent bounded page response tag or extent')
        self._validate_window(size, offset, limit)
        end = len(output) - retain_size
        page = output[BOUND_RESPONSE.size:end]
        encoding, content, next_offset, next_cursor = self._decode_page(
            page, len(page), size, offset, limit, CURSOR_BYTES, b'HIAARO02')
        if (next_offset is None) != (retain_size == 0):
            raise ValueError('HIA Agent page omitted its durable cursor frame')
        return encoding, content, next_cursor, output[end:]

    def _captured_page(self, executable, fd, header):
        import fcntl

        if os.pwrite(fd, header, 0) != len(header):
            raise OSError('short write of HIA retained page frame')
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL))
        return self._standalone_page(executable, fd)

    @staticmethod
    def _validate_window(size, offset, limit):
        if (not 0 <= size <= MAX_ARTIFACT_BYTES
                or type(offset) is not int or not 0 <= offset < 1 << 63
                or type(limit) is not int or not 0 < limit <= MAX_PAGE_BYTES):
            raise ValueError('outside native HIA Agent artifact page profile')

    @staticmethod
    def _standalone_page(executable, contents):
        from .hia_scalar_reference_native import sealed_reference_bytes

        with sealed_reference_bytes(executable) as program:
            child = subprocess.run(['/proc/self/fd/' + str(program)], stdin=contents,
                                   pass_fds=(program,), capture_output=True, env={'PATH': ''})
        if child.returncode or child.stderr:
            raise ValueError('standalone HIA Agent artifact page rejected the input')
        return child.stdout

    def _read_page(self, artifact, offset, limit, *, reference=None):
        if type(artifact) is not bytes:
            raise ValueError('outside native HIA Agent artifact page profile')
        self._validate_window(len(artifact), offset, limit)
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

            with sealed_reference_bytes(header, artifact) as contents:
                output = self._standalone_page(executable, contents)
            width = len(output)
        return self._decode_page(output, width, len(artifact), offset, limit, reserved, tag_expected)

    @staticmethod
    def _decode_page(output, width, artifact_size, offset, limit, reserved, tag_expected):
        capacity = RESPONSE.size + reserved + 4 * ((limit + 2) // 3)
        if not RESPONSE.size <= width <= capacity:
            raise ValueError('native HIA Agent artifact page rejected the input')
        tag, kind, used, next_offset, size = RESPONSE.unpack_from(output)
        has_next = next_offset != END_OF_ARTIFACT
        header_size = RESPONSE.size + (reserved if has_next else 0)
        if (tag != tag_expected or kind not in (0, 1) or size + header_size != width
                or used > min(limit, max(0, artifact_size - offset))
                or size != (4 * ((used + 2) // 3) if kind else used)
                or next_offset != (offset + used if offset + used < artifact_size
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
