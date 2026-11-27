"""Byte transport for the independently tested HIA JSON layout component.

The caller must supply admitted compact UTF-8 JSON bytes. This component is a
layout formatter, not a JSON decoder, graph serializer or CLI output policy.
It preserves lexical bytes, inserts two-space layout and appends no newline.
The HIA image retains its original 8 MiB input and 129-entry stack profile.
Output is allocated from the successful HIA measurement; it has no 8 MiB cap.

Package resources carry the HIA source used for local manifest admission.
This byte-only API is separate from the existing CLI graph/text output policy.
"""
from __future__ import annotations

import ctypes
import struct
import sys

from .hia_json_preflight_native import (
    NativeHiaJsonImage, _installed_json_image, _source_resource_path,
)

SOURCE = _source_resource_path('examples/hia_bootstrap/json_pretty.hiaasm')
SCHEMA = 'hepta.hia.json-pretty-native.v1'
WORKSPACE_BYTES = 32 + 129
STATUSES = frozenset(range(6))


class HiaJsonLayoutRefused(ValueError):
    """An actual HIA refusal, without admitting failed output or its length."""

    def __init__(self, status: int, error_offset: int):
        self.status = status
        self.error_offset = error_offset
        super().__init__(
            'native HIA JSON layout refused with status '
            + str(status) + ' at byte ' + str(error_offset)
        )


class NativeJsonPretty(NativeHiaJsonImage):
    """Pinned image and private workspace for each admitted byte input."""

    @staticmethod
    def _success_extent(status, workspace):
        # Only a successful actual return may admit the output-length field.
        # Refusals can leave that field unchanged from a preceding invocation.
        if type(status) is not int or status not in STATUSES:
            raise RuntimeError('invalid native HIA JSON layout return')
        error_offset, diagnostic = struct.unpack_from('<QQ', workspace, 16)
        if status:
            if diagnostic != status:
                raise RuntimeError('invalid native HIA JSON layout refusal diagnostic')
            raise HiaJsonLayoutRefused(status, error_offset)
        if error_offset != 0 or diagnostic != 0:
            raise RuntimeError('invalid native HIA JSON layout success diagnostic')
        count, = struct.unpack_from('<Q', workspace, 8)
        return count

    def format_admitted_compact(self, wire: bytes) -> bytes:
        """Lay out one already admitted compact wire; return bytes without LF.

        This entry transports exact bytes. It does not traverse objects, sort
        keys, escape strings, print, choose a destination or publish a file.
        It does not grant JSON admission and must not be substituted directly
        for the original CLI functions with their broader object/text domains.
        """
        if type(wire) is not bytes:
            raise TypeError('native HIA JSON layout requires exact admitted bytes')
        workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        empty_output = ctypes.create_string_buffer(1)
        # The immutable input is held for both synchronous calls. The public
        # HIA entry declares this input as readbuf, as in the existing wire ABI.
        struct.pack_into('<Q', workspace, 0, 0)
        status = self._entry(wire, len(wire), empty_output, 0,
                             workspace, WORKSPACE_BYTES)
        measured = self._success_extent(status, workspace)
        if measured > sys.maxsize:
            raise OverflowError('native HIA JSON layout exceeds addressable byte extent')
        output = ctypes.create_string_buffer(max(1, measured))
        struct.pack_into('<Q', workspace, 0, 1)
        status = self._entry(wire, len(wire), output, measured,
                             workspace, WORKSPACE_BYTES)
        emitted = self._success_extent(status, workspace)
        if emitted != measured:
            raise RuntimeError('native HIA JSON layout measurement and emission differ')
        return ctypes.string_at(output, emitted)


def installed_json_pretty(manifest_path: str) -> NativeJsonPretty:
    """Use the existing source-bound local manifest loader for this HIA source."""
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeJsonPretty)
