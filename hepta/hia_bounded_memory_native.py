"""Exact-object transport for HIA-owned VM fill and overlapping byte moves.

The host observes exact kind, sign, bit length, an unsigned word and buffer
address/extent. HIA decides all original refusals before mutation. No size
ceiling is added: admitted bytearrays and extents retain the original domain.
The two original Python bodies are never entered after native selection.
"""
from __future__ import annotations

import ctypes
import os
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/bounded_memory.hepta')
SCHEMA = 'hepta.hia.bounded-memory-native.v1'
SELECTOR = 'HEPTA_HIA_BOUNDED_MEMORY_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIABMEM1', 'little')
_ERRORS = {1: 'E_HIA_VM_RANGE: invalid owned-byte extent',
           2: 'E_HIA_VM_VALUE: expected u8'}


def _integer_facts(value):
    """Bounded representation observations, never arbitrary object callbacks.

    Flag bits describe exact int, negative sign and bits beyond the low word.
    HIA refuses non-unit flags independently of the integer word. Transport
    zero for those facts: masking a negative PyLong would allocate a temporary
    proportional to its bit length, even before an earlier range refusal.
    """
    if type(value) is not int:
        return 0, 0
    flags = 1 | (int(value < 0) << 1) | (int(value.bit_length() > 64) << 2)
    return flags, value if flags == 1 else 0


def packet(operation, buffer, first, count, last):
    return struct.pack('<10Q', REQUEST_MAGIC, operation, int(type(buffer) is bytearray), 0,
                       *_integer_facts(first), *_integer_facts(count), *_integer_facts(last))


class NativeBoundedMemory(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        super().__init__(image, expected_sha256)
        # Keep Python's GIL while mutating a Python-owned bytearray. Holding the
        # export also prevents resize for the complete foreign call. Neither
        # path releases a live borrowed pointer or calls a user hook.
        address = ctypes.cast(self._entry, ctypes.c_void_p).value
        self._memory_entry = ctypes.PYFUNCTYPE(ctypes.c_uint64,
            *([ctypes.c_void_p, ctypes.c_uint64] * 3))(address)

    def _call(self, operation, buffer, first, count, last):
        raw = packet(operation, buffer, first, count, last)
        source = ctypes.create_string_buffer(raw, len(raw))
        extent = len(buffer) if type(buffer) is bytearray else 0
        target = ((ctypes.c_ubyte * extent).from_buffer(buffer)
                  if extent else (ctypes.c_ubyte * 1)())
        try:
            result = self._memory_entry(source, len(raw), target, extent, None, 0)
        finally:
            # A retained exception traceback must not keep a live buffer
            # export. The reference range/value refusals never export one.
            del target
        if type(result) is not int:
            raise RuntimeError('invalid native bounded-memory result')
        if result in _ERRORS:
            raise ValueError(_ERRORS[result])
        if result != 0:
            raise RuntimeError('invalid native bounded-memory result')

    def fill_bytes(self, buffer, offset, count, value):
        self._call(1, buffer, offset, count, value)

    def move_bytes(self, buffer, destination, source, count):
        self._call(2, buffer, destination, count, source)


def installed_bounded_memory(manifest_path):
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeBoundedMemory)


def selected_bounded_memory():
    if SELECTOR not in os.environ:
        return None
    path = os.environ[SELECTOR]
    if not path:
        raise ValueError('bounded-memory selector must not be empty')
    return installed_bounded_memory(path)
