"""Selected HIA mapping decisions over one actually captured kernel snapshot.

File descriptors, fstat/seals, function addresses and final kernel readback
remain in native_mapping_identity. This image performs no filesystem or loader
operation. Its anonymous flat-code loader does not call verify_loaded_symbols,
so admitting this helper cannot recursively depend on its own decisions. On a
numeric or ASCII refusal, HIA identifies the first offending source span; only
that token is passed to Python int/decode to preserve the original exception
cause. The Python mapping policy is never rerun after native selection.
"""
from __future__ import annotations

import ctypes
import os
import struct
import sys

from .hia_json_preflight_native import (
    NativeHiaJsonImage, _installed_json_image, _source_resource_path,
)

SOURCE = _source_resource_path('examples/hia_bootstrap/native_mapping.hepta')
SCHEMA = 'hepta.hia.native-mapping-native.v1'
SELECTOR = 'HEPTA_HIA_NATIVE_MAPPING_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIAMAP01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAMPR01', 'little')
STATE_BYTES = 8192
MAX_MAPS_BYTES = 16 << 20
REASONS = {
    1: 'incomplete kernel mapping record',
    2: 'unrecognized kernel mapping record',
    3: 'invalid kernel mapping interval or identity',
    4: 'native entry is not in a private nonwritable executable mapping',
    5: 'native entry maps a different file object; retained loader mapping refused',
    6: 'native entry lies outside the sealed file bytes',
    7: 'native entry has no unique identity-matched executable mapping',
    8: 'unable to establish actual loaded file identity',
    9: 'unable to establish actual loaded file identity',
}


def state_bytes(addresses, expected_device, inode, file_bytes, *, digit_limit=None):
    """Encode actual foreign observations; no serialized receipt is authority."""
    if digit_limit is None:
        digit_limit = sys.get_int_max_str_digits()
    values = (REQUEST_MAGIC, len(addresses), *expected_device, inode, file_bytes,
              digit_limit, 0, *addresses.values())
    if (type(addresses) is not dict or not 1 <= len(addresses) <= 128
            or any(type(value) is not int or not 0 <= value < 1 << 64 for value in values)
            or file_bytes == 0 or any(value == 0 for value in addresses.values())):
        raise ValueError('native mapping packet differs from actual Linux word observations')
    return struct.pack('<' + 'Q' * len(values), *values).ljust(STATE_BYTES, b'\0')


class NativeMappingImage(NativeHiaJsonImage):
    def matches(self, contents, addresses, expected_device, inode, file_bytes):
        from .native_mapping_identity import NativeMappingRejected

        if type(contents) is not bytes or len(contents) > MAX_MAPS_BYTES:
            raise ValueError('native mapping snapshot exceeds the original kernel-read bound')
        original = state_bytes(addresses, expected_device, inode, file_bytes)
        source = ctypes.create_string_buffer(contents, max(1, len(contents)))
        state = ctypes.create_string_buffer(original, STATE_BYTES)
        count = len(addresses)
        initial = b'\xa5' * (16 + count * 8)
        output = ctypes.create_string_buffer(initial, len(initial))
        returned = self._entry(source, len(contents), output, len(initial), state, STATE_BYTES)
        if (type(returned) is not int or returned not in (0, *REASONS)
                or source.raw[:len(contents)] != contents
                or state.raw[:64 + 8 * count] != original[:64 + 8 * count]):
            raise ValueError('native mapping result or immutable observations changed')
        if returned:
            if output.raw != initial:
                raise ValueError('native mapping refusal changed its unpublished output')
            if returned == 8:
                raise ValueError('native mapping packet or native profile refused')
            if returned == 9:
                operation, begin, end = struct.unpack_from('<3Q', state.raw, 4200)
                if operation not in (1, 10, 16) or not 0 <= begin <= end <= len(contents):
                    raise ValueError('native mapping error span is invalid')
                token = contents[begin:end]
                try:
                    if operation == 1:
                        token.decode('ascii')
                    else:
                        int(token, operation)
                except ValueError as error:
                    raise NativeMappingRejected('E_NATIVE_MAPPING: ' + REASONS[returned]) from error
                raise ValueError('native mapping error span does not reproduce its foreign exception')
            raise NativeMappingRejected('E_NATIVE_MAPPING: ' + REASONS[returned])
        magic, actual_count = struct.unpack_from('<2Q', output.raw)
        if magic != RESULT_MAGIC or actual_count != count:
            raise ValueError('native mapping response identity differs')
        offsets = struct.unpack_from('<' + 'Q' * count, output.raw, 16)
        if any(offset >= file_bytes for offset in offsets):
            raise ValueError('native mapping response exceeds the actual file extent')
        return {name: [{'file_offset': offset, 'permissions': 'r-xp'}]
                for name, offset in zip(addresses, offsets)}


def installed_native_mapping(manifest_path):
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeMappingImage)


def selected_native_mapping():
    if SELECTOR not in os.environ:
        return None
    selected = os.environ[SELECTOR]
    if not selected:
        raise ValueError('native mapping selector must not be empty')
    return installed_native_mapping(selected)
