"""Optional HIA snapshot kernel; host transport is not native Agent service.

Objects have already been decoded by the hosted caller. Transport preserves
exact Python type distinctions and field names; native HIA chooses admission,
error category, size and every generated payload byte. No input path or native
address is accepted. Invalid selected artifacts/results never use a fallback.
"""
from __future__ import annotations
import ctypes
from pathlib import Path
import struct
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/agent_snapshot.hiaasm')
SCHEMA = 'hepta.hia.agent-snapshot-native.v1'
MAX_EXTENT = 1 << 20
MAX_WIRE = (4 << 20) + 96
_KEYS = {'bytes_hex': 1, 'byte_length': 2, 'fill_byte': 3}
_MESSAGES = {
    1: 'buffer bytes must be bounded canonical lowercase hex',
    2: 'buffer fill requires exact bounded integer length and byte',
    3: 'buffer snapshot has missing or unknown fields',
    4: 'borrowed arguments require a byte snapshot',
}


def transport(value, materialize=False):
    """Encode typed fields, not a host admission decision or precomputed bytes.

    Dictionary keys are decoded strings in the public wire. Unknown/non-string
    keys have the same native unknown-field tag. Negative/over-u64 integers and
    non-integer objects have distinct non-admissible representation tags.
    Oversized strings are transported as tag 4: no valid descriptor is lost
    since a valid lowercase hex string is at most 2 MiB of ASCII.
    """
    is_dict = type(value) is dict
    count = len(value) if is_dict else 0
    wire = bytearray(struct.pack('<QQQQ', 1, int(materialize), int(is_dict), count))
    if not is_dict or count > 2:
        return bytes(wire)
    for key, item in value.items():
        key_id = _KEYS.get(key, 0) if type(key) is str else 0
        tag, number, payload = 0, 0, b''
        if type(item) is str:
            if len(item) <= 2 * MAX_EXTENT:
                try:
                    payload = item.encode('utf-8')
                    tag = 1
                    if len(payload) > 2 * MAX_EXTENT:
                        tag, payload = 4, b''
                except UnicodeError:
                    tag = 4
            else:
                tag = 4
        elif type(item) is int:
            tag = 2 if 0 <= item <= (1 << 64) - 1 else 3
            number = item if tag == 2 else 0
        wire.extend(struct.pack('<QQQQ', key_id, tag, len(payload), number))
        wire.extend(payload)
    return bytes(wire)


class NativeAgentSnapshot(NativeHiaJsonImage):
    def evaluate(self, value, *, materialize=False):
        wire = transport(value, materialize)
        if len(wire) > MAX_WIRE:
            raise RuntimeError('invalid Agent snapshot transport extent')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        capacity = 8 + MAX_EXTENT if materialize else 8
        output = ctypes.create_string_buffer(capacity)
        scratch = ctypes.create_string_buffer(64)
        result = self._entry(source, len(wire), output, capacity, scratch, 64)
        if result in _MESSAGES:
            from .hia_agent_store import reject
            reject('E_HIA_ARGUMENTS', _MESSAGES[result])
        if result != 0:
            raise RuntimeError('native Agent snapshot rejected its declared protocol buffers')
        size = struct.unpack_from('<Q', output.raw)[0]
        if size > MAX_EXTENT:
            raise RuntimeError('invalid native Agent snapshot result length')
        return output.raw[8:8 + size] if materialize else size


def installed_snapshot(manifest_path: str) -> NativeAgentSnapshot:
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeAgentSnapshot)
