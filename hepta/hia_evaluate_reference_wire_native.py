"""Map the admitted HIA Evaluate projector and decode its scalar VM packet."""

from functools import lru_cache
import json
import mmap
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _ensure_ctypes, _source_resource_path
from .hia_scalar_reference_wire import MAX_FRAME_WORDS, MAX_PACKET_BYTES, TYPES

SOURCE = _source_resource_path('examples/hia_bootstrap/evaluate_reference_wire.hepta')
SCHEMA = 'hepta.hia.evaluate-reference-wire-native.v1'
SELECTOR = 'HEPTA_HIA_EVALUATE_REFERENCE_WIRE_MANIFEST'
MAGIC = int.from_bytes(b'HIAERW01', 'little')
REFUSED = 0xfffffffd
WORK_BYTES = 48 << 20
HEADER = struct.Struct('<8Q')


class NativeEvaluateReferenceWire(NativeHiaJsonImage):
    @lru_cache(maxsize=8)
    def project(self, canonical: bytes, entry: str):
        """Return immutable scalar instructions, or None outside the HIA domain."""
        ffi = _ensure_ctypes()
        request = b'[' + canonical + b',' + json.dumps(entry, ensure_ascii=True).encode('ascii') + b']'
        with mmap.mmap(-1, MAX_PACKET_BYTES) as output, mmap.mmap(-1, WORK_BYTES) as work:
            length = self._entry(request, len(request),
                                 ffi.addressof(ffi.c_char.from_buffer(output)), len(output),
                                 ffi.addressof(ffi.c_char.from_buffer(work)), len(work))
            if length == REFUSED:
                return None
            if not HEADER.size <= length <= MAX_PACKET_BYTES:
                raise ValueError('invalid HIA Evaluate reference wire length')
            magic, registers, bounce, end, count, *reserved = HEADER.unpack_from(output)
            if (magic != MAGIC or any(reserved) or registers < 1 or bounce < 1
                    or registers + bounce > MAX_FRAME_WORDS or end < HEADER.size + 8
                    or end % 8 or end + 8 * count != length):
                raise ValueError('invalid HIA Evaluate reference wire header')
            return_types = []
            for (code,) in struct.iter_unpack('<Q', output[end:length]):
                if code >= len(TYPES):
                    raise ValueError('invalid HIA Evaluate reference return type')
                return_types.append(TYPES[code])
            body = bytes(HEADER.size) + output[HEADER.size:end]
        return body, registers, bounce, tuple(return_types), False
