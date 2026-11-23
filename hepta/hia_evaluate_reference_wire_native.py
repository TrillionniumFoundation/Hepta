"""Map the admitted HIA Evaluate projector and decode its VM packet."""

from functools import lru_cache
import json
import mmap
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _ensure_ctypes, _source_resource_path
from .hia_program import MAX_NODES
from .hia_scalar_reference_wire import MAX_FRAME_WORDS, MAX_PACKET_BYTES, RESOURCE_KINDS, TYPES

SOURCE = _source_resource_path('examples/hia_bootstrap/evaluate_reference_wire.hepta')
SCHEMA = 'hepta.hia.evaluate-reference-wire-native.v1'
SELECTOR = 'HEPTA_HIA_EVALUATE_REFERENCE_WIRE_MANIFEST'
MAGIC = int.from_bytes(b'HIAERW01', 'little')
RESOURCE_MAGIC = int.from_bytes(b'HIAERW02', 'little')
REFUSED = 0xfffffffd
WORK_BYTES = 48 << 20
HEADER = struct.Struct('<8Q')


class NativeEvaluateReferenceWire(NativeHiaJsonImage):
    @lru_cache(maxsize=8)
    def project(self, canonical: bytes, entry: str, *, allow_resources=False):
        """Return immutable reference instructions, or None outside the HIA domain."""
        ffi = _ensure_ctypes()
        name = json.dumps(entry, ensure_ascii=True).encode('ascii')
        request = b'[' + canonical + b',' + name + (b',1]' if allow_resources else b',0]')
        # Every container adds at most one child beyond its direct commas.
        # Counting punctuation inside strings can only increase this bound.
        nodes = min(MAX_NODES + 3, 1 + request.count(b',') + request.count(b'[') + request.count(b'{'))
        # Each decoded node occupies 72 bytes; block and SSA rows need at most
        # another 40 per node. The fixed function and loan tables occupy 64 KiB.
        workspace = min(WORK_BYTES, (68 << 10) + 112 * nodes + len(request))
        # Resource return instructions are the largest encoding: their command,
        # site, restoration and operand words fit within 256 bytes per Core node.
        # The decoder also uses output as its duplicate-key hash table. Its
        # capacity rounds twice the key bound up to a power of two.
        key_slots = min(MAX_NODES + 3, len(request) // 4 + 1) * 2
        key_bytes = 8 << (key_slots - 1).bit_length()
        capacity = min(MAX_PACKET_BYTES, max(8192 + 256 * nodes, key_bytes))
        with mmap.mmap(-1, capacity) as output, mmap.mmap(-1, workspace) as work:
            length = self._entry(request, len(request),
                                 ffi.addressof(ffi.c_char.from_buffer(output)), len(output),
                                 ffi.addressof(ffi.c_char.from_buffer(work)), len(work))
            if length == REFUSED:
                return None
            if not HEADER.size <= length <= capacity:
                raise ValueError('invalid HIA Evaluate reference wire length')
            magic, registers, bounce, end, count, sites, *reserved = HEADER.unpack_from(output)
            expected_magic = RESOURCE_MAGIC if allow_resources else MAGIC
            if (magic != expected_magic or sites > int(allow_resources) or any(reserved)
                    or registers < 1 or bounce < 1
                    or registers + bounce > MAX_FRAME_WORDS or end < HEADER.size + 8
                    or end % 8 or end + 8 * count != length):
                raise ValueError('invalid HIA Evaluate reference wire header')
            types = (*TYPES, *RESOURCE_KINDS[1:]) if allow_resources else TYPES
            return_types = []
            for (code,) in struct.iter_unpack('<Q', output[end:length]):
                if code >= len(types):
                    raise ValueError('invalid HIA Evaluate reference return type')
                return_types.append(types[code])
            body = bytes(HEADER.size) + output[HEADER.size:end]
        return body, registers, bounce, tuple(return_types), bool(sites)
