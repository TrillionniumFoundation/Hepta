"""Opaque-byte transport for the complete HIA raw JSON nominal packet codec.

The image parses, counts, validates and serializes every payload node. This
module owns code/buffer custody and fixed control fields only. Its new status
API does not replace the existing public JSON diagnostics or object routes.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
from hashlib import sha256
import mmap
import struct
import sys

from .hia_json_preflight_native import (
    NativeHiaJsonImage, _installed_json_image, _source_resource_path, scratch_sizes,
)


SOURCE = _source_resource_path('examples/hia_bootstrap/nominal_json.hepta')
SCHEMA = 'hepta.hia.nominal-json-native.v1'
MAX_BYTES = 8 * 1024 * 1024
MAX_NODES = 262144
MAX_DEPTH = 128
REQUEST_MAGIC = int.from_bytes(b'HIANJQ01', 'little')
REPLY_MAGIC = int.from_bytes(b'HIANJP01', 'little')
HEADER = struct.Struct('<8Q')
BAD_JSON = 0xffffffff
BAD_BUDGET = 0xfffffffe
BAD_ABI = 0xfffffffd
BAD_DUPLICATE = 0xfffffffc
BAD_BYTES = 0xfffffffb
BAD_INTEGER = 0xfffffffa
BAD_INTERNAL = 0xfffffff9
_REFUSALS = {
    BAD_JSON: 'invalid raw JSON syntax or UTF-8',
    BAD_BUDGET: 'raw JSON node or depth budget exceeded',
    BAD_DUPLICATE: 'duplicate decoded JSON object key',
    BAD_BYTES: 'raw JSON byte budget exceeded',
    BAD_INTEGER: 'JSON integer exceeds the selected decimal digit limit',
}


class NominalJSONProtocolError(RuntimeError):
    """An ABI, implementation or fixed response-custody invariant failed."""


class NominalJSONRejected(ValueError):
    """A new codec status, not the old public message/span diagnostic API."""

    def __init__(self, status: int, *, input_sha256: str | None, policy_sha256: str):
        self.status = status
        self.input_sha256 = input_sha256
        self.policy_sha256 = policy_sha256
        super().__init__('HIA nominal JSON packet: ' + _REFUSALS[status])


@dataclass(frozen=True)
class NominalJSONPacket:
    wire: bytes
    input_sha256: str
    packet_sha256: str
    image_sha256: str
    integer_digit_limit: int
    constructor_wrapper: bool
    legacy: bool
    source_nodes: int
    policy_sha256: str
    identity_sha256: str


def packet_buffer_sizes(size: int) -> tuple[int, int]:
    """Allocate byte capacities only; the HIA image charges actual JSON nodes."""
    if type(size) is not int or not 0 <= size <= MAX_BYTES:
        raise ValueError('outside the nominal JSON byte allocation profile')
    bound = min(MAX_NODES, (size + 1) // 2 + 1)
    keys, stack = scratch_sizes(size, MAX_NODES, MAX_DEPTH)
    arena = max(stack, 64 + bound * 56 + size)
    decoder_scratch = max(keys, 128 + (MAX_DEPTH + 1) * 48)
    # Values, object keys and count words fit 40*N + source bytes. The optional
    # constructor root and boolean add 41 bytes outside the JSON input budget.
    return max(decoder_scratch, 40 * bound + size + 41), arena + bound * 8


class NativeNominalJSON(NativeHiaJsonImage):
    """Pinned immutable code; private buffers and scalar policy on every call."""

    def encode(self, raw: bytes, *, constructor_wrapper: bool = False,
               legacy: bool = False, integer_digit_limit: int | None = None) -> NominalJSONPacket:
        if type(raw) is not bytes:
            raise TypeError('nominal JSON input must be exact raw bytes')
        if type(constructor_wrapper) is not bool or type(legacy) is not bool:
            raise TypeError('nominal JSON wrapper controls must be exact booleans')
        if legacy and not constructor_wrapper:
            raise ValueError('legacy requires the constructor wrapper')
        digits = sys.get_int_max_str_digits() if integer_digit_limit is None else integer_digit_limit
        if type(digits) is not int or not (digits == 0 or 640 <= digits < 1 << 64):
            raise ValueError('integer digit limit must be zero or an integer from 640 through u64 max')
        mode = 1 if constructor_wrapper else 0
        legacy_word = 1 if legacy else 0
        request = HEADER.pack(REQUEST_MAGIC, digits, mode, legacy_word, 0, 0, 0, 0)
        policy_sha = sha256(b'hepta.hia.nominal-json-policy.v1\0'
                            + bytes.fromhex(self.image_sha256) + request).hexdigest()
        if len(raw) > MAX_BYTES:
            # Do not copy or hash an unbounded rejected foreign input. The image
            # independently checks this same byte bound for direct ABI callers.
            raise NominalJSONRejected(BAD_BYTES, input_sha256=None, policy_sha256=policy_sha)
        input_sha = sha256(raw).hexdigest()
        output_size, workspace_size = packet_buffer_sizes(len(raw))
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        flags = mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS
        with mmap.mmap(-1, output_size, flags=flags) as output, \
                mmap.mmap(-1, workspace_size, flags=flags) as workspace:
            workspace[:HEADER.size] = request
            output_address = ctypes.addressof(ctypes.c_char.from_buffer(output))
            workspace_address = ctypes.addressof(ctypes.c_char.from_buffer(workspace))
            result = self._entry(source, len(raw), output_address, output_size,
                                 workspace_address, workspace_size)
            if type(result) is not int:
                raise NominalJSONProtocolError('native packet result is not an exact integer')
            if source.raw[:len(raw)] != raw:
                raise NominalJSONProtocolError('native packet input bytes changed')
            if result in _REFUSALS:
                raise NominalJSONRejected(result, input_sha256=input_sha, policy_sha256=policy_sha)
            if result in (BAD_ABI, BAD_INTERNAL):
                raise NominalJSONProtocolError('native packet rejected its ABI or internal invariants')
            if not 16 <= result <= output_size or result > 0xffffffff:
                raise NominalJSONProtocolError('native packet result extent or zero-extension differs')
            reply = HEADER.unpack_from(workspace)
            if (reply[:6] != (REPLY_MAGIC, result, digits, mode, legacy_word, len(raw))
                    or not 1 <= reply[6] <= MAX_NODES or reply[7] != 1):
                raise NominalJSONProtocolError('native packet response changed its scalar policy or input identity')
            packet = output[:result]
            source_nodes = reply[6]
        packet_sha = sha256(packet).hexdigest()
        identity_sha = sha256(b'hepta.hia.nominal-json-result.v1\0'
                              + bytes.fromhex(policy_sha) + bytes.fromhex(input_sha)
                              + bytes.fromhex(packet_sha) + struct.pack('<Q', source_nodes)).hexdigest()
        return NominalJSONPacket(packet, input_sha, packet_sha, self.image_sha256, digits,
                                 constructor_wrapper, legacy, source_nodes, policy_sha, identity_sha)

    def packet(self, raw: bytes, *, integer_digit_limit: int | None = None) -> bytes:
        return self.encode(raw, integer_digit_limit=integer_digit_limit).wire

    def constructor_packet(self, raw: bytes, *, legacy: bool = False,
                           integer_digit_limit: int | None = None) -> bytes:
        return self.encode(raw, constructor_wrapper=True, legacy=legacy,
                           integer_digit_limit=integer_digit_limit).wire


def installed_nominal_json(manifest_path) -> NativeNominalJSON:
    return _installed_json_image(str(manifest_path), SOURCE, SCHEMA, NativeNominalJSON)
