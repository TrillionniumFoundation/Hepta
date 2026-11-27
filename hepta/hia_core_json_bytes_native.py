"""Fixed native images for the existing Core public-bytes JSON boundary.

The HIA front image owns complete UTF-8 validation, ordered Core preflight,
integer digit policy and canonical serialization. The nominal image consumes
that canonical wire. Host work is limited to immutable image selection,
private buffers, fixed response fields, identity hashes and error rendering.
The existing public routes and their semantic Core checker remain unchanged.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import mmap
import struct
import sys

from .hia_json_decode_native import arena_sizes
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_nominal_json_native import (
    NativeNominalJSON, NominalJSONPacket, NominalJSONRejected,
    BAD_JSON, BAD_BUDGET, BAD_ABI, BAD_DUPLICATE, BAD_BYTES, BAD_INTEGER, BAD_INTERNAL,
)
from .hia_program import HIAProgramRejected

SOURCE = _source_resource_path('examples/hia_bootstrap/core_json_bytes.hepta')
SCHEMA = 'hepta.hia.core-json-bytes-native.v1'
MAX_BYTES = 8 * 1024 * 1024
MAX_NODES = 262144
MAX_DEPTH = 64
REQUEST_MAGIC = int.from_bytes(b'HIACJQ01', 'little')
REPLY_MAGIC = int.from_bytes(b'HIACJP01', 'little')
HEADER = struct.Struct('<8Q')


class CoreJSONBytesProtocolError(RuntimeError):
    """A fixed ABI, code or response identity invariant failed."""


@dataclass(frozen=True)
class CoreJSONCanonical:
    canonical_bytes: bytes
    input_sha256: str
    canonical_sha256: str
    image_sha256: str
    integer_digit_limit: int
    source_nodes: int
    policy_sha256: str
    identity_sha256: str


@dataclass(frozen=True)
class CoreJSONBytesResult:
    canonical: CoreJSONCanonical
    packet: NominalJSONPacket
    identity_sha256: str


def canonical_buffer_sizes(size: int) -> tuple[int, int]:
    if type(size) is not int or not 0 <= size <= MAX_BYTES:
        raise ValueError('outside the Core JSON byte allocation profile')
    arena, keys = arena_sizes(size, MAX_NODES, MAX_DEPTH)
    return max(size, keys), arena


def _public_rejection(status: int) -> None:
    if status == BAD_BYTES:
        raise HIAProgramRejected('program exceeds byte budget', 'E_HIA_LIMIT')
    if status == BAD_BUDGET:
        raise HIAProgramRejected('program exceeds structural budget before JSON allocation', 'E_HIA_LIMIT')
    if status in (BAD_JSON, BAD_DUPLICATE, BAD_INTEGER):
        raise HIAProgramRejected('invalid/deep UTF-8 JSON', 'E_HIA_FORMAT')
    raise CoreJSONBytesProtocolError('native Core JSON front door rejected its ABI or internal invariants')


class NativeCoreJSONBytes(NativeHiaJsonImage):
    """Pinned front-door code; every call owns its input and scratch buffers."""

    def canonicalize(self, raw: bytes, *, integer_digit_limit: int | None = None) -> CoreJSONCanonical:
        if type(raw) is not bytes:
            raise TypeError('Core JSON byte input must be exact raw bytes')
        digits = sys.get_int_max_str_digits() if integer_digit_limit is None else integer_digit_limit
        if type(digits) is not int or not (digits == 0 or 640 <= digits < 1 << 64):
            raise ValueError('integer digit limit must be zero or an integer from 640 through u64 max')
        request = HEADER.pack(REQUEST_MAGIC, digits, 0, 0, 0, 0, 0, 0)
        policy_sha = sha256(b'hepta.hia.core-json-bytes-policy.v1\0'
                            + bytes.fromhex(self.image_sha256) + request).hexdigest()
        if len(raw) > MAX_BYTES:
            # No unbounded copy or digest of an already rejected foreign input.
            # The HIA entry independently enforces this same byte limit.
            _public_rejection(BAD_BYTES)
        input_sha = sha256(raw).hexdigest()
        output_size, workspace_size = canonical_buffer_sizes(len(raw))
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
                raise CoreJSONBytesProtocolError('native Core JSON result is not an exact integer')
            if source.raw[:len(raw)] != raw:
                raise CoreJSONBytesProtocolError('native Core JSON input bytes changed')
            if result in (BAD_JSON, BAD_BUDGET, BAD_ABI, BAD_DUPLICATE, BAD_BYTES, BAD_INTEGER, BAD_INTERNAL):
                _public_rejection(result)
            if not 0 < result <= min(len(raw), output_size) or result > 0xffffffff:
                raise CoreJSONBytesProtocolError('native Core JSON result extent or zero-extension differs')
            reply = HEADER.unpack_from(workspace)
            if (reply[:4] != (REPLY_MAGIC, result, digits, len(raw))
                    or not 1 <= reply[4] <= MAX_NODES
                    or reply[5:] != (MAX_NODES, MAX_DEPTH, 1)):
                raise CoreJSONBytesProtocolError('native Core JSON response changed its policy or input identity')
            canonical = output[:result]
            source_nodes = reply[4]
        canonical_sha = sha256(canonical).hexdigest()
        identity_sha = sha256(b'hepta.hia.core-json-canonical-result.v1\0'
                              + bytes.fromhex(policy_sha) + bytes.fromhex(input_sha)
                              + bytes.fromhex(canonical_sha) + struct.pack('<Q', source_nodes)).hexdigest()
        return CoreJSONCanonical(canonical, input_sha, canonical_sha, self.image_sha256,
                                 digits, source_nodes, policy_sha, identity_sha)

    def decode(self, raw: bytes, nominal: NativeNominalJSON, *,
               integer_digit_limit: int | None = None,
               constructor_wrapper: bool = False, legacy: bool = False) -> CoreJSONBytesResult:
        if type(constructor_wrapper) is not bool or type(legacy) is not bool:
            raise TypeError('Core JSON wrapper controls must be exact booleans')
        if legacy and not constructor_wrapper:
            raise ValueError('legacy requires the constructor wrapper')
        if not isinstance(nominal, NativeNominalJSON):
            raise TypeError('Core JSON packet output requires an explicitly installed nominal image')
        canonical = self.canonicalize(raw, integer_digit_limit=integer_digit_limit)
        try:
            packet = nominal.encode(canonical.canonical_bytes,
                                    integer_digit_limit=canonical.integer_digit_limit,
                                    constructor_wrapper=constructor_wrapper, legacy=legacy)
        except NominalJSONRejected as exc:
            raise CoreJSONBytesProtocolError('nominal image rejected an admitted canonical Core JSON wire') from exc
        if (packet.input_sha256 != canonical.canonical_sha256
                or packet.source_nodes != canonical.source_nodes
                or packet.integer_digit_limit != canonical.integer_digit_limit
                or packet.constructor_wrapper is not constructor_wrapper
                or packet.legacy is not legacy):
            raise CoreJSONBytesProtocolError('nominal response differs from the admitted canonical request')
        identity_sha = sha256(b'hepta.hia.core-json-bytes-result.v1\0'
                              + bytes.fromhex(canonical.identity_sha256)
                              + bytes.fromhex(packet.identity_sha256)).hexdigest()
        return CoreJSONBytesResult(canonical, packet, identity_sha)


def installed_core_json_bytes(manifest_path) -> NativeCoreJSONBytes:
    return _installed_json_image(str(manifest_path), SOURCE, SCHEMA, NativeCoreJSONBytes)
