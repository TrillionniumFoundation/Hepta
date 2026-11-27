"""Exact-byte transport for the HIA Agent signature and byte-export owner.

Full Core verification precedes this boundary. Raw JSON and immutable-tuple
snapshots are separate transports; neither performs export policy in Python. Policy runs
in the admitted HIA image; the host only allocates storage, invokes that image,
maps its refusal code and decodes its complete JSON result.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import struct

from .hia_agent_store import _agent_resource_path
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_native_metadata.hepta')
SCHEMA = 'hepta.hia.agent-native-metadata.v2'
SELECTOR = 'HEPTA_HIA_AGENT_NATIVE_METADATA_MANIFEST'
MAGIC = int.from_bytes(b'HIANMQ01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIANMD01', 'little')
MAX_JSON = 8 * 1024 * 1024
SNAPSHOT_MAGIC = int.from_bytes(b'HIAMT001', 'little')
SNAPSHOT_HEADER_BYTES = 32
SNAPSHOT_RECORD_BYTES = 576
HEADER_BYTES = 64
MIN_OUTPUT_BYTES = 4 * 1024 * 1024
FRAMING, STORAGE = 0xfffffffd, 0xfffffffe
JSON_MANIFEST, JSON_CORE = 0xfffffff0, 0xffffffef
REFUSALS = {
    0xfffffffb: 'borrowed-byte exports require a bounded immutable tuple',
    0xfffffffa: 'invalid or duplicate borrowed-byte export',
    0xfffffff9: 'borrowed-byte profile cannot extend a nominal/scalar export contract',
    0xfffffff8: 'borrowed-byte export conflicts with the closed native ABI',
    0xfffffff7: 'borrowed-byte export names a missing function',
    0xfffffff6: 'borrowed-byte export requires loans, scalars and one u32 result',
}


def capture_request(checked, manifest_wire: bytes) -> bytes:
    """Capture already verified Core and a raw standard-JSON manifest.

    Neither the manifest nor its children are decoded or normalized here.
    The structured bit records the original verified program's provenance.
    """
    core = checked.canonical_bytes
    if type(core) is not bytes or not 0 < len(core) <= MAX_JSON:
        raise ValueError('invalid admitted canonical byte capture')
    if type(manifest_wire) is not bytes or len(manifest_wire) > MAX_JSON:
        raise ValueError('invalid raw borrowed-byte manifest capture')
    header = struct.pack('<8Q', MAGIC, 1, len(core), len(manifest_wire),
                         int(checked.structured_bytes is not None), 0, 0, 0)
    return header + core + manifest_wire


def capture_object_request(checked, exports) -> bytes:
    """Observe exact immutable types without coercing or validating policy.

    A name carries its true codepoint length and at most 128 original u32
    codepoints. Integers carry exact type, sign and bit length; their nonnegative
    value is copied only when it fits the fixed u64 transport word. These
    observations distinguish every value relevant to the original bounded
    export policy, including malformed and surrogate-containing values.
    """
    core = checked.canonical_bytes
    if type(core) is not bytes or not 0 < len(core) <= MAX_JSON:
        raise ValueError('invalid admitted canonical byte capture')
    top_tag = int(type(exports) is tuple)
    amount = len(exports) if top_tag else 0
    copied = amount if top_tag and amount <= 128 else 0
    snapshot = bytearray(SNAPSHOT_HEADER_BYTES + copied * SNAPSHOT_RECORD_BYTES)
    struct.pack_into('<4Q', snapshot, 0, SNAPSHOT_MAGIC, top_tag, amount, 0)
    for index in range(copied):
        pair = exports[index]
        pair_tag = int(type(pair) is tuple)
        pair_count = len(pair) if pair_tag else 0
        base = SNAPSHOT_HEADER_BYTES + index * SNAPSHOT_RECORD_BYTES
        struct.pack_into('<2Q', snapshot, base, pair_tag, pair_count)
        if not pair_tag or pair_count != 2:
            continue
        name, extent = pair
        name_tag = int(type(name) is str)
        name_count = len(name) if name_tag else 0
        extent_tag = int(type(extent) is int)
        sign = int(extent < 0) if extent_tag else 0
        bits = extent.bit_length() if extent_tag else 0
        low = extent if extent_tag and sign == 0 and bits <= 64 else 0
        struct.pack_into('<6Q', snapshot, base + 16,
                         name_tag, name_count, extent_tag, sign, bits, low)
        if name_tag:
            for at, character in enumerate(name[:128]):
                struct.pack_into('<I', snapshot, base + 64 + at * 4, ord(character))
    header = struct.pack('<8Q', MAGIC, 2, len(core), len(snapshot),
                         int(checked.structured_bytes is not None), 0, 0, 0)
    return header + core + bytes(snapshot)


def storage_sizes(core_size: int, manifest_size: int) -> tuple[int, int]:
    """Private storage bound; public JSON and program limits are unchanged."""
    if (type(core_size) is not int or type(manifest_size) is not int
            or not 0 < core_size <= MAX_JSON or not 0 <= manifest_size <= MAX_JSON):
        raise ValueError('metadata captured spans exceed storage bounds')
    largest = max(core_size, manifest_size)
    nodes = min(262144, ((largest + 1) >> 1) + 1)
    arena = max(8192, 64 + nodes * 56 + largest)
    workspace_size = ((arena + 15) & -16) + 65536
    output_size = max(MIN_OUTPUT_BYTES, core_size + 65600)
    return output_size, workspace_size


@dataclass(frozen=True)
class AgentMetadataReceipt:
    status: int
    payload_wire: bytes
    raw_header: bytes


class NativeAgentMetadata(NativeHiaJsonImage):
    """One real native entry invocation with three private byte buffers."""

    def transition(self, request: bytes) -> AgentMetadataReceipt:
        if (type(request) is not bytes or not HEADER_BYTES <= len(request)
                <= HEADER_BYTES + 2 * MAX_JSON):
            raise ValueError('metadata transport is outside captured-byte bounds')
        words = struct.unpack_from('<8Q', request)
        core_size, manifest_size = words[2:4]
        output_size, workspace_size = storage_sizes(core_size, manifest_size)
        if len(request) != HEADER_BYTES + core_size + manifest_size:
            raise ValueError('metadata captured-span framing mismatch')
        source = ctypes.create_string_buffer(request, len(request))
        output = ctypes.create_string_buffer(output_size)
        workspace = ctypes.create_string_buffer(workspace_size)
        result = self._entry(source, len(request), output, output_size,
                             workspace, workspace_size)
        if source.raw != request:
            raise ValueError('native metadata changed its captured read-only input')
        header = bytes(output.raw[:HEADER_BYTES])
        if result in REFUSALS or result in (FRAMING, STORAGE, JSON_MANIFEST, JSON_CORE):
            return AgentMetadataReceipt(result, b'', header)
        if type(result) is not int or not HEADER_BYTES < result <= output_size:
            raise ValueError('invalid native metadata return framing')
        fields = struct.unpack('<8Q', header)
        if (fields[0:2] != (RESULT_MAGIC, 1) or not 1 <= fields[2] <= 1024
                or fields[3] > fields[2] or fields[4] > min(128, fields[3])
                or fields[5] != result - HEADER_BYTES or fields[6:] != (0, 0)):
            raise ValueError('invalid native metadata published header')
        return AgentMetadataReceipt(0, bytes(output.raw[HEADER_BYTES:result]), header)


def _decoded_receipt(receipt: AgentMetadataReceipt):
    if receipt.status in REFUSALS:
        from .hia_program_native import _reject
        _reject(REFUSALS[receipt.status], 'E_HIA_BYTE_ABI')
    if receipt.status != 0:
        raise ValueError('native metadata framing, raw JSON or admitted-Core inconsistency')
    from .hia_program_tools import decode_json
    return decode_json(receipt.payload_wire)


def call_admitted_metadata_image(native, checked, manifest_wire: bytes):
    """Decode the raw-JSON profile after the caller's full Core verifier."""
    return _decoded_receipt(native.transition(capture_request(checked, manifest_wire)))


def call_admitted_metadata_object_image(native, checked, exports=()):
    """Preserve the original immutable-tuple domain and first-refusal order."""
    return _decoded_receipt(native.transition(capture_object_request(checked, exports)))


def prepare_native_metadata(document, *, native, manifest_wire: bytes):
    from .hia_program import verify_program
    checked = verify_program(document)
    return call_admitted_metadata_image(native, checked, manifest_wire)


def installed_agent_metadata(manifest_path: str) -> NativeAgentMetadata:
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeAgentMetadata)


def selected_agent_metadata():
    """Absence is unselected; present empty or invalid admission always fails."""
    import os
    if SELECTOR not in os.environ:
        return None
    selected = os.environ[SELECTOR]
    if not selected:
        raise ValueError('native Agent metadata manifest selector is empty')
    return installed_agent_metadata(selected)
