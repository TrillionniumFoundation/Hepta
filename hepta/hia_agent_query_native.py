"""Transport for the independently developed complete native query owner.

This supplies no implicit default provider. Native qualification is separate
from source generation.  It contains no graph selection, signature construction, query
dictionary construction, or Python payload/digest implementation.
"""
from __future__ import annotations
import ctypes
import struct

MAGIC = int.from_bytes(b"HIAPQ001", "little")
RESULT_MAGIC = int.from_bytes(b"HIAPQR01", "little")
NONE = (1 << 64) - 1
HEADER = 128
RECORD = 544
CORE_OFFSET = HEADER + 6 * RECORD
MAX_CORE = 8 * 1024 * 1024
MAX_QUERY = 1024 * 1024

# Exact public refusals; invocation/custody failures are not translated into a
# successful query and never invoke the retired/reference policy.
REFUSALS = {
    0xfffffff0: "E_HIA_QUERY: fields must be a unique nonempty subset of op, args, attrs",
    0xffffffef: "E_HIA_QUERY: function, block and output identities must be strings",
    0xffffffee: "E_HIA_QUERY: function not found",
    0xffffffed: "E_HIA_QUERY: block not found",
    0xffffffec: "E_HIA_QUERY: SSA output does not identify one instruction",
    0xfffffffc: "E_HIA_QUERY: cross-block SSA cycle reaches selected block; use full-module view",
    0xfffffffb: "E_HIA_QUERY: transitive CFG view exceeds bounded block budget",
    0xfffffffa: "E_HIA_QUERY: transitive SSA view exceeds bounded operation budget",
    0xffffffeb: "E_HIA_EDIT: JSON container exceeds queued-node/byte budget",
    0xffffffea: "E_HIA_EDIT: JSON input exceeds nesting depth before encoding",
    0xffffffe9: "E_HIA_EDIT: JSON encoding exceeds byte budget",
    0xffffffe8: "E_HIA_EDIT: JSON input exceeds node/byte budget",
    0xffffffe7: "E_HIA_EDIT: JSON string exceeds byte budget before encoding",
    0xffffffe6: "E_HIA_EDIT: unpaired Unicode surrogate in UTF-8 JSON",
    0xffffffe5: "E_HIA_EDIT: JSON integer exceeds byte budget",
}

def capture_string(value):
    """Transport exact Python type, length and a sufficient bounded prefix.

    Admitted Core identifiers have at most128 ASCII codepoints.  Exact length
    plus128 original codepoints preserves equality with every such identifier.
    Native fields validation also has the stricter fixed op/args/attrs domain.
    Unsupported types are not coerced.  Surrogates are transported as u32,
    rather than failing in a host UTF8 encoder before native selector refusal.
    """
    raw = bytearray(RECORD)
    if type(value) is str:
        prefix = value[:128]
        struct.pack_into("<3Q", raw, 0, 1, len(value), len(prefix))
        for index, character in enumerate(prefix):
            struct.pack_into("<I", raw, 24 + index * 4, ord(character))
    return bytes(raw)

def capture_request(checked, *, function, block, output, fields):
    """Call only after the original complete verify_program boundary."""
    canonical = checked.canonical_bytes
    structured = checked.structured_bytes
    if type(canonical) is not bytes or not 0 < len(canonical) <= MAX_CORE:
        raise ValueError("invalid admitted canonical byte capture")
    if structured is not None and (
            type(structured) is not bytes or not 0 < len(structured) <= MAX_CORE):
        raise ValueError("invalid admitted structured byte capture")
    tag = 1 if type(fields) is list else 2 if type(fields) is tuple else 0
    count = len(fields) if tag else 0
    # A malformed oversized collection is represented by its true length.
    # None of its children can affect the first native fields refusal.
    copies = tuple(fields[:4]) if tag and count <= 3 else ()
    if copies:
        count = len(copies)
    parts = [capture_string(copies[index]) if index < len(copies)
             else bytes(RECORD) for index in range(3)]
    parts.extend(capture_string(value) for value in (function, block, output))
    header = struct.pack("<16Q", MAGIC, 1, len(canonical),
                         len(structured) if structured is not None else 0,
                         tag, count, int(structured is not None),
                         *([0] * 9))
    return header + b"".join(parts) + canonical + (structured or b"")

def call_admitted_query_image(native, checked, *, function, block, output, fields):
    """The installed image's actual transition returns the entire query wire.

    NativeHiaJsonImage admission/captured-image custody must be the standard
    exact source/schema/factory path.  This function does not supply an image
    factory or weaken worker pinned-bundle ownership.
    """
    from hepta.hia_program_tools import HIAEditRejected, decode_json
    request = capture_request(checked, function=function, block=block,
                              output=output, fields=fields)
    receipt = native.transition(request)       # exact, single native invocation
    if receipt.status in REFUSALS:
        raise HIAEditRejected(REFUSALS[receipt.status])
    if receipt.status != 0:
        raise ValueError("native query framing/admitted-Core inconsistency")
    if not 0 < len(receipt.query_wire) <= MAX_QUERY:
        raise ValueError("invalid native query result frame")
    # This is object transport only.  It neither re-encodes nor rebuilds a
    # context, selects instructions, computes hashes, nor supplies a fallback.
    return decode_json(receipt.query_wire)

# The eventual facade remains:
#
#   checked = verify_program(document)   # original first authority
#   native = configured_query_provider() # independently admitted provider
#   return call_admitted_query_image(native, checked, ...)
#
# A real installed default provider is an explicit remaining integration
# prerequisite.  This draft does not invent one for source/no-bundle callers.


from dataclasses import dataclass
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_agent_store import _agent_resource_path

SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_query.hepta')
SCHEMA = 'hepta.hia.agent-query-native.v1'
CUSTODY = 0xffffffe4
SELECTOR = 'HEPTA_HIA_AGENT_QUERY_MANIFEST'
OUTPUT_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class AgentQueryReceipt:
    status: int
    query_wire: bytes
    raw_header: bytes


class NativeAgentQuery(NativeHiaJsonImage):
    """One real HIA invocation, no graph/query/selector or digest policy."""

    def transition(self, request: bytes) -> AgentQueryReceipt:
        if (type(request) is not bytes or not CORE_OFFSET <= len(request)
                <= CORE_OFFSET + 2 * MAX_CORE):
            raise ValueError('native query transport is outside captured-byte bounds')
        words = struct.unpack_from('<16Q', request)
        canonical_size, structured_size = words[2:4]
        # These checks choose bounded storage only.  Native owns all public
        # field/selector decisions and the complete query payload.
        if (not 0 < canonical_size <= MAX_CORE or structured_size > MAX_CORE
                or len(request) != CORE_OFFSET + canonical_size + structured_size):
            raise ValueError('native query captured-span framing mismatch')
        workspace_size = 456 * min(canonical_size, 262144) + canonical_size + 268560
        source = ctypes.create_string_buffer(request, len(request))
        output = ctypes.create_string_buffer(OUTPUT_BYTES)
        workspace = ctypes.create_string_buffer(workspace_size)
        result = self._entry(source, len(request), output, OUTPUT_BYTES,
                             workspace, workspace_size)
        if source.raw != request:
            raise ValueError('native query changed its captured read-only input')
        if result in REFUSALS or result == CUSTODY:
            return AgentQueryReceipt(result, b'', bytes(output.raw[:64]))
        if type(result) is not int or not 64 < result <= 64 + MAX_QUERY:
            raise ValueError('invalid native query return framing')
        header = bytes(output.raw[:64])
        fields = struct.unpack('<8Q', header)
        if fields != (RESULT_MAGIC, 1, result - 64, 0, 0, 0, 0, 0):
            raise ValueError('invalid native query published header')
        return AgentQueryReceipt(0, bytes(output.raw[64:result]), header)


def installed_agent_query(manifest_path: str) -> NativeAgentQuery:
    # Exact source/schema/factory binding; the worker whitelist must explicitly
    # register this owner before a pinned bundle can select it.
    return _installed_json_image(manifest_path, SOURCE, SCHEMA, NativeAgentQuery)


def prepare_native_query(document, *, native, function, block, output, fields):
    """Same first verifier as prepare_edit; provider provisioning is explicit.

    This draft does not silently use a seed image, hosted fallback, manifest
    environment key or unregistered image factory for ordinary callers.
    """
    from .hia_program import verify_program
    checked = verify_program(document)
    return call_admitted_query_image(native, checked, function=function,
                                     block=block, output=output, fields=fields)

def selected_agent_query():
    """Explicit installed selection only; absence retains the public default.

    A present empty selector is an admission error. An admitted selected
    image's refusal never falls back to hosted query construction.
    """
    import os
    if SELECTOR not in os.environ:
        return None
    selected = os.environ[SELECTOR]
    if not selected:
        raise ValueError('native complete-query manifest selector is empty')
    return installed_agent_query(selected)
