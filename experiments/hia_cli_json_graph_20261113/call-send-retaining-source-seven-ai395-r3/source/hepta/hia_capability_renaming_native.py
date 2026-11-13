"""Native Core edge policy; host-owned symbol/Capability transport is explicit.

Dense symbols encode exact string identity only. They are not pre-resolved
capability/map indexes: absent sources, duplicate targets, dropped locals and
root/parent closure are all decided by HIA. The complete Core verifier still
checks operation typing, borrow creation/end, joins, returns and permissions.
"""
from __future__ import annotations

import ctypes
from pathlib import Path
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/capability_renaming.hiaasm')
SCHEMA = 'hepta.hia.capability-renaming-native.v1'
MAGIC = int.from_bytes(b'HIACAP01', 'little')
RESULT = int.from_bytes(b'HIACAR01', 'little')
NONE = (1 << 64) - 1
MAX_CAPABILITIES = 262144
MAX_SYMBOLS = 2097152
SELECTOR = 'HEPTA_HIA_CAPABILITY_RENAMING_MANIFEST'
ERRORS = {
    0xffffffff: ('exact internal capability graph and name map required', 'E_HIA_RESOURCE'),
    0xfffffffe: ('insufficient native capability result or workspace', 'E_HIA_RESOURCE'),
    0xfffffffd: ('linear capability duplicated across an edge', 'E_HIA_RESOURCE'),
    0xfffffffc: ('edge names an absent capability', 'E_HIA_RESOURCE'),
    0xfffffffb: ('edge drops a live owner or local loan', 'E_HIA_RESOURCE'),
    0xfffffffa: ('loan must travel with its owner/parent capability', 'E_HIA_LOAN'),
}


def encode_graph(capabilities, remap):
    """Snapshot verifier-owned records, preserving opaque string identities.

    Counts inherit the full Core node ceiling, not a smaller demo-graph bound.
    No graph relation is computed in this encoder. No mutable input container
    is consulted again after the private records have been captured.
    """
    from .hia_capability_flow import Capability, CapabilityFlowRejected
    def reject():
        raise CapabilityFlowRejected('exact internal capability graph and name map required')
    if type(capabilities) is not dict or type(remap) is not dict:
        reject()
    if len(capabilities) > MAX_CAPABILITIES or len(remap) > MAX_CAPABILITIES:
        reject()
    try:
        caps, edges = tuple(capabilities.items()), tuple(remap.items())
    except RuntimeError as exc:
        raise CapabilityFlowRejected('capability transport changed during capture') from exc
    if len(caps) > MAX_CAPABILITIES or len(edges) > MAX_CAPABILITIES:
        reject()
    symbols, ids = [], {}
    def symbol(value, nullable=False):
        if value is None and nullable:
            return NONE
        if type(value) is not str:
            reject()
        if value not in ids:
            ids[value] = len(symbols)
            symbols.append(value)
        return ids[value]
    rows = bytearray()
    for name, cap in caps:
        if type(name) is not str or type(cap) is not Capability or type(cap.external) is not bool:
            reject()
        rows.extend(struct.pack('<6Q', symbol(name), symbol(cap.typ), symbol(cap.root),
                                symbol(cap.parent, True), int(cap.external), symbol(cap.origin, True)))
    for source, target in edges:
        rows.extend(struct.pack('<2Q', symbol(source), symbol(target)))
    if len(symbols) > MAX_SYMBOLS:
        reject()
    return struct.pack('<8Q', MAGIC, len(caps), len(edges), len(symbols), 0, 0, 0, 0) + rows, tuple(symbols)


class NativeCapabilityRenaming(NativeHiaJsonImage):
    def run(self, wire):
        from .hia_capability_flow import CapabilityFlowRejected
        if type(wire) is not bytes or not 64 <= len(wire) <= 64 + MAX_CAPABILITIES * 64:
            raise CapabilityFlowRejected(ERRORS[0xffffffff][0])
        magic, n, m, ns, *reserved = struct.unpack_from('<8Q', wire)
        if (magic != MAGIC or n > MAX_CAPABILITIES or m > MAX_CAPABILITIES
                or ns > MAX_SYMBOLS or any(reserved) or len(wire) != 64 + n * 48 + m * 16):
            raise CapabilityFlowRejected(ERRORS[0xffffffff][0])
        size = 64 + m * 48
        source = ctypes.create_string_buffer(wire, len(wire))
        output = ctypes.create_string_buffer(size)
        state = ctypes.create_string_buffer(size + ns * 24)
        status = self._entry(source, len(wire), output, size, state, len(state))
        if status in ERRORS:
            message, code = ERRORS[status]
            raise CapabilityFlowRejected(message, code)
        if status != size:
            raise CapabilityFlowRejected('invalid native capability return')
        return output.raw

    def rename(self, capabilities, remap):
        from .hia_capability_flow import Capability, CapabilityFlowRejected
        wire, symbols = encode_graph(capabilities, remap)
        result = self.run(wire)
        _, _, m, ns, *_ = struct.unpack_from('<8Q', wire)
        if struct.unpack_from('<8Q', result) != (RESULT, m, ns, 0, 0, 0, 0, 0):
            raise CapabilityFlowRejected('invalid native capability result header')
        output = {}
        for name, typ, root, parent, external, origin in struct.iter_unpack('<6Q', result[64:]):
            if (name >= ns or typ >= ns or root >= ns or external > 1
                    or parent != NONE and parent >= ns or origin != NONE and origin >= ns):
                raise CapabilityFlowRejected('invalid native capability output symbol')
            output[symbols[name]] = Capability(symbols[typ], symbols[root],
                symbols[parent] if parent != NONE else None, bool(external),
                symbols[origin] if origin != NONE else None)
        if len(output) != m:
            raise CapabilityFlowRejected('invalid native capability output inventory')
        return output


def installed_capability_renaming(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeCapabilityRenaming)
