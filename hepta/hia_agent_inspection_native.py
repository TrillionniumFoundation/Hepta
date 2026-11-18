"""Pinned native Core summary and exact inspection of immutable subtrees."""
from __future__ import annotations

import ctypes
import struct

from .hia_agent_store import _agent_resource_path, reject
from .hia_json_decode_native import arena_sizes
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_program import MAX_BYTES, MAX_DEPTH, MAX_NODES
from .hia_program_tools import HIAEditRejected

SOURCE = _agent_resource_path('examples/hia_bootstrap/agent_inspection.hepta')
SCHEMA = 'hepta.hia.agent-inspection-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_INSPECTION_MANIFEST'
SELECTOR_BYTES = 512
HEADER = struct.Struct('<3Q')
TAIL = HEADER.size + 2 * SELECTOR_BYTES + 8
VIEW = b'HIAVIEW1'
SCHEMA_PROBE = b'HIAOSC01'
HASH_INPUT = b'HIAONH01'
IMPORT_DIAGNOSTICS = b'HIAADG01'
NOMINAL_CONTEXT = b'HIAONC01'
NOMINAL_TAIL = 9472
REFUSALS = {
    4294967288: 'function view requires an exact function',
    4294967289: 'function is not in this program',
    4294967290: 'block is not in this function',
}


class NativeAgentInspection(NativeHiaJsonImage):
    def view(self, canonical_core, view, selector):
        if (type(canonical_core) is not bytes or not 0 < len(canonical_core) <= MAX_BYTES
                or view not in ('function', 'block')):
            raise ValueError('invalid native HIA Agent inspection profile')
        fn = selector.get('function', '').encode('utf-8', 'surrogatepass')
        block = selector.get('block', '').encode('utf-8', 'surrogatepass')
        if len(fn) > SELECTOR_BYTES or len(block) > SELECTOR_BYTES:
            raise ValueError('invalid native HIA Agent inspection selector extent')
        arena_size, parser_size = arena_sizes(len(canonical_core), MAX_NODES, MAX_DEPTH)
        source = ctypes.create_string_buffer(canonical_core)
        output = ctypes.create_string_buffer(max(parser_size, len(canonical_core)))
        arena = ctypes.create_string_buffer(arena_size + TAIL)
        HEADER.pack_into(arena, arena_size, 1 if view == 'function' else 2, len(fn), len(block))
        at = arena_size + HEADER.size
        arena[at:at + len(fn)] = fn
        at += SELECTOR_BYTES
        arena[at:at + len(block)] = block
        arena[-8:] = VIEW
        width = self._entry(source, len(canonical_core), output, len(output), arena, len(arena))
        if width in REFUSALS:
            reject('E_HIA_SELECTOR', REFUSALS[width])
        if not 0 < width <= len(canonical_core):
            raise ValueError('invalid native HIA Agent inspection reply')
        return output.raw[:width]

    def summary(self, admitted):
        core = admitted.canonical_bytes
        original = admitted.structured_bytes
        context = b''
        if original is not None:
            version, _ = self._report(original, mode=SCHEMA_PROBE)
            if not 1 <= version <= 4:
                raise ValueError('unknown native Agent inspection input profile')
            length, digest = self._report(original, mode=HASH_INPUT)
            if length != 64:
                raise ValueError('invalid native Agent inspection input digest')
            context = NOMINAL_CONTEXT + struct.pack('<Q', version) + digest
        length, result = self._report(core, context=context)
        if length == 4294967294:
            raise HIAEditRejected('E_HIA_EDIT: JSON encoding exceeds byte budget')
        if not 0 < length <= MAX_BYTES:
            raise ValueError('invalid native HIA Agent inspection summary')
        return result

    def import_diagnostics(self, core, original, profile):
        context = b''
        if profile:
            length, digest = self._report(original, mode=HASH_INPUT)
            if length != 64:
                raise ValueError('invalid native Agent import digest')
            context = NOMINAL_CONTEXT + struct.pack('<Q', profile) + digest
        size, result = self._report(core, mode=IMPORT_DIAGNOSTICS, context=context)
        if not 0 < size <= 256 or len(result) != size:
            raise ValueError('invalid native Agent import diagnostics')
        return result

    def _report(self, raw, *, mode=bytes(8), context=b''):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_BYTES:
            raise ValueError('invalid native HIA Agent inspection input extent')
        arena_size, parser_size = arena_sizes(len(raw), MAX_NODES, MAX_DEPTH)
        output_size = (MAX_BYTES if mode == bytes(8)
                       else max(parser_size, len(raw), 256) if mode in (HASH_INPUT, IMPORT_DIAGNOSTICS)
                       else max(parser_size, 64))
        source = ctypes.create_string_buffer(raw)
        output = ctypes.create_string_buffer(output_size)
        workspace = ctypes.create_string_buffer(arena_size + NOMINAL_TAIL)
        workspace[arena_size:arena_size + len(context)] = context
        workspace[-8:] = mode
        size = self._entry(source, len(raw), output, output_size, workspace, len(workspace))
        return size, output.raw[:size] if 0 < size <= output_size else b''


def installed_agent_inspection(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeAgentInspection)
