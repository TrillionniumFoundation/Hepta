"""Read the scalar proof graph emitted from an already admitted Core input."""
from __future__ import annotations

import ctypes
import os
import struct

from .hia_cnf_native import (
    CIRCUIT_CAPACITY, CIRCUIT_NODES, CIRCUIT_REQUEST, GRAPH_PROJECTION_REQUEST, PROJECTION_INPUT_LIMIT,
)
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SELECTOR = 'HEPTA_HIA_CORE_PROOF_WIRE_MANIFEST'
SOURCE = _source_resource_path('examples/hia_bootstrap/core_proof_wire.hepta')
SCHEMA = 'hepta.hia.core-proof-wire-native.v1'
OBLIGATION_REQUEST = int.from_bytes(b'HIAOBL01', 'little')
OBLIGATION_SOLVER_REQUEST = int.from_bytes(b'HIAOBP01', 'little')
OBLIGATION_WITNESS_REQUEST = int.from_bytes(b'HIAOBW01', 'little')
MACHINE_RELOCATION_REQUEST = int.from_bytes(b'HIAELFX1', 'little')
ELF_FUNCTION_LINK_REQUEST = int.from_bytes(b'HIAELFX2', 'little')
ELF_OBJECT_RELOCATION_REQUEST = int.from_bytes(b'HIAELFX3', 'little')


class NativeCoreProofWire(NativeHiaJsonImage):
    def obligation_wire(self, role, observations=b''):
        """Read one scalar proof obligation assembled by HIA from native observations."""
        if not 0 <= role < 5 or len(observations) > 80 + 40 * CIRCUIT_NODES:
            raise ValueError('outside the scalar artifact obligation profile')
        source = struct.pack('<4Q', OBLIGATION_REQUEST, role, len(observations), 0) + observations
        frame = self._proof_wire_exchange(source, 64 + 40 * CIRCUIT_NODES)
        if frame is None:
            return None
        magic, nodes, pairs, reserved = struct.unpack_from('<4Q', frame)
        split = 32 + 40 * nodes
        if (magic != CIRCUIT_REQUEST or nodes > CIRCUIT_NODES or pairs > 2 or reserved
                or len(frame) != split + 16 * pairs):
            raise RuntimeError('invalid native scalar artifact obligation identity')
        return frame

    def solver_frame(self, phase, role, payload, *, remaining=0):
        request = struct.pack('<4Q', OBLIGATION_SOLVER_REQUEST, phase, role, remaining)
        return self._proof_wire_exchange(request + payload, CIRCUIT_CAPACITY)

    def witness_frame(self, circuit, decision, mapping):
        request = struct.pack('<4Q', OBLIGATION_WITNESS_REQUEST, len(circuit), len(decision), len(mapping))
        return self._proof_wire_exchange(request + circuit + decision + mapping, CIRCUIT_CAPACITY)

    def machine_relocation_frame(self, text_size, address, entry, arguments, profile, relocations):
        packet = struct.pack('<6Q', MACHINE_RELOCATION_REQUEST, text_size, address, entry, arguments, profile)
        return self._proof_wire_exchange(packet + relocations, CIRCUIT_CAPACITY)

    def elf_function_link_frame(self, source, target, export):
        name = export.encode('utf-8')
        if len(name) > 256:
            return None
        head = struct.pack('<4Q256s', ELF_FUNCTION_LINK_REQUEST, len(source), len(target), len(name), name)
        return self._proof_wire_exchange(head + source + target, CIRCUIT_CAPACITY)

    def elf_object_relocation_frame(self, layout, text, address, abort, helper):
        header = struct.pack('<5Q', ELF_OBJECT_RELOCATION_REQUEST, len(layout), address, abort, helper)
        return self._proof_wire_exchange(header + layout + text, CIRCUIT_CAPACITY)

    def _proof_wire_exchange(self, source, capacity):
        output = ctypes.create_string_buffer(capacity)
        scratch = ctypes.create_string_buffer(1)
        size = self._checked_default_entry(source, len(source), output, len(output), scratch, len(scratch))
        if size == 0xfffffffc:
            return None
        if not 32 <= size <= len(output):
            raise RuntimeError('invalid native scalar proof response extent')
        return output.raw[:size]

    def project(self, source):
        # The caller has independently verified these exact immutable bytes.
        # This filter packs the model; it does not authorize publication.
        output = ctypes.create_string_buffer(max(2 << 20, len(source)))
        workspace = ctypes.create_string_buffer((4 << 20) + len(source))
        size = self._checked_default_entry(source, len(source), output, len(output), workspace, len(workspace))
        if size == 0xfffffffc:
            return None
        if not 32 <= size <= PROJECTION_INPUT_LIMIT:
            raise RuntimeError('invalid native Core proof frame extent')
        magic, mode, arguments, returns = struct.unpack_from('<4Q', output)
        paths, = struct.unpack_from('<Q', workspace, 40)
        if (magic, mode, returns) != (GRAPH_PROJECTION_REQUEST, 2, 1) or not 1 <= paths <= 1024 or arguments > 6:
            raise RuntimeError('invalid native Core proof graph header')
        return output.raw[:size], paths


def selected_core_proof_wire():
    manifest = os.environ.get(SELECTOR)
    return None if manifest is None else _installed_json_image(manifest, SOURCE, SCHEMA, NativeCoreProofWire)


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
