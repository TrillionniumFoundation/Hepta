"""Read the scalar proof graph emitted from an already admitted Core input."""
from __future__ import annotations

import ctypes
import os
import struct

from .hia_cnf_native import GRAPH_PROJECTION_REQUEST, PROJECTION_INPUT_LIMIT
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SELECTOR = 'HEPTA_HIA_CORE_PROOF_WIRE_MANIFEST'
SOURCE = _source_resource_path('examples/hia_bootstrap/core_proof_wire.hepta')
SCHEMA = 'hepta.hia.core-proof-wire-native.v1'


class NativeCoreProofWire(NativeHiaJsonImage):
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
