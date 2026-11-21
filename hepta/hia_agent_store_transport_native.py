"""Bind the selected HIA Store codec; the bridge only carries its bytes."""
import ctypes
import os
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/agent_store_transport.hepta')
SCHEMA = 'hepta.hia.agent-store-transport-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_STORE_TRANSPORT_MANIFEST'


class NativeAgentStoreTransport(NativeHiaJsonImage):
    def _project(self, frame, extent):
        source = ctypes.create_string_buffer(frame, len(frame))
        output = ctypes.create_string_buffer(extent)
        count = self._entry(source, len(frame), output, extent, None, 0)
        if count == 0:
            return None
        if count != extent:
            raise ValueError('invalid HIA Store codec response extent')
        return output.raw

    def command(self, request, kind, target, size):
        return self._project(struct.pack('<8s4Q', b'HIASTCM1', request, kind, target, size), 48)

    def acknowledgement(self, request, kind, frame):
        raw = self._project(struct.pack('<8s2Q', b'HIASTAK1', request, kind) + frame, 48)
        return None if raw is None else struct.unpack('<6Q', raw)

    def query_header(self, table, limit, frame):
        raw = self._project(struct.pack('<8s2Q', b'HIASTRW1', table, limit) + frame, 56)
        return None if raw is None else struct.unpack('<7Q', raw)

    def query_event(self, kind, rowid, offset, data, *, pending_id, pending_size,
                    limit, rows, unique, plan, mask):
        frame = struct.pack('<8s12Q', b'HIASTEV1', kind, rowid, offset, len(data),
                            int(pending_size is not None), pending_id or 0, pending_size or 0,
                            limit, rows, int(unique), plan, mask)
        if kind == 4 and pending_size is None and len(data) == 416:
            frame += data
        raw = self._project(frame, 16)
        return None if raw is None else struct.unpack('<2Q', raw)


def selected_store_transport():
    selected = os.environ.get(SELECTOR)
    if selected is not None:
        return _installed_json_image(selected, SOURCE, SCHEMA, NativeAgentStoreTransport)
    return None


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
