"""Bind the selected HIA Store codec; the bridge only carries its bytes."""
import ctypes
import os
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/agent_store_transport.hepta')
SCHEMA = 'hepta.hia.agent-store-transport-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_STORE_TRANSPORT_MANIFEST'
UNIQUE_ACTION = struct.Struct('<4Q')
UNIQUE_OUTPUT = UNIQUE_ACTION.size + 8128
UNIQUE_WORKSPACE = 128


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

    def unique_row(self, request, plan, read):
        """Carry the Store byte stream; HIA controls every read and fragment."""
        state = ctypes.create_string_buffer(UNIQUE_WORKSPACE)
        output = ctypes.create_string_buffer(UNIQUE_OUTPUT)
        packet = struct.pack('<8s2Q', b'HIASTUR1', request, plan)
        row = bytearray()
        while True:
            source = ctypes.create_string_buffer(packet, len(packet))
            count = self._entry(source, len(packet), output, len(output), state, len(state))
            if not UNIQUE_ACTION.size <= count <= len(output):
                return None
            action, extent, coordinate, reserved = UNIQUE_ACTION.unpack_from(output)
            if reserved != 0:
                return None
            if action == 2:
                if not 0 < extent <= 8128 or count != UNIQUE_ACTION.size + extent or coordinate != len(row):
                    return None
                row.extend(output.raw[UNIQUE_ACTION.size:count])
                extent = 8
            elif action == 3:
                if (count != UNIQUE_ACTION.size or extent != len(row) or coordinate > 1
                        or (coordinate == 0 and row)):
                    return None
                return [bytes(row)] if coordinate == 1 else []
            elif action != 1 or count != UNIQUE_ACTION.size:
                return None
            if extent == 0 or extent > 8128:
                return None
            packet = b'HIASTUC1' + read(extent)

    def row_values(self, table, columns, data):
        header = struct.pack('<8s3Q', b'HIASTVL1', columns, table, len(data))
        directory = data[:32 + 24 * columns]
        raw = self._project(header + directory, 16)
        return None if raw is None else struct.unpack('<2Q', raw)

    def transaction(self, kind, status, count, previous, generation, receipt=b''):
        frame = struct.pack('<8s5Q', b'HIASTTX1', kind, status, count, previous, generation)
        raw = self._project(frame + receipt, 16)
        return None if raw is None else struct.unpack('<2Q', raw)

    def parameters(self, statement, form, cells, limit):
        count = len(cells)
        query = form is None
        header = struct.pack('<8s8s3Q', b'HIASTPA1', b'HIAQPA01' if query else form, statement, count, limit)
        fields = (struct.pack('<2Q', kind, len(payload)) for kind, payload in cells)
        directory = self._project(b''.join((header, *fields)), (32 if query else 40) + 24 * count)
        if directory is None:
            return None
        return b''.join((directory, *(payload for _, payload in cells)))


def selected_store_transport():
    selected = os.environ.get(SELECTOR)
    if selected is not None:
        return _installed_json_image(selected, SOURCE, SCHEMA, NativeAgentStoreTransport)
    return None


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
