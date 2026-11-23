"""Bind the native Worker's public Inspect request projection to the service."""
import ctypes
import struct

from .hia_agent_store import _agent_resource_path, reject, wire
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image


SOURCE = _agent_resource_path('examples/hia_bootstrap/worker_inspection_request.hepta')
SCHEMA = 'hepta.hia.inspection-request-native.v1'
SELECTOR = 'HEPTA_HIA_INSPECTION_REQUEST_MANIFEST'
VIEWS = ('summary', 'function', 'block', 'dependencies', 'lowering')
HEADER = struct.Struct('<8sQQ')
WORD = struct.Struct('<Q')


def _fragment(packet, offset):
    if len(packet) - offset < WORD.size:
        raise ValueError('incomplete native Inspect projection')
    size, = WORD.unpack_from(packet, offset)
    start = offset + WORD.size
    end = start + size
    if end > len(packet):
        raise ValueError('invalid native Inspect fragment extent')
    return packet[start:end], end


class NativeWorkerInspectionRequest(NativeHiaJsonImage):
    def project(self, arguments, catalog_sha256):
        raw = wire([catalog_sha256, arguments])
        if not 2 <= len(raw) <= 16384:
            raise ValueError('native Inspect request exceeds its wire extent')
        source = ctypes.create_string_buffer(raw, len(raw))
        output = ctypes.create_string_buffer(16384)
        workspace = ctypes.create_string_buffer(65536)
        size = self._entry(source, len(raw), output, len(output), workspace, len(workspace))
        if not HEADER.size <= size <= len(output):
            raise ValueError('invalid native Inspect request projection')
        packet = output.raw[:size]
        tag, ordinal, disposition = HEADER.unpack_from(packet)
        if tag != b'HIAINR01' or not 1 <= ordinal <= len(VIEWS):
            raise ValueError('unknown native Inspect request projection')
        view = VIEWS[ordinal - 1]
        # The public service already resolved the context and program references.
        _, offset = _fragment(packet, HEADER.size)
        _, offset = _fragment(packet, offset)
        if disposition:
            if offset != size:
                raise ValueError('invalid native Inspect refusal extent')
            if disposition == 1:
                reject('E_HIA_CURSOR', 'inspection returns an immutable artifact; paginate it through hia_read')
            if disposition == 2 and view == 'dependencies':
                reject('E_HIA_SELECTOR', 'dependencies require function, block and output')
            raise ValueError('unknown native Inspect request refusal')

        fields = ('function', 'block', 'output') if view == 'dependencies' else (
            ('function', 'block') if view in ('function', 'block') else ())
        selector = {}
        for field in fields:
            part, offset = _fragment(packet, offset)
            if len(part) > 512:
                raise ValueError('invalid native Inspect selector extent')
            selector[field] = part.decode('utf-8', 'surrogatepass')
        if offset != size:
            raise ValueError('unexpected native Inspect selector bytes')
        return view, selector


def installed_worker_inspection_request(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeWorkerInspectionRequest)
