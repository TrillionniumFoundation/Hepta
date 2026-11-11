"""HIA-owned ordinary JSON canonical bytes and worker request admission.

The byte arena and request digest come from the immutable HIA image. This
adapter owns trusted code/buffer custody and materializes Python objects for
the existing service. It does not replace that service, its journal, response
serialization, or the Runtime process owner. Explicit selection never falls
back to the hosted request validator.
"""
from __future__ import annotations

import ctypes
import struct
import sys

from .hia_agent_data_json_native import materialize_data
from .hia_agent_store import AgentRejected
from .hia_json_decode_native import arena_sizes
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/worker_request.hepta')
SCHEMA = 'hepta.hia.worker-request-native.v1'
SELECTOR = 'HEPTA_HIA_WORKER_REQUEST_MANIFEST'
MAX_BYTES = 8 * 1024 * 1024
PRIVATE_BYTES = 16384

ERRORS = {
    0xffffffef: ('E_HIA_FIELDS', 'worker request has missing or unknown fields'),
    0xffffffee: ('E_HIA_WORKER_SCHEMA', 'unknown worker envelope'),
    0xffffffed: ('E_HIA_WORKER_IDENTITY', 'invalid worker digest field'),
    0xffffffec: ('E_HIA_CATALOG_STALE', 'worker request catalog differs from installed bytes'),
    0xffffffeb: ('E_HIA_WORKER_TOOL', 'invalid worker tool name'),
    0xffffffea: ('E_HIA_WORKER', 'E_HIA_EDIT: JSON encoding exceeds byte budget'),
    0xffffffe9: ('E_HIA_WORKER_IDENTITY', 'worker request digest mismatch'),
}


class NativeRequestRejected(AgentRejected):
    """A parsed request remains available for the existing correlation rule."""
    def __init__(self, code, message, request):
        super().__init__(code, message)
        self.request = request


def buffer_sizes(size):
    arena, keys = arena_sizes(size, 262144, 128)
    # Numeric normalization can grow, e.g. 1e15 -> 1000000000000000.0.
    # Reserve the actual full wire ceiling; the HIA appends are independently
    # checked. Decoder scratch and numeric scratch cannot alias the arena.
    return max(MAX_BYTES, keys), arena + PRIVATE_BYTES


class NativeWorkerRequest(NativeHiaJsonImage):
    def _run(self, raw, catalog=None):
        if type(raw) is not bytes or len(raw) > MAX_BYTES:
            raise ValueError('worker JSON must be bytes within 8 MiB')
        if catalog is not None and (type(catalog) is not str or len(catalog) != 64
                or any(ch not in '0123456789abcdef' for ch in catalog)):
            raise ValueError('trusted catalog pin must be canonical SHA-256')
        output_size, scratch_size = buffer_sizes(len(raw))
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        output = ctypes.create_string_buffer(output_size)
        scratch = ctypes.create_string_buffer(scratch_size)
        struct.pack_into('<2Q', scratch, 0, int(catalog is not None), sys.get_int_max_str_digits())
        if catalog is not None:
            ctypes.memmove(ctypes.addressof(scratch) + scratch_size - PRIVATE_BYTES + 64,
                           catalog.encode('ascii'), 64)
        result = self._entry(source, len(raw), output, output_size, scratch, scratch_size)
        if result == 0xfffffffd:
            raise RuntimeError('native worker request rejected its scratch profile')
        if result in (0xffffffff, 0xfffffffc, 0xfffffffe, 0xfffffff0):
            reasons = {0xffffffff: 'invalid JSON syntax or Unicode',
                       0xfffffffc: 'duplicate decoded object key',
                       0xfffffffe: 'JSON node/depth budget exceeded',
                       0xfffffff0: 'nonfinite number or integer conversion limit'}
            raise ValueError(reasons[result])
        if result not in ERRORS and not 1 <= result <= MAX_BYTES:
            raise RuntimeError('invalid native worker request result')
        # Validate the exact HIA arena in the shared foreign-value bridge. It
        # does not reparse JSON syntax, recompute a hash or encode any payload.
        arena_size = struct.unpack_from('<Q', scratch, 32)[0]
        if not 64 <= arena_size <= scratch_size - PRIVATE_BYTES:
            raise RuntimeError('invalid native worker request arena extent')
        arena = ctypes.string_at(scratch, arena_size)
        if result in ERRORS:
            request = materialize_data(arena, raw)
            code, message = ERRORS[result]
            raise NativeRequestRejected(code, message, request)
        return ctypes.string_at(output, result), arena

    def canonicalize(self, raw):
        """Canonical UTF-8 ordinary JSON, including finite binary64 values."""
        return self._run(raw)[0]

    def admit(self, raw, catalog):
        """Return the existing foreign request only after native admission."""
        if catalog is None:
            raise ValueError('trusted catalog pin must be canonical SHA-256')
        _canonical, arena = self._run(raw, catalog)
        return materialize_data(arena, raw)


def installed_worker_request(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeWorkerRequest)
