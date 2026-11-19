"""HIA-owned ordinary JSON canonical bytes and worker request admission.

The byte arena, request digest and admitted terminal envelope come from the
immutable HIA image. The adapter holds buffers and materializes objects for
the existing service; it does not replace the service, its body serialization,
its journal or the Runtime process owner.
"""
from __future__ import annotations

import ctypes
from functools import partial
import os
import struct
import subprocess
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
TERMINAL_FRAME = struct.Struct('<8s4Q')

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
    def matches_standalone(self, executable):
        return executable.startswith(b'\x7fELF') and executable.count(self._mapping[:]) == 1

    def _run(self, raw, catalog=None, *, terminal=False):
        if type(raw) is not bytes or len(raw) > MAX_BYTES:
            raise ValueError('worker JSON must be bytes within 8 MiB')
        if catalog is not None and (type(catalog) is not str or len(catalog) != 64
                or any(ch not in '0123456789abcdef' for ch in catalog)):
            raise ValueError('trusted catalog pin must be canonical SHA-256')
        output_size, scratch_size = buffer_sizes(len(raw))
        source = ctypes.create_string_buffer(raw, max(1, len(raw)))
        output = ctypes.create_string_buffer(output_size)
        scratch = ctypes.create_string_buffer(scratch_size)
        max_digits = sys.get_int_max_str_digits()
        struct.pack_into('<2Q', scratch, 0, int(catalog is not None), max_digits)
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
        if terminal:
            request = materialize_data(arena, raw)
            from .hia_native_helpers import pinned_worker_terminal_executable

            executable = pinned_worker_terminal_executable()
            if executable is not None:
                admitted = raw

                def terminal(identities, body):
                    nonlocal admitted
                    if admitted is None:
                        raise ValueError('native worker terminal report was not admitted')
                    _validate_terminal_body(body)
                    pins = _terminal_pins(identities)
                    payload, admitted = admitted, None
                    return _standalone_terminal(executable, payload, catalog, max_digits, pins, body)

                return request, terminal
            return request, partial(self._terminal, scratch)
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

    def admit_for_terminal(self, raw, catalog):
        """Keep the admitted arena for this worker's one terminal report."""
        if catalog is None:
            raise ValueError('trusted catalog pin must be canonical SHA-256')
        return self._run(raw, catalog, terminal=True)

    def _terminal(self, scratch, identities, body):
        _validate_terminal_body(body)
        pins = _terminal_pins(identities)
        size = ctypes.sizeof(scratch)
        struct.pack_into('<Q', scratch, 0, 2)
        at = size - PRIVATE_BYTES + 520
        struct.pack_into('<Q', scratch, at, len(pins) - 2)
        ctypes.memmove(ctypes.addressof(scratch) + at + 8, b''.join(pins), 64 * len(pins))
        source = ctypes.create_string_buffer(body, max(1, len(body)))
        output = ctypes.create_string_buffer(MAX_BYTES)
        result = self._entry(source, len(body), output, MAX_BYTES, scratch, size)
        if result == 0xffffffea:
            raise ValueError('E_HIA_EDIT: JSON encoding exceeds byte budget')
        if not 0 < result <= MAX_BYTES:
            raise ValueError('native worker terminal report was not admitted')
        return ctypes.string_at(output, result)


def _validate_terminal_body(body):
    if type(body) is not bytes or len(body) > MAX_BYTES:
        raise ValueError('worker terminal JSON must be bytes within 8 MiB')


def _terminal_pins(identities):
    names = ('backend_sha256', 'worker_sha256')
    if 'native_helpers_sha256' in identities:
        names += ('native_helpers_sha256',)
    pins = [identities[name].encode('ascii') for name in names]
    if any(len(pin) != 64 for pin in pins):
        raise ValueError('invalid terminal source identity')
    return pins


def _standalone_terminal(executable, request, catalog, max_digits, pins, body):
    from .hia_scalar_reference_native import sealed_reference_bytes

    helpers = len(pins) - 2
    header = TERMINAL_FRAME.pack(b'HIATRP01', len(request), len(body), max_digits, helpers)
    header += catalog.encode('ascii') + b''.join(pins) + (b'\0' * 64 if not helpers else b'')
    with (sealed_reference_bytes(executable) as program,
          sealed_reference_bytes(header, request, body) as contents):
        os.lseek(contents, 0, os.SEEK_SET)
        child = subprocess.run(['/proc/self/fd/' + str(program)], stdin=contents,
                               pass_fds=(program,), capture_output=True, env={'PATH': ''})
    if child.returncode == 3 and not child.stdout and not child.stderr:
        raise ValueError('E_HIA_EDIT: JSON encoding exceeds byte budget')
    if (child.returncode or child.stderr or not 1 < len(child.stdout) <= MAX_BYTES + 1
            or not child.stdout.endswith(b'\n')):
        raise ValueError('native worker terminal report was not admitted')
    return child.stdout[:-1]


def installed_worker_request(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeWorkerRequest)
