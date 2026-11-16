"""Explicit experimental whole primitive Core admission image.

The HIA image checks declarations, instruction contracts, calls and complete
resource-flow bodies. The explicit selector leaves the default unchanged and
never falls back on refusal. Host decoding/custody/normalization are not replaced.
"""
import ctypes
from contextvars import ContextVar
import os
from pathlib import Path

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_function_shape_native import MAX_BYTES, MAX_NODES, scratch_sizes as declaration_sizes
from .hia_program_shape_native import ERROR_CODES as DECLARATION_ERRORS
from .hia_core_diagnostic_protocol import (
    TABLE_CAPACITY, TRAILER_BYTES, DIAGNOSTIC_MAGIC,
    diagnostic_capacity, diagnostic_scratch_bytes,
)

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/core_admission.hepta')
SCHEMA = 'hepta.hia.core-admission-native.v1'
SELECTOR = 'HEPTA_HIA_CORE_ADMISSION_MANIFEST'
ERROR_CODES = {**DECLARATION_ERRORS, 0xfffffff0: 'E_HIA_OPCODE',
               0xffffffef: 'E_HIA_RESOURCE', 0xffffffee: 'E_HIA_LOAN'}
_DIAGNOSTIC_SINK = ContextVar('hia_core_admission_diagnostic_sink', default=None)
def scratch_sizes(size):
    state, arena = declaration_sizes(size)
    nodes = min(MAX_NODES, (size + 1) // 2 + 1)
    return state + nodes * 120 + diagnostic_scratch_bytes(size), arena


class NativeCoreAdmission(NativeHiaJsonImage):
    def _invoke(self, wire):
        if type(wire) is not bytes:
            raise TypeError('exact JSON bytes required')
        if len(wire) > MAX_BYTES:
            return 0xfffffffe, 'program exceeds byte budget'
        state_size, arena_size = scratch_sizes(len(wire))
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        state = ctypes.create_string_buffer(state_size)
        arena = ctypes.create_string_buffer(arena_size)
        result = self._entry(source, len(wire), state, state_size, arena, arena_size)
        if result not in {0, 0xfffffffd, *ERROR_CODES}:
            raise RuntimeError('invalid native whole Core admission result')
        if result in {0, 0xfffffffd}:
            return result, None
        trailer = state_size - TRAILER_BYTES
        trailer_bytes = ctypes.string_at(ctypes.addressof(state) + trailer, TRAILER_BYTES)
        words = tuple(int.from_bytes(trailer_bytes[offset:offset + 8], 'little')
                      for offset in range(0, TRAILER_BYTES, 8))
        table, output, size, capacity, status, magic, fault, reserved = words
        expected_table = state_size - diagnostic_scratch_bytes(len(wire))
        if (table != expected_table or output != table + TABLE_CAPACITY
                or capacity != diagnostic_capacity(len(wire)) or not 0 < size <= capacity
                or output + capacity != trailer or status != result
                or magic != DIAGNOSTIC_MAGIC or fault or reserved):
            raise RuntimeError('invalid native whole Core diagnostic trailer')
        try:
            message = ctypes.string_at(ctypes.addressof(state) + output, size).decode('utf-8')
        except UnicodeDecodeError as error:
            raise RuntimeError('invalid native whole Core diagnostic UTF-8') from error
        return result, message

    def status(self, wire):
        result, message = self._invoke(wire)
        sink = _DIAGNOSTIC_SINK.get()
        if sink is not None and sink[0] is self and sink[1] is wire:
            sink[2].append((result, message))
        return result

    def admit(self, wire):
        from .hia_program import HIAProgramRejected
        # Keep the public status boundary observable and invoke the image once.
        # This sink is scoped to one call, isolated across threads/tasks and
        # restored on re-entry; it never caches policy or an earlier message.
        messages = []
        token = _DIAGNOSTIC_SINK.set((self, wire, messages))
        try:
            result = self.status(wire)
        finally:
            _DIAGNOSTIC_SINK.reset(token)
        if len(messages) != 1 or messages[0][0] != result:
            raise RuntimeError('missing native whole Core diagnostic invocation')
        message = messages[0][1]
        if result == 0xfffffffd:
            raise RuntimeError('native whole Core scratch/ABI refusal')
        if result:
            raise HIAProgramRejected(message, ERROR_CODES[result])


def installed_core_admission(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeCoreAdmission)


def selected_core_structure(data, raw):
    """Admit the complete detached primitive document or remain unselected.

    Call only after the existing strict bounded decode and composite/legacy
    namespace handling. JSON decoding, object custody and normalization remain
    explicit host dependencies. A selected error never falls back to old policy.
    """
    if SELECTOR not in os.environ:
        return None
    path = os.environ[SELECTOR]
    if not path:
        raise ValueError('Core admission selector must not be empty')
    installed_core_admission(path).admit(raw)
    # Materialization follows admission, not a second declaration/body check.
    functions = {fn['name']: fn for fn in data['functions']}
    blocks = {name: {block['id']: block for block in fn['blocks']}
              for name, fn in functions.items()}
    return functions, blocks
