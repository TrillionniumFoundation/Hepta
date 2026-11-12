"""Explicit experimental whole primitive Core admission image.

The HIA image checks declarations, instruction contracts, calls and complete
resource-flow bodies. The explicit selector leaves the default unchanged and
never falls back on refusal. Host decoding/custody/normalization are not replaced.
"""
import ctypes
from dataclasses import dataclass
import struct
import os
from pathlib import Path

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_function_shape_native import MAX_BYTES, MAX_NODES, scratch_sizes as declaration_sizes
from .hia_program_shape_native import ERROR_CODES as DECLARATION_ERRORS, ERROR_MESSAGES

from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/core_admission.hepta')
SCHEMA = 'hepta.hia.core-admission-native.v4'
SELECTOR = 'HEPTA_HIA_CORE_ADMISSION_MANIFEST'
ERROR_CODES = {**DECLARATION_ERRORS, 0xfffffff0: 'E_HIA_OPCODE',
               0xffffffef: 'E_HIA_RESOURCE', 0xffffffee: 'E_HIA_LOAN'}
CORE_ERROR_MESSAGES = {**ERROR_MESSAGES,
                       0xffffffee: 'returned loan must be its declared parameter or a direct child'}


DIAGNOSTIC_MAGIC = int.from_bytes(b'HIACD001', 'little')
DIAGNOSTIC_HEADER = 64
DIAGNOSTIC_CAPACITY = 512
DIAGNOSTIC_BYTES = DIAGNOSTIC_HEADER + DIAGNOSTIC_CAPACITY
BODY_DIAGNOSTIC_KIND = 16
BODY_DIAGNOSTIC_OFFSET = 16384
DECLARATION_DIAGNOSTIC_KIND = 17
DECLARATION_DIAGNOSTIC_STATUSES = frozenset({0xfffffffb, 0xfffffffa, 0xfffffff9, 0xfffffff8,
                                           0xfffffff7, 0xfffffff6, 0xfffffff5, 0xfffffff4,
                                           0xfffffff3, 0xfffffff2})
BODY_DIAGNOSTIC_STATUSES = frozenset({0xfffffffb, 0xfffffffa, 0xfffffff9, 0xfffffff8,
                                     0xfffffff7, 0xfffffff6, 0xfffffff3, 0xfffffff0,
                                     0xffffffef, 0xffffffee})


def scratch_sizes(size):
    state, arena = declaration_sizes(size)
    nodes = min(MAX_NODES, (size + 1) // 2 + 1)
    return state + nodes * 120 + DIAGNOSTIC_BYTES, arena


@dataclass(frozen=True)
class CoreAdmissionReceipt:
    status: int
    diagnostic_kind: int
    message: str | None
    raw: bytes
    native_executed: bool


class NativeCoreAdmission(NativeHiaJsonImage):
    def receipt(self, wire: bytes) -> CoreAdmissionReceipt:
        if type(wire) is not bytes:
            raise TypeError('exact JSON bytes required')
        if len(wire) > MAX_BYTES:
            return CoreAdmissionReceipt(0xfffffffe, 0, None, b'', False)
        state_size, arena_size = scratch_sizes(len(wire))
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        state = ctypes.create_string_buffer(state_size)
        arena = ctypes.create_string_buffer(arena_size)
        result = self._entry(source, len(wire), state, state_size, arena, arena_size)
        if source.raw[:len(wire)] != wire:
            raise RuntimeError('native Core admission changed its immutable input')
        if result not in {0, 0xfffffffd, *ERROR_CODES}:
            raise RuntimeError('invalid native whole Core result')
        if result == 0xfffffffd:
            return CoreAdmissionReceipt(result, 0, None, b'', True)
        raw = state.raw[-DIAGNOSTIC_BYTES:]
        magic, version, status, kind, size, capacity, reserved0, reserved1 = struct.unpack_from('<8Q', raw)
        if magic != DIAGNOSTIC_MAGIC or status != result:
            raise RuntimeError('invalid native Core diagnostic frame')
        if version == 1:
            if (capacity != DIAGNOSTIC_CAPACITY or reserved0 or reserved1
                    or size > DIAGNOSTIC_CAPACITY):
                raise RuntimeError('invalid native Core diagnostic frame')
            if kind == 0:
                if size:
                    raise RuntimeError('native Core diagnostic has no family')
                message = None
            elif ((kind == 1 and result == 0xfffffff5)
                  or (kind == 2 and result == 0xffffffef)):
                if not size:
                    raise RuntimeError('empty native Core value diagnostic')
                try:
                    message = raw[DIAGNOSTIC_HEADER:DIAGNOSTIC_HEADER + size].decode('ascii')
                except UnicodeDecodeError as error:
                    raise RuntimeError('native Core diagnostic is not admitted ASCII') from error
            else:
                raise RuntimeError('native Core diagnostic status and family differ')
            published = raw[:DIAGNOSTIC_HEADER + size]
        elif version == 2 and ((kind == BODY_DIAGNOSTIC_KIND and result in BODY_DIAGNOSTIC_STATUSES)
                              or (kind == DECLARATION_DIAGNOSTIC_KIND and result in DECLARATION_DIAGNOSTIC_STATUSES)):
            if (reserved0 != BODY_DIAGNOSTIC_OFFSET or reserved1
                    or capacity != state_size - DIAGNOSTIC_BYTES - BODY_DIAGNOSTIC_OFFSET
                    or not 0 < size <= capacity):
                raise RuntimeError('invalid native Core body diagnostic range')
            # Only transport already-published native bytes. No runtime text,
            # template, interpolation, ordering or policy is selected here.
            payload = ctypes.string_at(ctypes.addressof(state) + reserved0, size)
            try:
                message = payload.decode('utf-8')
            except UnicodeDecodeError as error:
                raise RuntimeError('native Core body diagnostic is not valid UTF-8') from error
            published = raw[:DIAGNOSTIC_HEADER] + payload
        else:
            raise RuntimeError('native Core diagnostic status and family differ')
        return CoreAdmissionReceipt(result, kind, message, published, True)

    def status(self, wire: bytes) -> int:
        return self.receipt(wire).status

    def admit(self, wire: bytes):
        from .hia_program import HIAProgramRejected
        receipt = self.receipt(wire)
        result = receipt.status
        if result == 0xfffffffd:
            raise RuntimeError('native whole Core scratch/ABI refusal')
        if result:
            message = receipt.message
            if message is None:
                message = CORE_ERROR_MESSAGES.get(result, 'native primitive Core admission rejected')
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
