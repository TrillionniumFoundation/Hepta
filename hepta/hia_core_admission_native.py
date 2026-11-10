"""Explicit experimental whole primitive Core admission image.

The HIA image checks declarations, instruction contracts, calls and complete
resource-flow bodies. The explicit selector leaves the default unchanged and
never falls back on refusal. Host decoding/custody/normalization are not replaced.
"""
import ctypes
import os
from pathlib import Path

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_function_shape_native import MAX_BYTES, MAX_NODES, scratch_sizes as declaration_sizes
from .hia_program_shape_native import ERROR_CODES as DECLARATION_ERRORS, ERROR_MESSAGES

SOURCE = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_admission.hiaasm'
SCHEMA = 'hepta.hia.core-admission-native.v1'
SELECTOR = 'HEPTA_HIA_CORE_ADMISSION_MANIFEST'
ERROR_CODES = {**DECLARATION_ERRORS, 0xfffffff0: 'E_HIA_OPCODE',
               0xffffffef: 'E_HIA_RESOURCE', 0xffffffee: 'E_HIA_LOAN'}
CORE_ERROR_MESSAGES = {**ERROR_MESSAGES,
                       0xffffffee: 'returned loan must be its declared parameter or a direct child'}


def scratch_sizes(size):
    state, arena = declaration_sizes(size)
    nodes = min(MAX_NODES, (size + 1) // 2 + 1)
    return state + nodes * 120, arena


class NativeCoreAdmission(NativeHiaJsonImage):
    def status(self, wire):
        if type(wire) is not bytes:
            raise TypeError('exact JSON bytes required')
        if len(wire) > MAX_BYTES:
            return 0xfffffffe
        state_size, arena_size = scratch_sizes(len(wire))
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        state = ctypes.create_string_buffer(state_size)
        arena = ctypes.create_string_buffer(arena_size)
        result = self._entry(source, len(wire), state, state_size, arena, arena_size)
        if result not in {0, 0xfffffffd, *ERROR_CODES}:
            raise RuntimeError('invalid native whole Core admission result')
        return result

    def admit(self, wire):
        from .hia_program import HIAProgramRejected
        result = self.status(wire)
        if result == 0xfffffffd:
            raise RuntimeError('native whole Core scratch/ABI refusal')
        if result:
            raise HIAProgramRejected(CORE_ERROR_MESSAGES.get(result, 'native primitive Core admission rejected'),
                                     ERROR_CODES[result])


def installed_core_admission(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeCoreAdmission)


def selected_core_structure(data, raw):
    """Admit the complete detached primitive document or remain unselected.

    Call only after the existing strict bounded decode and composite/legacy
    namespace handling. JSON decoding, object custody and normalization remain
    explicit host dependencies. A selected error never falls back to old policy.
    """
    path = os.environ.get(SELECTOR)
    if not path:
        return None
    installed_core_admission(path).admit(raw)
    # Materialization follows admission, not a second declaration/body check.
    functions = {fn['name']: fn for fn in data['functions']}
    blocks = {name: {block['id']: block for block in fn['blocks']}
              for name, fn in functions.items()}
    return functions, blocks
