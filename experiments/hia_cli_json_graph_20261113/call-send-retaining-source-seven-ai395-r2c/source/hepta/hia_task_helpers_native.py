"""Explicit native task-helper Core generation with descriptor-only transport.

HIA owns every generated name, instruction, block, effect and cleanup decision.
The bridge copies resolved descriptors and decodes a complete generated Core
function; it never interprets a lowering plan. Type/protocol resolution and the
surrounding elaborator remain separately selected owners.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import json
import os
import struct

from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_program import HIAProgramRejected

SOURCE = _source_resource_path('examples/hia_bootstrap/task_helpers.hiaasm')
SCHEMA = 'hepta.hia.task-helpers-native.v1'
SELECTOR = 'HEPTA_HIA_TASK_HELPERS_MANIFEST'
MAGIC = int.from_bytes(b'HIATHP01', 'little')
HEADER_BYTES = 64
INPUT_BYTES = 128 << 10
OUTPUT_BYTES = 4 << 20
WORKSPACE_BYTES = 2 << 20
ERRORS = {
    1: ('E_HIA_LIMIT', 'nominal elaboration expansion budget exceeded'),
    2: ('E_HIA_LOAN', 'cannot invent an inactive loan'),
    3: ('E_HIA_LOAN', 'inactive padding contains a loan'),
}


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate native task-helper field')
        value[key] = item
    return value


def _constant(value):
    raise ValueError('non-JSON constant in native task-helper result')


@dataclass(frozen=True)
class HelperResult:
    serial: int
    name: str | None
    helper: dict | None
    error: int

    def admit(self):
        if self.error:
            code, message = ERRORS[self.error]
            raise HIAProgramRejected(message, code)


def packet(typ, step, operation, serial, poll_effects, cancel_effects):
    """Copy descriptor fields verbatim; all layout use and effect union is HIA."""
    return transport([serial, operation, typ.flat, typ.state.flat, typ.result.flat,
        step.flat, [[variant, [field.flat for _, field in fields]]
                    for variant, fields in step.variants],
        typ.poll, typ.cancel, poll_effects, cancel_effects])


class NativeTaskHelpers(NativeHiaJsonImage):
    def generate(self, typ, step, operation, serial, poll_effects, cancel_effects):
        if type(serial) is not int or not 0 <= serial <= 8192:
            raise HIAProgramRejected('native task-helper counter outside ABI', 'E_HIA_TYPE')
        wire = packet(typ, step, operation, serial, poll_effects, cancel_effects)
        return self.generate_packet(wire, serial=serial)

    def generate_packet(self, wire, *, serial):
        """A real image call with private buffers and byte-exact input readback."""
        def reject(message):
            raise HIAProgramRejected('native task-helper transport: ' + message, 'E_HIA_TYPE')
        if (type(wire) is not bytes or len(wire) > INPUT_BYTES
                or type(serial) is not int or not 0 <= serial <= 8192):
            reject('invalid packet or starting counter')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(OUTPUT_BYTES)
        workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        extent = self._entry(source, len(wire), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire:
            reject('input bytes changed')
        if type(extent) is not int or not HEADER_BYTES <= extent <= OUTPUT_BYTES:
            reject('invalid result extent/status ' + str(extent))
        magic, error, final, name_id, size, r0, r1, r2 = struct.unpack_from('<8Q', output)
        expected_name = serial + 1 if serial < 8192 else 0
        if (magic != MAGIC or error not in {0, *ERRORS} or r0 or r1 or r2
                or size != extent - HEADER_BYTES or not serial <= final <= 8192
                or name_id != expected_name or (error == 1 and final != 8192)
                or (error != 1 and (not name_id or final < name_id))):
            reject('invalid header or fresh-state correlation')
        try:
            payload = json.loads(ctypes.string_at(ctypes.addressof(output) + HEADER_BYTES, size),
                object_pairs_hook=_pairs, parse_constant=_constant)
            if type(payload) is not dict or set(payload) != {'helper'}:
                raise ValueError('invalid envelope')
            helper = payload['helper']
            name = 'h2internal_' + str(name_id) if name_id else None
            if error:
                if helper is not None:
                    raise ValueError('semantic refusal supplied a helper')
            elif (type(helper) is not dict or set(helper) !=
                    {'name', 'params', 'returns', 'effects', 'entry', 'blocks'}
                    or helper['name'] != name or type(helper['entry']) is not str
                    or any(type(helper[field]) is not list
                           for field in ('params', 'returns', 'effects', 'blocks'))):
                raise ValueError('invalid complete Core function envelope')
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            reject('invalid payload: ' + str(exc))
        return HelperResult(final, name, helper, error)


def installed_task_helpers(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeTaskHelpers)


def selected_task_helpers():
    path = os.environ.get(SELECTOR)
    if not path:
        return None
    try:
        return installed_task_helpers(path)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native task helpers refused: ' + str(exc),
                                 'E_HIA_TYPE') from exc
