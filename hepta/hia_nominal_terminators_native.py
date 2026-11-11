"""Native nominal exit/edge policy with lossless descriptor and object transport."""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import os
import struct

from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_native_value_graph import decode_native_graph
from .hia_program import HIAProgramRejected

SOURCE = _source_resource_path('examples/hia_bootstrap/nominal_terminators.hiaasm')
SCHEMA = 'hepta.hia.nominal-terminators-native.v1'
SELECTOR = 'HEPTA_HIA_NOMINAL_TERMINATORS_MANIFEST'
MAGIC = int.from_bytes(b'HIANTM01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 16 << 20
WORKSPACE_BYTES = 32 << 20
ERRORS = {
    1: ('E_HIA_CFG', 'missing nominal terminator'),
    2: ('E_HIA_FORMAT', 'jump: expected exactly args, op, target'),
    3: ('E_HIA_FORMAT', 'branch: expected exactly cond, else, op, then'),
    4: ('E_HIA_NAME', 'value reference: invalid/reserved ASCII identifier'),
    5: ('E_HIA_NAME', 'value reference: identifier uses the elaborator namespace'),
    6: ('E_HIA_SSA', 'undefined/nonlocal nominal value'),
    7: ('E_HIA_RESOURCE', 'use of consumed nominal value'),
    8: ('E_HIA_CFG', 'nominal branch condition must be bool'),
    9: ('E_HIA_FORMAT', 'nominal edge: expected exactly args, target'),
    10: ('E_HIA_NAME', 'edge target: invalid/reserved ASCII identifier'),
    11: ('E_HIA_NAME', 'edge target: identifier uses the elaborator namespace'),
    12: ('E_HIA_FORMAT', 'edge arguments: expected value list'),
    13: ('E_HIA_NAME', 'edge arguments: invalid/reserved ASCII identifier'),
    14: ('E_HIA_CFG', 'nominal edge names a missing block'),
    15: ('E_HIA_RESOURCE', 'nominal linear value duplicated on edge'),
    16: ('E_HIA_RESOURCE', 'edge drops a live nominal value'),
    17: ('E_HIA_TYPE', 'nominal edge types differ'),
    18: ('E_HIA_FORMAT', 'return: expected exactly op, values'),
    19: ('E_HIA_FORMAT', 'return values: expected value list'),
    20: ('E_HIA_NAME', 'return values: invalid/reserved ASCII identifier'),
    21: ('E_HIA_TYPE', 'nominal return types differ'),
    22: ('E_HIA_RESOURCE', 'return leaves a live nominal value'),
    23: ('E_HIA_FORMAT', 'trap: expected exactly code, op'),
    24: ('E_HIA_CFG', 'unknown nominal terminator'),
}


class TerminatorPacket:
    """Hold original descriptors and value aliases without semantic comparisons."""
    def __init__(self, term, environment, signatures, returns, serial):
        self.types, self.type_ids, self.values, value_ids = [], {}, [], {}
        rows = []
        for name, value in environment.items():
            if id(value) not in value_ids:
                value_ids[id(value)] = len(self.values)
                self.values.append(value)
            rows.append([name, self.type_ref(value.typ), value.names,
                         value.external, value.consumed, value_ids[id(value)]])
        targets = [[name, [self.type_ref(typ) for _, typ in parameters]]
                   for name, parameters in signatures.items()]
        expected = [self.type_ref(typ) for typ in returns]
        descriptors = [[typ.kind, typ.flat, typ.linear] for typ in self.types]
        self.wire = transport([serial, term, descriptors, rows, targets, expected])

    def type_ref(self, typ):
        if id(typ) not in self.type_ids:
            self.type_ids[id(typ)] = len(self.types)
            self.types.append(typ)
        return self.type_ids[id(typ)]


@dataclass(frozen=True)
class TerminatorResult:
    serial: int
    error: int
    request: int
    structured: bool
    term: dict | None
    states: list

    def admit(self):
        if self.error:
            code, message = ERRORS[self.error]
            raise HIAProgramRejected(message, code)


class NativeNominalTerminators(NativeHiaJsonImage):
    def lower(self, term, environment, signatures, returns, serial):
        context = TerminatorPacket(term, environment, signatures, returns, serial)
        return self.lower_packet(context.wire, context.values, serial)

    def lower_packet(self, wire, values, serial):
        def reject(message):
            raise HIAProgramRejected('native nominal terminator transport: ' + message, 'E_HIA_TYPE')
        if (type(wire) is not bytes or len(wire) > INPUT_BYTES or type(serial) is not int
                or not 0 <= serial <= 8192 or len(values) > 262144):
            reject('invalid input/counter extent')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(OUTPUT_BYTES)
        workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        extent = self._entry(source, len(wire), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire:
            reject('original bytes changed')
        if type(extent) is not int or not 80 <= extent <= OUTPUT_BYTES:
            reject('invalid native result extent/status ' + str(extent))
        magic, error, final, size, request, structured, count, reserved = struct.unpack_from('<8Q', output)
        if (magic != MAGIC or error not in {0, *ERRORS} or reserved or final != serial
                or size != extent - 64 or request not in (0, 1) or structured not in (0, 1)
                or count != len(values) or 64 + count * 8 + 16 > extent
                or (error == 1) != (structured == 0) or request and error):
            reject('invalid result/counter/state framing')
        flags = [struct.unpack_from('<Q', output, 64 + i * 8)[0] for i in range(count)]
        if (any(flag not in (0, 1) for flag in flags)
                or any(item.consumed and not flag for item, flag in zip(values, flags))
                or (request or not structured) and flags != [int(item.consumed) for item in values]):
            reject('invalid complete consumption-state framing')
        try:
            start = 64 + count * 8
            encoded = ctypes.string_at(ctypes.addressof(output) + start, extent - start)
            term = decode_native_graph(encoded, wire)
            if error or request:
                if term is not None:
                    raise ValueError('refusal/delegation supplied a term')
            elif type(term) is not dict:
                raise ValueError('completed terminator is not an object')
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
            reject('invalid object graph: ' + str(exc))
        return TerminatorResult(final, error, request, bool(structured), term,
                                [(item, bool(flag)) for item, flag in zip(values, flags)])


def installed_nominal_terminators(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeNominalTerminators)


def selected_nominal_terminators():
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    try:
        return installed_nominal_terminators(selected)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native nominal terminators refused: ' + str(exc), 'E_HIA_TYPE') from exc
