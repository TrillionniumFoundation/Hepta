"""HIA-owned partial-record transitions and field borrowing.

Native queries invoke existing type-owner methods at their original points.
This bridge transports their results and complete native Core/state objects;
it never computes a partial field inventory, lowering or linear transfer.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import json
import os
import struct

from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_record_operations_native import RecordPacket, _pairs, _constant
from .hia_program import HIAProgramRejected

SOURCE = _source_resource_path('examples/hia_bootstrap/record_transitions.hepta')
SCHEMA = 'hepta.hia.record-transitions-native.v1'
SELECTOR = 'HEPTA_HIA_RECORD_TRANSITIONS_MANIFEST'
MAGIC = int.from_bytes(b'HIARTN01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 8 << 20
WORKSPACE_BYTES = 16 << 20
ERRORS = {
    1: ('E_HIA_LIMIT', 'nominal elaboration expansion budget exceeded'),
    2: ('E_HIA_LOAN', 'cannot invent an inactive loan'),
    3: ('E_HIA_FORMAT', 'record.begin: expected exactly '),
    4: ('E_HIA_TYPE', 'record.begin requires one empty partial-record output'),
    5: ('E_HIA_INIT', 'record.begin cannot initialize a field'),
    6: ('E_HIA_FORMAT', 'record.take: expected exactly field'),
    7: ('E_HIA_TYPE', 'record.take requires one record'),
    8: ('E_HIA_NAME', 'projected record field: invalid/reserved ASCII identifier'),
    9: ('E_HIA_NAME', 'projected record field: identifier uses the elaborator namespace'),
    10: ('E_HIA_INIT', 'use of an uninitialized record field'),
    11: ('E_HIA_TYPE', 'unknown nominal field'),
    12: ('E_HIA_TYPE', 'nominal output type/arity mismatch'),
    13: ('E_HIA_RESOURCE', 'use of consumed nominal value'),
    14: ('E_HIA_FORMAT', 'record.insert: expected exactly field'),
    15: ('E_HIA_TYPE', 'record.insert requires partial record and field value'),
    16: ('E_HIA_NAME', 'initialized record field: invalid/reserved ASCII identifier'),
    17: ('E_HIA_NAME', 'initialized record field: identifier uses the elaborator namespace'),
    18: ('E_HIA_INIT', 'record field is already initialized'),
    19: ('E_HIA_TYPE', 'inserted record field type differs'),
    20: ('E_HIA_FORMAT', 'record.finish: expected exactly '),
    21: ('E_HIA_TYPE', 'record.finish requires one partial record'),
    22: ('E_HIA_INIT', 'record.finish requires every field initialized'),
    23: ('E_HIA_FORMAT', 'record.abandon: expected exactly '),
    24: ('E_HIA_TYPE', 'record.abandon requires one partial record'),
    25: ('E_HIA_INIT', 'record.abandon requires every field moved out'),
    26: ('E_HIA_FORMAT', 'record.borrow: expected exactly field, mode'),
    27: ('E_HIA_TYPE', 'record.borrow requires a record'),
    28: ('E_HIA_LOAN', 'record.borrow mode must be read or mut'),
    29: ('E_HIA_TYPE', 'record.borrow requires a primitive owner/view field'),
}


class TransitionPacket(RecordPacket):
    def __init__(self, *args):
        super().__init__(*args)
        self.resolved = None

    def data(self):
        values = [[self.type_ref(item.typ), item.names, item.external, item.consumed]
                  for item in self.values]
        descriptors = []
        index = 0
        while index < len(self.types):
            typ = self.types[index]
            descriptors.append([typ.kind, typ.flat, typ.linear,
                [[name, self.type_ref(child)] for name, child in typ.fields],
                None if typ.record is None else self.type_ref(typ.record)])
            index += 1
        return transport([self.phase, self.serial, self.operation, self.attrs,
            descriptors, values, self.arguments, self.declared, self.resolved, self.outputs])


@dataclass(frozen=True)
class TransitionResult:
    serial: int
    error: int
    request: int
    query: object
    ops: list
    states: list
    bindings: list

    def admit(self):
        if self.error:
            code, message = ERRORS[self.error]
            raise HIAProgramRejected(message, code)


class NativeRecordTransitions(NativeHiaJsonImage):
    def lower(self, operation, args, attrs, actual, declared, serial, *, partial_record, resolve_type, reparse_outputs):
        context = TransitionPacket(operation, args, attrs, actual, declared, serial)
        for _ in range(3):
            result = self.step(context)
            if not result.request:
                return result
            if result.request == 1:
                typ = partial_record(context.types[result.query['base']], result.query['fields'])
                context.resolved = context.type_ref(typ)
                context.phase = 1
            elif result.request == 2:
                context.resolved = context.type_ref(resolve_type(result.query['type']))
                context.phase = 1
            else:
                context.outputs = [[name, context.type_ref(typ)] for name, typ in reparse_outputs()]
                context.phase = 2
        raise HIAProgramRejected('native record-transition transport: incomplete continuation', 'E_HIA_TYPE')

    def step(self, context):
        from .hia_program_composite import _Value
        def reject(message):
            raise HIAProgramRejected('native record-transition transport: ' + message, 'E_HIA_TYPE')
        wire = context.data()
        if (len(wire) > INPUT_BYTES or type(context.serial) is not int
                or not 0 <= context.serial <= 8192 or context.phase not in (0, 1, 2)):
            reject('invalid input or starting counter')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output, workspace = ctypes.create_string_buffer(OUTPUT_BYTES), ctypes.create_string_buffer(WORKSPACE_BYTES)
        extent = self._entry(source, len(wire), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire:
            reject('input bytes changed')
        if type(extent) is not int or not 64 <= extent <= OUTPUT_BYTES:
            reject('invalid result extent/status ' + str(extent))
        magic, error, final, request, size, r0, r1, r2 = struct.unpack_from('<8Q', output)
        expected_requests = {'record.begin': (0, None, None), 'record.take': (1, 3, 0),
            'record.insert': (1, 3, 0), 'record.finish': (3, None, 0),
            'record.abandon': (3, None, 0), 'record.borrow': (2, 3, 0)}
        expected = expected_requests.get(context.operation, (None, None, None))[context.phase]
        if (magic != MAGIC or error not in {0, *ERRORS} or r0 or r1 or r2
                or size != extent - 64 or not context.serial <= final <= 8192
                or error == 1 and final != 8192 or request not in (0, 1, 2, 3)
                or expected is None or not error and request != expected
                or context.operation not in {'record.begin', 'record.take'} and final != context.serial
                or request and (error or final != context.serial)):
            reject('invalid frame or continuation/counter correlation')
        try:
            payload = json.loads(ctypes.string_at(ctypes.addressof(output) + 64, size),
                                 object_pairs_hook=_pairs, parse_constant=_constant)
            if type(payload) is not dict or set(payload) != {'ops', 'consumed', 'values', 'query'}:
                raise ValueError('invalid complete-state envelope')
            ops, flags, values, query = (payload[key] for key in ('ops', 'consumed', 'values', 'query'))
            counts = {'record.begin': 1, 'record.take': 2, 'record.insert': 1,
                      'record.finish': 1, 'record.abandon': 0, 'record.borrow': 1}
            if (type(ops) is not list or type(flags) is not list or type(values) is not list
                    or len(flags) != len(context.values) or any(type(flag) is not bool for flag in flags)
                    or (error or request) and values
                    or not error and not request and len(values) != counts[context.operation]
                    or request and (ops or flags != [item.consumed for item in context.values])
                    or not request and query is not None):
                raise ValueError('invalid partial effects or binding/query inventory')
            if request == 1:
                if (type(query) is not dict or set(query) != {'base', 'fields'}
                        or type(query['base']) is not int or not 0 <= query['base'] < len(context.types)
                        or type(query['fields']) is not list or len(query['fields']) > 64
                        or any(type(name) is not str for name in query['fields'])):
                    raise ValueError('invalid partial-record type-owner query')
            elif request == 2:
                if (type(query) is not dict or set(query) != {'type'}
                        or query['type'] not in {'readbuf', 'mutbuf'}):
                    raise ValueError('invalid primitive type-owner query')
            elif request == 3 and query != {}:
                raise ValueError('invalid output-reparse query')
            bindings = []
            for item in values:
                if (type(item) is not list or len(item) != 5 or type(item[0]) is not str
                        or type(item[1]) is not int or not 0 <= item[1] < len(context.types)
                        or type(item[2]) is not list or any(type(name) is not str for name in item[2])
                        or item[3] is not False or item[4] is not False):
                    raise ValueError('invalid descriptor-preserving value binding')
                bindings.append((item[0], _Value(context.types[item[1]], tuple(item[2]), False, False)))
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            reject('invalid payload: ' + str(exc))
        return TransitionResult(final, error, request, query, ops, list(zip(context.values, flags)), bindings)


def installed_record_transitions(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeRecordTransitions)


def selected_record_transitions():
    manifest = os.environ.get(SELECTOR)
    if not manifest:
        return None
    try:
        return installed_record_transitions(manifest)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native record transitions refused: ' + str(exc), 'E_HIA_TYPE') from exc
