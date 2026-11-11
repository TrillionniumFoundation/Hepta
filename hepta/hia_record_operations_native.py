"""Explicit native record construction, unpack and projection owner.

HIA owns field/type/linear/loan policy and complete alias bindings. The single
continuation reparses outputs using the existing type owner at its original
point; the bridge neither compares types nor computes field offsets.
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

SOURCE = _source_resource_path('examples/hia_bootstrap/record_operations.hiaasm')
SCHEMA = 'hepta.hia.record-operations-native.v1'
SELECTOR = 'HEPTA_HIA_RECORD_OPERATIONS_MANIFEST'
MAGIC = int.from_bytes(b'HIAREC01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 8 << 20
WORKSPACE_BYTES = 16 << 20
ERRORS = {
    1: ('E_HIA_FORMAT', 'record.make: expected exactly '),
    2: ('E_HIA_TYPE', 'record.make needs one nominal record output'),
    3: ('E_HIA_TYPE', 'record fields differ from nominal declaration'),
    4: ('E_HIA_RESOURCE', 'use of consumed nominal value'),
    5: ('E_HIA_FORMAT', 'record.unpack: expected exactly '),
    6: ('E_HIA_TYPE', 'record.unpack requires a record'),
    7: ('E_HIA_TYPE', 'nominal output type/arity mismatch'),
    8: ('E_HIA_FORMAT', 'record.get: expected exactly field'),
    9: ('E_HIA_TYPE', 'record.get requires a record'),
    10: ('E_HIA_NAME', 'projected record field: invalid/reserved ASCII identifier'),
    11: ('E_HIA_NAME', 'projected record field: identifier uses the elaborator namespace'),
    12: ('E_HIA_INIT', 'use of an uninitialized record field'),
    13: ('E_HIA_TYPE', 'unknown nominal field'),
    14: ('E_HIA_RESOURCE', 'linear fields require consuming record.unpack/take'),
}


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate native record-operation output field')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('non-JSON constant in native record-operation result')


class RecordPacket:
    """Copy held value/descriptor graphs without resolving nominal identity."""
    def __init__(self, operation, args, attrs, actual, declared, serial):
        self.operation, self.attrs, self.serial = operation, attrs, serial
        self.types, self.type_ids, self.values, value_ids = [], {}, [], {}
        self.arguments = []
        for name, value in zip(args, actual, strict=True):
            if id(value) not in value_ids:
                value_ids[id(value)] = len(self.values)
                self.values.append(value)
            self.arguments.append([name, value_ids[id(value)]])
        self.declared = [[name, self.type_ref(typ)] for name, typ in declared]
        self.phase, self.outputs = 0, None

    def type_ref(self, typ):
        if id(typ) not in self.type_ids:
            self.type_ids[id(typ)] = len(self.types)
            self.types.append(typ)
        return self.type_ids[id(typ)]

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
                          descriptors, values, self.arguments, self.declared, self.outputs])


@dataclass(frozen=True)
class RecordResult:
    serial: int
    error: int
    request: int
    ops: list
    states: list
    bindings: list

    def admit(self):
        if self.error:
            code, message = ERRORS[self.error]
            raise HIAProgramRejected(message, code)


class NativeRecordOperations(NativeHiaJsonImage):
    def lower(self, operation, args, attrs, actual, declared, serial, *, reparse_outputs):
        context = RecordPacket(operation, args, attrs, actual, declared, serial)
        result = self.step(context)
        if result.request:
            context.outputs = [[name, context.type_ref(typ)] for name, typ in reparse_outputs()]
            context.phase = 1
            result = self.step(context)
        if result.request:
            raise HIAProgramRejected('native record-operation transport: incomplete continuation', 'E_HIA_TYPE')
        return result

    def step(self, context):
        from .hia_program_composite import _Value
        def reject(message):
            raise HIAProgramRejected('native record-operation transport: ' + message, 'E_HIA_TYPE')
        wire = context.data()
        if (len(wire) > INPUT_BYTES or type(context.serial) is not int
                or not 0 <= context.serial <= 8192 or context.phase not in (0, 1)):
            reject('invalid input or starting counter')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(OUTPUT_BYTES)
        workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        extent = self._entry(source, len(wire), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire:
            reject('input bytes changed')
        if type(extent) is not int or not 64 <= extent <= OUTPUT_BYTES:
            reject('invalid result extent/status ' + str(extent))
        magic, error, final, request, size, r0, r1, r2 = struct.unpack_from('<8Q', output)
        if (magic != MAGIC or error not in {0, *ERRORS} or r0 or r1 or r2
                or size != extent - 64 or final != context.serial or request not in (0, 1)
                or context.operation == 'record.make' and (request or context.phase)
                or context.operation in {'record.unpack', 'record.get'} and not error
                    and request != (1 if context.phase == 0 else 0)
                or request and (error or context.operation not in {'record.unpack', 'record.get'}
                    or context.phase != 0)):
            reject('invalid frame or continuation/counter correlation')
        try:
            payload = json.loads(ctypes.string_at(ctypes.addressof(output) + 64, size),
                                 object_pairs_hook=_pairs, parse_constant=_constant)
            if type(payload) is not dict or set(payload) != {'ops', 'consumed', 'values'}:
                raise ValueError('invalid complete-state envelope')
            ops, flags, values = payload['ops'], payload['consumed'], payload['values']
            if (type(ops) is not list or ops or type(flags) is not list or type(values) is not list
                    or len(flags) != len(context.values) or any(type(flag) is not bool for flag in flags)
                    or (error or request) and values
                    or not error and not request and (len(values) > 64
                        or context.operation != 'record.unpack' and len(values) != 1)
                    or request and flags != [item.consumed for item in context.values]):
                raise ValueError('invalid partial effects or complete binding inventory')
            bindings = []
            for item in values:
                if (type(item) is not list or len(item) != 5 or type(item[0]) is not str
                        or type(item[1]) is not int or not 0 <= item[1] < len(context.types)
                        or type(item[2]) is not list or any(type(name) is not str for name in item[2])
                        or type(item[3]) is not bool or type(item[4]) is not bool):
                    raise ValueError('invalid descriptor-preserving value binding')
                bindings.append((item[0], _Value(context.types[item[1]], tuple(item[2]), item[3], item[4])))
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            reject('invalid payload: ' + str(exc))
        return RecordResult(final, error, request, ops, list(zip(context.values, flags)), bindings)


def installed_record_operations(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeRecordOperations)


def selected_record_operations():
    manifest = os.environ.get(SELECTOR)
    if not manifest:
        return None
    try:
        return installed_record_operations(manifest)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native record operations refused: ' + str(exc),
                                 'E_HIA_TYPE') from exc
