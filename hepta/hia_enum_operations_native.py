"""Explicit native enum construction/tag lowering with lossless owner transport.

HIA owns semantic admission, consumption, padding, names and complete Core
objects. The two tag continuations invoke the existing type owner in its
original order; they do not grant the bridge a type-comparison policy.
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

SOURCE = _source_resource_path('examples/hia_bootstrap/enum_operations.hiaasm')
SCHEMA = 'hepta.hia.enum-operations-native.v1'
SELECTOR = 'HEPTA_HIA_ENUM_OPERATIONS_MANIFEST'
MAGIC = int.from_bytes(b'HIAEOP01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 8 << 20
WORKSPACE_BYTES = 16 << 20
ERRORS = {
    1: ('E_HIA_LIMIT', 'nominal elaboration expansion budget exceeded'),
    2: ('E_HIA_LOAN', 'cannot invent an inactive loan'),
    3: ('E_HIA_FORMAT', 'enum.make: expected exactly variant'),
    4: ('E_HIA_TYPE', 'enum.make needs an enum output'),
    5: ('E_HIA_NAME', 'constructed variant: invalid/reserved ASCII identifier'),
    6: ('E_HIA_NAME', 'constructed variant: identifier uses the elaborator namespace'),
    7: ('E_HIA_TYPE', 'enum payload differs from selected variant'),
    8: ('E_HIA_RESOURCE', 'use of consumed nominal value'),
    9: ('E_HIA_FORMAT', 'enum.tag: expected exactly '),
    10: ('E_HIA_TYPE', 'enum.tag requires an enum'),
    11: ('E_HIA_TYPE', 'nominal output type/arity mismatch'),
}


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate native enum-operation output field')
        result[key] = value
    return result


def _constant(value):
    raise ValueError('non-JSON constant in native enum-operation result')


class EnumPacket:
    """Hold interned descriptor/value identities while copying their exact data."""
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
        self.phase, self.expected, self.tag_declared, self.bound = 0, None, None, None

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
                [[name, [self.type_ref(child) for _, child in fields]]
                 for name, fields in typ.variants]])
            index += 1
        return transport([self.phase, self.serial, self.operation, self.attrs, descriptors,
                          values, self.arguments, self.declared, self.expected,
                          self.tag_declared, self.bound])


@dataclass(frozen=True)
class EnumResult:
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


class NativeEnumOperations(NativeHiaJsonImage):
    def lower(self, operation, args, attrs, actual, declared, serial, *, tag_outputs, tag_binding):
        context = EnumPacket(operation, args, attrs, actual, declared, serial)
        result = self.step(context)
        if result.request == 1:
            expected, outputs = tag_outputs()
            context.expected = context.type_ref(expected)
            context.tag_declared = [[name, context.type_ref(typ)] for name, typ in outputs]
            context.phase = 1
            result = self.step(context)
            if result.request == 2:
                context.bound = context.type_ref(tag_binding())
                context.phase = 2
                result = self.step(context)
        if result.request:
            raise HIAProgramRejected('native enum-operation transport: incomplete continuation', 'E_HIA_TYPE')
        return result

    def step(self, context):
        from .hia_program_composite import _Value
        def reject(message):
            raise HIAProgramRejected('native enum-operation transport: ' + message, 'E_HIA_TYPE')
        wire = context.data()
        if (len(wire) > INPUT_BYTES or type(context.serial) is not int
                or not 0 <= context.serial <= 8192 or context.phase not in (0, 1, 2)):
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
                or size != extent - 64 or not context.serial <= final <= 8192
                or error == 1 and final != 8192 or request not in (0, 1, 2)
                or context.operation == 'enum.tag' and (final != context.serial
                    or not error and request != (context.phase + 1 if context.phase < 2 else 0))
                or context.operation == 'enum.make' and (request or context.phase)
                or request and (error or context.operation != 'enum.tag'
                    or request != context.phase + 1 or final != context.serial)):
            reject('invalid frame or continuation/counter correlation')
        try:
            payload = json.loads(ctypes.string_at(ctypes.addressof(output) + 64, size),
                                 object_pairs_hook=_pairs, parse_constant=_constant)
            if type(payload) is not dict or set(payload) != {'ops', 'consumed', 'values'}:
                raise ValueError('invalid complete-state envelope')
            ops, flags, values = payload['ops'], payload['consumed'], payload['values']
            if (type(ops) is not list or type(flags) is not list or type(values) is not list
                    or len(flags) != len(context.values) or any(type(flag) is not bool for flag in flags)
                    or (error or request) and values or not error and not request and len(values) != 1
                    or request and (ops or flags != [item.consumed for item in context.values])):
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
        return EnumResult(final, error, request, ops, list(zip(context.values, flags)), bindings)


def installed_enum_operations(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeEnumOperations)


def selected_enum_operations():
    manifest = os.environ.get(SELECTOR)
    if not manifest:
        return None
    try:
        return installed_enum_operations(manifest)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native enum operations refused: ' + str(exc),
                                 'E_HIA_TYPE') from exc
