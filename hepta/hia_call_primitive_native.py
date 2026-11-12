"""Complete native ordinary call and primitive erasure with lossless graphs.

The native owner requests a held signature inventory and output type reparse
at their original semantic points. This bridge copies descriptors and decodes
complete Core/state objects; no call lookup, ownership or lowering plan runs
in Python. Generic source-array references preserve large repeated aliases.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import os
import struct

from .hia_instruction_policy_native import transport
from .hia_machine_transport import _private_zeroed_buffer
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_native_value_graph import decode_native_graph
from .hia_record_operations_native import RecordPacket
from .hia_program import HIAProgramRejected

SOURCE = _source_resource_path('examples/hia_bootstrap/call_primitive.hiaasm')
SCHEMA = 'hepta.hia.call-primitive-native.v1'
SELECTOR = 'HEPTA_HIA_CALL_PRIMITIVE_MANIFEST'
MAGIC = int.from_bytes(b'HIACPR01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 64 << 20
WORKSPACE_BYTES = 32 << 20
ERRORS = {
    1: ('E_HIA_LIMIT', 'nominal elaboration expansion budget exceeded'),
    2: ('E_HIA_FORMAT', 'call: expected exactly function'),
    3: ('E_HIA_NAME', 'callee: invalid/reserved ASCII identifier'),
    4: ('E_HIA_NAME', 'callee: identifier uses the elaborator namespace'),
    5: ('E_HIA_CALL', 'unknown nominal callee'),
    6: ('E_HIA_CALL', 'nominal call argument types differ'),
    7: ('E_HIA_TYPE', 'nominal output type/arity mismatch'),
    8: ('E_HIA_RESOURCE', 'use of consumed nominal value'),
    9: ('E_HIA_TYPE', 'primitive instruction cannot reinterpret a nominal value'),
}


class CallPrimitivePacket(RecordPacket):
    def __init__(self, *args):
        super().__init__(*args)
        self.signatures = None

    def data(self):
        values = [[self.type_ref(item.typ), item.names, item.external, item.consumed]
                  for item in self.values]
        descriptors = [[typ.kind, typ.flat, typ.linear] for typ in self.types]
        return transport([self.phase, self.serial, self.operation, self.attrs,
            descriptors, values, self.arguments, self.declared, self.signatures, self.outputs])


@dataclass(frozen=True)
class CallPrimitiveResult:
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


class NativeCallPrimitive(NativeHiaJsonImage):
    def lower(self, operation, args, attrs, actual, declared, serial, *, signatures, reparse_outputs):
        context = CallPrimitivePacket(operation, args, attrs, actual, declared, serial)
        for _ in range(3):
            result = self.step(context)
            if not result.request:
                return result
            if result.request == 1:
                # Lossless inventory projection only. HIA performs the lookup,
                # argument comparison and every later semantic choice.
                context.signatures = [[name, [context.type_ref(typ) for _, typ in params],
                                       [context.type_ref(typ) for typ in returns]]
                                      for name, (params, returns) in signatures.items()]
            else:
                context.outputs = [[name, context.type_ref(typ)] for name, typ in reparse_outputs()]
            context.phase += 1
        raise HIAProgramRejected('native call/primitive transport: incomplete continuation', 'E_HIA_TYPE')

    def step(self, context):
        from .hia_program_composite import _Value
        def reject(message):
            raise HIAProgramRejected('native call/primitive transport: ' + message, 'E_HIA_TYPE')
        wire = context.data()
        if (len(wire) > INPUT_BYTES or type(context.serial) is not int
                or not 0 <= context.serial <= 8192 or context.phase not in (0, 1, 2)):
            reject('invalid input or starting counter')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output, workspace = _private_zeroed_buffer(OUTPUT_BYTES), _private_zeroed_buffer(WORKSPACE_BYTES)
        extent = self._entry(source, len(wire), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire:
            reject('input bytes changed')
        if type(extent) is not int or not 64 <= extent <= OUTPUT_BYTES:
            reject('invalid result extent/status ' + str(extent))
        magic, error, final, request, size, r0, r1, r2 = struct.unpack_from('<8Q', output)
        phases = (1, 2, 0) if context.operation == 'call' else (0,)
        expected = phases[context.phase] if context.phase < len(phases) else None
        if (magic != MAGIC or error not in {0, *ERRORS} or r0 or r1 or r2
                or size != extent - 64 or not context.serial <= final <= 8192
                or error == 1 and final != 8192 or request not in (0, 1, 2)
                or error == 1 and (context.operation != 'call' or context.phase != 2)
                or expected is None or not error and request != expected or error and request
                or (context.operation != 'call' or context.phase != 2 or error not in (0, 1))
                    and final != context.serial
                or request and final != context.serial):
            reject('invalid frame or continuation/counter correlation')
        try:
            payload = decode_native_graph(ctypes.string_at(ctypes.addressof(output) + 64, size), wire)
            if type(payload) is not dict or set(payload) != {'ops', 'consumed', 'values', 'query'}:
                raise ValueError('invalid complete-state envelope')
            ops, flags, values, query = (payload[key] for key in ('ops', 'consumed', 'values', 'query'))
            declared = context.outputs if context.operation == 'call' and context.phase == 2 else context.declared
            if (type(ops) is not list or type(flags) is not list or type(values) is not list
                    or len(flags) != len(context.values) or any(type(flag) is not bool for flag in flags)
                    or len(ops) != (0 if error or request else 1)
                    or (request or error not in (0, 1)) and values
                    or len(values) > len(declared)
                    or error == 1 and len(values) >= len(declared)
                    or not error and not request and len(values) != len(declared)
                    or request and (flags != [item.consumed for item in context.values] or query != {})
                    or not request and query is not None):
                raise ValueError('invalid effects, binding inventory or query')
            bindings = []
            for item in values:
                if (type(item) is not list or len(item) != 5 or type(item[0]) is not str
                        or type(item[1]) is not int or not 0 <= item[1] < len(context.types)
                        or type(item[2]) is not list or any(type(name) is not str for name in item[2])
                        or item[3] is not False or item[4] is not False):
                    raise ValueError('invalid descriptor-preserving value binding')
                bindings.append((item[0], _Value(context.types[item[1]], tuple(item[2]), False, False)))
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
            reject('invalid graph payload: ' + str(exc))
        return CallPrimitiveResult(final, error, request, ops, list(zip(context.values, flags)), bindings)


def installed_call_primitive(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeCallPrimitive)


def selected_call_primitive():
    manifest = os.environ.get(SELECTOR)
    if not manifest:
        return None
    try:
        return installed_call_primitive(manifest)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native call/primitive refused: ' + str(exc), 'E_HIA_TYPE') from exc
