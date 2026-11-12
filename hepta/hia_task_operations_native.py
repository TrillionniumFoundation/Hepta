"""Complete ordinary task lowering with ordered native-issued continuations.

HIA owns instruction policy, names, linear transfer, bindings and emitted Core.
This bridge transports held descriptors and invokes the existing type/helper
owners only when requested. Helper generation sees the already-applied native
prefix, including on failure; no ordinary task lowering executes in Python.
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

SOURCE = _source_resource_path('examples/hia_bootstrap/task_operations.hiaasm')
SCHEMA = 'hepta.hia.task-operations-native.v1'
SELECTOR = 'HEPTA_HIA_TASK_OPERATIONS_MANIFEST'
MAGIC = int.from_bytes(b'HIATOP01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 8 << 20
WORKSPACE_BYTES = 16 << 20
HELPER_OPERATIONS = frozenset(('task.start', 'task.poll', 'task.cancel', 'task.join', 'task.close'))
ERRORS = {
    1: ('E_HIA_LIMIT', 'nominal elaboration expansion budget exceeded'),
    2: ('E_HIA_LOAN', 'cannot invent an inactive loan'),
    3: ('E_HIA_FORMAT', '{operation}: expected exactly '),
    4: ('E_HIA_TYPE', 'task.create needs state and one task output'),
    5: ('E_HIA_TYPE', 'task state type differs from protocol'),
    6: ('E_HIA_TYPE', 'task operation requires one task'),
    7: ('E_HIA_TYPE', 'nominal output type/arity mismatch'),
    8: ('E_HIA_RESOURCE', 'use of consumed nominal value'),
    9: ('E_HIA_OPCODE', 'unknown task operation'),
}


class TaskPacket(RecordPacket):
    def __init__(self, *args):
        super().__init__(*args)
        self.receipts = []
        self.helper_name = self.prefix = None

    def data(self):
        values = [[self.type_ref(item.typ), item.names, item.external, item.consumed]
                  for item in self.values]
        descriptors = []
        index = 0
        while index < len(self.types):
            typ = self.types[index]
            descriptors.append([typ.kind, typ.flat, typ.linear,
                None if typ.state is None else self.type_ref(typ.state),
                None if typ.result is None else self.type_ref(typ.result)])
            index += 1
        return transport([self.phase, self.serial, self.operation, self.attrs,
            descriptors, values, self.arguments, self.declared, self.receipts,
            self.outputs, self.helper_name, self.prefix])


@dataclass(frozen=True)
class TaskResult:
    operation: str
    serial: int
    error: int
    request: int
    query: object
    ops: list
    states: list
    bindings: list
    raw_bindings: list

    def admit(self):
        if self.error:
            code, message = ERRORS[self.error]
            raise HIAProgramRejected(message.format(operation=self.operation), code)


class NativeTaskOperations(NativeHiaJsonImage):
    def lower(self, operation, args, attrs, actual, declared, serial, *, apply,
              check_task, resolve_type, reparse_outputs, helper):
        context = TaskPacket(operation, args, attrs, actual, declared, serial)
        for _ in range(4):
            result = self.step(context)
            # The original helper call follows consumption, fresh allocation
            # and env binding. Preserve that prefix even if its owner rejects.
            apply(result)
            result.admit()
            if not result.request:
                return
            if result.request == 1:
                check_task(context.types[result.query['type']])
                context.receipts.append(result.query['type'])
            elif result.request == 2:
                context.receipts.append(context.type_ref(resolve_type(result.query['type'])))
            elif result.request == 3:
                context.outputs = [[name, context.type_ref(typ)] for name, typ in reparse_outputs()]
            else:
                context.prefix = [result.serial, result.raw_bindings]
                context.helper_name, context.serial = helper(
                    context.types[result.query['type']], result.query['operation'])
            context.phase += 1
        raise HIAProgramRejected('native task-operation transport: incomplete continuation', 'E_HIA_TYPE')

    def step(self, context):
        from .hia_program_composite import _Value
        def reject(message):
            raise HIAProgramRejected('native task-operation transport: ' + message, 'E_HIA_TYPE')
        wire = context.data()
        if (len(wire) > INPUT_BYTES or type(context.serial) is not int
                or not 0 <= context.serial <= 8192 or context.phase not in (0, 1, 2, 3)):
            reject('invalid input or starting counter')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output, workspace = ctypes.create_string_buffer(OUTPUT_BYTES), ctypes.create_string_buffer(WORKSPACE_BYTES)
        extent = self._entry(source, len(wire), output, OUTPUT_BYTES, workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire:
            reject('input bytes changed')
        if type(extent) is not int or not 64 <= extent <= OUTPUT_BYTES:
            reject('invalid result extent/status ' + str(extent))
        magic, error, final, request, size, r0, r1, r2 = struct.unpack_from('<8Q', output)
        phases = ((1, 0) if context.operation == 'task.create' else
                  (2, 3, 2, 0) if context.operation == 'task.state' else
                  (3, 4, 0) if context.operation in HELPER_OPERATIONS else (0,))
        expected = phases[context.phase] if context.phase < len(phases) else None
        may_allocate = context.phase == 1 and (context.operation == 'task.create'
                                              or context.operation in HELPER_OPERATIONS)
        if (magic != MAGIC or error not in {0, *ERRORS} or r0 or r1 or r2
                or size != extent - 64 or not context.serial <= final <= 8192
                or error == 1 and final != 8192 or request not in (0, 1, 2, 3, 4)
                or expected is None or not error and request != expected
                or error and request or not may_allocate and final != context.serial
                or request in (1, 2, 3) and final != context.serial):
            reject('invalid frame or continuation/counter correlation')
        try:
            payload = json.loads(ctypes.string_at(ctypes.addressof(output) + 64, size),
                                 object_pairs_hook=_pairs, parse_constant=_constant)
            if type(payload) is not dict or set(payload) != {'ops', 'consumed', 'values', 'query'}:
                raise ValueError('invalid complete-state envelope')
            ops, flags, values, query = (payload[key] for key in ('ops', 'consumed', 'values', 'query'))
            count = (0 if context.operation == 'task.close' or context.operation in HELPER_OPERATIONS
                     and context.phase == 2 else 1)
            if (type(ops) is not list or type(flags) is not list or type(values) is not list
                    or len(flags) != len(context.values) or any(type(flag) is not bool for flag in flags)
                    or (error or request in (1, 2, 3)) and values
                    or not error and request in (0, 4) and len(values) != count
                    or request and ops
                    or request in (1, 2, 3) and flags != [item.consumed for item in context.values]
                    or not request and query is not None):
                raise ValueError('invalid partial effects or binding/query inventory')
            if request == 1:
                if (type(query) is not dict or set(query) != {'type'} or type(query['type']) is not int
                        or not 0 <= query['type'] < len(context.types)):
                    raise ValueError('invalid task protocol query')
            elif request == 2 and query != {'type': 'u8'}:
                raise ValueError('invalid primitive type-owner query')
            elif request == 3 and query != {}:
                raise ValueError('invalid output-reparse query')
            elif request == 4:
                if (type(query) is not dict or set(query) != {'type', 'operation'}
                        or type(query['type']) is not int or not 0 <= query['type'] < len(context.types)
                        or query['operation'] != context.operation[5:]):
                    raise ValueError('invalid task-helper query')
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
        return TaskResult(context.operation, final, error, request, query, ops,
                          list(zip(context.values, flags)), bindings, values)


def installed_task_operations(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeTaskOperations)


def selected_task_operations():
    manifest = os.environ.get(SELECTOR)
    if not manifest:
        return None
    try:
        return installed_task_operations(manifest)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native task operations refused: ' + str(exc), 'E_HIA_TYPE') from exc
