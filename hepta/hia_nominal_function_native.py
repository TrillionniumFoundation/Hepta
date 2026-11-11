"""HIA-owned nominal function orchestration with explicit native continuations.

This bridge keeps opaque descriptor/value identities and mutable operation
buffers. It services only the controller's requests; it does not choose an
instruction family, perform SSA/type/ownership decisions or construct Core.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import os
import struct

from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_native_value_graph import decode_native_graph
from .hia_program import HIAProgramRejected

SOURCE = _source_resource_path('examples/hia_bootstrap/nominal_function.hiaasm')
SCHEMA = 'hepta.hia.nominal-function-native.v1'
SELECTOR = 'HEPTA_HIA_NOMINAL_FUNCTION_MANIFEST'
MAGIC = int.from_bytes(b'HIANFN01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 64 << 20
WORKSPACE_BYTES = 64 << 20
ERRORS = {
    1: ('E_HIA_LIMIT', 'nominal elaboration expansion budget exceeded'),
    2: ('E_HIA_CFG', 'invalid nominal block inventory'),
    3: ('E_HIA_FORMAT', 'nominal block: expected exactly id, ops, params, term'),
    4: ('E_HIA_NAME', 'block: invalid/reserved ASCII identifier'),
    5: ('E_HIA_NAME', 'block: identifier uses the elaborator namespace'),
    6: ('E_HIA_CFG', 'duplicate nominal block'),
    7: ('E_HIA_FORMAT', 'block operations must be a list'),
    8: ('E_HIA_FORMAT', 'nominal instruction: expected exactly args, attrs, op, out'),
    9: ('E_HIA_FORMAT', 'invalid nominal instruction'),
    10: ('E_HIA_OPCODE', 'nominal operation is outside the selected input profile'),
    11: ('E_HIA_FORMAT', 'instruction arguments: expected value list'),
    12: ('E_HIA_NAME', 'instruction arguments: invalid/reserved ASCII identifier'),
    13: ('E_HIA_LIMIT', 'nominal elaborated value-slot budget exceeded'),
    14: ('E_HIA_SSA', 'nominal SSA value defined twice'),
    15: ('E_HIA_NAME', 'entry: invalid/reserved ASCII identifier'),
    16: ('E_HIA_NAME', 'entry: identifier uses the elaborator namespace'),
    17: ('E_HIA_CFG', 'nominal entry parameters differ from signature'),
    18: ('E_HIA_NAME', 'value reference: invalid/reserved ASCII identifier'),
    19: ('E_HIA_NAME', 'value reference: identifier uses the elaborator namespace'),
    20: ('E_HIA_SSA', 'undefined/nonlocal nominal value'),
    21: ('E_HIA_RESOURCE', 'use of consumed nominal value'),
}


def _reject(message):
    raise HIAProgramRejected('native nominal function transport: ' + message, 'E_HIA_TYPE')


def _unavailable(*args, **kwargs):
    _reject('selected controller requested a hosted semantic closure')


def _required(selector):
    selected = selector()
    if selected is None:
        _reject('selected controller requires native continuation ' + selector.__name__)
    return selected


class FunctionContext:
    def __init__(self, owner, function):
        self.owner, self.function = owner, function
        self.function_bytes = transport(function)
        self.types, self.type_ids, self.type_rows, self.sent_types = [], {}, [], 0
        self.values, self.value_ids = [], {}
        self.pool, self.blocks, self.signatures = [], [], {}
        self.environment, self.ops, self.result, self.current = {}, [], [], None
        self.environment_snapshot = {}
        self.pending_environment = {}
        self.signature_inventory = ()
        self.reply, self.sequence = None, 0
        self.executed = self.completed = 0
        self.pending = None
        self.closed = False
        self.output = ctypes.create_string_buffer(OUTPUT_BYTES)
        self.workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)

    def close(self):
        self.closed = True
        # A completed/aborted public invocation cannot use its native arena
        # again. Release it even when a callback traceback retains this object.
        self.output = self.workspace = None

    def hold(self, value):
        identifier = len(self.pool)
        self.pool.append(value)
        return identifier

    def type_ref(self, typ):
        if id(typ) not in self.type_ids:
            identifier = len(self.types)
            self.type_ids[id(typ)] = identifier
            self.types.append(typ)
            self.type_rows.append([identifier, typ.kind, typ.flat, typ.linear, self.hold(typ.flat)])
        return self.type_ids[id(typ)]

    def value_ref(self, value):
        if id(value) not in self.value_ids:
            self.value_ids[id(value)] = len(self.values)
            self.values.append(value)
        return self.value_ids[id(value)]

    def parameters(self, parameters):
        return [[name, self.type_ref(typ)] for name, typ in parameters]

    def source(self, path):
        value = self.function
        if type(path) is not list:
            _reject('source location is not a path')
        for key in path:
            if (type(value) is dict and type(key) is not str
                    or type(value) is list and (type(key) is not int or not 0 <= key < len(value))
                    or type(value) not in (dict, list)):
                _reject('source location differs from a complete value')
            try:
                value = value[key]
            except (KeyError, IndexError, TypeError):
                _reject('source location is outside the held function')
        return value

    def data(self):
        if self.closed:
            _reject('closed function context cannot resume')
        if transport(self.function) != self.function_bytes:
            _reject('held function changed during continuation')
        environment = []
        snapshot = {}
        for name, value in self.environment.items():
            held = (id(value), value.consumed)
            snapshot[name] = held
            if self.environment_snapshot.get(name) != held:
                environment.append([name, self.value_ref(value), value.consumed])
        for name in self.environment_snapshot.keys() - snapshot.keys():
            environment.append([name, None, None])
        self.pending_environment = snapshot
        return transport([self.function, self.sequence, self.owner.serial, self.owner.value_slots,
            self.owner.parameter_loan_returns, list(self.owner.nominal_operations),
            self.type_rows[self.sent_types:], self.reply, environment])

    def service(self, request, query):
        if (self.closed or self.pending is None or self.executed >= self.sequence
                or type(request) is not int or request != self.pending[0]
                or query is not self.pending[1]):
            _reject('callback is not the current unexecuted continuation')
        # Consume the permission before invoking any callback. A callback may
        # mutate the type/helper state and then interrupt before its reply is
        # assigned; that request must never become eligible for replay.
        self.executed = self.sequence
        try:
            self._service(request, query)
            self.completed = self.sequence
            self.pending = None
        except BaseException:
            self.closed = True
            raise

    def _service(self, request, query):
        from .hia_program_composite import _Value
        keys = {1: {'path'}, 2: {'index', 'name', 'params', 'flat', 'bindings'},
                3: set(), 4: {'index'}, 5: {'index', 'ops'},
                6: {'owner', 'path', 'actual', 'declared'}, 7: {'path', 'signature'},
                8: {'current'}, 9: {'path'}, 10: {'path'}, 11: set(), 12: {'values'}}
        if request not in keys or type(query) is not dict or set(query) != keys[request]:
            _reject('continuation is not a complete object')
        for name in ('index', 'owner', 'signature'):
            if name in query and (type(query[name]) is not int or query[name] < 0):
                _reject('continuation index is not an unsigned integer')
        def rows(items, width, *, binding=False):
            if type(items) is not list:
                _reject('native descriptor rows are not an array')
            for item in items:
                if (type(item) is not list or len(item) != width or type(item[0]) is not str
                        or type(item[1]) is not int or not 0 <= item[1] < len(self.types)):
                    _reject('native descriptor row is outside the held inventory')
                if binding and (type(item[2]) is not list or any(type(name) is not str for name in item[2])
                                or type(item[3]) is not bool or item[4] is not False):
                    _reject('native parameter binding has invalid value fields')
        if request == 1:
            if self.owner.native_types is None:
                _reject('selected controller requires the native parameter/type owner')
            self.reply = self.parameters(self.owner.parameters(self.source(query['path'])))
        elif request == 2:
            if query['index'] != len(self.blocks) or type(query['name']) is not str or type(query['flat']) is not list:
                _reject('native block storage is not ordered')
            rows(query['params'], 2)
            rows(query['bindings'], 5, binding=True)
            bindings = {}
            for name, identifier, names, external, consumed in query['bindings']:
                bindings[name] = _Value(self.types[identifier], tuple(names), external, consumed)
            parameters = tuple((name, self.types[identifier]) for name, identifier in query['params'])
            flat = query['flat']
            self.blocks.append((query['name'], parameters, flat, bindings))
            self.signatures[query['name']] = parameters
            self.reply = self.hold(flat)
        elif request == 3:
            self.signature_inventory = tuple(self.owner.signatures.items())
            self.reply = [name for name, _ in self.signature_inventory]
        elif request == 4:
            if query['index'] >= len(self.signature_inventory):
                _reject('signature reference is outside the held inventory')
            parameters, returns = self.signature_inventory[query['index']][1]
            self.reply = [self.parameters(parameters), [self.type_ref(typ) for typ in returns]]
        elif request == 5:
            if query['index'] >= len(self.blocks) or type(query['ops']) is not list or query['ops']:
                _reject('native block start is not a fresh operation array')
            self.environment = self.blocks[query['index']][3]
            self.environment_snapshot = {}
            self.ops = query['ops']
            self.reply = None
        elif request == 6:
            rows(query['declared'], 2)
            if (type(query['actual']) is not list or any(type(value) is not int or not 0 <= value < len(self.values)
                                                       for value in query['actual'])):
                _reject('actual-value reference is outside the held inventory')
            self.dispatch(query)
            self.reply = None
        elif request == 7:
            from .hia_nominal_terminators_native import selected_nominal_terminators
            native = _required(selected_nominal_terminators)
            if query['signature'] >= len(self.signature_inventory):
                _reject('terminator signature is outside the held inventory')
            returns = self.signature_inventory[query['signature']][1][1]
            lowered = native.lower(self.source(query['path']), self.environment,
                self.signatures, returns, self.owner.serial)
            for value, consumed in lowered.states:
                value.consumed = consumed
            lowered.admit()
            self.reply = [lowered.request, self.hold(self.ops), self.hold(lowered.term)]
        elif request == 8:
            current = query['current']
            if (type(current) is not dict or set(current) != {'id', 'params', 'ops', 'term'}
                    or type(current['id']) is not str or type(current['params']) is not list
                    or type(current['ops']) is not list or current['term'] is not None and type(current['term']) is not dict):
                _reject('native current block is not a complete Core object')
            self.current = query['current']
            self.ops = self.current['ops']
            self.result.append(self.current)
            self.reply = None
        elif request == 9:
            from .hia_enum_match_native import selected_enum_match
            _required(selected_enum_match)
            self.owner.lower_enum_match(self.source(query['path']), self.environment,
                self.signatures, self.current, self.result, _unavailable, _unavailable)
            self.reply = None
        elif request == 10:
            self.reply = [self.hold(self.result), self.hold(self.source(query['path']))]
        elif request == 11:
            self.reply = [[name, origins] for name, origins in self.owner.return_origins.items()]
        elif request == 12:
            if type(query['values']) is not list or any(type(value) is not list for value in query['values']):
                _reject('held origin chunks are not complete arrays')
            self.reply = [self.hold(value) for value in query['values']]
        else:
            _reject('unknown controller continuation')

    def dispatch(self, query):
        from .hia_record_transitions_native import selected_record_transitions
        from .hia_record_operations_native import selected_record_operations
        from .hia_enum_operations_native import selected_enum_operations
        from .hia_task_operations_native import selected_task_operations
        from .hia_call_primitive_native import selected_call_primitive
        instruction = self.source(query['path'])
        actual = [self.values[identifier] for identifier in query['actual']]
        declared = tuple((name, self.types[identifier]) for name, identifier in query['declared'])
        selectors = {1: selected_record_transitions, 2: selected_record_operations,
                     3: selected_enum_operations, 4: selected_task_operations, 5: selected_call_primitive}
        kind = query['owner']
        if type(kind) is not int or kind not in selectors:
            _reject('native instruction continuation is outside the owned inventory')
        selected = _required(selectors[kind])
        arguments = (instruction, actual, declared, self.environment, self.ops, _unavailable, _unavailable)
        if kind == 1:
            self.owner.lower_record_transition(*arguments, _unavailable, _unavailable)
        elif kind == 2:
            self.owner.lower_record_operation(*arguments, _unavailable)
        elif kind == 3:
            self.owner.lower_enum_operation(*arguments)
        elif kind == 4:
            def apply(result):
                self.owner.serial = result.serial
                self.ops.extend(result.ops)
                for value, consumed in result.states:
                    value.consumed = consumed
                self.environment.update(result.bindings)
            def helper(typ, operation):
                name = self.owner.helper(typ, operation, require_native=True)
                return name, self.owner.serial
            selected.lower(instruction['op'], instruction['args'], instruction['attrs'], actual,
                declared, self.owner.serial, apply=apply, check_task=self.owner.check_task,
                resolve_type=self.owner.types.resolve,
                reparse_outputs=lambda: self.owner.parameters(instruction['out']), helper=helper)
        else:
            self.owner.lower_call_primitive(*arguments)


@dataclass(frozen=True)
class FunctionResult:
    serial: int
    value_slots: int
    error: int
    request: int
    value: object

    def admit(self):
        if self.error:
            code, message = ERRORS[self.error]
            raise HIAProgramRejected(message, code)


class NativeNominalFunction(NativeHiaJsonImage):
    def lower(self, owner, function):
        context = FunctionContext(owner, function)
        try:
            for _ in range(8 * 262144 + 32):
                result = self.step(context)
                owner.serial, owner.value_slots = result.serial, result.value_slots
                result.admit()
                if not result.request:
                    return result.value
                context.service(result.request, result.value)
            _reject('controller did not complete within its public structural bound')
        finally:
            context.close()

    def step(self, context):
        if context.closed:
            _reject('closed function context cannot resume')
        if context.pending is not None or context.completed != context.sequence:
            _reject('previous function continuation has not completed')
        try:
            return self._step(context)
        except BaseException:
            context.closed = True
            raise

    def _step(self, context):
        wire = context.data()
        serial, slots = context.owner.serial, context.owner.value_slots
        if (len(wire) > INPUT_BYTES or type(serial) is not int or not 0 <= serial <= 8192
                or type(slots) is not int or not 0 <= slots < 2**64):
            _reject('input/counter extent differs')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        extent = self._entry(source, len(wire), context.output, OUTPUT_BYTES,
                             context.workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire:
            _reject('input bytes changed')
        if type(extent) is not int or not 80 <= extent <= OUTPUT_BYTES:
            _reject('invalid result extent/status ' + str(extent))
        magic, error, final, values, request, size, sequence, reserved = struct.unpack_from('<8Q', context.output)
        if (magic != MAGIC or error not in {0, *ERRORS} or reserved or size != extent - 64
                or not serial <= final <= 8192 or values < slots or request > 12
                or error and request or sequence != context.sequence + 1
                or error == 1 and final != 8192 or error == 13 and values <= 32768):
            _reject('invalid controller frame/counter correlation')
        try:
            encoded = ctypes.string_at(ctypes.addressof(context.output) + 64, size)
            value = decode_native_graph(encoded, wire, external=context.pool)
            if error and value is not None or not error and type(value) is not dict:
                raise ValueError('invalid complete result/continuation shape')
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
            _reject('invalid object graph: ' + str(exc))
        context.sequence += 1
        context.sent_types = len(context.types)
        context.environment_snapshot = context.pending_environment
        context.pending = (request, value) if request else None
        if not request:
            context.closed = True
        return FunctionResult(final, values, error, request, value)


def installed_nominal_function(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeNominalFunction)


def selected_nominal_function():
    manifest = os.environ.get(SELECTOR)
    if not manifest:
        return None
    try:
        return installed_nominal_function(manifest)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native nominal function refused: ' + str(exc), 'E_HIA_TYPE') from exc
