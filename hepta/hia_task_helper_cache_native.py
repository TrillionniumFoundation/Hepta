"""HIA-owned task helper cache and exact generator continuation order.

The bridge transports HIA-issued type identities, executes only requested
continuations and materializes complete native state deltas. Cache lookup,
miss ordering, prefix commits, refusal and helper publication belong to HIA.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import os
import secrets
import struct

from .hia_composite_types_native import _NativeTypeIdentity
from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_native_value_graph import NativeValuePool, decode_bound_native_graph
from .hia_program import HIAProgramRejected
from .hia_task_helpers_native import ERRORS as HELPER_ERRORS

SOURCE = _source_resource_path('examples/hia_bootstrap/task_helper_cache.hiaasm')
SCHEMA = 'hepta.hia.task-helper-cache-native.v1'
SELECTOR = 'HEPTA_HIA_TASK_HELPER_CACHE_MANIFEST'
MAGIC = int.from_bytes(b'HIATHC01', 'little')
INPUT_BYTES = 1 << 20
OUTPUT_BYTES = 4096
WORKSPACE_BYTES = 2 << 20
ERRORS = {**HELPER_ERRORS,
    4: ('E_HIA_TYPE', 'selected native function requires native task helper generation'),
    5: ('E_HIA_TYPE', 'selected native task helper cache requires native task helper generation')}


def _reject(message):
    raise HIAProgramRejected('native task helper cache transport: ' + message, 'E_HIA_TYPE')


class HelperCacheContext:
    """One invocation; the owner's cache persists across invocations/functions."""
    def __init__(self, owner, typ, operation, *, require_native=False):
        self.owner, self.typ, self.operation = owner, typ, operation
        key = typ.key
        if type(key) is not _NativeTypeIdentity:
            _reject('selected cache requires HIA-issued type identities')
        self.nonce, self.type_id = key.session, key.identifier
        self.keys = {}
        self.pool = NativeValuePool()
        rows = []
        for (held_key, held_operation), name in tuple(owner.helper_names.items()):
            identifier = self.identity(held_key)
            rows.append([identifier, held_operation, name, self.pool.add(name)])
        self.identity(key)
        self.metadata = [self.type_id, operation, require_native, rows, secrets.token_hex(16)]
        self.metadata_bytes = transport(self.metadata)
        self.inventory, self.functions = None, ()
        self.generator = self.step_type = self.generated = None
        self.effects = [None, None]
        self.reply, self.sequence = None, 0
        self.executed = self.completed = 0
        self.pending = None
        self.terminal = None
        self._issued = self._binding = self._issued_fields = None
        self.closed = self.released = self.committed = False
        self.output = self.workspace = None
        try:
            self.output = ctypes.create_string_buffer(OUTPUT_BYTES)
            self.workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        except BaseException:
            self.close()
            raise

    def identity(self, key):
        if (type(key) is not _NativeTypeIdentity or key.session is not self.nonce
                or type(key.identifier) is not int or not 0 < key.identifier <= 0xffffffff):
            _reject('type identity is outside the held HIA session')
        self.keys[key.identifier] = key
        return key.identifier

    def close(self):
        self.closed = self.released = True
        self._binding = None
        self.output = self.workspace = None

    def data(self):
        if self.closed:
            _reject('closed helper cache context cannot resume')
        if transport(self.metadata) != self.metadata_bytes:
            _reject('held cache metadata changed')
        return transport([self.metadata, self.sequence, self.owner.serial, self.reply, self.inventory])

    def service(self, request, query):
        if (self.closed or self.pending is None or self.executed >= self.sequence
                or type(request) is not int or request != self.pending[0]
                or query is not self.pending[1]):
            _reject('callback is not the current unexecuted continuation')
        try:
            self._validate(self._issued)
            self.executed = self.sequence
            self._service(request, query)
            self.completed = self.sequence
            self.pending = None
        except BaseException:
            self.close()
            raise

    def _validate(self, result):
        if (result is not self._issued or self._binding is None
                or any(type(value) is not int for value in (result.error, result.request, result.sequence))
                or (result.error, result.request, result.sequence) != self._issued_fields):
            _reject('result is not the current issued native frame')
        try:
            self._binding.validate(result.value)
        except ValueError as error:
            _reject('issued graph changed: ' + str(error))

    def _service(self, request, query):
        fields = {1: set(), 2: set(), 3: set(), 4: {'index', 'slot'},
                  5: {'serial'}, 6: {'key'}}
        if request not in fields or type(query) is not dict or set(query) != fields[request]:
            _reject('continuation is not a complete object')
        if request == 1:
            from .hia_task_helpers_native import selected_task_helpers
            self.generator = selected_task_helpers()
            self.reply = self.generator is not None
        elif request == 2:
            native_types = self.owner.native_types
            if native_types is None or native_types._nonce is not self.nonce:
                _reject('selected cache requires the native task protocol owner')
            # Hold the already owned type session; the default wrapper cannot
            # reselect a hosted task check between admission and invocation.
            self.step_type = native_types.check_task(self.typ, self.owner.signatures)
            self.reply = None
        elif request == 3:
            self.functions = tuple(self.owner.functions.items())
            self.inventory = [self.typ.poll, self.typ.cancel, [name for name, _ in self.functions]]
            self.reply = None
        elif request == 4:
            index, slot = query['index'], query['slot']
            if (type(index) is not int or not 0 <= index < len(self.functions)
                    or type(slot) is not int or slot not in (0, 1)):
                _reject('effect reference is outside the held function inventory')
            self.effects[slot] = self.functions[index][1]['effects']
            self.reply = None
        elif request == 5:
            serial = query['serial']
            if (type(serial) is not int or not 0 <= serial <= 8192
                    or self.generator is None or self.step_type is None):
                _reject('generator continuation lacks admitted dependencies')
            result = self.generator.generate(self.typ, self.step_type, self.operation, serial, *self.effects)
            self.generated = result
            name_id = self.pool.add(result.name)
            helper_id = self.pool.add(result.helper)
            self.reply = [result.serial, result.error, result.name, name_id, helper_id]
        else:
            if type(query['key']) is not str:
                _reject('missing function key is not a string')
            raise KeyError(query['key'])

    def commit(self, result):
        if (self.released or self.committed or self.terminal is None
                or result is not self.terminal):
            _reject('terminal result is not the current uncommitted result')
        # Claim before the first owner write: an interrupted prefix is never
        # replayable, including when the original exception keeps this context.
        try:
            self._validate(result)
            self.committed = True
            value = result.value
            for serial in value['serial']:
                self.owner.serial = serial
            for identifier, operation, name in value['cache']:
                self.owner.helper_names[(self.keys[identifier], operation)] = name
            result.admit()
            for helper in value['helpers']:
                self.owner.helpers.append(helper)
            return value['name']
        except BaseException:
            self.close()
            raise


@dataclass(frozen=True)
class HelperCacheResult:
    error: int
    request: int
    sequence: int
    value: dict

    def admit(self):
        if self.error:
            code, message = ERRORS[self.error]
            raise HIAProgramRejected(message, code)


class NativeTaskHelperCache(NativeHiaJsonImage):
    def lower(self, owner, typ, operation, *, require_native=False):
        context = HelperCacheContext(owner, typ, operation, require_native=require_native)
        try:
            for _ in range(16):
                result = self.step(context)
                if result.request:
                    context.service(result.request, result.value)
                else:
                    return context.commit(result)
            _reject('controller did not complete within its fixed continuation bound')
        finally:
            context.close()

    def step(self, context):
        if context.closed:
            _reject('closed helper cache context cannot resume')
        if context.pending is not None or context.completed != context.sequence:
            _reject('previous helper cache continuation has not completed')
        try:
            return self._step(context)
        except BaseException:
            context.closed = True
            raise

    def _step(self, context):
        wire = context.data()
        if len(wire) > INPUT_BYTES:
            _reject('input exceeds private byte capacity')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        extent = self._entry(source, len(wire), context.output, OUTPUT_BYTES,
                             context.workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire:
            _reject('input bytes changed')
        if type(extent) is not int or not 88 <= extent <= OUTPUT_BYTES:
            _reject('invalid result extent/status ' + str(extent))
        magic, error, request, size, sequence, r0, r1, r2 = struct.unpack_from('<8Q', context.output)
        if (magic != MAGIC or error not in {0, *ERRORS} or request > 6 or error and request
                or r0 or r1 or r2 or size != extent - 64 or sequence != context.sequence + 1):
            _reject('invalid controller frame/sequence correlation')
        try:
            encoded = ctypes.string_at(ctypes.addressof(context.output) + 64, size)
            value, binding = decode_bound_native_graph(encoded, wire, external=context.pool)
            if type(value) is not dict:
                raise ValueError('result is not a complete object')
            if not request:
                if set(value) != {'serial', 'cache', 'helpers', 'name'}:
                    raise ValueError('result state fields differ')
                if any(type(value[key]) is not list or len(value[key]) > 1
                       for key in ('serial', 'cache', 'helpers')):
                    raise ValueError('result state arrays differ')
                if any(type(item) is not int or not 0 <= item <= 8192 for item in value['serial']):
                    raise ValueError('result serial is outside the held counter')
                for row in value['cache']:
                    if (type(row) is not list or len(row) != 3 or type(row[0]) is not int
                            or row[0] != context.type_id or row[1] != context.operation
                            or type(row[2]) is not str):
                        raise ValueError('result cache row is outside the held request')
                if value['name'] is not None and type(value['name']) is not str:
                    raise ValueError('result name is not a held string/null')
                if error and value['helpers'] or any(type(item) is not dict for item in value['helpers']):
                    raise ValueError('result helper publication differs')
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError) as exc:
            _reject('invalid complete object graph: ' + str(exc))
        result = HelperCacheResult(error, request, sequence, value)
        context._issued = result
        context._binding = binding
        context._issued_fields = (error, request, sequence)
        context.sequence = sequence
        context.pending = (request, value) if request else None
        if not request:
            context.closed = True
            context.terminal = result
        return result


def installed_task_helper_cache(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeTaskHelperCache)


def selected_task_helper_cache():
    manifest = os.environ.get(SELECTOR)
    if not manifest:
        return None
    try:
        return installed_task_helper_cache(manifest)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native task helper cache refused: ' + str(exc), 'E_HIA_TYPE') from exc
