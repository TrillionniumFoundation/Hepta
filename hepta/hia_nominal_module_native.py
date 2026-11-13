"""HIA-owned module production order, inventory admission and complete exports."""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
import os
import secrets
import struct

from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_native_value_graph import decode_native_graph
from .hia_program import HIAProgramRejected

SOURCE = _source_resource_path('examples/hia_bootstrap/nominal_module.hepta')
SCHEMA = 'hepta.hia.nominal-module-native.v1'
SELECTOR = 'HEPTA_HIA_NOMINAL_MODULE_MANIFEST'
MAGIC = int.from_bytes(b'HIANMD01', 'little')
INPUT_BYTES = 256 << 20
OUTPUT_BYTES = 8 << 20
WORKSPACE_BYTES = 8 << 20


def rejected(message):
    raise HIAProgramRejected('native nominal module transport: ' + message, 'E_HIA_TYPE')


@dataclass(frozen=True)
class ModuleResult:
    error: int
    request: int
    index: int
    sequence: int
    pool_extent: int
    value: dict | None

    def admit(self):
        if self.error:
            raise HIAProgramRejected('elaborated program exceeds core inventory budget', 'E_HIA_LIMIT')


class ModuleContext:
    """Private foreign value custody; no export or instruction policy."""
    def __init__(self, owner):
        self.owner = owner
        self.metadata = [owner.document['schema'], owner.document['module'],
                         len(owner.document['functions']), secrets.token_hex(16)]
        self.wire = transport(self.metadata)
        self.pool = []
        self.output = self.workspace = None
        self.sequence = 0
        self.closed = False
        self.pending = None
        self.executed = self.completed = 0
        try:
            self.output = ctypes.create_string_buffer(OUTPUT_BYTES)
            self.workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
            self.acknowledge(0, 0)
        except BaseException:
            self.close()
            raise

    def close(self):
        self.closed = True
        self.pending = None
        self.output = self.workspace = None

    def acknowledge(self, sequence, action, index=0, pool_id=0, count=0, blocks=()):
        payload = b''.join(struct.pack('<Q', value) for value in blocks)
        header = struct.pack('<8Q', MAGIC, sequence, action, index, pool_id, count, len(payload), 0)
        if len(header) + len(payload) > OUTPUT_BYTES:
            rejected('acknowledgement exceeds private output extent')
        ctypes.memmove(self.output, header + payload, len(header) + len(payload))

    def signatures(self):
        types, indices = [], {}
        def reference(typ):
            if id(typ) not in indices:
                indices[id(typ)] = len(types); types.append(typ)
            return indices[id(typ)]
        rows = [[name, [reference(typ) for _, typ in params], [reference(typ) for typ in returns]]
                for name, (params, returns) in self.owner.signatures.items()]
        descriptors = [[typ.kind, typ.flat] for typ in types]
        self.wire = transport([*self.metadata, descriptors, rows])

    def invoke(self, result):
        if (self.closed or result is not self.pending
                or result.sequence != self.sequence or self.executed == self.sequence):
            rejected('continuation is not the current unexecuted native request')
        self.executed = self.sequence
        self.pending = None
        try:
            self._invoke(result)
            self.completed = self.sequence
        except BaseException:
            self.close()
            raise

    def _invoke(self, result):
        # The image selects each continuation. The fixed adapter executes it
        # once and retains the exact produced object, without rebuilding Core.
        if result.request == 1:
            index = result.index
            if not 0 <= index < self.metadata[2] or index != len(self.pool):
                rejected('function continuation is not the next private pool slot')
            value = self.owner.function(self.owner.document['functions'][index])
            pool_id = len(self.pool); self.pool.append((value,))
            self.acknowledge(result.sequence, 1, index, pool_id, len(value['blocks']))
        elif result.request == 2:
            if result.index != 0 or len(self.pool) != self.metadata[2]:
                rejected('helper continuation precedes complete function results')
            values = tuple(self.owner.helpers)
            pool_id = len(self.pool); self.pool.append(values)
            self.acknowledge(result.sequence, 2, 0, pool_id, len(values),
                             [len(value['blocks']) for value in values])
        elif result.request == 3:
            if result.index != 0 or len(self.pool) != self.metadata[2] + 1:
                rejected('signature continuation precedes complete helper custody')
            self.signatures()
            self.acknowledge(result.sequence, 3)
        else:
            rejected('unknown owner continuation')


class NativeNominalModule(NativeHiaJsonImage):
    def step(self, context):
        if context.closed:
            rejected('closed module context cannot resume')
        if context.completed != context.sequence:
            rejected('native continuation has not been acknowledged')
        try:
            return self._step(context)
        except BaseException:
            context.close()
            raise

    def _step(self, context):
        wire = context.wire
        if type(wire) is not bytes or len(wire) > INPUT_BYTES:
            rejected('invalid source extent')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        extent = self._entry(source, len(wire), context.output, OUTPUT_BYTES,
                             context.workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire:
            rejected('original bytes changed')
        if type(extent) is not int or not 80 <= extent <= OUTPUT_BYTES:
            rejected('invalid native extent/status ' + str(extent))
        magic, error, request, index, sequence, size, pool, reserved = struct.unpack_from('<8Q', context.output)
        if (magic != MAGIC or error not in (0, 1) or request not in (0, 1, 2, 3)
                or reserved or size != extent - 64 or pool != context.metadata[2] + 1
                or error and request or sequence < context.sequence
                or request and sequence != context.sequence + 1):
            rejected('invalid result/continuation framing')
        encoded = ctypes.string_at(ctypes.addressof(context.output)+64, extent-64)
        try:
            value = decode_native_graph(encoded, wire, external=context.pool)
            if error or request:
                if value is not None:
                    raise ValueError('refusal/continuation supplied a module')
            elif type(value) is not dict or len(context.pool) != pool:
                raise ValueError('completed result has no complete object custody')
        except (TypeError, ValueError, UnicodeError, KeyError, RecursionError, OverflowError) as exc:
            rejected('invalid complete object graph: ' + str(exc))
        context.sequence = sequence
        result = ModuleResult(error, request, index, sequence, pool, value)
        context.pending = result if request else None
        if request == 0:
            context.closed = True
        return result

    def lower(self, owner):
        context = ModuleContext(owner)
        try:
            while True:
                result = self.step(context)
                result.admit()
                if result.request == 0:
                    return result.value
                context.invoke(result)
        finally:
            context.close()


def installed_nominal_module(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeNominalModule)


def selected_nominal_module():
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    try:
        return installed_nominal_module(selected)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native nominal module refused: ' + str(exc), 'E_HIA_TYPE') from exc
