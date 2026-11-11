"""Fixed continuations for HIA-owned nominal declaration admission."""
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

SOURCE = _source_resource_path('examples/hia_bootstrap/nominal_admission.hiaasm')
SCHEMA = 'hepta.hia.nominal-admission-native.v1'
SELECTOR = 'HEPTA_HIA_NOMINAL_ADMISSION_MANIFEST'
MAGIC = int.from_bytes(b'HIANAD01', 'little')
INPUT_BYTES = 32 << 20
OUTPUT_BYTES = 1 << 20
WORKSPACE_BYTES = 40 << 20
ERRORS = {
 1: ('E_HIA_FORMAT', 'nominal program: expected exactly functions, module, schema, types'),
 2: ('E_HIA_SCHEMA', 'unsupported nominal program schema'),
 3: ('E_HIA_SCHEMA', 'legacy nominal adapter only targets composite v1'),
 4: ('E_HIA_NAME', 'module: invalid/reserved ASCII identifier'),
 5: ('E_HIA_NAME', 'module: identifier uses the elaborator namespace'),
 6: ('E_HIA_FORMAT', 'invalid nominal function inventory'),
 7: ('E_HIA_FORMAT', 'function: expected exactly blocks, effects, entry, name, params, returns'),
 8: ('E_HIA_FORMAT', 'function: expected exactly blocks, effects, entry, name, params, return_loans, returns'),
 9: ('E_HIA_NAME', 'function: invalid/reserved ASCII identifier'),
 10: ('E_HIA_NAME', 'function: identifier uses the elaborator namespace'),
 11: ('E_HIA_NAME', 'duplicate nominal function'),
 12: ('E_HIA_TYPE', 'function returns must be a list'),
 13: ('E_HIA_LOAN', 'stored loans may not escape a function'),
 14: ('E_HIA_EFFECT', 'unknown/duplicate nominal function effect'),
}


def rejected(message):
    raise HIAProgramRejected('native nominal admission transport: ' + message, 'E_HIA_TYPE')


@dataclass(frozen=True)
class AdmissionResult:
    error: int
    request: int
    index: int
    item: int
    sequence: int
    value: object

    def admit(self):
        if self.error in (15,16):
            raise KeyError(self.value)
        if self.error == 17:
            raise TypeError("unhashable type: '" + self.value + "'")
        if self.error:
            code, message = ERRORS[self.error]
            raise HIAProgramRejected(message, code)


class AdmissionContext:
    """Retained original object custody and fixed native dependency calls."""
    def __init__(self, owner, document, legacy=False):
        self.owner, self.document = owner, document
        self.legacy = legacy
        self.wire = transport([None, secrets.token_hex(16), document])
        self.output = ctypes.create_string_buffer(OUTPUT_BYTES)
        self.workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
        self.sequence = self.executed = 0
        self.closed = False
        self.acknowledge(0, 0)

    def acknowledge(self, sequence, action, index=0, item=0):
        ctypes.memmove(self.output, struct.pack('<8Q', MAGIC, sequence, action, index, item, 0, 0, 0), 64)

    def invoke(self, result):
        if self.closed or result.sequence != self.sequence or result.sequence <= self.executed:
            rejected('callback is not the current unexecuted continuation')
        self.executed = result.sequence
        owner, document = self.owner, self.document
        action, index, item, value = result.request, result.index, result.item, result.value
        self.wire = transport(None)
        if action == 1:
            owner.nominal_operations = frozenset(value)
        elif action == 10:
            owner.document = document
            owner.serial = value['serial']; owner.value_slots = value['value_slots']
        elif action == 12:
            from .hia_composite_types_native import selected_composite_types
            selected = selected_composite_types(document['types'],
                recursive_chain=value['recursive_chain'], partial_records=value['partial_records'])
            if selected is None:
                rejected('selected admission requires the selected native type owner')
            owner.native_types = selected
            owner.types = selected
        elif action == 2:
            owner.parameter_loan_returns = value
        elif action == 3:
            owner.functions, owner.signatures, owner.return_origins = {}, {}, {}
            owner.helpers, owner.helper_names = [], {}
        elif 4 <= action <= 7:
            functions = document['functions']
            if not 0 <= index < len(functions):
                rejected('function index outside original inventory')
            function = functions[index]
            if action == 4:
                self.params = owner.parameters(function['params'])
                self.returns = []
            elif action == 5:
                if item != len(self.returns) or not 0 <= item < len(function['returns']):
                    rejected('return continuation is not the next original occurrence')
                typ = owner.types.resolve(function['returns'][item])
                self.returns.append(typ)
                self.wire = transport([typ.kind, list(typ.flat)])
            elif action == 6:
                owner.return_origins[value] = owner.types.loan_origins(function, self.params, tuple(self.returns))
            else:
                owner.functions[value] = function
                owner.signatures[value] = (self.params, tuple(self.returns))
        elif action == 8:
            if not 0 <= index < len(document['types']):
                rejected('task declaration index outside original inventory')
            owner.check_task(owner.types.resolve(document['types'][index]['name']))
        elif action in (9,11):
            # The foreign Python API's truth conversion is observed only when
            # HIA requests it, after original root/schema guards. HIA owns all
            # profile selection and subsequent declaration decisions.
            observed = bool(self.legacy)
            self.wire = transport([observed, document])
        else:
            rejected('unknown declaration continuation')
        self.acknowledge(result.sequence, action, index, item)


class NativeNominalAdmission(NativeHiaJsonImage):
    def step(self, context):
        if context.closed:
            rejected('closed admission context cannot resume')
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
        magic, error, request, index, item, sequence, size, reserved = struct.unpack_from('<8Q', context.output)
        if (magic != MAGIC or not 0 <= error <= 17 or not 0 <= request <= 12
                or reserved or size != extent - 64 or error and request
                or sequence < context.sequence or request and sequence != context.sequence + 1
                or request not in (4,5,6,7,8) and index or request != 5 and item):
            rejected('invalid declaration result framing')
        encoded = ctypes.string_at(ctypes.addressof(context.output) + 64, extent - 64)
        try:
            value = decode_native_graph(encoded, wire)
            if error == 15:
                if type(value) is not str: raise ValueError('invalid missing foreign key')
            elif error == 16:
                if type(value) not in (str,int,float,bool,type(None)):
                    raise ValueError('invalid missing foreign schema key')
            elif error == 17:
                if value not in ('list','dict'): raise ValueError('invalid foreign unhashable type')
            elif request == 1:
                if type(value) is not list or any(type(name) is not str for name in value):
                    raise ValueError('invalid initial operation inventory')
            elif request == 10:
                if (type(value) is not dict or set(value) != {'serial','value_slots'}
                        or any(type(value[name]) is not int for name in value)):
                    raise ValueError('invalid initial held fields')
            elif request == 12:
                if (type(value) is not dict or set(value) != {'recursive_chain','partial_records'}
                        or any(type(value[name]) is not bool for name in value)):
                    raise ValueError('invalid native type flags')
            elif request == 2:
                if type(value) is not bool: raise ValueError('invalid held loan flag')
            elif request in (6, 7):
                if type(value) is not str: raise ValueError('invalid held function name')
            elif value is not None:
                raise ValueError('unexpected declaration result graph')
        except (TypeError, ValueError, UnicodeError, KeyError, RecursionError, OverflowError) as exc:
            rejected('invalid complete declaration graph: ' + str(exc))
        context.sequence = sequence
        if request == 0:
            context.closed = True
        return AdmissionResult(error, request, index, item, sequence, value)

    def initialize(self, owner, document, *, legacy=False):
        context = AdmissionContext(owner, document, legacy)
        try:
            while True:
                result = self.step(context)
                result.admit()
                if not result.request:
                    return
                context.invoke(result)
        except BaseException:
            context.closed = True
            raise


def installed_nominal_admission(manifest):
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeNominalAdmission)


def selected_nominal_admission():
    manifest = os.environ.get(SELECTOR)
    if not manifest:
        return None
    try:
        return installed_nominal_admission(manifest)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native nominal admission refused: ' + str(exc), 'E_HIA_TYPE') from exc
