"""Transport for the complete HIA nominal constructor.

HIA chooses every validation, continuation, prefix commit, and diagnostic.
Python materializes issued type identities and complete state, without a
second source-language classifier. Selection is explicit and indivisible.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct

from .hia_composite_constructor_errors import ERRORS
from .hia_composite_function_tokens import ObjectTokenDecoder, TokenProtocolError, detached_packet_index
from .hia_composite_types_native import SOURCE as TYPE_SOURCE, SESSION_BYTES
from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_program import HIAProgramRejected

SCHEMA = 'hepta.hia.composite-constructor-native.v1'
SELECTOR = 'HEPTA_HIA_COMPOSITE_CONSTRUCTOR_MANIFEST'
KERNELS = ('owner', 'render')
SOURCES = {name: _source_resource_path('examples/hia_bootstrap/composite_constructor_' + name + '.hepta')
           for name in KERNELS}
WORKSPACE_BYTES, INPUT_BYTES, OUTPUT_BYTES = 192 << 20, 64 << 20, 64 << 10
MAGIC = int.from_bytes(b'HIACTK01', 'little')
CTOR_MAGIC = int.from_bytes(b'HIACTR01', 'little')
RESPONSE_MAGIC = int.from_bytes(b'HIACTP01', 'little')


def _pairs(rows):
    result = {}
    for name, value in rows:
        if name in result:
            raise ValueError('duplicate constructor bundle field')
        result[name] = value
    return result


def _custody_index(wire, value):
    """Index original representation identities after an exact byte binding.

    Service requests use a detached copy. Final source references retain the
    caller's already detached document identities, without inspecting nominal
    fields. The whole packet is read back again before state publication.
    """
    index, pending = {}, [(0, value)]
    while pending:
        offset, item = pending.pop()
        index[offset] = item
        kind, size = struct.unpack_from('<2Q', wire, offset)
        if kind not in (5, 6):
            continue
        values = list(item) if kind == 5 else [v for pair in item.items() for v in pair]
        cursor = offset + 24
        children = []
        for child in values:
            children.append((cursor, child))
            cursor += 16 + struct.unpack_from('<Q', wire, cursor + 8)[0]
        if cursor != offset + 16 + size:
            raise TokenProtocolError('original representation changed while indexing')
        pending.extend(reversed(children))
    return index


class NativeCompositeConstructor:
    def __init__(self, images, *, types_source_sha256):
        if set(images) != set(KERNELS):
            raise ValueError('complete constructor requires both HIA kernels')
        self.images, self.types_source_sha256 = dict(images), types_source_sha256

    def initialize(self, owner, document, *, legacy=False):
        if sha256(TYPE_SOURCE.read_bytes()).hexdigest() != self.types_source_sha256:
            raise HIAProgramRejected('selected native constructor type-state source changed', 'E_HIA_TYPE')
        NativeConstructorInvocation(self.images, owner, document, legacy=legacy).initialize()


class NativeConstructorInvocation:
    """One source snapshot; complete native state is mirrored on completion.

    The temporary arena is released before function lowering acquires its own
    arena. The native type session survives exactly when constructor stage 2
    has committed, including a later constructor semantic refusal.
    """

    def __init__(self, images, owner, document, *, legacy=False):
        self.images, self.owner = dict(images), owner
        self.types = None
        self._broken = False
        self._request = self._stage = 0
        self._profile = self._issued_phase = None
        self._waiting = self._completed = False
        self._delegate_error = None
        self._workspace = self._output = self._empty = None
        try:
            self._workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
            self._output = ctypes.create_string_buffer(OUTPUT_BYTES)
            self._empty = ctypes.create_string_buffer(1)
            self._original = [document, legacy]
            self._source_wire = transport(self._original)
            if len(self._source_wire) > INPUT_BYTES:
                self._refuse('source exceeds derived transport capacity')
            try:
                self._snapshot, self._source_index = detached_packet_index(self._source_wire)
                self._return_index = _custody_index(self._source_wire, self._original)
                if transport(self._original) != self._source_wire:
                    self._refuse('source changed while taking its custody copy')
            except (TokenProtocolError, UnicodeError, ValueError) as exc:
                self._refuse('source is not a detached exact tree: ' + str(exc))
        except BaseException:
            self._workspace = self._output = self._empty = None
            raise

    def _refuse(self, message):
        self._broken = True
        raise HIAProgramRejected('native composite constructor transport: ' + message, 'E_HIA_TYPE')

    def _frame(self, size):
        if self._broken:
            self._refuse('protocol has already refused')
        if type(size) is not int or size != 64:
            self._refuse('invalid continuation extent/status ' + str(size))
        frame = struct.unpack_from('<8Q', self._output)
        magic, action, error, phase, stage, profile, request, pending = frame
        phases = {10: 1, 30: 2, 41: 3, 50: 4, 81: 3, 82: 5}
        if (self._completed or magic != CTOR_MAGIC or action not in (0, 2) or not self._stage <= stage <= 3
                or profile not in range(5) or not self._request <= request <= self._request + 1
                or pending not in range(6) or error not in (0, 999, *ERRORS)
                or phase not in (*phases, 2000)):
            self._refuse('invalid continuation frame or state correlation')
        if ((stage == 0 and profile != 0) or (stage != 0 and profile == 0)
                or (phase == 2000 and (action != 2 or pending))
                or (phase != 2000 and error)
                or (action == 0 and pending)
                or (action == 2 and phase != 2000 and pending == 0)):
            self._refuse('inconsistent continuation state')
        if self._profile is not None and profile != self._profile:
            self._refuse('continuation changed the issued profile')
        if phase == 2000:
            if request != self._request or (self._waiting and error != 999):
                self._refuse('completion changed the issued request identity')
            self._completed = True
            self._waiting = False
        else:
            expected_stage = 3 if phase != 10 else (1 if action == 2 else 2)
            if stage != expected_stage:
                self._refuse('resume phase changed its committed stage')
            if action == 2:
                if self._waiting or pending != phases[phase] or request != self._request + 1:
                    self._refuse('request kind changed its resume phase or sequence')
                self._issued_phase = phase
                self._waiting = True
            else:
                if not self._waiting or request != self._request or phase != self._issued_phase:
                    self._refuse('response changed the issued request phase or identity')
                self._waiting = False
        self._profile = profile
        self._stage = stage
        return frame

    def _invoke(self, wire):
        if self._broken:
            self._refuse('protocol has already refused')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        result = self.images['owner']._entry(source, len(wire), self._output,
            OUTPUT_BYTES, self._workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire:
            self._refuse('native input bytes changed')
        return self._frame(result)

    def _run(self):
        if self._broken:
            self._refuse('protocol has already refused')
        if self.types is None or self.types._closed or self.types._broken:
            self._refuse('continuation has no live native type dependency')
        with self.types._lock:
            size = self.images['owner']._entry(self.types._state, SESSION_BYTES,
                self._output, OUTPUT_BYTES, self._workspace, WORKSPACE_BYTES)
        return self._frame(size)

    def _stream(self, action, request):
        if self._broken:
            self._refuse('protocol has already refused')
        decoder = ObjectTokenDecoder(self._return_index if action == 0 else self._source_index)
        sequence = 0
        while not decoder.complete:
            # The generic renderer never reads the type state. Giving it an
            # empty borrowed buffer also covers refusals before type creation.
            size = self.images['render']._entry(self._empty, 0, self._output,
                OUTPUT_BYTES, self._workspace, WORKSPACE_BYTES)
            if type(size) is not int or not 64 <= size <= OUTPUT_BYTES:
                self._refuse('invalid stream extent/status ' + str(size))
            frame = struct.unpack_from('<8Q', self._output)
            if (frame[0] != MAGIC or frame[1] != action or frame[2] != sequence
                    or frame[3] not in (0, 1) or frame[4] or frame[5]
                    or frame[6] != request or frame[7] != size - 64):
                self._refuse('stream changed continuation identity')
            try:
                decoder.feed(ctypes.string_at(ctypes.addressof(self._output) + 64, frame[7]),
                             final=bool(frame[3]))
            except TokenProtocolError as exc:
                self._refuse('malformed complete native state: ' + str(exc))
            sequence += 1
        return decoder.root

    def _type_id(self, typ):
        identifier = self.types._ids.get(id(typ))
        if identifier is None or self.types._types.get(identifier) is not typ:
            self._refuse('descriptor belongs to no issued native identity')
        return identifier

    def _issued_type(self, identifier):
        if type(identifier) is not int or identifier not in self.types._types:
            self._refuse('unissued native type identity')
        return self.types._types[identifier]

    def _params(self, rows):
        if type(rows) is not list:
            self._refuse('parameter state is not a list')
        result = []
        for row in rows:
            if type(row) is not list or len(row) != 2 or type(row[0]) is not str:
                self._refuse('invalid parameter state framing')
            result.append((row[0], self._issued_type(row[1])))
        return tuple(result)

    def _returns(self, values):
        if type(values) is not list:
            self._refuse('return state is not a list')
        return tuple(self._issued_type(identifier) for identifier in values)

    def _registry(self, rows):
        if type(rows) is not list:
            self._refuse('registry is not a list')
        functions, signatures = {}, {}
        for row in rows:
            if (type(row) is not list or len(row) != 4 or type(row[0]) is not str
                    or row[0] in signatures or type(row[3]) is not dict):
                self._refuse('invalid complete registry framing')
            functions[row[0]] = row[3]
            signatures[row[0]] = (self._params(row[1]), self._returns(row[2]))
        return functions, signatures

    def _service(self, command, kind, request):
        if type(command) is not list or not command or type(command[0]) is not int or command[0] != kind:
            self._refuse('request command and frame disagree')
        error, count, payload = 0, 0, b''
        try:
            if kind == 1:
                if len(command) != 4 or self.types is not None or any(type(v) is not bool for v in command[2:]):
                    self._refuse('invalid type initializer request')
                from .hia_composite_types_native import selected_composite_types
                self.types = selected_composite_types(command[1],
                    recursive_chain=command[2], partial_records=command[3])
                if self.types is None:
                    raise HIAProgramRejected('selected native constructor requires native types', 'E_HIA_TYPE')
            else:
                if self.types is None or self.types._closed or self.types._broken:
                    self._refuse('typed service has no live native dependency')
                with self.types._lock:
                    if kind == 2:
                        if len(command) != 2:
                            self._refuse('invalid parameter request arity')
                        ids = [self._type_id(typ) for _, typ in self.types.parameters(command[1])]
                    elif kind == 3:
                        if len(command) != 2:
                            self._refuse('invalid type resolution request arity')
                        ids = [self._type_id(self.types.resolve(command[1]))]
                    elif kind == 4:
                        if len(command) != 4 or type(command[1]) is not dict:
                            self._refuse('invalid origin request arity')
                        origins = self.types.loan_origins(command[1], self._params(command[2]),
                                                          self._returns(command[3]))
                        parts = []
                        for origin in origins:
                            if origin is None:
                                parts.append(struct.pack('<3Q', 0, 0, 0))
                            else:
                                name = origin[0].encode('utf-8')
                                parts.append(struct.pack('<3Q', 1, len(name), origin[1]) + name)
                        count, payload = len(origins), b''.join(parts)
                        ids = None
                    elif kind == 5:
                        if len(command) != 3:
                            self._refuse('invalid task protocol request arity')
                        _, signatures = self._registry(command[2])
                        ids = [self._type_id(self.types.check_task(self._issued_type(command[1]), signatures))]
                    else:
                        self._refuse('unknown typed native service')
                    if ids is not None:
                        count, payload = len(ids), b''.join(struct.pack('<Q', value) for value in ids)
        except HIAProgramRejected as exc:
            if self._broken or (self.types is not None and self.types._broken):
                self._refuse('native service transport failed: ' + str(exc))
            error, count, payload, self._delegate_error = 1, 0, b'', exc
        return self._invoke(struct.pack('<8Q', RESPONSE_MAGIC, request, kind, error,
                                       count, len(payload), 0, 0) + payload)

    def _mirror(self, value, frame):
        if (type(value) is not list or len(value) != 6 or type(value[0]) is not int
                or type(value[1]) is not int or type(value[2]) is not bool
                or value[:2] != [frame[4], frame[5]] or value[2] != self._snapshot[1]):
            self._refuse('complete state disagrees with native frame')
        stage, profile, legacy, document, registry, origins = value
        if stage == 0:
            if value[3:] != [None, None, None]:
                self._refuse('uncommitted state contains owner fields')
            return
        if document is not self._original[0] or transport(self._original) != self._source_wire:
            self._refuse('native document does not reference the frozen input')
        from .hia_schema import COMPOSITE_OPERATIONS_BY_SCHEMA, LEGACY_COMPOSITE_OPERATIONS
        schemas = tuple('hepta.hia.composite.v' + str(i) for i in range(1, 5))
        self.owner.document, self.owner.serial, self.owner.value_slots = document, 0, 0
        self.owner.nominal_operations = (LEGACY_COMPOSITE_OPERATIONS if legacy else
                                         COMPOSITE_OPERATIONS_BY_SCHEMA[schemas[profile - 1]])
        if stage >= 2:
            if self.types is None:
                self._refuse('committed native type state is missing')
            self.owner.native_types = self.owner.types = self.types
            self.owner.parameter_loan_returns = profile == 4
        if stage < 3:
            if registry is not None or origins is not None:
                self._refuse('uncommitted inventories were published')
            return
        functions, signatures = self._registry(registry)
        if type(origins) is not list:
            self._refuse('origin state is not a list')
        materialized = {}
        for row in origins:
            if (type(row) is not list or len(row) != 2 or type(row[0]) is not str
                    or row[0] in materialized or type(row[1]) is not list):
                self._refuse('invalid origin registry framing')
            values = []
            for origin in row[1]:
                if origin is not None and (type(origin) is not list or len(origin) != 2
                        or type(origin[0]) is not str or type(origin[1]) is not int):
                    self._refuse('invalid origin slot framing')
                values.append(None if origin is None else tuple(origin))
            materialized[row[0]] = tuple(values)
        self.owner.functions, self.owner.signatures, self.owner.return_origins = functions, signatures, materialized
        self.owner.helpers, self.owner.helper_names = [], {}

    def initialize(self):
        try:
            frame = self._invoke(self._source_wire)
            while True:
                action, error, phase, request, pending = frame[1], frame[2], frame[3], frame[6], frame[7]
                if phase == 2000:
                    value = self._stream(0, request)
                    self._mirror(value, frame)
                    if error == 999:
                        if self._delegate_error is None:
                            self._refuse('unissued delegated semantic refusal')
                        raise self._delegate_error
                    if error:
                        code, message = ERRORS[error]
                        raise HIAProgramRejected(message, code)
                    return
                if action == 0:
                    frame = self._run()
                    continue
                if action != 2 or request != self._request + 1:
                    self._refuse('replayed or skipped native request')
                self._request = request
                command = self._stream(pending, request)
                frame = self._service(command, pending, request)
        finally:
            self._workspace = self._output = self._empty = None
            if self.types is not None and getattr(self.owner, 'native_types', None) is not self.types:
                self.types.close()
            self._source_index.clear()
            self._return_index.clear()
            # Avoid a self -> delegated exception -> traceback -> self cycle.
            # The currently raised exception and committed owner state retain
            # their normal lifetimes; the temporary bridge retains neither.
            self._delegate_error = None


def installed_composite_constructor(path):
    path = Path(path)
    raw = path.read_bytes()
    if len(raw) > 65536:
        raise ValueError('constructor bundle exceeds fixed framing')
    value = json.loads(raw, object_pairs_hook=_pairs)
    if (type(value) is not dict or set(value) != {'schema', 'kernels', 'types_source_sha256'}
            or value['schema'] != SCHEMA or type(value['kernels']) is not dict
            or set(value['kernels']) != set(KERNELS)):
        raise ValueError('invalid complete constructor bundle')
    digest = value['types_source_sha256']
    if type(digest) is not str or len(digest) != 64 or any(ch not in '0123456789abcdef' for ch in digest):
        raise ValueError('invalid constructor type dependency identity')
    images = {}
    for name in KERNELS:
        component = value['kernels'][name]
        if type(component) is not str:
            raise ValueError('invalid constructor kernel manifest path')
        images[name] = _installed_json_image(str(path.parent / component), SOURCES[name],
            'hepta.hia.composite-constructor-' + name + '-native.v1', NativeHiaJsonImage)
    return NativeCompositeConstructor(images, types_source_sha256=digest)


def selected_composite_constructor():
    path = os.environ.get(SELECTOR)
    if not path:
        return None
    try:
        return installed_composite_constructor(path)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native composite constructor refused: ' + str(exc), 'E_HIA_TYPE') from exc
