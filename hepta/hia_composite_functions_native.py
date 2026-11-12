"""Explicit complete-function HIA bundle with typed native continuations.

The bridge snapshots representation, forwards HIA-created requests to selected
native owners, materializes generic Core tokens, and mirrors native state. It
does not scan source blocks, look up source names, compare types, decide live
values, generate Core instructions, or fall back to hosted function lowering.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
from threading import RLock
import weakref

from .hia_composite_function_tokens import ObjectTokenDecoder, TokenProtocolError, detached_packet_index
from .hia_composite_functions_errors import ERRORS
from .hia_composite_types_native import SOURCE as TYPE_SOURCE, SESSION_BYTES
from .hia_instruction_policy_native import transport
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_program import HIAProgramRejected
from .hia_task_helpers_native import SOURCE as HELPER_SOURCE, selected_task_helpers

SCHEMA = 'hepta.hia.composite-functions-native.v1'
SELECTOR = 'HEPTA_HIA_COMPOSITE_FUNCTIONS_MANIFEST'
KERNELS = ('admit', 'records', 'advanced', 'terms', 'render')
SOURCES = {name: _source_resource_path('examples/hia_bootstrap/composite_function_' + name + '.hiaasm')
           for name in KERNELS}
WORKSPACE_BYTES = 192 << 20
INPUT_BYTES = 64 << 20
OUTPUT_BYTES = 64 << 10
MAGIC = int.from_bytes(b'HIAFNC01', 'little')
ADMIT_MAGIC = int.from_bytes(b'HIAFAD01', 'little')
ADMIT_RESPONSE_MAGIC = int.from_bytes(b'HIAFRS01', 'little')
LOWER_RESPONSE_MAGIC = int.from_bytes(b'HIAFLR01', 'little')
NEXT_MAGIC = int.from_bytes(b'HIAFNX01', 'little')
METADATA_REQUEST_MAGIC = int.from_bytes(b'HIAFMQ01', 'little')
METADATA_MAGIC = int.from_bytes(b'HIAFMD01', 'little')
OPERATIONS = ('start', 'poll', 'cancel', 'join', 'close')

def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate function bundle field')
        result[key] = value
    return result


class NativeCompositeFunctions:
    def __init__(self, images, *, types_source_sha256, helpers_source_sha256):
        if set(images) != set(KERNELS):
            raise ValueError('complete function bundle requires every HIA kernel')
        self.images = dict(images)
        self.types_source_sha256 = types_source_sha256
        self.helpers_source_sha256 = helpers_source_sha256

    def session(self, owner, *, legacy=False):
        if owner.native_types is None:
            raise HIAProgramRejected('selected native function lowering requires native types', 'E_HIA_TYPE')
        if sha256(TYPE_SOURCE.read_bytes()).hexdigest() != self.types_source_sha256:
            raise HIAProgramRejected('selected native function type-state source changed', 'E_HIA_TYPE')
        if sha256(HELPER_SOURCE.read_bytes()).hexdigest() != self.helpers_source_sha256:
            raise HIAProgramRejected('selected native function helper source changed', 'E_HIA_TYPE')
        helpers = selected_task_helpers()
        if helpers is None:
            raise HIAProgramRejected('selected native function lowering requires native task helpers', 'E_HIA_TYPE')
        return NativeFunctionSession(self.images, owner, helpers, legacy=legacy)


class NativeFunctionSession:
    """One locked native owner for the admitted document's frozen functions.

    The ordinary elaborator supplies its detached document members. Arbitrary
    replacement dictionaries passed to this private API are not another source
    admission route; exact representation custody is checked before native NEXT.
    """

    def __init__(self, images, owner, helpers, *, legacy=False):
        self.images, self.owner, self.helpers = dict(images), weakref.proxy(owner), helpers
        self.types = owner.native_types
        self._lock = RLock()
        self._broken = False
        self._closed = False
        self._request = 0
        self._serial = owner.serial
        self._slots = owner.value_slots
        self._pending_helpers = {}
        self._delegate_errors = {}
        self._active_kernel = 'admit'
        self._workspace = self._output = None
        self._source_index = {}
        self._function_sources = {}
        try:
            self._workspace = ctypes.create_string_buffer(WORKSPACE_BYTES)
            self._output = ctypes.create_string_buffer(OUTPUT_BYTES)
            with self.types._lock:
                members = tuple(owner.document['functions'])
                registry = [[name, [[pname, self._type_id(typ)] for pname, typ in params],
                             [self._type_id(typ) for typ in returns]]
                            for name, (params, returns) in owner.signatures.items()]
                wire = transport([owner.document, registry, list(owner.return_origins.items()),
                                  owner.serial, owner.value_slots, legacy, 0])
                if len(wire) > INPUT_BYTES:
                    self._refuse('initial packet exceeds derived transport capacity')
                try:
                    detached, self._source_index = detached_packet_index(wire)
                    self._function_sources = {
                        id(member): (member, transport(snapshot))
                        for member, snapshot in zip(members, detached[0]['functions'], strict=True)
                    }
                except (TokenProtocolError, ValueError, UnicodeError, OverflowError) as exc:
                    self._refuse('initial packet is not a detached exact tree: ' + str(exc))
                frame = self._invoke_bytes('admit', wire)
                if frame[1] != 0 or frame[2] != 0:
                    self._refuse('initial native state is not ready')
        except BaseException:
            # The owner cannot close a session whose construction never
            # returned, including a failure after only one buffer allocation.
            self.close()
            raise

    def close(self):
        with self._lock:
            self._closed = True
            self._workspace = self._output = None
            self._source_index.clear()
            self._function_sources.clear()

    def _refuse(self, message):
        self._broken = True
        raise HIAProgramRejected('native composite function transport: ' + message, 'E_HIA_TYPE')

    def _type_id(self, typ):
        identifier = self.types._ids.get(id(typ))
        if identifier is None or self.types._types.get(identifier) is not typ:
            self._refuse('descriptor does not belong to the selected native session')
        return identifier

    def _issued_type(self, identifier):
        if type(identifier) is not int or identifier not in self.types._types:
            self._refuse('unissued native descriptor identity')
        return self.types._types[identifier]

    def _frame(self, size):
        if type(size) is not int or size != 64:
            self._refuse('invalid native continuation extent/status ' + str(size))
        frame = struct.unpack_from('<8Q', self._output)
        magic, action, error, phase, serial, slots, request, reserved = frame
        if (magic != ADMIT_MAGIC or reserved or action not in (0, 1, 2, 10, 20, 21, 30)
                or not self._serial <= serial <= 8192 or slots < self._slots
                or request < self._request or request > self._request + 1):
            self._refuse('invalid continuation frame or state correlation')
        if action == 1:
            if error != 999 and error not in ERRORS:
                self._refuse('unrecognized native semantic error')
        elif error:
            self._refuse('semantic error accompanied a success transition')
        self._serial, self._slots = serial, slots
        self.owner.serial, self.owner.value_slots = serial, slots
        return frame

    def _invoke_bytes(self, kernel, wire):
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        size = self.images[kernel]._entry(source, len(wire), self._output,
            OUTPUT_BYTES, self._workspace, WORKSPACE_BYTES)
        if ctypes.string_at(source, len(wire)) != wire:
            self._refuse('native input bytes changed')
        return self._frame(size)

    def _run(self, kernel):
        if self.types._closed or self.types._broken:
            self._refuse('native type dependency is closed or broken')
        size = self.images[kernel]._entry(self.types._state, SESSION_BYTES,
            self._output, OUTPUT_BYTES, self._workspace, WORKSPACE_BYTES)
        return self._frame(size)

    def _stream(self, expected_action, expected_request):
        decoder = ObjectTokenDecoder(self._source_index)
        sequence = 0
        while not decoder.complete:
            size = self.images['render']._entry(self.types._state, SESSION_BYTES,
                self._output, OUTPUT_BYTES, self._workspace, WORKSPACE_BYTES)
            if type(size) is not int or not 64 <= size <= OUTPUT_BYTES:
                self._refuse('invalid native stream extent/status ' + str(size))
            magic, action, actual_sequence, final, serial, slots, request, payload = struct.unpack_from('<8Q', self._output)
            if (magic != MAGIC or action != expected_action or actual_sequence != sequence
                    or final not in (0, 1) or serial != self._serial or slots != self._slots
                    or request != expected_request or payload != size - 64):
                self._refuse('stream chunk changed its request or state identity')
            try:
                decoder.feed(ctypes.string_at(ctypes.addressof(self._output) + 64, payload), final=bool(final))
            except TokenProtocolError as exc:
                self._refuse('malformed native object stream: ' + str(exc))
            sequence += 1
        return decoder.root

    def _service(self, command, request, kernel):
        if (type(command) is not list or not command or type(command[0]) is not int
                or command[0] not in (2, 3, 4, 5, 6)):
            self._refuse('unknown typed native service request')
        kind = command[0]
        error = 0
        ids = []
        final_serial = 0
        helper_name = b''
        try:
            if kind == 2:
                if len(command) != 2:
                    self._refuse('bad native parameter request arity')
                values = self.types.parameters(command[1])
                ids = [self._type_id(typ) for _, typ in values]
            elif kind == 3:
                if len(command) != 2:
                    self._refuse('bad native resolution request arity')
                ids = [self._type_id(self.types.resolve(command[1]))]
            elif kind == 4:
                if len(command) != 3 or type(command[2]) is not list:
                    self._refuse('bad native partial-type request shape')
                ids = [self._type_id(self.types.partial_record(self._issued_type(command[1]), command[2]))]
            elif kind == 5:
                if len(command) != 2:
                    self._refuse('bad native task-protocol request arity')
                ids = [self._type_id(self.types.check_task(self._issued_type(command[1]), self.owner.signatures))]
            else:
                if len(command) != 7:
                    self._refuse('bad native helper request arity')
                result = self.helpers.generate(self._issued_type(command[1]), self._issued_type(command[2]),
                    command[3], command[4], command[5], command[6])
                error, final_serial = result.error, result.serial
                helper_name = b'' if result.name is None else result.name.encode('utf-8')
                if error:
                    try:
                        result.admit()
                    except HIAProgramRejected as exc:
                        self._delegate_errors[request] = exc
                else:
                    self._pending_helpers[request] = result.helper
        except HIAProgramRejected as exc:
            if self._broken or self.types._broken or kind == 6:
                self._refuse('native service transport failed: ' + str(exc))
            error = 1
            self._delegate_errors[request] = exc
        if kernel == 'admit':
            if kind != 2:
                self._refuse('admission requested a nonparameter service')
            response = struct.pack('<4Q', ADMIT_RESPONSE_MAGIC, request, error, len(ids))
        else:
            response = struct.pack('<8Q', LOWER_RESPONSE_MAGIC, request, kind, error,
                len(ids), final_serial, len(helper_name), 0)
        response += b''.join(struct.pack('<Q', identifier) for identifier in ids) + helper_name
        return self._invoke_bytes(kernel, response)

    def _mirror_state(self, expected_error):
        wire = struct.pack('<2Q', METADATA_REQUEST_MAGIC, 0)
        source = ctypes.create_string_buffer(wire)
        size = self.images['records']._entry(source, len(wire), self._output,
            OUTPUT_BYTES, self._workspace, WORKSPACE_BYTES)
        if (ctypes.string_at(source, len(wire)) != wire or type(size) is not int
                or not 64 <= size <= OUTPUT_BYTES):
            self._refuse('invalid native final-state frame')
        magic, serial, slots, cache_count, append_count, error, request, reserved = struct.unpack_from('<8Q', self._output)
        if (magic != METADATA_MAGIC or reserved or serial != self._serial or slots != self._slots
                or error != expected_error or request != self._request
                or cache_count > 720 or append_count > 720
                or size != 64 + cache_count * 24 + append_count * 8):
            self._refuse('final-state counts/counters do not match the continuation')
        cache = {}
        previous = 0
        for index in range(cache_count):
            typ, operation, name = struct.unpack_from('<3Q', self._output, 64 + index * 24)
            if operation >= len(OPERATIONS) or not previous < name <= serial:
                self._refuse('invalid native helper-cache entry')
            key = (self._issued_type(typ).key, OPERATIONS[operation])
            if key in cache:
                self._refuse('repeated native helper-cache identity')
            cache[key] = 'h2internal_' + str(name)
            previous = name
        handles = [struct.unpack_from('<Q', self._output, 64 + cache_count * 24 + index * 8)[0]
                   for index in range(append_count)]
        if (len(set(handles)) != len(handles) or set(handles) != set(self._pending_helpers)
                or handles != sorted(handles)):
            self._refuse('unissued or missing successful helper append')
        self.owner.helper_names.clear()
        self.owner.helper_names.update(cache)
        self.owner.helpers.extend(self._pending_helpers[handle] for handle in handles)
        self._pending_helpers.clear()

    def function(self, fn):
        with self._lock, self.types._lock:
            if self._closed or self._broken:
                self._refuse('function session is closed or broken')
            issued = self._function_sources.get(id(fn))
            if issued is None or issued[0] is not fn:
                self._refuse('function is not an admitted document member')
            try:
                same_packet = transport(fn) == issued[1]
            except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
                self._refuse('function representation changed after snapshot: ' + str(exc))
            if not same_packet:
                self._refuse('function representation changed after snapshot')
            # The native NEXT command performs the function lookup. The bridge
            # only transports the already admitted caller-selected name.
            try:
                name = fn['name'].encode('utf-8')
            except (TypeError, KeyError, AttributeError, UnicodeError) as exc:
                self._refuse('invalid selected function name: ' + str(exc))
            frame = self._invoke_bytes('admit', struct.pack('<2Q', NEXT_MAGIC, len(name)) + name)
            if frame[1] != 0:
                self._refuse('native NEXT did not enter its original first pass')
            self._active_kernel = 'admit'
            while True:
                frame = self._run(self._active_kernel)
                action, error, phase, request = frame[1], frame[2], frame[3], frame[6]
                if action == 1:
                    self._mirror_state(error)
                    if error == 999:
                        exception = self._delegate_errors.pop(request, None)
                        if exception is None:
                            self._refuse('unissued delegated semantic refusal')
                        raise exception
                    code, message = ERRORS[error]
                    raise HIAProgramRejected(message, code)
                if action == 10:
                    self._active_kernel = 'records'
                    continue
                if action == 20:
                    self._active_kernel = 'terms'
                    continue
                if action == 21:
                    self._active_kernel = 'records'
                    continue
                if action == 30:
                    self._active_kernel = 'advanced'
                    continue
                if action != 2:
                    self._refuse('unexpected native state transition')
                if phase == 2000:
                    result = self._stream(0, request)
                    self._mirror_state(0)
                    if (type(result) is not dict or not {'name', 'params', 'returns', 'effects', 'entry', 'blocks'}.issubset(result)
                            or set(result) - {'name', 'params', 'returns', 'effects', 'entry', 'blocks', 'return_loans'}):
                        self._refuse('native stream is not a complete Core function envelope')
                    return result
                if request != self._request + 1:
                    self._refuse('native service request was replayed or skipped')
                self._request = request
                # Stream action is the fixed service kind, emitted by HIA.
                # Read its frame before decoding; _service checks the full
                # typed request again and correlates the native response.
                kind = 2
                if self._active_kernel != 'admit':
                    # Pending service kind is carried by the first stream
                    # header, not inferred from source syntax or operation.
                    kind = self._peek_stream_action()
                command = self._stream(kind, request)
                if type(command) is not list or not command or command[0] != kind:
                    self._refuse('native command and stream kinds disagree')
                response = self._service(command, request, self._active_kernel)
                if response[1] == 1:
                    self._mirror_state(response[2])
                    exception = self._delegate_errors.pop(request, None)
                    if response[2] != 999 or exception is None:
                        self._refuse('invalid completed delegated refusal')
                    raise exception

    def _peek_stream_action(self):
        # This word is fixed transport metadata issued by service_request(),
        # not a source lookup or semantic computation. The renderer rebinds it
        # in every checked chunk. The state buffer is never returned to callers.
        return struct.unpack_from('<Q', self._workspace, 4096 + 64)[0]


def installed_composite_functions(path):
    path = Path(path)
    raw = path.read_bytes()
    if len(raw) > 65536:
        raise ValueError('function bundle manifest exceeds fixed framing')
    value = json.loads(raw, object_pairs_hook=_pairs)
    if (type(value) is not dict or set(value) != {'schema', 'kernels', 'types_source_sha256', 'helpers_source_sha256'}
            or value['schema'] != SCHEMA or type(value['kernels']) is not dict
            or set(value['kernels']) != set(KERNELS)):
        raise ValueError('invalid complete function bundle manifest')
    for key in ('types_source_sha256', 'helpers_source_sha256'):
        text = value[key]
        if type(text) is not str or len(text) != 64 or any(ch not in '0123456789abcdef' for ch in text):
            raise ValueError('invalid function dependency source identity')
    images = {}
    for name in KERNELS:
        manifest = value['kernels'][name]
        if type(manifest) is not str:
            raise ValueError('invalid function kernel manifest path')
        images[name] = _installed_json_image(str(path.parent / manifest), SOURCES[name],
            'hepta.hia.composite-function-' + name + '-native.v1', NativeHiaJsonImage)
    return NativeCompositeFunctions(images, types_source_sha256=value['types_source_sha256'],
        helpers_source_sha256=value['helpers_source_sha256'])


def selected_composite_functions():
    path = os.environ.get(SELECTOR)
    if not path:
        return None
    try:
        return installed_composite_functions(path)
    except (ValueError, OSError, UnicodeError, RuntimeError) as exc:
        raise HIAProgramRejected('selected native composite functions refused: ' + str(exc), 'E_HIA_TYPE') from exc
