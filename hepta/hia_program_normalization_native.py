"""Fixed transport for the explicit HIA normalization development candidate.

The HIA coordinator owns request order, snapshot/structure decisions, encoding
and final materialization. Its required code dependencies are the raw JSON
front and the two binary64 kernels. CPython object and diagnostic mechanisms
remain explicit hosted dependencies. Physical-recursion compatibility and
whole public-domain equivalence are not established by this selection.
"""
from __future__ import annotations

import ctypes
import _json
from functools import lru_cache
from hashlib import sha256
import json
import mmap
import os
from pathlib import Path
import secrets
import struct
import sys

from .hia_core_json_bytes_native import NativeCoreJSONBytes
from .hia_agent_binary64_native import NativeAgentBinary64
from .hia_agent_binary64_format_native import NativeAgentBinary64Format
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path
from .hia_program import HIAProgramRejected
from .hia_program_normalization_notes import (
    NativeCPythonNotes, API_NAMES as NOTE_API_NAMES, require_supported_interpreter,
)



# These are fixed CPython object-representation primitives, used at native-
# selected positions. They bypass foreign __class__, metaclass comparison,
# __len__/__getitem__ overrides exactly where the original C encoder does.
_type_subtype = ctypes.PYFUNCTYPE(ctypes.c_int, ctypes.py_object, ctypes.py_object)(
    ('PyType_IsSubtype', ctypes.pythonapi))
_sequence_fast = ctypes.PYFUNCTYPE(ctypes.py_object, ctypes.py_object, ctypes.c_char_p)(
    ('PySequence_Fast', ctypes.pythonapi))
_mapping_items = ctypes.PYFUNCTYPE(ctypes.py_object, ctypes.py_object)(
    ('PyMapping_Items', ctypes.pythonapi))

SELECTOR = 'HEPTA_HIA_PROGRAM_NORMALIZATION_MANIFEST'
SCHEMA = 'hepta.hia.program-normalization-native.v4-development-permanent'
NOTE_SCHEMA = 'hepta.hosted.cpython-note-hia-packer.v1'
NOTE_PACKER_SOURCE = 'examples/hia_bootstrap/cpython_note_packer.hiaasm'
NOTE_SOURCES = {
    name: _source_resource_path(name) for name in (
        NOTE_PACKER_SOURCE,
        'hepta/hia_program_normalization_notes.py',
    )
}
SOURCES = {
    'normalization': _source_resource_path('examples/hia_bootstrap/program_normalization.hiaasm'),
    'front': _source_resource_path('examples/hia_bootstrap/core_json_bytes.hiaasm'),
    'binary64': _source_resource_path('examples/hia_bootstrap/agent_binary64.hiaasm'),
    'binary64_format': _source_resource_path('examples/hia_bootstrap/agent_binary64_format.hiaasm'),
}
MAX_BYTES, MAX_NODES, WORKSPACE_BYTES = 8 << 20, 262144, 128 << 20
POOL_BASE = 4096 + (MAX_NODES * 2 + 65) * 128
INPUT_MAGIC = int.from_bytes(b'HIANORQ2', 'little')
OUTPUT_MAGIC = int.from_bytes(b'HIANORP2', 'little')
_DEAD_HANDLE = object()
FRAME = struct.Struct('<8Q')
PACKET = struct.Struct('<16Q')
ERRORS = {
    1: ('program exceeds byte budget', 'E_HIA_LIMIT'),
    3: ('invalid/deep UTF-8 JSON', 'E_HIA_FORMAT'),
    4: ('caller-owned tree exceeds snapshot budget', 'E_HIA_LIMIT'),
    5: ('cyclic caller-owned HIA tree', 'E_HIA_FORMAT'),
    6: ('caller-owned tree exceeds queued-node budget', 'E_HIA_LIMIT'),
    7: ('non-string caller-owned JSON key', 'E_HIA_FORMAT'),
    8: ('caller-owned dictionary grew past node budget', 'E_HIA_LIMIT'),
    9: ('caller-owned list grew past node budget', 'E_HIA_LIMIT'),
    10: ('caller-owned tree mutated during bounded snapshot', 'E_HIA_FORMAT'),
    11: ('unsupported caller-owned JSON node', 'E_HIA_FORMAT'),
    12: ('program exceeds structural budget', 'E_HIA_LIMIT'),
    13: ('program exceeds queued-node budget', 'E_HIA_LIMIT'),
    14: ('non-string JSON key', 'E_HIA_FORMAT'),
    19: ('cyclic HIA JSON structure', 'E_HIA_FORMAT'),
    15: ('integer exceeds JSON byte budget', 'E_HIA_LIMIT'),
    16: ('only bounded integer JSON values are supported', 'E_HIA_FORMAT'),
    17: ('unpaired Unicode surrogate', 'E_HIA_FORMAT'),
    18: ('program exceeds byte budget before encoding', 'E_HIA_LIMIT'),
}


class NormalizationProtocolError(RuntimeError):
    """A fixed native request, response or retained-custody invariant failed."""


class _UnsupportedKeyErrorProbe(dict):
    """Fixed one-key C diagnostic input, never the caller's business graph."""
    __slots__ = ('key',)

    def __init__(self, key):
        # Keep the physical dict nonempty without hashing the foreign key.
        dict.__init__(self, {'_': None})
        self.key = key

    def items(self):
        return [(self.key, None)]


class _MalformedItemErrorProbe(dict):
    """One native-proved malformed pair, without another caller items call."""
    __slots__ = ('item',)

    def __init__(self, item):
        dict.__init__(self, {'_': None})
        self.item = item

    def items(self):
        return [self.item]


class NativeProgramNormalization:
    """Four held HIA mappings and one HIA-produced hosted diagnostic ABI.

    The runtime CPython mechanism does not establish whole normalization or
    physical-recursion compatibility. The old packet codec remains independent.
    """

    def __init__(self, images, *, notes=None):
        require_supported_interpreter()
        if type(images) is not dict or set(images) != set(SOURCES):
            raise NormalizationProtocolError('complete normalization requires every declared image')
        if not isinstance(images['normalization'], NativeHiaJsonImage):
            raise NormalizationProtocolError('normalization coordinator is not an admitted image')
        if not isinstance(images['front'], NativeCoreJSONBytes):
            raise NormalizationProtocolError('normalization byte dependencies differ')
        if not isinstance(images['binary64'], NativeAgentBinary64) or not isinstance(images['binary64_format'], NativeAgentBinary64Format):
            raise NormalizationProtocolError('normalization binary64 dependencies differ')
        if not isinstance(notes, NativeCPythonNotes) or notes.closed:
            raise NormalizationProtocolError('current interpreter requires an admitted hosted note mechanism')
        self.images = dict(images)
        self.notes = notes

    def normalize_program(self, value):
        from .hia_program import VerifiedProgram
        # Preserve this property access outside the public exception wrapper.
        if isinstance(value, VerifiedProgram):
            value = value.canonical_bytes
        try:
            context = NormalizationContext(self, value)
            # The coordinator now owns the original argument reference. In
            # the reference entry STORE_FAST replaces it after snapshot; an
            # extra forwarding-frame reference would delay its destructor.
            del value
            try:
                result = context.run()
            except BaseException:
                context._close_preserving_error()
                raise
            context.close()
            return result
        except HIAProgramRejected:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as error:
            raise HIAProgramRejected('invalid/deep UTF-8 JSON', 'E_HIA_FORMAT') from error


class NormalizationContext:
    """One native continuation; a consumed foreign observation never retries."""

    def __init__(self, owner, value):
        self.owner = owner
        self._images = dict(owner.images)
        self._notes = owner.notes
        self.digits = sys.get_int_max_str_digits()
        self.closed = False
        self.workspace = self.output = None
        self._created_arena = self._previous_arena = None
        self.cleanup_error = None
        self._issued = self._awaiting = self._reply = None
        self._sequence = 0
        self._pool, self._ids = [], {}
        self._scope_stack, self._scope_handles = [0], {0: []}
        self._handle_scopes, self._scope_sequence = {}, 0
        self._slots, self._pin_counts, self._permanent = {}, {}, set()
        self._note_slots = {}
        self._failed = False
        self._nonce = struct.unpack('<2Q', secrets.token_bytes(16))
        self._iteration_error = None
        try:
            root = self._handle(value)
            self.workspace = mmap.mmap(-1, WORKSPACE_BYTES, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
            self.output = mmap.mmap(-1, MAX_BYTES + FRAME.size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
            self._issued = self._enter(0, None, (0, root, self.digits, int(self._notes is not None), b'', None))
        except BaseException:
            self._failed = True
            self._close_preserving_error()
            raise

    def close(self):
        self.closed = True
        self._issued = self._awaiting = self._reply = None
        first_error = None
        for name in ('_created_arena', '_previous_arena', 'output', 'workspace'):
            arena = getattr(self, name)
            if arena is not None:
                try:
                    arena.close()
                    setattr(self, name, None)
                except BaseException as error:
                    if first_error is None:
                        first_error = error
        if not self._failed:
            self._slots, self._pin_counts, self._note_slots = {}, {}, {}
            self._pool, self._ids = [], {}
        self.cleanup_error = first_error
        if first_error is not None:
            raise first_error

    def _close_preserving_error(self):
        try:
            self.close()
        except BaseException:
            # Physical storage that failed to close remains rooted on this
            # permanently revoked context. Preserve the original exception.
            pass

    def _handle(self, value, *, scope=None, own=True):
        if self.closed:
            raise NormalizationProtocolError('closed normalization cannot accept foreign custody')
        identity = id(value)
        handle = self._ids.get(identity)
        if scope is None:
            scope = self._scope_stack[-1]
        if handle is None:
            self._pool.append(value)
            handle = len(self._pool)
            self._ids[identity] = handle
            self._handle_scopes[handle] = None
            if own:
                self._scope_handles[scope].append(handle)
                self._handle_scopes[handle] = scope
        elif self._pool[handle - 1] is not value:
            raise NormalizationProtocolError('foreign handle identity changed')
        elif own and self._handle_scopes[handle] is None:
            self._scope_handles[scope].append(handle)
            self._handle_scopes[handle] = scope
        elif own and scope == 0 and self._handle_scopes[handle] != 0:
            previous = self._handle_scopes[handle]
            self._scope_handles[previous].remove(handle)
            self._scope_handles[0].append(handle)
            self._handle_scopes[handle] = 0
        return handle

    def _discard_unowned(self, handle):
        if self._handle_scopes[handle] is not None or self._pin_counts.get(handle, 0):
            return
        value = self._pool[handle - 1]
        self._pool[handle - 1] = _DEAD_HANDLE
        if self._ids.pop(id(value)) != handle:
            raise NormalizationProtocolError('native temporary identity registry differs')
        del self._handle_scopes[handle]
        del value

    def _pin(self, slot, handle):
        if type(slot) is not int or not (1 <= slot <= 9 or 16 <= slot <= 80):
            raise NormalizationProtocolError('native reference slot differs')
        if handle:
            self._value(handle)
            self._pin_counts[handle] = self._pin_counts.get(handle, 0) + 1
        previous = self._slots.pop(slot, 0)
        if handle:
            self._slots[slot] = handle
        if previous:
            self._pin_counts[previous] -= 1
            self._discard_unowned(previous)

    def _pin_value(self, slot, value):
        handle = self._handle(value, own=False)
        self._pin(slot, handle)
        return handle

    def _release_owner(self, handle, scope):
        self._value(handle)
        actual = self._handle_scopes[handle]
        if actual != scope:
            # An iterator can return itself or another already-held ancestor.
            # Dropping this borrow must not discard that owner's reference.
            if actual is not None and actual not in self._scope_stack:
                raise NormalizationProtocolError('native borrow has no retained scope')
            return
        self._scope_handles[scope].remove(handle)
        self._handle_scopes[handle] = None
        self._discard_unowned(handle)

    def _value(self, handle):
        if type(handle) is not int or not 1 <= handle <= len(self._pool):
            raise NormalizationProtocolError('native request names an absent foreign handle')
        value = self._pool[handle - 1]
        if value is _DEAD_HANDLE:
            raise NormalizationProtocolError('native request names an expired foreign handle')
        return value

    def _release_scope(self, scope, parent):
        if scope in self._note_slots:
            raise NormalizationProtocolError('native parent capture still has a note-key pin')
        if len(self._scope_stack) < 2 or self._scope_stack[-2:] != [parent, scope]:
            raise NormalizationProtocolError('native temporary scope release differs')
        handles = self._scope_handles.pop(scope)
        self._scope_stack.pop()
        # Drop transient borrowed values before their original owning capture.
        # Actual Python object destruction occurs here, at the HIA-issued C
        # encoder scope boundary, before its next sibling or final boxing.
        for handle in reversed(handles):
            if self._pool[handle - 1] is _DEAD_HANDLE or self._handle_scopes[handle] != scope:
                raise NormalizationProtocolError('native temporary handle custody differs')
            self._handle_scopes[handle] = None
            self._discard_unowned(handle)

    @staticmethod
    def _kind(value, kind=None):
        # Identity facts never hash or compare a foreign metaclass. Rich
        # membership is a separate, explicitly native-issued observation.
        if kind is None:
            kind = type(value)
        if value is None:
            return 0
        if kind is bool:
            return 2 if value else 1
        for expected, number in ((int, 3), (str, 4), (list, 5), (dict, 6), (bytes, 7)):
            if kind is expected:
                return number
        return 8

    def _enter(self, event, frame, reply):
        if self.closed or self.workspace is None or self.output is None:
            raise NormalizationProtocolError('normalization context is closed')
        status, a, b, c, payload, cause = reply
        if type(payload) is not bytes:
            raise NormalizationProtocolError('foreign reply payload is not exact bytes')
        sequence, action = (0, 0) if frame is None else (frame[1], frame[2])
        raw = PACKET.pack(INPUT_MAGIC, event, *self._nonce, sequence, action,
                          status, a, b, c, len(payload), 0, 0, 0, 0, 0) + payload
        source = ctypes.create_string_buffer(raw, len(raw))
        output_address = ctypes.addressof(ctypes.c_char.from_buffer(self.output))
        workspace_address = ctypes.addressof(ctypes.c_char.from_buffer(self.workspace))
        returned = self._images['normalization']._entry(source, len(raw), output_address,
            len(self.output), workspace_address, len(self.workspace))
        if type(returned) is not int or not FRAME.size <= returned <= len(self.output):
            raise NormalizationProtocolError('native normalization refused its protocol or extent')
        if source.raw != raw:
            raise NormalizationProtocolError('native normalization changed the foreign input')
        result = FRAME.unpack_from(self.output)
        magic, current, request, error, handle, x, y, size = result
        if (magic != OUTPUT_MAGIC or returned != FRAME.size + size or request not in (*range(12), 17, 18, *range(20, 27), *range(28, 36), 37, 38, *range(40, 46), *range(50, 58), *range(60, 68))
                or error not in (0, 20, *ERRORS) or size > MAX_BYTES):
            raise NormalizationProtocolError('native normalization fixed response differs')
        if event == 1:
            if result != frame:
                raise NormalizationProtocolError('native launch claim changed its issued observation')
        elif request:
            if current != self._sequence + 1 or error or size:
                raise NormalizationProtocolError('native normalization request sequence differs')
            self._sequence = current
        elif current != self._sequence or (error and (x or y or size)) or (error and error != 20 and handle):
            raise NormalizationProtocolError('native normalization completion differs')
        if error == 20 and not handle:
            raise NormalizationProtocolError('native foreign exception lost its object custody')
        if not request and not error and (not 1 <= x <= (size + 1) // 2 + 1
                or not handle or (y != 0 and y < 640) or size == 0):
            raise NormalizationProtocolError('native normalization success identity differs')
        return result

    def observe(self, frame):
        if self.closed or frame is not self._issued or not frame[2] or self._awaiting is not None:
            self.close()
            raise NormalizationProtocolError('foreign observation was not issued exactly once')
        try:
            self._awaiting = frame
            self._enter(1, frame, (0, 0, 0, 0, b'', None))
            self._issued = None
            try:
                reply = self._foreign(frame)
            except BaseException as error:
                # The native state consumes this known foreign exception and
                # orders scope release. It cannot grant the observation again.
                try:
                    error_handle = self._handle(error, scope=0)
                except BaseException:
                    self._failed = True
                    self._close_preserving_error()
                    raise error
                reply = (3, error_handle, 0, 0, b'', None)
            self._reply = reply
            return reply
        except BaseException:
            self._failed = True
            self._close_preserving_error()
            raise

    def accept(self, frame, reply):
        if self.closed or frame is not self._awaiting or reply is not self._reply:
            self.close()
            raise NormalizationProtocolError('foreign outcome was not the issued observation result')
        try:
            if reply[5] is not None:
                self._iteration_error = reply[5]
            result = self._enter(2, frame, reply)
            self._awaiting = self._reply = None
            self._issued = result
            return result
        except BaseException:
            self._failed = True
            self._close_preserving_error()
            raise

    def _foreign(self, frame):
        action, handle, a, b = frame[2], frame[4], frame[5], frame[6]
        if action == 9:
            wire = self.workspace[POOL_BASE:POOL_BASE + a] if handle == 0 else self._value(handle)
            if type(wire) is not bytes or len(wire) != a or a > MAX_BYTES:
                raise NormalizationProtocolError('native raw request has a different byte input')
            result = self._images['front'].canonicalize_preserving_original_errors(wire, integer_digit_limit=self.digits)
            return (0, result.source_nodes, 0, 0, result.canonical_bytes, None)
        if action == 50:
            if handle or a != self._scope_sequence + 1 or b != self._scope_stack[-1]:
                raise NormalizationProtocolError('native temporary scope admission differs')
            self._scope_handles[a] = []
            self._scope_stack.append(a)
            self._scope_sequence = a
            return (0, a, 0, 0, b'', None)
        if action == 51:
            if handle:
                raise NormalizationProtocolError('native temporary scope request has a payload handle')
            self._release_scope(a, b)
            return (0, b, 0, 0, b'', None)
        if action == 52:
            if a != self._scope_stack[-1] or b:
                raise NormalizationProtocolError('native iterator release scope differs')
            self._release_owner(handle, a)
            return (0, 0, 0, 0, b'', None)
        if action == 53:
            if b:
                raise NormalizationProtocolError('native local reference assignment differs')
            self._pin(a, handle)
            return (0, 0, 0, 0, b'', None)
        if action == 54:
            if a or b:
                raise NormalizationProtocolError('native argument transfer differs')
            if handle not in self._permanent:
                self._release_owner(handle, 0)
            return (0, 0, 0, 0, b'', None)
        if action == 56:
            if a or b:
                raise NormalizationProtocolError('native detached leaf transfer differs')
            self._handle(self._value(handle), scope=0)
            self._permanent.add(handle)
            return (0, 0, 0, 0, b'', None)
        if action == 57:
            if a != self._scope_stack[-1] or b:
                raise NormalizationProtocolError('native active container reference differs')
            self._handle(self._value(handle))
            return (0, 0, 0, 0, b'', None)
        if action == 26:
            if handle or b:
                raise NormalizationProtocolError('native binary64 formatting request differs')
            raw = self._images['binary64_format'].render_bits(struct.pack('<Q', a))
            return (0, 0, 0, 0, raw, None)
        if action == 34:
            return (0, sys.get_int_max_str_digits(), 0, 0, b'', None)
        if action == 37:
            if handle or not len(self.workspace) < a or not 0 <= b <= len(self.workspace):
                raise NormalizationProtocolError('native workspace growth request differs')
            self._created_arena = mmap.mmap(-1, a, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
            if b:
                source = ctypes.addressof(ctypes.c_char.from_buffer(self.workspace))
                target = ctypes.addressof(ctypes.c_char.from_buffer(self._created_arena))
                ctypes.memmove(target, source, b)
                if self._created_arena[:b] != self.workspace[:b]:
                    raise NormalizationProtocolError('native workspace growth changed its retained prefix')
            self._previous_arena = self.workspace
            self.workspace = self._created_arena
            self._created_arena = None
            self._previous_arena.close()
            self._previous_arena = None
            return (0, len(self.workspace), 0, 0, b'', None)
        if action == 61:
            if handle or not len(self.output) < a or not FRAME.size <= b <= len(self.output):
                raise NormalizationProtocolError('native output growth request differs')
            self._created_arena = mmap.mmap(-1, a, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
            source = ctypes.addressof(ctypes.c_char.from_buffer(self.output))
            target = ctypes.addressof(ctypes.c_char.from_buffer(self._created_arena))
            ctypes.memmove(target, source, b)
            if self._created_arena[:b] != self.output[:b]:
                raise NormalizationProtocolError('native output growth changed its retained prefix')
            self._previous_arena = self.output
            self.output = self._created_arena
            self._created_arena = None
            self._previous_arena.close()
            self._previous_arena = None
            return (0, len(self.output), 0, 0, b'', None)
        if action in (63, 64):
            # Both the exception and parent/key are native-issued opaque
            # identities. Call outside observe's child exception handler;
            # key.__repr__ must see the original surrounding handled error.
            # No borrowed foreign object is kept in a Python error local.
            if self._notes is None or not handle:
                raise NormalizationProtocolError('native parent note has no pinned interpreter mechanism')
            if action == 63:
                return (0, self._handle(self._notes.note(self._value(handle), 1,
                    self._value(a) if a else {}, self._value(b), 0), scope=0), 0, 0, b'', None)
            return (0, self._handle(self._notes.note(self._value(handle), 2,
                self._value(a) if a else [], None, b), scope=0), 0, 0, b'', None)
        if action == 65:
            # Pin an existing handle, not another strong object snapshot.
            # Its original parent items capture owns the actual key. This
            # permits the handle to survive its temporary child-scope drop.
            if b or not a or a not in self._scope_stack or a in self._note_slots:
                raise NormalizationProtocolError('native note-key pin differs')
            self._value(handle)
            self._pin_counts[handle] = self._pin_counts.get(handle, 0) + 1
            self._note_slots[a] = handle
            return (0, 0, 0, 0, b'', None)
        if action == 66:
            if b or a != self._scope_stack[-1] or self._note_slots.get(a) != handle:
                raise NormalizationProtocolError('native note-key release differs')
            # Consume before a possible destructor or interrupted ACK. The
            # context is fenced on an unknown handoff; no key is reacquired.
            del self._note_slots[a]
            self._pin_counts[handle] -= 1
            self._discard_unowned(handle)
            return (0, 0, 0, 0, b'', None)
        if action == 67:
            if a or b:
                raise NormalizationProtocolError('native replaced-error release differs')
            self._release_owner(handle, 0)
            return (0, 0, 0, 0, b'', None)
        if action == 62:
            # HIA has already selected the original diagnostic and its exact
            # point in traversal. These fixed probes do not visit a payload
            # child or decide whether an object/key/cycle should be admitted.
            if b or a not in (1, 2, 3, 4) or (a == 1 and handle) or (a != 1 and not handle):
                raise NormalizationProtocolError('native C diagnostic request differs')
            if a == 1:
                probe = [None]
                markers = {id(probe): probe}
                encoder = _json.make_encoder(markers, None, _json.encode_basestring,
                                             None, ':', ',', True, False, False)
                encoder(probe, 0)
            elif a == 2:
                probe = _UnsupportedKeyErrorProbe(self._value(handle))
                try:
                    encoder = _json.make_encoder(None, None, _json.encode_basestring,
                                                 None, ':', ',', True, False, False)
                    encoder(probe, 0)
                finally:
                    # Its traceback can retain the private probe. Remove only
                    # the additional foreign-key borrow before native unwind.
                    probe.key = None
            elif a == 3:
                # HIA proved the current decimal digit refusal, using either
                # its bit bound or its complete native decimal conversion.
                # The original C encoder invokes this exact builtin repr
                # slot, bypassing a foreign int subclass's __repr__ override.
                # Do not retain the scalar in a Python local on its traceback.
                if not _type_subtype(type(self._value(handle)), int):
                    raise NormalizationProtocolError('native integer diagnostic type differs')
                int.__repr__(self._value(handle))
            else:
                # HIA has consumed the physical tuple/size observation of this
                # exact already-captured item. A one-item private C probe
                # recovers the real interpreter exception; it never calls the
                # caller mapping, sorts multiple keys or traverses a child.
                probe = _MalformedItemErrorProbe(self._value(handle))
                try:
                    encoder = _json.make_encoder(None, None, _json.encode_basestring,
                                                 None, ':', ',', True, False, False)
                    encoder(probe, 0)
                finally:
                    probe.item = None
            raise NormalizationProtocolError('native-proved C diagnostic unexpectedly succeeded')
        if action == 60:
            if handle or b or not 0 < a <= len(self.output) - FRAME.size:
                raise NormalizationProtocolError('native UTF-8 error extent differs')
            # HIA emitted the complete Unicode result, including surrogate
            # code points, and proved that strict UTF-8 must fail. Boxing this
            # native byte sequence and invoking the original encoding error
            # primitive preserves the real exception object/positions without
            # traversing or serializing any caller object here.
            value = self.output[FRAME.size:FRAME.size + a].decode('utf-8', 'surrogatepass')
            value.encode('utf-8')
            raise NormalizationProtocolError('native-proved UTF-8 error unexpectedly succeeded')
        if action in (40, 44):
            if handle or not 0 <= a <= len(self.workspace) or b > len(self.workspace) - a:
                raise NormalizationProtocolError('native scalar materialization extent differs')
            raw = self.workspace[a:a + b]
            value = raw.decode('utf-8') if action == 40 else int.from_bytes(raw, 'little', signed=True)
            return (0, self._handle(value), 0, 0, b'', None)
        if action == 41:
            if handle or a not in (5, 6) or b:
                raise NormalizationProtocolError('native container materialization tag differs')
            return (0, self._handle([] if a == 5 else {}), 0, 0, b'', None)
        if action == 43:
            if handle or a not in (0, 1, 2) or b:
                raise NormalizationProtocolError('native constant materialization tag differs')
            return (0, self._handle((None, False, True)[a]), 0, 0, b'', None)
        if action == 45:
            if handle or not 64 <= a <= len(self.output) or b > len(self.output) - a:
                raise NormalizationProtocolError('native floating materialization extent differs')
            bits = self._images['binary64'].bits(self.output[a:a + b])
            return (0, self._handle(struct.unpack('<d', bits)[0]), 0, 0, b'', None)
        if action == 31:
            # A comparison exception may retain this frame. The original C
            # sorter does not add a Python-local reference to its entire
            # temporary items capture, which HIA releases during unwind.
            list.sort(self._value(handle))
            return (0, 0, 0, 0, b'', None)
        if action == 35:
            # No Python local retains the temporary float when the original
            # C diagnostic raises. HIA still owns its exact scope until ACK.
            if a != 1 or b or not _type_subtype(type(self._value(handle)), float):
                raise NormalizationProtocolError('native scalar error request differs')
            # The HIA coordinator has already proved this physical float is
            # nonfinite. Use only the C scalar error primitive here. The
            # Python JSONEncoder.encode wrapper would inspect __class__ via
            # isinstance(value, str) before reaching the original C %R error,
            # adding an observable callback and changing caller exceptions.
            # This is an explicit remaining CPython diagnostic dependency;
            # neither an object graph nor a policy decision is delegated.
            encoder = _json.make_encoder(None, None, _json.encode_basestring,
                                         None, ':', ',', True, False, False)
            encoder(self._value(handle), 0)
            raise NormalizationProtocolError('nonfinite scalar unexpectedly acquired a JSON representation')
        value = self._value(handle)
        if action == 42:
            child = self._value(b)
            if type(value) is list and a == 0:
                value.append(child)
            elif type(value) is dict and type(self._value(a)) is str:
                value[self._value(a)] = child
            else:
                raise NormalizationProtocolError('native materialized parent edge differs')
            return (0, 0, 0, 0, b'', None)
        if action == 22:
            actual = type(value)
            facts = 0
            for position, expected in enumerate((str, int, float, list, tuple, dict)):
                facts |= int(_type_subtype(actual, expected)) << position
            constant = 0 if value is None else 1 if value is False else 2 if value is True else 3
            return (0, facts, constant, 0, b'', None)
        if action == 23:
            if a == 4:
                result = str.__len__(value)
            elif a == 6:
                result = dict.__len__(value)
            elif a == 3:
                result = int.bit_length(value)
            else:
                raise NormalizationProtocolError('native physical representation request differs')
            return (0, result, 0, 0, b'', None)
        if action == 24:
            if not 1 <= b <= 4096 or a > str.__len__(value) or b > str.__len__(value) - a:
                raise NormalizationProtocolError('native physical string chunk differs')
            raw = str.__getitem__(value, slice(a, a + b)).encode('utf-32-le', 'surrogatepass')
            return (0, 0, 0, 0, raw, None)
        if action == 25:
            return (0, struct.unpack('<Q', struct.pack('<d', value))[0], 0, 0, b'', None)
        if action == 28:
            captured = _sequence_fast(value, b'_iterencode_list needs a sequence')
            size = list.__len__(captured) if _type_subtype(type(captured), list) else tuple.__len__(captured)
            return (0, self._handle(captured), size, 0, b'', None)
        if action == 29:
            # One builtin retrieval is atomic under the GIL. Treat its normal
            # end as the C encoder's next physical-size observation, without a
            # Python check/use gap or a subclass __getitem__ callback.
            try:
                child = list.__getitem__(value, a) if _type_subtype(type(value), list) else tuple.__getitem__(value, a)
            except IndexError:
                return (0, 0, 0, 0, b'', None)
            return (1, self._handle(child), 0, 0, b'', None)
        if action == 30:
            return (0, self._handle(_mapping_items(value)), 0, 0, b'', None)
        if action == 32:
            if not _type_subtype(type(value), tuple):
                return (0, 0, 0, (1 << 64) - 1, b'', None)
            size = tuple.__len__(value)
            if size != 2:
                return (0, 0, 0, size, b'', None)
            return (0, self._handle(tuple.__getitem__(value, 0)),
                    self._handle(tuple.__getitem__(value, 1)), 2, b'', None)
        if action == 33:
            # The original fixed foreign error operation. It retains the real
            # __class__/type diagnostic behavior, including caller exceptions.
            json.JSONEncoder.default(None, value)
            raise NormalizationProtocolError('unsupported object unexpectedly acquired a default representation')
        if action == 38:
            if not a or b:
                raise NormalizationProtocolError('native physical integer extent differs')
            return (0, 0, 0, 0, int.to_bytes(value, a, 'little', signed=True), None)
        if action == 1:
            return (0, self._kind(value), 0, 0, b'', None)
        if action == 2:
            return (0, len(value), 0, 0, b'', None)
        if action == 3:
            if a not in (5, 6):
                raise NormalizationProtocolError('native iterator request has a different object kind')
            try:
                iterator = iter(value) if a == 5 else iter(value.items())
            except RuntimeError as error:
                return (2, 0, 0, 0, b'', error)
            return (0, self._handle(iterator), 0, 0, b'', None)
        if action == 4:
            if a not in (5, 6):
                raise NormalizationProtocolError('native iterator result kind differs')
            try:
                if a == 5:
                    child = next(value)
                else:
                    key, child = next(value)
                    self._pin_value(3, key)
                self._pin_value(4, child)
            except StopIteration:
                return (0, 0, 0, 0, b'', None)
            except RuntimeError as error:
                return (2, 0, 0, 0, b'', error)
            if a == 5:
                return (1, self._handle(child), 0, 0, b'', None)
            return (1, self._handle(child), self._handle(key), self._kind(key), b'', None)
        if action in (5, 6):
            if type(value) is not str or not 1 <= b <= 4096 or not a <= len(value) or b > len(value) - a:
                raise NormalizationProtocolError('native string request has a different bounded range')
            raw = value[a:a + b].encode('utf-32-le', 'surrogatepass') if action == 5 else value[a:a + b].encode('utf-8')
            return (0, 0, 0, 0, raw, None)
        if action == 7:
            if type(value) is not int:
                raise NormalizationProtocolError('native integer request has a different object kind')
            return (0, value.bit_length(), 0, 0, b'', None)
        if action == 8:
            if type(value) is not int or not 1 <= a <= MAX_BYTES // 2 + 1:
                raise NormalizationProtocolError('native binary integer request has a different extent')
            return (0, 0, 0, 0, value.to_bytes(a, 'little', signed=True), None)
        if action == 17:
            return (0, self._handle(iter(value)), 0, 0, b'', None)
        if action == 18:
            try:
                key = next(value)
            except StopIteration:
                return (0, 0, 0, 0, b'', None)
            return (1, self._handle(key), self._kind(key), 0, b'', None)
        if action == 20:
            values = value.values() if a == 6 else value
            self._pin_value(8, values)
            captured = []
            captured.extend(values)
            return (0, self._handle(captured), len(captured), 0, b'', None)
        if action == 21:
            if type(value) is not list or b or a != len(value) - 1:
                raise NormalizationProtocolError('native captured-list lookup differs')
            child = value.pop()
            return (0, self._pin_value(6, child), 0, 0, b'', None)
        if action == 10:
            kind = type(value)
            held = 0
            if a in (1, 2):
                held = self._pin_value(2 if a == 1 else 7, kind)
            elif a != 0:
                raise NormalizationProtocolError('native type-observation slot differs')
            member = kind in (dict, list)
            return (0, int(member), held, self._kind(value, kind), b'', None)
        if action == 11:
            # The handle is the exact type retained before the previous rich
            # comparison, not a second type(value) lookup.
            return (0, int(not (value not in (str, int, bool))), 0, 0, b'', None)
        raise NormalizationProtocolError('native normalization issued an unknown observation')

    def run(self):
        try:
            frame = self._issued
            while frame[2]:
                reply = self.observe(frame)
                frame = self.accept(frame, reply)
            if frame[3] == 20:
                terminal_error = self._value(frame[4])
                try:
                    if not isinstance(terminal_error, BaseException):
                        raise NormalizationProtocolError('native foreign error handle is not an exception')
                    # Only the HIA-confirmed delivered exception loses the
                    # transport's extra owner reference. Original local slots,
                    # pinned arguments and unrelated retained values remain
                    # live with this traceback, as they do in the public
                    # reference frame. A failed/unknown native transition
                    # never reaches this terminal handoff.
                    self._release_owner(frame[4], 0)
                    if self._notes is not None:
                        self._notes.deliver(terminal_error)
                    raise terminal_error
                finally:
                    # An exception retaining this frame must not retain a
                    # second reference to itself through a Python local.
                    terminal_error = None
            if frame[3]:
                message, code = ERRORS[frame[3]]
                if frame[3] == 10:
                    terminal_cause = self._iteration_error
                    try:
                        if not isinstance(terminal_cause, RuntimeError):
                            raise NormalizationProtocolError('snapshot mutation lacks its original exception')
                        self._iteration_error = None
                        raise HIAProgramRejected(message, code) from terminal_cause
                    finally:
                        terminal_cause = None
                raise HIAProgramRejected(message, code)
            return self._value(frame[4]), self.output[FRAME.size:FRAME.size + frame[7]]
        except BaseException:
            self._failed = True
            self._close_preserving_error()
            raise


def _pairs(values):
    result = {}
    for name, value in values:
        if name in result:
            raise ValueError('duplicate normalization manifest field')
        result[name] = value
    return result


def _admit_cold_note_production(receipt, source, packer, note_image, consumed):
    """Check fixed production receipts; this is not a new cold qualification.

    The strict builder already admits a complete matching-source cold report.
    Installed use rebinds actual current component/source/image bytes and both
    native receipts. It imports no authoring module and cannot activate a route.
    """
    required = {
        'schema', 'status', 'scope', 'profile', 'source_manifest',
        'compiler_sha256', 'cold_report_sha256', 'source_sha256',
        'packer_image_sha256', 'image_sha256', 'native_compilation',
        'native_emission', 'production_c_compiler_used',
        'physical_recursion_qualified', 'whole_stack_rewritten_in_hia',
    }
    def digest_text(value):
        return (type(value) is str and len(value) == 64
                and all(c in '0123456789abcdef' for c in value))
    if (type(receipt) is not dict or set(receipt) != required
            or receipt['schema'] != 'hepta.hia.cpython-note-packer-production.v2'
            or receipt['status'] != 'NATIVE_HIA_PACKER_EMITTED'
            or receipt['scope'] != 'MATCHING_SOURCE_COLD'
            or type(receipt['profile']) is not str or not receipt['profile']
            or type(receipt['source_manifest']) is not dict
            or not receipt['source_manifest']
            or not digest_text(receipt['compiler_sha256'])
            or not digest_text(receipt['cold_report_sha256'])
            or receipt['source_sha256'] != sha256(source).hexdigest()
            or receipt['packer_image_sha256'] != sha256(packer).hexdigest()
            or receipt['image_sha256'] != sha256(note_image).hexdigest()
            or receipt['production_c_compiler_used'] is not False
            or receipt['physical_recursion_qualified'] is not False
            or receipt['whole_stack_rewritten_in_hia'] is not False
            or len(note_image) != 298
            or sha256(note_image).hexdigest() !=
                'd1ed5ac60b3d84952157262d6ea4252cbe4346c38417281945af636f5deacf23'):
        raise ValueError('matching-source HIA note production receipt differs')
    contract_name = 'docs/HIA_SELFHOST_CORE_SUPPORT.json'
    contract_path = _source_resource_path(contract_name)
    contract_bytes = contract_path.read_bytes()
    contract = json.loads(contract_bytes, object_pairs_hook=_pairs)
    identity = contract.get('source_identity') if type(contract) is dict else None
    if (type(identity) is not dict or type(identity.get('files')) is not dict
            or contract.get('profile') != receipt['profile']
            or receipt['source_manifest'] != {**identity['files'], contract_name: sha256(contract_bytes).hexdigest()}):
        raise ValueError('HIA note production does not match the installed complete source contract')
    consumed.append((contract_path, contract_bytes))
    for name, digest in receipt['source_manifest'].items():
        if (type(name) is not str or not name or Path(name).is_absolute()
                or '..' in Path(name).parts or not digest_text(digest)):
            raise ValueError('HIA note production source identity differs')
    for path in {*SOURCES.values(), *NOTE_SOURCES.values()}:
        raw = path.read_bytes()
        # Resource paths are source-owned in a checkout and _data-owned after
        # installation. Use the declared stable repository name, never cwd.
        name = next((n for n, p in NOTE_SOURCES.items() if p == path), None)
        if name is None:
            name = next('examples/hia_bootstrap/' + p.name
                        for p in SOURCES.values() if p == path)
        if receipt['source_manifest'].get(name) != sha256(raw).hexdigest():
            raise ValueError('HIA note production is not bound to current owner sources')
        consumed.append((path, raw))
    compilation = receipt['native_compilation']
    numeric = {'input_bytes': len(source), 'produced_bytes': len(packer),
               'result_u64': len(packer), 'core_u32': len(packer), 'abi_status': 0}
    if (type(compilation) is not dict or not packer
            or compilation.get('status') != 'returned'
            or compilation.get('format') != 'flat-x86-64'
            or compilation.get('return_encoding') != 'zero-extended-u32'
            or compilation.get('source_unchanged') is not True
            or compilation.get('source_sha256') != receipt['source_sha256']
            or compilation.get('input_sha256') != receipt['source_sha256']
            or compilation.get('artifact_sha256') != receipt['compiler_sha256']
            or compilation.get('image_sha256') != receipt['compiler_sha256']
            or compilation.get('produced_sha256') != receipt['packer_image_sha256']
            or type(compilation.get('forbidden_compiler_modules_loaded')) is not list
            or compilation['forbidden_compiler_modules_loaded'] != []
            or any(type(compilation.get(k)) is not int or compilation[k] != v
                   for k, v in numeric.items())):
        raise ValueError('HIA note production compiler receipt differs')
    emission = receipt['native_emission']
    numeric = {'input_bytes': 0, 'result_u64': len(note_image),
               'core_u32': len(note_image), 'abi_status': 0}
    if (type(emission) is not dict
            or emission.get('status') != 'returned'
            or emission.get('format') != 'flat-x86-64'
            or emission.get('return_encoding') != 'zero-extended-u32'
            or emission.get('source_unchanged') is not True
            or emission.get('source_sha256') != sha256(b'').hexdigest()
            or emission.get('input_sha256') != sha256(b'').hexdigest()
            or emission.get('artifact_sha256') != receipt['packer_image_sha256']
            or emission.get('image_sha256') != receipt['packer_image_sha256']
            or emission.get('output_sha256') != receipt['image_sha256']
            or type(emission.get('forbidden_compiler_modules_loaded')) is not list
            or emission['forbidden_compiler_modules_loaded'] != []
            or any(type(emission.get(k)) is not int or emission[k] != v
                   for k, v in numeric.items())):
        raise ValueError('HIA note production emission receipt differs')


def _admit_note_production(path, declaration, note_image, consumed):
    """Bind the held bytes to an actual HIA packer development receipt.

    This remains development admission, not current-source cold proof. The
    independent C/assembler references are not runtime production inputs.
    Every receipt and packer byte is read afresh and included in final readback.
    """
    if (type(declaration) is not dict
            or set(declaration) != {'receipt_path', 'receipt_sha256',
                                    'packer_image_path', 'packer_image_sha256'}):
        raise ValueError('hosted note HIA production declaration differs')
    values = {}
    for key, digest_key in (('receipt_path', 'receipt_sha256'),
                            ('packer_image_path', 'packer_image_sha256')):
        filename = declaration[key]
        if type(filename) is not str or not filename or Path(filename).name != filename:
            raise ValueError('hosted note production input must be a sibling basename')
        input_path = path.parent / filename
        data = input_path.read_bytes()
        if sha256(data).hexdigest() != declaration[digest_key]:
            raise ValueError('hosted note production input changed')
        consumed.append((input_path, data))
        values[key] = data
    receipt = json.loads(values['receipt_path'], object_pairs_hook=_pairs)
    if type(receipt) is dict and receipt.get('schema') == 'hepta.hia.cpython-note-packer-production.v2':
        source = NOTE_SOURCES[NOTE_PACKER_SOURCE].read_bytes()
        consumed.append((NOTE_SOURCES[NOTE_PACKER_SOURCE], source))
        _admit_cold_note_production(receipt, source, values['packer_image_path'], note_image, consumed)
        return
    if (type(receipt) is not dict
            or receipt.get('schema') != 'hepta.hia.cpython-note-packer.native-development.v1'
            or receipt.get('status') != 'PASS_HIA_PACKER_EMISSION_ONLY'
            or receipt.get('scope') != 'PREDECESSOR_COMPILER_DEVELOPMENT_HIA_PACKER_EMISSION'
            or receipt.get('production_c_compiler_used') is not False
            or receipt.get('current_source_cold_qualification') is not False
            or receipt.get('source_clean_before') is not True
            or receipt.get('source_clean_after') is not True
            or type(receipt.get('failures')) is not list or receipt['failures']):
        raise ValueError('hosted note HIA production receipt was not admitted')
    source = NOTE_SOURCES[NOTE_PACKER_SOURCE].read_bytes()
    # The production source was read above and is checked again at the end.
    # Record this second exact byte observation rather than trusting a path.
    consumed.append((NOTE_SOURCES[NOTE_PACKER_SOURCE], source))
    packer = values['packer_image_path']

    def same_snapshot(name, content=None):
        before, after = receipt.get(name + '_before'), receipt.get(name + '_after')
        if (type(before) is not dict or type(after) is not dict or before != after
                or set(before) != {'bytes', 'path', 'sha256'}
                or type(before['bytes']) is not int or before['bytes'] <= 0
                or type(before['path']) is not str or not before['path']
                or type(before['sha256']) is not str or len(before['sha256']) != 64
                or any(c not in '0123456789abcdef' for c in before['sha256'])):
            raise ValueError('hosted note HIA production input snapshot differs')
        if content is not None and (before['bytes'] != len(content)
                or before['sha256'] != sha256(content).hexdigest()):
            raise ValueError('hosted note HIA production snapshot is not these bytes')
        return before

    compiler_identity = same_snapshot('compiler')
    source_identity = same_snapshot('packer_source', source)
    packer_identity = same_snapshot('native_packer', packer)
    same_snapshot('expected', note_image)
    produced = receipt.get('produced_image')
    if (type(produced) is not dict or set(produced) != {'bytes', 'path', 'sha256'}
            or type(produced['bytes']) is not int or produced['bytes'] != len(note_image)
            or type(produced['path']) is not str or not produced['path']
            or produced['sha256'] != sha256(note_image).hexdigest()):
        raise ValueError('hosted note production receipt names another emitted image')
    compilation = receipt.get('native_compilation')
    if (type(compilation) is not dict or compilation.get('status') != 'returned'
            or compilation.get('format') != 'flat-x86-64'
            or compilation.get('return_encoding') != 'zero-extended-u32'
            or compilation.get('source_unchanged') is not True
            or compilation.get('source_sha256') != source_identity['sha256']
            or compilation.get('input_sha256') != source_identity['sha256']
            or compilation.get('artifact_sha256') != compiler_identity['sha256']
            or compilation.get('image_sha256') != compiler_identity['sha256']
            or compilation.get('produced_sha256') != packer_identity['sha256']
            or any(type(compilation.get(key)) is not int
                   or compilation[key] != packer_identity['bytes']
                   for key in ('result_u64', 'core_u32', 'produced_bytes'))
            or type(compilation.get('abi_status')) is not int
            or compilation['abi_status'] != 0):
        raise ValueError('hosted note HIA packer compile receipt differs')
    observations = receipt.get('observations')
    if (type(observations) is not list or len(observations) != 6
            or any(type(row) is not dict or row.get('passed') is not True
                   or row.get('every_byte_equal') is not True for row in observations)):
        raise ValueError('hosted note HIA packer emission controls are incomplete')
    names = [row.get('case') for row in observations]
    if any(type(name) is not str for name in names) or set(names) != {
            'exact', 'short', 'nonempty', 'precedence', 'zero-output', 'tail'}:
        raise ValueError('hosted note HIA packer emission cases differ')
    exact = observations[names.index('exact')]
    actual = exact.get('actual')
    if (type(actual) is not dict or actual.get('status') != 'returned'
            or actual.get('format') != 'flat-x86-64'
            or actual.get('return_encoding') != 'zero-extended-u32'
            or actual.get('source_unchanged') is not True
            or actual.get('artifact_sha256') != packer_identity['sha256']
            or actual.get('image_sha256') != packer_identity['sha256']
            or actual.get('source_sha256') != sha256(b'').hexdigest()
            or actual.get('input_sha256') != sha256(b'').hexdigest()
            or actual.get('output_sha256') != produced['sha256']
            or any(type(actual.get(key)) is not int or actual[key] != len(note_image)
                   for key in ('result_u64', 'core_u32'))
            or type(actual.get('abi_status')) is not int or actual['abi_status'] != 0
            or type(actual.get('input_bytes')) is not int or actual['input_bytes'] != 0
            or type(exact.get('actual_bytes')) is not int or exact['actual_bytes'] != len(note_image)
            or exact.get('actual_sha256') != produced['sha256']):
        raise ValueError('hosted note HIA packer did not emit this complete image')


@lru_cache(maxsize=8)
def _mapped(images, note_image, note_digest, interpreter):
    classes = {'normalization': NativeHiaJsonImage, 'front': NativeCoreJSONBytes,
               'binary64': NativeAgentBinary64, 'binary64_format': NativeAgentBinary64Format}
    notes = NativeCPythonNotes(note_image, note_digest) if note_image is not None else None
    try:
        if notes is not None:
            actual = (sys.implementation.name, notes.interpreter_identity['version'],
                notes.interpreter_identity['hexversion'], notes.interpreter_identity['soabi'],
                notes.interpreter_identity['executable_sha256'],
                tuple((item['name'], item['image_sha256']) for item in notes.api_identity))
            if actual != interpreter:
                raise ValueError('fixed note table is not bound to the declared current interpreter')
        elif interpreter is not None:
            raise ValueError('absent note mechanism declared interpreter authority')
        return NativeProgramNormalization({name: classes[name](raw, digest) for name, digest, raw in images}, notes=notes)
    except BaseException:
        if notes is not None:
            try: notes.close()
            except BaseException: pass
        raise


def installed_program_normalization(path):
    require_supported_interpreter()
    path = Path(path)
    raw = path.read_bytes()
    manifest = json.loads(raw, object_pairs_hook=_pairs)
    if (type(manifest) is not dict or set(manifest) != {'schema', 'images', 'hosted_mechanisms'} or manifest['schema'] != SCHEMA
            or type(manifest['images']) is not dict or set(manifest['images']) != set(SOURCES)):
        raise ValueError('complete native normalization manifest required')
    images, consumed = [], [(path, raw)]
    for name, source in SOURCES.items():
        row = manifest['images'][name]
        if type(row) is not dict or set(row) != {'image_path', 'source_sha256', 'image_sha256'}:
            raise ValueError('native normalization component identity differs')
        filename = row['image_path']
        if type(filename) is not str or not filename or Path(filename).name != filename:
            raise ValueError('native normalization image must be a sibling basename')
        source_bytes = source.read_bytes()
        image_path = path.parent / filename
        image_bytes = image_path.read_bytes()
        if sha256(source_bytes).hexdigest() != row['source_sha256'] or sha256(image_bytes).hexdigest() != row['image_sha256']:
            raise ValueError('native normalization component source or image changed')
        consumed.extend(((source, source_bytes), (image_path, image_bytes)))
        images.append((name, row['image_sha256'], image_bytes))
    mechanisms = manifest['hosted_mechanisms']
    note_image = note_digest = interpreter = None
    if type(mechanisms) is not dict:
        raise ValueError('normalization hosted mechanism declaration differs')
    if sys.version_info[:2] >= (3, 14):
        if set(mechanisms) != {'cpython_notes'}:
            raise ValueError('current interpreter note mechanism is undeclared')
        note = mechanisms['cpython_notes']
        if (type(note) is not dict or set(note) != {'schema', 'image_path', 'image_sha256', 'sources', 'interpreter', 'production'}
                or note['schema'] != NOTE_SCHEMA or type(note['sources']) is not dict
                or set(note['sources']) != set(NOTE_SOURCES)):
            raise ValueError('fixed hosted note mechanism identity differs')
        for name, source in NOTE_SOURCES.items():
            source_bytes = source.read_bytes()
            if sha256(source_bytes).hexdigest() != note['sources'][name]:
                raise ValueError('hosted note mechanism source changed')
            consumed.append((source, source_bytes))
        filename = note['image_path']
        if type(filename) is not str or not filename or Path(filename).name != filename:
            raise ValueError('hosted note image must be a sibling basename')
        note_path = path.parent / filename
        note_image = note_path.read_bytes()
        note_digest = note['image_sha256']
        if sha256(note_image).hexdigest() != note_digest:
            raise ValueError('hosted note mechanism image changed')
        consumed.append((note_path, note_image))
        _admit_note_production(path, note['production'], note_image, consumed)
        declared = note['interpreter']
        if (type(declared) is not dict or set(declared) != {'implementation', 'version', 'hexversion', 'soabi', 'executable_sha256', 'api_images'}
                or declared['implementation'] != 'cpython' or type(declared['hexversion']) is not int
                or type(declared['api_images']) is not dict or set(declared['api_images']) != set(NOTE_API_NAMES)):
            raise ValueError('hosted note interpreter binding differs')
        interpreter = (declared['implementation'], declared['version'], declared['hexversion'],
            declared['soabi'], declared['executable_sha256'],
            tuple((name, declared['api_images'][name]) for name in NOTE_API_NAMES))
    elif mechanisms:
        raise ValueError('this interpreter has no declared exception-note ABI')
    result = _mapped(tuple(images), note_image, note_digest, interpreter)
    if any(file.read_bytes() != data for file, data in consumed):
        raise ValueError('native normalization admission inputs changed')
    return result


def selected_program_normalization():
    path = os.environ.get(SELECTOR)
    return installed_program_normalization(path) if path else None
