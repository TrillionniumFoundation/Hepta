"""Experimental raw transport for the HIA JSON subcontrollers.

No default CLI, encoder or public selector imports this module. The caller
must retain the Python roots named by borrowed integer pointers and supply
separately admitted HIA text, sort, note and graph images plus a pinned leaf
DSO. This file has no Python traversal, classifier, sorting, JSON escaping,
number formatting or layout implementation.

The 3.12 generator profile/captured bindings, integer preflight/_pylong policy,
chunk/writer allocation and asynchronous schedules remain unqualified. This
private transport does not narrow the public domain or supply admission.
"""
from __future__ import annotations

import ctypes
import struct
from hepta.hia_cli_json_sort_native import (
    CpythonJsonLeaves, FRAME_WORDS, LEAF_ABI, SortSession,
)

WORD = struct.Struct('<Q')
NOTE_MAGIC = int.from_bytes(b'HCLINTE1', 'little')
GRAPH_MAGIC = int.from_bytes(b'HCLICGR1', 'little')
FRAME_BASE = 4096
FRAME_BYTES = 256
MAX_SIZE = (1 << 63) - 1
GRAPH_LITERALS = {
    512: b'_iterencode_list needs a sequence\0',
    576: b' while encoding a JSON object\0',
    640: b'Circular reference detected\0',
    704: b'items must return 2-tuples\0',
    768: b'keys must be str, int, float, bool or None, not %.100s\0',
    896: b'encoder() must return a string, not %.80s\0',
}
NOTE_LITERALS = {
    0: b'when serializing %T object\0',
    1: b'when serializing %T item %zd\0',
    2: b'when serializing %T item %R\0',
}
WRONG_NOTES = b'Cannot add note: __notes__ is not a list\0'
OWNED_FIELDS = {40: 1, 48: 2, 56: 4, 80: 8, 88: 16, 96: 32}


def native_entry(image):
    address = ctypes.cast(image._entry, ctypes.c_void_p).value
    if not address:
        raise ValueError('admitted HIA image has no actual entry')
    return ctypes.PYFUNCTYPE(
        ctypes.c_uint32, *([ctypes.c_void_p, ctypes.c_uint64] * 3))(address)


def exact_word(value):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise ValueError('raw transaction word differs')
    return value


class RawTransactions:
    """A private C owner and one-leaf frames; never object-handle conversion."""

    def __init__(self, leaves):
        if not isinstance(leaves, CpythonJsonLeaves):
            raise TypeError('admitted CLI JSON leaf mechanism required')
        self.leaves = leaves
        self.context = ctypes.create_string_buffer(leaves.context_bytes)
        self.frame = (ctypes.c_uint64 * FRAME_WORDS)()
        self.view = (ctypes.c_uint64 * 9)()
        self.active = False
        self.external_pending = False
        self.protocol_failed = False
        self.nested_active = None
        self.nested_failure = None
        self.actual_leaf_returns = []
        self.actual_generator_leaf_returns = []
        if leaves.init(self.context, leaves.context_bytes) != 0:
            raise RuntimeError('CLI JSON raw context initialization refused')
        self.refresh()

    def refresh(self):
        if self.leaves.views(self.context, self.leaves.context_bytes, self.view) != 0:
            self.protocol_failed = True
            raise RuntimeError('CLI JSON raw context view refused')
        return self.view

    def call(self, operation, arguments=(), *, generator_pointer=0,
             parent_pointer=0, instruction=0):
        if (self.active or self.external_pending or self.protocol_failed
                or self.nested_active is not None):
            raise RuntimeError('CLI JSON raw context is active or inadmissible')
        if type(operation) is not int or not 1 <= operation <= 139 or len(arguments) > 5:
            raise ValueError('one named raw leaf required')
        words = tuple(exact_word(value) for value in arguments)
        generator_pointer = exact_word(generator_pointer)
        parent_pointer = exact_word(parent_pointer)
        instruction = exact_word(instruction)
        if not generator_pointer and (parent_pointer or instruction):
            raise ValueError('generator frame context has no actual owner')
        framed_entry = None
        if generator_pointer:
            if self.leaves.profile != 31214 or not getattr(self.leaves, 'runtime_312_binding', None):
                raise ValueError('exact mapped 3.12 runtime binding required')
            address = ctypes.cast(self.leaves.library.hia_cli_json_leaf_in_generator,
                                  ctypes.c_void_p).value
            if not address:
                raise ValueError('actual generator-frame leaf entry is absent')
            framed_entry = ctypes.PYFUNCTYPE(ctypes.c_uint64,
                ctypes.POINTER(ctypes.c_uint64), ctypes.c_void_p,
                ctypes.c_void_p, ctypes.c_uint64)(address)
        self.active = True
        try:
            frame = self.frame
            for index in range(FRAME_WORDS):
                frame[index] = 0
            frame[0] = LEAF_ABI
            frame[1] = operation
            frame[2] = ctypes.addressof(self.context)
            for index, value in enumerate(words, 3):
                frame[index] = value
            returned = (self.leaves.entry(frame) if framed_entry is None else
                        framed_entry(frame, generator_pointer, parent_pointer, instruction))
            # Owners are committed in C before marker 2, not by the append.
            if returned != 0 or frame[18] != 2:
                self.protocol_failed = True
                raise RuntimeError('CLI JSON one-leaf transaction refused')
            self.refresh()
            self.actual_leaf_returns.append(
                (operation, words, tuple(frame[9:17]), frame[8], frame[17]))
            if generator_pointer:
                self.actual_generator_leaf_returns.append(
                    (operation, generator_pointer, parent_pointer, instruction,
                     tuple(frame[9:17]), frame[8], frame[17]))
            return frame
        finally:
            self.active = False

    def capture_external(self, error):
        # Acquisition only while the adapter's except is active.
        if (self.external_pending or self.active or self.protocol_failed
                or self.nested_active is not None):
            raise RuntimeError('CLI JSON external exception permission differs')
        if self.leaves.capture_external(self.context, error) != 0:
            self.protocol_failed = True
            raise RuntimeError('CLI JSON external exception acquisition refused')
        self.external_pending = True

    def install_external_after_except(self):
        if not self.external_pending:
            raise RuntimeError('no acquired CLI JSON external exception')
        self.external_pending = False
        return self.call(40)

    def nested_sort(self, image, borrowed_items_pointer):
        if (self.active or self.external_pending or self.protocol_failed
                or self.nested_active is not None):
            raise RuntimeError('CLI JSON nested sort context is inadmissible')
        self.refresh()
        if self.view[5] or self.view[8]:
            raise RuntimeError('nested sort requires an empty result/error owner')
        session = SortSession.from_raw(image, self.leaves, borrowed_items_pointer)
        # Keep the actual nested owner before it can detach the aliased list.
        # An unconfirmed unwind must not lose its context through a temporary.
        self.nested_active = session
        try:
            # Business comparison errors remain in the nested C owner.
            status = session.run()
            if not session.finished or status not in (0, 1):
                raise RuntimeError('nested sort did not reach a raw terminal')
            returned = self.leaves.transfer_closed_error(self.context, session.context)
            if returned != 0:
                raise RuntimeError('nested sort error transfer refused')
            self.refresh()
            if (status == 0) != (self.view[8] == 0):
                raise RuntimeError('nested sort result/error transfer differs')
            self.nested_active = None
            return session
        except BaseException as error:
            # No list restore/DECREF is attempted in this handled-exception
            # window. Retain both raw contexts and refuse every later leaf.
            # This is an explicit unqualified cleanup failure, not closure.
            self.protocol_failed = True
            self.nested_active = session
            self.nested_failure = error
            raise

    def raise_pending(self):
        self.refresh()
        if not self.view[8]:
            raise RuntimeError('no actual CLI JSON pending exception')
        self.leaves.raise_pending(self.context)
        raise RuntimeError('actual CLI JSON exception did not propagate')


class NoteSession:
    """One-use HIA note continuation on the graph's existing raw owner."""

    def __init__(self, image, raw, *, kind, object_pointer, key_or_index,
                 notes_name, type_error):
        if kind not in NOTE_LITERALS:
            raise ValueError('HIA note kind differs')
        self.raw = raw
        self.image = image
        self.entry = native_entry(image)
        self.state = ctypes.create_string_buffer(1024)
        self.busy = self.pending = self.finish_pending = False
        self.aborting = self.finished = self.quarantined = False
        self.last_issued = self.last_consumed = 0
        self.actual_native_returns = []
        self.unwind_failure = None
        for offset, value in ((0, NOTE_MAGIC), (120, kind), (128, object_pointer),
                              (136, key_or_index), (144, notes_name),
                              (152, type_error)):
            self.put(offset, exact_word(value))
        self.kind = kind

    def get(self, offset):
        return WORD.unpack_from(self.state, offset)[0]

    def put(self, offset, value):
        WORD.pack_into(self.state, offset, value)

    def views(self):
        view = self.raw.refresh()
        self.put(48, view[8])
        self.put(288, view[5])
        return view

    def literal(self, offset, raw):
        if self.state.raw[offset:offset + len(raw)] != raw:
            raise RuntimeError('HIA note literal differs')
        return ctypes.addressof(self.state) + offset

    def step(self):
        if self.finished or self.busy or self.quarantined:
            raise RuntimeError('HIA note is terminal or active')
        self.busy = True
        self.pending = False
        try:
            self.views()
            status = self.entry(None, 0, None, 0, self.state, 1024)
            self.actual_native_returns.append(status)
            if status == 2:
                sequence = self.get(16)
                if self.get(24) != 1 or sequence <= self.last_issued:
                    raise RuntimeError('HIA note request permission differs')
                self.last_issued = sequence
                self.pending = True
            elif status == 0 and self.get(112) == 1:
                self.finish_pending = True
            else:
                raise RuntimeError('HIA note protocol refused')
            return status
        finally:
            self.busy = False

    def observe(self):
        if not self.pending or self.busy or self.finished or self.quarantined:
            raise RuntimeError('HIA note has no observation permission')
        self.pending = False
        self.busy = True
        try:
            sequence, operation = self.get(16), self.get(64)
            if sequence != self.last_issued or sequence <= self.last_consumed:
                raise RuntimeError('HIA note effect already consumed')
            self.last_consumed = sequence
            args = [self.get(72 + index * 8) for index in range(4)]
            if operation not in (6, 10, 16, 42, 43, 44, 45, 46, 47, 48,
                                 49, 50, 51, 52, 53, 54):
                raise RuntimeError('HIA note issued a non-note leaf')
            if operation in (47, 48, 49):
                if args[0] != 512 or operation != 47 + self.kind:
                    raise RuntimeError('HIA note format selector differs')
                args[0] = self.literal(512, NOTE_LITERALS[self.kind])
            elif operation == 10:
                if args[1:3] != [640, len(WRONG_NOTES)]:
                    raise RuntimeError('HIA wrong-notes selector differs')
                args[1] = self.literal(640, WRONG_NOTES)
            frame = self.raw.call(operation, args)
            self.views()
            for index in range(8):
                self.put(160 + 8 * index, frame[9 + index])
            self.put(32, sequence)
            self.put(40, operation)
        finally:
            self.busy = False

    def start_abort(self):
        self.pending = self.finish_pending = False
        self.finished = False
        self.raw.install_external_after_except()
        self.aborting = True
        if self.get(112) == 1:
            self.finish_pending = True
        else:
            self.put(56, 1)

    def run(self):
        if self.finished or self.busy or self.quarantined:
            raise RuntimeError('HIA note cannot be re-entered')
        try:
            while True:
                failed = False
                try:
                    while not self.finish_pending:
                        if self.step() == 2:
                            self.observe()
                    # Post-entry views and bookkeeping stay under the same
                    # external-BaseException boundary as the actual entry.
                    self.finish_pending = False
                    self.views()
                    self.finished = True
                    return None
                except BaseException as error:
                    if self.aborting or self.raw.protocol_failed:
                        raise
                    self.raw.capture_external(error)
                    failed = True
                if failed:
                    # The Python except target has been cleared. Only now
                    # may the HIA plan release actual note/cell references.
                    self.start_abort()
        except BaseException as error:
            self.quarantined = True
            self.pending = self.finish_pending = False
            self.raw.protocol_failed = True
            self.unwind_failure = error
            raise


class GraphSession:
    """Private raw 3.14 graph transport, with no public selector.

    The scalar transport is separately supplied and pinned. Its interface
    run_raw(raw, object_pointer, kind, quoted) must leave its result or actual
    exception in the same C owner. It cannot use a Python JSON serializer or
    sort. This wrapper neither certifies it nor supplies a hidden fallback.
    """

    def __init__(self, image, leaves, *, sort_image, note_image, scalar,
                 root_pointer, markers_pointer, default_pointer,
                 encoder_pointer, fast_encoder, notes_name_pointer,
                 value_error_pointer, type_error_pointer):
        self.finished = True
        self.quarantined = self.busy = self.pending = False
        self.finish_pending = self.aborting = False
        self.image, self.sort_image, self.note_image = image, sort_image, note_image
        self.scalar = scalar
        self.raw = RawTransactions(leaves)
        self.entry = native_entry(image)
        self.state = ctypes.create_string_buffer(FRAME_BASE + FRAME_BYTES * 4)
        self.output = ctypes.create_string_buffer(256)
        self.source_address = self.source_bytes = 0
        self.last_issued = self.last_consumed = 0
        self.status = None
        self.output_count = None
        self.result_permission = False
        self.actual_native_returns = []
        self.actual_component_returns = []
        self.active_note = None
        self.unwind_failure = None
        self.notes_name_pointer = exact_word(notes_name_pointer)
        self.type_error_pointer = exact_word(type_error_pointer)
        if type(fast_encoder) is not bool:
            raise TypeError('exact admitted encoder-identity flag required')
        for offset, value in (
            (0, GRAPH_MAGIC), (128, root_pointer), (136, leaves.profile),
            (144, markers_pointer), (152, default_pointer),
            (160, encoder_pointer), (168, int(fast_encoder)),
            (176, value_error_pointer), (184, type_error_pointer),
        ):
            self.put(offset, exact_word(value))
        self.finished = False

    def get(self, offset):
        return WORD.unpack_from(self.state, offset)[0]

    def put(self, offset, value):
        WORD.pack_into(self.state, offset, value)

    def views(self):
        view = self.raw.refresh()
        self.put(48, view[8])
        self.put(192, view[5])
        return view

    def top(self):
        top = self.get(200)
        if top < FRAME_BASE or (top - FRAME_BASE) % FRAME_BYTES:
            raise RuntimeError('HIA graph frame address differs')
        if top > ctypes.sizeof(self.state) - FRAME_BYTES:
            raise RuntimeError('HIA graph frame is out of storage')
        return top

    def literal(self, offset, length=None):
        if offset not in GRAPH_LITERALS:
            raise RuntimeError('HIA graph literal address differs')
        raw = GRAPH_LITERALS[offset]
        if length is not None and length != len(raw):
            raise RuntimeError('HIA graph literal size differs')
        if self.state.raw[offset:offset + len(raw)] != raw:
            raise RuntimeError('HIA graph literal bytes differ')
        return ctypes.addressof(self.state) + offset

    def owned_addresses(self, destination, flags, mask):
        top = self.top()
        field = destination - top
        if (field not in OWNED_FIELDS or OWNED_FIELDS[field] != mask
                or flags != top + 104):
            raise RuntimeError('HIA graph ownership-cell binding differs')
        base = ctypes.addressof(self.state)
        return base + destination, base + flags

    def leaf_arguments(self, operation, args):
        args = list(args)
        if operation == 10:
            args[1] = self.literal(args[1], args[2])
        elif operation == 24:
            if args[1] != 512:
                raise RuntimeError('HIA sequence error literal differs')
            args[1] = self.literal(args[1])
        elif operation == 65:
            if args[1] not in (768, 896):
                raise RuntimeError('HIA type error literal differs')
            args[1] = self.literal(args[1])
        elif operation in (62, 64):
            args[0], args[1] = self.owned_addresses(args[0], args[1], args[2])
            if operation == 64 and args[2] == 16:
                # Clear before DECREF, including an interrupted reply.
                self.source_address = self.source_bytes = 0
        elif operation == 63:
            args[1], args[2] = self.owned_addresses(args[1], args[2], args[3])
        elif operation == 66:
            if args[:3] != [576, self.top() + 104, 64]:
                raise RuntimeError('HIA recursion owner binding differs')
            args[0] = self.literal(576)
            args[1] += ctypes.addressof(self.state)
        elif operation == 67:
            if args[:2] != [self.top() + 104, 64]:
                raise RuntimeError('HIA recursion release binding differs')
            args[0] += ctypes.addressof(self.state)
        elif operation == 38:
            top = self.top()
            if args[0] != self.get(top + 88) or not (self.get(top + 104) & 16):
                raise RuntimeError('HIA Unicode data owner differs')
        return args

    def grow(self, which, required):
        if type(required) is not int or required <= 0 or required > MAX_SIZE:
            raise MemoryError('HIA graph storage address range exceeded')
        old = self.output if which == 'output' else self.state
        size = ctypes.sizeof(old)
        if required <= size:
            raise RuntimeError('HIA graph requested a non-growing allocation')
        fresh = ctypes.create_string_buffer(required)
        ctypes.memmove(fresh, old, size)
        # Opaque bytes never DECREF their numeric words. Only the active HIA
        # state owns each raw object after this mechanical move.
        if which == 'output':
            self.output = fresh
        else:
            self.state = fresh

    def step(self):
        if self.finished or self.busy or self.quarantined:
            raise RuntimeError('HIA graph is terminal or active')
        self.pending = False
        self.busy = True
        try:
            self.views()
            status = self.entry(
                self.source_address, self.source_bytes,
                self.output, ctypes.sizeof(self.output),
                self.state, ctypes.sizeof(self.state))
            self.status = status
            self.actual_native_returns.append(status)
            if status == 2:
                sequence = self.get(16)
                if self.get(24) != 1 or sequence <= self.last_issued:
                    raise RuntimeError('HIA graph request permission differs')
                self.last_issued = sequence
                self.pending = True
            elif status in (0, 1):
                self.views()
                if self.get(200) != 0 or self.get(120) != status + 1 or self.raw.view[5]:
                    raise RuntimeError('HIA graph terminal ownership differs')
                if (status == 0) != (self.raw.view[8] == 0):
                    raise RuntimeError('HIA graph status/error ownership differs')
                self.finish_pending = True
            else:
                raise RuntimeError('HIA graph protocol refused')
            return status
        finally:
            self.busy = False

    def observe(self):
        if not self.pending or self.busy or self.finished or self.quarantined:
            raise RuntimeError('HIA graph has no observation permission')
        self.pending = False
        self.busy = True
        try:
            sequence, operation = self.get(16), self.get(64)
            if sequence != self.last_issued or sequence <= self.last_consumed:
                raise RuntimeError('HIA graph effect already consumed')
            self.last_consumed = sequence
            args = tuple(self.get(72 + index * 8) for index in range(5))
            if operation == 200:
                result = self.scalar.run_raw(self.raw, args[0], args[1], args[2])
                self.actual_component_returns.append((sequence, operation, result))
            elif operation == 201:
                result = self.raw.nested_sort(self.sort_image, args[0])
                self.actual_component_returns.append(
                    (sequence, operation, result.status,
                     tuple(result.actual_native_returns),
                     tuple(result.actual_leaf_returns)))
            elif operation == 202:
                self.grow('output', args[0])
            elif operation == 203:
                result = NoteSession(
                    self.note_image, self.raw, kind=args[0],
                    object_pointer=args[1], key_or_index=args[2],
                    notes_name=self.notes_name_pointer,
                    type_error=self.type_error_pointer)
                self.active_note = result
                result.run()
                self.actual_component_returns.append(
                    (sequence, operation, tuple(result.actual_native_returns)))
                self.active_note = None
            elif operation == 204:
                self.grow('state', args[0])
            else:
                if operation not in (6, 10, 20, 24, 25, 26, 27, 32, 38,
                                     55, 57, 58, 59, 60, 62, 63, 64,
                                     65, 66, 67):
                    raise RuntimeError('HIA graph issued a non-graph leaf')
                frame = self.raw.call(operation, self.leaf_arguments(operation, args))
                if operation == 38 and not self.raw.view[8]:
                    count, kind, pointer = frame[9], frame[10], frame[11]
                    if kind not in (1, 2, 4) or count > MAX_SIZE // kind or not pointer:
                        raise RuntimeError('HIA raw Unicode extent differs')
                    self.source_address, self.source_bytes = pointer, count * kind
                for index in range(8):
                    self.put(256 + 8 * index, frame[9 + index])
            self.views()
            self.put(32, sequence)
            self.put(40, operation)
        finally:
            self.busy = False

    def start_abort(self):
        self.pending = self.finish_pending = self.result_permission = False
        self.finished = False
        self.output_count = None
        self.source_address = self.source_bytes = 0
        self.raw.install_external_after_except()
        self.aborting = True
        if self.get(120) != 0 and self.get(200) == 0 and self.raw.view[5] == 0:
            self.status = 1
            self.put(208, 0)
            self.finish_pending = True
        else:
            self.put(56, 1)

    def run_raw(self):
        if self.finished or self.busy or self.quarantined:
            raise RuntimeError('HIA graph cannot be re-entered')
        try:
            while True:
                failed = False
                try:
                    while not self.finish_pending:
                        if self.step() == 2:
                            self.observe()
                    self.finish_pending = False
                    self.views()
                    if self.status == 0:
                        count = self.get(208)
                        if count > ctypes.sizeof(self.output) // 4:
                            raise RuntimeError('HIA graph output extent differs')
                        self.output_count = count
                        self.result_permission = True
                    elif self.status != 1 or not self.raw.view[8]:
                        raise RuntimeError('HIA graph terminal result differs')
                    self.finished = True
                    return self.status
                except BaseException as error:
                    if (self.aborting or self.raw.protocol_failed
                            or (self.active_note is not None
                                and self.active_note.quarantined)):
                        raise
                    self.raw.capture_external(error)
                    failed = True
                if failed:
                    # Revoke output before installing the acquired error.
                    # Completed HIA cleanup is not replayed: start_abort
                    # consumes the terminal flag in the existing workspace.
                    self.start_abort()
        except BaseException as error:
            self.quarantined = True
            self.pending = self.finish_pending = self.result_permission = False
            self.unwind_failure = error
            raise

    def make_raw_unicode_result(self):
        """One-use physical UTF-32 conversion, not public admission."""
        if not self.finished or self.status != 0 or not self.result_permission:
            raise RuntimeError('HIA graph has no result conversion permission')
        self.result_permission = False
        self.views()
        if self.raw.view[5] or self.raw.view[8]:
            raise RuntimeError('HIA graph result/error owner is not empty')
        frame = self.raw.call(68, (ctypes.addressof(self.output), self.output_count))
        # The integer is only an audit address; the C context still owns it.
        return frame[9]

    def close(self):
        if self.quarantined:
            raise RuntimeError('HIA graph cleanup was not proven complete')
        if not self.finished:
            error = RuntimeError('unfinished HIA graph session')
            self.raw.capture_external(error)
            del error
            self.start_abort()
            self.run_raw()
        self.result_permission = False
        self.source_address = self.source_bytes = 0
        self.views()
        if self.raw.view[5]:
            self.raw.call(6)
