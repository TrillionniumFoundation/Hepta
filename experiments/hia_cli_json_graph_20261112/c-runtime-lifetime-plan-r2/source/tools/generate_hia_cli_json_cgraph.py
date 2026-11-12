"""Experimental HIA graph traversal for the two retained 3.14 C profiles.

This is a *subcontroller*, not a replacement of the public CLI.  The separate
Python-encoder profile and the public binding/setup continuation are still
required.  No selector is added here and no previously UNKNOWN job is used.

HIA owns object classification branches, marker policy, current-size loops,
key conversion before values, child continuations, original items-list sort,
layout, versioned item ownership, error-note calls and ordered cleanup.  Raw
CPython leaves do individual operations; 200/201/203 name separately admitted
HIA text/sort/note components.  202/204 are mechanical buffer reallocations.
No node, depth or eight-MiB substitute limit is introduced.  Arithmetic
overflow requests MemoryError; original recursion leaves remain explicit.

This source has not been generated or executed.  Allocation/GC schedules,
public encoder binding, Python 3.12 traversal and nested component transport
remain explicit development obligations rather than a narrowed public domain.
"""
from __future__ import annotations

import ast
from pathlib import Path


SYMBOLS = {
    'MAGIC': int.from_bytes(b'HCLICGR1', 'little'), 'ABI': 0xfffffffd,
    'GLOBAL_PHASE': 8, 'SEQUENCE': 16, 'PENDING': 24,
    'REPLY_SEQUENCE': 32, 'REPLY_OPERATION': 40, 'REPLY_ERROR': 48,
    'ABORT': 56, 'OPERATION': 64, 'ARGUMENTS': 72, 'FINAL_STATUS': 120,
    'ROOT': 128, 'PROFILE': 136, 'MARKERS': 144, 'DEFAULT_FN': 152,
    'STRING_ENCODER': 160, 'FAST_STRING_ENCODER': 168,
    'VALUE_ERROR': 176, 'TYPE_ERROR': 184, 'CONTEXT_SLOT': 192,
    'TOP': 200, 'OUTPUT_COUNT': 208, 'ANSWER': 256,
    'FRAME_BASE': 4096, 'FRAME_BYTES': 256,
    'F_OBJECT': 0, 'F_PHASE': 8, 'F_KIND': 16, 'F_LEVEL': 24,
    'F_INDEX': 32, 'F_IDENT': 40, 'F_ITEMS': 48, 'F_ITEM': 56,
    'F_KEY': 64, 'F_VALUE': 72, 'F_KEYSTR': 80, 'F_ENCODED': 88,
    'F_NEWOBJ': 96, 'F_FLAGS': 104, 'F_FIRST': 112,
    'F_CHILD_STATUS': 120, 'F_MARKER_RETURN': 128,
    'F_FAST_TYPE': 136, 'F_AFTER_COPY': 144, 'F_SCALAR_KIND': 152,
    'F_UNICODE_COUNT': 160, 'F_UNICODE_KIND': 168,
    'OWN_IDENT': 1, 'OWN_ITEMS': 2, 'OWN_ITEM': 4,
    'OWN_KEYSTR': 8, 'OWN_ENCODED': 16, 'OWN_NEWOBJ': 32,
    'RECURSIVE': 64,
    'SEQUENCE_MESSAGE': 512, 'RECURSION_MESSAGE': 576,
    'CIRCULAR_MESSAGE': 640, 'ITEMS_MESSAGE': 704,
    'KEY_ERROR_MESSAGE': 768, 'ENCODER_ERROR_MESSAGE': 896,
}
LITERALS = {
    'SEQUENCE_MESSAGE': b'_iterencode_list needs a sequence\0',
    'RECURSION_MESSAGE': b' while encoding a JSON object\0',
    'CIRCULAR_MESSAGE': b'Circular reference detected\0',
    'ITEMS_MESSAGE': b'items must return 2-tuples\0',
    'KEY_ERROR_MESSAGE': b'keys must be str, int, float, bool or None, not %.100s\0',
    'ENCODER_ERROR_MESSAGE': b'encoder() must return a string, not %.80s\0',
}


SOURCE = r'''
def cli_json_cgraph(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < FRAME_BASE + FRAME_BYTES or get(w, 0) != MAGIC or get(w, FINAL_STATUS) != 0:
        return ABI
    aborting = get(w, ABORT)
    if aborting != 0:
        # An adapter failure can precede reply publication.  Abort consumes
        # that permission without demanding a reply to an unexecuted leaf.
        put(w, ABORT, 0)
        put(w, PENDING, 0)
        if get(w, GLOBAL_PHASE) == 0:
            put(w, OUTPUT_COUNT, 0)
            put(w, FINAL_STATUS, 2)
            return 1
        fput(w, F_PHASE, 900)
    elif get(w, PENDING) != 0:
        if get(w, REPLY_SEQUENCE) != get(w, SEQUENCE) or get(w, REPLY_OPERATION) != get(w, OPERATION):
            return ABI
        put(w, PENDING, 0)
    elif get(w, GLOBAL_PHASE) != 0:
        return ABI
    if get(w, GLOBAL_PHASE) == 0:
        if get(w, ROOT) == 0 or get(w, DEFAULT_FN) == 0 or get(w, STRING_ENCODER) == 0:
            return ABI
        if get(w, PROFILE) != 31404 and get(w, PROFILE) != 31410:
            # No public selector currently admits this incomplete subcontroller.
            return ABI
        literals(w)
        put(w, TOP, FRAME_BASE)
        clear_frame(w, FRAME_BASE)
        fput(w, F_OBJECT, get(w, ROOT))
        fput(w, F_PHASE, 1)
        put(w, GLOBAL_PHASE, 1)
    if get(w, REPLY_ERROR) != 0 and (get(w, OPERATION) == 202 or get(w, OPERATION) == 204):
        fput(w, F_PHASE, 900)
    while True:
        phase = fget(w, F_PHASE)
        if phase < 20:
            status = scalar_node(s, o, w, phase)
        elif phase < 40:
            status = sequence_node(o, w, phase)
        elif phase < 80:
            status = mapping_node(o, w, phase)
        elif phase < 100:
            status = default_node(w, phase)
        elif phase < 200:
            status = marker_node(w, phase)
        else:
            status = unwind_node(w, phase)
        if status != 4:
            return status
        if get(w, TOP) == 0:
            return get(w, FINAL_STATUS) - 1
    return ABI

def scalar_node(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 1:
        return request(w, 55, fget(w, F_OBJECT), 0, 0, 0, 0, 2)
    if phase == 2:
        kind = answer(w, 0)
        if (kind & 448) != 0:
            which = choose((kind & 64) != 0, 0, choose((kind & 128) != 0, 1, 2))
            fput(w, F_SCALAR_KIND, which)
            fput(w, F_PHASE, 3)
            return 4
        if (kind & 1) != 0:
            fput(w, F_SCALAR_KIND, 0)
            fput(w, F_AFTER_COPY, 10)
            if get(w, FAST_STRING_ENCODER) == 0:
                return request(w, 32, get(w, STRING_ENCODER), fget(w, F_OBJECT), 0, 0, 0, 5)
            return request(w, 200, fget(w, F_OBJECT), 0, 1, 0, 0, 5)
        if (kind & 2) != 0 or (kind & 4) != 0:
            fput(w, F_SCALAR_KIND, choose((kind & 2) != 0, 1, 2))
            fput(w, F_AFTER_COPY, 10)
            return request(w, 200, fget(w, F_OBJECT), fget(w, F_SCALAR_KIND), 0, 0, 0, 5)
        if (kind & 24) != 0:
            fput(w, F_KIND, 1)
            return request(w, 66, RECURSION_MESSAGE, field(w, F_FLAGS), RECURSIVE, 0, 0, 20)
        if (kind & 32) != 0:
            fput(w, F_KIND, 2)
            return request(w, 66, RECURSION_MESSAGE, field(w, F_FLAGS), RECURSIVE, 0, 0, 40)
        fput(w, F_KIND, 3)
        return marker(w, 80)
    if phase == 3:
        # Keep the classification across a possible allocation reply; the
        # reply scratch is not a persistent object observation record.
        status = reserve(o, w, 5, 3)
        if status != 4:
            return status
        append_constant(o, w, fget(w, F_SCALAR_KIND))
        return pop(w, 0)
    if phase == 5:
        if get(w, CONTEXT_SLOT) == 0:
            if (fget(w, F_FLAGS) & OWN_KEYSTR) != 0:
                return drop(w, F_KEYSTR, OWN_KEYSTR, 900)
            return failed(w)
        return adopt(w, F_ENCODED, OWN_ENCODED, 6)
    if phase == 6:
        return request(w, 55, fget(w, F_ENCODED), 0, 0, 0, 0, 11)
    if phase == 11:
        if (answer(w, 0) & 1) == 0:
            return request(w, 65, get(w, TYPE_ERROR), ENCODER_ERROR_MESSAGE, fget(w, F_ENCODED), 0, 0, 13)
        if (fget(w, F_FLAGS) & OWN_KEYSTR) != 0:
            return drop(w, F_KEYSTR, OWN_KEYSTR, 15)
        fput(w, F_PHASE, 15)
        return 4
    if phase == 13:
        # encoder_encode_string releases its wrong-type result before its
        # caller releases keystr.  A subtype finalizer can observe this order.
        return drop(w, F_ENCODED, OWN_ENCODED, 14)
    if phase == 14:
        if (fget(w, F_FLAGS) & OWN_KEYSTR) != 0:
            return drop(w, F_KEYSTR, OWN_KEYSTR, 900)
        return failed(w)
    if phase == 15:
        return request(w, 38, fget(w, F_ENCODED), 0, 0, 0, 0, 12)
    if phase == 12:
        fput(w, F_UNICODE_COUNT, answer(w, 0))
        fput(w, F_UNICODE_KIND, answer(w, 1))
        fput(w, F_PHASE, 7)
        return 4
    if phase == 7:
        count = fget(w, F_UNICODE_COUNT)
        kind = fget(w, F_UNICODE_KIND)
        if kind != 1 and kind != 2 and kind != 4:
            return ABI
        shift = choose(kind == 1, 0, choose(kind == 2, 1, 2))
        if count > length(s) >> shift:
            return ABI
        status = reserve(o, w, count, 7)
        if status != 4:
            return status
        index = 0
        cursor = get(w, OUTPUT_COUNT)
        while index < count:
            value = byte(s, index * kind)
            if kind >= 2:
                value = value | (byte(s, index * kind + 1) << 8)
            if kind == 4:
                value = value | (byte(s, index * kind + 2) << 16) | (byte(s, index * kind + 3) << 24)
            point(o, cursor + index, value)
            index = index + 1
        put(w, OUTPUT_COUNT, cursor + count)
        return drop(w, F_ENCODED, OWN_ENCODED, 8)
    if phase == 8:
        fput(w, F_PHASE, fget(w, F_AFTER_COPY))
        return 4
    if phase == 10:
        return pop(w, 0)
    return ABI

def sequence_node(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 20:
        if get(w, REPLY_ERROR) != 0:
            return failed(w)
        return request(w, 24, fget(w, F_OBJECT), SEQUENCE_MESSAGE, 0, 0, 0, 21)
    if phase == 21:
        if get(w, CONTEXT_SLOT) == 0:
            return failed(w)
        return adopt(w, F_ITEMS, OWN_ITEMS, 22)
    if phase == 22:
        return request(w, 55, fget(w, F_ITEMS), 0, 0, 0, 0, 23)
    if phase == 23:
        fput(w, F_FAST_TYPE, choose((answer(w, 0) & 8) != 0, 1, 2))
        return request(w, 26, fget(w, F_ITEMS), fget(w, F_FAST_TYPE), 0, 0, 0, 24)
    if phase == 24:
        if answer(w, 0) == 0:
            return drop(w, F_ITEMS, OWN_ITEMS, 25)
        return marker(w, 26)
    if phase == 25:
        status = reserve(o, w, 2, 25)
        if status != 4:
            return status
        append_point(o, w, 91)
        append_point(o, w, 93)
        return leave_success(w)
    if phase == 26:
        status = reserve(o, w, 2 + 2 * (fget(w, F_LEVEL) + 1), 26)
        if status != 4:
            return status
        append_point(o, w, 91)
        fput(w, F_LEVEL, fget(w, F_LEVEL) + 1)
        newline(o, w, fget(w, F_LEVEL))
        fput(w, F_INDEX, 0)
        return request(w, 26, fget(w, F_ITEMS), fget(w, F_FAST_TYPE), 0, 0, 0, 28)
    if phase == 27:
        return request(w, 26, fget(w, F_ITEMS), fget(w, F_FAST_TYPE), 0, 0, 0, 28)
    if phase == 28:
        if fget(w, F_INDEX) >= answer(w, 0):
            return unmark(w, 35)
        return request(w, 27, fget(w, F_ITEMS), fget(w, F_INDEX), fget(w, F_FAST_TYPE), 0, 0, 29)
    if phase == 29:
        if get(w, PROFILE) == 31410:
            return request(w, 63, answer(w, 0), field(w, F_ITEM), field(w, F_FLAGS), OWN_ITEM, 0, 30)
        fput(w, F_ITEM, answer(w, 0))
        fput(w, F_PHASE, 30)
        return 4
    if phase == 30:
        if fget(w, F_INDEX) != 0:
            status = reserve(o, w, 2 + 2 * fget(w, F_LEVEL), 30)
            if status != 4:
                return status
            append_point(o, w, 44)
            newline(o, w, fget(w, F_LEVEL))
        fput(w, F_PHASE, 34)
        return 4
    if phase == 34:
        # A frame allocation must not replay the separator already emitted.
        return push(w, fget(w, F_ITEM), fget(w, F_LEVEL), 31, 34)
    if phase == 31:
        if fget(w, F_CHILD_STATUS) != 0:
            return request(w, 203, 1, fget(w, F_OBJECT), fget(w, F_INDEX), 0, 0, 32)
        fput(w, F_PHASE, 32)
        return 4
    if phase == 32:
        if (fget(w, F_FLAGS) & OWN_ITEM) != 0:
            return drop(w, F_ITEM, OWN_ITEM, 33)
        fput(w, F_ITEM, 0)
        fput(w, F_PHASE, 33)
        return 4
    if phase == 33:
        if fget(w, F_CHILD_STATUS) != 0:
            return failed(w)
        fput(w, F_INDEX, fget(w, F_INDEX) + 1)
        fput(w, F_PHASE, 27)
        return 4
    if phase == 35:
        status = reserve(o, w, 2 + 2 * (fget(w, F_LEVEL) - 1), 35)
        if status != 4:
            return status
        fput(w, F_LEVEL, fget(w, F_LEVEL) - 1)
        newline(o, w, fget(w, F_LEVEL))
        append_point(o, w, 93)
        return drop(w, F_ITEMS, OWN_ITEMS, 36)
    if phase == 36:
        return leave_success(w)
    return ABI

def mapping_node(o:mutbuf, w:mutbuf, phase:u64) -> u64:
    if phase == 40:
        if get(w, REPLY_ERROR) != 0:
            return failed(w)
        return request(w, 26, fget(w, F_OBJECT), 3, 0, 0, 0, 41)
    if phase == 41:
        if answer(w, 0) == 0:
            fput(w, F_PHASE, 42)
            return 4
        return marker(w, 43)
    if phase == 42:
        status = reserve(o, w, 2, 42)
        if status != 4:
            return status
        append_point(o, w, 123)
        append_point(o, w, 125)
        return leave_success(w)
    if phase == 43:
        status = reserve(o, w, 1, 43)
        if status != 4:
            return status
        append_point(o, w, 123)
        fput(w, F_LEVEL, fget(w, F_LEVEL) + 1)
        fput(w, F_FIRST, 1)
        return request(w, 25, fget(w, F_OBJECT), 0, 0, 0, 0, 44)
    if phase == 44:
        if get(w, CONTEXT_SLOT) == 0:
            return failed(w)
        return adopt(w, F_ITEMS, OWN_ITEMS, 45)
    if phase == 45:
        # The actual PyMapping_Items list is passed to the HIA sort owner.
        # No key list, copied tuple list, Python sorted or C PyList_Sort exists.
        return request(w, 201, fget(w, F_ITEMS), 0, 0, 0, 0, 46)
    if phase == 46:
        if get(w, REPLY_ERROR) != 0:
            return failed(w)
        fput(w, F_INDEX, 0)
        fput(w, F_PHASE, 47)
        return 4
    if phase == 47:
        return request(w, 26, fget(w, F_ITEMS), 1, 0, 0, 0, 48)
    if phase == 48:
        if fget(w, F_INDEX) >= answer(w, 0):
            return drop(w, F_ITEMS, OWN_ITEMS, 74)
        return request(w, 27, fget(w, F_ITEMS), fget(w, F_INDEX), 1, 0, 0, 49)
    if phase == 49:
        if get(w, PROFILE) == 31410:
            return request(w, 63, answer(w, 0), field(w, F_ITEM), field(w, F_FLAGS), OWN_ITEM, 0, 50)
        fput(w, F_ITEM, answer(w, 0))
        fput(w, F_PHASE, 50)
        return 4
    if phase == 50:
        return request(w, 55, fget(w, F_ITEM), 0, 0, 0, 0, 51)
    if phase == 51:
        if (answer(w, 0) & 16) == 0:
            return request(w, 10, get(w, VALUE_ERROR), ITEMS_MESSAGE, ITEMS_MESSAGE_LENGTH, 0, 0, 900)
        return request(w, 26, fget(w, F_ITEM), 2, 0, 0, 0, 52)
    if phase == 52:
        if answer(w, 0) != 2:
            return request(w, 10, get(w, VALUE_ERROR), ITEMS_MESSAGE, ITEMS_MESSAGE_LENGTH, 0, 0, 900)
        return request(w, 27, fget(w, F_ITEM), 0, 2, 0, 0, 53)
    if phase == 53:
        fput(w, F_KEY, answer(w, 0))
        return request(w, 27, fget(w, F_ITEM), 1, 2, 0, 0, 54)
    if phase == 54:
        fput(w, F_VALUE, answer(w, 0))
        return request(w, 55, fget(w, F_KEY), 0, 0, 0, 0, 55)
    if phase == 55:
        kind = answer(w, 0)
        if (kind & 1) != 0:
            return request(w, 63, fget(w, F_KEY), field(w, F_KEYSTR), field(w, F_FLAGS), OWN_KEYSTR, 0, 58)
        if (kind & 4) != 0:
            return request(w, 200, fget(w, F_KEY), 2, 0, 0, 0, 56)
        if (kind & 448) != 0:
            return request(w, 200, fget(w, F_KEY), 3, 0, 0, 0, 56)
        if (kind & 2) != 0:
            return request(w, 200, fget(w, F_KEY), 1, 0, 0, 0, 56)
        return request(w, 65, get(w, TYPE_ERROR), KEY_ERROR_MESSAGE, fget(w, F_KEY), 0, 0, 900)
    if phase == 56:
        if get(w, CONTEXT_SLOT) == 0:
            return failed(w)
        return adopt(w, F_KEYSTR, OWN_KEYSTR, 58)
    if phase == 58:
        status = reserve(o, w, 2 + 2 * fget(w, F_LEVEL), 58)
        if status != 4:
            return status
        if fget(w, F_FIRST) == 0:
            append_point(o, w, 44)
        fput(w, F_FIRST, 0)
        newline(o, w, fget(w, F_LEVEL))
        if get(w, FAST_STRING_ENCODER) == 0:
            return request(w, 32, get(w, STRING_ENCODER), fget(w, F_KEYSTR), 0, 0, 0, 59)
        return request(w, 200, fget(w, F_KEYSTR), 0, 1, 0, 0, 59)
    if phase == 59:
        # Validation belongs to encoder_encode_string, then the caller drops
        # keystr, then it accumulates the encoded result.  Phases 5/11/13/14/15
        # retain this order on both success and wrong-type result failure.
        fput(w, F_AFTER_COPY, 61)
        fput(w, F_PHASE, 5)
        return 4
    if phase == 61:
        status = reserve(o, w, 2, 61)
        if status != 4:
            return status
        append_point(o, w, 58)
        append_point(o, w, 32)
        fput(w, F_PHASE, 65)
        return 4
    if phase == 65:
        return push(w, fget(w, F_VALUE), fget(w, F_LEVEL), 62, 65)
    if phase == 62:
        if fget(w, F_CHILD_STATUS) != 0:
            return request(w, 203, 2, fget(w, F_OBJECT), fget(w, F_KEY), 0, 0, 63)
        fput(w, F_PHASE, 63)
        return 4
    if phase == 63:
        if (fget(w, F_FLAGS) & OWN_ITEM) != 0:
            return drop(w, F_ITEM, OWN_ITEM, 64)
        fput(w, F_ITEM, 0)
        fput(w, F_PHASE, 64)
        return 4
    if phase == 64:
        fput(w, F_KEY, 0)
        fput(w, F_VALUE, 0)
        if fget(w, F_CHILD_STATUS) != 0:
            return failed(w)
        fput(w, F_INDEX, fget(w, F_INDEX) + 1)
        fput(w, F_PHASE, 47)
        return 4
    if phase == 74:
        return unmark(w, 75)
    if phase == 75:
        status = reserve(o, w, 2 + 2 * fget(w, F_LEVEL), 75)
        if status != 4:
            return status
        if fget(w, F_FIRST) == 0:
            fput(w, F_LEVEL, fget(w, F_LEVEL) - 1)
            newline(o, w, fget(w, F_LEVEL))
        append_point(o, w, 125)
        return leave_success(w)
    return ABI

def default_node(w:mutbuf, phase:u64) -> u64:
    if phase == 80:
        return request(w, 32, get(w, DEFAULT_FN), fget(w, F_OBJECT), 0, 0, 0, 81)
    if phase == 81:
        if get(w, CONTEXT_SLOT) == 0:
            return failed(w)
        return adopt(w, F_NEWOBJ, OWN_NEWOBJ, 82)
    if phase == 82:
        return request(w, 66, RECURSION_MESSAGE, field(w, F_FLAGS), RECURSIVE, 0, 0, 83)
    if phase == 83:
        if get(w, REPLY_ERROR) != 0:
            return failed(w)
        return push(w, fget(w, F_NEWOBJ), fget(w, F_LEVEL), 84, 83)
    if phase == 84:
        return request(w, 67, field(w, F_FLAGS), RECURSIVE, 0, 0, 0, 85)
    if phase == 85:
        return drop(w, F_NEWOBJ, OWN_NEWOBJ, 86)
    if phase == 86:
        if fget(w, F_CHILD_STATUS) != 0:
            return request(w, 203, 0, fget(w, F_OBJECT), 0, 0, 0, 900)
        return unmark(w, 87)
    if phase == 87:
        return pop(w, 0)
    return ABI

def marker_node(w:mutbuf, phase:u64) -> u64:
    if phase == 110:
        if get(w, CONTEXT_SLOT) == 0:
            return failed(w)
        return adopt(w, F_IDENT, OWN_IDENT, 111)
    if phase == 111:
        return request(w, 58, get(w, MARKERS), fget(w, F_IDENT), 0, 0, 0, 112)
    if phase == 112:
        if get(w, REPLY_ERROR) != 0:
            return failed(w)
        if answer(w, 0) != 0:
            return request(w, 10, get(w, VALUE_ERROR), CIRCULAR_MESSAGE, CIRCULAR_MESSAGE_LENGTH, 0, 0, 900)
        return request(w, 59, get(w, MARKERS), fget(w, F_IDENT), fget(w, F_OBJECT), 0, 0, 113)
    if phase == 113:
        if get(w, REPLY_ERROR) != 0:
            return failed(w)
        fput(w, F_PHASE, fget(w, F_MARKER_RETURN))
        return 4
    if phase == 120:
        if get(w, REPLY_ERROR) != 0:
            return failed(w)
        return drop(w, F_IDENT, OWN_IDENT, 121)
    if phase == 121:
        fput(w, F_PHASE, fget(w, F_MARKER_RETURN))
        return 4
    return ABI

def unwind_node(w:mutbuf, phase:u64) -> u64:
    if phase == 800:
        return pop(w, 0)
    if phase != 900:
        return ABI
    if get(w, CONTEXT_SLOT) != 0:
        return request(w, 6, 0, 0, 0, 0, 0, 900)
    flags = fget(w, F_FLAGS)
    if fget(w, F_KIND) == 3 and (flags & RECURSIVE) != 0:
        return request(w, 67, field(w, F_FLAGS), RECURSIVE, 0, 0, 0, 900)
    if (flags & OWN_ENCODED) != 0:
        return drop(w, F_ENCODED, OWN_ENCODED, 900)
    if (flags & OWN_KEYSTR) != 0:
        return drop(w, F_KEYSTR, OWN_KEYSTR, 900)
    if (flags & OWN_ITEM) != 0:
        return drop(w, F_ITEM, OWN_ITEM, 900)
    if (flags & OWN_NEWOBJ) != 0:
        return drop(w, F_NEWOBJ, OWN_NEWOBJ, 900)
    if fget(w, F_KIND) == 1:
        if (flags & OWN_IDENT) != 0:
            return drop(w, F_IDENT, OWN_IDENT, 900)
        if (flags & OWN_ITEMS) != 0:
            return drop(w, F_ITEMS, OWN_ITEMS, 900)
    else:
        if (flags & OWN_ITEMS) != 0:
            return drop(w, F_ITEMS, OWN_ITEMS, 900)
        if (flags & OWN_IDENT) != 0:
            return drop(w, F_IDENT, OWN_IDENT, 900)
    if (flags & RECURSIVE) != 0:
        return request(w, 67, field(w, F_FLAGS), RECURSIVE, 0, 0, 0, 900)
    if flags != 0:
        return ABI
    return pop(w, 1)

def marker(w:mutbuf, following:u64) -> u64:
    fput(w, F_MARKER_RETURN, following)
    if get(w, MARKERS) == 0:
        fput(w, F_PHASE, following)
        return 4
    return request(w, 57, fget(w, F_OBJECT), 0, 0, 0, 0, 110)

def unmark(w:mutbuf, following:u64) -> u64:
    fput(w, F_MARKER_RETURN, following)
    if (fget(w, F_FLAGS) & OWN_IDENT) == 0:
        fput(w, F_PHASE, following)
        return 4
    return request(w, 60, get(w, MARKERS), fget(w, F_IDENT), 0, 0, 0, 120)

def failed(w:mutbuf) -> u64:
    fput(w, F_PHASE, 900)
    return 4

def leave_success(w:mutbuf) -> u64:
    if (fget(w, F_FLAGS) & RECURSIVE) != 0:
        return request(w, 67, field(w, F_FLAGS), RECURSIVE, 0, 0, 0, 800)
    return pop(w, 0)

def adopt(w:mutbuf, slot:u64, mask:u64, phase:u64) -> u64:
    return request(w, 62, field(w, slot), field(w, F_FLAGS), mask, 0, 0, phase)

def drop(w:mutbuf, slot:u64, mask:u64, phase:u64) -> u64:
    return request(w, 64, field(w, slot), field(w, F_FLAGS), mask, 0, 0, phase)

def reserve(o:mutbuf, w:mutbuf, count:u64, phase:u64) -> u64:
    current = get(w, OUTPUT_COUNT)
    if current > 2305843009213693951 or count > 2305843009213693951 - current:
        return request(w, 20, 0, 0, 0, 0, 0, 900)
    required = (current + count) * 4
    if required > length(o):
        return request(w, 202, required, 0, 0, 0, 0, phase)
    return 4

def push(w:mutbuf, object:u64, level:u64, following:u64, retry:u64) -> u64:
    top = get(w, TOP)
    if top > 9223372036854775807 - FRAME_BYTES * 2:
        return request(w, 20, 0, 0, 0, 0, 0, 900)
    next = top + FRAME_BYTES
    if next + FRAME_BYTES > length(w):
        return request(w, 204, next + FRAME_BYTES, 0, 0, 0, 0, retry)
    fput(w, F_PHASE, following)
    put(w, TOP, next)
    clear_frame(w, next)
    fput(w, F_OBJECT, object)
    fput(w, F_LEVEL, level)
    fput(w, F_PHASE, 1)
    return 4

def pop(w:mutbuf, status:u64) -> u64:
    if fget(w, F_FLAGS) != 0:
        return ABI
    top = get(w, TOP)
    if top == FRAME_BASE:
        put(w, TOP, 0)
        put(w, FINAL_STATUS, status + 1)
        if status != 0:
            put(w, OUTPUT_COUNT, 0)
        return 4
    if top < FRAME_BASE + FRAME_BYTES:
        return ABI
    put(w, TOP, top - FRAME_BYTES)
    fput(w, F_CHILD_STATUS, status)
    return 4

def clear_frame(w:mutbuf, at:u64) -> u64:
    fill_range(w, at, FRAME_BYTES, 0)
    return 0

def request(w:mutbuf, operation:u64, a:u64, b:u64, c:u64, d:u64, e:u64, phase:u64) -> u64:
    if get(w, PENDING) != 0 or get(w, SEQUENCE) == 18446744073709551615:
        return ABI
    put(w, SEQUENCE, get(w, SEQUENCE) + 1)
    put(w, OPERATION, operation)
    put(w, ARGUMENTS, a)
    put(w, ARGUMENTS + 8, b)
    put(w, ARGUMENTS + 16, c)
    put(w, ARGUMENTS + 24, d)
    put(w, ARGUMENTS + 32, e)
    fput(w, F_PHASE, phase)
    put(w, PENDING, 1)
    return 2

def field(w:mutbuf, offset:u64) -> u64:
    return get(w, TOP) + offset

def fget(w:mutbuf, offset:u64) -> u64:
    return get(w, field(w, offset))

def fput(w:mutbuf, offset:u64, value:u64) -> u64:
    return put(w, field(w, offset), value)

def answer(w:mutbuf, index:u64) -> u64:
    return get(w, ANSWER + index * 8)

def point(o:mutbuf, index:u64, value:u64) -> u64:
    store(o, index * 4, value & 255)
    store(o, index * 4 + 1, (value >> 8) & 255)
    store(o, index * 4 + 2, (value >> 16) & 255)
    store(o, index * 4 + 3, (value >> 24) & 255)
    return 0

def append_point(o:mutbuf, w:mutbuf, value:u64) -> u64:
    cursor = get(w, OUTPUT_COUNT)
    point(o, cursor, value)
    put(w, OUTPUT_COUNT, cursor + 1)
    return 0

def newline(o:mutbuf, w:mutbuf, level:u64) -> u64:
    append_point(o, w, 10)
    index = 0
    while index < level * 2:
        append_point(o, w, 32)
        index = index + 1
    return 0

def append_constant(o:mutbuf, w:mutbuf, which:u64) -> u64:
    if which == 0:
        append_point(o, w, 110)
        append_point(o, w, 117)
        append_point(o, w, 108)
        append_point(o, w, 108)
    elif which == 1:
        append_point(o, w, 116)
        append_point(o, w, 114)
        append_point(o, w, 117)
        append_point(o, w, 101)
    else:
        append_point(o, w, 102)
        append_point(o, w, 97)
        append_point(o, w, 108)
        append_point(o, w, 115)
        append_point(o, w, 101)
    return 0

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, at + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0
'''


def source_program():
    constants = dict(SYMBOLS)
    body = ['def literals(w:mutbuf) -> u64:']
    for name, raw in LITERALS.items():
        constants[name + '_LENGTH'] = len(raw)
        padded = raw + bytes((-len(raw)) % 8)
        for start in range(0, len(padded), 8):
            body += [f'    put(w, {SYMBOLS[name] + start}, {int.from_bytes(padded[start:start + 8], "little")})']
    body += ['    return 0']

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node

    tree = ast.parse(SOURCE + '\n' + '\n'.join(body))
    return ast.unparse(ast.fix_missing_locations(Constants().visit(tree))) + '\n'


def document():
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
                                  'module': 'cli_json_cgraph', 'functions': functions})


if __name__ == '__main__':
    import argparse
    from hepta.hia_agent_assembly import render_assembly
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        stream.write(render_assembly(document()))
