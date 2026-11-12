"""HIA continuation for the original encoder's second object observation.

Opaque Python type facts and C sequence/mapping primitives are transport.
Classification order, active identities, traversal, scalar formatting requests,
JSON emission and final byte admission belong to this native program.
"""

BODY = r'''
def norm_encode_start(w:mutbuf, o:mutbuf) -> u32:
    put(w, H_STAGE, 3)
    put(w, H_OUT_CURSOR, 64)
    put(w, H_E_DEPTH, 0)
    put(w, H_E_OVERFLOW, 0)
    put(w, H_E_SURROGATE, 0)
    put(w, H_EXPECT_COUNT, 0)
    put(w, H_E_SCOPE_CURRENT, 0)
    return norm_encode_value(w, o, 0, 0, 0)

def norm_encode_begin_scope(w:mutbuf, o:mutbuf, phase:u64) -> u32:
    sequence = get(w, H_E_SCOPE_SEQUENCE)
    if sequence == NONE:
        return BAD_ABI
    put(w, H_PHASE, phase)
    return norm_issue(w, o, 50, 0, sequence + 1, get(w, H_E_SCOPE_CURRENT))

def norm_encode_end_scope(w:mutbuf, o:mutbuf, phase:u64) -> u32:
    current = get(w, H_E_SCOPE_CURRENT)
    if current == 0:
        return BAD_ABI
    parent = 0
    depth = get(w, H_E_DEPTH)
    if depth != 0:
        parent = get(w, ENCODE_STACK_BASE + (depth - 1) * 96 + 80)
    if parent == current:
        return BAD_ABI
    put(w, H_PHASE, phase)
    return norm_issue(w, o, 51, 0, current, parent)

def norm_encode_value(w:mutbuf, o:mutbuf, node:u64, handle:u64, key:u64) -> u32:
    put(w, H_E_NODE, node)
    put(w, H_E_HANDLE, handle)
    put(w, H_E_KEY, key)
    return norm_encode_begin_scope(w, o, 203)

def norm_encode_abort(w:mutbuf, o:mutbuf, code:u64) -> u32:
    put(w, H_E_PENDING_ERROR, code)
    return norm_encode_abort_step(w, o)

def norm_encode_abort_step(w:mutbuf, o:mutbuf) -> u32:
    current = get(w, H_E_SCOPE_CURRENT)
    if current == 0:
        return norm_error_final(w, o, get(w, H_E_PENDING_ERROR))
    depth = get(w, H_E_DEPTH)
    if depth != 0:
        frame = ENCODE_STACK_BASE + (depth - 1) * 96
        if get(w, frame + 80) == current:
            # Only a value-child error receives a parent note. Key encoding,
            # items capture, sorting and tuple-shape failures do not set this
            # permission. Consume it before the hosted diagnostic can run.
            if get(w, frame + 72) != 0:
                put(w, frame + 72, 0)
                if get(w, H_E_PENDING_ERROR) == 20 and get(w, H_PYTHON_NOTES) != 0:
                    mode = get(w, frame)
                    error = get(w, H_FOREIGN_ERROR)
                    if error == 0 or get(w, H_E_NOTE_OLD_ERROR) != 0:
                        return BAD_ABI
                    put(w, H_E_NOTE_OLD_ERROR, error)
                    put(w, H_PHASE, 237)
                    if mode == 2 or mode == 4:
                        if get(w, frame + 88) != 1 or get(w, frame + 64) == 0:
                            return BAD_ABI
                        return norm_issue(w, o, 63, error, get(w, frame + 16), get(w, frame + 64))
                    if (mode != 1 and mode != 3) or get(w, frame + 32) == 0:
                        return BAD_ABI
                    return norm_issue(w, o, 64, error, get(w, frame + 16), get(w, frame + 32) - 1)
            if get(w, frame + 88) != 0:
                # The pin protects only this already acquired key identity.
                # Its release is a separate consumed foreign observation.
                put(w, frame + 88, 0)
                put(w, H_PHASE, 241)
                return norm_issue(w, o, 66, get(w, frame + 64), current, 0)
            put(w, H_E_DEPTH, depth - 1)
    return norm_encode_end_scope(w, o, 208)

def norm_encode_visit(w:mutbuf, o:mutbuf, node:u64, handle:u64, key:u64) -> u32:
    put(w, H_E_NODE, node)
    put(w, H_E_KEY, key)
    if node != NONE:
        at = norm_record(node)
        if get(w, at + 104) == 1:
            kind = get(w, at)
            if key != 0 or (kind != 5 and kind != 6):
                return BAD_ABI
            if kind == 6:
                norm_sort(w, node)
            return norm_encode_push(w, o, choose(kind == 5, 1, 2), node, 0, 0)
        handle = get(w, at + 8)
    if handle == 0:
        return BAD_ABI
    put(w, H_E_HANDLE, handle)
    put(w, H_PHASE, 201)
    return norm_issue(w, o, 22, handle, 0, 0)

def norm_encode_push(w:mutbuf, o:mutbuf, mode:u64, node:u64, handle:u64, capture:u64) -> u32:
    depth = get(w, H_E_DEPTH)
    frame = ENCODE_STACK_BASE + depth * 96
    if frame + 96 > length(w):
        put(w, H_E_PUSH_MODE, mode)
        put(w, H_E_NODE, node)
        put(w, H_E_HANDLE, handle)
        put(w, H_E_CAPTURE, capture)
        put(w, H_PHASE, 200)
        return norm_issue(w, o, 37, 0, frame + 96, length(w))
    fill_range(w, frame, 96, 0)
    put(w, frame, mode)
    put(w, frame + 8, node)
    put(w, frame + 16, handle)
    put(w, frame + 24, capture)
    put(w, frame + 40, NONE)
    put(w, frame + 48, NONE)
    put(w, frame + 80, get(w, H_E_SCOPE_CURRENT))
    if get(w, H_E_SCOPE_CURRENT) == 0:
        return BAD_ABI
    if mode == 1 or mode == 2:
        put(w, frame + 40, get(w, norm_record(node) + 40))
    put(w, H_E_DEPTH, depth + 1)
    norm_emit_byte(w, o, choose(mode == 1 or mode == 3, 91, 123))
    return norm_schedule(w, 250, 0)

def norm_encode_cycle(w:mutbuf, handle:u64) -> u64:
    depth = get(w, H_E_DEPTH)
    index = 0
    while index < depth:
        frame = ENCODE_STACK_BASE + index * 96
        if get(w, frame) >= 3 and get(w, frame + 16) == handle:
            return 1
        index = index + 1
    return 0

def norm_encode_close(w:mutbuf, o:mutbuf) -> u32:
    depth = get(w, H_E_DEPTH)
    if depth == 0:
        return BAD_ABI
    mode = get(w, ENCODE_STACK_BASE + (depth - 1) * 96)
    norm_emit_byte(w, o, choose(mode == 1 or mode == 3, 93, 125))
    put(w, H_E_DEPTH, depth - 1)
    return norm_encode_end_scope(w, o, 204)

def norm_encode_next(w:mutbuf, o:mutbuf) -> u32:
    depth = get(w, H_E_DEPTH)
    if depth == 0:
        # Encoding first visits the complete graph. UTF-8 conversion follows
        # it, and only then does the public final-wire size check run.
        if get(w, H_E_SURROGATE) != 0:
            put(w, H_PHASE, 235)
            return norm_issue(w, o, 60, 0, get(w, H_OUT_CURSOR) - 64, 0)
        if get(w, H_E_OVERFLOW) != 0:
            return norm_error(w, o, 1)
        return norm_mat_start(w, o, get(w, H_OUT_CURSOR) - 64)
    frame = ENCODE_STACK_BASE + (depth - 1) * 96
    mode = get(w, frame)
    index = get(w, frame + 32)
    if get(w, frame + 72) != 0:
        put(w, frame + 72, 0)
        if get(w, frame + 88) != 0:
            put(w, frame + 88, 0)
            put(w, H_PHASE, 240)
            return norm_issue(w, o, 66, get(w, frame + 64), get(w, frame + 80), 0)
    if get(w, frame + 88) != 0:
        return BAD_ABI
    needed = get(w, H_OUT_CURSOR) + 32768
    if needed > length(o):
        return norm_encode_output_room(w, o, needed, 1)
    if mode == 1 or mode == 2:
        child = get(w, frame + 40)
        if child == NONE:
            return norm_encode_close(w, o)
        record = norm_record(child)
        put(w, frame + 40, get(w, record + 24))
        put(w, frame + 32, index + 1)
        if index != 0:
            norm_emit_byte(w, o, 44)
        if mode == 1:
            put(w, frame + 72, 1)
            return norm_encode_value(w, o, child, 0, 0)
        put(w, frame + 48, child)
        put(w, frame + 56, 0)
        put(w, frame + 64, get(w, record + 64))
        return norm_encode_value(w, o, NONE, get(w, record + 64), 1)
    return norm_encode_begin_scope(w, o, 205)

def norm_encode_output_room(w:mutbuf, o:mutbuf, needed:u64, resume:u64) -> u32:
    if needed <= length(o) or resume < 1 or resume > 3:
        return BAD_ABI
    # This is physical storage for the original complete Unicode result, not
    # a larger public byte budget. Native final admission still uses MAX_BYTES.
    put(w, H_E_OUTPUT_RESUME, resume)
    put(w, H_PHASE, 234)
    return norm_issue(w, o, 61, 0, needed, get(w, H_OUT_CURSOR))

def norm_encode_scalar_done(w:mutbuf, o:mutbuf) -> u32:
    if get(w, H_E_KEY) != 0:
        depth = get(w, H_E_DEPTH)
        if depth == 0:
            return BAD_ABI
        frame = ENCODE_STACK_BASE + (depth - 1) * 96
        if get(w, frame) != 2 and get(w, frame) != 4:
            return BAD_ABI
        norm_emit_byte(w, o, 58)
        if get(w, H_PYTHON_NOTES) != 0:
            if get(w, frame + 64) == 0 or get(w, frame + 88) != 0:
                return BAD_ABI
            put(w, H_PHASE, 239)
            return norm_issue(w, o, 65, get(w, frame + 64), get(w, frame + 80), 0)
        put(w, frame + 72, 1)
        return norm_encode_visit(w, o, get(w, frame + 48), get(w, frame + 56), 0)
    return norm_encode_end_scope(w, o, 204)

def norm_encode_kind(w:mutbuf, o:mutbuf, facts:u64, constant:u64) -> u32:
    key = get(w, H_E_KEY)
    kind = 8
    if key == 0 and constant < 3:
        kind = constant
    else:
        if (facts & 1) != 0:
            kind = 4
        else:
            if key != 0 and (facts & 4) != 0:
                kind = 9
            else:
                if constant < 3:
                    kind = constant
                else:
                    if (facts & 2) != 0:
                        kind = 3
                    else:
                        if (facts & 4) != 0:
                            kind = 9
                        else:
                            if (facts & 24) != 0:
                                kind = 5
                            else:
                                if (facts & 32) != 0:
                                    kind = 6
    put(w, H_E_KIND, kind)
    if kind < 3:
        if key != 0:
            norm_emit_byte(w, o, 34)
        norm_literal(w, o, kind)
        if key != 0:
            norm_emit_byte(w, o, 34)
        return norm_encode_scalar_done(w, o)
    handle = get(w, H_E_HANDLE)
    if kind == 4:
        put(w, H_PHASE, 220)
        return norm_issue(w, o, 23, handle, 4, 0)
    if kind == 3:
        put(w, H_PHASE, 230)
        return norm_issue(w, o, 23, handle, 3, 0)
    if kind == 9:
        put(w, H_PHASE, 225)
        return norm_issue(w, o, 25, handle, 0, 0)
    if key != 0:
        return norm_encode_cause(w, o, 2, handle)
    if kind == 5:
        put(w, H_PHASE, 210)
        return norm_issue(w, o, 28, handle, 0, 0)
    if kind == 6:
        put(w, H_PHASE, 211)
        return norm_issue(w, o, 23, handle, 6, 0)
    put(w, H_PHASE, 202)
    return norm_issue(w, o, 33, handle, 0, 0)

def norm_encode_string_next(w:mutbuf, o:mutbuf) -> u32:
    count = get(w, H_E_STRING_LENGTH) - get(w, H_E_STRING_OFFSET)
    if count == 0:
        norm_emit_byte(w, o, 34)
        return norm_encode_scalar_done(w, o)
    if count > 4096:
        count = 4096
    needed = get(w, H_OUT_CURSOR) + count * 6 + 1
    if needed > length(o):
        return norm_encode_output_room(w, o, needed, 2)
    put(w, H_PHASE, 221)
    return norm_issue(w, o, 24, get(w, H_E_HANDLE), get(w, H_E_STRING_OFFSET), count)

def norm_encode_point(w:mutbuf, o:mutbuf, point:u64) -> u64:
    if point < 32:
        norm_emit_byte(w, o, 92)
        escape = 0
        if point == 8:
            escape = 98
        if point == 9:
            escape = 116
        if point == 10:
            escape = 110
        if point == 12:
            escape = 102
        if point == 13:
            escape = 114
        if escape != 0:
            return norm_emit_byte(w, o, escape)
        norm_emit_byte(w, o, 117)
        norm_emit_byte(w, o, 48)
        norm_emit_byte(w, o, 48)
        norm_emit_byte(w, o, norm_hex(point >> 4))
        return norm_emit_byte(w, o, norm_hex(point & 15))
    if point == 34 or point == 92:
        norm_emit_byte(w, o, 92)
    if point < 128:
        return norm_emit_byte(w, o, point)
    if point < 2048:
        norm_emit_byte(w, o, 192 | (point >> 6))
        return norm_emit_byte(w, o, 128 | (point & 63))
    if point < 65536:
        if point >= 55296 and point <= 57343:
            put(w, H_E_SURROGATE, 1)
        norm_emit_byte(w, o, 224 | (point >> 12))
        norm_emit_byte(w, o, 128 | ((point >> 6) & 63))
        return norm_emit_byte(w, o, 128 | (point & 63))
    norm_emit_byte(w, o, 240 | (point >> 18))
    norm_emit_byte(w, o, 128 | ((point >> 12) & 63))
    norm_emit_byte(w, o, 128 | ((point >> 6) & 63))
    return norm_emit_byte(w, o, 128 | (point & 63))

def norm_encode_integer_request(w:mutbuf, o:mutbuf, limit:u64) -> u32:
    bits = get(w, H_E_BITS)
    put(w, H_E_LIMIT, limit)
    if limit != 0 and limit < 4611686018427387904 and bits > limit * 4:
        return norm_encode_cause(w, o, 3, get(w, H_E_HANDLE))
    # Even a later byte-limit refusal must retain complete Unicode text: a
    # later surrogate's original UnicodeEncodeError owns that entire text.
    output_needed = get(w, H_OUT_CURSOR) + bits // 3 + 4
    if output_needed > length(o):
        return norm_encode_output_room(w, o, output_needed, 3)
    size = (bits + 8) // 8
    binary = ENCODE_STACK_BASE + get(w, H_E_DEPTH) * 96 + 16
    decimal = (binary + size + 23) & 18446744073709551608
    needed = decimal + (bits // 29 + 2) * 8 + 16
    put(w, H_E_BINARY, binary)
    put(w, H_E_DECIMAL, decimal)
    put(w, H_E_INTEGER_BYTES, size)
    if needed > length(w):
        put(w, H_PHASE, 232)
        return norm_issue(w, o, 37, 0, needed, binary)
    put(w, H_PHASE, 233)
    return norm_issue(w, o, 38, get(w, H_E_HANDLE), size, 0)

def norm_encode_integer_bytes(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = get(w, H_E_INTEGER_BYTES)
    if size == 0 or length(s) != 128 + size:
        return BAD_ABI
    binary = get(w, H_E_BINARY)
    decimal = get(w, H_E_DECIMAL)
    negative = choose(byte(s, 128 + size - 1) >= 128, 1, 0)
    carry = negative
    index = 0
    while index < size:
        value = byte(s, 128 + index)
        if negative != 0:
            value = (value ^ 255) + carry
            carry = choose(value > 255, 1, 0)
            value = value & 255
        store(w, binary + index, value)
        index = index + 1
    fill_range(w, binary + size, 8, 0)
    while size != 0 and byte(w, binary + size - 1) == 0:
        size = size - 1
    actual_bits = 0
    if size != 0:
        actual_bits = (size - 1) * 8
        high = byte(w, binary + size - 1)
        while high != 0:
            actual_bits = actual_bits + 1
            high = high >> 1
    if actual_bits != get(w, H_E_BITS):
        return BAD_ABI
    count = 1
    put(w, decimal, 0)
    words = (size + 3) // 4
    while words != 0:
        words = words - 1
        carry = get(w, binary + words * 4) & 4294967295
        index = 0
        while index < count:
            value = get(w, decimal + index * 8) * 4294967296 + carry
            put(w, decimal + index * 8, value % 1000000000)
            carry = value // 1000000000
            index = index + 1
        while carry != 0:
            put(w, decimal + count * 8, carry % 1000000000)
            carry = carry // 1000000000
            count = count + 1
    high = get(w, decimal + (count - 1) * 8)
    digits = 1
    while high >= 10:
        high = high // 10
        digits = digits + 1
    digits = (count - 1) * 9 + digits
    if get(w, H_E_LIMIT) != 0 and digits > get(w, H_E_LIMIT):
        return norm_encode_cause(w, o, 3, get(w, H_E_HANDLE))
    if get(w, H_E_KEY) != 0:
        norm_emit_byte(w, o, 34)
    if negative != 0:
        norm_emit_byte(w, o, 45)
    leading = True
    while count != 0:
        count = count - 1
        value = get(w, decimal + count * 8)
        divisor = 100000000
        if leading:
            while divisor > 1 and divisor > value:
                divisor = divisor // 10
            leading = False
        while divisor != 0:
            norm_emit_byte(w, o, 48 + value // divisor)
            value = value % divisor
            divisor = divisor // 10
    if get(w, H_E_KEY) != 0:
        norm_emit_byte(w, o, 34)
    return norm_encode_scalar_done(w, o)

def norm_encode_container_ack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, H_PHASE)
    status = norm_read(s, 48, 8)
    a = norm_read(s, 56, 8)
    b = norm_read(s, 64, 8)
    if length(s) != 128:
        return BAD_ABI
    if phase == 212 or phase == 213:
        if status == 0:
            return norm_encode_end_scope(w, o, 206)
        if status != 1 or a == 0 or get(w, H_E_DEPTH) == 0:
            return BAD_ABI
        frame = ENCODE_STACK_BASE + (get(w, H_E_DEPTH) - 1) * 96
        index = get(w, frame + 32)
        put(w, frame + 32, index + 1)
        if index != 0:
            norm_emit_byte(w, o, 44)
        if phase == 212:
            put(w, frame + 72, 1)
            return norm_encode_visit(w, o, NONE, a, 0)
        put(w, H_PHASE, 214)
        return norm_issue(w, o, 32, a, 0, 0)
    if status != 0:
        return BAD_ABI
    if phase == 210:
        if a == 0:
            return BAD_ABI
        if b == 0:
            norm_emit_byte(w, o, 91)
            norm_emit_byte(w, o, 93)
            return norm_encode_scalar_done(w, o)
        if norm_encode_cycle(w, get(w, H_E_HANDLE)) != 0:
            return norm_encode_cause(w, o, 1, 0)
        return norm_encode_push(w, o, 3, NONE, get(w, H_E_HANDLE), a)
    if phase == 211:
        if a == 0:
            norm_emit_byte(w, o, 123)
            norm_emit_byte(w, o, 125)
            return norm_encode_scalar_done(w, o)
        if norm_encode_cycle(w, get(w, H_E_HANDLE)) != 0:
            return norm_encode_cause(w, o, 1, 0)
        put(w, H_PHASE, 215)
        return norm_issue(w, o, 30, get(w, H_E_HANDLE), 0, 0)
    if phase == 214:
        if norm_read(s, 72, 8) != 2:
            return norm_encode_cause(w, o, 4, get(w, H_REQUEST_HANDLE))
        if a == 0 or b == 0:
            return BAD_ABI
        frame = ENCODE_STACK_BASE + (get(w, H_E_DEPTH) - 1) * 96
        put(w, frame + 48, NONE)
        put(w, frame + 56, b)
        put(w, frame + 64, a)
        return norm_encode_visit(w, o, NONE, a, 1)
    if phase == 215:
        if a == 0:
            return BAD_ABI
        put(w, H_E_CAPTURE, a)
        put(w, H_PHASE, 216)
        return norm_issue(w, o, 31, a, 0, 0)
    if phase == 216:
        if a != 0:
            return BAD_ABI
        return norm_encode_push(w, o, 4, NONE, get(w, H_E_HANDLE), get(w, H_E_CAPTURE))
    return BAD_ABI

def norm_encode_scalar_ack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, H_PHASE)
    if norm_read(s, 48, 8) != 0:
        return BAD_ABI
    if phase == 221:
        count = get(w, H_REQUEST_B)
        if count == 0 or count > 4096 or length(s) != 128 + count * 4:
            return BAD_ABI
        index = 0
        while index < count:
            point = norm_read(s, 128 + index * 4, 4)
            if point > 1114111:
                return BAD_ABI
            norm_encode_point(w, o, point)
            index = index + 1
        put(w, H_E_STRING_OFFSET, get(w, H_E_STRING_OFFSET) + count)
        return norm_encode_string_next(w, o)
    if phase == 227:
        size = length(s) - 128
        if size == 0 or size > 32:
            return BAD_ABI
        if get(w, H_E_KEY) != 0:
            norm_emit_byte(w, o, 34)
        index = 0
        while index < size:
            norm_emit_byte(w, o, byte(s, 128 + index))
            index = index + 1
        if get(w, H_E_KEY) != 0:
            norm_emit_byte(w, o, 34)
        return norm_encode_scalar_done(w, o)
    if phase == 233:
        return norm_encode_integer_bytes(s, o, w)
    if length(s) != 128:
        return BAD_ABI
    a = norm_read(s, 56, 8)
    if phase == 220:
        put(w, H_E_STRING_LENGTH, a)
        put(w, H_E_STRING_OFFSET, 0)
        norm_emit_byte(w, o, 34)
        return norm_encode_string_next(w, o)
    if phase == 225:
        if ((a >> 52) & 2047) == 2047:
            put(w, H_PHASE, 226)
            return norm_issue(w, o, 35, get(w, H_E_HANDLE), 1, 0)
        put(w, H_PHASE, 227)
        return norm_issue(w, o, 26, 0, a, 0)
    if phase == 230:
        put(w, H_E_BITS, a)
        put(w, H_PHASE, 231)
        return norm_issue(w, o, 34, 0, 0, 0)
    if phase == 231:
        if a != 0 and a < 640:
            return BAD_ABI
        return norm_encode_integer_request(w, o, a)
    if phase == 232:
        if a != length(w) or a < get(w, H_REQUEST_A):
            return BAD_ABI
        put(w, H_PHASE, 233)
        return norm_issue(w, o, 38, get(w, H_E_HANDLE), get(w, H_E_INTEGER_BYTES), 0)
    return BAD_ABI

def norm_encode_ack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, H_PHASE)
    if phase >= 210 and phase <= 216:
        return norm_encode_container_ack(s, o, w)
    if phase >= 220 and phase <= 233:
        return norm_encode_scalar_ack(s, o, w)
    if length(s) != 128 or norm_read(s, 48, 8) != 0:
        return BAD_ABI
    if phase == 238 or phase == 241:
        if norm_read(s, 56, 8) != 0 or norm_read(s, 64, 8) != 0 or norm_read(s, 72, 8) != 0:
            return BAD_ABI
        return norm_encode_abort_step(w, o)
    if phase == 240:
        if norm_read(s, 56, 8) != 0 or norm_read(s, 64, 8) != 0 or norm_read(s, 72, 8) != 0:
            return BAD_ABI
        return norm_schedule(w, 250, 0)
    if phase == 239:
        if norm_read(s, 56, 8) != 0 or norm_read(s, 64, 8) != 0 or norm_read(s, 72, 8) != 0 or get(w, H_E_DEPTH) == 0:
            return BAD_ABI
        frame = ENCODE_STACK_BASE + (get(w, H_E_DEPTH) - 1) * 96
        if (get(w, frame) != 2 and get(w, frame) != 4) or get(w, frame + 88) != 0 or get(w, frame + 72) != 0:
            return BAD_ABI
        put(w, frame + 88, 1)
        put(w, frame + 72, 1)
        return norm_encode_visit(w, o, get(w, frame + 48), get(w, frame + 56), 0)
    if phase == 234:
        if norm_read(s, 56, 8) != length(o) or length(o) < get(w, H_REQUEST_A):
            return BAD_ABI
        resume = get(w, H_E_OUTPUT_RESUME)
        if resume == 1:
            return norm_schedule(w, 250, 0)
        if resume == 2:
            return norm_encode_string_next(w, o)
        if resume == 3:
            return norm_encode_integer_request(w, o, get(w, H_E_LIMIT))
        return BAD_ABI
    if phase == 235 or phase == 236:
        # Native-proved error operations cannot return success.
        return BAD_ABI
    if phase == 200:
        if norm_read(s, 56, 8) != length(w) or length(w) < get(w, H_REQUEST_A):
            return BAD_ABI
        return norm_encode_push(w, o, get(w, H_E_PUSH_MODE), get(w, H_E_NODE), get(w, H_E_HANDLE), get(w, H_E_CAPTURE))
    if phase == 203 or phase == 205:
        scope = norm_read(s, 56, 8)
        if scope != get(w, H_REQUEST_A) or scope != get(w, H_E_SCOPE_SEQUENCE) + 1:
            return BAD_ABI
        put(w, H_E_SCOPE_SEQUENCE, scope)
        put(w, H_E_SCOPE_CURRENT, scope)
        if phase == 203:
            return norm_encode_visit(w, o, get(w, H_E_NODE), get(w, H_E_HANDLE), get(w, H_E_KEY))
        if get(w, H_E_DEPTH) == 0:
            return BAD_ABI
        frame = ENCODE_STACK_BASE + (get(w, H_E_DEPTH) - 1) * 96
        put(w, H_PHASE, choose(get(w, frame) == 3, 212, 213))
        return norm_issue(w, o, 29, get(w, frame + 24), get(w, frame + 32), 0)
    if phase == 204 or phase == 206 or phase == 208:
        parent = norm_read(s, 56, 8)
        if parent != get(w, H_REQUEST_B):
            return BAD_ABI
        put(w, H_E_SCOPE_CURRENT, parent)
        if phase == 206:
            return norm_encode_close(w, o)
        if phase == 208:
            return norm_encode_abort_step(w, o)
        return norm_schedule(w, 250, 0)
    if phase == 201:
        facts = norm_read(s, 56, 8)
        constant = norm_read(s, 64, 8)
        if facts > 63 or constant > 3:
            return BAD_ABI
        return norm_encode_kind(w, o, facts, constant)
    return BAD_ABI

def norm_encode_note_ack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    # FormatNote can replace the exception when key repr or note publication
    # itself fails. The primitive returns that actual object, never a message
    # reconstructed in Python. Its original cause/context chain remains held.
    status = norm_read(s, 48, 8)
    new_error = norm_read(s, 56, 8)
    old_error = get(w, H_E_NOTE_OLD_ERROR)
    if length(s) != 128 or (status != 0 and status != 3) or new_error == 0 or old_error == 0 or norm_read(s, 64, 8) != 0 or norm_read(s, 72, 8) != 0:
        return BAD_ABI
    put(w, H_FOREIGN_ERROR, new_error)
    put(w, H_E_PENDING_ERROR, 20)
    put(w, H_E_NOTE_OLD_ERROR, 0)
    if new_error != old_error:
        put(w, H_PHASE, 238)
        return norm_issue(w, o, 67, old_error, 0, 0)
    return norm_encode_abort_step(w, o)

def norm_encode_cause(w:mutbuf, o:mutbuf, kind:u64, handle:u64) -> u32:
    if kind < 1 or kind > 4 or (kind == 1 and handle != 0) or (kind != 1 and handle == 0):
        return BAD_ABI
    put(w, H_PHASE, 236)
    return norm_issue(w, o, 62, handle, kind, 0)
'''
