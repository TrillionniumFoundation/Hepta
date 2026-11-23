"""Project each closed block on independent input generators.

Register lanes form a module over the unsigned 64-bit ring for sums. A run
with one unit in a lane determines its entire contribution by linearity.
Memory enters the sum through unsigned bytes. SAD admits only raw bytes
against the invariant zero register, so its eight components sum linearly.
The word circuit independently checks byte/SAD, carry and OR identities.

Zero scans use OR and whole-lane moves. An arbitrary nonzero input bit has
exactly the same route as the representative in its lane or source byte.
Copies admit only unmodified byte loads and stores. Their basis components
establish every output byte location independently, including overwrite
order. Out-of-range stores fail before the solver sees a candidate.

Class interning retains the ordered machine/reference coefficients. The HIA
solver receives a symbolic choice of classes and checks their word miter.
A mismatched coefficient therefore yields a replayable SAT witness.
"""

SOURCE = '''
def simd_data(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) < 168 or uint(s, 32, 8) != REPLY_MAGIC:
        return 0
    isa = uint(s, 8, 8)
    shape = uint(s, 16, 8)
    role = uint(s, 24, 8)
    span = uint(s, 56, 8)
    if isa < 1 or isa > 3 or shape < 1 or shape > 3 or span == 0 or span > 2048:
        return 0
    if uint(s, 64, 8) != 0 or uint(s, 88, 8) != 1 or uint(s, 96, 8) != 56 or length(s) != 168 + span:
        return 0
    put(w, SD_SPAN, span)
    put(w, SD_ISA, isa)
    put(w, SD_SHAPE, shape)
    put(w, SD_ROLE, role)
    copy_input(s, w, 112, SD_TEXT, span)
    if role >= 30 and role <= 33:
        if span < 94:
            return 0
        if role == 30:
            size = simd_prefix_suffix_partition(w, 0)
        elif role == 31:
            if shape == 3:
                size = simd_copy_guards(w, 0)
            else:
                size = simd_read_guards(w, 0)
        elif role == 32:
            size = simd_initial_registers(w, shape == 3)
        elif shape != 3 and isa != 1:
            size = simd_short_entry(w, 8 << isa)
        else:
            return 0
        return data_output(o, w, size)
    if role == 53 and shape == 3:
        size = simd_source_separation(w, 0)
        return data_output(o, w, size)
    instructions = simd_data_program(w, isa, shape, role)
    if instructions == 0 or instructions > 16:
        return 0
    lanes = 1 << isa
    put(w, SD_LANES, lanes)
    memory = data_extent(isa, role)
    put(w, SD_MEMORY, memory)
    put(w, SD_CLASS_COUNT, 0)
    token = 0
    while token < 80 + memory:
        data_initial(w, token, lanes, role)
        i = 0
        while i < instructions:
            if data_run(w, get(w, SD_OPS + 8 * i), token) == 0:
                return 0
            i = i + 1
        data_compare(w, token)
        token = token + 1
    if get(w, SD_CLASS_COUNT) == 0 or get(w, SD_CLASS_COUNT) > 20:
        return 0
    size = data_formula(w)
    return data_output(o, w, size)

def simd_register_move(w:mutbuf, at:u64) -> u64:
    rex = byte(w, at)
    modrm = byte(w, at + 2)
    if (rex & 248) != 72 or byte(w, at + 1) != 137 or (modrm >> 6) != 3:
        return 256
    src = ((rex & 4) << 1) | ((modrm >> 3) & 7)
    dest = ((rex & 1) << 3) | (modrm & 7)
    return (dest << 4) | src

def simd_initial_registers(w:mutbuf, copy:bool) -> u64:
    at = BINDING + 80
    count = simd_register_move(w, at + choose(copy, 90, 44))
    if count > 255:
        return 0
    put(w, SIMD_COUNT_MOVE_SLOT, count)
    if copy:
        result = simd_register_move(w, at)
        if result > 255:
            return 0
        put(w, SIMD_RESULT_MOVE_SLOT, result)
        return simd_copy_init(w, 0)
    if byte(w, at) != 184:
        return 0
    put(w, SIMD_RESULT_MOVE_SLOT, get(w, at + 1) & 4294967295)
    return simd_read_init(w, 0)

def data_output(o:mutbuf, w:mutbuf, size:u64) -> u64:
    if size < 80 or size > 10320 or size > length(o):
        return 0
    i = 0
    while i < size:
        store(o, i, byte(w, FRAME + i))
        i = i + 1
    return size

def data_extent(isa:u64, role:u64) -> u64:
    if role == 42:
        return 32 << isa
    if role == 43:
        return 8 << isa
    if role == 46:
        return 16
    if role >= 48 and role <= 51:
        return 1 << (role - 48)
    return choose(role == 52, 1, 0)

def initial_vector(w:mutbuf, token:u64, register:u64, lane:u64, lanes:u64, role:u64) -> u64:
    if lane >= lanes:
        return 0
    if register == 2 and get(w, SD_SHAPE) != 3 and role != 40 and role != 41:
        if get(w, SD_ISA) != 1 or (role != 47 and role != 52):
            return 0
    if register == 0 and (role == 46 or role == 47) and lane >= 2:
        return 0
    return choose(token == register * 8 + lane, 1, 0)

def data_initial(w:mutbuf, token:u64, lanes:u64, role:u64) -> u64:
    reg = 0
    while reg < 8:
        lane = 0
        while lane < 8:
            put(w, SD_VEC + 64 * reg + 8 * lane, initial_vector(w, token, reg, lane, lanes, role))
            lane = lane + 1
        reg = reg + 1
    reg = 0
    while reg < 16:
        put(w, SD_GPR + 8 * reg, choose(token == 64 + reg, 1, 0))
        reg = reg + 1
    put(w, SD_RAW_MASK, 0)
    put(w, SD_RAW_GPR, 0)
    extent = get(w, SD_MEMORY)
    i = 0
    while i < extent:
        store(w, SD_DST + i, 0)
        i = i + 1
    return 0

def data_byte(token:u64, disp:u64, size:u64) -> u64:
    start = 80 + disp
    if token < start or token - start >= size:
        return 0
    return 1 << (8 * (token - start))

def data_sad(a:u64, b:u64) -> u64:
    total = 0
    k = 0
    while k < 8:
        x = (a >> (k * 8)) & 255
        y = (b >> (k * 8)) & 255
        total = total + choose(x >= y, x - y, y - x)
        k = k + 1
    return total

def data_get(w:mutbuf, reg:u64, lane:u64) -> u64:
    return get(w, SD_VEC + 64 * reg + 8 * lane)

def data_set(w:mutbuf, reg:u64, lane:u64, val:u64) -> u64:
    return put(w, SD_VEC + 64 * reg + 8 * lane, val)

def data_store(w:mutbuf, disp:u64, size:u64, val:u64) -> u64:
    if disp + size > get(w, SD_MEMORY):
        return 0
    i = 0
    while i < size:
        store(w, SD_DST + disp + i, (val >> (8 * i)) & 255)
        i = i + 1
    return 1

def data_run(w:mutbuf, instruction:u64, token:u64) -> u64:
    op = instruction & 255
    width = (instruction >> 8) & 255
    dst = (instruction >> 16) & 255
    a = (instruction >> 24) & 255
    b = (instruction >> 32) & 255
    raw = get(w, SD_RAW_MASK)
    shape = get(w, SD_SHAPE)
    if shape == 1 and (op == 2 or op == 6 or op == 16):
        return 0
    if shape == 2 and (op == 1 or op == 3 or op == 5 or op == 15):
        return 0
    if shape == 3 and op != 7 and op != 8 and op != 13 and op != 14:
        return 0
    if shape == 1 and dst == 2 and op <= 12 and op != 4 and op != 8 and op != 10:
        return 0
    if op == 3:
        other = choose(a == 2, b, a)
        if shape != 1 or (a != 2 and b != 2) or other == 2 or (raw & (1 << other)) == 0:
            return 0
    if op == 5 and (get(w, SD_SHAPE) != 1 or a != 2):
        return 0
    if op == 4 and a != b:
        return 0
    if op == 8:
        lane = 0
        while lane < width:
            if data_store(w, b + 8 * lane, 8, data_get(w, dst, lane)) == 0:
                return 0
            lane = lane + 1
        return 1
    if op == 10:
        put(w, SD_RAW_GPR, get(w, SD_RAW_GPR) & (0 - 1 - (1 << dst)))
        put(w, SD_GPR + 8 * dst, data_get(w, a, 0))
        return 1
    if op == 13:
        put(w, SD_RAW_GPR, get(w, SD_RAW_GPR) | (1 << dst))
        put(w, SD_GPR + 8 * dst, data_byte(token, b, width))
        return 1
    if op == 14:
        return data_store(w, b, width, get(w, SD_GPR + 8 * dst))
    if op == 15 or op == 16:
        put(w, SD_RAW_GPR, get(w, SD_RAW_GPR) & (0 - 1 - (1 << dst)))
        left = get(w, SD_GPR + 8 * dst)
        right = get(w, SD_GPR + 8 * a)
        put(w, SD_GPR + 8 * dst, choose(op == 15, left + right, left | right))
        return 1
    raw = raw & (0 - 1 - (1 << dst))
    if op == 7 or op == 11 and (get(w, SD_RAW_GPR) & (1 << a)) != 0:
        raw = raw | (1 << dst)
    put(w, SD_RAW_MASK, raw)
    lane = 0
    while lane < width:
        val = data_lane(w, op, a, b, token, lane)
        data_set(w, dst, lane, val)
        lane = lane + 1
    while lane < 8:
        data_set(w, dst, lane, 0)
        lane = lane + 1
    return 1

def data_lane(w:mutbuf, op:u64, a:u64, b:u64, token:u64, lane:u64) -> u64:
    if op == 7:
        return data_byte(token, b + 8 * lane, 8)
    if op == 9:
        return data_get(w, a, (lane + b) & 7)
    if op == 12:
        return choose(lane + b < 2, data_get(w, a, (lane + b) & 7), 0)
    if op == 11:
        return choose(lane == 0, get(w, SD_GPR + a * 8), 0)
    left = data_get(w, a, lane)
    if op == 5 or op == 6:
        right = data_byte(token, b + 8 * lane, 8)
        return choose(op == 5, data_sad(left, right), left | right)
    right = data_get(w, b, lane)
    if op == 1:
        return left + right
    if op == 2:
        return left | right
    return choose(op == 3, data_sad(left, right), left ^ right)

def data_pair(w:mutbuf, a:u64, b:u64) -> u64:
    count = get(w, SD_CLASS_COUNT)
    if count > 20:
        return 0
    i = 0
    while i < count:
        at = SD_CLASSES + i * 16
        if get(w, at) == a and get(w, at + 8) == b:
            return 0
        i = i + 1
    if count < 20:
        put(w, SD_CLASSES + count * 16, a)
        put(w, SD_CLASSES + count * 16 + 8, b)
    put(w, SD_CLASS_COUNT, count + 1)
    return 0

def aggregate(w:mutbuf, register:u64, lanes:u64, shape:u64) -> u64:
    total = 0
    lane = 0
    while lane < lanes:
        val = data_get(w, register, lane)
        total = choose(shape == 1, total + val, total | val)
        lane = lane + 1
    return total

def compare_value(w:mutbuf, a:u64, b:u64, shape:u64) -> u64:
    if shape == 2:
        return data_pair(w, choose(a == 0, 0, 1), choose(b == 0, 0, 1))
    return data_pair(w, a, b)

def vector_origin(token:u64, reg:u64, lanes:u64) -> u64:
    start = reg * 8
    return choose(token >= start and token < start + lanes, 1, 0)

def vector_frame(w:mutbuf, token:u64, lanes:u64, role:u64, allowed:u64) -> u64:
    reg = 0
    while reg < 8:
        if (allowed & (1 << reg)) == 0:
            lane = 0
            while lane < lanes:
                data_pair(w, data_get(w, reg, lane), initial_vector(w, token, reg, lane, lanes, role))
                lane = lane + 1
        reg = reg + 1
    return 0

def general_frame(w:mutbuf, token:u64, allowed:u64) -> u64:
    reg = 0
    while reg < 16:
        if (allowed & (1 << reg)) == 0:
            data_pair(w, get(w, SD_GPR + reg * 8), choose(token == 64 + reg, 1, 0))
        reg = reg + 1
    return 0

def data_compare(w:mutbuf, token:u64) -> u64:
    shape = get(w, SD_SHAPE)
    role = get(w, SD_ROLE)
    isa = get(w, SD_ISA)
    lanes = get(w, SD_LANES)
    memory = get(w, SD_MEMORY)
    if shape == 3:
        i = 0
        while i < memory:
            data_pair(w, byte(w, SD_DST + i), choose(token == 80 + i, 1, 0))
            i = i + 1
        return 0
    if role == 40 or role == 41:
        mask = choose(role == 40, 61, 5)
        reg = 0
        while reg < 8:
            if (mask & (1 << reg)) != 0:
                data_pair(w, aggregate(w, reg, lanes, 2), 0)
            reg = reg + 1
        vector_frame(w, token, lanes, role, mask)
        return general_frame(w, token, 0)
    if isa != 1 or (role != 47 and role != 52):
        data_pair(w, aggregate(w, 2, lanes, 2), 0)
    input = choose(token >= 80 and token < 80 + memory, 1, 0)
    if role == 42 or role == 43 or role == 44 or role == 45 or role == 46:
        before_lanes = choose(role == 46, 2, lanes)
        expected = vector_origin(token, 0, before_lanes) + input
        after_lanes = choose(role == 45 or role == 46, 2, lanes)
        after = aggregate(w, 0, after_lanes, shape)
        multiple = role == 42 and (isa != 1 or shape == 2)
        if multiple or role == 44:
            reg = 3
            while reg <= 5:
                expected = expected + vector_origin(token, reg, lanes)
                if multiple:
                    val = aggregate(w, reg, lanes, shape)
                    after = choose(shape == 1, after + val, after | val)
                reg = reg + 1
        compare_value(w, after, expected, shape)
        if role == 44:
            vector_frame(w, token, lanes, role, 1)
        if role == 45 or role == 46:
            lane = 2
            while lane < lanes:
                data_pair(w, data_get(w, 0, lane), 0)
                lane = lane + 1
            vector_frame(w, token, lanes, role, 3)
            general_frame(w, token, 0)
        return 0
    if role == 47:
        compare_value(w, get(w, SD_GPR), vector_origin(token, 0, 2), shape)
        if isa != 1:
            vector_frame(w, token, lanes, role, 1)
            general_frame(w, token, 513)
        return 0
    expected = choose(token == 64, 1, 0) + input
    compare_value(w, get(w, SD_GPR), expected, shape)
    if role != 52:
        vector_frame(w, token, lanes, role, 2)
        general_frame(w, token, 513)
    return 0

def data_node(w:mutbuf, index:u64, op:u64, width:u64, a:u64, b:u64, k:u64) -> u64:
    at = FRAME + 32 + 40 * index
    put(w, at, op)
    put(w, at + 8, width)
    put(w, at + 16, a)
    put(w, at + 24, b)
    put(w, at + 32, k)
    return index

def data_formula(w:mutbuf) -> u64:
    data_laws(w, 0)
    index = get(w, SD_NODE_COUNT)
    bad = get(w, SD_BAD_NODE)
    i = 0
    while i < get(w, SD_CLASS_COUNT):
        a = data_node(w, index, 2, 64, 0, 0, get(w, SD_CLASSES + 16 * i))
        b = data_node(w, index + 1, 2, 64, 0, 0, get(w, SD_CLASSES + 16 * i + 8))
        ax = data_node(w, index + 2, 3, 64, 0, a, 0)
        bx = data_node(w, index + 3, 3, 64, 0, b, 0)
        different = data_node(w, index + 4, 8, 1, ax, bx, 0)
        ordinal = data_node(w, index + 5, 2, 8, 0, 0, i)
        selected = data_node(w, index + 6, 7, 1, 1, ordinal, 0)
        mismatch = data_node(w, index + 7, 3, 1, selected, different, 0)
        bad = data_node(w, index + 8, 4, 1, bad, mismatch, 0)
        index = index + 9
        i = i + 1
    return simd_miter(w, index, bad, get(w, SD_FALSE_NODE))
'''
