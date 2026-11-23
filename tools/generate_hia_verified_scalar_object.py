"""Generate the HIA register-leaf x86-64 producer from the admitted scalar SSA subject."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import GRAPH_PROJECTION_REQUEST
from tools import generate_hia_core_proof_wire as proof_wire
from tools.generate_hia_core_proof_wire import SUBJECT_MAGIC
from tools.generate_hia_verified_simd_sse2_object import OBJECT_LAYOUT, object_program

MODULE = 'verified_scalar_object'
SOURCE = '''
def produce(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 480 or length(o) < 16384 or length(w) < 8192:
        return 0
    magic = uint(s, 0, 8)
    ranked = magic == LEAF_SUBJECT
    if ranked == False and magic != SUBJECT_MAGIC:
        return 0
    ranks = uint(s, 48, 8)
    graph_end = 320 + uint(s, 32, 8)
    if graph_end < 320 or graph_end > length(s) or length(s) - graph_end != ranks or ranks > 70:
        return 0
    args = uint(s, 8, 8)
    n = uint(s, 40, 8)
    profile = uint(s, 16, 8)
    if args > 6 or n == 0 or n > 192:
        return 0
    if reserved_name(s, n):
        put(w, 64, 5)
        return 0
    if symbol(s, n) == 0:
        return 0
    if profile < 1 or profile > 6 or (ranked == False and ranks != 0) or uint(s, 56, 8) != 0:
        return 0
    if uint(s, 320, 8) != GRAPH_MAGIC or uint(s, 328, 8) != 2 or uint(s, 336, 8) != args or uint(s, 344, 8) != 1:
        return 0
    graph = 360 + 8 * args
    if graph + 88 > length(s) or uint(s, graph + 8, 8) != 1 or uint(s, graph + 16, 8) != 0:
        return 0
    block = graph + 24
    ops = uint(s, block + 8, 8)
    if ops > 64 or uint(s, block, 8) != args or uint(s, block + 16, 8) != 1:
        return 0
    if uint(s, block + 40, 8) != 1 or uint(s, block + 56, 8) != 0:
        return 0
    size = 96 + args * 8 + ops * 48
    if uint(s, graph, 8) != size or graph_end != graph + 2 * size or (ranked and ranks != args + ops):
        return 0
    k = 0
    while k < size:
        if byte(s, graph + k) != byte(s, graph + size + k):
            return 0
        k = k + 1
    zero(o, 16384)
    zero(w, 8192)
    put(w, 0, 64)
    put(w, 16, args + ops)
    put(w, 64, 1)
    put(w, 72, ranks)
    k = 0
    while k < ranks:
        rank = byte(s, graph_end + k)
        if rank >= ranks or byte(w, 6144 + rank) != 0:
            return 0
        store(w, 6144 + rank, 1)
        store(w, 6000 + k, rank)
        k = k + 1
    first = block + 64 + args * 8
    returned = uint(s, first + ops * 48, 8)
    if returned >= args + ops:
        return 0
    k = 0
    while k < args + ops:
        put(w, slot(k) + 16, 255)
        if k < args:
            typ = uint(s, 352 + k * 8, 8)
            if typ != uint(s, block + 64 + k * 8, 8) or valid_type(typ) == False:
                return 0
            put(w, slot(k), typ)
        else:
            row = first + (k - args) * 48
            typ = uint(s, row + 8, 8)
            argc = arity(uint(s, row, 8))
            if argc > 3 or valid_type(typ) == False:
                return 0
            put(w, slot(k), typ)
            j = 0
            while j < argc:
                dep = uint(s, row + 16 + j * 8, 8)
                if dep >= k:
                    return 0
                put(w, slot(dep) + 8, get(w, slot(dep) + 8) + 1)
                j = j + 1
        k = k + 1
    if get(w, slot(returned)) != uint(s, 352 + args * 8, 8):
        return 0
    put(w, slot(returned) + 8, get(w, slot(returned) + 8) + 1)
    k = 0
    while k < args:
        if get(w, slot(k) + 8) != 0:
            reg = reg_order(k + 1)
            put(w, slot(k) + 16, reg)
            normalize(o, w, reg, get(w, slot(k)))
        k = k + 1
    k = 0
    while k < ops:
        if instruction(s, o, w, first + k * 48, args + k) == 0:
            return 0
        k = k + 1
    reg = get(w, slot(returned) + 16)
    if reg > 11:
        return 0
    move(o, w, 0, reg)
    emit(o, w, 195, 1)
    hot = get(w, 0)
    emit(o, w, 59477, 2)
    relocation = get(w, 0) - 64
    emit(o, w, 0, 4)
    emit(o, w, 2831, 2)
    k = 0
    while k < get(w, 8):
        at = get(w, 3072 + k * 8)
        write(o, at, hot - at - 4, 4)
        k = k + 1
    if get(w, 24) != 0:
        return 0
    put(w, 64, 0)
    put(w, 48, hot - 64)
    put(w, 56, choose(profile >= 2, profile, 2))
    return obj(s, o, n, get(w, 0) - 64, relocation)

def slot(id:u64) -> u64:
    return 256 + id * 32

def valid_type(t:u64) -> bool:
    width = t & 127
    return t < 256 and (width == 1 and t == 1 or width == 8 or width == 16 or width == 32 or width == 64)

def arity(op:u64) -> u64:
    if op == 2:
        return 0
    if op == 6 or op == 20 or op == 33 or op == 38:
        return 1
    if op == 11:
        return 3
    if (op >= 3 and op <= 15) or op == 22 or op == 23 or op == 32 or (op >= 34 and op <= 37) or op == 39:
        return 2
    return 255

def reg_order(i:u64) -> u64:
    return (REG_ORDER >> (i * 4)) & 15

def emit(o:mutbuf, w:mutbuf, v:u64, size:u64) -> u64:
    at = get(w, 0)
    if at + size > 14336:
        return put(w, 24, 1)
    write(o, at, v, size)
    return put(w, 0, at + size)

def rr(o:mutbuf, w:mutbuf, op:u64, reg:u64, rm:u64) -> u64:
    emit(o, w, 72 | ((reg >> 3) << 2) | (rm >> 3), 1)
    emit(o, w, op, choose(op > 255, 2, 1))
    return emit(o, w, 192 | ((reg & 7) << 3) | (rm & 7), 1)

def move(o:mutbuf, w:mutbuf, dst:u64, src:u64) -> u64:
    if dst != src:
        rr(o, w, 137, src, dst)
    return 0

def literal(o:mutbuf, w:mutbuf, dst:u64, v:u64) -> u64:
    emit(o, w, 72 | (dst >> 3) | ((184 + (dst & 7)) << 8), 2)
    return emit(o, w, v, 8)

def immediate(o:mutbuf, w:mutbuf, group:u64, dst:u64, v:u64) -> u64:
    compact = v < 128 or v >= 18446744073709551488
    opcode = choose(compact, 131, 129)
    emit(o, w, (72 | (dst >> 3)) | (opcode << 8) | ((192 | (group << 3) | (dst & 7)) << 16), 3)
    return emit(o, w, v, choose(compact, 1, 4))

def shift(o:mutbuf, w:mutbuf, group:u64, reg:u64, count:u64) -> u64:
    opcode = choose(count == 64, 211, 193)
    emit(o, w, (72 | (reg >> 3)) | (opcode << 8) | ((192 | (group << 3) | (reg & 7)) << 16), 3)
    if count != 64:
        emit(o, w, count, 1)
    return 0

def normalize(o:mutbuf, w:mutbuf, dst:u64, t:u64) -> u64:
    width = t & 127
    if t > 127 and width < 64:
        shift(o, w, 4, dst, 64 - width)
        shift(o, w, 7, dst, 64 - width)
    elif width < 32:
        immediate(o, w, 4, dst, (1 << width) - 1)
    elif width == 32:
        shift(o, w, 4, dst, 32)
        shift(o, w, 5, dst, 32)
    return 0

def occupant(w:mutbuf, reg:u64, count:u64) -> u64:
    i = 0
    while i < count:
        if get(w, slot(i) + 16) == reg:
            return i
        i = i + 1
    return 255

def free_register(w:mutbuf, count:u64, exclude:u64) -> u64:
    i = 0
    while i < 9:
        r = reg_order(i)
        if (exclude & (1 << r)) == 0 and occupant(w, r, count) == 255:
            return r
        i = i + 1
    return 255

def dying(w:mutbuf, id:u64) -> bool:
    return get(w, slot(id) + 8) == get(w, slot(id) + 24)

def evacuate(o:mutbuf, w:mutbuf, id:u64, count:u64, exclude:u64) -> bool:
    fresh = free_register(w, count, exclude)
    if fresh == 255:
        return False
    move(o, w, fresh, get(w, slot(id) + 16))
    put(w, slot(id) + 16, fresh)
    return True

def select_destination(s:readbuf, w:mutbuf, row:u64, i:u64, op:u64, t:u64) -> u64:
    if op == 36 or op == 37 or (op == 39 and t < 128):
        return 0
    shift_op = op == 34 or op == 35
    disallow = choose(shift_op, 2, 0)
    begin = 0
    end = arity(op)
    if op == 11:
        begin = 2
    elif op == 10 or op == 23 or shift_op:
        end = 1
    j = begin
    while j < end:
        id = uint(s, row + 16 + j * 8, 8)
        reg = get(w, slot(id) + 16)
        if dying(w, id) and (disallow & (1 << reg)) == 0:
            return reg
        j = j + 1
    return free_register(w, i, disallow)

def instruction(s:readbuf, o:mutbuf, w:mutbuf, row:u64, i:u64) -> u64:
    op = uint(s, row, 8)
    t = get(w, slot(i))
    argc = arity(op)
    arg = 0
    while arg < argc:
        id = uint(s, row + 16 + arg * 8, 8)
        if get(w, slot(id) + 16) >= 16:
            return 0
        put(w, slot(id) + 24, get(w, slot(id) + 24) + 1)
        arg = arg + 1
    a = uint(s, row + 16, 8)
    b = uint(s, row + 24, 8)
    c = uint(s, row + 32, 8)
    # The unused argument slots in an admitted subject are zero-filled.
    if a >= get(w, 16) or b >= get(w, 16) or c >= get(w, 16):
        return 0
    if op == 36 or op == 37 or (op == 39 and t < 128):
        r = 0
        while r <= 2:
            id = occupant(w, r, i)
            if id != 255 and dying(w, id) == False:
                if evacuate(o, w, id, i, 5) == False:
                    put(w, 64, choose(op == 39, 10, 9))
                    return 0
            r = r + 2
        r = get(w, slot(b) + 16)
        if (op == 36 or op == 37) and (r == 0 or r == 2):
            if evacuate(o, w, b, i, 5) == False:
                put(w, 64, 8)
                return 0
    if (op == 34 or op == 35) and get(w, slot(b) + 16) != 1:
        id = occupant(w, 1, i)
        if id != 255:
            if evacuate(o, w, id, i, 0) == False:
                put(w, 64, 7)
                return 0
        move(o, w, 1, get(w, slot(b) + 16))
        put(w, slot(b) + 16, 1)
    dst = select_destination(s, w, row, i, op, t)
    if dst == 255:
        put(w, 64, 2)
        return 0
    put(w, 96, get(w, slot(a) + 16))
    put(w, 104, get(w, slot(b) + 16))
    put(w, 112, get(w, slot(c) + 16))
    put(w, 120, get(w, slot(a)))
    put(w, 128, uint(s, row + 40, 8))
    if lower(o, w, i, op, t, dst) == 0:
        return 0
    normalize(o, w, dst, t)
    arg = 0
    while arg < argc:
        id = uint(s, row + 16 + arg * 8, 8)
        left = get(w, slot(id) + 8) - 1
        put(w, slot(id) + 8, left)
        put(w, slot(id) + 24, 0)
        if left == 0:
            put(w, slot(id) + 16, 255)
        arg = arg + 1
    if get(w, slot(i) + 8) > 0:
        put(w, slot(i) + 16, dst)
    return 1

def scratch_reg(w:mutbuf, count:u64, dst:u64) -> u64:
    r = free_register(w, count, 1 << dst)
    if r != 255:
        return r
    best = 255
    selected = 255
    i = 0
    while i < count:
        r = get(w, slot(i) + 16)
        if r != 255 and r != dst and dying(w, i):
            # Several dying values are considered in the original SSA name
            # order; the source subject carries the rank of every spelling.
            if get(w, 72) == 0 and selected != 255:
                return 255
            rank = byte(w, 6000 + i)
            if selected == 255 or rank < best:
                best = rank
                selected = r
        i = i + 1
    return selected

def condition(op:u64, signed:bool) -> u64:
    if op == 7 or op == 8:
        return op - 3
    if signed:
        return (SIGNED_CC >> ((op - 12) * 4)) & 15
    return (UNSIGNED_CC >> ((op - 12) * 4)) & 15

def local_branch(o:mutbuf, w:mutbuf, condition:u64) -> u64:
    emit(o, w, 15 | ((128 + condition) << 8), 2)
    at = get(w, 0)
    emit(o, w, 0, 4)
    return at

def abort_branch(o:mutbuf, w:mutbuf, condition:u64) -> u64:
    count = get(w, 8)
    if count >= 256:
        return put(w, 24, 1)
    put(w, 3072 + count * 8, local_branch(o, w, condition))
    return put(w, 8, count + 1)

def check_fits(o:mutbuf, w:mutbuf, count:u64, dst:u64, t:u64) -> bool:
    bits = t & 127
    if t > 127 and bits < 64:
        half = 1 << (bits - 1)
        immediate(o, w, 7, dst, 0 - half)
        abort_branch(o, w, 12)
        immediate(o, w, 7, dst, half - 1)
        abort_branch(o, w, 15)
    elif bits < 32:
        immediate(o, w, 7, dst, (1 << bits) - 1)
        abort_branch(o, w, 7)
    elif bits == 32:
        temp = scratch_reg(w, count, dst)
        if temp == 255:
            put(w, 64, 11)
            return False
        move(o, w, temp, dst)
        shift(o, w, 5, temp, 32)
        rr(o, w, 133, temp, temp)
        abort_branch(o, w, 5)
    return True

def lower(o:mutbuf, w:mutbuf, i:u64, op:u64, t:u64, dst:u64) -> u64:
    a = get(w, 96)
    b = get(w, 104)
    bits = t & 127
    signed = t > 127
    if op == 2:
        literal(o, w, dst, get(w, 128))
    elif op == 36 or op == 37:
        rr(o, w, 133, b, b)
        abort_branch(o, w, 4)
        move(o, w, 0, a)
        if signed:
            immediate(o, w, 7, b, 18446744073709551615)
            safe = local_branch(o, w, 5)
            minimum = 0 - (1 << (bits - 1))
            if bits < 64:
                immediate(o, w, 7, 0, minimum)
            else:
                literal(o, w, 2, minimum)
                rr(o, w, 57, 2, 0)
            abort_branch(o, w, 4)
            write(o, safe, get(w, 0) - safe - 4, 4)
            emit(o, w, 39240, 2)
            rr(o, w, 247, 7, b)
        else:
            rr(o, w, 49, 2, 2)
            rr(o, w, 247, 6, b)
        if op == 37:
            move(o, w, 0, 2)
    elif op == 39 and signed == False:
        if b == 0:
            b = a
            a = 0
        move(o, w, 0, a)
        rr(o, w, 247, 4, b)
        abort_branch(o, w, 2)
        if check_fits(o, w, i, 0, t) == False:
            return 0
    elif op == 34 or op == 35:
        move(o, w, dst, a)
        immediate(o, w, 7, 1, bits)
        abort_branch(o, w, 3)
        group = choose(op == 34, 4, choose(signed, 7, 5))
        shift(o, w, group, dst, 64)
    elif op == 33:
        move(o, w, dst, a)
        if signed:
            rr(o, w, 247, 3, dst)
            if bits == 64:
                abort_branch(o, w, 0)
            if check_fits(o, w, i, dst, t) == False:
                return 0
        else:
            rr(o, w, 133, dst, dst)
            abort_branch(o, w, 5)
    elif op == 6 or op == 20 or op == 38:
        move(o, w, dst, a)
        if op == 6:
            if t == 1:
                immediate(o, w, 6, dst, 1)
            else:
                rr(o, w, 247, 2, dst)
        elif op == 38:
            if checked_cast(o, w, i, dst, get(w, 120), t) == False:
                return 0
    elif op == 7 or op == 8 or (op >= 12 and op <= 15):
        rr(o, w, 57, b, a)
        cc = condition(op, get(w, 120) > 127)
        literal(o, w, dst, 0)
        emit(o, w, (64 | (dst >> 3)) | 3840 | ((144 + cc) << 16) | ((192 | (dst & 7)) << 24), 4)
    elif op == 11:
        rr(o, w, 133, a, a)
        move(o, w, dst, get(w, 112))
        rr(o, w, 17679, dst, b)
    else:
        if dst == b and op != 10 and op != 23:
            b = a
            a = dst
        move(o, w, dst, a)
        if op == 32 or op == 39:
            rr(o, w, 44815, dst, b)
        else:
            opcode = binary_opcode(op)
            if opcode == 0:
                return 0
            rr(o, w, opcode, b, dst)
        if op == 39:
            abort_branch(o, w, 0)
            if check_fits(o, w, i, dst, t) == False:
                return 0
        elif op == 22 or op == 23:
            if signed:
                if bits == 64:
                    abort_branch(o, w, 0)
                if check_fits(o, w, i, dst, t) == False:
                    return 0
            elif op == 23 or bits == 64:
                abort_branch(o, w, 2)
            elif check_fits(o, w, i, dst, t) == False:
                return 0
    return 1

def binary_opcode(op:u64) -> u64:
    if op == 3:
        return 33
    if op == 4:
        return 9
    if op == 5:
        return 49
    if op == 9 or op == 22:
        return 1
    if op == 10 or op == 23:
        return 41
    return 0

def compare_bound(o:mutbuf, w:mutbuf, count:u64, dst:u64, value:u64, cc:u64) -> bool:
    if value <= 2147483647 or value >= 18446744071562067968:
        immediate(o, w, 7, dst, value)
    else:
        r = scratch_reg(w, count, dst)
        if r == 255:
            put(w, 64, 12)
            return False
        literal(o, w, r, value)
        rr(o, w, 57, r, dst)
    abort_branch(o, w, cc)
    return True

def checked_cast(o:mutbuf, w:mutbuf, count:u64, dst:u64, src:u64, target:u64) -> bool:
    a = src & 127
    b = target & 127
    from_signed = src > 127
    to_signed = target > 127
    if from_signed == False and to_signed == False:
        if a > b:
            return check_fits(o, w, count, dst, target)
        return True
    if from_signed and (to_signed == False or a > b):
        lower = choose(to_signed, 0 - (1 << (b - 1)), 0)
        if compare_bound(o, w, count, dst, lower, 12) == False:
            return False
    source_positive = a - choose(from_signed, 1, 0)
    target_positive = b - choose(to_signed, 1, 0)
    if source_positive > target_positive:
        if target_positive == 63 and from_signed == False:
            rr(o, w, 133, dst, dst)
            abort_branch(o, w, 8)
        else:
            upper = (1 << target_positive) - 1
            return compare_bound(o, w, count, dst, upper, choose(from_signed, 15, 7))
    return True
'''


SUBJECT_ENTRY = '''
def proof_wire(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    graph = widen(scalar_graph(s, o, w))
    if graph >= 4294967292 or graph < 40 or length(o) < SUBJECT_HEADER + graph:
        return leaf_refusal(o, explain_leaf(s, o, w))
    fn = child(w, field(w, 0, K_functions))
    blocks = field(w, fn, K_blocks)
    if count(w, blocks) != 1:
        return leaf_refusal(o, 3)
    block = child(w, blocks)
    if proof_term(w, field(w, field(w, block, K_term), K_op)) != 1:
        return leaf_refusal(o, 6)
'''

SUBJECT_HELPERS = '''
def leaf_refusal(o:mutbuf, reason:u64) -> u64:
    if length(o) < 16:
        return REFUSED
    put(o, 0, LEAF_REFUSAL)
    put(o, 8, reason)
    return 16

def explain_leaf(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(o) < 32768 or length(w) < 4096:
        return 1
    put(o, 48, 262144)
    put(o, 56, 64)
    end = widen(decode_json(s, w, o))
    if end >= 4294967292:
        return 1
    functions = field(w, 0, K_functions)
    if count(w, functions) != 1:
        return 1
    fn = child(w, functions)
    blocks = field(w, fn, K_blocks)
    if count(w, blocks) != 1:
        return 3
    p = child(w, field(w, fn, K_params))
    while p != NONE:
        typ = field(w, p, K_type)
        if proof_loan(w, typ) != 0:
            return 4
        p = next_node(w, p)
    return 1

def leaf_ranks(o:mutbuf, w:mutbuf, graph:u64) -> u64:
    fn = child(w, field(w, 0, K_functions))
    block = child(w, field(w, fn, K_blocks))
    slots = count(w, field(w, block, K_params)) + count(w, field(w, block, K_ops))
    end = SUBJECT_HEADER + graph
    if slots > 70 or length(o) < end + slots:
        return REFUSED
    table = get(w, 24)
    i = 0
    while i < slots:
        rank = 0
        j = 0
        while j < slots:
            if leaf_name_less(w, get(w, table + j * 8), get(w, table + i * 8)):
                rank = rank + 1
            j = j + 1
        store(o, end + i, rank)
        i = i + 1
    put(o, 0, LEAF_SUBJECT)
    put(o, 48, slots)
    return end + slots

def leaf_name_less(w:mutbuf, a:u64, b:u64) -> bool:
    row = 64 + a * 56
    left = get(w, row + 24)
    n = get(w, row + 32)
    row = 64 + b * 56
    right = get(w, row + 24)
    m = get(w, row + 32)
    i = 0
    while i < n and i < m:
        x = byte(w, left + i)
        y = byte(w, right + i)
        if x != y:
            return x < y
        i = i + 1
    return n < m
'''


BUILD_DIAGNOSTIC_ENTRY = '''
    if length(w) == 24 and get(w, 0) == PUBLISH_FAILURE:
        return verified_publication_failure(s, o, get(w, 8), get(w, 16))
    if length(w) == 48 and get(w, 0) == OUTPUT_PATH:
        return verified_output_path(s, o, w)
    if length(w) == 24 and get(w, 0) == CORE_ERROR:
        return core_driver_error(s, o, get(w, 8), get(w, 16))
    if length(w) >= 4096 and get(w, 0) == CHECKED_ERROR:
        return checked_driver_error(s, o, w, get(w, 8))
'''

BUILD_DIAGNOSTICS = '''
def driver_word(o:mutbuf, at:u64, value:u64, size:u64) -> u64:
    if at > length(o) or size > length(o) - at:
        return length(o)
    k = 0
    while k < size:
        store(o, at + k, (value >> (8 * k)) & 255)
        k = k + 1
    return at + size

def driver_escape(s:readbuf, o:mutbuf, pos:u64, size:u64, at:u64) -> u64:
    i = 0
    while i < size:
        ch = widen(byte(s, pos + i))
        if ch == 34 or ch == 92:
            at = driver_word(o, at, 92 | (ch << 8), 2)
        elif ch < 32:
            escaped = choose(ch == 8, 98, choose(ch == 9, 116, choose(ch == 10, 110, choose(ch == 12, 102, choose(ch == 13, 114, 0)))))
            if escaped != 0:
                at = driver_word(o, at, 92 | (escaped << 8), 2)
            else:
                low = ch & 15
                high = ch >> 4
                at = driver_word(o, at, 808482140 | ((high + 48) << 32) | ((low + choose(low < 10, 48, 87)) << 40), 6)
        elif ch >= 128:
            n = register_utf8(s, pos + i, pos + size, ch)
            if n == 0:
                return 0
            k = 0
            while k < n:
                at = driver_word(o, at, widen(byte(s, pos + i + k)), 1)
                k = k + 1
            i = i + n - 1
        else:
            at = driver_word(o, at, ch, 1)
        i = i + 1
    return at

def verified_publication_failure(s:readbuf, o:mutbuf, observed:u64, linked:u64) -> u64:
    if length(s) != 96 or length(o) < 256 or obligation_word(s, 0) != 3544409130703866184:
        return 0
    if obligation_word(s, 16) != 2 or obligation_word(s, 24) != 4:
        return 0
    if linked < 18446744073709547521:
        return 0
    if observed == 0:
        if linked != 18446744073709551599:
            return 0
        return driver_publish_exists(o, 0)
    if observed < 18446744073709547521:
        return 0
    return driver_publish_link(o, 0)

def verified_output_path(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    size = length(s)
    if size == 0 or size > 4095 or length(o) < size + 1 or byte(s, 0) != 47:
        return 0
    strategy = get(w, 8)
    if strategy < 1 or strategy > 3:
        return 0
    phase = get(w, 16)
    if phase == 0:
        if get(w, 24) != 0 or get(w, 32) != 0 or get(w, 40) != 0:
            return 0
        slash = 0
        i = 0
        while i < size:
            ch = byte(s, i)
            if ch == 0:
                return 0
            if ch == 47:
                slash = i
            i = i + 1
        end = choose(slash == 0, 1, slash)
        i = 0
        while i < end:
            store(o, i, byte(s, i))
            i = i + 1
        store(o, end, 0)
        return end + 1
    if phase != 1 or length(o) < 256:
        return 0
    destination = get(w, 24)
    parent = get(w, 32)
    mode = get(w, 40)
    if (destination != 0 and destination < 18446744073709547521) or (parent != 0 and parent < 18446744073709547521):
        return 0
    if mode > 4294967295 or (parent != 0 and mode != 0):
        return 0
    if destination != 0 and parent == 0 and (mode & 61440) == 16384:
        return 1
    if strategy == 1:
        return driver_scalar_path(o, 0)
    if strategy == 2:
        return driver_simd_path(o, 0)
    return driver_checked_path(o, 0)

def core_driver_error(s:readbuf, o:mutbuf, source:u64, status:u64) -> u64:
    size = length(s)
    if size < 128 or source > 8388608:
        return 0
    t = size - 64
    nodes = ((source + 1) >> 1) + 1
    nodes = choose(nodes > 262144, 262144, nodes)
    capacity = source + nodes + 4096
    if capacity > t or t - capacity < 8192:
        return 0
    offset = t - capacity
    n = obligation_word(s, t + 16)
    if obligation_word(s, t) != offset - 8192 or obligation_word(s, t + 8) != offset or n == 0 or n > capacity:
        return 0
    if obligation_word(s, t + 24) != capacity or obligation_word(s, t + 32) != status or obligation_word(s, t + 40) != DIAGNOSTIC_MAGIC:
        return 0
    if obligation_word(s, t + 48) != 0 or obligation_word(s, t + 56) != 0 or length(o) < 256 + n * 6:
        return 0
    at = driver_prefix(o, 0)
    at = driver_status(o, at, status)
    if at == 0:
        return 0
    at = driver_escape(s, o, offset, n, at)
    if at == 0:
        return 0
    return driver_suffix(o, at)

def checked_driver_error(s:readbuf, o:mutbuf, w:mutbuf, scalar_refusal:u64) -> u64:
    if length(o) < 32768 or length(w) < 4096:
        return 0
    put(o, 48, 262144)
    put(o, 56, 64)
    if widen(decode_json(s, w, o)) >= 4294967292:
        return 0
    functions = field(w, 0, K_functions)
    if count(w, functions) != 1:
        return driver_many_functions(o, 0)
    if proof_schema(w, field(w, 0, K_schema)) == 0:
        return driver_schema(o, 0)
    fn = child(w, functions)
    returns = field(w, fn, K_returns)
    if count(w, returns) != 1 or proof_type(w, child(w, returns)) == 0:
        return driver_return(o, 0)
    effect = child(w, field(w, fn, K_effects))
    while effect != NONE:
        if proof_effect(w, effect) == 0:
            return driver_effect(o, 0)
        effect = next_node(w, effect)
    params = field(w, fn, K_params)
    p = child(w, params)
    loans = 0
    while p != NONE:
        if proof_loan(w, field(w, p, K_type)) != 0:
            loans = loans + 1
        p = next_node(w, p)
    if loans > 1 or count(w, params) + loans > 6:
        return driver_words(o, 0)
    if loans != 0:
        return driver_borrow(o, 0)
    blocks = field(w, fn, K_blocks)
    count_ops = 0
    b = child(w, blocks)
    while b != NONE:
        count_ops = count_ops + count(w, field(w, b, K_ops))
        b = next_node(w, b)
    if count(w, blocks) > 16 or count_ops > 64:
        return driver_budget(o, 0)
    if scalar_refusal == 5:
        return driver_loader(o, 0)
    return 0
'''


def build_diagnostic_source():
    from hepta.hia_core_admission_native import ERROR_CODES
    from hepta.hia_core_diagnostic_protocol import DIAGNOSTIC_MAGIC
    from tools.generate_hia_shared_build_report import append_function
    from tools.generate_hia_verified_register_report import REPORT_SOURCE
    import ast
    import json

    def literal(name, value):
        return append_function(name, value).replace('append_word(', 'driver_word(')

    sample = json.dumps({'diagnostics': [{'code': 'E_DRIVER', 'phase': 'driver', 'message': 'MESSAGE'}],
                         'ok': False, 'status': 'error'}, indent=2, sort_keys=True) + '\n'
    prefix, suffix = sample.split('MESSAGE')
    source = BUILD_DIAGNOSTICS.replace('DIAGNOSTIC_MAGIC', str(DIAGNOSTIC_MAGIC))
    utf8 = next(fn for fn in ast.parse(REPORT_SOURCE).body if fn.name == 'register_utf8')
    source += '\n' + ast.unparse(utf8) + '\n'
    source += literal('driver_prefix', prefix) + literal('driver_suffix', suffix)
    status_source = ['def driver_status(o:mutbuf, at:u64, status:u64) -> u64:']
    for name in sorted(set(ERROR_CODES.values())):
        function = 'driver_' + name.lower()
        source += literal(function, name + ': ')
        choices = [f'status == {code}' for code, label in ERROR_CODES.items() if label == name]
        status_source.extend(('    if ' + ' or '.join(choices) + ':', f'        return {function}(o, at)'))
    source += '\n'.join([*status_source, '    return 0', ''])
    messages = {
        'publish_exists': 'E_PUBLISH_EXISTS: output must be a new file',
        'publish_link': 'E_PUBLISH_LINK: no-replace link failed',
        'scalar_path': 'E_HIA_VERIFIED_SCALAR: output must be a new path in an existing directory',
        'simd_path': 'output must be a new file in an existing directory',
        'checked_path': 'E_HIA_SAFE_CORE: output must be a new path in an existing directory',
        'many_functions': 'one function is required',
        'schema': 'E_HIA_SAFE_CORE: Safe Core admits exactly one primitive function',
        'return': 'E_HIA_SAFE_CORE: exactly one scalar entry/return is required',
        'effect': 'E_HIA_SAFE_CORE: unreviewed resource effects',
        'words': 'E_HIA_SAFE_CORE: one borrowed range and at most six ABI argument words are admitted',
        'borrow': 'E_HIA_SAFE_CORE: borrowed range requires an exact extent and the u32 packed-result ABI',
        'budget': 'E_HIA_SAFE_CORE: Safe Core block/operation budget exceeded',
        'loader': 'E_HIA_PROGRAM_ABI: export conflicts with the closed runtime or loader ABI',
    }
    for name, message in messages.items():
        source += literal('driver_text_' + name, message)
        source += (f'\ndef driver_{name}(o:mutbuf, at:u64) -> u64:\n'
                   f'    return driver_suffix(o, driver_text_{name}(o, driver_prefix(o, at)))\n')
    return source

def subject_program():
    helpers = SUBJECT_HELPERS + '\n' + proof_wire.match('loan', {'readbuf': 1, 'mutbuf': 2})
    entry = SUBJECT_ENTRY.replace('    graph =', BUILD_DIAGNOSTIC_ENTRY + '    graph =')
    for label, tag in [('CORE_ERROR', b'HIACDG01'), ('CHECKED_ERROR', b'HIACDG02'), ('OUTPUT_PATH', b'HIAOUT01'),
                       ('PUBLISH_FAILURE', b'HIAPUBD1')]:
        entry = entry.replace(label, str(int.from_bytes(tag, 'little')))
    source = proof_wire.subject_source(entry, 'leaf_ranks(o, w, graph)', helpers + build_diagnostic_source(), simd=False)
    source = source.replace('LEAF_REFUSAL', str(int.from_bytes(b'HIASLR01', 'little')))
    source = source.replace('LEAF_SUBJECT', str(int.from_bytes(b'HIASLE01', 'little')))
    return proof_wire.program(subject=True, subject_override=('verified_scalar_subject', source))


def reserved_name_source():
    names = ('_init', '_fini', '__gmon_start__', '__cxa_finalize', '__dso_handle',
             '_ITM_registerTMCloneTable', '_ITM_deregisterTMCloneTable', 'abort')
    lines = ['def reserved_name(s:readbuf, n:u64) -> bool:']
    for name in names:
        raw = name.encode('ascii')
        fields = [f'n == {len(raw)}']
        for i in range(0, len(raw), 8):
            part = raw[i:i + 8]
            fields.append(f'uint(s, {64 + i}, {len(part)}) == {int.from_bytes(part, "little")}')
        lines.extend(('    if ' + ' and '.join(fields) + ':', '        return True'))
    return '\n'.join((*lines, '    return False', ''))


def program():
    def nibbles(values):
        return sum(value << (4 * i) for i, value in enumerate(values))

    constants = {
        'GRAPH_MAGIC': GRAPH_PROJECTION_REQUEST, 'SUBJECT_MAGIC': SUBJECT_MAGIC,
        'LEAF_SUBJECT': int.from_bytes(b'HIASLE01', 'little'),
        'REG_ORDER': nibbles((0, 7, 6, 2, 1, 8, 9, 10, 11)),
        'SIGNED_CC': nibbles((12, 14, 15, 13)), 'UNSIGNED_CC': nibbles((2, 6, 7, 3)),
    }
    return object_program(SOURCE + '\n' + reserved_name_source() + OBJECT_LAYOUT, MODULE, 64, constants)


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap' / (MODULE + '.hepta')
    target.write_text(render_assembly(program()))
    target.with_name('verified_scalar_subject.hepta').write_text(render_assembly(subject_program()))
