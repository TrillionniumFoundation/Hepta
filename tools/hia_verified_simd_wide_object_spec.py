"""HIA source for bounded AVX2/AVX512 reductions and disjoint endpoint copies."""

WIDE_LABELS = ('short_init', 'narrow', 'word8', 'word4', 'word2', 'single', 'vector_done',
               'wide_fold', 'tail32', 'tail16', 'tail8', 'tail4', 'tail2')
WIDE = """
def wide_reduction(o:mutbuf, w:mutbuf, shape:u64, width:u64) -> u64:
    emit(o, w, 'b8 00 00 00 00 48 39 f2')
    jcc(o, w, 135, ABORT)
    emit(o, w, '48 85 d2')
    jcc(o, w, 132, DONE)
    emit(o, w, '48 85 ff')
    jcc(o, w, 132, ABORT)
    emit(o, w, '49 89 f9 49 01 d1')
    jcc(o, w, 130, ABORT)
    emit(o, w, '49 89 d2')
    compare_count(o, w, width)
    jcc(o, w, 130, SHORT_INIT)
    i = 0
    while i < 5:
        r = choose(i == 0, 0, i + 1)
        vreg(o, w, width, 239, r, r, r)
        i = i + 1
    label(w, BULK)
    compare_count(o, w, width * 4)
    jcc(o, w, 130, MERGE)
    i = 0
    while i < 4:
        r = choose(i == 0, 0, i + 2)
        wide_chunk(o, w, width, shape, i, r)
        i = i + 1
    wide_advance(o, w, shape, width * 4)
    jump(o, w, BULK)
    label(w, MERGE)
    i = 3
    while i < 6:
        combine(o, w, width, shape, 0, i)
        i = i + 1
    label(w, VECTOR)
    compare_count(o, w, width)
    jcc(o, w, 130, WIDE_FOLD)
    wide_chunk(o, w, width, shape, 0, 0)
    wide_advance(o, w, shape, width)
    jump(o, w, VECTOR)
    label(w, WIDE_FOLD)
    if width == 64:
        emit(o, w, '62 f3 fd 48 3b c1 01')
        combine(o, w, 32, shape, 0, 1)
    emit(o, w, 'c4 e3 7d 39 c1 01')
    combine(o, w, 16, shape, 0, 1)
    jump(o, w, NARROW)
    label(w, SHORT_INIT)
    vreg(o, w, 16, 239, 0, 0, 0)
    vreg(o, w, 16, 239, 2, 2, 2)
    label(w, NARROW)
    compare_count(o, w, 16)
    jcc(o, w, 130, HORIZONTAL)
    wide_chunk(o, w, 16, shape, 0, 0)
    wide_advance(o, w, shape, 16)
    jump(o, w, NARROW)
    label(w, HORIZONTAL)
    emit(o, w, 'c4 e1 f9 7e c0 c5 f9 73')
    emit(o, w, 'd8 08 c4 c1 f9 7e c1')
    reduce_scalar(o, w, shape)
    block = 8
    level = WORD8
    while block >= 2:
        label(w, level)
        compare_count(o, w, block)
        jcc(o, w, 130, level + 1)
        emit_word_read(o, w, block, 15)
        if shape == 1:
            emit(o, w, 'c4 c1 f9 6e c9')
            vreg(o, w, 16, 246, 1, 2, 1)
            emit(o, w, 'c4 c1 f9 7e c9')
        reduce_scalar(o, w, shape)
        wide_advance(o, w, shape, block)
        block = block >> 1
        level = level + 1
    label(w, SINGLE)
    emit(o, w, '4d 85 d2')
    jcc(o, w, 132, VECTOR_DONE)
    emit_word_read(o, w, 1, 15)
    reduce_scalar(o, w, shape)
    label(w, VECTOR_DONE)
    emit(o, w, 'c5 f8 77')
    return 0

def wide_copy(o:mutbuf, w:mutbuf, width:u64) -> u64:
    copy_guards(o, w)
    label(w, BULK)
    compare_count(o, w, width * 4)
    jcc(o, w, 130, VECTOR)
    i = 0
    while i < 4:
        vmem(o, w, width, 111, i + 1, 0, 2, i)
        i = i + 1
    i = 0
    while i < 4:
        vmem(o, w, width, 127, i + 1, 0, 7, i)
        i = i + 1
    wide_advance(o, w, 3, width * 4)
    jump(o, w, BULK)
    label(w, VECTOR)
    compare_count(o, w, width)
    jcc(o, w, 130, TAIL)
    vmem(o, w, width, 111, 1, 0, 2, 0)
    vmem(o, w, width, 127, 1, 0, 7, 0)
    wide_advance(o, w, 3, width)
    jump(o, w, VECTOR)
    label(w, TAIL)
    emit(o, w, '4d 85 d2')
    jcc(o, w, 132, VECTOR_DONE)
    compare_count(o, w, 1)
    jcc(o, w, 132, SINGLE)
    block = width >> 1
    level = choose(width == 64, TAIL32, TAIL16)
    while block >= 2:
        label(w, level)
        compare_count(o, w, block)
        jcc(o, w, 130, choose(block == 2, SINGLE, level + 1))
        endpoint_load(o, w, block, 1)
        wide_alu(o, w, 73, 234, block)
        emit(o, w, '4c 01 d2')
        endpoint_load(o, w, block, 2)
        endpoint_store(o, w, block, 1)
        emit(o, w, '4c 01 d7')
        endpoint_store(o, w, block, 2)
        jump(o, w, VECTOR_DONE)
        block = block >> 1
        level = level + 1
    label(w, SINGLE)
    endpoint_load(o, w, 1, 1)
    endpoint_store(o, w, 1, 1)
    label(w, VECTOR_DONE)
    emit(o, w, 'c5 f8 77')
    return 0

def endpoint_load(o:mutbuf, w:mutbuf, block:u64, reg:u64) -> u64:
    if block >= 16:
        vmem(o, w, block, 111, reg, 0, 2, 0)
    else:
        emit_word_read(o, w, block, choose(reg == 1, 10, 26))
    return 0

def endpoint_store(o:mutbuf, w:mutbuf, block:u64, reg:u64) -> u64:
    if block >= 16:
        vmem(o, w, block, 127, reg, 0, 7, 0)
    else:
        if block == 2:
            append(o, w, 102, 1)
        append(o, w, choose(block == 8, 76, 68), 1)
        append(o, w, choose(block == 1, 136, 137), 1)
        append(o, w, choose(reg == 1, 15, 31), 1)
    return 0

def emit_word_read(o:mutbuf, w:mutbuf, block:u64, operand:u64) -> u64:
    append(o, w, choose(block == 4, 68, 76), 1)
    if block >= 4:
        append(o, w, 139, 1)
    else:
        append(o, w, 15, 1)
        append(o, w, choose(block == 1, 182, 183), 1)
    return append(o, w, operand, 1)

def wide_chunk(o:mutbuf, w:mutbuf, width:u64, shape:u64, index:u64, acc:u64) -> u64:
    if shape == 1:
        vmem(o, w, width, 246, 1, 2, 7, index)
        combine(o, w, width, shape, acc, 1)
    else:
        vmem(o, w, width, 235, acc, acc, 7, index)
    return 0

def combine(o:mutbuf, w:mutbuf, width:u64, shape:u64, acc:u64, arg:u64) -> u64:
    return vreg(o, w, width, choose(shape == 1, 212, 235), acc, acc, arg)

def vprefix(o:mutbuf, w:mutbuf, width:u64, opcode:u64, src:u64) -> u64:
    pp = choose(opcode == 111 or opcode == 127, 2, 1)
    inverted = (15 - src) << 3
    if width == 64:
        emit(o, w, '62 f1')
        append(o, w, choose(opcode == 246, 0, 128) + inverted + 4 + pp, 1)
        append(o, w, 72, 1)
    else:
        append(o, w, 197, 1)
        append(o, w, 128 + inverted + choose(width == 32, 4, 0) + pp, 1)
    return append(o, w, opcode, 1)

def vreg(o:mutbuf, w:mutbuf, width:u64, opcode:u64, dst:u64, src:u64, arg:u64) -> u64:
    vprefix(o, w, width, opcode, src)
    return append(o, w, 192 + dst * 8 + arg, 1)

def vmem(o:mutbuf, w:mutbuf, width:u64, opcode:u64, reg:u64, src:u64, base:u64, index:u64) -> u64:
    vprefix(o, w, width, opcode, src)
    append(o, w, base + reg * 8 + choose(index == 0, 0, 64), 1)
    if index != 0:
        append(o, w, choose(width == 64, index, index * width), 1)
    return 0

def wide_advance(o:mutbuf, w:mutbuf, shape:u64, count:u64) -> u64:
    wide_alu(o, w, 72, 199, count)
    if shape == 3:
        wide_alu(o, w, 72, 194, count)
    return wide_alu(o, w, 73, 234, count)

def compare_count(o:mutbuf, w:mutbuf, count:u64) -> u64:
    return wide_alu(o, w, 73, 250, count)

def wide_alu(o:mutbuf, w:mutbuf, rex:u64, opcode:u64, count:u64) -> u64:
    append(o, w, rex, 1)
    append(o, w, choose(count < 128, 131, 129), 1)
    append(o, w, opcode, 1)
    return append(o, w, count, choose(count < 128, 1, 4))

def host_target(s:readbuf, o:mutbuf) -> u32:
    if length(s) < 48 or length(o) < 8:
        return 0
    n = uint(s, 8, 8)
    if n == 0 or n > 1024 or length(s) != 16 + 32 * n:
        return 0
    target = 3
    i = 0
    while i < n:
        at = 16 + i * 32
        max_leaf = uint(s, at, 8)
        ecx = uint(s, at + 8, 8)
        xcr0 = uint(s, at + 16, 8)
        ebx = uint(s, at + 24, 8)
        if max_leaf > 4294967295 or ecx > 4294967295 or ebx > 4294967295:
            return 0
        if max_leaf < 7 or (ecx & 469762048) != 469762048 or (xcr0 & 6) != 6 or (ebx & 32) == 0:
            target = 1
        elif (xcr0 & 230) != 230 or (ebx & 1073807360) != 1073807360:
            target = choose(target < 2, target, 2)
        i = i + 1
    put(o, 0, target)
    return 8
"""
