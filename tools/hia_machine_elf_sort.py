"""HIA continuation for CPython's stable Powersort comparison schedule.

The algorithm follows Objects/listobject.c in the PSF-licensed CPython
v3.12.14, v3.13.11 and v3.14.4 sources. The run detector changed in 3.13;
binary insertion, gallop searches and merge decisions remain explicit HIA.
The caller supplies opaque nodes and the single fixed foreign comparison.
No Python sorted/list.sort callback implements any ordering decision.
"""
from __future__ import annotations

# One private 2048-byte context, followed by no external Python state. Stack
# bounds follow signed-64-bit addressable sequences, rather than a new input
# count cap. Caller reserves the context together with both node arrays.
FIELDS = {
    'SORT_CTX': 704, 'SORT_VERSION': 712,
    'TC_PC': 0, 'TC_POS': 8, 'TC_MINRUN': 16, 'TC_RUN': 24,
    'TC_LIMIT': 32, 'TC_INDEX': 40, 'TC_DESC': 48, 'TC_NEQ': 56,
    'TC_BSTART': 64, 'TC_BLO': 72, 'TC_BHI': 80, 'TC_PIVOT': 88,
    'TC_MID': 96, 'TC_STACK_N': 104, 'TC_POWER': 112,
    'TC_MERGE_I': 120, 'TC_MERGE_RET': 128, 'TC_MIN_GALLOP': 136,
    'TC_GALLOP': 144, 'TC_A': 152, 'TC_B': 160, 'TC_DEST': 168,
    'TC_BASE_A': 176, 'TC_BASE_B': 184, 'TC_NA': 192, 'TC_NB': 200,
    'TC_ACOUNT': 208, 'TC_BCOUNT': 216, 'TC_GKIND': 224,
    'TC_GKEY': 232, 'TC_GBASE': 240, 'TC_GN': 248, 'TC_GHINT': 256,
    'TC_GOFS': 264, 'TC_GLAST': 272, 'TC_GMAX': 280, 'TC_GDIR': 288,
    'TC_GRESULT': 296, 'TC_GRET': 304, 'TC_GMID': 312,
    'TC_COMPARE': 320, 'TC_WAIT': 328, 'TC_STACK': 352,
}

BODY = r'''
def tc_get(w:mutbuf, slot:u64) -> u64:
    return get(w, get(w, SORT_CTX) + slot)

def tc_put(w:mutbuf, slot:u64, value:u64) -> u64:
    put(w, get(w, SORT_CTX) + slot, value)
    return 0

def tc_pc(w:mutbuf, pc:u64) -> u64:
    tc_put(w, TC_PC, pc)
    return 4

def tc_item(w:mutbuf, index:u64) -> u64:
    return get(w, get(w, SORT_ARRAY) + index * 8)

def tc_stack(w:mutbuf, index:u64) -> u64:
    return get(w, SORT_CTX) + TC_STACK + index * 24

def tc_reverse(w:mutbuf, pos:u64, n:u64) -> u64:
    array = get(w, SORT_ARRAY)
    i = 0
    while i < (n >> 1):
        a = array + (pos + i) * 8
        b = array + (pos + n - i - 1) * 8
        v = get(w, a)
        put(w, a, get(w, b))
        put(w, b, v)
        i = i + 1
    return 0

def sort_start(w:mutbuf, array:u64, temp:u64, n:u64, kind:u64, ret:u64) -> u64:
    ctx = temp + n * 8
    if ctx > length(w) or 2048 > length(w) - ctx:
        return ABI
    put(w, SORT_ARRAY, array)
    put(w, SORT_TMP, temp)
    put(w, SORT_N, n)
    put(w, SORT_KIND, kind)
    put(w, SORT_RET, ret)
    put(w, SORT_CTX, ctx)
    fill_range(w, ctx, 2048, 0)
    r = 0
    k = n
    while k >= 64:
        r = r | (k & 1)
        k = k >> 1
    tc_put(w, TC_MINRUN, k + r)
    tc_put(w, TC_MIN_GALLOP, 7)
    tc_put(w, TC_PC, 1)
    return advance(w, 900)

def tc_compare(w:mutbuf, a:u64, b:u64, ret:u64) -> u64:
    kind = get(w, SORT_KIND)
    comparison = sort_compare(w, a, b, kind)
    tc_put(w, TC_PC, ret)
    if comparison != 2:
        tc_put(w, TC_COMPARE, comparison)
        return 4
    tc_put(w, TC_WAIT, 1)
    if kind == 1:
        return request(w, 10, a, b, 2, 0, 900)
    offset = choose(kind == 2, 24, 40)
    return request(w, 10, get(w, a + offset), get(w, b + offset), 0, 0, 900)

def sorting(s:readbuf, w:mutbuf) -> u64:
    if tc_get(w, TC_WAIT) != 0:
        if fact(w, 0, 0) != 2 or fact(w, 0, 8) > 1:
            return ABI
        tc_put(w, TC_COMPARE, fact(w, 0, 8))
        tc_put(w, TC_WAIT, 0)
    pc = tc_get(w, TC_PC)
    if pc < 30:
        return tc_runs(w, pc)
    if pc < 80:
        return tc_schedule(w, pc)
    if pc < 100:
        return tc_merge_start(w, pc)
    if pc < 120:
        return tc_gallop(w, pc)
    if pc < 140:
        return tc_merge_lo(w, pc)
    if pc < 160:
        return tc_merge_hi(w, pc)
    return ABI

def tc_run_done(w:mutbuf) -> u64:
    tc_put(w, TC_RUN, tc_get(w, TC_INDEX))
    return tc_pc(w, 30)

def tc_equal_reverse(w:mutbuf) -> u64:
    neq = tc_get(w, TC_NEQ)
    if neq != 0:
        count = neq + 1
        tc_reverse(w, tc_get(w, TC_POS) + tc_get(w, TC_INDEX) - count, count)
        tc_put(w, TC_NEQ, 0)
    return 0

def tc_runs(w:mutbuf, pc:u64) -> u64:
    pos = tc_get(w, TC_POS)
    remaining = get(w, SORT_N) - pos
    index = tc_get(w, TC_INDEX)
    result = tc_get(w, TC_COMPARE)
    if pc == 1:
        if remaining == 0:
            return tc_pc(w, 70)
        tc_put(w, TC_INDEX, 1)
        tc_put(w, TC_DESC, 0)
        if remaining == 1:
            return tc_run_done(w)
        if get(w, SORT_VERSION) == 312:
            return tc_compare(w, tc_item(w, pos + 1), tc_item(w, pos), 3)
        return tc_pc(w, 10)
    if pc == 3:
        tc_put(w, TC_DESC, result)
        tc_put(w, TC_INDEX, 2)
        return tc_pc(w, 4)
    if pc == 4:
        if index == remaining:
            if tc_get(w, TC_DESC) != 0:
                tc_reverse(w, pos, index)
            return tc_run_done(w)
        return tc_compare(w, tc_item(w, pos + index), tc_item(w, pos + index - 1), 5)
    if pc == 5:
        if result != tc_get(w, TC_DESC):
            if tc_get(w, TC_DESC) != 0:
                tc_reverse(w, pos, index)
            return tc_run_done(w)
        tc_put(w, TC_INDEX, index + 1)
        return tc_pc(w, 4)
    if pc == 10:
        if index == remaining:
            return tc_run_done(w)
        return tc_compare(w, tc_item(w, pos + index), tc_item(w, pos + index - 1), 11)
    if pc == 11:
        if result == 0:
            tc_put(w, TC_INDEX, index + 1)
            return tc_pc(w, 10)
        if index > 1:
            return tc_compare(w, tc_item(w, pos), tc_item(w, pos + index - 1), 13)
        tc_put(w, TC_INDEX, index + 1)
        tc_put(w, TC_NEQ, 0)
        return tc_pc(w, 14)
    if pc == 13:
        if result != 0:
            return tc_run_done(w)
        tc_reverse(w, pos, index)
        tc_put(w, TC_INDEX, index + 1)
        tc_put(w, TC_NEQ, 0)
        return tc_pc(w, 14)
    if pc == 14:
        if index == remaining:
            return tc_pc(w, 17)
        return tc_compare(w, tc_item(w, pos + index), tc_item(w, pos + index - 1), 15)
    if pc == 15:
        if result != 0:
            tc_equal_reverse(w)
            tc_put(w, TC_INDEX, index + 1)
            return tc_pc(w, 14)
        return tc_compare(w, tc_item(w, pos + index - 1), tc_item(w, pos + index), 16)
    if pc == 16:
        if result != 0:
            return tc_pc(w, 17)
        tc_put(w, TC_NEQ, tc_get(w, TC_NEQ) + 1)
        tc_put(w, TC_INDEX, index + 1)
        return tc_pc(w, 14)
    if pc == 17:
        tc_equal_reverse(w)
        tc_reverse(w, pos, index)
        return tc_pc(w, 18)
    if pc == 18:
        if index == remaining:
            return tc_run_done(w)
        return tc_compare(w, tc_item(w, pos + index), tc_item(w, pos + index - 1), 19)
    if pc == 19:
        if result != 0:
            return tc_run_done(w)
        tc_put(w, TC_INDEX, index + 1)
        return tc_pc(w, 18)
    return ABI

def tc_power(start:u64, n1:u64, n2:u64, total:u64) -> u64:
    a = start * 2 + n1
    b = a + n1 + n2
    power = 0
    done = 0
    while done == 0:
        power = power + 1
        if a >= total:
            a = a - total
            b = b - total
        elif b >= total:
            done = 1
        if done == 0:
            a = a << 1
            b = b << 1
    return power

def tc_merge_call(w:mutbuf, index:u64, ret:u64) -> u64:
    tc_put(w, TC_MERGE_I, index)
    tc_put(w, TC_MERGE_RET, ret)
    return tc_pc(w, 80)

def tc_schedule(w:mutbuf, pc:u64) -> u64:
    pos = tc_get(w, TC_POS)
    n = tc_get(w, TC_STACK_N)
    if pc == 30:
        run = tc_get(w, TC_RUN)
        if run >= tc_get(w, TC_MINRUN):
            return tc_pc(w, 50)
        remaining = get(w, SORT_N) - pos
        tc_put(w, TC_LIMIT, choose(remaining < tc_get(w, TC_MINRUN), remaining, tc_get(w, TC_MINRUN)))
        tc_put(w, TC_BSTART, choose(run == 0, 1, run))
        return tc_pc(w, 31)
    if pc == 31:
        start = tc_get(w, TC_BSTART)
        if start == tc_get(w, TC_LIMIT):
            tc_put(w, TC_RUN, start)
            return tc_pc(w, 50)
        tc_put(w, TC_PIVOT, tc_item(w, pos + start))
        tc_put(w, TC_BLO, 0)
        tc_put(w, TC_BHI, start)
        return tc_pc(w, 32)
    if pc == 32:
        mid = (tc_get(w, TC_BLO) + tc_get(w, TC_BHI)) >> 1
        tc_put(w, TC_MID, mid)
        return tc_compare(w, tc_get(w, TC_PIVOT), tc_item(w, pos + mid), 33)
    if pc == 33:
        if tc_get(w, TC_COMPARE) != 0:
            tc_put(w, TC_BHI, tc_get(w, TC_MID))
        else:
            tc_put(w, TC_BLO, tc_get(w, TC_MID) + 1)
        left = tc_get(w, TC_BLO)
        if left < tc_get(w, TC_BHI):
            return tc_pc(w, 32)
        array = get(w, SORT_ARRAY) + (pos + left) * 8
        count = tc_get(w, TC_BSTART) - left
        copy_work(w, array + 8, w, array, count * 8)
        put(w, array, tc_get(w, TC_PIVOT))
        tc_put(w, TC_BSTART, tc_get(w, TC_BSTART) + 1)
        return tc_pc(w, 31)
    if pc == 50:
        if n != 0:
            top = tc_stack(w, n - 1)
            power = tc_power(get(w, top), get(w, top + 8), tc_get(w, TC_RUN), get(w, SORT_N))
            tc_put(w, TC_POWER, power)
        return tc_pc(w, 51)
    if pc == 51:
        if n > 1 and get(w, tc_stack(w, n - 2) + 16) > tc_get(w, TC_POWER):
            return tc_merge_call(w, n - 2, 51)
        if n != 0:
            put(w, tc_stack(w, n - 1) + 16, tc_get(w, TC_POWER))
        if n >= 64:
            return ABI
        top = tc_stack(w, n)
        put(w, top, pos)
        put(w, top + 8, tc_get(w, TC_RUN))
        put(w, top + 16, 0)
        tc_put(w, TC_STACK_N, n + 1)
        tc_put(w, TC_POS, pos + tc_get(w, TC_RUN))
        return tc_pc(w, 1)
    if pc == 70:
        if n < 2:
            return advance(w, get(w, SORT_RET))
        index = n - 2
        if index > 0 and get(w, tc_stack(w, index - 1) + 8) < get(w, tc_stack(w, index + 1) + 8):
            index = index - 1
        return tc_merge_call(w, index, 70)
    return ABI

def tc_gallop_start(w:mutbuf, kind:u64, key:u64, base:u64, n:u64, hint:u64, ret:u64) -> u64:
    if n == 0 or hint >= n:
        return ABI
    tc_put(w, TC_GKIND, kind)
    tc_put(w, TC_GKEY, key)
    tc_put(w, TC_GBASE, base)
    tc_put(w, TC_GN, n)
    tc_put(w, TC_GHINT, hint)
    tc_put(w, TC_GRET, ret)
    return tc_pc(w, 100)

def tc_gcompare(w:mutbuf, index:u64, ret:u64) -> u64:
    value = get(w, tc_get(w, TC_GBASE) + index * 8)
    key = tc_get(w, TC_GKEY)
    if tc_get(w, TC_GKIND) == 0:
        return tc_compare(w, value, key, ret)
    return tc_compare(w, key, value, ret)

def tc_gallop(w:mutbuf, pc:u64) -> u64:
    hint = tc_get(w, TC_GHINT)
    kind = tc_get(w, TC_GKIND)
    result = tc_get(w, TC_COMPARE)
    ofs = tc_get(w, TC_GOFS)
    last = tc_get(w, TC_GLAST)
    right = tc_get(w, TC_GDIR)
    if pc == 100:
        return tc_gcompare(w, hint, 101)
    if pc == 101:
        right = choose(result != kind, 1, 0)
        tc_put(w, TC_GDIR, right)
        tc_put(w, TC_GOFS, 1)
        tc_put(w, TC_GLAST, 0)
        tc_put(w, TC_GMAX, choose(right != 0, tc_get(w, TC_GN) - hint, hint + 1))
        return tc_pc(w, 102)
    if pc == 102:
        if ofs >= tc_get(w, TC_GMAX):
            return tc_pc(w, 105)
        index = choose(right != 0, hint + ofs, hint - ofs)
        return tc_gcompare(w, index, 103)
    if pc == 103:
        keep = choose(right != 0, choose(result != kind, 1, 0), choose(result == kind, 1, 0))
        if keep == 0:
            return tc_pc(w, 105)
        tc_put(w, TC_GLAST, ofs)
        tc_put(w, TC_GOFS, (ofs << 1) + 1)
        return tc_pc(w, 102)
    if pc == 105:
        ofs = choose(ofs > tc_get(w, TC_GMAX), tc_get(w, TC_GMAX), ofs)
        if right != 0:
            last = last + hint
            ofs = ofs + hint
        else:
            old_last = last
            last = hint - ofs
            ofs = hint - old_last
        tc_put(w, TC_GLAST, last + 1)
        tc_put(w, TC_GOFS, ofs)
        return tc_pc(w, 106)
    if pc == 106:
        if last >= ofs:
            tc_put(w, TC_GRESULT, ofs)
            return tc_pc(w, tc_get(w, TC_GRET))
        mid = last + ((ofs - last) >> 1)
        tc_put(w, TC_GMID, mid)
        return tc_gcompare(w, mid, 107)
    if pc == 107:
        if result != kind:
            tc_put(w, TC_GLAST, tc_get(w, TC_GMID) + 1)
        else:
            tc_put(w, TC_GOFS, tc_get(w, TC_GMID))
        return tc_pc(w, 106)
    return ABI

def tc_merge_start(w:mutbuf, pc:u64) -> u64:
    if pc == 80:
        index = tc_get(w, TC_MERGE_I)
        n = tc_get(w, TC_STACK_N)
        left = tc_stack(w, index)
        right = tc_stack(w, index + 1)
        na = get(w, left + 8)
        nb = get(w, right + 8)
        a = get(w, SORT_ARRAY) + get(w, left) * 8
        b = get(w, SORT_ARRAY) + get(w, right) * 8
        if na == 0 or nb == 0 or a + na * 8 != b:
            return ABI
        tc_put(w, TC_A, a)
        tc_put(w, TC_B, b)
        tc_put(w, TC_NA, na)
        tc_put(w, TC_NB, nb)
        put(w, left + 8, na + nb)
        if index == n - 3:
            copy_work(w, right, w, tc_stack(w, index + 2), 24)
        tc_put(w, TC_STACK_N, n - 1)
        return tc_gallop_start(w, 1, get(w, b), a, na, 0, 81)
    if pc == 81:
        k = tc_get(w, TC_GRESULT)
        a = tc_get(w, TC_A) + k * 8
        na = tc_get(w, TC_NA) - k
        tc_put(w, TC_A, a)
        tc_put(w, TC_NA, na)
        if na == 0:
            return tc_pc(w, tc_get(w, TC_MERGE_RET))
        nb = tc_get(w, TC_NB)
        return tc_gallop_start(w, 0, get(w, a + (na - 1) * 8), tc_get(w, TC_B), nb, nb - 1, 82)
    if pc == 82:
        nb = tc_get(w, TC_GRESULT)
        tc_put(w, TC_NB, nb)
        if nb == 0:
            return tc_pc(w, tc_get(w, TC_MERGE_RET))
        return tc_pc(w, choose(tc_get(w, TC_NA) <= nb, 120, 140))
    return ABI

def tc_take(w:mutbuf, from_b:u64, reverse:u64) -> u64:
    slot = choose(from_b != 0, TC_B, TC_A)
    source = tc_get(w, slot)
    dest = tc_get(w, TC_DEST)
    put(w, dest, get(w, source))
    delta = choose(reverse != 0, 18446744073709551608, 8)
    tc_put(w, slot, source + delta)
    tc_put(w, TC_DEST, dest + delta)
    count = choose(from_b != 0, TC_NB, TC_NA)
    tc_put(w, count, tc_get(w, count) - 1)
    return 0

def tc_lo_end(w:mutbuf, copy_b:u64) -> u64:
    dest = tc_get(w, TC_DEST)
    if copy_b != 0:
        nb = tc_get(w, TC_NB)
        copy_work(w, dest, w, tc_get(w, TC_B), nb * 8)
        put(w, dest + nb * 8, get(w, tc_get(w, TC_A)))
    else:
        copy_work(w, dest, w, tc_get(w, TC_A), tc_get(w, TC_NA) * 8)
    return tc_pc(w, tc_get(w, TC_MERGE_RET))

def tc_merge_lo(w:mutbuf, pc:u64) -> u64:
    if pc == 120:
        a = tc_get(w, TC_A)
        temp = get(w, SORT_TMP)
        copy_work(w, temp, w, a, tc_get(w, TC_NA) * 8)
        tc_put(w, TC_DEST, a)
        tc_put(w, TC_A, temp)
        tc_take(w, 1, 0)
        if tc_get(w, TC_NB) == 0:
            return tc_lo_end(w, 0)
        if tc_get(w, TC_NA) == 1:
            return tc_lo_end(w, 1)
        tc_put(w, TC_GALLOP, tc_get(w, TC_MIN_GALLOP))
        tc_put(w, TC_ACOUNT, 0)
        tc_put(w, TC_BCOUNT, 0)
        return tc_pc(w, 121)
    if pc == 121:
        return tc_compare(w, get(w, tc_get(w, TC_B)), get(w, tc_get(w, TC_A)), 122)
    if pc == 122:
        if tc_get(w, TC_COMPARE) != 0:
            tc_take(w, 1, 0)
            count = tc_get(w, TC_BCOUNT) + 1
            tc_put(w, TC_BCOUNT, count)
            tc_put(w, TC_ACOUNT, 0)
            if tc_get(w, TC_NB) == 0:
                return tc_lo_end(w, 0)
        else:
            tc_take(w, 0, 0)
            count = tc_get(w, TC_ACOUNT) + 1
            tc_put(w, TC_ACOUNT, count)
            tc_put(w, TC_BCOUNT, 0)
            if tc_get(w, TC_NA) == 1:
                return tc_lo_end(w, 1)
        if count < tc_get(w, TC_GALLOP):
            return tc_pc(w, 121)
        tc_put(w, TC_GALLOP, tc_get(w, TC_GALLOP) + 1)
        return tc_pc(w, 124)
    if pc == 124:
        gallop = tc_get(w, TC_GALLOP)
        gallop = gallop - choose(gallop > 1, 1, 0)
        tc_put(w, TC_GALLOP, gallop)
        tc_put(w, TC_MIN_GALLOP, gallop)
        return tc_gallop_start(w, 1, get(w, tc_get(w, TC_B)), tc_get(w, TC_A), tc_get(w, TC_NA), 0, 125)
    if pc == 125:
        k = tc_get(w, TC_GRESULT)
        tc_put(w, TC_ACOUNT, k)
        if k != 0:
            copy_work(w, tc_get(w, TC_DEST), w, tc_get(w, TC_A), k * 8)
            tc_put(w, TC_DEST, tc_get(w, TC_DEST) + k * 8)
            tc_put(w, TC_A, tc_get(w, TC_A) + k * 8)
            tc_put(w, TC_NA, tc_get(w, TC_NA) - k)
            if tc_get(w, TC_NA) == 1:
                return tc_lo_end(w, 1)
            if tc_get(w, TC_NA) == 0:
                return tc_lo_end(w, 0)
        tc_take(w, 1, 0)
        if tc_get(w, TC_NB) == 0:
            return tc_lo_end(w, 0)
        return tc_gallop_start(w, 0, get(w, tc_get(w, TC_A)), tc_get(w, TC_B), tc_get(w, TC_NB), 0, 126)
    if pc == 126:
        k = tc_get(w, TC_GRESULT)
        tc_put(w, TC_BCOUNT, k)
        if k != 0:
            copy_work(w, tc_get(w, TC_DEST), w, tc_get(w, TC_B), k * 8)
            tc_put(w, TC_DEST, tc_get(w, TC_DEST) + k * 8)
            tc_put(w, TC_B, tc_get(w, TC_B) + k * 8)
            tc_put(w, TC_NB, tc_get(w, TC_NB) - k)
            if tc_get(w, TC_NB) == 0:
                return tc_lo_end(w, 0)
        tc_take(w, 0, 0)
        if tc_get(w, TC_NA) == 1:
            return tc_lo_end(w, 1)
        if tc_get(w, TC_ACOUNT) >= 7 or tc_get(w, TC_BCOUNT) >= 7:
            return tc_pc(w, 124)
        tc_put(w, TC_GALLOP, tc_get(w, TC_GALLOP) + 1)
        tc_put(w, TC_MIN_GALLOP, tc_get(w, TC_GALLOP))
        tc_put(w, TC_ACOUNT, 0)
        tc_put(w, TC_BCOUNT, 0)
        return tc_pc(w, 121)
    return ABI

def tc_hi_end(w:mutbuf, copy_a:u64) -> u64:
    dest = tc_get(w, TC_DEST)
    if copy_a != 0:
        na = tc_get(w, TC_NA)
        copy_work(w, dest - (na - 1) * 8, w, tc_get(w, TC_A) - (na - 1) * 8, na * 8)
        put(w, dest - na * 8, get(w, tc_get(w, TC_B)))
    else:
        nb = tc_get(w, TC_NB)
        if nb != 0:
            copy_work(w, dest - (nb - 1) * 8, w, tc_get(w, TC_BASE_B), nb * 8)
    return tc_pc(w, tc_get(w, TC_MERGE_RET))

def tc_merge_hi(w:mutbuf, pc:u64) -> u64:
    if pc == 140:
        a = tc_get(w, TC_A)
        b = tc_get(w, TC_B)
        temp = get(w, SORT_TMP)
        na = tc_get(w, TC_NA)
        nb = tc_get(w, TC_NB)
        copy_work(w, temp, w, b, nb * 8)
        tc_put(w, TC_BASE_A, a)
        tc_put(w, TC_BASE_B, temp)
        tc_put(w, TC_DEST, b + (nb - 1) * 8)
        tc_put(w, TC_A, a + (na - 1) * 8)
        tc_put(w, TC_B, temp + (nb - 1) * 8)
        tc_take(w, 0, 1)
        if tc_get(w, TC_NA) == 0:
            return tc_hi_end(w, 0)
        if nb == 1:
            return tc_hi_end(w, 1)
        tc_put(w, TC_GALLOP, tc_get(w, TC_MIN_GALLOP))
        tc_put(w, TC_ACOUNT, 0)
        tc_put(w, TC_BCOUNT, 0)
        return tc_pc(w, 141)
    if pc == 141:
        return tc_compare(w, get(w, tc_get(w, TC_B)), get(w, tc_get(w, TC_A)), 142)
    if pc == 142:
        if tc_get(w, TC_COMPARE) != 0:
            tc_take(w, 0, 1)
            count = tc_get(w, TC_ACOUNT) + 1
            tc_put(w, TC_ACOUNT, count)
            tc_put(w, TC_BCOUNT, 0)
            if tc_get(w, TC_NA) == 0:
                return tc_hi_end(w, 0)
        else:
            tc_take(w, 1, 1)
            count = tc_get(w, TC_BCOUNT) + 1
            tc_put(w, TC_BCOUNT, count)
            tc_put(w, TC_ACOUNT, 0)
            if tc_get(w, TC_NB) == 1:
                return tc_hi_end(w, 1)
        if count < tc_get(w, TC_GALLOP):
            return tc_pc(w, 141)
        tc_put(w, TC_GALLOP, tc_get(w, TC_GALLOP) + 1)
        return tc_pc(w, 144)
    if pc == 144:
        gallop = tc_get(w, TC_GALLOP)
        gallop = gallop - choose(gallop > 1, 1, 0)
        tc_put(w, TC_GALLOP, gallop)
        tc_put(w, TC_MIN_GALLOP, gallop)
        na = tc_get(w, TC_NA)
        return tc_gallop_start(w, 1, get(w, tc_get(w, TC_B)), tc_get(w, TC_BASE_A), na, na - 1, 145)
    if pc == 145:
        k = tc_get(w, TC_NA) - tc_get(w, TC_GRESULT)
        tc_put(w, TC_ACOUNT, k)
        if k != 0:
            tc_put(w, TC_DEST, tc_get(w, TC_DEST) - k * 8)
            tc_put(w, TC_A, tc_get(w, TC_A) - k * 8)
            copy_work(w, tc_get(w, TC_DEST) + 8, w, tc_get(w, TC_A) + 8, k * 8)
            tc_put(w, TC_NA, tc_get(w, TC_NA) - k)
            if tc_get(w, TC_NA) == 0:
                return tc_hi_end(w, 0)
        tc_take(w, 1, 1)
        if tc_get(w, TC_NB) == 1:
            return tc_hi_end(w, 1)
        nb = tc_get(w, TC_NB)
        return tc_gallop_start(w, 0, get(w, tc_get(w, TC_A)), tc_get(w, TC_BASE_B), nb, nb - 1, 146)
    if pc == 146:
        k = tc_get(w, TC_NB) - tc_get(w, TC_GRESULT)
        tc_put(w, TC_BCOUNT, k)
        if k != 0:
            tc_put(w, TC_DEST, tc_get(w, TC_DEST) - k * 8)
            tc_put(w, TC_B, tc_get(w, TC_B) - k * 8)
            copy_work(w, tc_get(w, TC_DEST) + 8, w, tc_get(w, TC_B) + 8, k * 8)
            tc_put(w, TC_NB, tc_get(w, TC_NB) - k)
            if tc_get(w, TC_NB) == 1:
                return tc_hi_end(w, 1)
            if tc_get(w, TC_NB) == 0:
                return tc_hi_end(w, 0)
        tc_take(w, 0, 1)
        if tc_get(w, TC_NA) == 0:
            return tc_hi_end(w, 0)
        if tc_get(w, TC_ACOUNT) >= 7 or tc_get(w, TC_BCOUNT) >= 7:
            return tc_pc(w, 144)
        tc_put(w, TC_GALLOP, tc_get(w, TC_GALLOP) + 1)
        tc_put(w, TC_MIN_GALLOP, tc_get(w, TC_GALLOP))
        tc_put(w, TC_ACOUNT, 0)
        tc_put(w, TC_BCOUNT, 0)
        return tc_pc(w, 141)
    return ABI
'''
