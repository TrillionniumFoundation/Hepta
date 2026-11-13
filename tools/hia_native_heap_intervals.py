"""Pure HIA interval/scalar transfer for the retained heap-budget owner.

This module authors HIA; none of its Python executes a selected transfer.
The enclosing owner supplies byte-offset get/put and one mutable arena.
Values occupy 40 bytes: kind, low sign/magnitude, high sign/magnitude.
Kinds are unknown=0, bool=1, exact int=2, and interval=3. Canonical intervals
are ordered; zero signs are zero. A degenerate kind-3 interval stays kind 3
when copied, while the original _bounded construction returns kind 2.

Inputs and output must be disjoint 40-byte regions in the actual arena.
No global word or scratch arena is reserved. Signed 128-bit mathematical
intermediates use explicit sign/high/low words; every typed endpoint has at
most a u64 magnitude. This is the verified Core domain, not a new public
integer quota. The original Python helper definitions remain independent.
"""
from __future__ import annotations

from tools.generate_hia_program_execution import OP_IDS, TYPES

TYPE_IDS = {name: index for index, name in enumerate(TYPES, 1)}
ERROR_DETAILS = {
    1: 'checked constant arithmetic may trap',
    2: 'unreviewed integer cast mode cannot qualify a heap budget',
    3: 'checked constant shift count traps',
    4: 'checked constant division or remainder traps',
    5: 'checked constant negation may trap',
}
ABI_REJECTED = 16

_BODY = r'''
def heap_cmp(asign:u64, amag:u64, bsign:u64, bmag:u64) -> u64:
    if asign != bsign:
        return choose(asign != 0, 1, 2)
    if amag == bmag:
        return 0
    if asign == 0:
        return choose(amag < bmag, 1, 2)
    return choose(amag > bmag, 1, 2)

def heap_wide_cmp(asign:u64, ahigh:u64, alow:u64, bsign:u64, bhigh:u64, blow:u64) -> u64:
    if ahigh == 0 and alow == 0:
        asign = 0
    if bhigh == 0 and blow == 0:
        bsign = 0
    if asign != bsign:
        return choose(asign != 0, 1, 2)
    if ahigh == bhigh and alow == blow:
        return 0
    smaller = ahigh < bhigh or (ahigh == bhigh and alow < blow)
    if asign == 0:
        return choose(smaller, 1, 2)
    return choose(smaller, 2, 1)

def heap_width(t:u64) -> u64:
    if t == 1 or t == 5:
        return 8
    if t == 2 or t == 6:
        return 16
    if t == 3 or t == 7:
        return 32
    if t == 4 or t == 8 or t == 9 or t == 10:
        return 64
    return 0

def heap_signed(t:u64) -> u64:
    return choose(t == 1 or t == 2 or t == 3 or t == 4 or t == 9, 1, 0)

def heap_max(t:u64) -> u64:
    width = heap_width(t)
    if heap_signed(t) != 0:
        return (1 << (width - 1)) - 1
    if width == 64:
        return 18446744073709551615
    return (1 << width) - 1

def heap_neg_limit(t:u64) -> u64:
    if heap_signed(t) == 0:
        return 0
    return 1 << (heap_width(t) - 1)

def heap_mask(t:u64) -> u64:
    width = heap_width(t)
    if width == 64:
        return 18446744073709551615
    return (1 << width) - 1

def heap_small(t:u64) -> u64:
    return choose(t == 1 or t == 2 or t == 3 or t == 5 or t == 6 or t == 7, 1, 0)

def heap_slot(w:mutbuf, at:u64) -> u64:
    return choose(at <= length(w) and length(w) - at >= 40, 1, 0)

def heap_overlap(a:u64, b:u64) -> u64:
    return choose(a < b + 40 and b < a + 40, 1, 0)

def heap_value_valid(w:mutbuf, at:u64) -> u64:
    if heap_slot(w, at) == 0:
        return 0
    kind = get(w, at)
    ls = get(w, at + 8)
    lm = get(w, at + 16)
    hs = get(w, at + 24)
    hm = get(w, at + 32)
    if kind > 3 or ls > 1 or hs > 1 or (lm == 0 and ls != 0) or (hm == 0 and hs != 0):
        return 0
    if kind == 0:
        return choose((ls | lm | hs | hm) == 0, 1, 0)
    if kind == 1:
        return choose(ls == 0 and hs == 0 and lm <= 1 and lm == hm, 1, 0)
    if kind == 2:
        return choose(ls == hs and lm == hm, 1, 0)
    return choose(heap_cmp(ls, lm, hs, hm) != 2, 1, 0)

def heap_emit(w:mutbuf, out:u64, kind:u64, ls:u64, lm:u64, hs:u64, hm:u64) -> u64:
    put(w, out, kind)
    put(w, out + 8, choose(lm == 0, 0, ls))
    put(w, out + 16, lm)
    put(w, out + 24, choose(hm == 0, 0, hs))
    put(w, out + 32, hm)
    return 0

def heap_unknown(w:mutbuf, out:u64) -> u64:
    return heap_emit(w, out, 0, 0, 0, 0, 0)

def heap_bounded(w:mutbuf, out:u64, ls:u64, lm:u64, hs:u64, hm:u64) -> u64:
    ls = choose(lm == 0, 0, ls)
    hs = choose(hm == 0, 0, hs)
    relation = heap_cmp(ls, lm, hs, hm)
    if relation == 2:
        return heap_unknown(w, out)
    return heap_emit(w, out, choose(relation == 0, 2, 3), ls, lm, hs, hm)

def heap_value_copy(w:mutbuf, out:u64, value:u64) -> u64:
    return heap_emit(w, out, get(w, value), get(w, value + 8), get(w, value + 16), get(w, value + 24), get(w, value + 32))

def heap_numeric(w:mutbuf, value:u64) -> u64:
    return choose(get(w, value) == 2 or get(w, value) == 3, 1, 0)

def heap_exact_value(w:mutbuf, value:u64) -> u64:
    return choose(heap_numeric(w, value) != 0 and get(w, value + 8) == get(w, value + 24) and get(w, value + 16) == get(w, value + 32), 1, 0)

def heap_within(t:u64, sign:u64, high:u64, low:u64) -> u64:
    if high != 0:
        return 0
    if sign != 0 and low != 0:
        return choose(heap_signed(t) != 0 and low <= heap_neg_limit(t), 1, 0)
    return choose(low <= heap_max(t), 1, 0)

def heap_raw(t:u64, sign:u64, magnitude:u64) -> u64:
    if sign != 0:
        magnitude = 0 - magnitude
    return magnitude & heap_mask(t)

def heap_wrapped(w:mutbuf, out:u64, t:u64, sign:u64, magnitude:u64) -> u64:
    raw = heap_raw(t, sign, magnitude)
    if heap_signed(t) != 0 and raw >= heap_neg_limit(t):
        magnitude = (0 - raw) & heap_mask(t)
        return heap_emit(w, out, 2, 1, magnitude, 1, magnitude)
    return heap_emit(w, out, 2, 0, raw, 0, raw)

def heap_entry_value(w:mutbuf, t:u64, out:u64) -> u64:
    if heap_slot(w, out) == 0 or t == 0 or t > @TYPE_COUNT@:
        return 16
    if heap_small(t) == 0:
        return heap_unknown(w, out)
    return heap_emit(w, out, 3, heap_signed(t), heap_neg_limit(t), 0, heap_max(t))

def heap_combine(w:mutbuf, a:u64, b:u64, out:u64) -> u64:
    if heap_value_valid(w, a) == 0 or heap_value_valid(w, b) == 0 or heap_slot(w, out) == 0:
        return 16
    if heap_overlap(out, a) != 0 or heap_overlap(out, b) != 0:
        return 16
    if get(w, a) == 1 and get(w, b) == 1:
        if get(w, a + 16) == get(w, b + 16):
            return heap_value_copy(w, out, a)
        return heap_unknown(w, out)
    if heap_numeric(w, a) == 0 or heap_numeric(w, b) == 0:
        return heap_unknown(w, out)
    low = a
    high = a
    if heap_cmp(get(w, a + 8), get(w, a + 16), get(w, b + 8), get(w, b + 16)) == 2:
        low = b
    if heap_cmp(get(w, a + 24), get(w, a + 32), get(w, b + 24), get(w, b + 32)) == 1:
        high = b
    return heap_bounded(w, out, get(w, low + 8), get(w, low + 16), get(w, high + 24), get(w, high + 32))

def heap_mul_hi(a:u64, b:u64) -> u64:
    alo = a & 4294967295
    ahi = a >> 32
    blo = b & 4294967295
    bhi = b >> 32
    first = ahi * blo + ((alo * blo) >> 32)
    second = alo * bhi + (first & 4294967295)
    return ahi * bhi + (first >> 32) + (second >> 32)

def heap_arith_part(kind:u64, sa:u64, ma:u64, sb:u64, mb:u64, part:u64) -> u64:
    if kind == 3:
        if ma == 0 or mb == 0:
            return 0
        if part == 0:
            return sa ^ sb
        if part == 1:
            return heap_mul_hi(ma, mb)
        return ma * mb
    if kind == 2 and mb != 0:
        sb = 1 - sb
    if sa == sb:
        if part == 0:
            return sa
        if part == 1:
            return choose(ma + mb < ma, 1, 0)
        return ma + mb
    if part == 1:
        return 0
    if ma == mb:
        return 0
    if part == 0:
        return choose(ma > mb, sa, sb)
    return choose(ma > mb, ma - mb, mb - ma)

def heap_binary_end(w:mutbuf, kind:u64, a:u64, b:u64, upper:u64, part:u64) -> u64:
    if kind != 3:
        left = a + 8 + upper * 16
        right = b + 8 + choose(kind == 2, 1 - upper, upper) * 16
        return heap_arith_part(kind, get(w, left), get(w, left + 8), get(w, right), get(w, right + 8), part)
    ss = 0
    sh = 0
    sl = 0
    index = 0
    while index < 4:
        left = a + 8 + (index // 2) * 16
        right = b + 8 + (index % 2) * 16
        ns = heap_arith_part(3, get(w, left), get(w, left + 8), get(w, right), get(w, right + 8), 0)
        nh = heap_arith_part(3, get(w, left), get(w, left + 8), get(w, right), get(w, right + 8), 1)
        nl = heap_arith_part(3, get(w, left), get(w, left + 8), get(w, right), get(w, right + 8), 2)
        relation = heap_wide_cmp(ns, nh, nl, ss, sh, sl)
        if index == 0 or (upper == 0 and relation == 1) or (upper == 1 and relation == 2):
            ss = ns
            sh = nh
            sl = nl
        index = index + 1
    if part == 0:
        return ss
    return choose(part == 1, sh, sl)

def heap_binary(w:mutbuf, op:u64, t:u64, a:u64, b:u64, out:u64) -> u64:
    if heap_numeric(w, a) == 0 or heap_numeric(w, b) == 0:
        return heap_unknown(w, out)
    kind = 3
    if op == @INT_ADD_CHECKED@ or op == @INT_ADD_WRAP@:
        kind = 1
    elif op == @INT_SUB_CHECKED@ or op == @INT_SUB_WRAP@:
        kind = 2
    ls = heap_binary_end(w, kind, a, b, 0, 0)
    lm = heap_binary_end(w, kind, a, b, 0, 2)
    hs = heap_binary_end(w, kind, a, b, 1, 0)
    hm = heap_binary_end(w, kind, a, b, 1, 2)
    if heap_within(t, ls, heap_binary_end(w, kind, a, b, 0, 1), lm) != 0 and heap_within(t, hs, heap_binary_end(w, kind, a, b, 1, 1), hm) != 0:
        return heap_bounded(w, out, ls, lm, hs, hm)
    if heap_exact_value(w, a) != 0 and heap_exact_value(w, b) != 0:
        if op == @INT_ADD_WRAP@ or op == @INT_SUB_WRAP@ or op == @INT_MUL_WRAP@:
            return heap_wrapped(w, out, t, ls, lm)
        return 1
    return heap_unknown(w, out)

def heap_cast(w:mutbuf, t:u64, mode:u64, a:u64, out:u64) -> u64:
    if mode != 1 and mode != 2:
        return 2
    if heap_numeric(w, a) == 0:
        if heap_small(t) != 0:
            return heap_bounded(w, out, heap_signed(t), heap_neg_limit(t), 0, heap_max(t))
        return heap_unknown(w, out)
    ls = get(w, a + 8)
    lm = get(w, a + 16)
    hs = get(w, a + 24)
    hm = get(w, a + 32)
    if mode == 1:
        if heap_cmp(ls, lm, heap_signed(t), heap_neg_limit(t)) == 1:
            ls = heap_signed(t)
            lm = heap_neg_limit(t)
        if heap_cmp(hs, hm, 0, heap_max(t)) == 2:
            hs = 0
            hm = heap_max(t)
        return heap_bounded(w, out, ls, lm, hs, hm)
    if heap_within(t, ls, 0, lm) != 0 and heap_within(t, hs, 0, hm) != 0:
        return heap_bounded(w, out, ls, lm, hs, hm)
    if heap_exact_value(w, a) != 0:
        return heap_wrapped(w, out, t, ls, lm)
    if heap_small(t) != 0:
        return heap_bounded(w, out, heap_signed(t), heap_neg_limit(t), 0, heap_max(t))
    return heap_unknown(w, out)

def heap_shift_part(left:u64, sign:u64, magnitude:u64, count:u64, part:u64) -> u64:
    if part == 0:
        return choose(magnitude == 0, 0, sign)
    if left != 0:
        if part == 1:
            if count == 0:
                return 0
            return magnitude >> (64 - count)
        return magnitude << count
    if part == 1:
        return 0
    if sign == 0:
        return magnitude >> count
    rounded = magnitude >> count
    if count != 0 and (magnitude & ((1 << count) - 1)) != 0:
        rounded = rounded + 1
    return rounded

def heap_shift_end(w:mutbuf, left:u64, a:u64, b:u64, upper:u64, part:u64) -> u64:
    ss = 0
    sh = 0
    sl = 0
    index = 0
    while index < 4:
        value = a + 8 + (index // 2) * 16
        amount = get(w, b + 16 + (index % 2) * 16)
        ns = heap_shift_part(left, get(w, value), get(w, value + 8), amount, 0)
        nh = heap_shift_part(left, get(w, value), get(w, value + 8), amount, 1)
        nl = heap_shift_part(left, get(w, value), get(w, value + 8), amount, 2)
        relation = heap_wide_cmp(ns, nh, nl, ss, sh, sl)
        if index == 0 or (upper == 0 and relation == 1) or (upper == 1 and relation == 2):
            ss = ns
            sh = nh
            sl = nl
        index = index + 1
    if part == 0:
        return ss
    return choose(part == 1, sh, sl)

def heap_shift(w:mutbuf, op:u64, t:u64, a:u64, b:u64, out:u64) -> u64:
    if heap_numeric(w, a) == 0 or heap_numeric(w, b) == 0:
        return heap_unknown(w, out)
    if get(w, b + 8) != 0 or get(w, b + 32) >= heap_width(t):
        if heap_exact_value(w, a) != 0 and heap_exact_value(w, b) != 0:
            return 3
        return heap_unknown(w, out)
    left = choose(op == @INT_SHL_CHECKED@, 1, 0)
    ls = heap_shift_end(w, left, a, b, 0, 0)
    lm = heap_shift_end(w, left, a, b, 0, 2)
    hs = heap_shift_end(w, left, a, b, 1, 0)
    hm = heap_shift_end(w, left, a, b, 1, 2)
    if left != 0:
        if heap_within(t, ls, heap_shift_end(w, left, a, b, 0, 1), lm) == 0 or heap_within(t, hs, heap_shift_end(w, left, a, b, 1, 1), hm) == 0:
            if heap_exact_value(w, a) != 0 and heap_exact_value(w, b) != 0:
                return heap_wrapped(w, out, t, ls, lm)
            return heap_unknown(w, out)
    return heap_bounded(w, out, ls, lm, hs, hm)

def heap_or_xor(w:mutbuf, t:u64, a:u64, b:u64, out:u64) -> u64:
    if heap_numeric(w, a) == 0 or heap_numeric(w, b) == 0:
        return heap_unknown(w, out)
    if get(w, a + 8) != 0 or get(w, b + 8) != 0 or get(w, a + 32) > heap_max(t) or get(w, b + 32) > heap_max(t):
        return heap_unknown(w, out)
    top = choose(get(w, a + 32) > get(w, b + 32), get(w, a + 32), get(w, b + 32))
    ceiling = 0
    while top != 0:
        ceiling = (ceiling << 1) | 1
        top = top >> 1
    if ceiling > heap_max(t):
        return heap_unknown(w, out)
    return heap_bounded(w, out, 0, 0, 0, ceiling)

def heap_bitnot(w:mutbuf, t:u64, a:u64, out:u64) -> u64:
    if heap_numeric(w, a) == 0:
        return heap_unknown(w, out)
    if heap_within(t, get(w, a + 8), 0, get(w, a + 16)) == 0 or heap_within(t, get(w, a + 24), 0, get(w, a + 32)) == 0:
        return heap_unknown(w, out)
    if heap_signed(t) == 0:
        return heap_bounded(w, out, 0, heap_mask(t) - get(w, a + 32), 0, heap_mask(t) - get(w, a + 16))
    ls = choose(get(w, a + 24) == 0, 1, 0)
    lm = choose(get(w, a + 24) == 0, get(w, a + 32) + 1, get(w, a + 32) - 1)
    hs = choose(get(w, a + 8) == 0, 1, 0)
    hm = choose(get(w, a + 8) == 0, get(w, a + 16) + 1, get(w, a + 16) - 1)
    return heap_bounded(w, out, ls, lm, hs, hm)

def heap_and_mask(w:mutbuf, t:u64, a:u64, b:u64, out:u64) -> u64:
    found = 0
    upper = 0
    index = 0
    while index < 2:
        value = choose(index == 0, a, b)
        if heap_numeric(w, value) != 0 and get(w, value + 8) == 0 and get(w, value + 32) <= heap_max(t):
            if found == 0 or get(w, value + 32) < upper:
                upper = get(w, value + 32)
            found = 1
        index = index + 1
    if found == 0:
        return heap_unknown(w, out)
    return heap_bounded(w, out, 0, 0, 0, upper)

def heap_divrem(w:mutbuf, op:u64, t:u64, a:u64, b:u64, out:u64) -> u64:
    if heap_numeric(w, b) == 0:
        return heap_unknown(w, out)
    if get(w, b + 16) == 0 and get(w, b + 32) == 0:
        return 4
    positive = get(w, b + 8) == 0 and get(w, b + 16) != 0
    partial = heap_exact_value(w, a) == 0 or heap_exact_value(w, b) == 0
    if heap_signed(t) == 0 and op == @INT_REM_CHECKED@ and positive and partial:
        return heap_bounded(w, out, 0, 0, 0, get(w, b + 32) - 1)
    if positive and (heap_signed(t) != 0 or op == @INT_DIV_CHECKED@):
        ls = heap_signed(t)
        lm = heap_neg_limit(t)
        hs = 0
        hm = heap_max(t)
        if heap_numeric(w, a) != 0:
            ls = get(w, a + 8)
            lm = get(w, a + 16)
            hs = get(w, a + 24)
            hm = get(w, a + 32)
        if heap_within(t, ls, 0, lm) == 0 or heap_within(t, hs, 0, hm) == 0 or get(w, b + 32) > heap_max(t):
            return heap_unknown(w, out)
        if partial:
            if heap_signed(t) == 0:
                return heap_bounded(w, out, 0, lm // get(w, b + 32), 0, hm // get(w, b + 16))
            if op == @INT_DIV_CHECKED@:
                lm = choose(ls != 0, lm // get(w, b + 16), 0)
                hm = choose(hs == 0, hm // get(w, b + 16), 0)
                return heap_bounded(w, out, 1, lm, 0, hm)
            upper = get(w, b + 32) - 1
            return heap_bounded(w, out, 1, choose(ls != 0 and lm != 0, upper, 0), 0, choose(hs == 0 and hm != 0, upper, 0))
    if heap_exact_value(w, a) == 0 or heap_exact_value(w, b) == 0:
        return heap_unknown(w, out)
    ma = get(w, a + 16)
    mb = get(w, b + 16)
    if mb == 0 or (heap_signed(t) != 0 and get(w, a + 8) != 0 and ma == heap_neg_limit(t) and get(w, b + 8) != 0 and mb == 1):
        return 4
    quotient = ma // mb
    if op == @INT_DIV_CHECKED@:
        sign = get(w, a + 8) ^ get(w, b + 8)
        return heap_emit(w, out, 2, sign, quotient, sign, quotient)
    remainder = ma - quotient * mb
    return heap_emit(w, out, 2, get(w, a + 8), remainder, get(w, a + 8), remainder)

def heap_exact(w:mutbuf, op:u64, t:u64, a:u64, b:u64, out:u64) -> u64:
    comparison = op == @COMPARE_EQ@ or op == @COMPARE_NE@ or op == @COMPARE_LT@ or op == @COMPARE_LE@ or op == @COMPARE_GT@ or op == @COMPARE_GE@
    if comparison and (get(w, a) == 1 or get(w, b) == 1):
        if get(w, a) != 1 or get(w, b) != 1 or (op != @COMPARE_EQ@ and op != @COMPARE_NE@):
            return heap_unknown(w, out)
        equal = get(w, a + 16) == get(w, b + 16)
        truth = choose(op == @COMPARE_EQ@, choose(equal, 1, 0), choose(equal, 0, 1))
        return heap_emit(w, out, 1, 0, truth, 0, truth)
    if heap_exact_value(w, a) == 0 or (op != @BIT_NOT@ and heap_exact_value(w, b) == 0):
        return heap_unknown(w, out)
    if comparison:
        relation = heap_cmp(get(w, a + 8), get(w, a + 16), get(w, b + 8), get(w, b + 16))
        truth = 0
        if op == @COMPARE_EQ@:
            truth = choose(relation == 0, 1, 0)
        elif op == @COMPARE_NE@:
            truth = choose(relation != 0, 1, 0)
        elif op == @COMPARE_LT@:
            truth = choose(relation == 1, 1, 0)
        elif op == @COMPARE_LE@:
            truth = choose(relation != 2, 1, 0)
        elif op == @COMPARE_GT@:
            truth = choose(relation == 2, 1, 0)
        elif op == @COMPARE_GE@:
            truth = choose(relation != 1, 1, 0)
        return heap_emit(w, out, 1, 0, truth, 0, truth)
    if op == @INT_DIV_CHECKED@ or op == @INT_REM_CHECKED@:
        return heap_divrem(w, op, t, a, b, out)
    if op == @INT_SHL_CHECKED@ or op == @INT_SHR_CHECKED@:
        return heap_shift(w, op, t, a, b, out)
    first = heap_raw(t, get(w, a + 8), get(w, a + 16))
    if op == @BIT_NOT@:
        return heap_wrapped(w, out, t, 0, first ^ heap_mask(t))
    second = heap_raw(t, get(w, b + 8), get(w, b + 16))
    if op == @BIT_AND@:
        return heap_wrapped(w, out, t, 0, first & second)
    if op == @BIT_OR@:
        return heap_wrapped(w, out, t, 0, first | second)
    if op == @BIT_XOR@:
        return heap_wrapped(w, out, t, 0, first ^ second)
    return heap_unknown(w, out)

def heap_negate(w:mutbuf, t:u64, a:u64, out:u64) -> u64:
    if heap_numeric(w, a) == 0:
        return heap_unknown(w, out)
    ls = choose(get(w, a + 32) == 0, 0, 1 - get(w, a + 24))
    lm = get(w, a + 32)
    hs = choose(get(w, a + 16) == 0, 0, 1 - get(w, a + 8))
    hm = get(w, a + 16)
    if heap_within(t, ls, 0, lm) != 0 and heap_within(t, hs, 0, hm) != 0:
        return heap_bounded(w, out, ls, lm, hs, hm)
    if heap_exact_value(w, a) != 0:
        return 5
    return heap_unknown(w, out)

def heap_fold(w:mutbuf, op:u64, t:u64, mode:u64, a:u64, b:u64, c:u64, out:u64) -> u64:
    if heap_value_valid(w, a) == 0 or heap_value_valid(w, b) == 0 or heap_value_valid(w, c) == 0 or heap_slot(w, out) == 0:
        return 16
    if heap_overlap(out, a) != 0 or heap_overlap(out, b) != 0 or heap_overlap(out, c) != 0 or t == 0 or t > @TYPE_COUNT@:
        return 16
    if op == @SELECT@:
        if get(w, a) == 1:
            return heap_value_copy(w, out, choose(get(w, a + 16) != 0, b, c))
        return heap_combine(w, b, c, out)
    if op == @BOOL_NOT@:
        if get(w, a) == 1:
            truth = 1 - get(w, a + 16)
            return heap_emit(w, out, 1, 0, truth, 0, truth)
        return heap_unknown(w, out)
    if op == @BOOL_AND@ or op == @BOOL_OR@:
        if get(w, a) != 1 or get(w, b) != 1:
            return heap_unknown(w, out)
        truth = get(w, a + 16) & get(w, b + 16)
        if op == @BOOL_OR@:
            truth = get(w, a + 16) | get(w, b + 16)
        return heap_emit(w, out, 1, 0, truth, 0, truth)
    if op == @COMPARE_EQ@ or op == @COMPARE_NE@ or op == @COMPARE_LT@ or op == @COMPARE_LE@ or op == @COMPARE_GT@ or op == @COMPARE_GE@:
        return heap_exact(w, op, t, a, b, out)
    if heap_width(t) == 0:
        return 16
    if op == @INT_ADD_CHECKED@ or op == @INT_SUB_CHECKED@ or op == @INT_MUL_CHECKED@ or op == @INT_ADD_WRAP@ or op == @INT_SUB_WRAP@ or op == @INT_MUL_WRAP@:
        return heap_binary(w, op, t, a, b, out)
    if op == @INT_CAST@:
        return heap_cast(w, t, mode, a, out)
    if op == @INT_SHL_CHECKED@ or op == @INT_SHR_CHECKED@:
        return heap_shift(w, op, t, a, b, out)
    if op == @INT_DIV_CHECKED@ or op == @INT_REM_CHECKED@:
        return heap_divrem(w, op, t, a, b, out)
    if op == @INT_NEG_CHECKED@:
        return heap_negate(w, t, a, out)
    if op == @BIT_NOT@ or op == @BIT_AND@ or op == @BIT_OR@ or op == @BIT_XOR@:
        status = heap_exact(w, op, t, a, b, out)
        if status != 0 or get(w, out) != 0:
            return status
        if op == @BIT_NOT@:
            return heap_bitnot(w, t, a, out)
        if op == @BIT_AND@:
            return heap_and_mask(w, t, a, b, out)
        return heap_or_xor(w, t, a, b, out)
    return heap_unknown(w, out)
'''

BODY = _BODY.replace('@TYPE_COUNT@', str(len(TYPES)))
for _name, _value in OP_IDS.items():
    BODY = BODY.replace('@' + _name.upper().replace('.', '_') + '@', str(_value))
if '@' in BODY:
    raise ValueError('unresolved native heap interval authoring constant')
