"""Author the whole Hepta source grammar as an iterative HIA task machine.

Development source: generated HIA makes grammar decisions. Token transport and
AST object materialization stay separate. No production/default closure claim.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_source_lexer_native import KEYWORD_ORDER, PAIR_ORDER
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

# Header256, 4112 fixed128-byte tasks, padding, (5*4096+64)128-byte nodes.
AST_BASE=528384
WORKSPACE=3158016
SOURCE=r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 3158016 or length(s) < 48 or length(s) > 1048576:
        return 4294967293
    count = read_word(s, 8)
    payload = read_word(s, 32)
    if read_word(s, 0) != 3549479791681612104 or count == 0 or count > 4096 or read_word(s, 16) >= count or read_word(s, 24) > 96:
        return 4294967293
    if payload != 48 + count * 56 or payload > length(s) or read_word(s, 40) != length(s) - payload:
        return 4294967293
    i = 0
    last = 0
    while i < count:
        row = 48 + i * 56
        k = read_word(s, row)
        if valid_kind(k) == 0 or read_word(s, row + 8) < last or read_word(s, row + 16) < read_word(s, row + 8) or read_word(s, row + 24) == 0 or read_word(s, row + 32) == 0:
            return 4294967293
        if read_word(s, row + 40) > read_word(s, row + 48) or read_word(s, row + 48) > length(s) - payload:
            return 4294967293
        if (k == 0 and i + 1 != count) or (i + 1 == count and k != 0):
            return 4294967293
        last = read_word(s, row + 16)
        i = i + 1
    i = 0
    while i < 256:
        put(w, i, 0)
        i = i + 8
    put(w, 0, read_word(s, 16))
    put(w, 32, read_word(s, 24))
    push(s, w, 1, 0, 0)
    run(s, w)
    if get(w, 40) == 0:
        namespaces(s, w)
    if get(w, 40) == 0:
        tree_depth(w)
    if get(w, 40) == 999:
        return 4294967292
    nodes = get(w, 24)
    splits = get(w, 120)
    size = 128 + nodes * 128 + splits * 16
    if length(o) < size:
        return 4294967294
    i = 0
    while i < 128:
        put(o, i, 0)
        i = i + 8
    put(o, 0, 3549479791681612105)
    put(o, 8, nodes)
    put(o, 16, splits)
    put(o, 24, get(w, 0))
    put(o, 32, get(w, 8))
    put(o, 40, get(w, 80))
    put(o, 48, get(w, 40))
    put(o, 56, get(w, 48))
    put(o, 64, get(w, 56))
    put(o, 72, get(w, 64))
    put(o, 80, get(w, 72))
    put(o, 88, get(w, 88))
    i = 0
    while i < nodes * 128:
        put(o, 128 + i, get(w, 528384 + i))
        i = i + 8
    i = 0
    while i < splits:
        split = get(w, 128)
        put(o, 128 + nodes * 128 + i * 16, field(w, split, 3))
        put(o, 136 + nodes * 128 + i * 16, field(w, split, 4))
        put(w, 128, field(w, split, 5))
        i = i + 1
    return size

def valid_kind(k:u64) -> u64:
    if k <= 5 or (k >= 128 and k < 157) or (k >= 512 and k < 524) or (k >= 256 and k < 384):
        return 1
    return 0

def current(s:readbuf, w:mutbuf) -> u64:
    if get(w, 8) != 0:
        return get(w, 8)
    return read_word(s, 48 + get(w, 0) * 56)

def mark(w:mutbuf) -> u64:
    return get(w, 0) * 2 + choose(get(w, 8) != 0, 1, 0)

def advance(s:readbuf, w:mutbuf) -> u64:
    m = mark(w)
    if current(s, w) != 0:
        put(w, 112, m)
        put(w, 0, get(w, 0) + 1)
        put(w, 8, 0)
    return m + 1

def take(s:readbuf, w:mutbuf, k:u64) -> u64:
    if current(s, w) == k:
        advance(s, w)
        return 1
    return 0

def fail(w:mutbuf, code:u64, begin:u64, end:u64, arg:u64, ref:u64) -> u64:
    if get(w, 40) == 0:
        put(w, 40, code)
        put(w, 48, begin)
        put(w, 56, end)
        put(w, 64, arg)
        put(w, 88, ref)
    return 0

def expected(s:readbuf, w:mutbuf, k:u64, code:u64) -> u64:
    if current(s, w) != k:
        return fail(w, code, mark(w), mark(w), k, 0)
    return advance(s, w)

def token_equal(s:readbuf, a:u64, b:u64) -> u64:
    if a == 0 or b == 0:
        return choose(a == b, 1, 0)
    ra = 48 + ((a - 1) >> 1) * 56
    rb = 48 + ((b - 1) >> 1) * 56
    x = read_word(s, ra + 40)
    y = read_word(s, rb + 40)
    n = read_word(s, ra + 48) - x
    if n != read_word(s, rb + 48) - y:
        return 0
    i = 0
    while i < n:
        if byte(s, read_word(s, 32) + x + i) != byte(s, read_word(s, 32) + y + i):
            return 0
        i = i + 1
    return 1

def word_is(s:readbuf, ref:u64, word:u64, size:u64) -> u64:
    if ref == 0:
        return 0
    row = 48 + ((ref - 1) >> 1) * 56
    at = read_word(s, 32) + read_word(s, row + 40)
    if read_word(s, row + 48) - read_word(s, row + 40) != size:
        return 0
    i = 0
    while i < size:
        if byte(s, at + i) != ((word >> (i * 8)) & 255):
            return 0
        i = i + 1
    return 1

def field(w:mutbuf, n:u64, slot:u64) -> u64:
    return get(w, 528384 + (n - 1) * 128 + slot * 8)

def set_field(w:mutbuf, n:u64, slot:u64, value:u64) -> u64:
    put(w, 528384 + (n - 1) * 128 + slot * 8, value)
    return 0

def node(s:readbuf, w:mutbuf, tag:u64, start:u64, end:u64) -> u64:
    n = get(w, 24) + 1
    if n > read_word(s, 8) * 5 + 64:
        fail(w, 999, mark(w), mark(w), 0, 0)
        return 1
    put(w, 24, n)
    i = 0
    while i < 16:
        set_field(w, n, i, 0)
        i = i + 1
    set_field(w, n, 0, tag)
    set_field(w, n, 1, start)
    set_field(w, n, 2, end)
    return n

def append(s:readbuf, w:mutbuf, owner:u64, slot:u64, value:u64) -> u64:
    n = node(s, w, 1, 0, 0)
    set_field(w, n, 3, value)
    last = field(w, owner, slot)
    if last == 0:
        set_field(w, owner, slot, n)
    else:
        while field(w, last, 4) != 0:
            last = field(w, last, 4)
        set_field(w, last, 4, n)
    return n

def edge(s:readbuf, w:mutbuf, owner:u64, value:u64) -> u64:
    append(s, w, owner, 15, value)
    return 0

def attach_expr(s:readbuf, w:mutbuf, owner:u64, child:u64) -> u64:
    append(s, w, owner, 5, child)
    edge(s, w, owner, child)
    return 0

def frame(w:mutbuf) -> u64:
    return 256 + (get(w, 16) - 1) * 128

def push(s:readbuf, w:mutbuf, kind:u64, a:u64, b:u64) -> u64:
    depth = get(w, 16)
    if depth >= 4112:
        return fail(w, 999, mark(w), mark(w), 0, 0)
    if kind == 5 or kind == 7 or kind == 8:
        if get(w, 32) + 1 > 96:
            return fail(w, 7, mark(w), mark(w), 0, 0)
        put(w, 32, get(w, 32) + 1)
    f = 256 + depth * 128
    i = 0
    while i < 128:
        put(w, f + i, 0)
        i = i + 8
    put(w, f, kind)
    put(w, f + 16, mark(w))
    put(w, f + 40, a)
    put(w, f + 48, b)
    put(w, 16, depth + 1)
    return 0

def finish(w:mutbuf, result:u64) -> u64:
    f = frame(w)
    kind = get(w, f)
    if kind == 5 or kind == 7 or kind == 8:
        put(w, 32, get(w, 32) - 1)
    put(w, 16, get(w, 16) - 1)
    put(w, 104, result)
    return 0

def close_type(s:readbuf, w:mutbuf) -> u64:
    k = current(s, w)
    if k == K_SHR or k == K_GE:
        n = node(s, w, 3, 0, 0)
        set_field(w, n, 3, get(w, 0))
        set_field(w, n, 4, k)
        if get(w, 136) == 0:
            put(w, 128, n)
        else:
            set_field(w, get(w, 136), 5, n)
        put(w, 136, n)
        put(w, 120, get(w, 120) + 1)
        put(w, 112, get(w, 0) * 2)
        put(w, 8, choose(k == K_GE, 317, 318))
        return 1
    return expected(s, w, 318, 5)

def path(s:readbuf, w:mutbuf, first_error:u64, next_error:u64) -> u64:
    ref = expected(s, w, 1, first_error)
    head = node(s, w, 2, 0, 0)
    set_field(w, head, 3, ref)
    last = head
    while take(s, w, K_PATH) == 1 and get(w, 40) == 0:
        ref = expected(s, w, 1, next_error)
        n = node(s, w, 2, 0, 0)
        set_field(w, n, 3, ref)
        set_field(w, last, 4, n)
        last = n
    return head

def path_last(w:mutbuf, n:u64) -> u64:
    while field(w, n, 4) != 0:
        n = field(w, n, 4)
    return field(w, n, 3)

def path_count(w:mutbuf, n:u64) -> u64:
    count = 0
    while n != 0:
        count = count + 1
        n = field(w, n, 4)
    return count

def list_count(w:mutbuf, n:u64) -> u64:
    count = 0
    while n != 0:
        count = count + 1
        n = field(w, n, 4)
    return count

def type_step(s:readbuf, w:mutbuf) -> u64:
    f = frame(w)
    phase = get(w, f + 8)
    n = get(w, f + 24)
    if phase == 0:
        k = current(s, w)
        tag = 10
        if k == K_READ:
            tag = 15
        if k == K_MUT:
            tag = 16
        if k == K_RAW:
            tag = 13
        if k == 347:
            tag = 12
        n = node(s, w, tag, mark(w), mark(w))
        put(w, f + 24, n)
        if tag == 15 or tag == 16:
            advance(s, w)
            set_field(w, n, 4, expected(s, w, 2, 3))
            put(w, f + 8, 1)
            push(s, w, 8, 0, 0)
            return 0
        if tag == 13:
            advance(s, w)
            if current(s, w) != K_CONST and current(s, w) != K_MUT:
                return fail(w, 4, mark(w), mark(w), 0, 0)
            if current(s, w) == K_MUT:
                set_field(w, n, 0, 14)
            advance(s, w)
            put(w, f + 8, 1)
            push(s, w, 8, 0, 0)
            return 0
        if tag == 12:
            advance(s, w)
            put(w, f + 8, 2)
            push(s, w, 8, 0, 0)
            return 0
        names = path(s, w, 1, 2)
        set_field(w, n, 3, names)
        if take(s, w, 316) == 1:
            put(w, f + 8, 3)
        else:
            put(w, f + 8, 6)
        return 0
    if phase == 1:
        set_field(w, n, 3, get(w, 104))
        set_field(w, n, 2, get(w, 112))
        return finish(w, n)
    if phase == 2:
        set_field(w, n, 3, get(w, 104))
        if take(s, w, 315) == 1:
            set_field(w, n, 0, 11)
            set_field(w, n, 4, expected(s, w, 3, 6))
        expected(s, w, 349, 9)
        set_field(w, n, 2, get(w, 112))
        return finish(w, n)
    if phase == 3:
        if current(s, w) == 2:
            append(s, w, n, 5, advance(s, w))
            put(w, f + 8, 5)
        else:
            put(w, f + 8, 4)
            push(s, w, 8, 0, 0)
        return 0
    if phase == 4:
        append(s, w, n, 4, get(w, 104))
        put(w, f + 8, 5)
        return 0
    if phase == 5:
        if take(s, w, 300) == 1:
            put(w, f + 8, 3)
        else:
            close_type(s, w)
            put(w, f + 8, 6)
        return 0
    names = field(w, n, 3)
    ref = field(w, names, 3)
    if path_count(w, names) == 1 and list_count(w, field(w, n, 4)) != 1:
        if word_is(s, ref, 125780153759042, 6) == 1 or word_is(s, ref, 1802723668, 4) == 1 or word_is(s, ref, 125780290692435, 6) == 1:
            fail(w, 8, mark(w), mark(w), ref, 0)
    set_field(w, n, 2, get(w, 112))
    return finish(w, n)
'''

# Remaining task-machine families are appended below during development.
SOURCE+=r'''
def precedence(k:u64) -> u64:
    if k == K_OROR:
        return 1
    if k == K_ANDAND:
        return 2
    if k == 380:
        return 3
    if k == 350:
        return 4
    if k == 294:
        return 5
    if k == K_EQ or k == K_NE:
        return 6
    if k == 316 or k == 318 or k == K_LE or k == K_GE:
        return 7
    if k == K_SHL or k == K_SHR:
        return 8
    if k == 299 or k == 301:
        return 9
    if k == 298 or k == 303 or k == 293:
        return 10
    return 0

def expr_step(s:readbuf, w:mutbuf) -> u64:
    f = frame(w)
    phase = get(w, f + 8)
    left = get(w, f + 24)
    if phase == 0:
        k = current(s, w)
        ref = advance(s, w)
        start = ref - 1
        put(w, f + 16, start)
        put(w, f + 32, ref)
        if k == 3 or k == 4 or k == K_TRUE or k == K_FALSE:
            tag = choose(k == 3, 40, choose(k == 4, 41, 42))
            left = node(s, w, tag, start, start)
            set_field(w, left, 3, choose(k == K_TRUE or k == K_FALSE, choose(k == K_TRUE, 1, 0), ref))
            put(w, f + 24, left)
            put(w, f + 8, 10)
            return 0
        if k == 301 or k == 289 or k == K_READ or k == K_MUT or k == K_MOVE:
            put(w, f + 8, 1)
            push(s, w, 7, 12, get(w, f + 48))
            return 0
        if k == 1:
            names = node(s, w, 2, 0, 0)
            set_field(w, names, 3, ref)
            put(w, f + 56, names)
            put(w, f + 64, names)
            put(w, f + 8, 3)
            return 0
        if k == 296:
            put(w, f + 8, 2)
            push(s, w, 7, 0, 1)
            return 0
        if k == 347:
            left = node(s, w, 51, start, start)
            put(w, f + 24, left)
            put(w, f + 72, 349)
            put(w, f + 8, 12)
            return 0
        if k == 5:
            return fail(w, 54, start, start, ref, 0)
        return fail(w, 55, start, start, ref, 0)
    if phase == 1:
        operand = get(w, 104)
        left = node(s, w, 43, get(w, f + 16), field(w, operand, 2))
        set_field(w, left, 3, get(w, f + 32))
        attach_expr(s, w, left, operand)
        put(w, f + 24, left)
        put(w, f + 8, 10)
        return 0
    if phase == 2:
        left = get(w, 104)
        expected(s, w, 297, 9)
        set_field(w, left, 1, get(w, f + 16))
        set_field(w, left, 2, get(w, 112))
        put(w, f + 24, left)
        put(w, f + 8, 10)
        return 0
    if phase == 3:
        if take(s, w, K_PATH) == 1:
            if current(s, w) == 316:
                if get(w, f + 80) != 0:
                    return fail(w, 52, mark(w), mark(w), 0, 0)
                put(w, f + 8, 4)
                push(s, w, 11, 0, 0)
            else:
                ref = expected(s, w, 1, 51)
                n = node(s, w, 2, 0, 0)
                set_field(w, n, 3, ref)
                set_field(w, get(w, f + 64), 4, n)
                put(w, f + 64, n)
            return 0
        names = get(w, f + 56)
        if path_count(w, names) > 1:
            q = node(s, w, 4, get(w, f + 16), get(w, 112))
            set_field(w, q, 3, names)
            append(s, w, get(w, 80), 8, q)
        left = node(s, w, 44, get(w, f + 16), get(w, 112))
        set_field(w, left, 3, names)
        set_field(w, left, 4, get(w, f + 80))
        put(w, f + 24, left)
        if get(w, f + 48) == 1 and take(s, w, 379) == 1:
            set_field(w, left, 0, 50)
            put(w, f + 8, 5)
        else:
            put(w, f + 8, 10)
        return 0
    if phase == 4:
        bag = get(w, 104)
        put(w, f + 80, field(w, bag, 3))
        put(w, f + 8, 3)
        return 0
    if phase == 5:
        if current(s, w) == 381:
            advance(s, w)
            set_field(w, left, 2, get(w, 112))
            put(w, f + 8, 10)
        else:
            append(s, w, left, 6, field_name(s, w))
            expected(s, w, 314, 9)
            put(w, f + 8, 6)
            push(s, w, 7, 0, 1)
        return 0
    if phase == 6:
        attach_expr(s, w, left, get(w, 104))
        if take(s, w, 300) == 1:
            put(w, f + 8, 5)
        else:
            expected(s, w, 381, 53)
            set_field(w, left, 2, get(w, 112))
            put(w, f + 8, 10)
        return 0
    if phase == 10:
        k = current(s, w)
        if k == 296:
            if field(w, left, 0) != 44:
                return fail(w, 50, mark(w), mark(w), 0, 0)
            advance(s, w)
            set_field(w, left, 0, 45)
            put(w, f + 72, 297)
            put(w, f + 8, 12)
            return 0
        if take(s, w, 347) == 1:
            put(w, f + 8, 14)
            push(s, w, 7, 0, 1)
            return 0
        if take(s, w, 302) == 1:
            ref = field_name(s, w)
            n = node(s, w, 47, field(w, left, 1), get(w, 112))
            set_field(w, n, 3, ref)
            attach_expr(s, w, n, left)
            put(w, f + 24, n)
            return 0
        if k == K_AS and get(w, f + 40) <= 11:
            advance(s, w)
            put(w, f + 8, 15)
            push(s, w, 8, 0, 0)
            return 0
        p = precedence(k)
        if p != 0 and p >= get(w, f + 40):
            put(w, f + 32, advance(s, w))
            put(w, f + 8, 16)
            push(s, w, 7, p + 1, get(w, f + 48))
            return 0
        return finish(w, left)
    if phase == 12:
        if current(s, w) == get(w, f + 72):
            advance(s, w)
            set_field(w, left, 2, get(w, 112))
            put(w, f + 8, 10)
        else:
            put(w, f + 8, 13)
            push(s, w, 7, 0, 1)
        return 0
    if phase == 13:
        attach_expr(s, w, left, get(w, 104))
        if take(s, w, 300) == 1:
            put(w, f + 8, 12)
        else:
            expected(s, w, get(w, f + 72), 9)
            set_field(w, left, 2, get(w, 112))
            put(w, f + 8, 10)
        return 0
    if phase == 14:
        expected(s, w, 349, 9)
        child = get(w, 104)
        n = node(s, w, 46, field(w, left, 1), get(w, 112))
        attach_expr(s, w, n, left)
        attach_expr(s, w, n, child)
        put(w, f + 24, n)
        put(w, f + 8, 10)
        return 0
    if phase == 15:
        n = node(s, w, 48, field(w, left, 1), get(w, 112))
        set_field(w, n, 3, get(w, 104))
        attach_expr(s, w, n, left)
        put(w, f + 24, n)
        put(w, f + 8, 10)
        return 0
    child = get(w, 104)
    n = node(s, w, 49, field(w, left, 1), field(w, child, 2))
    set_field(w, n, 3, get(w, f + 32))
    attach_expr(s, w, n, left)
    attach_expr(s, w, n, child)
    put(w, f + 24, n)
    put(w, f + 8, 10)
    return 0

def field_name(s:readbuf, w:mutbuf) -> u64:
    if current(s, w) == K_MATCH:
        return advance(s, w)
    return expected(s, w, 1, 12)

def block_step(s:readbuf, w:mutbuf) -> u64:
    f = frame(w)
    n = get(w, f + 24)
    phase = get(w, f + 8)
    if phase == 0:
        expected(s, w, 379, 9)
        n = node(s, w, 30, get(w, f + 16), get(w, 112))
        put(w, f + 24, n)
        put(w, f + 8, 1)
        return 0
    if phase == 2:
        append(s, w, n, 3, get(w, 104))
        put(w, f + 8, 1)
        return 0
    if take(s, w, 381) == 1:
        set_field(w, n, 2, get(w, 112))
        return finish(w, n)
    if current(s, w) == 0:
        return fail(w, 38, mark(w), mark(w), 0, 0)
    put(w, f + 8, 2)
    push(s, w, 6, 0, 0)
    return 0

def body_edges(s:readbuf, w:mutbuf, owner:u64, block:u64) -> u64:
    items = field(w, block, 3)
    while items != 0:
        edge(s, w, owner, field(w, items, 3))
        items = field(w, items, 4)
    return 0

def stmt_step(s:readbuf, w:mutbuf) -> u64:
    f = frame(w)
    phase = get(w, f + 8)
    n = get(w, f + 24)
    if phase == 0:
        k = current(s, w)
        tag = 68
        if k == K_LET:
            tag = 60
        if k == K_RETURN:
            tag = 61
        if k == K_FOR:
            tag = 62
        if k == K_WHILE:
            tag = 63
        if k == K_IF:
            tag = 64
        if k == K_UNSAFE:
            tag = 65
        if k == K_MATCH:
            tag = 66
        n = node(s, w, tag, mark(w), mark(w))
        put(w, f + 24, n)
        if tag != 68:
            advance(s, w)
        if tag == 60:
            set_field(w, n, 5, take(s, w, K_MUT))
            set_field(w, n, 3, expected(s, w, 1, 39))
            if take(s, w, 314) == 1:
                put(w, f + 8, 1)
                push(s, w, 8, 0, 0)
            else:
                put(w, f + 8, 2)
            return 0
        if tag == 61:
            if current(s, w) == 315:
                put(w, f + 8, 4)
            else:
                put(w, f + 8, 3)
                push(s, w, 7, 0, 1)
            return 0
        if tag == 62:
            set_field(w, n, 3, expected(s, w, 1, 42))
            expected(s, w, K_IN, 9)
            put(w, f + 8, 5)
            push(s, w, 7, 0, 0)
            return 0
        if tag == 63 or tag == 64 or tag == 66:
            put(w, f + 8, 8)
            push(s, w, 7, 0, 0)
            return 0
        if tag == 65:
            put(w, f + 8, 7)
            push(s, w, 5, 0, 0)
            return 0
        put(w, f + 8, 13)
        push(s, w, 7, 0, 1)
        return 0
    tag = field(w, n, 0)
    if phase == 1:
        set_field(w, n, 4, get(w, 104))
        put(w, f + 8, 2)
        return 0
    if phase == 2:
        expected(s, w, 317, 9)
        put(w, f + 8, 3)
        push(s, w, 7, 0, 1)
        return 0
    if phase == 3:
        slot = choose(tag == 60, 6, 3)
        set_field(w, n, slot, get(w, 104))
        edge(s, w, n, get(w, 104))
        put(w, f + 8, 4)
        return 0
    if phase == 4:
        expected(s, w, 315, choose(tag == 60, 40, 41))
        set_field(w, n, 2, get(w, 112))
        return finish(w, n)
    if phase == 5:
        set_field(w, n, 4, get(w, 104))
        edge(s, w, n, get(w, 104))
        expected(s, w, K_RANGE, 43)
        put(w, f + 8, 6)
        push(s, w, 7, 0, 0)
        return 0
    if phase == 6:
        set_field(w, n, 5, get(w, 104))
        edge(s, w, n, get(w, 104))
        put(w, f + 8, 7)
        push(s, w, 5, 0, 0)
        return 0
    if phase == 7:
        body = get(w, 104)
        set_field(w, n, choose(tag == 62, 6, choose(tag == 65, 3, 4)), body)
        body_edges(s, w, n, body)
        set_field(w, n, 2, field(w, body, 2))
        return finish(w, n)
    if phase == 8:
        set_field(w, n, 3, get(w, 104))
        edge(s, w, n, get(w, 104))
        if tag == 66:
            expected(s, w, 379, 9)
            put(w, f + 8, 11)
        else:
            put(w, f + 8, 9)
            push(s, w, 5, 0, 0)
        return 0
    if phase == 9:
        body = get(w, 104)
        set_field(w, n, 4, body)
        body_edges(s, w, n, body)
        set_field(w, n, 2, field(w, body, 2))
        if tag == 64 and take(s, w, K_ELSE) == 1:
            put(w, f + 8, 10)
            push(s, w, 5, 0, 0)
            return 0
        return finish(w, n)
    if phase == 10:
        body = get(w, 104)
        set_field(w, n, 5, body)
        body_edges(s, w, n, body)
        set_field(w, n, 2, field(w, body, 2))
        return finish(w, n)
    if phase == 11:
        if take(s, w, 381) == 1:
            set_field(w, n, 2, get(w, 112))
            return finish(w, n)
        put(w, f + 8, 12)
        push(s, w, 10, 0, 0)
        return 0
    if phase == 12:
        append(s, w, n, 4, get(w, 104))
        edge(s, w, n, get(w, 104))
        if take(s, w, 300) == 1:
            put(w, f + 8, 11)
        else:
            expected(s, w, 381, 46)
            set_field(w, n, 2, get(w, 112))
            return finish(w, n)
        return 0
    if phase == 13:
        target = get(w, 104)
        set_field(w, n, 3, target)
        edge(s, w, n, target)
        if take(s, w, 317) == 1:
            tag = field(w, target, 0)
            if tag != 44 and tag != 46 and tag != 47:
                return fail(w, 47, field(w, target, 1), field(w, target, 2), 0, 0)
            set_field(w, n, 0, 67)
            put(w, f + 8, 14)
            push(s, w, 7, 0, 1)
        else:
            expected(s, w, 315, 49)
            set_field(w, n, 2, get(w, 112))
            return finish(w, n)
        return 0
    set_field(w, n, 4, get(w, 104))
    edge(s, w, n, get(w, 104))
    expected(s, w, 315, 48)
    set_field(w, n, 2, get(w, 112))
    return finish(w, n)

def arm_step(s:readbuf, w:mutbuf) -> u64:
    f = frame(w)
    if get(w, f + 8) == 0:
        names = path(s, w, 1, 2)
        if path_count(w, names) < 2:
            return fail(w, 44, get(w, f + 16), get(w, f + 16), 0, 0)
        pattern = node(s, w, 27, get(w, f + 16), get(w, 112))
        set_field(w, pattern, 3, names)
        if take(s, w, 296) == 1:
            append(s, w, pattern, 4, expected(s, w, 1, 45))
            while take(s, w, 300) == 1 and get(w, 40) == 0:
                append(s, w, pattern, 4, expected(s, w, 1, 45))
            expected(s, w, 297, 9)
        set_field(w, pattern, 2, get(w, 112))
        expected(s, w, K_FATARROW, 9)
        n = node(s, w, 28, get(w, f + 16), get(w, 112))
        set_field(w, n, 3, pattern)
        put(w, f + 24, n)
        put(w, f + 8, 1)
        push(s, w, 5, 0, 0)
        return 0
    n = get(w, f + 24)
    block = get(w, 104)
    set_field(w, n, 4, block)
    set_field(w, n, 2, field(w, block, 2))
    body_edges(s, w, n, block)
    return finish(w, n)
'''
SOURCE+=r'''
def token_in_list(s:readbuf, w:mutbuf, items:u64, ref:u64) -> u64:
    while items != 0:
        if token_equal(s, field(w, items, 3), ref) == 1:
            return 1
        items = field(w, items, 4)
    return 0

def parameters(s:readbuf, w:mutbuf, simple:u64) -> u64:
    bag = node(s, w, 5, 0, 0)
    if take(s, w, 316) == 0:
        return bag
    more = 1
    while more == 1 and get(w, 40) == 0:
        if simple == 0 and current(s, w) == 2:
            append(s, w, bag, 5, advance(s, w))
        else:
            ref = expected(s, w, 1, choose(simple == 1, 13, 14))
            append(s, w, bag, 4, ref)
            if simple == 0:
                bound = 0
                if take(s, w, 314) == 1:
                    bound = expected(s, w, 1, 15)
                old = field(w, bag, 6)
                found = 0
                while old != 0 and get(w, 40) == 0:
                    row = field(w, old, 3)
                    if token_equal(s, field(w, row, 3), ref) == 1:
                        set_field(w, row, 4, bound)
                        found = 1
                    old = field(w, old, 4)
                if found == 0:
                    row = node(s, w, 6, 0, 0)
                    set_field(w, row, 3, ref)
                    set_field(w, row, 4, bound)
                    append(s, w, bag, 6, row)
        more = take(s, w, 300)
    close_type(s, w)
    return bag

def type_args_step(s:readbuf, w:mutbuf) -> u64:
    f = frame(w)
    if get(w, f + 8) == 0:
        expected(s, w, 316, 9)
        n = node(s, w, 5, 0, 0)
        put(w, f + 24, n)
        put(w, f + 8, 1)
        push(s, w, 8, 0, 0)
        return 0
    n = get(w, f + 24)
    append(s, w, n, 3, get(w, 104))
    if take(s, w, 300) == 1:
        push(s, w, 8, 0, 0)
    else:
        close_type(s, w)
        return finish(w, n)
    return 0

def abi(s:readbuf, w:mutbuf) -> u64:
    ref = expected(s, w, 5, 30)
    if word_is(s, ref, W_C, 1) == 0:
        fail(w, 31, ref - 1, ref - 1, 0, 0)
    return 0

def effects(s:readbuf, w:mutbuf, owner:u64) -> u64:
    expected(s, w, K_EFFECTS, 17)
    expected(s, w, 379, 9)
    more = 1
    while more == 1 and current(s, w) != 381 and get(w, 40) == 0:
        if current(s, w) != 1 and current(s, w) != K_UNSAFE:
            return fail(w, 18, mark(w), mark(w), 0, 0)
        ref = advance(s, w)
        if token_in_list(s, w, field(w, owner, 6), ref) == 1:
            return fail(w, 19, ref - 1, ref - 1, ref, 0)
        append(s, w, owner, 6, ref)
        more = take(s, w, 300)
    expected(s, w, 381, 20)
    return 0

def resources(s:readbuf, w:mutbuf, owner:u64) -> u64:
    expected(s, w, K_RESOURCES, 9)
    expected(s, w, 379, 9)
    while current(s, w) != 381 and get(w, 40) == 0:
        ref = expected(s, w, 1, 21)
        old = field(w, owner, 9)
        while old != 0 and get(w, 40) == 0:
            row = field(w, old, 3)
            if token_equal(s, field(w, row, 3), ref) == 1:
                return fail(w, 22, ref - 1, ref - 1, ref, 0)
            old = field(w, old, 4)
        expected(s, w, 317, 9)
        k = current(s, w)
        if k != 3 and k != 4 and k != K_TRUE and k != K_FALSE:
            return fail(w, 23, mark(w), mark(w), 0, 0)
        val = advance(s, w)
        row = node(s, w, 7, 0, 0)
        set_field(w, row, 3, ref)
        set_field(w, row, 4, k)
        set_field(w, row, 5, val)
        append(s, w, owner, 9, row)
        expected(s, w, 315, 24)
    expected(s, w, 381, 9)
    return 0

def mode(k:u64) -> u64:
    if k == K_READ:
        return 1
    if k == K_MUT:
        return 2
    if k == K_TAKE:
        return 3
    return 0

def return_type(s:readbuf, w:mutbuf, n:u64) -> u64:
    expected(s, w, K_ARROW, 35)
    k = current(s, w)
    if k == K_READ or k == K_MUT:
        set_field(w, n, 11, mode(k))
        advance(s, w)
    if current(s, w) == 2:
        set_field(w, n, 13, advance(s, w))
    put(w, frame(w) + 8, 3)
    push(s, w, 8, 0, 0)
    return 0

def function_step(s:readbuf, w:mutbuf) -> u64:
    f = frame(w)
    phase = get(w, f + 8)
    n = get(w, f + 24)
    if phase == 0:
        n = node(s, w, 24, get(w, f + 16), get(w, f + 16))
        put(w, f + 24, n)
        flags = 0
        if take(s, w, K_EXTERN) == 1:
            flags = 2
            abi(s, w)
        else:
            flags = take(s, w, K_PUB)
            if take(s, w, K_EXPORT) == 1:
                flags = flags | 4
                abi(s, w)
        set_field(w, n, 8, flags)
        expected(s, w, K_FN, 9)
        set_field(w, n, 3, expected(s, w, 1, 32))
        set_field(w, n, 10, parameters(s, w, 0))
        expected(s, w, 296, 9)
        put(w, f + 8, 1)
        return 0
    if phase == 1:
        if take(s, w, 297) == 1:
            return return_type(s, w, n)
        ref = expected(s, w, 1, 33)
        p = node(s, w, 25, ref - 1, ref - 1)
        set_field(w, p, 3, ref)
        put(w, f + 32, p)
        expected(s, w, 314, 9)
        k = current(s, w)
        if k == K_READ or k == K_MUT or k == K_TAKE:
            set_field(w, p, 5, mode(k))
            advance(s, w)
        if current(s, w) == 2:
            set_field(w, p, 6, advance(s, w))
        put(w, f + 8, 2)
        push(s, w, 8, 0, 0)
        return 0
    if phase == 2:
        p = get(w, f + 32)
        set_field(w, p, 4, get(w, 104))
        set_field(w, p, 2, get(w, 112))
        append(s, w, n, 4, p)
        if take(s, w, 300) == 1:
            put(w, f + 8, 1)
        else:
            expected(s, w, 297, 34)
            return return_type(s, w, n)
        return 0
    if phase == 3:
        set_field(w, n, 5, get(w, 104))
        if current(s, w) == 1 and word_is(s, mark(w) + 1, W_FROM, 4) == 1:
            advance(s, w)
            set_field(w, n, 12, expected(s, w, 1, 36))
        effects(s, w, n)
        if (field(w, n, 8) & 2) != 0:
            expected(s, w, 315, 37)
            set_field(w, n, 2, get(w, 112))
            return finish(w, n)
        if current(s, w) == K_RESOURCES:
            resources(s, w, n)
        put(w, f + 8, 4)
        push(s, w, 5, 0, 0)
        return 0
    body = get(w, 104)
    set_field(w, n, 7, body)
    set_field(w, n, 2, field(w, body, 2))
    return finish(w, n)

def struct_step(s:readbuf, w:mutbuf) -> u64:
    f = frame(w)
    n = get(w, f + 24)
    phase = get(w, f + 8)
    if phase == 0:
        n = node(s, w, 22, get(w, f + 16), get(w, f + 16))
        put(w, f + 24, n)
        set_field(w, n, 7, take(s, w, K_PUB))
        if take(s, w, K_REPR) == 1:
            expected(s, w, 296, 9)
            ref = expected(s, w, 1, 58)
            if word_is(s, ref, W_C, 1) == 0:
                return fail(w, 59, ref - 1, ref - 1, 0, 0)
            expected(s, w, 297, 9)
            set_field(w, n, 5, 1)
        expected(s, w, K_STRUCT, 9)
        set_field(w, n, 3, expected(s, w, 1, 25))
        bag = parameters(s, w, 0)
        set_field(w, n, 6, bag)
        items = field(w, bag, 6)
        while items != 0 and get(w, 40) == 0:
            ref = field(w, field(w, items, 3), 4)
            if ref != 0 and word_is(s, ref, W_COPY, 4) == 0:
                return fail(w, 16, mark(w), mark(w), 0, 0)
            items = field(w, items, 4)
        expected(s, w, 379, 9)
        put(w, f + 8, 1)
        return 0
    if phase == 1:
        if take(s, w, 381) == 1:
            set_field(w, n, 2, get(w, 112))
            return finish(w, n)
        ref = field_name(s, w)
        p = node(s, w, 25, ref - 1, ref - 1)
        set_field(w, p, 3, ref)
        put(w, f + 32, p)
        expected(s, w, 314, 9)
        put(w, f + 8, 2)
        push(s, w, 8, 0, 0)
        return 0
    p = get(w, f + 32)
    set_field(w, p, 4, get(w, 104))
    set_field(w, p, 2, get(w, 112))
    append(s, w, n, 4, p)
    if take(s, w, 300) == 1:
        put(w, f + 8, 1)
    else:
        expected(s, w, 381, 26)
        set_field(w, n, 2, get(w, 112))
        return finish(w, n)
    return 0

def enum_step(s:readbuf, w:mutbuf) -> u64:
    f = frame(w)
    n = get(w, f + 24)
    phase = get(w, f + 8)
    if phase == 0:
        n = node(s, w, 23, get(w, f + 16), get(w, f + 16))
        put(w, f + 24, n)
        set_field(w, n, 6, take(s, w, K_PUB))
        expected(s, w, K_ENUM, 9)
        set_field(w, n, 3, expected(s, w, 1, 27))
        set_field(w, n, 5, parameters(s, w, 1))
        expected(s, w, 379, 9)
        put(w, f + 8, 1)
        return 0
    if phase == 1:
        if take(s, w, 381) == 1:
            set_field(w, n, 2, get(w, 112))
            return finish(w, n)
        put(w, f + 8, 2)
        push(s, w, 13, 0, 0)
        return 0
    append(s, w, n, 4, get(w, 104))
    if take(s, w, 300) == 1:
        put(w, f + 8, 1)
    else:
        expected(s, w, 381, 29)
        set_field(w, n, 2, get(w, 112))
        return finish(w, n)
    return 0

def variant_step(s:readbuf, w:mutbuf) -> u64:
    f = frame(w)
    n = get(w, f + 24)
    if get(w, f + 8) == 0:
        ref = expected(s, w, 1, 28)
        n = node(s, w, 26, ref - 1, get(w, 112))
        set_field(w, n, 3, ref)
        put(w, f + 24, n)
        if take(s, w, 296) == 1:
            put(w, f + 8, 1)
            push(s, w, 8, 0, 0)
            return 0
        return finish(w, n)
    append(s, w, n, 4, get(w, 104))
    if take(s, w, 300) == 1:
        push(s, w, 8, 0, 0)
    else:
        expected(s, w, 297, 9)
        set_field(w, n, 2, get(w, 112))
        return finish(w, n)
    return 0

def program_step(s:readbuf, w:mutbuf) -> u64:
    f = frame(w)
    phase = get(w, f + 8)
    n = get(w, f + 24)
    if phase == 0:
        n = node(s, w, 20, mark(w), mark(w))
        put(w, f + 24, n)
        put(w, 80, n)
        if take(s, w, K_MODULE) == 1:
            set_field(w, n, 3, path(s, w, 1, 2))
            expected(s, w, 315, 9)
        while take(s, w, K_IMPORT) == 1 and get(w, 40) == 0:
            start = get(w, 112)
            names = path(s, w, 1, 2)
            alias = path_last(w, names)
            if take(s, w, K_AS) == 1:
                alias = expected(s, w, 1, 11)
            expected(s, w, 315, 9)
            item = node(s, w, 21, start, get(w, 112))
            set_field(w, item, 3, names)
            set_field(w, item, 4, alias)
            append(s, w, n, 4, item)
        put(w, f + 8, 1)
        return 0
    if phase == 2:
        child = get(w, 104)
        tag = field(w, child, 0)
        append(s, w, n, choose(tag == 22, 5, choose(tag == 23, 6, 7)), child)
        put(w, f + 8, 1)
        return 0
    k = current(s, w)
    if k == 0:
        return finish(w, n)
    next_at = get(w, 0) + 1
    if next_at >= read_word(s, 8):
        next_at = read_word(s, 8) - 1
    following = read_word(s, 48 + next_at * 56)
    kind = 0
    if k == K_STRUCT or k == K_REPR or (k == K_PUB and (following == K_STRUCT or following == K_REPR)):
        kind = 2
    else:
        if k == K_ENUM or (k == K_PUB and following == K_ENUM):
            kind = 3
        else:
            if k == K_PUB or k == K_EXPORT or k == K_FN or k == K_EXTERN:
                kind = 4
    if kind == 0:
        return fail(w, 10, mark(w), mark(w), 0, 0)
    put(w, f + 8, 2)
    push(s, w, kind, 0, 0)
    return 0

def namespaces(s:readbuf, w:mutbuf) -> u64:
    root = get(w, 80)
    names = field(w, root, 8)
    while names != 0 and get(w, 40) == 0:
        q = field(w, names, 3)
        ref = field(w, field(w, q, 3), 3)
        found = word_is(s, ref, W_RESULT, 6)
        list = field(w, root, 4)
        while list != 0:
            item = field(w, list, 3)
            if token_equal(s, ref, field(w, item, 4)) == 1:
                found = 1
            list = field(w, list, 4)
        list = field(w, root, 5)
        while list != 0:
            item = field(w, list, 3)
            if token_equal(s, ref, field(w, item, 3)) == 1:
                found = 1
            list = field(w, list, 4)
        list = field(w, root, 6)
        while list != 0:
            item = field(w, list, 3)
            if token_equal(s, ref, field(w, item, 3)) == 1:
                found = 1
            list = field(w, list, 4)
        if found == 0:
            return fail(w, 56, field(w, q, 1), field(w, q, 2), 0, q)
        names = field(w, names, 4)
    return 0

def depth_push(w:mutbuf, item:u64, depth:u64) -> u64:
    count = get(w, 16)
    if count >= 4112:
        return fail(w, 999, 0, 0, 0, 0)
    put(w, 256 + count * 16, item)
    put(w, 264 + count * 16, depth)
    put(w, 16, count + 1)
    return 0

def tree_depth(w:mutbuf) -> u64:
    put(w, 16, 0)
    funcs = field(w, get(w, 80), 7)
    while funcs != 0:
        fn = field(w, funcs, 3)
        block = field(w, fn, 7)
        if block != 0:
            list = field(w, block, 3)
            while list != 0:
                depth_push(w, field(w, list, 3), 1)
                list = field(w, list, 4)
        funcs = field(w, funcs, 4)
    while get(w, 16) != 0 and get(w, 40) == 0:
        count = get(w, 16) - 1
        put(w, 16, count)
        n = get(w, 256 + count * 16)
        depth = get(w, 264 + count * 16)
        if depth > 96:
            return fail(w, 57, field(w, n, 1), field(w, n, 2), 0, 0)
        children = field(w, n, 15)
        while children != 0 and get(w, 40) == 0:
            depth_push(w, field(w, children, 3), depth + 1)
            children = field(w, children, 4)
    return 0

def run(s:readbuf, w:mutbuf) -> u64:
    while get(w, 16) != 0 and get(w, 40) == 0:
        kind = get(w, frame(w))
        if kind == 1:
            program_step(s, w)
        if kind == 2:
            struct_step(s, w)
        if kind == 3:
            enum_step(s, w)
        if kind == 4:
            function_step(s, w)
        if kind == 5:
            block_step(s, w)
        if kind == 6:
            stmt_step(s, w)
        if kind == 7:
            expr_step(s, w)
        if kind == 8:
            type_step(s, w)
        if kind == 10:
            arm_step(s, w)
        if kind == 11:
            type_args_step(s, w)
        if kind == 13:
            variant_step(s, w)
    return 0
'''
SOURCE+='\ndef read_word(s:readbuf, at:u64) -> u64:\n    value = 0\n'+''.join(
    f'    value = value | (byte(s, at + {i}) << {8*i})\n' for i in range(8))+'    return value\n'
SOURCE+='\ndef get(w:mutbuf, at:u64) -> u64:\n    value = 0\n'+''.join(
    f'    value = value | (byte(w, at + {i}) << {8*i})\n' for i in range(8))+'    return value\n'
SOURCE+='\ndef put(w:mutbuf, at:u64, value:u64) -> u64:\n'+''.join(
    f'    store(w, at + {i}, (value >> {8*i}) & 255)\n' for i in range(8))+'    return 0\n'


def source_program():
    text=SOURCE
    guarded=('advance','take','expected','set_field','append','edge','attach_expr',
             'push','finish','close_type','path','path_last','path_count','list_count',
             'body_edges','parameters','abi','effects','resources','return_type')
    for name in guarded:
        a=text.index('def '+name+'(');b=text.index('\n',a)
        text=text[:b+1]+'    if get(w, 40) != 0:\n        return 0\n'+text[b+1:]
    a=text.index('def node(');b=text.index('\n',a)
    text=text[:b+1]+'    if get(w, 40) != 0:\n        return 1\n'+text[b+1:]
    # Token-exact replacement prevents keyword/macro prefix collisions.
    import re
    values={'K_'+word.upper():128+i for i,word in enumerate(KEYWORD_ORDER)}
    pairs={'SHR':'>>','GE':'>=','PATH':'::','OROR':'||','ANDAND':'&&','EQ':'==','NE':'!=',
           'LE':'<=','SHL':'<<','RANGE':'..','ARROW':'->','FATARROW':'=>'}
    values.update({'K_'+name:512+PAIR_ORDER.index(word) for name,word in pairs.items()})
    values.update({'W_'+name:int.from_bytes(word.encode(),'little') for name,word in {
        'C':'C','COPY':'Copy','FROM':'from','RESULT':'Result'}.items()})
    text=re.sub(r'\b(?:K|W)_[A-Z]+\b',lambda m:str(values[m[0]]),text)
    text=text.replace('125780153759042',str(int.from_bytes(b'Buffer','little')))
    text=text.replace('1802723668',str(int.from_bytes(b'Task','little')))
    text=text.replace('125780290692435',str(int.from_bytes(b'Sender','little')))
    return text


def document():
    nodes=ast.parse(source_program()).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for n in nodes:
        b=Builder(n,names,signatures,total);b.statements(n.body)
        functions.append({'name':names[n.name],'params':[b.param(v) for v in b.params],
            'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'source_parser','functions':functions})


def main():
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/source_parser.hiaasm'
    doc=document();path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size,'functions',len(doc['functions']),
          'blocks',sum(len(f['blocks']) for f in doc['functions']))


if __name__=='__main__':main()
