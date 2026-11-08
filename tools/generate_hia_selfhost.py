"""Author the fixed HIA Core bootstrap compiler; never used after B0.

The Python AST lowering here is a development-time source authoring aid.  The
checked-in HIA assembly contains the scanner, semantic verifier and x86 emitter.
B1 and subsequent generations consume that assembly as bytes themselves.
"""
from __future__ import annotations
import ast
import json
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_agent_assembly import render_assembly
from tools.hia_selfhost_limits import (MAX_INSTRUCTIONS, MAX_CORE_NODES, MAX_RELOCATIONS,
                                     MAX_SOURCE_LINES, MAX_LINE_BYTES)

TYPES = {"u64": 1, "usize": 2, "u32": 3, "u8": 4, "bool": 5, "readbuf": 6, "mutbuf": 7}
WORDS = ["hia-asm.v1", "hepta.hia.program.v8", "selfhost", "fn", "effects", "read", "write", "trap", "entry", "block", "end", "ret", "jump", "branch", "value", "mode", "wrap", "function", "true", "false", *TYPES,
 "const", "int.add.wrap", "int.sub.wrap", "int.mul.wrap", "bit.and", "bit.or", "bit.xor", "int.shl.checked", "int.shr.checked", "compare.eq", "compare.ne", "compare.lt", "compare.le", "compare.gt", "compare.ge", "bool.and", "bool.or", "bool.not", "int.cast", "buffer.len", "buffer.load", "buffer.store", "call", "selfhost_elf", "buffer.swap", "bit.not", "int.add.checked", "int.sub.checked", "select", "int.mul.checked", "int.div.checked", "int.rem.checked", "int.neg.checked",
 "user", "overflow", "division_by_zero", "bounds", "allocation"]
W = {s: i + 300 for i,s in enumerate(WORDS)}
# Scratch ABI: state 0..2047; function records; block records; local SSA types;
# argument vector; relative relocation records; bounded call graph and marks.
# All are ordinary borrowed bytes. The graph occupies previously unused scratch
# after the complete relocation table, so this profile keeps the 1 MiB limit.
FBASE, FSTRIDE, BBASE, BSTRIDE, VBASE, ARGS, FIXBASE = 4096, 320, 45056, 320, 536576, 569344, 570368
CBASE, CSTATE = 858368, 874752
SOURCE = r'''
def compile(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = 0
    n = length(w)
    if n < 1048576:
        return 4294967294
    if length(s) > 1048576:
        return 4294967295
    if length(o) > 1048576:
        return 4294967294
    i = 0
    while i < 17408:
        put(w, CBASE + i, 0)
        i = i + 8
    while phase < 3:
        i = 0
        while i < 256:
            put(w, i, 0)
            i = i + 8
        put(w, 248, 4)
        put(w, 48, phase)
        if phase == 0:
            if source_limits(s, w) == 0:
                return 4294967295
        next_token(s, w)
        expect(s, w, @hia-asm.v1@)
        expect(s, w, @hepta.hia.program.v8@)
        if get(w, 8) == @selfhost_elf@:
            put(w, 232, 1)
            expect(s, w, @selfhost_elf@)
        else:
            expect(s, w, @selfhost@)
        expect(s, w, 10)
        if get(w, 232) == 1:
            elf_begin(o, w)
        wrapper(o, w)
        put(w, 240, get(w, 56))
        while get(w, 8) == @fn@ and get(w, 40) == 0:
            parse_function(s, o, w)
        expect(s, w, 0)
        if get(w, 64) == 0:
            fail(w, 1)
        if get(w, 40) != 0:
            return 4294967295
        if phase == 0:
            check_graph(w)
            if get(w, 40) != 0:
                return 4294967295
        if get(w, 232) == 1:
            elf_finish(o, w)
        if phase == 1:
            if get(w, 56) > length(o):
                return 4294967294
        phase = phase + 1
    fix_all(o, w)
    if get(w, 40) != 0:
        return 4294967295
    return get(w, 56)

def parse_function(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    expect(s, w, @fn@)
    separated(w)
    if get(w, 32) != 0:
        fail(w, 49)
    f = expect(s, w, 257)
    adjacent(w)
    if f != get(w, 64) or f >= 128:
        return fail(w, 2)
    put(w, 72, f)
    put(w, 64, f + 1)
    fb = FBASE + f * FSTRIDE
    if get(w, 48) == 0:
        put(w, fb + 8, get(w, 80))
        put(w, fb + 40, 0)
    i = 0
    while i < 2048:
        put(w, VBASE + i * 16, 0)
        i = i + 1
    count = parse_params(s, w, 1)
    account_nodes(w, 11 + count * 3)
    expect(s, w, 45)
    adjacent(w)
    expect(s, w, 62)
    expect(s, w, 40)
    rt = read_type(s, w)
    if rt > 5:
        fail(w, 3)
    if get(w, 48) == 0:
        put(w, fb + 24, count)
        put(w, fb + 32, rt)
    expect(s, w, 41)
    separated(w)
    expect(s, w, @effects@)
    adjacent(w)
    expect(s, w, 40)
    expect(s, w, @read@)
    expect(s, w, 44)
    expect(s, w, @write@)
    expect(s, w, 44)
    expect(s, w, @trap@)
    expect(s, w, 41)
    separated(w)
    expect(s, w, @entry@)
    adjacent(w)
    expect(s, w, 40)
    adjacent(w)
    if expect(s, w, 258) != 0:
        fail(w, 4)
    adjacent(w)
    expect(s, w, 41)
    expect(s, w, 10)
    if f == 0:
        if count != 3 or rt != 3:
            fail(w, 5)
        if get(w, fb + 48) != 6 or get(w, fb + 56) != 7 or get(w, fb + 64) != 7:
            fail(w, 5)
    put(w, 96, 0)
    function_start(o, w)
    while get(w, 8) == @block@ and get(w, 40) == 0:
        parse_block(s, o, w)
    expect(s, w, @end@)
    expect(s, w, 10)
    if get(w, 96) == 0:
        fail(w, 6)
    if get(w, 48) == 0:
        put(w, fb + 16, get(w, 96))
    return 0

def parse_params(s:readbuf, w:mutbuf, signature:u64) -> u64:
    expect(s, w, 40)
    count = 0
    v = 0
    t = 0
    base = FBASE + get(w, 72) * FSTRIDE
    while get(w, 8) != 41 and get(w, 40) == 0:
        v = expect(s, w, 256)
        expect(s, w, 58)
        t = read_type(s, w)
        if count >= 16:
            return fail(w, 7)
        if signature == 1:
            if v != count:
                fail(w, 8)
            if get(w, 48) == 0:
                put(w, base + 48 + count * 8, t)
        else:
            define(w, v, t)
            if get(w, 48) == 0:
                put(w, BBASE + get(w, 88) * BSTRIDE + 32 + count * 16, v)
                put(w, BBASE + get(w, 88) * BSTRIDE + 40 + count * 16, t)
            if get(w, 96) == 0:
                if v != count or t != get(w, base + 48 + count * 8):
                    fail(w, 9)
        count = count + 1
        if get(w, 8) != 41:
            expect(s, w, 44)
            if get(w, 8) == 41:
                fail(w, 10)
    expect(s, w, 41)
    return count

def parse_block(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    # This block-local pending result is separate from the v5 node counter at
    # 248. A self call is admitted only when the next token is its exact ret.
    put(w, 256, 0)
    expect(s, w, @block@)
    separated(w)
    b = expect(s, w, 258)
    adjacent(w)
    if b != get(w, 96) or b >= 256 or get(w, 80) >= 1536:
        return fail(w, 11)
    put(w, 88, get(w, 80))
    put(w, 80, get(w, 80) + 1)
    bb = BBASE + get(w, 88) * BSTRIDE
    if get(w, 48) == 0:
        put(w, bb + 16, get(w, 72))
        put(w, bb + 24, 0)
        put(w, bb + 288, 18446744073709551615)
        put(w, bb + 296, 18446744073709551615)
    if get(w, 48) > 0:
        put(w, bb, get(w, 56))
    count = parse_params(s, w, 0)
    account_nodes(w, 4 + count * 3)
    if get(w, 48) == 0:
        put(w, bb + 8, count)
    if b == 0:
        if count != get(w, FBASE + get(w, 72) * FSTRIDE + 24):
            fail(w, 12)
    put(w, 96, b + 1)
    expect(s, w, 10)
    while (get(w, 8) == 256 or get(w, 8) == 95) and get(w, 40) == 0:
        instruction(s, o, w)
    if get(w, 8) == @ret@:
        account_nodes(w, 4)
        next_token(s, w)
        adjacent(w)
        expect(s, w, 40)
        v = expect(s, w, 256)
        t = variable(w, v)
        if t != get(w, FBASE + get(w, 72) * FSTRIDE + 32):
            fail(w, 13)
        expect(s, w, 41)
        if get(w, 256) != 0:
            if v + 1 != get(w, 256):
                fail(w, 59)
        else:
            load_var(o, w, 0, v, 0)
            mem(o, w, 139, 2, 5, 18446744073709551608)
            mem(o, w, 137, 0, 2, 0)
            emit(o, w, 201)
            emit(o, w, 195)
    else:
        if get(w, 8) == @trap@:
            explicit_trap(s, o, w)
        else:
            if get(w, 8) == @jump@:
                next_token(s, w)
                edge(s, o, w, 0)
            else:
                expect(s, w, @branch@)
                account_nodes(w, 1)
                separated(w)
                v = expect(s, w, 256)
                if variable(w, v) != 5:
                    fail(w, 14)
                load_var(o, w, 0, v, 0)
                emit(o, w, 72)
                emit(o, w, 133)
                emit(o, w, 192)
                emit(o, w, 15)
                emit(o, w, 132)
                at = get(w, 56)
                emit4(o, w, 0)
                edge(s, o, w, 0)
                if get(w, 48) == 2:
                    write4(o, at, get(w, 56) - at - 4)
                edge(s, o, w, 1)
    expect(s, w, 10)
    return 0

def args(s:readbuf, w:mutbuf, is_edge:u64) -> u64:
    expect(s, w, 40)
    n = 0
    v = 0
    t = 0
    j = 0
    while get(w, 8) != 41 and get(w, 40) == 0:
        v = expect(s, w, 256)
        t = variable(w, v)
        if n >= 16:
            return fail(w, 15)
        j = 0
        while j < n:
            if v == get(w, ARGS + j * 8) and (t == 7 or (is_edge == 1 and t == 6)):
                fail(w, 16)
            j = j + 1
        put(w, ARGS + n * 8, v)
        n = n + 1
        if get(w, 8) != 41:
            expect(s, w, 44)
            if get(w, 8) == 41:
                fail(w, 17)
    expect(s, w, 41)
    put(w, 136, n)
    return n

def edge(s:readbuf, o:mutbuf, w:mutbuf, arm:u64) -> u64:
    separated(w)
    b = expect(s, w, 258)
    adjacent(w)
    fbase = FBASE + get(w, 72) * FSTRIDE
    bid = get(w, fbase + 8) + b
    if b == 0 or b >= 256 or bid >= 1536:
        return fail(w, 18)
    bb = BBASE + bid * BSTRIDE
    n = args(s, w, 1)
    account_nodes(w, 4 + n)
    if get(w, 48) == 0:
        put(w, BBASE + get(w, 88) * BSTRIDE + 288 + arm * 8, bid)
    else:
        if b >= get(w, fbase + 16) or n != get(w, bb + 8):
            return fail(w, 19)
        i = 0
        v = 0
        t = 0
        while i < n:
            v = get(w, ARGS + i * 8)
            t = variable(w, v)
            if t != get(w, bb + 40 + i * 16):
                fail(w, 20)
            copy_argument(o, w, v, i, t)
            i = i + 1
        i = 0
        while i < n:
            v = get(w, bb + 32 + i * 16)
            t = get(w, bb + 40 + i * 16)
            mem(o, w, 139, 0, 5, 0 - frame(w) + i * 16)
            store_var(o, w, v, 0)
            if t >= 6:
                mem(o, w, 139, 0, 5, 0 - frame(w) + i * 16 + 8)
                store_var(o, w, v, 1)
            i = i + 1
        emit(o, w, 233)
        relocation(o, w, 2, bid)
    return 0

def instruction(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, 112) >= MAX_INSTRUCTIONS:
        return fail(w, 54)
    put(w, 112, get(w, 112) + 1)
    v = 2048
    t = 0
    if get(w, 8) == 95:
        next_token(s, w)
    else:
        v = expect(s, w, 256)
        expect(s, w, 58)
        t = read_type(s, w)
        if t >= 6:
            fail(w, 21)
    expect(s, w, 61)
    op = get(w, 8)
    next_token(s, w)
    adjacent(w)
    n = args(s, w, 0)
    account_nodes(w, 5 + n)
    if t != 0:
        account_nodes(w, 3)
    x = 0
    a = 0
    b = 0
    at = 0
    bt = 0
    if n > 0:
        a = get(w, ARGS)
        at = variable(w, a)
    if n > 1:
        b = get(w, ARGS + 8)
        bt = variable(w, b)
    if op == @const@:
        account_nodes(w, 1)
        separated(w)
        expect(s, w, 123)
        expect(s, w, @value@)
        expect(s, w, 58)
        if t == 5:
            if get(w, 8) == @true@:
                x = 1
                next_token(s, w)
            else:
                expect(s, w, @false@)
        else:
            x = expect(s, w, 259)
        expect(s, w, 125)
        if n != 0 or t == 0:
            fail(w, 22)
        if t == 3 and x > 4294967295:
            fail(w, 22)
        if t == 4 and x > 255:
            fail(w, 22)
        emit(o, w, 72)
        emit(o, w, 184)
        emit8(o, w, x)
    else:
        if op == @call@:
            account_nodes(w, 1)
            separated(w)
            expect(s, w, 123)
            expect(s, w, @function@)
            expect(s, w, 58)
            if get(w, 32) != 1:
                fail(w, 49)
            x = expect(s, w, 257)
            expect(s, w, 125)
            if x >= 128:
                fail(w, 23)
            else:
                if x == get(w, 72):
                    put(w, 256, v + 1)
                else:
                    if get(w, 48) == 0:
                        store(w, CBASE + get(w, 72) * 128 + x, 1)
            if get(w, 48) > 0:
                if x >= get(w, 1024):
                    fail(w, 23)
                fb = FBASE + x * FSTRIDE
                if n != get(w, fb + 24) or t != get(w, fb + 32):
                    fail(w, 24)
                i = 0
                av = 0
                typ = 0
                while i < n:
                    av = get(w, ARGS + i * 8)
                    typ = variable(w, av)
                    if typ != get(w, fb + 48 + i * 8):
                        fail(w, 25)
                    copy_argument(o, w, av, i, typ)
                    i = i + 1
                if x == get(w, 72):
                    # All arguments were staged before overwriting any entry
                    # parameter. Keep the frame and original result pointer;
                    # b0 begins after the prologue, including stack probes.
                    i = 0
                    while i < n:
                        mem(o, w, 139, 0, 5, 0 - frame(w) + i * 16)
                        store_var(o, w, i, 0)
                        if get(w, fb + 48 + i * 8) >= 6:
                            mem(o, w, 139, 0, 5, 0 - frame(w) + i * 16 + 8)
                            store_var(o, w, i, 1)
                        i = i + 1
                    emit(o, w, 233)
                    relocation(o, w, 2, get(w, fb + 8))
                else:
                    mem(o, w, 141, 7, 5, 0 - frame(w))
                    mem(o, w, 141, 6, 5, 0 - frame(w) + 512)
                    emit(o, w, 232)
                    relocation(o, w, 1, x)
                    mem(o, w, 139, 0, 5, 0 - frame(w) + 512)
        else:
            if op == @int.cast@:
                account_nodes(w, 1)
                separated(w)
                expect(s, w, 123)
                expect(s, w, @mode@)
                expect(s, w, 58)
                expect(s, w, @wrap@)
                expect(s, w, 125)
                if n != 1 or at > 4 or t > 4 or t == 0:
                    fail(w, 26)
                load_var(o, w, 0, a, 0)
                normalize(o, w, t)
            else:
                if op >= @bit.not@ and op <= @int.neg.checked@ and op != @select@:
                    checked_integer(o, w, op, n, a, b, at, bt, t)
                else:
                    operation(o, w, op, n, a, b, at, bt, t)
    if t != 0:
        define(w, v, t)
        if get(w, 256) == 0:
            store_var(o, w, v, 0)
    else:
        if op != @buffer.store@ and op != @buffer.swap@:
            fail(w, 27)
    expect(s, w, 10)
    if get(w, 256) != 0 and get(w, 8) != @ret@:
        fail(w, 59)
    return 0

def operation(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:
    if op == @select@:
        return select_scalar(o, w, n, a, b, at, bt, t)
    if op == @buffer.len@:
        if n != 1 or at < 6 or t != 2:
            fail(w, 28)
        load_var(o, w, 0, a, 1)
        return 0
    if op == @buffer.swap@:
        if n != 3 or t != 0 or at != 7 or bt != 2 or variable(w, get(w, ARGS + 16)) != 2:
            fail(w, 57)
        load_var(o, w, 1, b, 0)
        load_var(o, w, 2, a, 1)
        # cmp rcx, rdx; jb +2; ud2; nop. Both checks precede all memory access.
        emit8(o, w, 10379406269396105544)
        load_var(o, w, 6, get(w, ARGS + 16), 0)
        emit8(o, w, 10379406269396433224)
        load_var(o, w, 0, a, 0)
        # add rcx, rax; add rsi, rax; movzx edx, [rcx]; mov al, [rsi];
        # mov [rcx], al; mov [rsi], dl; nop. All value slots stay in memory.
        emit8(o, w, 13118921948371419464)
        emit8(o, w, 10382635531107731985)
        return 0
    if op == @buffer.load@ or op == @buffer.store@:
        if at < 6 or bt != 2:
            fail(w, 29)
        if op == @buffer.load@:
            if n != 2 or t != 4:
                fail(w, 30)
        else:
            if n != 3 or t != 0 or at != 7 or variable(w, get(w, ARGS + 16)) != 4:
                fail(w, 30)
        load_var(o, w, 1, b, 0)
        load_var(o, w, 2, a, 1)
        emit(o, w, 72)
        emit(o, w, 57)
        emit(o, w, 209)
        emit(o, w, 114)
        emit(o, w, 2)
        emit(o, w, 15)
        emit(o, w, 11)
        load_var(o, w, 0, a, 0)
        emit(o, w, 72)
        emit(o, w, 1)
        emit(o, w, 200)
        if op == @buffer.load@:
            emit(o, w, 15)
            emit(o, w, 182)
            emit(o, w, 0)
        else:
            load_var(o, w, 2, get(w, ARGS + 16), 0)
            emit(o, w, 136)
            emit(o, w, 16)
        return 0
    load_var(o, w, 0, a, 0)
    if op == @bool.not@:
        if n != 1 or at != 5 or t != 5:
            fail(w, 31)
        emit(o, w, 72)
        emit(o, w, 131)
        emit(o, w, 240)
        emit(o, w, 1)
        return 0
    if n != 2:
        fail(w, 32)
    load_var(o, w, 1, b, 0)
    if op >= @compare.eq@ and op <= @compare.ge@:
        if at > 4 or at != bt or t != 5:
            fail(w, 33)
        emit(o, w, 72)
        emit(o, w, 57)
        emit(o, w, 200)
        cond = 148
        if op == @compare.ne@:
            cond = 149
        if op == @compare.lt@:
            cond = 146
        if op == @compare.le@:
            cond = 150
        if op == @compare.gt@:
            cond = 151
        if op == @compare.ge@:
            cond = 147
        emit(o, w, 15)
        emit(o, w, cond)
        emit(o, w, 192)
        emit(o, w, 15)
        emit(o, w, 182)
        emit(o, w, 192)
        return 0
    if at != bt or t != at or t == 0:
        fail(w, 34)
    if op == @bool.and@ or op == @bool.or@:
        if t != 5:
            fail(w, 35)
    else:
        if t > 4:
            fail(w, 35)
    if op == @int.add.wrap@:
        emit(o, w, 72)
        emit(o, w, 1)
        emit(o, w, 200)
    else:
        if op == @int.sub.wrap@:
            emit(o, w, 72)
            emit(o, w, 41)
            emit(o, w, 200)
        else:
            if op == @int.mul.wrap@:
                emit(o, w, 72)
                emit(o, w, 15)
                emit(o, w, 175)
                emit(o, w, 193)
            else:
                if op == @bit.and@ or op == @bool.and@:
                    emit(o, w, 72)
                    emit(o, w, 33)
                    emit(o, w, 200)
                else:
                    if op == @bit.or@ or op == @bool.or@:
                        emit(o, w, 72)
                        emit(o, w, 9)
                        emit(o, w, 200)
                    else:
                        if op == @bit.xor@:
                            emit(o, w, 72)
                            emit(o, w, 49)
                            emit(o, w, 200)
                        else:
                            if op == @int.shl.checked@ or op == @int.shr.checked@:
                                width = 64
                                if t == 3:
                                    width = 32
                                if t == 4:
                                    width = 8
                                emit(o, w, 72)
                                emit(o, w, 131)
                                emit(o, w, 249)
                                emit(o, w, width)
                                emit(o, w, 114)
                                emit(o, w, 2)
                                emit(o, w, 15)
                                emit(o, w, 11)
                                emit(o, w, 72)
                                emit(o, w, 211)
                                if op == @int.shl.checked@:
                                    emit(o, w, 224)
                                else:
                                    emit(o, w, 232)
                            else:
                                fail(w, 36)
    normalize(o, w, t)
    return 0

def define(w:mutbuf, v:u64, t:u64) -> u64:
    if v >= 2048 or t == 0 or t > 7:
        return fail(w, 37)
    if get(w, VBASE + v * 16) != 0:
        return fail(w, 38)
    put(w, VBASE + v * 16, t)
    put(w, VBASE + v * 16 + 8, get(w, 88) + 1)
    fb = FBASE + get(w, 72) * FSTRIDE
    if get(w, 48) == 0:
        if v > get(w, fb + 40):
            put(w, fb + 40, v)
    return 0

def variable(w:mutbuf, v:u64) -> u64:
    if v >= 2048:
        return fail(w, 39)
    if get(w, VBASE + v * 16 + 8) != get(w, 88) + 1:
        return fail(w, 40)
    t = get(w, VBASE + v * 16)
    if t == 0:
        return fail(w, 40)
    return t

def read_type(s:readbuf, w:mutbuf) -> u64:
    t = get(w, 8)
    next_token(s, w)
    if t < @u64@ or t > @mutbuf@:
        return fail(w, 41)
    return t - @u64@ + 1

def check_graph(w:mutbuf) -> u64:
    f = 0
    b = 0
    i = 0
    base = 0
    n = 0
    start = 0
    target = 0
    arm = 0
    while f < get(w, 64) and get(w, 40) == 0:
        base = FBASE + f * FSTRIDE
        start = get(w, base + 8)
        n = get(w, base + 16)
        put(w, BBASE + start * BSTRIDE + 24, 1)
        i = 0
        while i < n:
            b = 0
            while b < n:
                arm = 0
                while arm < 2:
                    target = get(w, BBASE + (start + b) * BSTRIDE + 288 + arm * 8)
                    if target != 18446744073709551615:
                        if target <= start or target >= start + n:
                            fail(w, 42)
                        else:
                            if get(w, BBASE + (start + b) * BSTRIDE + 24) == 1:
                                put(w, BBASE + target * BSTRIDE + 24, 1)
                    arm = arm + 1
                b = b + 1
            i = i + 1
        b = 0
        while b < n:
            if get(w, BBASE + (start + b) * BSTRIDE + 24) != 1:
                fail(w, 43)
            b = b + 1
        f = f + 1
    put(w, 1024, get(w, 64))
    check_calls(w)
    return 0

def check_calls(w:mutbuf) -> u64:
    n = get(w, 64)
    step = 0
    f = 0
    target = 0
    ready = 0
    while step < n:
        f = 0
        while f < n:
            ready = 1
            target = 0
            while target < 128:
                if byte(w, CBASE + f * 128 + target) != 0:
                    if target >= n:
                        return fail(w, 55)
                    if get(w, CSTATE + target * 8) == 0:
                        ready = 0
                target = target + 1
            if ready == 1:
                put(w, CSTATE + f * 8, 1)
            f = f + 1
        step = step + 1
    f = 0
    while f < n:
        if get(w, CSTATE + f * 8) == 0:
            return fail(w, 56)
        f = f + 1
    return 0

def wrapper(o:mutbuf, w:mutbuf) -> u64:
    emit(o, w, 85)
    emit(o, w, 72)
    emit(o, w, 137)
    emit(o, w, 229)
    emit(o, w, 72)
    emit(o, w, 131)
    emit(o, w, 236)
    emit(o, w, 64)
    mem(o, w, 137, 7, 5, 18446744073709551552)
    mem(o, w, 137, 6, 5, 18446744073709551560)
    mem(o, w, 137, 2, 5, 18446744073709551568)
    mem(o, w, 137, 1, 5, 18446744073709551576)
    emit(o, w, 76)
    emit(o, w, 137)
    emit(o, w, 133)
    emit4(o, w, 18446744073709551584)
    emit(o, w, 76)
    emit(o, w, 137)
    emit(o, w, 141)
    emit4(o, w, 18446744073709551592)
    mem(o, w, 141, 7, 5, 18446744073709551552)
    mem(o, w, 141, 6, 5, 18446744073709551608)
    emit(o, w, 232)
    relocation(o, w, 1, 0)
    mem(o, w, 139, 0, 5, 18446744073709551608)
    emit(o, w, 201)
    emit(o, w, 195)
    return 0

def function_start(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 48) == 0:
        return 0
    fb = FBASE + get(w, 72) * FSTRIDE
    put(w, fb, get(w, 56))
    emit(o, w, 85)
    emit(o, w, 72)
    emit(o, w, 137)
    emit(o, w, 229)
    remain = frame(w)
    amount = 0
    while remain > 0:
        amount = remain
        if amount > 4096:
            amount = 4096
        emit(o, w, 72)
        emit(o, w, 129)
        emit(o, w, 236)
        emit4(o, w, amount)
        emit(o, w, 72)
        emit(o, w, 139)
        emit(o, w, 4)
        emit(o, w, 36)
        remain = remain - amount
    mem(o, w, 137, 6, 5, 18446744073709551608)
    i = 0
    t = 0
    while i < get(w, fb + 24):
        t = get(w, fb + 48 + i * 8)
        mem(o, w, 139, 0, 7, i * 16)
        store_var(o, w, i, 0)
        if t >= 6:
            mem(o, w, 139, 0, 7, i * 16 + 8)
            store_var(o, w, i, 1)
        i = i + 1
    return 0

def frame(w:mutbuf) -> u64:
    return (get(w, FBASE + get(w, 72) * FSTRIDE + 40) + 2) * 16 + 544

def copy_argument(o:mutbuf, w:mutbuf, v:u64, i:u64, t:u64) -> u64:
    load_var(o, w, 0, v, 0)
    mem(o, w, 137, 0, 5, 0 - frame(w) + i * 16)
    if t >= 6:
        load_var(o, w, 0, v, 1)
        mem(o, w, 137, 0, 5, 0 - frame(w) + i * 16 + 8)
    return 0

def load_var(o:mutbuf, w:mutbuf, reg:u64, v:u64, word:u64) -> u64:
    return mem(o, w, 139, reg, 5, 0 - 32 - v * 16 + word * 8)

def store_var(o:mutbuf, w:mutbuf, v:u64, word:u64) -> u64:
    return mem(o, w, 137, 0, 5, 0 - 32 - v * 16 + word * 8)

def normalize(o:mutbuf, w:mutbuf, t:u64) -> u64:
    if t == 4:
        emit(o, w, 72)
        emit(o, w, 37)
        emit4(o, w, 255)
    if t == 3:
        emit(o, w, 137)
        emit(o, w, 192)
    if t == 5:
        emit(o, w, 72)
        emit(o, w, 131)
        emit(o, w, 224)
        emit(o, w, 1)
    return 0

def mem(o:mutbuf, w:mutbuf, opcode:u64, reg:u64, base:u64, disp:u64) -> u64:
    emit(o, w, 72)
    emit(o, w, opcode)
    emit(o, w, 128 + reg * 8 + base)
    emit4(o, w, disp)
    return 0

def relocation(o:mutbuf, w:mutbuf, kind:u64, target:u64) -> u64:
    n = get(w, 224)
    if n >= MAX_RELOCATIONS:
        return fail(w, 44)
    if get(w, 48) == 2:
        put(w, FIXBASE + n * 24, get(w, 56))
        put(w, FIXBASE + n * 24 + 8, kind)
        put(w, FIXBASE + n * 24 + 16, target)
    put(w, 224, n + 1)
    emit4(o, w, 0)
    return 0

def fix_all(o:mutbuf, w:mutbuf) -> u64:
    i = 0
    at = 0
    kind = 0
    target = 0
    pos = 0
    while i < get(w, 224):
        at = get(w, FIXBASE + i * 24)
        kind = get(w, FIXBASE + i * 24 + 8)
        target = get(w, FIXBASE + i * 24 + 16)
        if kind == 1:
            pos = get(w, FBASE + target * FSTRIDE)
        else:
            pos = get(w, BBASE + target * BSTRIDE)
        write4(o, at, pos - at - 4)
        i = i + 1
    return 0

def emit8(o:mutbuf, w:mutbuf, x:u64) -> u64:
    return emit_bytes(o, w, x, 8)

def emit4(o:mutbuf, w:mutbuf, x:u64) -> u64:
    return emit_bytes(o, w, x, 4)

def emit(o:mutbuf, w:mutbuf, x:u64) -> u64:
    phase = get(w, 48)
    if phase > 0:
        pos = get(w, 56)
        if phase == 2:
            store(o, pos, x)
        put(w, 56, pos + 1)
    return 0

def write4(o:mutbuf, at:u64, x:u64) -> u64:
    i = 0
    while i < 4:
        store(o, at + i, x & 255)
        x = x >> 8
        i = i + 1
    return 0

def expect(s:readbuf, w:mutbuf, kind:u64) -> u64:
    value = get(w, 16)
    if get(w, 8) != kind:
        fail(w, 45)
    if get(w, 40) == 0:
        next_token(s, w)
    return value

def adjacent(w:mutbuf) -> u64:
    if get(w, 24) != get(w, 120):
        fail(w, 55)
    return 0

def separated(w:mutbuf) -> u64:
    if get(w, 24) <= get(w, 120):
        fail(w, 56)
    return 0

def next_token(s:readbuf, w:mutbuf) -> u64:
    pos = get(w, 0)
    put(w, 120, pos)
    n = length(s)
    c = 0
    begin = 0
    quoted = 0
    kind = 0
    val = 0
    while pos < n and byte(s, pos) == 32:
        pos = pos + 1
    put(w, 16, 0)
    put(w, 32, 0)
    put(w, 24, pos)
    if pos == n:
        put(w, 8, 0)
        put(w, 0, pos)
        return 0
    c = byte(s, pos)
    if c == 10 or c == 40 or c == 41 or c == 44 or c == 58 or c == 61 or c == 123 or c == 125 or c == 45 or c == 62:
        put(w, 8, c)
        put(w, 0, pos + 1)
        return 0
    if c == 95:
        put(w, 8, 95)
        put(w, 0, pos + 1)
        return 0
    if c == 34:
        quoted = 1
        put(w, 32, 1)
        pos = pos + 1
    begin = pos
    if quoted == 0 and c >= 48 and c <= 57:
        val = decimal(s, w, pos)
        put(w, 8, 259)
        put(w, 16, val)
        return 0
    while pos < n and is_word(byte(s, pos)) == 1:
        pos = pos + 1
    if begin == pos:
        return fail(w, 46)
    put(w, 0, pos)
    if quoted == 1:
        if pos >= n or byte(s, pos) != 34:
            return fail(w, 47)
        put(w, 0, pos + 1)
    kind = keyword(s, begin, pos - begin)
    if kind == 0:
        c = byte(s, begin)
        if c == 118 or c == 102 or c == 98:
            put(w, 0, begin + 1)
            val = decimal(s, w, begin + 1)
            if get(w, 0) != pos:
                fail(w, 48)
            if quoted == 1:
                if c != 102:
                    fail(w, 49)
                put(w, 0, pos + 1)
            kind = 256
            if c == 102:
                kind = 257
            if c == 98:
                kind = 258
            put(w, 16, val)
        else:
            fail(w, 50)
    else:
        if quoted == 1:
            if kind != @value@ and kind != @mode@ and kind != @wrap@ and kind != @function@:
                fail(w, 51)
        else:
            if kind == @value@ or kind == @mode@ or kind == @wrap@ or kind == @function@:
                fail(w, 51)
    put(w, 8, kind)
    return 0

def decimal(s:readbuf, w:mutbuf, pos:u64) -> u64:
    n = length(s)
    value = 0
    count = 0
    c = 0
    first = 0
    while pos < n and byte(s, pos) >= 48 and byte(s, pos) <= 57:
        c = byte(s, pos) - 48
        if count == 0:
            first = c
        if value > 1844674407370955161 or (value == 1844674407370955161 and c > 5):
            fail(w, 52)
        value = value * 10 + c
        pos = pos + 1
        count = count + 1
    if count == 0 or (count > 1 and first == 0):
        fail(w, 53)
    put(w, 0, pos)
    return value

def is_word(c:u64) -> u64:
    if (c >= 65 and c <= 90) or (c >= 97 and c <= 122) or (c >= 48 and c <= 57) or c == 46 or c == 45 or c == 95:
        return 1
    return 0

KEYWORD_FUNCTION

def match(s:readbuf, begin:u64, size:u64, expected:u64, a:u64, b:u64, c:u64, d:u64) -> u64:
    if size != expected:
        return 0
    i = 0
    word = 0
    shift = 0
    while i < size:
        word = a
        shift = i
        if i >= 8:
            word = b
            shift = i - 8
        if i >= 16:
            word = c
            shift = i - 16
        if i >= 24:
            word = d
            shift = i - 24
        if byte(s, begin + i) != ((word >> (shift * 8)) & 255):
            return 0
        i = i + 1
    return 1

def fail(w:mutbuf, code:u64) -> u64:
    if get(w, 40) == 0:
        put(w, 40, code)
        put(w, 104, get(w, 24))
    return 0

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0

def get(w:mutbuf, at:u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | (byte(w, at + i) << (i * 8))
        i = i + 1
    return value

def elf_begin(o:mutbuf, w:mutbuf) -> u64:
    emit8(o, w, 282584257676671)
    emit8(o, w, 0)
    emit8(o, w, 4299030529)
    emit8(o, w, 0)
    emit8(o, w, 0)
    emit8(o, w, 0)
    emit8(o, w, 274877906944)
    emit8(o, w, 1125925680840704)
    return 0

def elf_finish(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 48) == 0:
        return 0
    text = get(w, 56) - 64
    align8(o, w)
    symbols = get(w, 56)
    emit8(o, w, 0)
    emit8(o, w, 0)
    emit8(o, w, 0)
    emit8(o, w, 281487861612544)
    emit8(o, w, 0)
    emit8(o, w, 0)
    emit8(o, w, 281552286121985)
    emit8(o, w, 0)
    emit8(o, w, get(w, 240) - 64)
    strings = get(w, 56)
    emit4(o, w, 3171840)
    names = get(w, 56)
    emit8(o, w, 3314777386191695360)
    emit8(o, w, 3314757496449366387)
    emit8(o, w, 3314757496449692787)
    emit8(o, w, 7089075323386685555)
    emit8(o, w, 5129148576381677056)
    emit8(o, w, 7738135737529095502)
    emit(o, w, 0)
    align8(o, w)
    headers = get(w, 56)
    if get(w, 48) == 2:
        put(o, 40, headers)
    elf_section(o, w, 0, 0, 0, 0, 0, 0, 0)
    elf_section(o, w, 4294967297, 6, 64, text, 0, 16, 0)
    elf_section(o, w, 8589934599, 0, symbols, 72, 8589934595, 8, 24)
    elf_section(o, w, 12884901903, 0, strings, 4, 0, 1, 0)
    elf_section(o, w, 12884901911, 0, names, 49, 0, 1, 0)
    elf_section(o, w, 4294967329, 0, names + 49, 0, 0, 1, 0)
    return 0

def align8(o:mutbuf, w:mutbuf) -> u64:
    while (get(w, 56) & 7) != 0:
        emit(o, w, 0)
    return 0

def elf_section(o:mutbuf, w:mutbuf, kind:u64, flags:u64, offset:u64, size:u64, links:u64, alignment:u64, item_size:u64) -> u64:
    emit8(o, w, kind)
    emit8(o, w, flags)
    emit8(o, w, 0)
    emit8(o, w, offset)
    emit8(o, w, size)
    emit8(o, w, links)
    emit8(o, w, alignment)
    emit8(o, w, item_size)
    return 0

def account_nodes(w:mutbuf, amount:u64) -> u64:
    nodes = get(w, 248) + amount
    put(w, 248, nodes)
    if nodes > MAX_CORE_NODES:
        return fail(w, 58)
    return 0

def emit_bytes(o:mutbuf, w:mutbuf, x:u64, remaining:u64) -> u64:
    if remaining == 0:
        return 0
    emit(o, w, x & 255)
    return emit_bytes(o, w, x >> 8, remaining - 1)
# Kept in a separate HIA function so the per-function SSA ceiling stays 2047.
# Appending this helper preserves all existing compiler function identities.
def checked_integer(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:
    load_var(o, w, 0, a, 0)
    if op == @bit.not@:
        if n != 1 or at < 1 or at > 4 or t != at:
            fail(w, 31)
        # NOT is a full machine word operation; restore the declared width.
        emit(o, w, 72)
        emit(o, w, 247)
        emit(o, w, 208)
        normalize(o, w, t)
        return 0
    if op == @int.neg.checked@:
        if n != 1 or at < 1 or at > 4 or t != at:
            fail(w, 31)
        # The only representable unsigned negation is zero. Test before any
        # later operation, preserving all earlier observable stores.
        emit_bytes(o, w, 3112727966942536, 7)
        return 0
    if n != 2 or at != bt or t != at or t == 0 or t > 4:
        fail(w, 34)
    load_var(o, w, 1, b, 0)
    if op == @int.div.checked@ or op == @int.rem.checked@:
        # test rcx,rcx; jne +2; ud2; xor edx,edx; div rcx. Clearing the
        # dividend's upper half avoids machine overflow for every u64 input.
        emit_bytes(o, w, 3112727984309576, 7)
        emit_bytes(o, w, 1039235863089, 5)
        if op == @int.rem.checked@:
            emit_bytes(o, w, 13666632, 3)
        return 0
    if op == @int.mul.checked@:
        # Unsigned MUL sets CF iff the high half is nonzero. IMUL's signed
        # overflow flag would reject legal high-bit operands such as MAX*1.
        emit_bytes(o, w, 3112727952357192, 7)
    else:
        if op != @int.add.checked@ and op != @int.sub.checked@:
            return fail(w, 36)
        # Operands are zero extended. Preserve CF until the first branch:
        # add/sub rax, rcx; jnc +2; ud2. This checks 64-bit carry/borrow.
        emit(o, w, 72)
        if op == @int.add.checked@:
            emit(o, w, 1)
        else:
            emit(o, w, 41)
        emit(o, w, 200)
        emit(o, w, 115)
        emit(o, w, 2)
        emit(o, w, 15)
        emit(o, w, 11)
    if (op == @int.add.checked@ or op == @int.mul.checked@) and (t == 3 or t == 4):
        # A narrow result can overflow without a 64-bit carry. Save the full
        # result, normalize rax, then require that no high bits were lost.
        emit(o, w, 72)
        emit(o, w, 137)
        emit(o, w, 193)
        normalize(o, w, t)
        emit(o, w, 72)
        emit(o, w, 57)
        emit(o, w, 200)
        emit(o, w, 116)
        emit(o, w, 2)
        emit(o, w, 15)
        emit(o, w, 11)
    normalize(o, w, t)
    return 0


def select_scalar(o:mutbuf, w:mutbuf, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:
    if n != 3 or at != 5 or bt == 0 or bt > 5 or t != bt or variable(w, get(w, ARGS + 16)) != bt:
        fail(w, 60)
    # Core select(cond, true_value, false_value). Full-width moves preserve
    # the already-normalized scalar slots, including u64/usize high bits.
    load_var(o, w, 2, a, 0)
    load_var(o, w, 1, b, 0)
    load_var(o, w, 0, get(w, ARGS + 16), 0)
    # test rdx, rdx; cmovne rax, rcx
    emit(o, w, 72)
    emit(o, w, 133)
    emit(o, w, 210)
    emit(o, w, 72)
    emit(o, w, 15)
    emit(o, w, 69)
    emit(o, w, 193)
    return 0

# Appended helpers keep earlier HIA function names stable. Successor preflight
# and trap lowering execute here, without a host parser or lowering callback.
def explicit_trap(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    account_nodes(w, 3)
    expect(s, w, @trap@)
    separated(w)
    code = get(w, 8)
    if code != @user@ and code != @overflow@ and code != @division_by_zero@ and code != @bounds@ and code != @allocation@:
        return fail(w, 61)
    next_token(s, w)
    # The flat ABI exposes an aborting UD2, not a structured trap-code result.
    # Prior stores stay visible and no caller continuation is executed.
    emit(o, w, 15)
    emit(o, w, 11)
    return 0

def source_limits(s:readbuf, w:mutbuf) -> u64:
    pos = 0
    line_bytes = 0
    lines = 1
    while pos < length(s):
        if byte(s, pos) == 10:
            lines = lines + 1
            line_bytes = 0
            if lines > MAX_SOURCE_LINES:
                put(w, 24, pos)
                fail(w, 63)
                return 0
        else:
            line_bytes = line_bytes + 1
            if line_bytes > MAX_LINE_BYTES:
                put(w, 24, pos)
                fail(w, 62)
                return 0
        pos = pos + 1
    return 1
'''


def source_program():
    table = ['def keyword(s:readbuf, begin:u64, size:u64) -> u64:']
    for word, token in W.items():
        raw = word.encode().ljust(32, b'\0')
        chunks = [int.from_bytes(raw[i:i+8], 'little') for i in range(0, 32, 8)]
        table += [f'    if match(s, begin, size, {len(word)}, '+', '.join(map(str,chunks))+') == 1:', f'        return {token}']
    table += ['    return 0']
    text = SOURCE.replace('KEYWORD_FUNCTION', '\n'.join(table))
    for k,v in W.items(): text = text.replace('@'+k+'@', str(v))
    for key in ['FBASE','FSTRIDE','BBASE','BSTRIDE','VBASE','ARGS','FIXBASE','CBASE','CSTATE',
                'MAX_INSTRUCTIONS', 'MAX_CORE_NODES', 'MAX_RELOCATIONS',
                'MAX_SOURCE_LINES', 'MAX_LINE_BYTES']:
        text = text.replace(key, str(globals()[key]))
    return text


class Builder:
    def __init__(self, node, names, signatures):
        self.node,self.names,self.signatures = node,names,signatures
        self.serial=0; self.blocks=[]; self.env={}; self.block=None
        self.returns=node.returns.id
        params=[]
        for a in node.args.args:
            v=self.value(a.annotation.id); self.env[a.arg]=v; params.append(v)
        self.params=params
        self.block={'id':'b0','params':[self.param(v) for v in params],'ops':[]}
        self.blocks.append(self.block)

    def value(self,t):
        v=(f'v{self.serial}',t); self.serial+=1; return v
    def param(self,v): return {'name':v[0],'type':v[1]}
    def op(self,op,args,t=None,**attrs):
        out=[] if t is None else [self.value(t)]
        self.block['ops'].append({'op':op,'args':[a[0] for a in args],'out':[self.param(x) for x in out],'attrs':attrs})
        return out[0] if out else None
    def c(self,v,t='u64'): return self.op('const',[],t,value=v)
    def cast(self,x,t): return x if x[1]==t else self.op('int.cast',[x],t,mode='wrap')
    def fresh(self,env):
        new={k:self.value(v[1]) for k,v in env.items()}
        b={'id':'b'+str(len(self.blocks)),'params':[self.param(v) for v in new.values()],'ops':[]}
        self.blocks.append(b)
        return b,new
    def edge(self,b,env): return {'target':b['id'],'args':[env[k][0] for k in self.env_template(b)]}
    def env_template(self,b):
        return self.block_env_keys[b['id']]
    def jump(self,b,env,keys): self.block['term']={'op':'jump','target':b['id'],'args':[env[k][0] for k in keys]}
    def expr(self,e):
        if isinstance(e,ast.Name): return self.env[e.id]
        if isinstance(e,ast.Constant): return self.c(e.value,'bool' if type(e.value) is bool else 'u64')
        if isinstance(e,ast.BinOp):
            x,y=self.expr(e.left),self.expr(e.right)
            op={ast.Add:'int.add.wrap',ast.Sub:'int.sub.wrap',ast.Mult:'int.mul.wrap',ast.BitAnd:'bit.and',ast.BitOr:'bit.or',ast.BitXor:'bit.xor',ast.LShift:'int.shl.checked',ast.RShift:'int.shr.checked'}[type(e.op)]
            return self.op(op,[x,y],x[1])
        if isinstance(e,ast.Compare):
            assert len(e.ops)==1
            x,y=self.expr(e.left),self.expr(e.comparators[0])
            op={ast.Eq:'eq',ast.NotEq:'ne',ast.Lt:'lt',ast.LtE:'le',ast.Gt:'gt',ast.GtE:'ge'}[type(e.ops[0])]
            return self.op('compare.'+op,[x,y],'bool')
        if isinstance(e,ast.BoolOp):
            # Short circuit is essential for byte-at-end guards.
            val=self.expr(e.values[0])
            for tail in e.values[1:]:
                original=dict(self.env); key='shortcircuit'+str(self.serial)
                original[key]=val
                keys=list(original)
                yes,yenv=self.fresh(original); no,nenv=self.fresh(original); done,denv=self.fresh(original)
                self.block['term']={'op':'branch','cond':val[0],'then':{'target':yes['id'],'args':[x[0] for x in original.values()]},'else':{'target':no['id'],'args':[x[0] for x in original.values()]}}
                calc,cen=(yes,yenv) if isinstance(e.op,ast.And) else (no,nenv)
                other,oen=(no,nenv) if isinstance(e.op,ast.And) else (yes,yenv)
                self.block,self.env=calc,cen; self.env[key]=self.expr(tail); self.jump(done,self.env,keys)
                self.block,self.env=other,oen; self.jump(done,self.env,keys)
                self.block,self.env=done,denv; val=self.env.pop(key)
            return val
        if isinstance(e,ast.Call):
            name=e.func.id; args=[self.expr(x) for x in e.args]
            if name=='length': return self.cast(self.op('buffer.len',args,'usize'),'u64')
            if name=='byte': return self.cast(self.op('buffer.load',[args[0],self.cast(args[1],'usize')],'u8'),'u64')
            if name=='store': return self.op('buffer.store',[args[0],self.cast(args[1],'usize'),self.cast(args[2],'u8')])
            sig=self.signatures[name]
            assert len(args)==len(sig[0]),name
            converted=[self.cast(a,t) if a[1]!=t else a for a,t in zip(args,sig[0])]
            return self.op('call',converted,sig[1],function=self.names[name])
        raise ValueError(ast.dump(e))

    def statements(self, statements):
        for s in statements:
            if 'term' in self.block: break
            if isinstance(s,ast.Assign):
                assert len(s.targets)==1 and isinstance(s.targets[0],ast.Name)
                self.env[s.targets[0].id]=self.expr(s.value)
            elif isinstance(s,ast.Expr): self.expr(s.value)
            elif isinstance(s,ast.Return):
                val=self.cast(self.expr(s.value),self.returns)
                self.block['term']={'op':'ret','values':[val[0]]}
            elif isinstance(s,ast.If):
                cond=self.expr(s.test); base=dict(self.env); keys=list(base)
                yes,ye=self.fresh(base); no,ne=self.fresh(base)
                self.block['term']={'op':'branch','cond':cond[0],'then':{'target':yes['id'],'args':[v[0] for v in base.values()]},'else':{'target':no['id'],'args':[v[0] for v in base.values()]}}
                self.block,self.env=yes,ye; self.statements(s.body); yb,yend=self.block,dict(self.env)
                self.block,self.env=no,ne; self.statements(s.orelse); nb,nend=self.block,dict(self.env)
                live=[(b,e) for b,e in [(yb,yend),(nb,nend)] if 'term' not in b]
                if not live:
                    self.block,self.env=yb,yend; continue
                # Variables introduced on only one path cannot escape that path.
                common=[k for k in live[0][1] if all(k in e for b,e in live)]
                merged={k:live[0][1][k] for k in common}
                done,de=self.fresh(merged)
                for b,e in live:
                    self.block,self.env=b,e; self.jump(done,e,common)
                self.block,self.env=done,de
            elif isinstance(s,ast.While):
                base=dict(self.env); keys=list(base)
                entry,ee=self.fresh(base); self.jump(entry,self.env,keys)
                self.block,self.env=entry,ee
                cond=self.expr(s.test); head=self.block; he=dict(self.env)
                body,be=self.fresh(he); done,de=self.fresh(he)
                head['term']={'op':'branch','cond':cond[0],'then':{'target':body['id'],'args':[v[0] for v in he.values()]},'else':{'target':done['id'],'args':[v[0] for v in he.values()]}}
                self.block,self.env=body,be; self.statements(s.body)
                if 'term' not in self.block: self.jump(entry,self.env,keys)
                self.block,self.env=done,de
            else: raise ValueError(ast.dump(s))


def document():
    nodes=ast.parse(source_program()).body
    # Source order deliberately contains backward direct calls. The HIA
    # compiler's call-graph checker, not author-time topological numbering,
    # admits its non-self DAG and checked direct tail self calls. General
    # recursive cycles remain outside the native fixed profile.
    ordered=nodes
    assert ordered[0].name=='compile'
    names={n.name:'f'+str(i) for i,n in enumerate(ordered)}
    sigs={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in ordered}
    functions=[]
    for n in ordered:
        b=Builder(n,names,sigs)
        b.statements(n.body)
        functions.append({'name':names[n.name],'params':[b.param(x) for x in b.params],'returns':[b.returns], 'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return {'schema':'hepta.hia.program.v8','module':'selfhost','functions':functions},names


def main():
    doc,names=document()
    output=ROOT/'examples/hia_bootstrap/selfhost.hiaasm'
    output.write_text(render_assembly(doc))
    print(json.dumps({'bytes':output.stat().st_size,'functions':names,'operations':sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),'blocks':sum(len(f['blocks']) for f in doc['functions'])},sort_keys=True))

if __name__=='__main__': main()
