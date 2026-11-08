"""Authoring helpers for explicit libc-bound owned-buffer ELF output.

Only object output can carry the two closed allocator imports. Flat output
refuses instructions which require them before its first output write. These
are restricted HIA authoring functions, consumed by native successors after
B0; neither a Python object writer nor a loader rewrite creates their output.
The default borrowed entry remains the same six pointer/length arguments.
"""
from __future__ import annotations


SOURCE = r'''
def owned_read_outputs(s:readbuf, w:mutbuf) -> u64:
    put(w, 288, 0)
    put(w, 296, 2048)
    put(w, 304, 0)
    if get(w, 8) == 95:
        next_token(s, w)
        return 0
    count = 0
    v = 0
    t = 0
    while get(w, 8) != 61 and get(w, 40) == 0:
        if count >= 3:
            return fail(w, 66)
        v = expect(s, w, 256)
        expect(s, w, 58)
        t = read_type(s, w)
        put(w, 296 + count * 16, v)
        put(w, 304 + count * 16, t)
        count = count + 1
        if get(w, 8) != 61:
            expect(s, w, 44)
            if get(w, 8) == 61:
                return fail(w, 66)
    put(w, 288, count)
    if count == 0:
        return fail(w, 66)
    return 0

def owned_define_outputs(w:mutbuf) -> u64:
    i = 0
    v = 0
    t = 0
    if get(w, 40) != 0:
        return 0
    while i < get(w, 288):
        v = get(w, 296 + i * 16)
        t = get(w, 304 + i * 16)
        define(w, v, t)
        if get(w, 40) != 0:
            return 0
        if t >= 8:
            owner_produce(w, v)
        i = i + 1
    return 0

def owned_branch(o:mutbuf, w:mutbuf, condition:u64) -> u64:
    if condition == 0:
        emit(o, w, 233)
    else:
        emit(o, w, 15)
        emit(o, w, condition)
    at = get(w, 56)
    emit4(o, w, 0)
    return at

def owned_patch(o:mutbuf, w:mutbuf, at:u64) -> u64:
    if get(w, 48) == 2:
        write4(o, at, get(w, 56) - at - 4)
    return 0

def owned_immediate(o:mutbuf, w:mutbuf, value:u64, out:u64, word:u64) -> u64:
    emit_bytes(o, w, 47176, 2)
    emit8(o, w, value)
    store_var(o, w, out, word)
    return 0

def owned_import(o:mutbuf, w:mutbuf, symbol:u64) -> u64:
    if get(w, 232) != 1 or symbol > 1:
        return fail(w, 64)
    put(w, 344, get(w, 344) + 1)
    emit(o, w, 232)
    relocation(o, w, 3, symbol)
    return 0

def owned_allocate_libc(o:mutbuf, w:mutbuf, size:u64, out:u64, ok:u64, trapping:u64) -> u64:
    load_var(o, w, 6, size, 0)
    emit_bytes(o, w, 16155976, 3)
    empty = owned_branch(o, w, 132)
    oversize = owned_branch(o, w, 136)
    emit_bytes(o, w, 48968, 2)
    emit8(o, w, 1)
    owned_import(o, w, 0)
    emit_bytes(o, w, 12617032, 3)
    failed = owned_branch(o, w, 132)
    store_var(o, w, out, 0)
    load_var(o, w, 0, size, 0)
    store_var(o, w, out, 1)
    if trapping == 0:
        owned_immediate(o, w, 1, ok, 0)
    done = owned_branch(o, w, 0)
    owned_patch(o, w, empty)
    owned_immediate(o, w, 0, out, 0)
    owned_immediate(o, w, 0, out, 1)
    if trapping == 0:
        owned_immediate(o, w, 1, ok, 0)
    empty_done = owned_branch(o, w, 0)
    owned_patch(o, w, oversize)
    owned_patch(o, w, failed)
    if trapping == 1:
        emit_bytes(o, w, 2831, 2)
    else:
        owned_immediate(o, w, 0, out, 0)
        owned_immediate(o, w, 0, out, 1)
        owned_immediate(o, w, 0, ok, 0)
    owned_patch(o, w, done)
    owned_patch(o, w, empty_done)
    return 0

def owned_drop_libc(o:mutbuf, w:mutbuf, source:u64) -> u64:
    load_var(o, w, 7, source, 0)
    emit_bytes(o, w, 16745800, 3)
    empty = owned_branch(o, w, 132)
    owned_import(o, w, 1)
    owned_patch(o, w, empty)
    return 0

def owned_move_buffer(o:mutbuf, w:mutbuf, source:u64, out:u64) -> u64:
    load_var(o, w, 0, source, 0)
    store_var(o, w, out, 0)
    load_var(o, w, 0, source, 1)
    store_var(o, w, out, 1)
    return 0

def owned_instruction(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, at:u64) -> u64:
    if get(w, 232) != 1:
        return fail(w, 64)
    if op >= @chain.empty@:
        return chain_instruction(o, w, op, n, a, at)
    count = get(w, 288)
    out = get(w, 296)
    t = get(w, 304)
    if n != 1:
        return fail(w, 63)
    if op == @owner.move@ or op == @owner.drop@:
        if at < 8:
            return fail(w, 63)
        owner_free(w, a)
        if get(w, 40) != 0:
            return 0
        if op == @owner.move@:
            if count != 1 or t != at:
                return fail(w, 63)
            owned_move_buffer(o, w, a, out)
        else:
            if count != 0:
                return fail(w, 63)
            if get(w, FBASE + get(w, 72) * FSTRIDE + 176) != 1:
                return fail(w, 65)
            if at == 9:
                chain_drop_call(o, w, a)
            else:
                owned_drop_libc(o, w, a)
        owner_consume(w, a)
        return 0
    if at != 2 or t != 8:
        return fail(w, 63)
    if get(w, FBASE + get(w, 72) * FSTRIDE + 176) != 1:
        return fail(w, 65)
    trapping = 0
    ok = get(w, 312)
    if op == @buffer.new@:
        if count != 1:
            return fail(w, 63)
        trapping = 1
    else:
        if op != @buffer.try_new@ or count != 2 or get(w, 320) != 5:
            return fail(w, 63)
    owned_allocate_libc(o, w, a, out, ok, trapping)
    return 0

def owned_elf_relocations(o:mutbuf, w:mutbuf) -> u64:
    i = 0
    if get(w, 48) == 1:
        while i < get(w, 344):
            emit8(o, w, 0)
            emit8(o, w, 0)
            emit8(o, w, 0)
            i = i + 1
    else:
        while i < get(w, 224):
            if get(w, FIXBASE + i * 24 + 8) == 3:
                emit8(o, w, get(w, FIXBASE + i * 24) - 64)
                emit8(o, w, ((get(w, FIXBASE + i * 24 + 16) + 3) << 32) | 4)
                emit8(o, w, 18446744073709551612)
            i = i + 1
    return 0

def owned_elf_finish(o:mutbuf, w:mutbuf) -> u64:
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
    emit8(o, w, 77309411332)
    emit8(o, w, 0)
    emit8(o, w, 0)
    emit8(o, w, 77309411339)
    emit8(o, w, 0)
    emit8(o, w, 0)
    strings = get(w, 56)
    OWNED_SYMBOL_STRINGS
    names = get(w, 56)
    OWNED_SECTION_STRINGS
    align8(o, w)
    relocs = get(w, 56)
    owned_elf_relocations(o, w)
    headers = get(w, 56)
    if get(w, 48) == 2:
        put(o, 40, headers)
        write4(o, 60, 262151)
    elf_section(o, w, 0, 0, 0, 0, 0, 0, 0)
    elf_section(o, w, 4294967297, 6, 64, text, 0, 16, 0)
    elf_section(o, w, 8589934599, 0, symbols, 120, 8589934595, 8, 24)
    elf_section(o, w, 12884901903, 0, strings, 16, 0, 1, 0)
    elf_section(o, w, 12884901911, 0, names, 60, 0, 1, 0)
    elf_section(o, w, 4294967329, 0, names + 60, 0, 0, 1, 0)
    elf_section(o, w, 17179869233, 0, relocs, get(w, 344) * 24, 4294967298, 8, 24)
    return 0
'''

for _token, _data in {
    "OWNED_SYMBOL_STRINGS": b"\0f0\0calloc\0free\0",
    "OWNED_SECTION_STRINGS": b"\0.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0.rela.text\0",
}.items():
    _lines = []
    for _index in range(0, len(_data), 8):
        _chunk = _data[_index:_index + 8]
        _lines.append(f"emit_bytes(o, w, {int.from_bytes(_chunk, 'little')}, {len(_chunk)})")
    SOURCE = SOURCE.replace(_token, "\n    ".join(_lines))
