"""HIA explicit scalar exports, SysV wrappers and multiple-symbol ELF output.

The authoring text is compiled into the actual selfhost image. Source names are
copied from admitted declarations, never dispatched by hashes. Legacy borrowed
f0 output remains unchanged when no explicit exports line is present.
"""
from __future__ import annotations


def _hooks():
    lines=['def export_loader_hook(s:readbuf, begin:u64, size:u64) -> u64:']
    for name in ('abort','calloc','malloc','free','memset','memcpy','memmove','_init','_fini','__gmon_start__','__cxa_finalize','__dso_handle',
                 '_ITM_registerTMCloneTable','_ITM_deregisterTMCloneTable'):
        data=name.encode()
        words=[int.from_bytes(data[i:i+8],'little') for i in range(0,32,8)]
        lines.append(f'    if match(s, begin, size, {len(data)}, '+', '.join(map(str,words))+') == 1:')
        lines.append('        return 1')
    return '\n'.join(lines)+'\n    return 0\n'


SOURCE = r'''
def read_exports(s:readbuf, w:mutbuf) -> u64:
    put(w, 640, 0)
    put(w, 648, 0)
    if get(w, 8) != @exports@:
        return 0
    put(w, 640, 1)
    next_token(s, w)
    adjacent(w)
    expect(s, w, 40)
    n = 0
    record = 0
    while get(w, 8) != 41 and get(w, 40) == 0:
        if n >= 128 or get(w, 32) != 0:
            return fail(w, 68)
        identifier(s, w)
        if get(w, 40) != 0:
            return 0
        if lookup_identifier(s, w, 1010448, 48, n) != n:
            return fail(w, 68)
        if export_loader_hook(s, get(w, 456), get(w, 464)) == 1:
            return fail(w, 68)
        record = 1010448 + n * 48
        put(w, record, get(w, 456))
        put(w, record + 8, get(w, 464))
        put(w, record + 16, get(w, 472))
        next_token(s, w)
        n = n + 1
        if get(w, 8) != 41:
            expect(s, w, 44)
            if get(w, 8) == 41:
                return fail(w, 68)
    expect(s, w, 41)
    expect(s, w, 10)
    if n == 0 or get(w, 232) == 2:
        return fail(w, 68)
    # Explicit native scalar exports select an ELF object independently of the
    # ordinary module label. Flat/stdio ABI would be ambiguous for this list.
    put(w, 232, 1)
    put(w, 648, n)
    account_nodes(w, n + 1)
    return 0

def validate_exports(s:readbuf, w:mutbuf) -> u64:
    i = 0
    record = 0
    f = 0
    fb = 0
    j = 0
    if get(w, 640) == 0 or get(w, 432) == 1:
        return 0
    while i < get(w, 648):
        record = 1010448 + i * 48
        put(w, 456, get(w, record))
        put(w, 464, get(w, record + 8))
        put(w, 472, get(w, record + 16))
        f = lookup_identifier(s, w, FBASE + 240, FSTRIDE, get(w, 64))
        if f == get(w, 64):
            return fail(w, 68)
        put(w, record + 24, f)
        fb = FBASE + f * FSTRIDE
        if get(w, fb + 184) > 1:
            return fail(w, 68)
        if get(w, fb + 184) == 1:
            if scalar_type(get(w, fb + 32)) == 0:
                return fail(w, 68)
        j = 0
        while j < get(w, fb + 24):
            if scalar_type(get(w, fb + 48 + j * 8)) == 0 or get(w, fb + 48 + j * 8) == 16:
                return fail(w, 68)
            j = j + 1
        i = i + 1
    return 0

def export_wrapper(o:mutbuf, w:mutbuf, record:u64) -> u64:
    f = get(w, record + 24)
    fb = FBASE + f * FSTRIDE
    count = get(w, fb + 24)
    frame_size = (count + 4) * 16
    put(w, record + 32, get(w, 56))
    emit_bytes(o, w, 3850979413, 4)
    emit_bytes(o, w, 15499592, 3)
    emit4(o, w, frame_size)
    i = 0
    while i < count:
        if i == 0:
            emit_bytes(o, w, 16288072, 3)
        if i == 1:
            emit_bytes(o, w, 15763784, 3)
        if i == 2:
            emit_bytes(o, w, 13666632, 3)
        if i == 3:
            emit_bytes(o, w, 13142344, 3)
        if i == 4:
            emit_bytes(o, w, 12618060, 3)
        if i == 5:
            emit_bytes(o, w, 13142348, 3)
        if i >= 6:
            mem(o, w, 139, 0, 5, 16 + (i - 6) * 8)
        normalize(o, w, get(w, fb + 48 + i * 8))
        mem(o, w, 137, 0, 5, 0 - frame_size + i * 16)
        i = i + 1
    mem(o, w, 141, 7, 5, 0 - frame_size)
    mem(o, w, 141, 6, 5, 18446744073709551552)
    emit(o, w, 232)
    relocation(o, w, 1, f)
    if get(w, fb + 184) == 0:
        emit_bytes(o, w, 49201, 2)
    else:
        mem(o, w, 139, 0, 5, 18446744073709551552)
        normalize(o, w, get(w, fb + 32))
    emit_bytes(o, w, 50121, 2)
    put(w, record + 40, get(w, 56) - get(w, record + 32))
    return 0

def exports_finish(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, 48) == 0:
        return 0
    count = get(w, 648)
    i = 0
    record = 0
    while i < count:
        export_wrapper(o, w, 1010448 + i * 48)
        i = i + 1
    text = get(w, 56) - 64
    align8(o, w)
    symbols = get(w, 56)
    emit8(o, w, 0)
    emit8(o, w, 0)
    emit8(o, w, 0)
    emit8(o, w, 281487861612544)
    emit8(o, w, 0)
    emit8(o, w, 0)
    string_size = 1
    i = 0
    while i < count:
        record = 1010448 + i * 48
        emit8(o, w, 281552286121984 + string_size)
        emit8(o, w, get(w, record + 32) - 64)
        emit8(o, w, get(w, record + 40))
        string_size = string_size + get(w, record + 8) + 1
        i = i + 1
    symbol_count = count + 2
    if get(w, 344) != 0:
        emit8(o, w, 77309411328 + string_size)
        emit8(o, w, 0)
        emit8(o, w, 0)
        emit8(o, w, 77309411335 + string_size)
        emit8(o, w, 0)
        emit8(o, w, 0)
        symbol_count = symbol_count + 2
    strings = get(w, 56)
    emit(o, w, 0)
    i = 0
    j = 0
    while i < count:
        record = 1010448 + i * 48
        j = 0
        while j < get(w, record + 8):
            emit(o, w, byte(s, get(w, record) + j))
            j = j + 1
        emit(o, w, 0)
        i = i + 1
    if get(w, 344) != 0:
        emit_bytes(o, w, 109330211561827, 7)
        emit_bytes(o, w, 1701147238, 5)
        string_size = string_size + 12
    names = get(w, 56)
    EXPORT_SECTION_NAMES
    align8(o, w)
    relocs = get(w, 56)
    owned_elf_relocations(o, w)
    headers = get(w, 56)
    if get(w, 48) == 2:
        put(o, 40, headers)
        write4(o, 60, 262151)
    elf_section(o, w, 0, 0, 0, 0, 0, 0, 0)
    elf_section(o, w, 4294967297, 6, 64, text, 0, 16, 0)
    elf_section(o, w, 8589934599, 0, symbols, symbol_count * 24, 8589934595, 8, 24)
    elf_section(o, w, 12884901903, 0, strings, string_size, 0, 1, 0)
    elf_section(o, w, 12884901911, 0, names, 60, 0, 1, 0)
    elf_section(o, w, 4294967329, 0, names + 60, 0, 0, 1, 0)
    elf_section(o, w, 17179869233, 0, relocs, get(w, 344) * 24, 4294967298, 8, 24)
    return 0
''' + _hooks()

_data=b'\0.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0.rela.text\0'
assert len(_data)==60
SOURCE=SOURCE.replace('EXPORT_SECTION_NAMES','\n    '.join(
    f'emit_bytes(o, w, {int.from_bytes(_data[i:i+8], "little")}, {len(_data[i:i+8])})' for i in range(0,len(_data),8)))
