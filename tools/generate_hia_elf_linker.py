"""Author the closed-profile HIA ET_REL -> ET_DYN linker.

The checked-in HIA source performs object validation, layout, symbol merging,
relocation and ELF emission. This authoring aid is not used by the native linker.
Its profile is the selfhost compiler's canonical Linux x86-64 objects, not
arbitrary ELF objects. libc calloc/free remain explicit external ABI providers.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIALNK01', 'little')
LIMIT = 1 << 20
WORKSPACE = 16384
SOURCE = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/elf_linker.hiaasm'

AUTHORING = r'''
def link(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 24 or length(s) > 1048576:
        return 4294967295
    if length(w) < 16384:
        return 4294967294
    if read(s, 0, 8) != MAGIC:
        return 4294967295
    count = read(s, 8, 8)
    if count == 0 or count > 16 or 16 + count * 8 > length(s):
        return 4294967295
    zero(w, 0, 16384)
    put(w, 0, count, 8)
    put(w, 16, 1, 8)
    put(w, 32, 352, 8)
    at = 16 + count * 8
    i = 0
    while i < count:
        size = read(s, 16 + i * 8, 8)
        if size > length(s) - at:
            return 4294967295
        status = object(s, w, at, size, i)
        if status != 0:
            return status
        at = at + size
        i = i + 1
    if at != length(s):
        return 4294967295
    size = layout(w)
    if size > 1048576 or length(o) < size:
        return 4294967294
    zero(o, 0, size)
    headers(o, w)
    payload(s, o, w)
    tables(s, o, w)
    return size

def object(s:readbuf, w:mutbuf, base:u64, size:u64, index:u64) -> u64:
    if size < 448:
        return 4294967295
    if read(s, base, 8) != 282584257676671 or read(s, base + 8, 8) != 0:
        return 4294967295
    if read(s, base + 16, 8) != 4299030529 or read(s, base + 24, 8) != 0 or read(s, base + 32, 8) != 0:
        return 4294967295
    if read(s, base + 48, 8) != 274877906944 or read(s, base + 56, 4) != 4194304:
        return 4294967295
    sections = read(s, base + 60, 2)
    if (sections != 6 and sections != 7) or read(s, base + 62, 2) != 4:
        return 4294967295
    end = read(s, base + 40, 8)
    if end < 64 or end > size or (end & 7) != 0 or size - end != sections * 64:
        return 4294967295
    h = base + end
    i = 0
    while i < 8:
        if read(s, h + i * 8, 8) != 0:
            return 4294967295
        i = i + 1
    text = read(s, h + 96, 8)
    if text == 0 or text > end - 64:
        return 4294967295
    symbols = (64 + text + 7) & 18446744073709551608
    symbolbytes = read(s, h + 160, 8)
    if symbolbytes < 72 or symbolbytes > 3168 or div24(symbolbytes) * 24 != symbolbytes or symbols > end or symbolbytes > end - symbols:
        return 4294967295
    if sections == 6 and symbolbytes != 72:
        return 4294967295
    strings = symbols + symbolbytes
    stringbytes = read(s, h + 224, 8)
    if stringbytes < 4 or strings > end or stringbytes > end - strings:
        return 4294967295
    if sections == 6 and stringbytes != 4:
        return 4294967295
    names = strings + stringbytes
    namebytes = 49
    if sections == 7:
        namebytes = 60
    if names > end or namebytes > end - names:
        return 4294967295
    relocs = (names + namebytes + 7) & 18446744073709551608
    relocbytes = 0
    if sections == 7:
        relocbytes = read(s, h + 416, 8)
    if relocs > end or relocbytes != end - relocs or div24(relocbytes) * 24 != relocbytes:
        return 4294967295
    if section(s, h + 64, 4294967297, 6, 64, text, 0, 16, 0) == 0:
        return 4294967295
    if section(s, h + 128, 8589934599, 0, symbols, symbolbytes, 8589934595, 8, 24) == 0:
        return 4294967295
    if section(s, h + 192, 12884901903, 0, strings, stringbytes, 0, 1, 0) == 0:
        return 4294967295
    if section(s, h + 256, 12884901911, 0, names, namebytes, 0, 1, 0) == 0:
        return 4294967295
    if section(s, h + 320, 4294967329, 0, names + namebytes, 0, 0, 1, 0) == 0:
        return 4294967295
    if sections == 7:
        if section(s, h + 384, 17179869233, 0, relocs, relocbytes, 4294967298, 8, 24) == 0:
            return 4294967295
    if names_ok(s, base + names, namebytes) == 0:
        return 4294967295
    i = 64 + text
    while i < symbols:
        if byte(s, base + i) != 0:
            return 4294967295
        i = i + 1
    i = names + namebytes
    while i < relocs:
        if byte(s, base + i) != 0:
            return 4294967295
        i = i + 1
    if read(s, base + symbols, 8) != 0 or read(s, base + symbols + 8, 8) != 0 or read(s, base + symbols + 16, 8) != 0:
        return 4294967295
    if read(s, base + symbols + 24, 8) != 281487861612544 or read(s, base + symbols + 32, 8) != 0 or read(s, base + symbols + 40, 8) != 0:
        return 4294967295
    if byte(s, base + strings) != 0:
        return 4294967295
    record = 1024 + index * 128
    put(w, record, base, 8)
    put(w, record + 8, text, 8)
    put(w, record + 16, base + relocs, 8)
    put(w, record + 24, div24(relocbytes), 8)
    put(w, record + 32, get(w, 32), 8)
    put(w, 32, (get(w, 32) + text + 15) & 18446744073709551600, 8)
    put(w, record + 48, base + symbols, 8)
    put(w, record + 56, div24(symbolbytes), 8)
    put(w, record + 64, base + strings, 8)
    put(w, record + 72, stringbytes, 8)
    put(w, record + 80, sections, 8)
    status = scan_symbols(s, w, record)
    if status != 0:
        return status
    return relocations(s, w, record)

def scan_symbols(s:readbuf, w:mutbuf, record:u64) -> u64:
    strnext = 1
    i = 2
    initial = get(w, 8)
    while i < get(w, record + 56):
        symbol = get(w, record + 48) + i * 24
        word = read(s, symbol, 8)
        if word >> 32 == 18:
            if get(w, record + 80) != 7 or i + 2 != get(w, record + 56) or strnext + 12 != get(w, record + 72):
                return 4294967295
            if word != 77309411328 + strnext or read(s, symbol + 8, 8) != 0 or read(s, symbol + 16, 8) != 0:
                return 4294967295
            if read(s, symbol + 24, 8) != 77309411335 + strnext or read(s, symbol + 32, 8) != 0 or read(s, symbol + 40, 8) != 0:
                return 4294967295
            name = get(w, record + 64) + strnext
            if read(s, name, 7) != 109330211561827 or read(s, name + 7, 5) != 1701147238:
                return 4294967295
            put(w, record + 40, i, 8)
            put(w, 24, 1, 8)
            strnext = strnext + 12
            i = i + 2
        else:
            extent = add_symbol(s, w, record, symbol, strnext)
            if extent >= 4294967294:
                return extent
            strnext = strnext + extent
            i = i + 1
    if strnext != get(w, record + 72) or get(w, 8) == initial:
        return 4294967295
    return 0

def add_symbol(s:readbuf, w:mutbuf, record:u64, symbol:u64, strnext:u64) -> u64:
    if read(s, symbol, 8) != 281552286121984 + strnext or strnext >= get(w, record + 72):
        return 4294967295
    value = read(s, symbol + 8, 8)
    extent = read(s, symbol + 16, 8)
    if value >= get(w, record + 8) or extent == 0 or extent > get(w, record + 8) - value:
        return 4294967295
    name = get(w, record + 64) + strnext
    namelen = name_size(s, name, get(w, record + 72) - strnext)
    if namelen == 0 or forbidden(s, name, namelen) != 0:
        return 4294967295
    if get(w, record + 80) == 6:
        if namelen != 2 or read(s, name, 2) != 12390 or value != 0:
            return 4294967295
    if get(w, 8) >= 128:
        return 4294967294
    j = 0
    while j < get(w, 8):
        previous = 4096 + j * 48
        if get(w, previous + 8) == namelen:
            if equal(s, name, get(w, previous), namelen) == 1:
                return 4294967295
        j = j + 1
    target = 4096 + get(w, 8) * 48
    put(w, target, name, 8)
    put(w, target + 8, namelen, 8)
    put(w, target + 16, (record - 1024) >> 7, 8)
    put(w, target + 24, value, 8)
    put(w, target + 32, extent, 8)
    put(w, target + 40, get(w, 16), 8)
    put(w, 8, get(w, 8) + 1, 8)
    put(w, 16, get(w, 16) + namelen + 1, 8)
    return namelen + 1

def relocations(s:readbuf, w:mutbuf, record:u64) -> u64:
    if get(w, record + 24) != 0 and get(w, record + 40) == 0:
        return 4294967295
    i = 0
    previous = 0
    while i < get(w, record + 24):
        at = get(w, record + 16) + i * 24
        offset = read(s, at, 8)
        info = read(s, at + 8, 8)
        if offset < 1 or offset > get(w, record + 8) or get(w, record + 8) - offset < 4 or (i != 0 and offset < previous + 4):
            return 4294967295
        if byte(s, get(w, record) + 64 + offset - 1) != 232 or read(s, get(w, record) + 64 + offset, 4) != 0:
            return 4294967295
        if (info & 4294967295) != 4 or (info >> 32) < get(w, record + 40) or (info >> 32) > get(w, record + 40) + 1:
            return 4294967295
        if read(s, at + 16, 8) != 18446744073709551612:
            return 4294967295
        previous = offset
        i = i + 1
    return 0

def layout(w:mutbuf) -> u64:
    imported = get(w, 24)
    put(w, 48, get(w, 32), 8)
    hash = get(w, 32) + imported * 32
    count = 1 + get(w, 8) + imported * 2
    symbols = (hash + 12 + count * 4 + 7) & 18446744073709551608
    strings = symbols + count * 24
    strbytes = get(w, 16) + imported * 22
    relocs = (strings + strbytes + 7) & 18446744073709551608
    writable = (relocs + imported * 48 + 4095) & 18446744073709547520
    dynamic = writable + 16
    names = writable + 4096
    headers = (names + OUT_NAMES_BYTES + 7) & 18446744073709551608
    size = headers + 11 * 64
    put(w, 40, size, 8)
    put(w, 56, hash, 8)
    put(w, 64, symbols, 8)
    put(w, 72, strings, 8)
    put(w, 80, relocs, 8)
    put(w, 88, writable, 8)
    put(w, 96, dynamic, 8)
    put(w, 104, names, 8)
    put(w, 112, headers, 8)
    put(w, 120, strbytes, 8)
    return size

def headers(o:mutbuf, w:mutbuf) -> u64:
    put(o, 0, 282584257676671, 8)
    put(o, 16, 4299030531, 8)
    put(o, 32, 64, 8)
    put(o, 40, get(w, 112), 8)
    put(o, 52, 64, 2)
    put(o, 54, 56, 2)
    put(o, 56, 5, 2)
    put(o, 58, 64, 2)
    put(o, 60, 11, 2)
    put(o, 62, 9, 2)
    ph(o, 64, 1, 5, 0, get(w, 88), 4096)
    ph(o, 120, 1, 6, get(w, 88), 4096, 4096)
    ph(o, 176, 2, 6, get(w, 96), 224, 8)
    ph(o, 232, 1685382482, 4, get(w, 88), 4096, 1)
    ph(o, 288, 1685382481, 6, 0, 0, 16)
    at = get(w, 112)
    sh(o, at + 64, TEXT_NAME, 1, 6, 352, get(w, 32) - 352, 0, 0, 16, 0)
    sh(o, at + 128, PLT_NAME, 1, 6, get(w, 48), get(w, 24) * 32, 0, 0, 16, 16)
    sh(o, at + 192, HASH_NAME, 5, 2, get(w, 56), 12 + (1 + get(w, 8) + get(w, 24) * 2) * 4, 4, 0, 8, 4)
    sh(o, at + 256, SYM_NAME, 11, 2, get(w, 64), (1 + get(w, 8) + get(w, 24) * 2) * 24, 5, 1, 8, 24)
    sh(o, at + 320, STR_NAME, 3, 2, get(w, 72), get(w, 120), 0, 0, 1, 0)
    sh(o, at + 384, REL_NAME, 4, 2, get(w, 80), get(w, 24) * 48, 4, 0, 8, 24)
    sh(o, at + 448, GOT_NAME, 1, 3, get(w, 88), 16, 0, 0, 8, 8)
    sh(o, at + 512, DYN_NAME, 6, 3, get(w, 96), 224, 5, 0, 8, 16)
    sh(o, at + 576, SHSTR_NAME, 3, 0, get(w, 104), OUT_NAMES_BYTES, 0, 0, 1, 0)
    sh(o, at + 640, STACK_NAME, 1, 0, get(w, 104) + OUT_NAMES_BYTES, 0, 0, 0, 1, 0)
    OUT_NAMES_EMIT
    return 0

def payload(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    i = 0
    while i < get(w, 0):
        row = 1024 + i * 128
        copy(s, get(w, row) + 64, o, get(w, row + 32), get(w, row + 8))
        j = 0
        while j < get(w, row + 24):
            relocation = get(w, row + 16) + j * 24
            offset = read(s, relocation, 8)
            which = (read(s, relocation + 8, 8) >> 32) - get(w, row + 40)
            target = get(w, 48) + which * 16
            position = get(w, row + 32) + offset
            put(o, position, target - position - 4, 4)
            j = j + 1
        i = i + 1
    if get(w, 24) != 0:
        i = 0
        while i < 2:
            at = get(w, 48) + i * 16
            put(o, at, 9727, 2)
            put(o, at + 2, get(w, 88) + i * 8 - at - 6, 4)
            put(o, at + 6, 14757395258967641292, 8)
            put(o, at + 14, 52428, 2)
            i = i + 1
    return 0

def tables(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    count = 1 + get(w, 8) + get(w, 24) * 2
    hash = get(w, 56)
    put(o, hash, 1, 4)
    put(o, hash + 4, count, 4)
    put(o, hash + 8, 1, 4)
    i = 1
    while i + 1 < count:
        put(o, hash + 12 + i * 4, i + 1, 4)
        i = i + 1
    i = 0
    while i < get(w, 8):
        row = 4096 + i * 48
        at = get(w, 64) + (i + 1) * 24
        put(o, at, 281552286121984 + get(w, row + 40), 8)
        put(o, at + 8, get(w, 1024 + get(w, row + 16) * 128 + 32) + get(w, row + 24), 8)
        put(o, at + 16, get(w, row + 32), 8)
        copy(s, get(w, row), o, get(w, 72) + get(w, row + 40), get(w, row + 8))
        i = i + 1
    if get(w, 24) != 0:
        at = get(w, 72) + get(w, 16)
        put(o, at, 109330211561827, 7)
        put(o, at + 7, 1701147238, 5)
        put(o, at + 12, 3346019691232651628, 8)
        put(o, at + 20, 54, 2)
        at = get(w, 64) + (get(w, 8) + 1) * 24
        put(o, at, 77309411328 + get(w, 16), 8)
        put(o, at + 24, 77309411335 + get(w, 16), 8)
        i = 0
        while i < 2:
            at = get(w, 80) + i * 24
            put(o, at, get(w, 88) + i * 8, 8)
            put(o, at + 8, ((get(w, 8) + 1 + i) << 32) | 6, 8)
            i = i + 1
    at = get(w, 96)
    dynamic(o, at, 4, get(w, 56))
    dynamic(o, at + 16, 5, get(w, 72))
    dynamic(o, at + 32, 6, get(w, 64))
    dynamic(o, at + 48, 10, get(w, 120))
    dynamic(o, at + 64, 11, 24)
    dynamic(o, at + 80, 30, 8)
    dynamic(o, at + 96, 1879048187, 1)
    if get(w, 24) != 0:
        dynamic(o, at + 112, 1, get(w, 16) + 12)
        dynamic(o, at + 128, 7, get(w, 80))
        dynamic(o, at + 144, 8, 48)
        dynamic(o, at + 160, 9, 24)
    return 0

def div24(value:u64) -> u64:
    return ((value >> 3) * 2863311531) >> 33

def read(s:readbuf, at:u64, count:u64) -> u64:
    result = 0
    i = 0
    while i < count:
        result = result | (byte(s, at + i) << (i * 8))
        i = i + 1
    return result

def get(w:mutbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(w, at + i) << (i * 8))
        i = i + 1
    return result

def put(o:mutbuf, at:u64, value:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, at + i, value & 255)
        value = value >> 8
        i = i + 1
    return 0

def zero(o:mutbuf, at:u64, count:u64) -> u64:
    fill_range(o, at, count, 0)
    return 0

def copy(s:readbuf, begin:u64, o:mutbuf, at:u64, count:u64) -> u64:
    i = 0
    while i < count:
        store(o, at + i, byte(s, begin + i))
        i = i + 1
    return 0

def equal(s:readbuf, a:u64, b:u64, count:u64) -> u64:
    i = 0
    while i < count:
        if byte(s, a + i) != byte(s, b + i):
            return 0
        i = i + 1
    return 1

def name_size(s:readbuf, at:u64, limit:u64) -> u64:
    i = 0
    while i < limit and i <= 128:
        c = byte(s, at + i)
        if c == 0:
            return i
        if (c < 65 or c > 90) and (c < 97 or c > 122) and c != 95 and (i == 0 or c < 48 or c > 57):
            return 0
        i = i + 1
    return 0

def section(s:readbuf, at:u64, identity:u64, flags:u64, offset:u64, size:u64, link:u64, align:u64, stride:u64) -> u64:
    if read(s, at, 8) != identity or read(s, at + 8, 8) != flags or read(s, at + 16, 8) != 0:
        return 0
    if read(s, at + 24, 8) != offset or read(s, at + 32, 8) != size or read(s, at + 40, 8) != link:
        return 0
    if read(s, at + 48, 8) != align or read(s, at + 56, 8) != stride:
        return 0
    return 1

def ph(o:mutbuf, at:u64, kind:u64, flags:u64, offset:u64, size:u64, align:u64) -> u64:
    put(o, at, kind | (flags << 32), 8)
    put(o, at + 8, offset, 8)
    put(o, at + 16, offset, 8)
    put(o, at + 24, offset, 8)
    put(o, at + 32, size, 8)
    put(o, at + 40, size, 8)
    put(o, at + 48, align, 8)
    return 0

def sh(o:mutbuf, at:u64, name:u64, kind:u64, flags:u64, offset:u64, size:u64, link:u64, info:u64, align:u64, stride:u64) -> u64:
    put(o, at, name | (kind << 32), 8)
    put(o, at + 8, flags, 8)
    if (flags & 2) != 0:
        put(o, at + 16, offset, 8)
    put(o, at + 24, offset, 8)
    put(o, at + 32, size, 8)
    put(o, at + 40, link | (info << 32), 8)
    put(o, at + 48, align, 8)
    put(o, at + 56, stride, 8)
    return 0

def dynamic(o:mutbuf, at:u64, tag:u64, value:u64) -> u64:
    put(o, at, tag, 8)
    put(o, at + 8, value, 8)
    return 0
'''


def source_program():
    source = AUTHORING.replace('MAGIC', str(MAGIC))
    output_names = b'\0.text\0.plt\0.hash\0.dynsym\0.dynstr\0.rela.dyn\0.got\0.dynamic\0.shstrtab\0.note.GNU-stack\0'
    source = source.replace('OUT_NAMES_BYTES', str(len(output_names)))
    for token, name in sorted([('TEXT_NAME', b'.text'), ('PLT_NAME', b'.plt'), ('HASH_NAME', b'.hash'),
                        ('SYM_NAME', b'.dynsym'), ('STR_NAME', b'.dynstr'), ('REL_NAME', b'.rela.dyn'),
                        ('GOT_NAME', b'.got'), ('DYN_NAME', b'.dynamic'), ('SHSTR_NAME', b'.shstrtab'),
                        ('STACK_NAME', b'.note.GNU-stack')], key=lambda item: -len(item[0])):
        source = source.replace(token, str(output_names.index(name)))
    emit = []
    for i in range(0, len(output_names), 8):
        chunk = output_names[i:i + 8]
        emit.append(f'put(o, get(w, 104) + {i}, {int.from_bytes(chunk, "little")}, {len(chunk)})')
    source = source.replace('OUT_NAMES_EMIT', '\n    '.join(emit))
    source += '\ndef names_ok(s:readbuf, at:u64, count:u64) -> u64:\n'
    expected = b'\0.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0.rela.text\0'
    for i in range(0, 48, 8):
        source += f'    if read(s, at + {i}, 8) != {int.from_bytes(expected[i:i+8], "little")}:\n        return 0\n'
    source += '    if byte(s, at + 48) != 0:\n        return 0\n    if count == 60:\n'
    for i, amount in [(49, 8), (57, 3)]:
        source += f'        if read(s, at + {i}, {amount}) != {int.from_bytes(expected[i:i+amount], "little")}:\n            return 0\n'
    source += '    return 1\n\ndef forbidden(s:readbuf, at:u64, count:u64) -> u64:\n'
    for name in (b'abort', b'calloc', b'malloc', b'free', b'memset', b'memcpy', b'memmove', b'_init', b'_fini',
                 b'__gmon_start__', b'__cxa_finalize', b'__dso_handle', b'_ITM_registerTMCloneTable', b'_ITM_deregisterTMCloneTable'):
        checks = [f'count == {len(name)}']
        checks += [f'read(s, at + {i}, {len(name[i:i+8])}) == {int.from_bytes(name[i:i+8], "little")}' for i in range(0, len(name), 8)]
        source += '    if ' + ' and '.join(checks) + ':\n        return 1\n'
    return source + '    return 0\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'elf_linker', 'functions': functions})


def main():
    SOURCE.write_text(render_assembly(document()))
    print(SOURCE.name, SOURCE.stat().st_size)


if __name__ == '__main__':
    main()
