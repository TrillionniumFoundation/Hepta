"""Generate the independent HIA ELF header, section and segment reader."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_safe_core_elf_inventory_native import (
    CAPACITY, MAX_ELF, MAX_SECTIONS, MAX_SEGMENTS, MAX_SYMBOLS, REFUSAL_IDS,
)
from tools.generate_hia_elf_linker import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = 'examples/hia_bootstrap/safe_core_elf_inventory.hepta'
FIELDS = {'CAPACITY': CAPACITY, 'MAX_ELF': MAX_ELF, 'MAX_SECTIONS': MAX_SECTIONS,
          'MAX_SEGMENTS': MAX_SEGMENTS, 'MAX_SYMBOLS': MAX_SYMBOLS, 'ELF_IDENT': int.from_bytes(b'\x7fELF\x02\x01\x01\0', 'little')}
FIELDS.update({'E_' + name.upper(): number for name, number in REFUSAL_IDS.items()})
HELPER_NAME = b'__hia_native_fn_0\0'
FIELDS.update(HELPER_HEAD=int.from_bytes(HELPER_NAME[:8], 'little'),
              HELPER_BODY=int.from_bytes(HELPER_NAME[8:16], 'little'),
              HELPER_TAIL=int.from_bytes(HELPER_NAME[16:], 'little'))

SOURCE = r'''
def inventory(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < CAPACITY:
        return 4294967294
    size = length(s)
    if size < 64 or size > MAX_ELF:
        return terminal(o, E_EXTENT, 0, 0)
    if length(w) == 16 and get(w, 8) == 0:
        return symbol_table(s, o, get(w, 0))
    if length(w) == 24:
        return string_response(s, o, get(w, 0), get(w, 8), get(w, 16))
    if length(w) == 32:
        return load_binding(s, o, get(w, 0), get(w, 8), get(w, 16), get(w, 24))
    if length(w) == 40:
        return dynamic_tags(s, o, w)
    if length(w) == 48 and get(w, 40) == 0:
        return verify_plt_slot(s, o, w)
    if length(w) >= 64:
        if get(w, 0) == 2:
            return object_relocations(s, o, w)
        return loader_hash(s, o, w)
    if length(w) != 8:
        return 4294967293
    kind = get(w, 0)
    if word(s, 0, 8) != ELF_IDENT or word(s, 8, 8) != 0 or word(s, 16, 2) != kind:
        return terminal(o, E_IDENTITY, 0, 0)
    if word(s, 18, 2) != 62 or word(s, 20, 4) != 1 or word(s, 24, 8) != 0 or word(s, 48, 4) != 0:
        return terminal(o, E_IDENTITY, 0, 0)
    if word(s, 52, 2) != 64 or word(s, 58, 2) != 64:
        return terminal(o, E_IDENTITY, 0, 0)
    count = word(s, 60, 2)
    names = word(s, 62, 2)
    if count == 0 or count > MAX_SECTIONS or names == 0 or names >= count:
        return terminal(o, E_SECTIONS, 0, 0)
    shoff = word(s, 40, 8)
    if in_file(size, shoff, count * 64) == 0:
        return terminal(o, E_RANGE, 0, 0)
    names_row = shoff + names * 64
    if word(s, names_row + 4, 4) != 3:
        return terminal(o, E_MISSING_NAMES, 0, 0)
    error = sections(s, o, shoff, count, word(s, names_row + 24, 8), word(s, names_row + 32, 8))
    if error != 0:
        return terminal(o, error, 0, 0)
    phoff = word(s, 32, 8)
    phsize = word(s, 54, 2)
    phnum = word(s, 56, 2)
    if kind != 3:
        if phoff != 0 or phsize != 0 or phnum != 0:
            return terminal(o, E_OBJECT_SEGMENTS, 0, 0)
        return terminal(o, 0, count, 0)
    if phsize != 56 or phnum == 0 or phnum > MAX_SEGMENTS:
        return terminal(o, E_SEGMENTS, 0, 0)
    segment_base = 24 + count * 96
    error = segments(s, o, phoff, phnum, segment_base)
    if error != 0:
        return terminal(o, error, 0, 0)
    error = review_loads(o, phnum, segment_base)
    if error != 0:
        return terminal(o, error, 0, 0)
    return terminal(o, 0, count, phnum)

def terminal(o:mutbuf, error:u64, sections:u64, segments:u64) -> u64:
    return reply(o, error, sections, segments, 24 + sections * 96 + segments * 56)

def reply(o:mutbuf, error:u64, first:u64, second:u64, extent:u64) -> u64:
    put(o, 0, error)
    put(o, 8, first)
    put(o, 16, second)
    return extent

def word(s:readbuf, offset:u64, size:u64) -> u64:
    value = 0
    index = 0
    while index < size:
        value = value | (byte(s, offset + index) << (index * 8))
        index = index + 1
    return value

def get(w:mutbuf, offset:u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | (byte(w, offset + index) << (index * 8))
        index = index + 1
    return value

def put(w:mutbuf, offset:u64, value:u64) -> u64:
    index = 0
    while index < 8:
        store(w, offset + index, (value >> (index * 8)) & 255)
        index = index + 1
    return 0

def in_file(size:u64, offset:u64, count:u64) -> u64:
    if offset > size:
        return 0
    return choose(count <= size - offset, 1, 0)

def name_length(s:readbuf, offset:u64, extent:u64) -> u64:
    count = 0
    while count <= 256 and count < extent:
        if byte(s, offset + count) == 0:
            return count
        count = count + 1
    return 257

def ascii_name(s:readbuf, offset:u64, count:u64) -> u64:
    index = 0
    while index < count:
        if byte(s, offset + index) > 127:
            return 0
        index = index + 1
    return 1

def same_name(s:readbuf, left:u64, right:u64, count:u64) -> u64:
    index = 0
    while index < count:
        if byte(s, left + index) != byte(s, right + index):
            return 0
        index = index + 1
    return 1

def unique_name(s:readbuf, o:mutbuf, index:u64, offset:u64, count:u64) -> u64:
    previous = 0
    while previous < index:
        row = 24 + previous * 96
        if get(o, row + 16) == count and same_name(s, get(o, row + 8), offset, count) != 0:
            return 0
        previous = previous + 1
    return 1

def sections(s:readbuf, o:mutbuf, start:u64, count:u64, names_at:u64, names_size:u64) -> u64:
    index = 0
    while index < count:
        row = start + index * 64
        offset = word(s, row, 4)
        if offset >= names_size:
            return E_NAME_INDEX
        if in_file(length(s), names_at, names_size) == 0:
            return E_RANGE
        name_at = names_at + offset
        extent = name_length(s, name_at, names_size - offset)
        if extent > 256:
            return E_NAME_LENGTH
        if ascii_name(s, name_at, extent) == 0:
            return E_NAME_ASCII
        if unique_name(s, o, index, name_at, extent) == 0:
            return E_DUPLICATE
        kind = word(s, row + 4, 4)
        contents = word(s, row + 24, 8)
        size = word(s, row + 32, 8)
        if kind == 8 or size > MAX_ELF:
            return E_SECTION_EXTENT
        if in_file(length(s), contents, size) == 0:
            return E_RANGE
        result = 24 + index * 96
        put(o, result, index)
        put(o, result + 8, name_at)
        put(o, result + 16, extent)
        put(o, result + 24, kind)
        put(o, result + 32, word(s, row + 8, 8))
        put(o, result + 40, word(s, row + 16, 8))
        put(o, result + 48, contents)
        put(o, result + 56, size)
        put(o, result + 64, word(s, row + 40, 4))
        put(o, result + 72, word(s, row + 44, 4))
        put(o, result + 80, word(s, row + 48, 8))
        put(o, result + 88, word(s, row + 56, 8))
        index = index + 1
    return 0

def segments(s:readbuf, o:mutbuf, start:u64, count:u64, base:u64) -> u64:
    index = 0
    while index < count:
        relative = index * 56
        if in_file(length(s), start, relative + 56) == 0:
            return E_RANGE
        row = start + relative
        kind = word(s, row, 4)
        flags = word(s, row + 4, 4)
        offset = word(s, row + 8, 8)
        addr = word(s, row + 16, 8)
        paddr = word(s, row + 24, 8)
        filesz = word(s, row + 32, 8)
        memsz = word(s, row + 40, 8)
        align = word(s, row + 48, 8)
        if filesz > memsz or addr + memsz < addr:
            return E_SEGMENT_EXTENT
        if (kind != 1 and kind != 2 and kind != 0x6474e551 and kind != 0x6474e552) or paddr != addr:
            return E_SEGMENT_AUTHORITY
        if kind == 1 and (align != 4096 or (offset & 4095) != (addr & 4095) or filesz != memsz):
            return E_LOAD_EXTENT
        if in_file(length(s), offset, filesz) == 0:
            return E_RANGE
        result = base + relative
        put(o, result, kind)
        put(o, result + 8, flags)
        put(o, result + 16, offset)
        put(o, result + 24, addr)
        put(o, result + 32, filesz)
        put(o, result + 40, memsz)
        put(o, result + 48, align)
        index = index + 1
    return 0

def review_loads(o:mutbuf, count:u64, base:u64) -> u64:
    index = 0
    previous = 0
    last_end = 0
    overlap = 0
    while index < count:
        row = base + index * 56
        if get(o, row) == 1:
            addr = get(o, row + 24)
            if addr < previous:
                return E_LOAD_ORDER
            previous = addr
            size = get(o, row + 40)
            if size != 0:
                if (addr >> 12) < last_end:
                    overlap = 1
                last_end = ((addr + size - 1) >> 12) + 1
        index = index + 1
    return choose(overlap != 0, E_LOAD_OVERLAP, 0)


def string_response(s:readbuf, o:mutbuf, offset:u64, size:u64, index:u64) -> u64:
    if index >= size:
        return terminal(o, E_NAME_INDEX, 0, 0)
    if in_file(length(s), offset, size) == 0:
        return terminal(o, E_RANGE, 0, 0)
    start = offset + index
    count = name_length(s, start, size - index)
    if count > 256:
        return terminal(o, E_NAME_LENGTH, 0, 0)
    if ascii_name(s, start, count) == 0:
        return terminal(o, E_NAME_ASCII, 0, 0)
    return reply(o, 0, start, count, 24)

def symbol_table(s:readbuf, o:mutbuf, index:u64) -> u64:
    shoff = word(s, 40, 8)
    count = word(s, 60, 2)
    if count == 0 or count > MAX_SECTIONS or index >= count:
        return terminal(o, E_SYMBOL_TABLE, 0, 0)
    if in_file(length(s), shoff, count * 64) == 0:
        return terminal(o, E_RANGE, 0, 0)
    row = shoff + index * 64
    kind = word(s, row + 4, 4)
    size = word(s, row + 32, 8)
    if (kind != 2 and kind != 11) or word(s, row + 56, 8) != 24 or size > 24 * MAX_SYMBOLS or size % 24 != 0:
        return terminal(o, E_SYMBOL_TABLE, 0, 0)
    link = word(s, row + 40, 4)
    if link >= count:
        return terminal(o, E_SYMBOL_LINK, 0, 0)
    names = shoff + link * 64
    if word(s, names + 4, 4) != 3:
        return terminal(o, E_SYMBOL_NAMES, 0, 0)
    start = word(s, row + 24, 8)
    if in_file(length(s), start, size) == 0:
        return terminal(o, E_RANGE, 0, 0)
    return symbol_rows(s, o, start, size // 24, word(s, names + 24, 8), word(s, names + 32, 8))

def symbol_rows(s:readbuf, o:mutbuf, start:u64, count:u64, names_at:u64, names_size:u64) -> u64:
    index = 0
    while index < count:
        row = start + index * 24
        name_index = word(s, row, 4)
        if name_index >= names_size:
            return terminal(o, E_NAME_INDEX, 0, 0)
        if in_file(length(s), names_at, names_size) == 0:
            return terminal(o, E_RANGE, 0, 0)
        at = names_at + name_index
        extent = name_length(s, at, names_size - name_index)
        if extent > 256:
            return terminal(o, E_NAME_LENGTH, 0, 0)
        if ascii_name(s, at, extent) == 0:
            return terminal(o, E_NAME_ASCII, 0, 0)
        result = 24 + index * 56
        put(o, result, at)
        put(o, result + 8, extent)
        put(o, result + 16, word(s, row + 4, 1))
        put(o, result + 24, word(s, row + 5, 1))
        put(o, result + 32, word(s, row + 6, 2))
        put(o, result + 40, word(s, row + 8, 8))
        put(o, result + 48, word(s, row + 16, 8))
        index = index + 1
    return reply(o, 0, count, 0, 24 + count * 56)

def load_binding(s:readbuf, o:mutbuf, section_addr:u64, section_size:u64, section_offset:u64, permissions:u64) -> u64:
    phoff = word(s, 32, 8)
    phnum = word(s, 56, 2)
    if phnum > MAX_SEGMENTS or in_file(length(s), phoff, phnum * 56) == 0:
        return terminal(o, E_RANGE, 0, 0)
    selected = 0
    matches = 0
    index = 0
    while index < phnum:
        row = phoff + index * 56
        if word(s, row, 4) == 1:
            addr = word(s, row + 16, 8)
            extent = word(s, row + 32, 8)
            if section_addr >= addr and section_size <= extent:
                if section_addr - addr <= extent - section_size:
                    selected = row
                    matches = matches + 1
        index = index + 1
    if matches != 1:
        return terminal(o, E_MISSING_LOAD, 0, 0)
    offset = word(s, selected + 8, 8)
    addr = word(s, selected + 16, 8)
    flags = word(s, selected + 4, 4)
    if flags != permissions or section_offset < offset or section_offset - offset != section_addr - addr:
        return terminal(o, E_LOAD_BINDING, 0, 0)
    put(o, 24, 1)
    put(o, 32, flags)
    put(o, 40, offset)
    put(o, 48, addr)
    put(o, 56, word(s, selected + 32, 8))
    put(o, 64, word(s, selected + 40, 8))
    put(o, 72, word(s, selected + 48, 8))
    return reply(o, 0, 0, 0, 80)

def dynamic_tags(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    start = get(w, 0)
    size = get(w, 8)
    addr = get(w, 16)
    phoff = word(s, 32, 8)
    phnum = word(s, 56, 2)
    if phnum > MAX_SEGMENTS or in_file(length(s), phoff, phnum * 56) == 0:
        return terminal(o, E_RANGE, 0, 0)
    matches = 0
    index = 0
    while index < phnum:
        row = phoff + index * 56
        if word(s, row, 4) == 2:
            if word(s, row + 8, 8) != start or word(s, row + 16, 8) != addr or word(s, row + 32, 8) != size:
                return terminal(o, E_DYNAMIC_AUTHORITY, 0, 0)
            matches = matches + 1
        index = index + 1
    if matches != 1:
        return terminal(o, E_DYNAMIC_AUTHORITY, 0, 0)
    if size % 16 != 0:
        return terminal(o, E_DYNAMIC_EXTENT, 0, 0)
    if in_file(length(s), start, size) == 0:
        return terminal(o, E_RANGE, 0, 0)
    rows = 0
    at = 0
    while at < size:
        tag = word(s, start + at, 8)
        value = word(s, start + at + 8, 8)
        if tag == 0:
            while at < size:
                if word(s, start + at, 8) != 0 or word(s, start + at + 8, 8) != 0:
                    return terminal(o, E_DYNAMIC_TAIL, 0, 0)
                at = at + 16
        else:
            if approved_tag(tag) == 0:
                return terminal(o, E_DYNAMIC_TAG, 0, 0)
            scan = 0
            while scan < rows:
                if get(o, 24 + scan * 16) == tag:
                    return terminal(o, E_DYNAMIC_DUPLICATE, 0, 0)
                scan = scan + 1
            put(o, 24 + rows * 16, tag)
            put(o, 32 + rows * 16, value)
            rows = rows + 1
            at = at + 16
    if tag_equals(o, rows, 3, get(w, 24)) == 0 or tag_equals(o, rows, 2, 24) == 0:
        return terminal(o, E_DYNAMIC_PLT, 0, 0)
    if tag_equals(o, rows, 20, 7) == 0 or tag_equals(o, rows, 23, get(w, 32)) == 0:
        return terminal(o, E_DYNAMIC_PLT, 0, 0)
    if tag_equals(o, rows, 30, 8) == 0 or tag_equals(o, rows, 0x6ffffffb, 1) == 0:
        return terminal(o, E_DYNAMIC_PLT, 0, 0)
    return reply(o, 0, rows, 0, 24 + rows * 16)

def approved_tag(tag:u64) -> u64:
    if tag >= 1 and tag <= 6:
        return 1
    if tag == 10 or tag == 11 or tag == 20 or tag == 23 or tag == 30:
        return 1
    if tag == 0x6ffffef5 or tag == 0x6ffffffb or tag == 0x6ffffffe or tag == 0x6fffffff or tag == 0x6ffffff0:
        return 1
    return 0

def tag_equals(o:mutbuf, rows:u64, tag:u64, value:u64) -> u64:
    index = 0
    while index < rows:
        at = 24 + index * 16
        if get(o, at) == tag:
            return choose(get(o, at + 8) == value, 1, 0)
        index = index + 1
    return 0

def loader_hash(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    name_size = get(w, 48)
    if name_size != length(w) - 64 or name_size > 256 or get(w, 56) != 0:
        return 4294967293
    start = get(w, 8)
    size = get(w, 16)
    if in_file(length(s), start, size) == 0:
        return terminal(o, E_RANGE, 0, 0)
    authorized = choose(get(w, 32) == 1 and get(w, 24) == get(w, 40), 1, 0)
    kind = get(w, 0)
    if kind == 0:
        if authorized == 0 or size < 8:
            return terminal(o, E_SYSV_AUTHORITY, 0, 0)
        return terminal(o, review_sysv(s, start, size, sysv_export(w, name_size)), 0, 0)
    if kind == 1:
        if authorized == 0 or size < 16:
            return terminal(o, E_GNU_AUTHORITY, 0, 0)
        return terminal(o, review_gnu(s, start, size, gnu_export(w, name_size)), 0, 0)
    return 4294967293

def sysv_step(value:u64, letter:u64) -> u64:
    next = (value << 4) + letter
    high = next & 0xf0000000
    return (next ^ (high >> 24)) & 0x0fffffff

def sysv_export(w:mutbuf, size:u64) -> u64:
    value = 0
    index = 0
    while index < size:
        value = sysv_step(value, byte(w, 64 + index))
        index = index + 1
    return value

def sysv_abort() -> u64:
    return sysv_step(sysv_step(sysv_step(sysv_step(sysv_step(0, 97), 98), 111), 114), 116)

def review_sysv(s:readbuf, at:u64, size:u64, export:u64) -> u64:
    buckets = word(s, at, 4)
    chains = word(s, at + 4, 4)
    if buckets == 0 or buckets > 64 or chains != 3 or size != 8 + (buckets + chains) * 4:
        return E_SYSV_SHAPE
    head = at + 8
    next = head + buckets * 4
    if word(s, next, 4) != 0:
        return E_SYSV_INDEX
    index = 0
    while index < buckets + chains:
        if word(s, head + index * 4, 4) >= chains:
            return E_SYSV_INDEX
        index = index + 1
    seen = 0
    bucket = 0
    abort = sysv_abort()
    while bucket < buckets:
        index = word(s, head + bucket * 4, 4)
        while index != 0:
            mask = 1 << index
            hash = choose(index == 1, abort, export)
            if (seen & mask) != 0 or hash % buckets != bucket:
                return E_SYSV_LOOKUP
            seen = seen | mask
            index = word(s, next + index * 4, 4)
        bucket = bucket + 1
    return choose(seen == 6, 0, E_SYSV_MISSING)

def gnu_export(w:mutbuf, size:u64) -> u64:
    value = 5381
    index = 0
    while index < size:
        value = (value * 33 + byte(w, 64 + index)) & 0xffffffff
        index = index + 1
    return value

def review_gnu(s:readbuf, at:u64, size:u64, hash:u64) -> u64:
    buckets = word(s, at, 4)
    first = word(s, at + 4, 4)
    count = word(s, at + 8, 4)
    shift = word(s, at + 12, 4)
    if buckets == 0 or buckets > 64 or first != 2 or shift >= 32:
        return E_GNU_SHAPE
    if count != 1 and count != 2 and count != 4 and count != 8:
        return E_GNU_SHAPE
    if size != 16 + count * 8 + buckets * 4 + 4:
        return E_GNU_SHAPE
    mask = (1 << (hash % 64)) | (1 << ((hash >> shift) % 64))
    index = 0
    while index < count:
        expected = choose(index == (hash // 64) % count, mask, 0)
        if word(s, at + 16 + index * 8, 8) != expected:
            return E_GNU_LOOKUP
        index = index + 1
    start = at + 16 + count * 8
    index = 0
    while index < buckets:
        expected = choose(index == hash % buckets, 2, 0)
        if word(s, start + index * 4, 4) != expected:
            return E_GNU_LOOKUP
        index = index + 1
    return choose(word(s, start + buckets * 4, 4) == (hash | 1), 0, E_GNU_LOOKUP)

def verify_plt_slot(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = get(w, 0)
    addr = get(w, 8)
    got = get(w, 16)
    rela = get(w, 24)
    if in_file(length(s), at, 32) == 0 or in_file(length(s), rela, 24) == 0:
        return terminal(o, E_RANGE, 0, 0)
    slot = word(s, rela, 8)
    info = word(s, rela + 8, 8)
    symbol = info >> 32
    if (info & 0xffffffff) != 7 or symbol >= 32 or word(s, rela + 16, 8) != 0:
        return terminal(o, E_PLT_SLOT, 0, 0)
    if (get(w, 32) & (1 << symbol)) == 0 or slot != got + 24:
        return terminal(o, E_PLT_SLOT, 0, 0)
    if word(s, at, 2) != 0x35ff or word(s, at + 6, 2) != 0x25ff or word(s, at + 12, 4) != 0x00401f0f:
        return terminal(o, E_PLT_TARGET, 0, 0)
    if word(s, at + 16, 2) != 0x25ff or word(s, at + 22, 6) != 0xe90000000068:
        return terminal(o, E_PLT_TARGET, 0, 0)
    if rel32_matches(addr + 6, word(s, at + 2, 4), got + 8) == 0:
        return terminal(o, E_PLT_TARGET, 0, 0)
    if rel32_matches(addr + 12, word(s, at + 8, 4), got + 16) == 0:
        return terminal(o, E_PLT_TARGET, 0, 0)
    if rel32_matches(addr + 22, word(s, at + 18, 4), slot) == 0:
        return terminal(o, E_PLT_TARGET, 0, 0)
    if rel32_matches(addr + 32, word(s, at + 28, 4), addr) == 0:
        return terminal(o, E_PLT_TARGET, 0, 0)
    return terminal(o, 0, 0, 0)

def rel32_matches(base:u64, operand:u64, target:u64) -> u64:
    if operand >= 2147483648:
        return choose(target <= base and base - target == 4294967296 - operand, 1, 0)
    return choose(target >= base and target - base == operand, 1, 0)

def ordinary_call_symbol(s:readbuf, table:u64, symbol:u64) -> u64:
    # Inventories have already verified table/strings bounds and all names.
    secbase = word(s, 40, 8)
    count = word(s, 60, 2)
    if table >= count or in_file(length(s), secbase, count * 64) == 0:
        return 0
    row = secbase + table * 64
    names = word(s, row + 40, 4)
    if names >= count:
        return 0
    at = word(s, row + 24, 8)
    size = word(s, row + 32, 8)
    if symbol >= size // 24 or in_file(length(s), at, size) == 0:
        return 0
    names_row = secbase + names * 64
    start = word(s, names_row + 24, 8)
    span = word(s, names_row + 32, 8)
    index = word(s, at + symbol * 24, 4)
    if index >= span or in_file(length(s), start, span) == 0:
        return 0
    at = start + index
    remaining = span - index
    if remaining >= 6 and word(s, at, 6) == 0x0074726f6261:
        return 1
    if remaining >= 18 and word(s, at, 8) == HELPER_HEAD:
        if word(s, at + 8, 8) == HELPER_BODY and word(s, at + 16, 2) == HELPER_TAIL:
            return 2
    return 3

def object_relocations(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    rela = get(w, 8)
    text = get(w, 16)
    size = get(w, 24)
    addr = get(w, 32)
    table = get(w, 56)
    if size != length(w) - 64 or size > 65536:
        return 4294967293
    if in_file(length(s), text, size) == 0 or in_file(length(s), rela, 48) == 0:
        return terminal(o, E_RANGE, 0, 0)
    columns = 0
    seen = 0
    first = 0
    while columns < 2:
        at = rela + columns * 24
        offset = word(s, at, 8)
        info = word(s, at + 8, 8)
        if size < 4 or offset == 0 or offset > size - 4:
            return terminal(o, E_OBJECT_OPERAND, 0, 0)
        if (info & 0xffffffff) != 4 or word(s, at + 16, 8) != 18446744073709551612:
            return terminal(o, E_OBJECT_OPERAND, 0, 0)
        if word(s, text + offset - 1, 5) != 0xe8:
            return terminal(o, E_OBJECT_OPERAND, 0, 0)
        symbol = ordinary_call_symbol(s, table, info >> 32)
        if symbol == 0:
            return terminal(o, E_OBJECT_OPERAND, 0, 0)
        if symbol == 3 or offset == first:
            return terminal(o, E_OBJECT_CALL, 0, 0)
        target = choose(symbol == 1, get(w, 40), get(w, 48))
        end = addr + offset + 4
        if target < end:
            if end - target > 2147483648:
                return terminal(o, E_OBJECT_DISPLACEMENT, 0, 0)
        else:
            if target - end >= 2147483648:
                return terminal(o, E_OBJECT_DISPLACEMENT, 0, 0)
        out = 24 + columns * 32
        put(o, out, offset)
        put(o, out + 8, symbol)
        put(o, out + 16, target)
        put(o, out + 24, target - end)
        seen = seen | (1 << symbol)
        first = offset
        columns = columns + 1
    if seen != 6:
        return terminal(o, E_OBJECT_TEXT, 0, 0)
    if linked_text_matches(s, o, w, text, size) == 0:
        return terminal(o, E_OBJECT_TEXT, 0, 0)
    return reply(o, 0, 2, 0, 88)

def linked_text_matches(s:readbuf, o:mutbuf, w:mutbuf, text:u64, size:u64) -> u64:
    first = get(o, 24)
    first_value = get(o, 48)
    second = get(o, 56)
    second_value = get(o, 80)
    index = 0
    while index < size:
        expected = byte(s, text + index)
        if index >= first and index - first < 4:
            expected = (first_value >> ((index - first) * 8)) & 255
        if index >= second and index - second < 4:
            expected = (second_value >> ((index - second) * 8)) & 255
        if byte(w, 64 + index) != expected:
            return 0
        index = index + 1
    return 1
'''


def document():
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(FIELDS[node.id]), node) if node.id in FIELDS else node

    nodes = ast.fix_missing_locations(Constants().visit(ast.parse(SOURCE))).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'safe_core_elf_inventory',
                                  'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / SOURCE_PATH
    target.write_text(render_assembly(document()))
