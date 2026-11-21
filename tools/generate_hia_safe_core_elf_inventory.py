"""Generate the independent HIA ELF header, section and segment reader."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_safe_core_elf_inventory_native import (
    AUTHORITY_BYTES, AUTHORITY_MAGIC, CAPACITY, LOADER_AUTHORITIES, SECTION_AUTHORITIES,
    LOOKUP_MAGIC, LOOKUP_REQUIRED, LOOKUP_ROLES, LOOKUP_TYPED, LOOKUP_WORK,
    LOADER_EXECUTABLE_MAGIC, LOADER_EXECUTABLE_WORK,
    FINAL_LOADER_MAGIC, FINAL_LOADER_NAME, FINAL_LOADER_RECEIPT_MAGIC, FINAL_LOADER_WORK,
    DYNAMIC_ORDER_MAGIC, DYNAMIC_RELOCATION_MAGIC, DYNAMIC_SYMBOL_MAGIC, DYNAMIC_SYMBOL_NAME_OFFSET,
    EXECUTABLE_LAYOUT_MAGIC, FUNCTION_SYMBOL_MAGIC, LOADER_SECTION_MAGIC, OBJECT_INVENTORY_MAGIC,
    MAX_ELF, MAX_SECTIONS, MAX_SEGMENTS, MAX_SYMBOLS, REFUSAL_IDS,
    TEXT_GEOMETRY_MAGIC, UNWINDING_MAGIC,
    FUNCTION_LINK_MAGIC, FUNCTION_LINK_RECEIPT_MAGIC, FUNCTION_LINK_BYTES, FUNCTION_LINK_NAME_BYTES,
    FUNCTION_LINK_ROW_BYTES,
    FUNCTION_RECEIPT_MAGIC, FUNCTION_RECEIPT_BYTES, OWNED_FUNCTION_MAGIC,
    FUNCTION_LINK_SOURCE_OFFSET, FUNCTION_LINK_TARGET_OFFSET,
    OWNED_SHARED_MAGIC, OWNED_SHARED_MAX, OWNED_SHARED_REFUSALS,
    OWNED_SHARED_SYMBOL_MAGIC, OWNED_SHARED_SYMBOL_HEAD, OWNED_SHARED_SYMBOL_CAPACITY,
    OWNED_SHARED_SYMBOL_WORK, OWNED_SHARED_EXPECTED_COUNT, OWNED_SHARED_EXPECTED_RECORD, OWNED_SHARED_EXPECTED_WORK,
)
from tools.generate_hia_elf_linker import LinkerBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions

SOURCE_PATH = 'examples/hia_bootstrap/safe_core_elf_inventory.hepta'
FIELDS = {'CAPACITY': CAPACITY, 'MAX_ELF': MAX_ELF, 'MAX_SECTIONS': MAX_SECTIONS,
          'MAX_SEGMENTS': MAX_SEGMENTS, 'MAX_SYMBOLS': MAX_SYMBOLS, 'ELF_IDENT': int.from_bytes(b'\x7fELF\x02\x01\x01\0', 'little')}
FIELDS['FUNCTION_SYMBOL_MAGIC'] = FUNCTION_SYMBOL_MAGIC
FIELDS.update(OWNED_FUNCTION_MAGIC=OWNED_FUNCTION_MAGIC,
              FUNCTION_RECEIPT_MAGIC=FUNCTION_RECEIPT_MAGIC, FUNCTION_RECEIPT_BYTES=FUNCTION_RECEIPT_BYTES,
              OWNED_TEXT_ROLE=SECTION_AUTHORITIES.index('.text'),
              OWNED_SYMBOLS_ROLE=SECTION_AUTHORITIES.index('.symtab'))
FIELDS.update(DYNAMIC_SYMBOL_MAGIC=DYNAMIC_SYMBOL_MAGIC, DYNAMIC_SYMBOL_NAME_OFFSET=DYNAMIC_SYMBOL_NAME_OFFSET,
              ABORT_BYTES=int.from_bytes(b'abort', 'little'))
FIELDS.update(LOADER_SECTION_MAGIC=LOADER_SECTION_MAGIC, EXECUTABLE_LAYOUT_MAGIC=EXECUTABLE_LAYOUT_MAGIC,
              DYNAMIC_RELOCATION_MAGIC=DYNAMIC_RELOCATION_MAGIC)
FIELDS.update(DYNAMIC_ORDER_MAGIC=DYNAMIC_ORDER_MAGIC, OBJECT_INVENTORY_MAGIC=OBJECT_INVENTORY_MAGIC)
FIELDS.update(TEXT_GEOMETRY_MAGIC=TEXT_GEOMETRY_MAGIC, UNWINDING_MAGIC=UNWINDING_MAGIC)
FIELDS.update(AUTHORITY_BYTES=AUTHORITY_BYTES, AUTHORITY_MAGIC=AUTHORITY_MAGIC,
              LOADER_AUTHORITY_COUNT=len(LOADER_AUTHORITIES))
FIELDS.update(LOOKUP_MAGIC=LOOKUP_MAGIC, LOOKUP_ROLES=LOOKUP_ROLES, LOOKUP_WORK=LOOKUP_WORK)
FIELDS.update(LOADER_EXECUTABLE_MAGIC=LOADER_EXECUTABLE_MAGIC, LOADER_EXECUTABLE_WORK=LOADER_EXECUTABLE_WORK,
              ROLE_PLT=SECTION_AUTHORITIES.index('.plt'))
FIELDS.update(FINAL_LOADER_MAGIC=FINAL_LOADER_MAGIC, FINAL_LOADER_NAME=FINAL_LOADER_NAME,
              FINAL_LOADER_RECEIPT_MAGIC=FINAL_LOADER_RECEIPT_MAGIC, FINAL_LOADER_WORK=FINAL_LOADER_WORK)
for section in LOOKUP_REQUIRED:
    label = section.strip('.').replace('.', '_').upper()
    FIELDS['ROLE_' + label] = SECTION_AUTHORITIES.index(section)
    FIELDS['MISSING_' + label] = REFUSAL_IDS['lookup_missing_' + section]
    if section in LOOKUP_TYPED:
        FIELDS['KIND_' + label] = REFUSAL_IDS['lookup_kind_' + section]
FIELDS.update(FUNCTION_LINK_MAGIC=FUNCTION_LINK_MAGIC, FUNCTION_LINK_BYTES=FUNCTION_LINK_BYTES,
              FUNCTION_LINK_RECEIPT_MAGIC=FUNCTION_LINK_RECEIPT_MAGIC,
              FUNCTION_LINK_NAME_BYTES=FUNCTION_LINK_NAME_BYTES, FUNCTION_LINK_ROW_BYTES=FUNCTION_LINK_ROW_BYTES,
              FUNCTION_LINK_SOURCE_OFFSET=FUNCTION_LINK_SOURCE_OFFSET,
              FUNCTION_LINK_TARGET_OFFSET=FUNCTION_LINK_TARGET_OFFSET)
FIELDS.update({'E_' + name.upper(): number for name, number in REFUSAL_IDS.items()
               if not name.startswith('lookup_')})
FIELDS.update({'ABI_' + name.upper(): number for number, (name, _) in enumerate(OWNED_SHARED_REFUSALS, 1)})
FIELDS.update(OWNED_SHARED_MAGIC=OWNED_SHARED_MAGIC, OWNED_SHARED_MAX=OWNED_SHARED_MAX)
FIELDS.update(OWNED_SHARED_SYMBOL_MAGIC=OWNED_SHARED_SYMBOL_MAGIC, OWNED_SHARED_SYMBOL_HEAD=OWNED_SHARED_SYMBOL_HEAD,
              OWNED_SHARED_SYMBOL_CAPACITY=OWNED_SHARED_SYMBOL_CAPACITY, OWNED_SHARED_SYMBOL_WORK=OWNED_SHARED_SYMBOL_WORK)
FIELDS.update(OWNED_SHARED_EXPECTED_COUNT=OWNED_SHARED_EXPECTED_COUNT,
              OWNED_SHARED_EXPECTED_RECORD=OWNED_SHARED_EXPECTED_RECORD,
              OWNED_SHARED_EXPECTED_WORK=OWNED_SHARED_EXPECTED_WORK)
HELPER_NAME = b'__hia_native_fn_0\0'
FIELDS.update(HELPER_HEAD=int.from_bytes(HELPER_NAME[:8], 'little'),
              HELPER_BODY=int.from_bytes(HELPER_NAME[8:16], 'little'),
              HELPER_TAIL=int.from_bytes(HELPER_NAME[16:], 'little'), HELPER_SIZE=len(HELPER_NAME) - 1)
FIELDS.update(LIBC_HEAD=int.from_bytes(b'libc.so.', 'little'),
              VERSION_HEAD=int.from_bytes(b'GLIBC_2.', 'little'),
              VERSION_TAIL=int.from_bytes(b'2.5', 'little'))

SOURCE = r'''
def inventory(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) < CAPACITY:
        return 4294967294
    if length(w) == 8 and get(w, 0) == OWNED_SHARED_MAGIC:
        return owned_shared_layout(s, o)
    if length(w) == 8 and (get(w, 0) == FUNCTION_LINK_MAGIC or get(w, 0) == FUNCTION_LINK_RECEIPT_MAGIC):
        return verify_function_link(s, o, get(w, 0) == FUNCTION_LINK_RECEIPT_MAGIC)
    if (length(w) == OWNED_SHARED_SYMBOL_WORK or length(w) == OWNED_SHARED_EXPECTED_WORK) and get(w, 0) == OWNED_SHARED_SYMBOL_MAGIC:
        if length(o) < OWNED_SHARED_SYMBOL_CAPACITY:
            return 4294967294
        return owned_shared_symbols(s, o, w)
    size = length(s)
    if size < 64 or size > MAX_ELF:
        return terminal(o, E_EXTENT, 0, 0)
    if length(w) == 8 and get(w, 0) == LOADER_SECTION_MAGIC:
        return verify_loader_sections(s, o)
    if length(w) == 16 and get(w, 0) == AUTHORITY_MAGIC:
        return inventory_authorities(s, o, get(w, 8))
    if length(w) == 16 and (get(w, 0) == OWNED_FUNCTION_MAGIC or get(w, 0) == FUNCTION_RECEIPT_MAGIC):
        operation = get(w, 0)
        extra = choose(operation == FUNCTION_RECEIPT_MAGIC, FUNCTION_RECEIPT_BYTES, 0)
        if length(o) < CAPACITY + AUTHORITY_BYTES + extra:
            return 4294967294
        return owned_functions(s, o, get(w, 8), operation)
    if length(w) == LOOKUP_WORK and get(w, 0) == LOOKUP_MAGIC:
        if length(o) < CAPACITY + AUTHORITY_BYTES:
            return 4294967294
        return loader_lookup(s, o, w)
    if length(w) == LOADER_EXECUTABLE_WORK and get(w, 0) == LOADER_EXECUTABLE_MAGIC:
        if length(o) < CAPACITY + AUTHORITY_BYTES:
            return 4294967294
        return loader_executable(s, o, w)
    if length(w) == FINAL_LOADER_WORK and (get(w, 0) == FINAL_LOADER_MAGIC or get(w, 0) == FINAL_LOADER_RECEIPT_MAGIC):
        if length(o) < CAPACITY + AUTHORITY_BYTES:
            return 4294967294
        return final_loader(s, o, w, get(w, 0) == FINAL_LOADER_RECEIPT_MAGIC)
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
    if length(w) == 56 and get(w, 0) == FUNCTION_SYMBOL_MAGIC:
        return exact_functions(s, o, w)
    if length(w) >= 64:
        operation = get(w, 0)
        if operation == UNWINDING_MAGIC and length(w) == 64:
            return verify_bound_text(s, o, w, operation)
        if operation == TEXT_GEOMETRY_MAGIC:
            return verify_bound_text(s, o, w, operation)
        if operation == DYNAMIC_ORDER_MAGIC:
            return verify_dynamic_order(s, o, w)
        if operation == DYNAMIC_SYMBOL_MAGIC and length(w) >= DYNAMIC_SYMBOL_NAME_OFFSET:
            return verify_dynamic_symbols(s, o, w)
        if operation == 2:
            return object_relocations(s, o, w)
        if operation == 3 and length(w) == 88:
            return review_version_tables(s, o, w)
        if operation == 4 and length(w) == 64:
            return review_version_import(s, o, w)
        if operation == 5 and length(w) == 64:
            return verify_relro(s, o, w)
        if length(w) == 72 and (operation == EXECUTABLE_LAYOUT_MAGIC or operation == DYNAMIC_RELOCATION_MAGIC or operation == OBJECT_INVENTORY_MAGIC):
            return review_section_roles(s, o, w)
        return loader_hash(s, o, w)
    if length(w) != 8:
        return 4294967293
    return base_inventory(s, o, get(w, 0))

def base_inventory(s:readbuf, o:mutbuf, kind:u64) -> u64:
    size = length(s)
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

def inventory_authorities(s:readbuf, o:mutbuf, kind:u64) -> u64:
    extent = base_inventory(s, o, kind)
    if get(o, 0) != 0:
        return extent
    if length(o) - extent < AUTHORITY_BYTES:
        return 4294967294
    i = 0
    while i < AUTHORITY_BYTES:
        put(o, extent + i, 0)
        i = i + 8
    index = 0
    count = get(o, 8)
    while index < count:
        row = 24 + index * 96
        role = section_authority(s, get(o, row + 8), get(o, row + 16))
        if role != 0:
            put(o, extent + 8 * (role - 1), index + 1)
        index = index + 1
    return extent + AUTHORITY_BYTES

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

def exact_functions(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, 40) != 0 or get(w, 48) != 0:
        return 4294967293
    return function_extents(s, o, get(w, 8), get(w, 16), get(w, 24), get(w, 32))

def owned_functions(s:readbuf, o:mutbuf, kind:u64, operation:u64) -> u64:
    if kind != 1 and kind != 3:
        return terminal(o, E_IDENTITY, 0, 0)
    extent = inventory_authorities(s, o, kind)
    if get(o, 0) != 0:
        return extent
    roles = extent - AUTHORITY_BYTES
    text = get(o, roles + 8 * OWNED_TEXT_ROLE)
    symbols = get(o, roles + 8 * OWNED_SYMBOLS_ROLE)
    if text == 0:
        return terminal(o, E_OWNED_MISSING_TEXT, 0, 0)
    row = word(s, 40, 8) + (text - 1) * 64
    if word(s, row + 4, 4) != 1:
        return terminal(o, E_OWNED_TEXT_KIND, 0, 0)
    if symbols == 0:
        return terminal(o, E_OWNED_MISSING_SYMBOLS, 0, 0)
    first = word(s, row + 16, 8)
    text_size = word(s, row + 32, 8)
    end = function_extents(s, o, symbols - 1, text - 1, first, text_size)
    if get(o, 0) != 0 or operation != FUNCTION_RECEIPT_MAGIC:
        return end
    return write_function_receipt(s, o, end, first, text_size)

def write_function_receipt(s:readbuf, o:mutbuf, end:u64, first:u64, text_size:u64) -> u64:
    index = 0
    while index < FUNCTION_RECEIPT_BYTES:
        put(o, end + index, 0)
        index = index + 8
    put(o, end, first)
    put(o, end + 8, text_size)
    count = get(o, 8)
    if count <= 2:
        index = 0
        while index < count:
            write_function_link_row(s, o, 24 + index * 56, end + 16 + index * FUNCTION_LINK_ROW_BYTES)
            index = index + 1
    return end + FUNCTION_RECEIPT_BYTES

def write_function_link_row(s:readbuf, o:mutbuf, row:u64, out:u64) -> u64:
    name = get(o, row)
    size = get(o, row + 8)
    put(o, out, size)
    put(o, out + 8, get(o, row + 40))
    put(o, out + 16, get(o, row + 48))
    put(o, out + 24, get(o, row + 16))
    put(o, out + 32, get(o, row + 24))
    index = 0
    while index < size:
        store(o, out + 40 + index, byte(s, name + index))
        index = index + 1
    return 0

def function_extents(s:readbuf, o:mutbuf, table:u64, text:u64, first:u64, length_of_text:u64) -> u64:
    extent = symbol_table(s, o, table)
    if get(o, 0) != 0:
        return extent
    count = get(o, 8)
    selected = 0
    index = 0
    while index < count:
        row = 24 + index * 56
        if (get(o, row + 16) & 15) == 2 and get(o, row + 32) != 0:
            if exact_function_extent(o, row, text, first, length_of_text) == 0 or unique_function(s, o, row, selected) == 0:
                return terminal(o, E_FUNCTION_EXTENT, 0, 0)
            target = 24 + selected * 56
            if target != row:
                copy_symbol_row(o, target, row)
            selected = selected + 1
        index = index + 1
    return reply(o, 0, selected, 0, 24 + selected * 56)

def exact_function_extent(o:mutbuf, row:u64, text:u64, first:u64, extent:u64) -> u64:
    value = get(o, row + 40)
    size = get(o, row + 48)
    if get(o, row + 32) != text or size == 0 or size > extent or value < first:
        return 0
    return choose(value - first <= extent - size, 1, 0)

def verify_dynamic_symbols(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    name_size = get(w, 56)
    if name_size > 256 or name_size != length(w) - DYNAMIC_SYMBOL_NAME_OFFSET:
        return 4294967293
    return dynamic_symbols_with_name(s, o, w, DYNAMIC_SYMBOL_NAME_OFFSET, name_size)

def dynamic_symbols_with_name(s:readbuf, o:mutbuf, w:mutbuf, name_at:u64, name_size:u64) -> u64:
    response = exact_functions(s, o, w)
    if get(o, 0) != 0:
        return response
    if get(o, 8) != 1 or exact_dynamic_export(s, o, w, name_at, name_size) == 0:
        return terminal(o, E_DYNAMIC_EXPORT, 0, 0)
    response = symbol_table(s, o, get(w, 8))
    if get(o, 0) != 0:
        return response
    return exact_abort_import(s, o, response)

def exact_dynamic_export(s:readbuf, o:mutbuf, w:mutbuf, name_at:u64, name_size:u64) -> u64:
    if get(o, 32) != name_size:
        return 0
    field = 0
    while field < 40:
        if get(o, 40 + field) != get(w, 64 + field):
            return 0
        field = field + 8
    return scratch_name_matches(s, w, get(o, 24), name_at, name_size)

def scratch_name_matches(s:readbuf, w:mutbuf, offset_in_elf:u64, offset_in_work:u64, size:u64) -> u64:
    offset = 0
    while offset < size:
        if byte(s, offset_in_elf + offset) != byte(w, offset_in_work + offset):
            return 0
        offset = offset + 1
    return 1

def exact_abort_import(s:readbuf, o:mutbuf, response:u64) -> u64:
    count = get(o, 8)
    found = 0
    mask = 0
    index = 0
    while index < count:
        row = 24 + index * 56
        name_size = get(o, row + 8)
        is_abort = 0
        if name_size == 5:
            is_abort = choose(word(s, get(o, row), 5) == ABORT_BYTES, 1, 0)
        if is_abort != 0:
            mask = mask | (1 << index)
        if name_size != 0 and get(o, row + 32) == 0:
            if is_abort == 0 or found != 0:
                return terminal(o, E_DYNAMIC_IMPORT, 0, 0)
            found = 1
        index = index + 1
    if found == 0:
        return terminal(o, E_DYNAMIC_IMPORT, 0, 0)
    return reply(o, 0, count, mask, response)

def verify_dynamic_order(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    count = get(w, 16)
    if count != length(w) - 64:
        return terminal(o, E_DYNAMIC_ORDER, 0, 0)
    return exact_dynamic_order(s, o, w, get(w, 8), count)

def exact_dynamic_order(s:readbuf, o:mutbuf, w:mutbuf, table:u64, count:u64) -> u64:
    if count > 256:
        return terminal(o, E_DYNAMIC_ORDER, 0, 0)
    result = symbol_table(s, o, table)
    if get(o, 0) != 0:
        return result
    if get(o, 8) != 3 or get(o, 32) != 0 or empty_symbol_attributes(o, 24, 0) == 0:
        return terminal(o, E_DYNAMIC_ORDER, 0, 0)
    if get(o, 88) != 5 or word(s, get(o, 80), 5) != ABORT_BYTES or empty_symbol_attributes(o, 80, 18) == 0:
        return terminal(o, E_DYNAMIC_ORDER, 0, 0)
    if get(o, 144) != count:
        return terminal(o, E_DYNAMIC_ORDER, 0, 0)
    name = get(o, 136)
    index = 0
    while index < count:
        if byte(s, name + index) != byte(w, 64 + index):
            return terminal(o, E_DYNAMIC_ORDER, 0, 0)
        index = index + 1
    return reply(o, 0, 0, 0, 24)

def empty_symbol_attributes(o:mutbuf, row:u64, info:u64) -> u64:
    if get(o, row + 16) != info or get(o, row + 24) != 0 or get(o, row + 32) != 0:
        return 0
    return choose(get(o, row + 40) == 0 and get(o, row + 48) == 0, 1, 0)

def unique_function(s:readbuf, o:mutbuf, row:u64, selected:u64) -> u64:
    offset = get(o, row)
    size = get(o, row + 8)
    ordinal = 0
    while ordinal < selected:
        prior = 24 + ordinal * 56
        if get(o, prior + 8) == size and same_name(s, get(o, prior), offset, size) != 0:
            return 0
        ordinal = ordinal + 1
    return 1

def copy_symbol_row(o:mutbuf, target:u64, source:u64) -> u64:
    byte_index = 0
    while byte_index < 56:
        store(o, target + byte_index, byte(o, source + byte_index))
        byte_index = byte_index + 1
    return 0

def verify_function_link(s:readbuf, o:mutbuf, receipt:bool) -> u64:
    if length(s) != FUNCTION_LINK_BYTES:
        return 4294967293
    if word(s, 40, 8) != 0 or word(s, 48, 8) != 0 or word(s, 56, 8) != 0:
        return 4294967293
    count = word(s, 16, 8)
    export_size = word(s, 32, 8)
    if count == 0 or count > 2 or word(s, 24, 8) != count or export_size > FUNCTION_LINK_NAME_BYTES:
        return terminal(o, E_FUNCTION_INVENTORY, 0, 0)
    source = function_export_slot(s, FUNCTION_LINK_SOURCE_OFFSET, count, export_size)
    target = function_export_slot(s, FUNCTION_LINK_TARGET_OFFSET, count, export_size)
    if source == 0 or target == 0:
        return terminal(o, E_FUNCTION_INVENTORY, 0, 0)
    if exact_function_partition(s, count, word(s, 8, 8)) == 0:
        return terminal(o, E_FUNCTION_PARTITION, 0, 0)
    entry_before = FUNCTION_LINK_SOURCE_OFFSET + (source - 1) * FUNCTION_LINK_ROW_BYTES
    entry_after = FUNCTION_LINK_TARGET_OFFSET + (target - 1) * FUNCTION_LINK_ROW_BYTES
    if same_function_geometry(s, entry_before, entry_after, word(s, 0, 8)) == 0:
        return terminal(o, E_FUNCTION_LINK, 0, 0)
    helper = 0
    if count == 2:
        helper_before = FUNCTION_LINK_SOURCE_OFFSET + (2 - source) * FUNCTION_LINK_ROW_BYTES
        helper_after = FUNCTION_LINK_TARGET_OFFSET + (2 - target) * FUNCTION_LINK_ROW_BYTES
        if same_function_geometry(s, helper_before, helper_after, word(s, 0, 8)) == 0:
            return terminal(o, E_FUNCTION_LINK, 0, 0)
        helper = word(s, helper_after + 8, 8)
    if receipt:
        put(o, 24, word(s, entry_before + 8, 8))
        put(o, 32, word(s, entry_after + 8, 8))
        put(o, 40, helper)
        return reply(o, 0, choose(count == 1, 1, 0), 0, 48)
    return reply(o, 0, choose(count == 1, 1, 0), 0, 24)

def function_export_slot(s:readbuf, start:u64, count:u64, export_size:u64) -> u64:
    first = function_binding_role(s, start, export_size)
    if count == 1:
        return choose(first == 1, 1, 0)
    other = function_binding_role(s, start + FUNCTION_LINK_ROW_BYTES, export_size)
    if first == 1 and other == 2:
        return 1
    if first == 2 and other == 1:
        return 2
    return 0

def function_binding_role(s:readbuf, row:u64, export_size:u64) -> u64:
    name_size = word(s, row, 8)
    name = row + 40
    if name_size == export_size and same_name(s, name, 64, name_size) != 0:
        return 1
    if name_size == HELPER_SIZE and word(s, name, 8) == HELPER_HEAD and word(s, name + 8, 8) == HELPER_BODY:
        if word(s, name + 16, 2) == HELPER_TAIL:
            return 2
    return 0

def exact_function_partition(s:readbuf, count:u64, extent:u64) -> u64:
    first = FUNCTION_LINK_SOURCE_OFFSET
    second = first + FUNCTION_LINK_ROW_BYTES
    if count == 1:
        return choose(word(s, first + 8, 8) == 0 and word(s, first + 16, 8) == extent, 1, 0)
    if word(s, first + 8, 8) != 0:
        first = second
        second = FUNCTION_LINK_SOURCE_OFFSET
    distance = word(s, second + 8, 8)
    if word(s, first + 8, 8) != 0 or distance > extent or word(s, first + 16, 8) != distance:
        return 0
    return choose(word(s, second + 16, 8) == extent - distance, 1, 0)

def same_function_geometry(s:readbuf, source:u64, target:u64, address:u64) -> u64:
    destination = word(s, target + 8, 8)
    if destination < address or destination - address != word(s, source + 8, 8):
        return 0
    return same_name(s, source + 16, target + 16, 24)

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

def verify_loader_sections(s:readbuf, o:mutbuf) -> u64:
    start = word(s, 40, 8)
    count = word(s, 60, 2)
    names_index = word(s, 62, 2)
    if count == 0 or count > MAX_SECTIONS or names_index == 0 or names_index >= count:
        return terminal(o, E_SECTIONS, 0, 0)
    if in_file(length(s), start, count * 64) == 0:
        return terminal(o, E_RANGE, 0, 0)
    strings = start + names_index * 64
    if word(s, strings + 4, 4) != 3:
        return terminal(o, E_MISSING_NAMES, 0, 0)
    names = word(s, strings + 24, 8)
    extent = word(s, strings + 32, 8)
    if in_file(length(s), names, extent) == 0:
        return terminal(o, E_RANGE, 0, 0)
    index = 0
    while index < count:
        row = start + index * 64
        offset = word(s, row, 4)
        if offset >= extent:
            return terminal(o, E_NAME_INDEX, 0, 0)
        result = verify_loader_section(s, o, row, names + offset, extent - offset)
        if result != 0:
            return result
        index = index + 1
    return reply(o, 0, 0, 0, 24)

def verify_loader_section(s:readbuf, o:mutbuf, row:u64, name:u64, extent:u64) -> u64:
    size = name_length(s, name, extent)
    if size > 256:
        return terminal(o, E_NAME_LENGTH, 0, 0)
    if ascii_name(s, name, size) == 0:
        return terminal(o, E_NAME_ASCII, 0, 0)
    role = section_authority(s, name, size)
    reviewed = role != 0 and role <= LOADER_AUTHORITY_COUNT
    flags = word(s, row + 8, 8)
    if (flags & 2) == 0:
        if reviewed:
            return reply(o, E_LOADER_SECTION_UNALLOCATED, name, size, 24)
        return 0
    if reviewed == False or (flags != 2 and flags != 3 and flags != 6 and flags != 66):
        return terminal(o, E_LOADER_SECTION_UNREVIEWED, 0, 0)
    span = word(s, row + 32, 8)
    if span == 0:
        return 0
    permissions = choose((flags & 1) != 0, 6, choose((flags & 4) != 0, 5, 4))
    result = load_binding(s, o, word(s, row + 16, 8), span, word(s, row + 24, 8), permissions)
    return choose(get(o, 0) == 0, 0, result)

def review_section_roles(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, 40) != 0 or get(w, 48) != 0 or get(w, 56) != 0 or get(w, 64) != 0:
        return 4294967293
    start = word(s, 40, 8)
    count = word(s, 60, 2)
    if count == 0 or count > MAX_SECTIONS or get(w, 8) >= count or get(w, 16) >= count or get(w, 24) >= count:
        return terminal(o, E_SECTIONS, 0, 0)
    if in_file(length(s), start, count * 64) == 0:
        return terminal(o, E_RANGE, 0, 0)
    operation = get(w, 0)
    direct = get(w, 32)
    if operation == OBJECT_INVENTORY_MAGIC:
        if direct > 1:
            return 4294967293
        return object_relocation_inventory(s, o, w, start + get(w, 8) * 64, direct)
    if direct != 0:
        return 4294967293
    if operation == EXECUTABLE_LAYOUT_MAGIC:
        return executable_section_layout(s, o, w, start, count)
    return dynamic_relocation_inventory(s, o, w, start, count)

def object_relocation_inventory(s:readbuf, o:mutbuf, w:mutbuf, row:u64, direct:u64) -> u64:
    if word(s, row + 4, 4) != 4 or word(s, row + 56, 8) != 24:
        return terminal(o, E_OBJECT_INVENTORY, 0, 0)
    if word(s, row + 32, 8) != choose(direct != 0, 24, 48):
        return terminal(o, E_OBJECT_INVENTORY, 0, 0)
    if word(s, row + 44, 4) != get(w, 16) or word(s, row + 40, 4) != get(w, 24):
        return terminal(o, E_OBJECT_INVENTORY, 0, 0)
    return reply(o, 0, 0, 0, 24)

def verify_bound_text(s:readbuf, o:mutbuf, w:mutbuf, operation:u64) -> u64:
    start = word(s, 40, 8)
    count = word(s, 60, 2)
    index = get(w, 8)
    if count == 0 or count > MAX_SECTIONS or index >= count:
        return terminal(o, E_SECTIONS, 0, 0)
    if in_file(length(s), start, count * 64) == 0:
        return terminal(o, E_RANGE, 0, 0)
    row = start + index * 64
    span = word(s, row + 32, 8)
    if operation == UNWINDING_MAGIC:
        if span != 0:
            return terminal(o, E_UNWINDING, 0, 0)
        return reply(o, 0, 0, 0, 24)
    return verify_object_text(s, o, w, row, span)

def verify_object_text(s:readbuf, o:mutbuf, w:mutbuf, row:u64, span:u64) -> u64:
    if word(s, row + 4, 4) != 1 or word(s, row + 8, 8) != 6 or word(s, row + 16, 8) != 0:
        return terminal(o, E_TEXT_SHAPE, 0, 0)
    if get(w, 16) != 6 or get(w, 24) != span or length(w) - 64 != span:
        return terminal(o, E_TEXT_SHAPE, 0, 0)
    start = word(s, row + 24, 8)
    if in_file(length(s), start, span) == 0:
        return terminal(o, E_RANGE, 0, 0)
    index = 0
    while index < span:
        if byte(s, start + index) != byte(w, 64 + index):
            return terminal(o, E_TEXT_SHAPE, 0, 0)
        index = index + 1
    if span > 65536:
        return terminal(o, E_TEXT_BUDGET, 0, 0)
    return reply(o, 0, 0, 0, 24)

def executable_section_layout(s:readbuf, o:mutbuf, w:mutbuf, start:u64, count:u64) -> u64:
    plt = start + get(w, 16) * 64
    got = start + get(w, 24) * 64
    if word(s, plt + 8, 8) != 6 or word(s, plt + 32, 8) != 32 or word(s, got + 8, 8) != 3 or word(s, got + 32, 8) != 32:
        return terminal(o, E_PLT_GOT_SHAPE, 0, 0)
    index = 0
    matched = 0
    while index < count:
        if (word(s, start + index * 64 + 8, 8) & 4) != 0:
            if index != get(w, 8) and index != get(w, 16):
                return terminal(o, E_EXECUTABLE_SECTION, 0, 0)
            matched = matched + 1
        index = index + 1
    if matched != 2:
        return terminal(o, E_EXECUTABLE_SECTION, 0, 0)
    return executable_load_layout(s, o, start + get(w, 8) * 64, plt)

def executable_load_layout(s:readbuf, o:mutbuf, text:u64, plt:u64) -> u64:
    addr = word(s, text + 16, 8)
    extent = word(s, text + 32, 8)
    result = load_binding(s, o, addr, extent, word(s, text + 24, 8), 5)
    if get(o, 0) != 0:
        return result
    if executable_load_count(s) != 1:
        return terminal(o, E_EXECUTABLE_SEGMENT, 0, 0)
    base = get(o, 48)
    span = get(o, 56)
    plt_addr = word(s, plt + 16, 8)
    result = load_binding(s, o, plt_addr, 32, word(s, plt + 24, 8), 5)
    if get(o, 0) != 0:
        return result
    if get(o, 48) != base or plt_addr != base or addr < base or span < 32:
        return terminal(o, E_EXECUTABLE_PARTITION, 0, 0)
    if addr - base != 32 or extent != span - 32:
        return terminal(o, E_EXECUTABLE_PARTITION, 0, 0)
    return reply(o, 0, 0, 0, 24)

def executable_load_count(s:readbuf) -> u64:
    start = word(s, 32, 8)
    extent = word(s, 56, 2)
    index = 0
    count = 0
    while index < extent:
        row = start + index * 56
        if word(s, row, 4) == 1 and (word(s, row + 4, 4) & 1) != 0:
            count = count + 1
        index = index + 1
    return count

def dynamic_relocation_inventory(s:readbuf, o:mutbuf, w:mutbuf, start:u64, count:u64) -> u64:
    index = 0
    wanted = get(w, 8)
    found = 0
    while index < count:
        row = start + index * 64
        kind = word(s, row + 4, 4)
        if kind == 4 or kind == 9:
            if index != wanted or kind != 4:
                return terminal(o, E_DYNAMIC_RELOCATION, 0, 0)
            found = 1
        index = index + 1
    rela = start + wanted * 64
    if found == 0 or word(s, rela + 56, 8) != 24 or word(s, rela + 32, 8) != 24:
        return terminal(o, E_DYNAMIC_RELOCATION, 0, 0)
    if word(s, rela + 40, 4) != get(w, 16) or word(s, rela + 44, 4) != get(w, 24):
        return terminal(o, E_DYNAMIC_RELOCATION, 0, 0)
    return reply(o, 0, 0, 0, 24)

def dynamic_tags(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    return exact_dynamic_tags(s, o, get(w, 0), get(w, 8), get(w, 16), get(w, 24), get(w, 32))

def exact_dynamic_tags(s:readbuf, o:mutbuf, start:u64, size:u64, addr:u64, got:u64, rela:u64) -> u64:
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
    if tag_equals(o, rows, 3, got) == 0 or tag_equals(o, rows, 2, 24) == 0:
        return terminal(o, E_DYNAMIC_PLT, 0, 0)
    if tag_equals(o, rows, 20, 7) == 0 or tag_equals(o, rows, 23, rela) == 0:
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

def loader_lookup(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, 8) > 256 or get(w, 16) != 0 or get(w, 24) != 0 or get(w, 32) != 0 or get(w, 40) != 0 or get(w, 48) != 0 or get(w, 56) != 0:
        return 4294967293
    extent = inventory_authorities(s, o, 3)
    if get(o, 0) != 0:
        return extent
    write_lookup_roles(s, o, w, extent)
    return lookup_dynamic(s, o, w)

def write_lookup_roles(s:readbuf, o:mutbuf, w:mutbuf, extent:u64) -> u64:
    first = extent - AUTHORITY_BYTES
    shoff = word(s, 40, 8)
    index = 0
    while index < AUTHORITY_BYTES:
        row = get(o, first + index)
        if row != 0:
            row = shoff + (row - 1) * 64
        put(w, LOOKUP_ROLES + index, row)
        index = index + 8
    return 0

def lookup_row(w:mutbuf, role:u64) -> u64:
    return get(w, LOOKUP_ROLES + role * 8)

def loader_executable(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    put(w, LOOKUP_WORK, get(w, 8))
    extent = inventory_authorities(s, o, 3)
    if get(o, 0) != 0:
        return extent
    write_lookup_roles(s, o, w, extent)
    return checked_executable_roles(s, o, w)

def checked_executable_roles(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    shape = executable_role_error(s, w)
    if shape != 0:
        return terminal(o, shape, 0, 0)
    result = executable_from_roles(s, o, w)
    if get(o, 0) != 0:
        return result
    return relocations_from_roles(s, o, w)

def final_loader(s:readbuf, o:mutbuf, w:mutbuf, receipt:bool) -> u64:
    name_size = get(w, 8)
    if name_size > 256:
        return 4294967293
    extent = inventory_authorities(s, o, 3)
    if get(o, 0) != 0:
        return extent
    write_lookup_roles(s, o, w, extent)
    result = loader_export_from_symbol_table(s, o, w, name_size)
    if get(o, 0) != 0:
        return result
    put(w, LOOKUP_WORK, get(o, 16))
    result = checked_executable_roles(s, o, w)
    if get(o, 0) != 0:
        return result
    result = checked_final_lookup(s, o, w, name_size)
    if get(o, 0) != 0 or receipt == False:
        return result
    text = lookup_row(w, OWNED_TEXT_ROLE)
    put(o, 24, word(s, text + 24, 8))
    put(o, 32, word(s, text + 16, 8))
    put(o, 40, word(s, text + 32, 8))
    put(o, 48, word(s, lookup_row(w, ROLE_PLT) + 16, 8) + 16)
    return reply(o, 0, 0, 0, 56)

def loader_export_from_symbol_table(s:readbuf, o:mutbuf, w:mutbuf, name_size:u64) -> u64:
    dynsym = lookup_row(w, ROLE_DYNSYM)
    if dynsym == 0:
        return terminal(o, MISSING_DYNSYM, 0, 0)
    text = lookup_row(w, OWNED_TEXT_ROLE)
    table = lookup_row(w, OWNED_SYMBOLS_ROLE)
    if text == 0:
        return terminal(o, E_OWNED_MISSING_TEXT, 0, 0)
    if word(s, text + 4, 4) != 1:
        return terminal(o, E_OWNED_TEXT_KIND, 0, 0)
    if table == 0:
        return terminal(o, E_OWNED_MISSING_SYMBOLS, 0, 0)
    start = word(s, 40, 8)
    section = (text - start) >> 6
    address = word(s, text + 16, 8)
    size = word(s, text + 32, 8)
    result = function_extents(s, o, (table - start) >> 6, section, address, size)
    if get(o, 0) != 0:
        return result
    put(w, 8, (dynsym - start) >> 6)
    put(w, 16, section)
    put(w, 24, address)
    put(w, 32, size)
    put(w, 40, 0)
    put(w, 48, 0)
    return loader_match_static_export(s, o, w, name_size)

def loader_match_static_export(s:readbuf, o:mutbuf, w:mutbuf, name_size:u64) -> u64:
    index = 0
    while index < get(o, 8):
        row = 24 + index * 56
        if get(o, row + 8) == name_size and scratch_name_matches(s, w, get(o, row), FINAL_LOADER_NAME, name_size) != 0:
            field = 0
            while field < 40:
                put(w, 64 + field, get(o, row + 16 + field))
                field = field + 8
            return dynamic_symbols_with_name(s, o, w, FINAL_LOADER_NAME, name_size)
        index = index + 1
    return terminal(o, E_DYNAMIC_EXPORT, 0, 0)

def checked_final_lookup(s:readbuf, o:mutbuf, w:mutbuf, name_size:u64) -> u64:
    dynamic = lookup_row(w, ROLE_DYNAMIC)
    if dynamic == 0:
        return terminal(o, MISSING_DYNAMIC, 0, 0)
    if word(s, dynamic + 4, 4) != 6:
        return terminal(o, KIND_DYNAMIC, 0, 0)
    result = load_binding(s, o, word(s, dynamic + 16, 8), word(s, dynamic + 32, 8), word(s, dynamic + 24, 8), 6)
    if get(o, 0) != 0:
        return result
    put(w, 8, name_size)
    index = 0
    while index < name_size:
        store(w, 64 + index, byte(w, FINAL_LOADER_NAME + index))
        index = index + 1
    return lookup_dynamic(s, o, w)

def executable_role_error(s:readbuf, w:mutbuf) -> u64:
    text = lookup_row(w, OWNED_TEXT_ROLE)
    if text == 0:
        return E_OWNED_MISSING_TEXT
    if word(s, text + 4, 4) != 1:
        return E_OWNED_TEXT_KIND
    plt = lookup_row(w, ROLE_PLT)
    if plt == 0:
        return E_LOADER_MISSING_PLT
    if word(s, plt + 4, 4) != 1:
        return E_LOADER_PLT_KIND
    got = lookup_row(w, ROLE_GOT)
    if got == 0:
        return MISSING_GOT
    if word(s, got + 4, 4) != 1:
        return KIND_GOT
    rela = lookup_row(w, ROLE_RELA_PLT)
    if rela == 0:
        return MISSING_RELA_PLT
    if word(s, rela + 4, 4) != 4:
        return KIND_RELA_PLT
    return 0

def executable_from_roles(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    start = word(s, 40, 8)
    put(w, 8, (lookup_row(w, OWNED_TEXT_ROLE) - start) >> 6)
    put(w, 16, (lookup_row(w, ROLE_PLT) - start) >> 6)
    put(w, 24, (lookup_row(w, ROLE_GOT) - start) >> 6)
    result = executable_section_layout(s, o, w, start, word(s, 60, 2))
    if get(o, 0) != 0:
        return result
    return relro_from_roles(s, o, w)

def relro_from_roles(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    row = lookup_row(w, ROLE_GOT)
    address = word(s, row + 16, 8)
    extent = word(s, row + 32, 8)
    result = load_binding(s, o, address, extent, word(s, row + 24, 8), 6)
    if get(o, 0) != 0:
        return result
    put(w, 8, get(o, 48))
    put(w, 16, get(o, 40))
    put(w, 24, get(o, 56))
    put(w, 32, get(o, 64))
    put(w, 40, address)
    put(w, 48, extent)
    return verify_relro(s, o, w)

def relocations_from_roles(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    dynsym = lookup_row(w, ROLE_DYNSYM)
    if dynsym == 0:
        return terminal(o, MISSING_DYNSYM, 0, 0)
    start = word(s, 40, 8)
    rela = lookup_row(w, ROLE_RELA_PLT)
    got = lookup_row(w, ROLE_GOT)
    put(w, 8, (rela - start) >> 6)
    put(w, 16, (dynsym - start) >> 6)
    put(w, 24, (got - start) >> 6)
    result = dynamic_relocation_inventory(s, o, w, start, word(s, 60, 2))
    if get(o, 0) != 0:
        return result
    plt = lookup_row(w, ROLE_PLT)
    put(w, 0, word(s, plt + 24, 8))
    put(w, 8, word(s, plt + 16, 8))
    put(w, 16, word(s, got + 16, 8))
    put(w, 24, word(s, rela + 24, 8))
    put(w, 32, get(w, LOOKUP_WORK))
    return verify_plt_slot(s, o, w)

def lookup_dynamic(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    dynamic = lookup_row(w, ROLE_DYNAMIC)
    if dynamic == 0:
        return terminal(o, MISSING_DYNAMIC, 0, 0)
    if word(s, dynamic + 4, 4) != 6:
        return terminal(o, KIND_DYNAMIC, 0, 0)
    got = lookup_row(w, ROLE_GOT)
    if got == 0:
        return terminal(o, MISSING_GOT, 0, 0)
    if word(s, got + 4, 4) != 1:
        return terminal(o, KIND_GOT, 0, 0)
    rela = lookup_row(w, ROLE_RELA_PLT)
    if rela == 0:
        return terminal(o, MISSING_RELA_PLT, 0, 0)
    if word(s, rela + 4, 4) != 4:
        return terminal(o, KIND_RELA_PLT, 0, 0)
    result = exact_dynamic_tags(s, o, word(s, dynamic + 24, 8), word(s, dynamic + 32, 8),
                                word(s, dynamic + 16, 8), word(s, got + 16, 8), word(s, rela + 16, 8))
    if get(o, 0) != 0:
        return result
    rows = get(o, 8)
    put(w, 16, tag_equals(o, rows, 4, word(s, lookup_row(w, ROLE_HASH) + 16, 8)))
    put(w, 24, tag_equals(o, rows, 0x6ffffef5, word(s, lookup_row(w, ROLE_GNU_HASH) + 16, 8)))
    put(w, 32, tag_equals(o, rows, 0x6ffffff0, word(s, lookup_row(w, ROLE_GNU_VERSION) + 16, 8)))
    put(w, 40, tag_equals(o, rows, 0x6ffffffe, word(s, lookup_row(w, ROLE_GNU_VERSION_R) + 16, 8)))
    put(w, 48, tag_equals(o, rows, 0x6fffffff, 1))
    dynsym = lookup_row(w, ROLE_DYNSYM)
    if dynsym == 0:
        return terminal(o, MISSING_DYNSYM, 0, 0)
    result = exact_dynamic_order(s, o, w, (dynsym - word(s, 40, 8)) >> 6, get(w, 8))
    if get(o, 0) != 0:
        return result
    return lookup_hashes(s, o, w)

def lookup_hashes(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    row = lookup_row(w, ROLE_HASH)
    if row == 0:
        return terminal(o, MISSING_HASH, 0, 0)
    if word(s, row + 4, 4) != 5:
        return terminal(o, KIND_HASH, 0, 0)
    size = word(s, row + 32, 8)
    if get(w, 16) == 0 or size < 8:
        return terminal(o, E_SYSV_AUTHORITY, 0, 0)
    error = review_sysv(s, word(s, row + 24, 8), size, sysv_export(w, get(w, 8)))
    if error != 0:
        return terminal(o, error, 0, 0)
    row = lookup_row(w, ROLE_GNU_HASH)
    if row == 0:
        return terminal(o, MISSING_GNU_HASH, 0, 0)
    if word(s, row + 4, 4) != 0x6ffffff6:
        return terminal(o, KIND_GNU_HASH, 0, 0)
    size = word(s, row + 32, 8)
    if get(w, 24) == 0 or size < 16:
        return terminal(o, E_GNU_AUTHORITY, 0, 0)
    error = review_gnu(s, word(s, row + 24, 8), size, gnu_export(w, get(w, 8)))
    if error != 0:
        return terminal(o, error, 0, 0)
    return lookup_versions(s, o, w)

def lookup_versions(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    versions = lookup_row(w, ROLE_GNU_VERSION)
    if versions == 0:
        return terminal(o, MISSING_GNU_VERSION, 0, 0)
    if word(s, versions + 4, 4) != 0x6fffffff:
        return terminal(o, KIND_GNU_VERSION, 0, 0)
    needed = lookup_row(w, ROLE_GNU_VERSION_R)
    if needed == 0:
        return terminal(o, MISSING_GNU_VERSION_R, 0, 0)
    if word(s, needed + 4, 4) != 0x6ffffffe:
        return terminal(o, KIND_GNU_VERSION_R, 0, 0)
    if (get(w, 32) & get(w, 40) & get(w, 48)) == 0 or word(s, versions + 32, 8) != 6 or word(s, needed + 32, 8) != 32:
        return terminal(o, E_VERSION_AUTHORITY, 0, 0)
    need_at = word(s, needed + 24, 8)
    result = exact_version_tables(s, o, word(s, versions + 24, 8), need_at)
    if get(o, 0) != 0:
        return result
    strings = lookup_row(w, ROLE_DYNSTR)
    if strings == 0:
        return terminal(o, MISSING_DYNSTR, 0, 0)
    if word(s, strings + 4, 4) != 3:
        return terminal(o, KIND_DYNSTR, 0, 0)
    return exact_version_import(s, o, need_at, word(s, strings + 24, 8), word(s, strings + 32, 8))

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
    helper = get(w, 48)
    count = choose(helper == 0, 1, 2)
    if size != length(w) - 64 or size > 65536:
        return 4294967293
    if in_file(length(s), text, size) == 0 or in_file(length(s), rela, count * 24) == 0:
        return terminal(o, E_RANGE, 0, 0)
    columns = 0
    seen = 0
    first = 0
    while columns < count:
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
        if symbol > count or offset == first:
            return terminal(o, E_OBJECT_CALL, 0, 0)
        target = choose(symbol == 1, get(w, 40), helper)
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
    if seen != choose(count == 1, 2, 6):
        return terminal(o, E_OBJECT_TEXT, 0, 0)
    if linked_text_matches(s, o, w, text, size, count) == 0:
        return terminal(o, E_OBJECT_TEXT, 0, 0)
    return reply(o, 0, count, 0, 24 + count * 32)

def linked_text_matches(s:readbuf, o:mutbuf, w:mutbuf, text:u64, size:u64, count:u64) -> u64:
    first = get(o, 24)
    first_value = get(o, 48)
    second = choose(count == 1, size, get(o, 56))
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

def review_version_tables(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, 16) != 6 or get(w, 40) != 32 or get(w, 56) != 7:
        return terminal(o, E_VERSION_AUTHORITY, 0, 0)
    if get(w, 64) != get(w, 24) or get(w, 72) != get(w, 48) or get(w, 80) != 1:
        return terminal(o, E_VERSION_AUTHORITY, 0, 0)
    return exact_version_tables(s, o, get(w, 8), get(w, 32))

def exact_version_tables(s:readbuf, o:mutbuf, versions:u64, needed:u64) -> u64:
    if in_file(length(s), versions, 6) == 0 or in_file(length(s), needed, 32) == 0:
        return terminal(o, E_RANGE, 0, 0)
    return terminal(o, choose(word(s, versions, 6) == 0x000100020000, 0, E_VERSION_AUTHORITY), 0, 0)

def review_version_import(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    return exact_version_import(s, o, get(w, 8), get(w, 16), get(w, 24))

def exact_version_import(s:readbuf, o:mutbuf, needed:u64, start:u64, size:u64) -> u64:
    if in_file(length(s), needed, 32) == 0:
        return terminal(o, E_RANGE, 0, 0)
    if word(s, needed, 4) != 0x00010001 or word(s, needed + 8, 8) != 16:
        return terminal(o, E_VERSION_IMPORT, 0, 0)
    if word(s, needed + 16, 4) != version_hash() or word(s, needed + 20, 4) != 0x00020000:
        return terminal(o, E_VERSION_IMPORT, 0, 0)
    if word(s, needed + 28, 4) != 0:
        return terminal(o, E_VERSION_IMPORT, 0, 0)
    error = verify_version_name(s, start, size, word(s, needed + 4, 4), 0)
    if error != 0:
        return terminal(o, error, 0, 0)
    return terminal(o, verify_version_name(s, start, size, word(s, needed + 24, 4), 1), 0, 0)

def version_hash() -> u64:
    index = 0
    value = 0
    while index < 8:
        value = sysv_step(value, (VERSION_HEAD >> (index * 8)) & 255)
        index = index + 1
    index = 0
    while index < 3:
        value = sysv_step(value, (VERSION_TAIL >> (index * 8)) & 255)
        index = index + 1
    return value

def verify_version_name(s:readbuf, start:u64, size:u64, index:u64, kind:u64) -> u64:
    if index >= size:
        return E_NAME_INDEX
    if in_file(length(s), start, size) == 0:
        return E_RANGE
    at = start + index
    count = name_length(s, at, size - index)
    if count > 256:
        return E_NAME_LENGTH
    if ascii_name(s, at, count) == 0:
        return E_NAME_ASCII
    if kind == 0:
        if count == 9 and word(s, at, 8) == LIBC_HEAD and byte(s, at + 8) == 54:
            return 0
    else:
        if count == 11 and word(s, at, 8) == VERSION_HEAD and word(s, at + 8, 3) == VERSION_TAIL:
            return 0
    return E_VERSION_IMPORT

def verify_relro(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    phoff = word(s, 32, 8)
    phnum = word(s, 56, 2)
    if phnum > MAX_SEGMENTS or in_file(length(s), phoff, phnum * 56) == 0:
        return terminal(o, E_RANGE, 0, 0)
    seen = 0
    relro = 0
    index = 0
    while index < phnum:
        row = phoff + index * 56
        if word(s, row, 4) == 0x6474e552:
            relro = row
            seen = seen + 1
        index = index + 1
    if seen != 1:
        return terminal(o, E_RELRO_COUNT, 0, 0)
    relative = word(s, relro + 16, 8)
    size = word(s, relro + 40, 8)
    base = get(w, 8)
    writable_size = get(w, 24)
    if word(s, relro + 4, 4) != 4 or word(s, relro + 48, 8) != 1:
        return terminal(o, E_RELRO_MAPPING, 0, 0)
    if size == 0 or word(s, relro + 32, 8) != size or relative < base or size > writable_size:
        return terminal(o, E_RELRO_MAPPING, 0, 0)
    offset = word(s, relro + 8, 8)
    writable_offset = get(w, 16)
    if relative - base > writable_size - size or offset < writable_offset:
        return terminal(o, E_RELRO_MAPPING, 0, 0)
    if offset - writable_offset != relative - base:
        return terminal(o, E_RELRO_MAPPING, 0, 0)
    first_page = relative // 4096
    end_page = (relative + size) // 4096
    writable_end = base + get(w, 32)
    last_page = writable_end // 4096 + choose(writable_end % 4096 == 0, 0, 1)
    if first_page < base // 4096 or first_page >= end_page or end_page > last_page:
        return terminal(o, E_RELRO_GOT, 0, 0)
    got = get(w, 40)
    protected_end = end_page * 4096
    if got < first_page * 4096 or got > protected_end or get(w, 48) > protected_end - got:
        return terminal(o, E_RELRO_GOT, 0, 0)
    return terminal(o, 0, 0, 0)

def owned_shared_layout(s:readbuf, o:mutbuf) -> u64:
    size = length(s)
    if size < 64 or size > OWNED_SHARED_MAX:
        return owned_shared_refusal(o, ABI_IDENTITY)
    if word(s, 0, 7) != ELF_IDENT or word(s, 16, 2) != 3 or word(s, 18, 2) != 62:
        return owned_shared_refusal(o, ABI_IDENTITY)
    if word(s, 20, 4) != 1 or word(s, 52, 2) != 64:
        return owned_shared_refusal(o, ABI_IDENTITY)
    shoff = word(s, 40, 8)
    sections = word(s, 60, 2)
    if word(s, 58, 2) != 64 or sections == 0 or sections > 4096 or in_file(size, shoff, sections * 64) == 0:
        return owned_shared_refusal(o, ABI_SECTIONS)
    dyns = 0
    sym = 0
    index = 0
    while index < sections:
        entry = shoff + index * 64
        kind = word(s, entry + 4, 4)
        extent = word(s, entry + 32, 8)
        if kind != 8 and extent != 0 and in_file(size, word(s, entry + 24, 8), extent) == 0:
            return owned_shared_refusal(o, ABI_SECTION_RANGE)
        if kind == 11:
            dyns = dyns + 1
            sym = entry
        index = index + 1
    if owned_shared_segments(s, o) != 0:
        # Segment validation emits its own exact first refusal.
        return 64
    if dyns != 1:
        return owned_shared_refusal(o, ABI_SYM_COUNT)
    symbols = word(s, sym + 32, 8)
    link = word(s, sym + 40, 4)
    if link >= sections or word(s, sym + 56, 8) != 24 or symbols % 24 != 0 or symbols < 24 or symbols > 1572864:
        return owned_shared_refusal(o, ABI_SYMBOLS)
    strings = shoff + link * 64
    if word(s, strings + 4, 4) != 3:
        return owned_shared_refusal(o, ABI_SYMBOLS)
    stroff = word(s, strings + 24, 8)
    strsize = word(s, strings + 32, 8)
    error = owned_shared_loader(s, get(o, 16), get(o, 24),
        word(s, strings + 16, 8), word(s, sym + 16, 8), strsize, stroff)
    if error != 0:
        return owned_shared_refusal(o, error)
    put(o, 0, 0)
    put(o, 16, shoff)
    put(o, 24, sections)
    put(o, 32, word(s, sym + 24, 8))
    put(o, 40, symbols)
    put(o, 48, stroff)
    put(o, 56, strsize)
    return 64 + get(o, 8) * 16

def owned_shared_segments(s:readbuf, o:mutbuf) -> u64:
    count = word(s, 56, 2)
    start = word(s, 32, 8)
    if word(s, 54, 2) != 56 or count == 0 or count > 128 or in_file(length(s), start, count * 56) == 0:
        return owned_shared_refusal(o, ABI_HEADERS)
    executable = 0
    stack = 0
    dynamic = 0
    index = 0
    while index < count:
        at = start + index * 56
        kind = word(s, at, 4)
        flags = word(s, at + 4, 4)
        offset = word(s, at + 8, 8)
        address = word(s, at + 16, 8)
        size = word(s, at + 32, 8)
        if kind == 3 or kind == 7:
            return owned_shared_refusal(o, ABI_INTERPRETER)
        if kind == 0x6474E551:
            stack = stack + 1
            if flags != 6:
                return owned_shared_refusal(o, ABI_STACK_FLAGS)
        if kind == 2:
            if in_file(length(s), offset, size) == 0 or size % 16 != 0:
                return owned_shared_refusal(o, ABI_DYNAMIC_RANGE)
            dynamic = dynamic + 1
            put(o, 16, offset)
            put(o, 24, size)
        if kind == 1:
            if flags != 4 and flags != 5 and flags != 6:
                return owned_shared_refusal(o, ABI_LOAD_FLAGS)
            end = address + size
            if in_file(length(s), offset, size) == 0 or (end < address and end != 0):
                return owned_shared_refusal(o, ABI_LOAD_RANGE)
            if flags == 5:
                put(o, 64 + executable * 16, address)
                put(o, 72 + executable * 16, size)
                executable = executable + 1
        index = index + 1
    if stack != 1:
        return owned_shared_refusal(o, ABI_STACK_COUNT)
    if executable == 0:
        return owned_shared_refusal(o, ABI_EXEC_COUNT)
    if dynamic != 1:
        return owned_shared_refusal(o, ABI_DYNAMIC_COUNT)
    put(o, 8, executable)
    return 0

def owned_shared_loader(s:readbuf, start:u64, size:u64, straddr:u64, symaddr:u64, strsize:u64, stroff:u64) -> u64:
    if size > 65536:
        return ABI_DYN_BOUND
    seen = 0
    consistent = 1
    terminated = 0
    at = start
    while at < start + size and terminated == 0:
        tag = word(s, at, 8)
        value = word(s, at + 8, 8)
        if tag == 0:
            terminated = 1
        else:
            if tag == 15 or tag == 16 or tag == 22 or tag == 29 or tag == 0x6FFFFEFA or tag == 0x6FFFFEFB or tag == 0x6FFFFEFC or tag == 0x7FFFFFFD or tag == 0x7FFFFFFF:
                return ABI_REDIRECT
            if tag == 30 and (value & 7) != 0:
                return ABI_FLAGS
            if tag == 0x6FFFFFFB and (value & (0x10 | 0x80 | 0x1000000)) != 0:
                return ABI_FLAGS_ONE
            bit = 0
            if tag == 5:
                bit = 1
                consistent = consistent & choose(value == straddr, 1, 0)
            if tag == 6:
                bit = 2
                consistent = consistent & choose(value == symaddr, 1, 0)
            if tag == 10:
                bit = 4
                consistent = consistent & choose(value == strsize, 1, 0)
            if tag == 11:
                bit = 8
                consistent = consistent & choose(value == 24, 1, 0)
            if (seen & bit) != 0:
                return ABI_DUPLICATE
            seen = seen | bit
            at = at + 16
    if terminated == 0 or seen != 15 or consistent == 0:
        return ABI_DYNAMIC_IDENTITY
    while start < at:
        if word(s, start, 8) == 1:
            offset = word(s, start + 8, 8)
            if offset >= strsize or in_file(length(s), stroff + offset, 1) == 0:
                return ABI_DEPENDENCY_RANGE
            if strsize - offset < 10 or word(s, stroff + offset, 8) != LIBC_HEAD:
                return ABI_DEPENDENCY
            if word(s, stroff + offset + 8, 2) != 54:
                return ABI_DEPENDENCY
        start = start + 16
    return 0

def owned_shared_refusal(o:mutbuf, code:u64) -> u64:
    put(o, 0, code)
    at = 8
    while at < 64:
        put(o, at, 0)
        at = at + 8
    return 64

def owned_shared_symbols(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    layout_size = owned_shared_layout(s, o)
    if get(o, 0) != 0:
        return layout_size
    start = get(o, 32)
    extent = get(o, 40)
    names = get(o, 48)
    names_extent = get(o, 56)
    # Mutable scratch holds a compressed binary name index. All branch
    # nodes are initialized on insertion, and the empty root is explicit.
    # The operation tag is consumed; its slot now counts defined exports.
    put(w, 0, 0)
    put(w, 8, 0)
    count = 0
    at = start
    while at < start + extent:
        index = word(s, at, 4)
        if index != 0:
            if index >= names_extent:
                return owned_shared_refusal(o, ABI_SYMBOL_NAME_OFFSET)
            name = names + index
            size = owned_shared_name_size(s, name, names_extent - index)
            if size > 512:
                return owned_shared_refusal(o, size - 512)
            info = byte(s, at + 4)
            binding = info >> 4
            if binding != 0:
                if binding != 1 and binding != 2:
                    return owned_shared_refusal(o, ABI_SYMBOL_BINDING)
                row = OWNED_SHARED_SYMBOL_HEAD + count * 24
                put(o, row, name)
                put(o, row + 8, size)
                final = word(s, at + 6, 2)
                distinct = owned_shared_insert(s, o, w, row, 16 + count * 24)
                if final == 0:
                    if distinct == 0:
                        return owned_shared_refusal(o, ABI_SYMBOL_DUPLICATE)
                    if owned_shared_allowed_import(s, name, size) == 0:
                        return owned_shared_named_error(o, ABI_SYMBOL_IMPORT, name, size)
                    put(o, row + 16, 0)
                else:
                    symbol_size = word(s, at + 16, 8)
                    if distinct == 0 or final >= get(o, 24) or byte(s, at + 5) & 3 != 0 or info & 15 != 2 or symbol_size == 0:
                        return owned_shared_named_error(o, ABI_SYMBOL_EXPORT, name, size)
                    section = get(o, 16) + final * 64
                    if owned_shared_mapped(s, o, section, word(s, at + 8, 8), symbol_size) == 0:
                        return owned_shared_named_error(o, ABI_SYMBOL_MAPPING, name, size)
                    put(o, row + 16, 1)
                    put(w, 0, get(w, 0) + 1)
                count = count + 1
        at = at + 24
    match = 0
    if length(w) == OWNED_SHARED_EXPECTED_WORK:
        match = owned_shared_exports_match(s, o, w, get(w, 0))
    owned_shared_refusal(o, 0)
    put(o, 8, count)
    put(o, 16, match)
    return OWNED_SHARED_SYMBOL_HEAD + count * 24

def owned_shared_named_error(o:mutbuf, code:u64, name:u64, size:u64) -> u64:
    owned_shared_refusal(o, code)
    put(o, 8, name)
    put(o, 16, size)
    return 64

def owned_shared_name_size(s:readbuf, name:u64, extent:u64) -> u64:
    at = 0
    ascii = 1
    spelling = 1
    while at < extent:
        letter = byte(s, name + at)
        if letter == 0:
            if ascii == 0:
                return 512 + ABI_SYMBOL_NAME_ASCII
            if at == 0 or at > 512 or spelling == 0:
                return 512 + ABI_SYMBOL_NAME_SPELLING
            return at
        if letter > 127:
            ascii = 0
        permitted = choose(letter >= 65 and letter <= 90 or letter >= 97 and letter <= 122 or letter == 95 or
                           at > 0 and letter >= 48 and letter <= 57, 1, 0)
        if permitted == 0:
            spelling = 0
        at = at + 1
    return 512 + ABI_SYMBOL_NAME_TERMINATION

def owned_shared_mapped(s:readbuf, o:mutbuf, section:u64, value:u64, size:u64) -> u64:
    flags = word(s, section + 8, 8)
    address = word(s, section + 16, 8)
    extent = word(s, section + 32, 8)
    if word(s, section + 4, 4) != 1 or flags & 4 == 0 or value < address or size > extent:
        return 0
    if value - address > extent - size:
        return 0
    index = 0
    count = get(o, 8)
    while index < count:
        row = 64 + index * 16
        low = get(o, row)
        extent = get(o, row + 8)
        if value >= low and size <= extent and value - low <= extent - size:
            return 1
        index = index + 1
    return 0

def owned_shared_name_bit(s:readbuf, name:u64, size:u64, bit:u64) -> u64:
    if bit // 8 >= size:
        return 0
    return (byte(s, name + bit // 8) >> (7 - bit % 8)) & 1

def owned_shared_name_difference(s:readbuf, o:mutbuf, row:u64, other:u64) -> u64:
    left = get(o, row)
    right = get(o, other)
    left_size = get(o, row + 8)
    right_size = get(o, other + 8)
    commons = choose(left_size < right_size, left_size, right_size)
    index = 0
    while index < commons:
        if byte(s, left + index) != byte(s, right + index):
            return index * 8 + owned_shared_first_bit(byte(s, left + index) ^ byte(s, right + index))
        index = index + 1
    if left_size == right_size:
        return 4096
    longer = choose(left_size > right_size, left, right)
    return index * 8 + owned_shared_first_bit(byte(s, longer + index))

def owned_shared_first_bit(value:u64) -> u64:
    index = 0
    while index < 8:
        if (value << index) & 128 != 0:
            return index
        index = index + 1
    return 8

def owned_shared_exports_match(s:readbuf, o:mutbuf, w:mutbuf, exports:u64) -> u64:
    # The expected source names travel in fixed-size records after scratch.
    # The ordinary caller still serializes the historical mismatch diagnostic,
    # but only HIA decides whether the two export sets actually agree.
    count = get(w, OWNED_SHARED_SYMBOL_WORK)
    if count != exports or count > OWNED_SHARED_EXPECTED_COUNT:
        return 2
    ordinal = 0
    at = OWNED_SHARED_SYMBOL_WORK + 8
    while ordinal < count:
        size = get(w, at)
        if size == 0 or size > 512:
            return 2
        if ordinal > 0 and owned_shared_expected_order(w, at - OWNED_SHARED_EXPECTED_RECORD, at) == 0:
            return 2
        if owned_shared_find_export(s, o, w, at + 8, size) == 0:
            return 2
        ordinal = ordinal + 1
        at = at + OWNED_SHARED_EXPECTED_RECORD
    return 1

def owned_shared_expected_order(w:mutbuf, previous:u64, current:u64) -> u64:
    before = get(w, previous)
    after = get(w, current)
    index = 0
    while index < before and index < after:
        first = byte(w, previous + 8 + index)
        second = byte(w, current + 8 + index)
        if first != second:
            return choose(first < second, 1, 0)
        index = index + 1
    return choose(before < after, 1, 0)

def owned_shared_find_export(s:readbuf, o:mutbuf, w:mutbuf, name:u64, size:u64) -> u64:
    current = get(w, 8)
    if current == 0:
        return 0
    while current & 1 == 0:
        row = current // 2
        bit = get(w, row)
        arm = 0
        if bit // 8 < size:
            arm = (byte(w, name + bit // 8) >> (7 - bit % 8)) & 1
        current = get(w, row + 8 + arm * 8)
    leaf = current // 2
    if get(o, leaf + 8) != size or get(o, leaf + 16) != 1:
        return 0
    start = get(o, leaf)
    index = 0
    while index < size:
        if byte(s, start + index) != byte(w, name + index):
            return 0
        index = index + 1
    return 1

def owned_shared_insert(s:readbuf, o:mutbuf, w:mutbuf, row:u64, branch:u64) -> u64:
    # Odd tokens locate output leaves. Even nonzero tokens locate
    # scratch branches whose bit numbers always increase down the tree.
    leaf = row * 2 + 1
    root = get(w, 8)
    if root == 0:
        put(w, 8, leaf)
        return 1
    name = get(o, row)
    size = get(o, row + 8)
    current = root
    while current & 1 == 0:
        node = current // 2
        arm = owned_shared_name_bit(s, name, size, get(w, node))
        current = get(w, node + 8 + arm * 8)
    different = owned_shared_name_difference(s, o, row, current // 2)
    if different == 4096:
        return 0
    current = root
    parent = 8
    descending = 1
    while current & 1 == 0 and descending == 1:
        node = current // 2
        bit = get(w, node)
        if bit >= different:
            descending = 0
        else:
            parent = node + 8 + owned_shared_name_bit(s, name, size, bit) * 8
            current = get(w, parent)
    arm = owned_shared_name_bit(s, name, size, different)
    put(w, branch, different)
    put(w, branch + 8 + arm * 8, leaf)
    put(w, branch + 16 - arm * 8, current)
    put(w, parent, branch * 2)
    return 1
'''


REVIEWED_OWNED_IMPORTS = (
    'malloc', 'calloc', 'free', 'abort', 'memset', 'memcpy', 'memmove', '__cxa_finalize',
    '_ITM_registerTMCloneTable', '_ITM_deregisterTMCloneTable', '__gmon_start__',
)


def owned_import_authoring():
    lines = ['def owned_shared_allowed_import(s:readbuf, name:u64, size:u64) -> u64:']
    for name in REVIEWED_OWNED_IMPORTS:
        words = [name[at:at + 8].encode('ascii') for at in range(0, len(name), 8)]
        check = ' and '.join(f'word(s, name + {at * 8}, {len(word)}) == {int.from_bytes(word, "little")}'
                             for at, word in enumerate(words))
        lines.extend((f'    if size == {len(name)}:', f'        if {check}:', '            return 1'))
    lines.append('    return 0')
    return '\n'.join(lines)


def section_authority_classifier():
    lines = ['def section_authority(s:readbuf, name:u64, size:u64) -> u64:']
    roles = [(index, name.encode('ascii')) for index, name in enumerate(SECTION_AUTHORITIES, 1)]
    for width in sorted({len(name) for _, name in roles}):
        lines.append(f'    if size == {width}:')
        for index, name in roles:
            if len(name) != width:
                continue
            first = int.from_bytes(name[:8], 'little')
            test = f'word(s, name, {min(width, 8)}) == {first}'
            if width > 8:
                suffix = int.from_bytes(name[8:], 'little')
                test += f' and word(s, name + 8, {width - 8}) == {suffix}'
            lines.extend((f'        if {test}:', f'            return {index}'))
    return '\n'.join((*lines, '    return 0', ''))


def document():
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(FIELDS[node.id]), node) if node.id in FIELDS else node

    source = '\n'.join((SOURCE, owned_import_authoring(), section_authority_classifier()))
    nodes = ast.fix_missing_locations(Constants().visit(ast.parse(source))).body
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
