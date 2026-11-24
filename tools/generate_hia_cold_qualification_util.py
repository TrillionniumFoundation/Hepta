"""Author native qualification byte operations and closed ELF inspections."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_document import document

ROOT = Path(__file__).resolve().parents[1]

SOURCE = r'''def utility(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or word_load(s, 0) != MAGIC:
        return 4294967295
    mode = word_load(s, 8)
    arg = word_load(s, 16)
    size = word_load(s, 24)
    if mode == 0:
        if length(s) != 32 or arg > 1048576 or size > 255:
            return 4294967295
        if length(o) < arg:
            return 4294967294
        fill_range(o, 0, arg, size)
        return arg
    if mode == 1:
        return module_name(s, o, arg, size)
    if arg != 0 or size > 1048576 or length(s) != 32 + size:
        return 4294967295
    if mode == 2:
        count = inspect_object(s, 32, size)
        if count == 0:
            return 4294967295
        return copy(s, o, 96, count)
    if mode == 3:
        if inspect_executable(s, 32, size) == 0:
            return 4294967295
        if length(o) < 8:
            return 4294967294
        put(o, 0, SUCCESS)
        return 8
    return 4294967295

def module_name(s:readbuf, o:mutbuf, name:u64, size:u64) -> u32:
    if name == 0 or name > 128 or size == 0 or size > 1048576 or length(s) != 32 + name + size:
        return 4294967295
    i = 0
    while i < name:
        c = byte(s, 32 + i)
        if c <= 32 or c > 126:
            return 4294967295
        i = i + 1
    start = 32 + name
    end = 0
    boundary = 0
    while end < size and byte(s, start + end) != 10:
        if byte(s, start + end) == 32:
            boundary = end + 1
        end = end + 1
    if end == size or boundary == 0 or boundary >= end:
        return 4294967295
    total = boundary + name + size - end
    if total > 1048576 or length(o) < total:
        return 4294967294
    move(s, o, start, 0, boundary)
    move(s, o, 32, boundary, name)
    move(s, o, start + end, boundary + name, size - end)
    return total

def elf_identity(s:readbuf, at:u64, size:u64) -> u64:
    if size < 64:
        return 0
    if word_load(s, at) != 282584257676671 or word_load(s, at + 8) != 0:
        return 0
    return 1

def inspect_executable(s:readbuf, at:u64, size:u64) -> u64:
    if elf_identity(s, at, size) == 0 or size <= 176:
        return 0
    if word_load(s, at + 16) != 4299030530 or word_load(s, at + 24) != 4194480 or word_load(s, at + 32) != 64 or word_load(s, at + 40) != 0 or word_load(s, at + 48) != 15762873576243200 or word_load(s, at + 56) != 2:
        return 0
    if word_load(s, at + 64) != 21474836481 or word_load(s, at + 72) != 0 or word_load(s, at + 80) != 4194304 or word_load(s, at + 88) != 4194304 or word_load(s, at + 96) != size or word_load(s, at + 104) != size or word_load(s, at + 112) != 4096:
        return 0
    if word_load(s, at + 120) != 27452613969 or word_load(s, at + 168) != 16:
        return 0
    i = 128
    while i < 168:
        if word_load(s, at + i) != 0:
            return 0
        i = i + 8
    return 1

def inspect_object(s:readbuf, at:u64, size:u64) -> u64:
    if elf_identity(s, at, size) == 0:
        return 0
    if word_load(s, at + 16) != 4299030529 or word_load(s, at + 24) != 0 or word_load(s, at + 32) != 0 or word_load(s, at + 48) != 274877906944 or word_load(s, at + 56) != 1125925676646400:
        return 0
    table = word_load(s, at + 40)
    if table & 7 != 0 or table > size or size - table != 384:
        return 0
    i = 0
    while i < 64:
        if byte(s, at + table + i) != 0:
            return 0
        i = i + 1
    index = 1
    while index < 6:
        row = at + table + index * 64
        offset = word_load(s, row + 24)
        amount = word_load(s, row + 32)
        if word_load(s, row + 16) != 0 or offset < 64 or offset > table or amount > table - offset:
            return 0
        index = index + 1
    text = at + table + 64
    sym = text + 64
    strings = sym + 64
    names = strings + 64
    stack = names + 64
    if word_load(s, text) != 4294967297 or word_load(s, text + 8) != 6 or word_load(s, text + 24) != 64 or word_load(s, text + 40) != 0 or word_load(s, text + 48) != 16 or word_load(s, text + 56) != 0:
        return 0
    count = word_load(s, text + 32)
    symoff = (64 + count + 7) & 18446744073709551608
    if word_load(s, sym) != 8589934599 or word_load(s, sym + 8) != 0 or word_load(s, sym + 24) != symoff or word_load(s, sym + 32) != 72 or word_load(s, sym + 40) != 8589934595 or word_load(s, sym + 48) != 8 or word_load(s, sym + 56) != 24:
        return 0
    if word_load(s, strings) != 12884901903 or word_load(s, strings + 8) != 0 or word_load(s, strings + 24) != symoff + 72 or word_load(s, strings + 32) != 4 or word_load(s, strings + 40) != 0 or word_load(s, strings + 48) != 1 or word_load(s, strings + 56) != 0:
        return 0
    if word_load(s, names) != 12884901911 or word_load(s, names + 8) != 0 or word_load(s, names + 24) != symoff + 76 or word_load(s, names + 32) != 49 or word_load(s, names + 40) != 0 or word_load(s, names + 48) != 1 or word_load(s, names + 56) != 0:
        return 0
    if word_load(s, stack) != 4294967329 or word_load(s, stack + 8) != 0 or word_load(s, stack + 24) != symoff + 125 or word_load(s, stack + 32) != 0 or word_load(s, stack + 40) != 0 or word_load(s, stack + 48) != 1 or word_load(s, stack + 56) != 0:
        return 0
    symoff = symoff + at
    i = 0
    while i < 24:
        if byte(s, symoff + i) != 0:
            return 0
        i = i + 1
    if word_load(s, symoff + 24) != 281487861612544 or word_load(s, symoff + 32) != 0 or word_load(s, symoff + 40) != 0 or word_load(s, symoff + 48) != 281552286121985 or word_load(s, symoff + 56) != 0 or word_load(s, symoff + 64) == 0 or word_load(s, symoff + 64) > count:
        return 0
    if uint(s, symoff + 72, 4) != 3171840:
        return 0
    if names_exact(s, symoff + 76) == 0:
        return 0
    return count

def names_exact(s:readbuf, at:u64) -> u64:
NAME_TESTS
    return 1

def copy(s:readbuf, o:mutbuf, at:u64, size:u64) -> u32:
    if length(o) < size:
        return 4294967294
    move(s, o, at, 0, size)
    return size

def move(s:readbuf, o:mutbuf, at:u64, dest:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, dest + i, byte(s, at + i))
        i = i + 1
    return 0

def uint(s:readbuf, at:u64, size:u64) -> u64:
    value = 0
    i = 0
    while i < size:
        value = value | (byte(s, at + i) << (8 * i))
        i = i + 1
    return value

def put(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, (value >> (8 * i)) & 255)
        i = i + 1
    return 0
'''


def source():
    import struct
    # Constants follow the same ELF fields as the independently retained
    # inspector. Packing is authoring-time data spelling, never runtime work.
    executable = struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    relocatable = struct.pack('<HHIQQQIHHHHHH', 1, 62, 1, 0, 0, 0, 0, 64, 0, 0, 64, 6, 4)
    constants = {4299030530: executable[:8], 15762873576243200: executable[32:40],
                 4299030529: relocatable[:8], 274877906944: relocatable[32:40],
                 1125925676646400: relocatable[40:48],
                 27452613969: struct.pack('<II', 0x6474e551, 6),
                 281487861612544: struct.pack('<IBBH', 0, 3, 0, 1),
                 281552286121985: struct.pack('<IBBH', 1, 18, 0, 1),
                 3171840: b'\0f0\0'}
    text = SOURCE
    import re
    for old, raw in constants.items():
        text = re.sub(r'\b' + str(old) + r'\b', str(int.from_bytes(raw, 'little')), text)
    text = text.replace('MAGIC', str(int.from_bytes(b'HIAQUT01', 'little')))
    text = text.replace('SUCCESS', str(int.from_bytes(b'HIAQOK01', 'little')))
    names = b'\0.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0'
    tests = []
    for at in range(0, len(names), 8):
        chunk = names[at:at + 8]
        tests.append(f'    if uint(s, at + {at}, {len(chunk)}) != {int.from_bytes(chunk, "little")}:\n        return 0')
    return text.replace('NAME_TESTS', '\n'.join(tests))


if __name__ == '__main__':
    path = ROOT / 'examples/hia_bootstrap/cold_qualification_util.hepta'
    path.write_text(render_assembly(document(source(), 'cold_qualification_util')))
    print(path.name, path.stat().st_size)
