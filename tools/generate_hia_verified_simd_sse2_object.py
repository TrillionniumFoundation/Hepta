"""Author the HIA SSE2 object producer for the three closed byte recurrences.

The runtime builds each instruction, resolves branches between named stages,
and writes one ELF relocation for the external abort call.
"""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_elf_linker import SOURCE as ELF
from tools.generate_hia_shared_linker import document, SOURCE as SHARED
from tools.generate_hia_elf_verified_linker import _shared_function

MOD = 'verified_simd_sse2_object'
LABELS = ('bulk', 'vector', 'merge', 'horizontal', 'tail', 'done', 'abort', 'admitted')
SOURCE = """
def produce(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 33 or length(s) > 160 or length(o) < 2048 or length(w) < 2048:
        return 0
    n = uint(s, 16, 8)
    shape = uint(s, 8, 8)
    if uint(s, 0, 8) != SUBJECT or n < 1 or n > 128 or length(s) != n + 32 or uint(s, 24 + n, 8) != 1:
        return 0
    if shape < 1 or shape > 3 or symbol(s, n) == 0:
        return 0
    zero(o, 2048)
    put(w, 0, 64)
    put(w, 8, 0)
    if shape == 3:
        copy_guards(o, w)
    else:
        reduce_guards(o, w, shape)
    loops(o, w, shape)
    label(w, DONE)
    if shape == 2:
        emit(o, w, '48 85 c0 b8 00 00 00 00')
        emit(o, w, '40 0f 94 c0')
    emit(o, w, 'c3')
    label(w, ABORT)
    emit(o, w, '48 83 ec 08 e8')
    reloc = get(w, 0) - 64
    emit(o, w, '00 00 00 00 0f 0b')
    i = 0
    while i < get(w, 8):
        row = 128 + i * 16
        at = get(w, row)
        to = get(w, 32 + get(w, row + 8) * 8)
        write(o, at, to - at - 4, 4)
        i = i + 1
    return obj(s, o, n, get(w, 0) - 64, reloc)

def reduce_guards(o:mutbuf, w:mutbuf, shape:u64) -> u64:
    emit(o, w, 'b8 00 00 00 00 48 39 f2')
    jcc(o, w, 135, ABORT)
    emit(o, w, '48 85 d2')
    jcc(o, w, 132, DONE)
    emit(o, w, '48 85 ff')
    jcc(o, w, 132, ABORT)
    emit(o, w, '49 89 f9 49 01 d1')
    jcc(o, w, 130, ABORT)
    emit(o, w, '49 89 d2 66 0f ef c0')
    emit(o, w, '66 0f ef d2')
    if shape == 2:
        emit(o, w, '66 0f ef db 66 0f ef e4')
        emit(o, w, '66 0f ef ed')
    return 0

def copy_guards(o:mutbuf, w:mutbuf) -> u64:
    emit(o, w, '4c 89 c0 49 39 f0')
    jcc(o, w, 135, ABORT)
    emit(o, w, '49 39 c8')
    jcc(o, w, 135, ABORT)
    emit(o, w, '4d 85 c0')
    jcc(o, w, 132, DONE)
    emit(o, w, '48 85 ff')
    jcc(o, w, 132, ABORT)
    emit(o, w, '49 89 f9 4d 01 c1')
    jcc(o, w, 130, ABORT)
    emit(o, w, '48 85 d2')
    jcc(o, w, 132, ABORT)
    emit(o, w, '49 89 d2 4d 01 c2')
    jcc(o, w, 130, ABORT)
    emit(o, w, '49 39 d1')
    jcc(o, w, 134, ADMITTED)
    emit(o, w, '49 39 fa')
    jcc(o, w, 135, ABORT)
    label(w, ADMITTED)
    emit(o, w, '4d 89 c2')
    return 0

def loops(o:mutbuf, w:mutbuf, shape:u64) -> u64:
    label(w, BULK)
    emit(o, w, '49 83 fa 40')
    jcc(o, w, 130, MERGE)
    i = 0
    while i < 4:
        chunk(o, w, shape, i)
        i = i + 1
    advance(o, w, shape, 64)
    jump(o, w, BULK)
    label(w, MERGE)
    if shape == 2:
        emit(o, w, '66 0f eb c3 66 0f eb c4')
        emit(o, w, '66 0f eb c5')
    label(w, VECTOR)
    emit(o, w, '49 83 fa 10')
    jcc(o, w, 130, HORIZONTAL)
    chunk(o, w, shape, 0)
    advance(o, w, shape, 16)
    jump(o, w, VECTOR)
    label(w, HORIZONTAL)
    if shape != 3:
        emit(o, w, '66 48 0f 7e c0')
        emit(o, w, '66 0f 73 d8 08')
        emit(o, w, '66 49 0f 7e c1')
        reduce_scalar(o, w, shape)
    label(w, TAIL)
    emit(o, w, '4d 85 d2')
    jcc(o, w, 132, DONE)
    if shape == 3:
        emit(o, w, '4c 0f b6 8a 00 00 00 00')
        emit(o, w, '44 88 8f 00 00 00 00')
    else:
        emit(o, w, '4c 0f b6 8f 00 00 00 00')
        reduce_scalar(o, w, shape)
    advance(o, w, shape, 1)
    jump(o, w, TAIL)
    return 0

def reduce_scalar(o:mutbuf, w:mutbuf, shape:u64) -> u64:
    if shape == 1:
        emit(o, w, '4c 01 c8')
    else:
        emit(o, w, '4c 09 c8')
    return 0

def chunk(o:mutbuf, w:mutbuf, shape:u64, index:u64) -> u64:
    emit(o, w, 'f3 0f 6f')
    address(o, w, choose(shape == 3, 10, 15), index)
    if shape == 3:
        emit(o, w, 'f3 0f 7f')
        address(o, w, 15, index)
    elif shape == 1:
        emit(o, w, '66 0f f6 ca 66 0f d4 c1')
    else:
        emit(o, w, '66 0f eb')
        append(o, w, 193 + choose(index == 0, 0, (index + 2) * 8), 1)
    return 0

def address(o:mutbuf, w:mutbuf, base:u64, index:u64) -> u64:
    if index == 0:
        append(o, w, base, 1)
    else:
        append(o, w, base + 64, 1)
        append(o, w, index * 16, 1)
    return 0

def advance(o:mutbuf, w:mutbuf, shape:u64, count:u64) -> u64:
    emit(o, w, '48 83 c7')
    append(o, w, count, 1)
    if shape == 3:
        emit(o, w, '48 83 c2')
        append(o, w, count, 1)
    emit(o, w, '49 83 ea')
    append(o, w, count, 1)
    return 0

def label(w:mutbuf, id:u64) -> u64:
    return put(w, 32 + id * 8, get(w, 0))

def jcc(o:mutbuf, w:mutbuf, condition:u64, destination:u64) -> u64:
    append(o, w, 15 + (condition << 8), 2)
    return fixup(o, w, destination)

def jump(o:mutbuf, w:mutbuf, destination:u64) -> u64:
    append(o, w, 233, 1)
    return fixup(o, w, destination)

def fixup(o:mutbuf, w:mutbuf, destination:u64) -> u64:
    count = get(w, 8)
    put(w, 128 + count * 16, get(w, 0))
    put(w, 136 + count * 16, destination)
    put(w, 8, count + 1)
    return append(o, w, 0, 4)

def append(o:mutbuf, w:mutbuf, value:u64, n:u64) -> u64:
    at = get(w, 0)
    write(o, at, value, n)
    return put(w, 0, at + n)

def symbol(s:readbuf, n:u64) -> u64:
    i = 0
    while i < n:
        ch = byte(s, 24 + i)
        if ch != 95 and (ch < 65 or ch > 90) and (ch < 97 or ch > 122):
            if i == 0 or ch < 48 or ch > 57:
                return 0
        i = i + 1
    if n == 5 and uint(s, 24, 5) == ABORT_NAME:
        return 0
    return 1

def obj(s:readbuf, o:mutbuf, n:u64, text:u64, reloc:u64) -> u32:
    rela = (64 + text + 7) & 18446744073709551608
    sym = rela + 24
    strings = sym + 96
    end = strings + n + 8
    sections = (end + SECTION_BYTES + 7) & 18446744073709551608
    name = 1
    abort = n + 2
    before = 0
    i = 0
    while i < 5 and i < n:
        a = byte(s, 24 + i)
        b = (ABORT_NAME >> (i * 8)) & 255
        if a != b:
            before = choose(a > b, 1, 0)
            i = 5
        else:
            i = i + 1
            if i == 5:
                before = choose(n > 5, 1, 0)
    if before == 1:
        abort = 1
        name = 7
    copy_bytes(s, o, 24, strings + name, n)
    write(o, strings + abort, ABORT_NAME, 5)
    put(o, 0, 282584257676671)
    put(o, 16, 4299030529)
    put(o, 40, sections)
    put(o, 52, 18014398509482048)
    write(o, 60, 327687, 4)
    put(o, rela, reloc)
    put(o, rela + 8, 12884901892)
    put(o, rela + 16, 18446744073709551612)
    write(o, sym + 28, 65539, 4)
    write(o, sym + 48, name, 4)
    write(o, sym + 52, 65554, 4)
    put(o, sym + 64, text)
    write(o, sym + 72, abort, 4)
    write(o, sym + 76, 16, 4)
    section(o, sections + 64, 1, 1, 6, 64, text, 0, 0, 16, 0)
    section(o, sections + 128, 7, 4, 0, rela, 24, 3, 1, 8, 24)
    section(o, sections + 192, 18, 2, 0, sym, 96, 4, 2, 8, 24)
    section(o, sections + 256, 26, 3, 0, strings, n + 8, 0, 0, 1, 0)
    section(o, sections + 320, 34, 3, 0, end, SECTION_BYTES, 0, 0, 1, 0)
    section(o, sections + 384, 44, 1, 0, end + SECTION_BYTES, 0, 0, 0, 1, 0)
    names(o, end)
    return sections + 448
"""

def program():
    def emit(match):
        data = bytes.fromhex(match[1])
        assert 1 <= len(data) <= 8
        return f'append(o, w, {int.from_bytes(data, "little")}, {len(data)})'
    policy = re.sub(r"emit\(o, w, '([a-f0-9 ]+)'\)", emit, SOURCE)
    names = b'\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab\0.note.GNU-stack\0'
    for token, value in {'SUBJECT': int.from_bytes(b'HIASIMC1','little'),
                         'SECTION_BYTES':len(names), 'ABORT_NAME':int.from_bytes(b'abort','little'),
                         **{label.upper():i for i,label in enumerate(LABELS)}}.items():
        policy = re.sub(r'\b' + token + r'\b', str(value), policy)
    policy += '\ndef names(o:mutbuf, at:u64) -> u64:\n'
    for i in range(0, len(names), 8):
        part = names[i:i+8]
        policy += f'    write(o, at + {i}, {int.from_bytes(part,"little")}, {len(part)})\n'
    policy += '    return 0\n'
    section = _shared_function('section', 'section_names').replace(
        '    if flags != 0:\n        put(o, at + 16, offset)\n','')
    helpers = ELF[ELF.index('def uint('):]
    return document(policy + section + '\ndef zero(' + SHARED.split('\ndef zero(', 1)[1] + '\n' + helpers, MOD)


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap' / (MOD + '.hepta')
    target.write_text(render_assembly(program()))
