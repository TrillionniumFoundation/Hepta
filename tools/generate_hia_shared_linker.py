"""Author the HIA linker for the direct emitter's single owned x86-64 object."""

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_elf_linker import LinkerBuilder, SOURCE as STATIC_SOURCE


SECTION_NAMES = ('.text', '.plt', '.dynstr', '.dynsym', '.hash', '.gnu.hash',
                 '.rela.dyn', '.got', '.dynamic', '.shstrtab')
IMPORTS = ('abort', 'calloc', 'malloc', 'free', 'memset', 'memcpy', 'memmove')

SOURCE = '''
def link_shared(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1048576:
        return 4294967294
    if object_layout(s, w) == 0:
        return 4294967295
    if symbols(s, w) == 0 or check_calls(s, w) == 0:
        return 4294967295
    layout(w)
    total = get(w, 232) + 704
    if length(o) < total:
        return 4294967294
    zero(o, total)
    headers(o, w)
    copy_bytes(s, o, get(w, 56), 400, get(w, 64))
    copy_bytes(s, o, get(w, 0), get(w, 160), get(w, 8))
    declarations(s, o, w)
    calls(s, o, w)
    dynamic(o, w)
    section_names(o, get(w, 224))
    return total

def object_layout(s:readbuf, w:mutbuf) -> u64:
    size = length(s)
    if size < 512 or size > 67108864:
        return 0
    if uint(s, 0, 8) != 282584257676671 or uint(s, 8, 8) != 0:
        return 0
    if uint(s, 16, 8) != 4299030529 or uint(s, 24, 8) != 0 or uint(s, 32, 8) != 0:
        return 0
    if uint(s, 48, 8) != 274877906944 or uint(s, 56, 8) != 1407404952518656:
        return 0
    h = uint(s, 40, 8)
    if h < 64 or h != size - 448 or (h & 7) != 0:
        return 0
    if uint(s, h + 68, 4) != 1 or uint(s, h + 72, 8) != 6:
        return 0
    text = uint(s, h + 88, 8)
    text_size = uint(s, h + 96, 8)
    align = uint(s, h + 112, 8)
    if align != 16 and align != 32 and align != 64:
        return 0
    if text < 64 or (text & (align - 1)) != 0 or text_size == 0 or text_size > 16777216 or within(h, text, text_size) == 0:
        return 0
    if uint(s, h + 132, 4) != 4 or uint(s, h + 136, 8) != 0 or uint(s, h + 168, 8) != 4294967299 or uint(s, h + 184, 8) != 24:
        return 0
    rela = uint(s, h + 152, 8)
    rela_size = uint(s, h + 160, 8)
    if rela < text + text_size or (rela & 7) != 0 or rela_size % 24 != 0 or rela_size / 24 > text_size / 5 or within(h, rela, rela_size) == 0:
        return 0
    if uint(s, h + 196, 4) != 2 or uint(s, h + 200, 8) != 0 or uint(s, h + 232, 4) != 4 or uint(s, h + 248, 8) != 24:
        return 0
    sym = uint(s, h + 216, 8)
    sym_size = uint(s, h + 224, 8)
    first_global = uint(s, h + 236, 4)
    if sym < rela + rela_size or (sym & 7) != 0 or sym_size < 72 or sym_size > 1572864 or sym_size % 24 != 0 or within(h, sym, sym_size) == 0:
        return 0
    if first_global < 2 or first_global >= sym_size / 24:
        return 0
    if uint(s, h + 260, 4) != 3 or uint(s, h + 264, 8) != 0:
        return 0
    strings = uint(s, h + 280, 8)
    strings_size = uint(s, h + 288, 8)
    if strings < sym + sym_size or strings_size == 0 or within(h, strings, strings_size) == 0 or byte(s, strings) != 0:
        return 0
    if uint(s, sym, 8) != 0 or uint(s, sym + 8, 8) != 0 or uint(s, sym + 16, 8) != 0:
        return 0
    if uint(s, sym + 24, 8) != 281487861612544 or uint(s, sym + 32, 8) != 0 or uint(s, sym + 40, 8) != 0:
        return 0
    put(w, 0, text)
    put(w, 8, text_size)
    put(w, 16, rela)
    put(w, 24, rela_size / 24)
    put(w, 32, sym)
    put(w, 40, sym_size / 24)
    put(w, 48, first_global)
    put(w, 56, strings)
    put(w, 64, strings_size)
    return 1

def symbols(s:readbuf, w:mutbuf) -> u64:
    exports = 0
    imports = 0
    imported_names = 0
    stub_base = aligned(get(w, 8), 16)
    i = 2
    while i < get(w, 40):
        entry = get(w, 32) + i * 24
        name = uint(s, entry, 4)
        if name == 0 or name >= get(w, 64):
            return 0
        first = get(w, 56) + name
        end = get(w, 56) + get(w, 64)
        if name_length(s, first, end) == 0:
            return 0
        tag = uint(s, entry + 4, 4)
        value = uint(s, entry + 8, 8)
        extent = uint(s, entry + 16, 8)
        if i < get(w, 48):
            if tag != 66050 or extent == 0 or within(get(w, 8), value, extent) == 0:
                return 0
        elif tag == 65554:
            if imports != 0 or exports == 128 or extent == 0 or within(get(w, 8), value, extent) == 0:
                return 0
            exports = exports + 1
        else:
            if tag != 16 or value != 0 or extent != 0:
                return 0
            import_name = allowed_import(s, first, end)
            if import_name == 0 or (import_name & imported_names) != 0:
                return 0
            imported_names = imported_names | import_name
            value = stub_base + imports * 16
            imports = imports + 1
        put(w, 256 + i * 8, value)
        i = i + 1
    if exports == 0:
        return 0
    put(w, 72, exports)
    put(w, 80, imports)
    put(w, 88, imports + exports + 1)
    return 1

def name_length(s:readbuf, first:u64, end:u64) -> u64:
    i = first
    while i < end and i - first <= 192:
        ch = byte(s, i)
        if ch == 0:
            return i - first
        if (ch < 65 or ch > 90) and (ch < 97 or ch > 122) and ch != 95:
            if i == first or ch < 48 or ch > 57:
                return 0
        i = i + 1
    return 0

def allowed_import(s:readbuf, first:u64, end:u64) -> u64:
@ALLOWED_IMPORTS@
    return 0

def check_calls(s:readbuf, w:mutbuf) -> u64:
    at = get(w, 16)
    last = 0
    i = 0
    while i < get(w, 24):
        place = uint(s, at, 8)
        symbol = uint(s, at + 12, 4)
        if symbol < 2 or symbol >= get(w, 40) or uint(s, at + 8, 4) != 4 or uint(s, at + 16, 8) != 18446744073709551612:
            return 0
        if place == 0 or (i != 0 and place < last + 5) or within(get(w, 8), place, 4) == 0:
            return 0
        if uint(s, get(w, 0) + place - 1, 5) != 232:
            return 0
        last = place
        at = at + 24
        i = i + 1
    return 1

def layout(w:mutbuf) -> u64:
    size = get(w, 64)
    if get(w, 80) != 0:
        size = size + 10
    symbols = aligned(400 + size, 8)
    sysv = symbols + get(w, 88) * 24
    gnu = aligned(sysv + 12 + get(w, 88) * 4, 8)
    rela = aligned(gnu + 28 + get(w, 72) * 4, 8)
    rx = aligned(rela + get(w, 80) * 24, 4096)
    stub = rx + aligned(get(w, 8), 16)
    rx_end = stub + get(w, 80) * 16
    if get(w, 80) == 0:
        rx_end = rx + get(w, 8)
    rw = aligned(rx_end, 4096)
    dynamic_size = 128
    if get(w, 80) != 0:
        dynamic_size = 192
    put(w, 96, size)
    put(w, 104, symbols)
    put(w, 112, sysv)
    put(w, 120, gnu)
    put(w, 128, rela)
    put(w, 136, rx_end)
    put(w, 144, dynamic_size)
    put(w, 160, rx)
    put(w, 168, stub)
    put(w, 176, rw)
    put(w, 184, rw + dynamic_size)
    put(w, 224, rw + 4096)
    put(w, 232, aligned(rw + 4096 + @SECTION_LEN@, 8))
    return 0

def declarations(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    count = get(w, 88)
    first = get(w, 80) + 1
    sysv = get(w, 112)
    gnu = get(w, 120)
    write(o, sysv, 1, 4)
    write(o, sysv + 4, count, 4)
    write(o, sysv + 8, first, 4)
    write(o, gnu, 1, 4)
    write(o, gnu + 4, first, 4)
    write(o, gnu + 8, 1, 4)
    write(o, gnu + 12, 6, 4)
    put(o, gnu + 16, 18446744073709551615)
    write(o, gnu + 24, first, 4)
    base = get(w, 32) + get(w, 48) * 24
    i = 0
    while i < get(w, 72):
        at = base + i * 24
        name = uint(s, at, 4)
        sym = get(w, 104) + (first + i) * 24
        write(o, sym, name, 4)
        write(o, sym + 4, 65554, 4)
        put(o, sym + 8, get(w, 160) + uint(s, at + 8, 8))
        put(o, sym + 16, uint(s, at + 16, 8))
        hash = gnu_hash(s, get(w, 56) + name)
        if first + i + 1 == count:
            hash = hash | 1
        else:
            write(o, sysv + 12 + (first + i) * 4, first + i + 1, 4)
            hash = hash & 4294967294
        write(o, gnu + 28 + i * 4, hash, 4)
        i = i + 1
    if get(w, 80) != 0:
        put(o, 400 + get(w, 64), 3346019691232651628)
        write(o, 408 + get(w, 64), 54, 2)
    i = 0
    while i < get(w, 80):
        old = base + (get(w, 72) + i) * 24
        sym = get(w, 104) + (i + 1) * 24
        write(o, sym, uint(s, old, 4), 4)
        write(o, sym + 4, 16, 4)
        stub = get(w, 168) + i * 16
        got = get(w, 184) + i * 8
        write(o, stub, 9727, 2)
        write(o, stub + 2, got - stub - 6, 4)
        rela = get(w, 128) + i * 24
        put(o, rela, got)
        put(o, rela + 8, ((i + 1) << 32) | 6)
        i = i + 1
    return 0

def gnu_hash(s:readbuf, first:u64) -> u64:
    hash = 5381
    while byte(s, first) != 0:
        hash = (hash * 33 + byte(s, first)) & 4294967295
        first = first + 1
    return hash

def calls(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = get(w, 16)
    i = 0
    while i < get(w, 24):
        place = uint(s, at, 8)
        symbol = uint(s, at + 12, 4)
        target = get(w, 256 + symbol * 8)
        write(o, get(w, 160) + place, target - place - 4, 4)
        at = at + 24
        i = i + 1
    return 0

def dynamic(o:mutbuf, w:mutbuf) -> u64:
    at = get(w, 176)
    tag(o, at, 5, 400)
    tag(o, at + 16, 6, get(w, 104))
    tag(o, at + 32, 10, get(w, 96))
    tag(o, at + 48, 11, 24)
    tag(o, at + 64, 4, get(w, 112))
    tag(o, at + 80, 1879047925, get(w, 120))
    tag(o, at + 96, 30, 8)
    if get(w, 80) != 0:
        tag(o, at + 112, 1, get(w, 64))
        tag(o, at + 128, 7, get(w, 128))
        tag(o, at + 144, 8, get(w, 80) * 24)
        tag(o, at + 160, 9, 24)
    return 0

def tag(o:mutbuf, at:u64, kind:u64, value:u64) -> u64:
    put(o, at, kind)
    put(o, at + 8, value)
    return 0

def headers(o:mutbuf, w:mutbuf) -> u64:
    put(o, 0, 282584257676671)
    put(o, 16, 4299030531)
    put(o, 32, 64)
    put(o, 40, get(w, 232))
    write(o, 52, 64, 2)
    write(o, 54, 56, 2)
    write(o, 56, 6, 2)
    write(o, 58, 64, 2)
    write(o, 60, 11, 2)
    write(o, 62, 10, 2)
    rx = get(w, 160)
    rw = get(w, 176)
    segment(o, 64, 1, 4, 0, rx, rx, 4096)
    segment(o, 120, 1, 5, rx, get(w, 136) - rx, get(w, 136) - rx, 4096)
    segment(o, 176, 1, 6, rw, get(w, 144) + get(w, 80) * 8, 4096, 4096)
    segment(o, 232, 2, 6, rw, get(w, 144), get(w, 144), 8)
    segment(o, 288, 1685382481, 6, 0, 0, 0, 16)
    segment(o, 344, 1685382482, 4, rw, get(w, 144) + get(w, 80) * 8, 4096, 1)
    at = get(w, 232) + 64
    section(o, at, @TEXT@, 1, 6, rx, get(w, 8), 0, 0, 16, 0)
    section(o, at + 64, @PLT@, 1, 6, get(w, 168), get(w, 80) * 16, 0, 0, 16, 16)
    section(o, at + 128, @DYNSTR@, 3, 2, 400, get(w, 96), 0, 0, 1, 0)
    section(o, at + 192, @DYNSYM@, 11, 2, get(w, 104), get(w, 88) * 24, 3, 1, 8, 24)
    section(o, at + 256, @HASH@, 5, 2, get(w, 112), 12 + get(w, 88) * 4, 4, 0, 4, 4)
    section(o, at + 320, @GNU_HASH@, 1879048182, 2, get(w, 120), 28 + get(w, 72) * 4, 4, 0, 8, 0)
    section(o, at + 384, @RELA_DYN@, 4, 2, get(w, 128), get(w, 80) * 24, 4, 0, 8, 24)
    section(o, at + 448, @GOT@, 1, 3, get(w, 184), get(w, 80) * 8, 0, 0, 8, 8)
    section(o, at + 512, @DYNAMIC@, 6, 3, rw, get(w, 144), 3, 0, 8, 16)
    section(o, at + 576, @SHSTRTAB@, 3, 0, get(w, 224), @SECTION_LEN@, 0, 0, 1, 0)
    return 0

def segment(o:mutbuf, at:u64, kind:u64, flags:u64, offset:u64, size:u64, memory:u64, align:u64) -> u64:
    write(o, at, kind, 4)
    write(o, at + 4, flags, 4)
    put(o, at + 8, offset)
    put(o, at + 16, offset)
    put(o, at + 24, offset)
    put(o, at + 32, size)
    put(o, at + 40, memory)
    put(o, at + 48, align)
    return 0

def section(o:mutbuf, at:u64, name:u64, kind:u64, flags:u64, offset:u64, size:u64, link:u64, info:u64, align:u64, entry:u64) -> u64:
    write(o, at, name, 4)
    write(o, at + 4, kind, 4)
    put(o, at + 8, flags)
    if flags != 0:
        put(o, at + 16, offset)
    put(o, at + 24, offset)
    put(o, at + 32, size)
    write(o, at + 40, link, 4)
    write(o, at + 44, info, 4)
    put(o, at + 48, align)
    put(o, at + 56, entry)
    return 0

def section_names(o:mutbuf, at:u64) -> u64:
@SECTION_NAME_WRITES@
    return 0

def zero(o:mutbuf, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, i, 0)
        i = i + 1
    return 0
'''


def source_program():
    sections = bytearray(b'\0')
    source = SOURCE
    for name in SECTION_NAMES:
        source = source.replace('@' + name[1:].upper().replace('.', '_') + '@', str(len(sections)))
        sections.extend(name.encode('ascii') + b'\0')
    writes = []
    for offset in range(0, len(sections), 8):
        part = sections[offset:offset + 8]
        writes.append(f'    write(o, at + {offset}, {int.from_bytes(part, "little")}, {len(part)})')
    imports = []
    for bit, name in enumerate(IMPORTS):
        word = name.encode('ascii') + b'\0'
        imports.append(f'    if end - first >= {len(word)} and uint(s, first, {len(word)}) == {int.from_bytes(word, "little")}:')
        imports.append(f'        return {1 << bit}')
    return (source.replace('@SECTION_LEN@', str(len(sections)))
            .replace('@SECTION_NAME_WRITES@', '\n'.join(writes))
            .replace('@ALLOWED_IMPORTS@', '\n'.join(imports))
            .replace(' / ', ' // ')
            + '\ndef within(' + STATIC_SOURCE.split('\ndef within(', 1)[1])


def document(source=None, module='elf_shared_linker'):
    nodes = ast.parse(source_program() if source is None else source).body
    names = {node.name: f'f{index}' for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(value) for value in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': module,
                                  'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/elf_shared_linker.hepta'
    target.write_text(render_assembly(document()))
