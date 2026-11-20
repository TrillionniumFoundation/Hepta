"""Author the bounded HIA linker for independently validated Safe Core ELF images.

This producer handles the one-export, one-abort-slot layout only. The
independent ELF and machine validators still decide whether bytes may publish.
"""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_elf_linker import SOURCE as STATIC_SOURCE
from tools.generate_hia_shared_linker import SOURCE as SHARED_SOURCE, document


SECTION_NAMES = (
    '.hash', '.gnu.hash', '.dynsym', '.dynstr', '.gnu.version', '.gnu.version_r',
    '.rela.plt', '.plt', '.text', '.eh_frame', '.dynamic', '.got', '.symtab',
    '.strtab', '.shstrtab',
)

# Slots 0..64 retain the ordinary linker's source inventory. Remaining slots
# carry the checked export row followed by output table/segment positions.
SOURCE = '''
def link_verified(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 512:
        return 4294967294
    if object_layout(s, w) == 0:
        return 4294967295
    if closed_object(s, w) == 0 or check_calls(s, w) == 0 or resolve_calls(s, w) == 0:
        return 4294967295
    layout(w)
    total = get(w, 216) + 1024
    if length(o) < total:
        return 4294967294
    zero(o, total)
    headers(o, w)
    copy_bytes(s, o, get(w, 56), 400, get(w, 64))
    copy_bytes(s, o, get(w, 56), get(w, 200), get(w, 64))
    copy_bytes(s, o, get(w, 0), 4128, get(w, 8))
    tables(s, o, w)
    dynamic(o, w)
    link_calls(s, o, w)
    write_names(o, get(w, 208))
    return total

def closed_object(s:readbuf, w:mutbuf) -> u64:
    if get(w, 8) > 65536 or get(w, 64) > 512:
        return 0
    first_global = get(w, 48)
    if (first_global != 2 and first_global != 3) or get(w, 40) != first_global + 2 or get(w, 24) != first_global - 1:
        return 0
    export = get(w, 32) + first_global * 24
    abort = export + 24
    name = uint(s, export, 4)
    abort_name = uint(s, abort, 4)
    end = get(w, 56) + get(w, 64)
    if name == 0 or name >= get(w, 64) or abort_name == 0 or abort_name >= get(w, 64):
        return 0
    if name_length(s, get(w, 56) + name, end) == 0:
        return 0
    if uint(s, export + 4, 4) != 65554 or uint(s, abort + 4, 4) != 16:
        return 0
    if uint(s, abort + 8, 8) != 0 or uint(s, abort + 16, 8) != 0:
        return 0
    abort_begin = get(w, 56) + abort_name
    if end - abort_begin < 6 or uint(s, abort_begin, 6) != 500136108641:
        return 0
    local_size = 0
    if first_global == 3:
        local = export - 24
        local_name = uint(s, local, 4)
        if local_name == 0 or local_name >= get(w, 64):
            return 0
        start = get(w, 56) + local_name
        if end - start < 18 or uint(s, start, 8) != 7020653741102096223 or uint(s, start + 8, 8) != 6876546240951511412 or uint(s, start + 16, 2) != 48:
            return 0
        if uint(s, local + 4, 4) != 66050 or uint(s, local + 8, 8) != 0:
            return 0
        local_size = uint(s, local + 16, 8)
        if local_size == 0:
            return 0
    if local_size >= get(w, 8) or uint(s, export + 8, 8) != local_size or uint(s, export + 16, 8) != get(w, 8) - local_size:
        return 0
    put(w, 72, export)
    put(w, 80, name)
    put(w, 88, abort_name)
    return 1

def resolve_calls(s:readbuf, w:mutbuf) -> u64:
    abort = get(w, 48) + 1
    seen = 0
    i = 0
    while i < get(w, 24):
        symbol = uint(s, get(w, 16) + i * 24 + 12, 4)
        if symbol == abort:
            if (seen & 1) != 0:
                return 0
            seen = seen | 1
        elif symbol == 2 and abort == 4:
            if (seen & 2) != 0:
                return 0
            seen = seen | 2
        else:
            return 0
        i = i + 1
    if seen == 1 + (abort - 3) * 2:
        return 1
    return 0

def layout(w:mutbuf) -> u64:
    strings = get(w, 64) + 22
    dynsym = aligned(400 + strings, 8)
    sysv = dynsym + 72
    gnu = sysv + 24
    versions = gnu + 32
    needed = aligned(versions + 6, 8)
    rela = needed + 32
    rx_end = 4128 + get(w, 8)
    rw = aligned(rx_end, 4096)
    symtab = rw + 4096
    strtab = symtab + get(w, 40) * 24
    names = strtab + get(w, 64)
    put(w, 96, strings)
    put(w, 104, dynsym)
    put(w, 112, sysv)
    put(w, 120, gnu)
    put(w, 128, versions)
    put(w, 136, needed)
    put(w, 144, rela)
    put(w, 152, rx_end)
    put(w, 160, rw)
    put(w, 168, rw + 288)
    put(w, 192, symtab)
    put(w, 200, strtab)
    put(w, 208, names)
    put(w, 216, aligned(names + @SECTION_LEN@, 8))
    return 0

def tables(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    strings = 400 + get(w, 64)
    write(o, strings, 3346019691232651628, 8)
    write(o, strings + 8, 54, 2)
    write(o, strings + 10, 3328827817059765319, 8)
    write(o, strings + 18, 3485234, 4)
    syms = get(w, 104)
    symbol(o, syms + 24, get(w, 88), 18, 0, 0)
    symbol(o, syms + 48, get(w, 80), 589842, 4128 + uint(s, get(w, 72) + 8, 8),
           uint(s, get(w, 72) + 16, 8))
    i = 1
    while i < get(w, 40):
        orig = get(w, 32) + i * 24
        name = uint(s, orig, 4)
        tag = uint(s, orig + 4, 4)
        value = uint(s, orig + 8, 8)
        size = uint(s, orig + 16, 8)
        if (tag >> 16) == 1:
            tag = (tag & 65535) | 589824
            value = value + 4128
        symbol(o, get(w, 192) + i * 24, name, tag, value, size)
        i = i + 1
    sysv = get(w, 112)
    write(o, sysv, 1, 4)
    write(o, sysv + 4, 3, 4)
    write(o, sysv + 8, 1, 4)
    write(o, sysv + 16, 2, 4)
    gnu = get(w, 120)
    value = gnu_hash(s, get(w, 56) + get(w, 80))
    put(o, gnu, 8589934593)
    put(o, gnu + 8, 21474836481)
    put(o, gnu + 16, (1 << (value & 63)) | (1 << ((value >> 5) & 63)))
    write(o, gnu + 24, 2, 4)
    write(o, gnu + 28, value | 1, 4)
    vers = get(w, 128)
    write(o, vers + 2, 2, 2)
    write(o, vers + 4, 1, 2)
    needed = get(w, 136)
    write(o, needed, 65537, 4)
    write(o, needed + 4, get(w, 64), 4)
    write(o, needed + 8, 16, 4)
    write(o, needed + 16, 157882997, 4)
    write(o, needed + 22, 2, 2)
    write(o, needed + 24, get(w, 64) + 10, 4)
    return 0

def symbol(o:mutbuf, at:u64, name:u64, tag:u64, value:u64, size:u64) -> u64:
    write(o, at, name, 4)
    write(o, at + 4, tag, 4)
    put(o, at + 8, value)
    put(o, at + 16, size)
    return 0

def link_calls(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    got = get(w, 168)
    rela = get(w, 144)
    put(o, rela, got + 24)
    put(o, rela + 8, 4294967303)
    put(o, got, get(w, 160))
    put(o, got + 24, 4118)
    write(o, 4096, 13823, 2)
    write(o, 4098, got + 8 - 4102, 4)
    write(o, 4102, 9727, 2)
    write(o, 4104, got + 16 - 4108, 4)
    write(o, 4108, 4202255, 4)
    write(o, 4112, 9727, 2)
    write(o, 4114, got + 24 - 4118, 4)
    write(o, 4118, 104, 1)
    write(o, 4123, 233, 1)
    write(o, 4124, 4294967264, 4)
    i = 0
    while i < get(w, 24):
        row = get(w, 16) + i * 24
        place = uint(s, row, 8)
        target = 4112
        if uint(s, row + 12, 4) == 2:
            target = 4128
        write(o, 4128 + place, target - (4128 + place + 4), 4)
        i = i + 1
    return 0

def dynamic(o:mutbuf, w:mutbuf) -> u64:
    at = get(w, 160)
    tag(o, at, 1, get(w, 64))
    tag(o, at + 16, 2, 24)
    tag(o, at + 32, 3, get(w, 168))
    tag(o, at + 48, 4, get(w, 112))
    tag(o, at + 64, 5, 400)
    tag(o, at + 80, 6, get(w, 104))
    tag(o, at + 96, 10, get(w, 96))
    tag(o, at + 112, 11, 24)
    tag(o, at + 128, 20, 7)
    tag(o, at + 144, 23, get(w, 144))
    tag(o, at + 160, 30, 8)
    tag(o, at + 176, 1879047925, get(w, 120))
    tag(o, at + 192, 1879048187, 1)
    tag(o, at + 208, 1879048190, get(w, 136))
    tag(o, at + 224, 1879048191, 1)
    tag(o, at + 240, 1879048176, get(w, 128))
    return 0

def headers(o:mutbuf, w:mutbuf) -> u64:
    put(o, 0, 282584257676671)
    put(o, 16, 4299030531)
    put(o, 32, 64)
    put(o, 40, get(w, 216))
    write(o, 52, 64, 2)
    write(o, 54, 56, 2)
    write(o, 56, 6, 2)
    write(o, 58, 64, 2)
    write(o, 60, 16, 2)
    write(o, 62, 15, 2)
    rw = get(w, 160)
    rx_size = get(w, 152) - 4096
    segment(o, 64, 1, 4, 0, 4096, 4096, 4096)
    segment(o, 120, 1, 5, 4096, rx_size, rx_size, 4096)
    segment(o, 176, 1, 6, rw, 4096, 4096, 4096)
    segment(o, 232, 2, 6, rw, 272, 272, 8)
    segment(o, 288, 1685382481, 6, 0, 0, 0, 16)
    segment(o, 344, 1685382482, 4, rw, 4096, 4096, 1)
    at = get(w, 216)
    section(o, at + 64, @HASH@, 5, 2, get(w, 112), 24, 3, 0, 4, 4)
    section(o, at + 128, @GNU_HASH@, 1879048182, 2, get(w, 120), 32, 3, 0, 8, 0)
    section(o, at + 192, @DYNSYM@, 11, 2, get(w, 104), 72, 4, 1, 8, 24)
    section(o, at + 256, @DYNSTR@, 3, 2, 400, get(w, 96), 0, 0, 1, 0)
    section(o, at + 320, @GNU_VERSION@, 1879048191, 2, get(w, 128), 6, 3, 0, 2, 2)
    section(o, at + 384, @GNU_VERSION_R@, 1879048190, 2, get(w, 136), 32, 4, 1, 8, 0)
    section(o, at + 448, @RELA_PLT@, 4, 66, get(w, 144), 24, 3, 12, 8, 24)
    section(o, at + 512, @PLT@, 1, 6, 4096, 32, 0, 0, 16, 16)
    section(o, at + 576, @TEXT@, 1, 6, 4128, get(w, 8), 0, 0, 16, 0)
    section(o, at + 640, @EH_FRAME@, 1, 2, rw, 0, 0, 0, 8, 0)
    section(o, at + 704, @DYNAMIC@, 6, 3, rw, 272, 4, 0, 8, 16)
    section(o, at + 768, @GOT@, 1, 3, get(w, 168), 32, 0, 0, 8, 8)
    section(o, at + 832, @SYMTAB@, 2, 0, get(w, 192), get(w, 40) * 24, 14, get(w, 48), 8, 24)
    section(o, at + 896, @STRTAB@, 3, 0, get(w, 200), get(w, 64), 0, 0, 1, 0)
    section(o, at + 960, @SHSTRTAB@, 3, 0, get(w, 208), @SECTION_LEN@, 0, 0, 1, 0)
    return 0

def write_names(o:mutbuf, at:u64) -> u64:
@SECTION_WRITES@
    return 0
'''


def _shared_function(name, successor):
    return ('\ndef ' + name + '(' + SHARED_SOURCE.split('\ndef ' + name + '(', 1)[1].split(
        '\ndef ' + successor + '(', 1)[0])


def source_program():
    names = bytearray(b'\0')
    source = SOURCE
    for name in SECTION_NAMES:
        source = source.replace('@' + name[1:].upper().replace('.', '_') + '@', str(len(names)))
        names.extend(name.encode('ascii') + b'\0')
    writes = []
    for offset in range(0, len(names), 8):
        word = names[offset:offset + 8]
        writes.append(f'    write(o, at + {offset}, {int.from_bytes(word, "little")}, {len(word)})')
    functions = (
        ('object_layout', 'symbols'), ('name_length', 'allowed_import'),
        ('check_calls', 'layout'), ('gnu_hash', 'calls'), ('tag', 'headers'),
        ('segment', 'section'), ('section', 'section_names'),
    )
    helpers = ''.join(_shared_function(name, end) for name, end in functions)
    helpers += '\ndef zero(' + SHARED_SOURCE.split('\ndef zero(', 1)[1]
    helpers += '\ndef within(' + STATIC_SOURCE.split('\ndef within(', 1)[1]
    return (source.replace('@SECTION_LEN@', str(len(names)))
            .replace('@SECTION_WRITES@', '\n'.join(writes)) + helpers).replace(' / ', ' // ')


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    module = 'elf_verified_linker'
    (root / f'examples/hia_bootstrap/{module}.hepta').write_text(render_assembly(document(source_program(), module)))
