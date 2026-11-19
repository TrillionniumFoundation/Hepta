"""Author the HIA read-only object wrapper for static build images."""
from pathlib import Path
import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE

EMBED_MAGIC = b'HIAEMB01'
EMBED_SOURCE = 'examples/hia_bootstrap/elf_embed_image.hepta'
SECTIONS = b'\0.symtab\0.strtab\0.shstrtab\0.text\0.data\0.bss\0.rodata\0.note.GNU-stack\0'
ENCODER = r'''
# HIAEMB01 is a tag followed by label length, payload length, zero and both spans.
# The output defines exactly two .rodata symbols, label_start and label_end.
def embed_image(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 33 or length(s) > 1048576 or uint(s, 0, 8) != WIRE_MAGIC or uint(s, 24, 8) != 0:
        return 4294967295
    name = uint(s, 8, 8)
    size = uint(s, 16, 8)
    if name == 0 or name > 127 or name > length(s) - 32 or size != length(s) - 32 - name:
        return 4294967295
    index = 0
    while index < name:
        point = byte(s, 32 + index)
        letters = (point >= 65 and point <= 90) or (point >= 97 and point <= 122)
        digits = index != 0 and point >= 48 and point <= 57
        if letters == False and digits == False and point != 95:
            return 4294967295
        index = index + 1
    end = 64 + size
    symbols = (end + 7) & 18446744073709551608
    strings = symbols + 72
    second_name = name + 8
    string_bytes = 2 * name + 13
    names = strings + string_bytes
    sections = (names + SECTION_NAME_SIZE + 7) & 18446744073709551608
    total = sections + 9 * 64
    if total > 1048576 or total > length(o):
        return 4294967294
    at = end
    while at < total:
        store(o, at, 0)
        at = at + 1
    ELF_HEADER_WRITES
    put(o, 40, sections)
    copy_bytes(s, o, 32 + name, 64, size)

    # Three Elf64_Sym records: undefined, global start and global end.
    put(o, symbols + 24, SYMBOL_BINDING + 1)
    put(o, symbols + 48, SYMBOL_BINDING + second_name)
    put(o, symbols + 56, size)
    copy_bytes(s, o, 32, strings + 1, name)
    write(o, strings + 1 + name, SUFFIX_START, 6)
    copy_bytes(s, o, 32, strings + second_name, name)
    write(o, strings + second_name + name, SUFFIX_END, 4)
    SECTION_NAME_WRITES
    SECTION_TABLE_WRITES
    return total

def section(o:mutbuf, at:u64, kind:u64, flags:u64, offset:u64, size:u64, link:u64, alignment:u64, unit:u64) -> u64:
    put(o, at, kind)
    put(o, at + 8, flags)
    put(o, at + 24, offset)
    put(o, at + 32, size)
    put(o, at + 40, link)
    put(o, at + 48, alignment)
    put(o, at + 56, unit)
    return 0
'''


def little(raw):
    return int.from_bytes(raw, 'little')


def render():
    # Emit numeric constants for ELF64, little endian, ET_REL, EM_X86_64.
    # The candidate supplies e_shoff after computing the output layout.
    header = struct.pack('<16sHHIQQQI6H', b'\x7fELF\x02\x01\x01',
                         1, 62, 1, 0, 0, 0, 0, 64, 0, 0, 64, 9, 8)
    table = (
        (b'.text', 1, 6, '64', '0', 0, 0, 1, 0),
        (b'.data', 1, 3, '64', '0', 0, 0, 1, 0),
        (b'.bss', 8, 3, '64', '0', 0, 0, 1, 0),
        (b'.rodata', 1, 2, '64', 'size', 0, 0, 16, 0),
        (b'.note.GNU-stack', 1, 0, 'end', '0', 0, 0, 1, 0),
        (b'.symtab', 2, 0, 'symbols', '72', 7, 1, 8, 24),
        (b'.strtab', 3, 0, 'strings', 'string_bytes', 0, 0, 1, 0),
        (b'.shstrtab', 3, 0, 'names', str(len(SECTIONS)), 0, 0, 1, 0),
    )
    rows = []
    for index, (name, kind, flags, offset, size, link, info, alignment, unit) in enumerate(table, 1):
        typed_name = (kind << 32) | SECTIONS.index(name + b'\0')
        link_info = (info << 32) | link
        rows.append(f'section(o, sections + {64 * index}, {typed_name}, {flags}, '
                    f'{offset}, {size}, {link_info}, {alignment}, {unit})')
    values = {
        'WIRE_MAGIC': little(EMBED_MAGIC),
        'ELF_HEADER_WRITES': '\n    '.join(
            f'put(o, {offset}, {little(header[offset:offset + 8])})'
            for offset in range(0, 64, 8) if offset != 40),
        'SYMBOL_BINDING': little(struct.pack('<IBBH', 0, 0x10, 0, 4)),
        'SUFFIX_START': little(b'_start'),
        'SUFFIX_END': little(b'_end'),
        'SECTION_NAME_SIZE': len(SECTIONS),
        'SECTION_NAME_WRITES': '\n    '.join(
            f'write(o, names + {offset}, {little(part)}, {len(part)})'
            for offset in range(0, len(SECTIONS), 8) if (part := SECTIONS[offset:offset + 8])),
        'SECTION_TABLE_WRITES': '\n    '.join(rows),
    }
    source = ENCODER
    for key, value in values.items():
        source = source.replace(key, str(value))
    helpers = LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]
    return render_assembly(document(source + helpers, 'elf_embed_image'))


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    (root / EMBED_SOURCE).write_text(render())
