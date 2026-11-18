"""Render the HIA packer shared by the four static Core edit applications."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE

MAGIC = int.from_bytes(b'HIACED01', 'little')
SOURCE = r'''
def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 56 or uint(s, 0, 8) != PACK_MAGIC:
        return 16
    stub = uint(s, 8, 8)
    calls = uint(s, 16, 8)
    if stub < 5 or stub > 3920 or calls == 0 or calls > 32:
        return 16
    stub_at = 56 + 16 * calls
    image_at = stub_at + stub
    if image_at > length(s):
        return 16
    end = image_at
    index = 0
    while index < 4:
        size = uint(s, 24 + 8 * index, 8)
        if size == 0 or size > 1048576:
            return 16
        end = end + size
        index = index + 1
    if end != length(s):
        return 16
    size = position(s, 176 + stub, 4)
    if size > length(o):
        return 3
    last = 0
    i = 0
    while i < calls:
        row = 56 + 16 * i
        hole = uint(s, row, 8)
        image = uint(s, row + 8, 8)
        if hole <= last or hole > stub - 4 or image >= 4:
            return 16
        if byte(s, stub_at + hole - 1) != 232 or uint(s, stub_at + hole, 4) != 0:
            return 16
        last = hole + 4
        i = i + 1
    header(o, size)
    copy_bytes(s, o, stub_at, 176, stub)
    source = image_at
    target = 176 + stub
    index = 0
    while index < 4:
        aligned = align(target)
        while target < aligned:
            store(o, target, 0)
            target = target + 1
        part = uint(s, 24 + 8 * index, 8)
        copy_bytes(s, o, source, target, part)
        source = source + part
        target = target + part
        index = index + 1
    i = 0
    while i < calls:
        row = 56 + 16 * i
        hole = 176 + uint(s, row, 8)
        image = uint(s, row + 8, 8)
        write(o, hole, align(position(s, 176 + stub, image)) - hole - 4, 4)
        i = i + 1
    return size

def position(s:readbuf, start:u64, index:u64) -> u64:
    i = 0
    while i < index:
        start = align(start) + uint(s, 24 + 8 * i, 8)
        i = i + 1
    return start

def align(offset:u64) -> u64:
    return (offset + 7) & 18446744073709551608

def header(o:mutbuf, size:u64) -> u64:
    i = 0
    while i < 176:
        write(o, i, 0, 8)
        i = i + 8
    write(o, 0, 282584257676671, 8)
    write(o, 16, 2, 2)
    write(o, 18, 62, 2)
    write(o, 20, 1, 4)
    write(o, 24, 4194480, 8)
    write(o, 32, 64, 8)
    write(o, 52, 64, 2)
    write(o, 54, 56, 2)
    write(o, 56, 2, 2)
    write(o, 64, 1, 4)
    write(o, 68, 5, 4)
    write(o, 80, 4194304, 8)
    write(o, 88, 4194304, 8)
    write(o, 96, size, 8)
    write(o, 104, size, 8)
    write(o, 112, 4096, 8)
    write(o, 120, 1685382481, 4)
    write(o, 124, 6, 4)
    write(o, 168, 16, 8)
    return 0
'''


def render():
    helpers = LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]
    return render_assembly(document(SOURCE.replace('PACK_MAGIC', str(MAGIC)) + helpers,
                                    'core_edit_packer'))


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_edit/packer.hepta'
    target.write_text(render())
