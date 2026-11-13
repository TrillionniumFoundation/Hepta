"""Author a Linux syscall-only executable entry in the generated HIA source.

Only the authoring aid packs literal instruction bytes. Successors emit their
own ELF headers, entry, calls and branches in HIA; no runtime assembler, libc,
dynamic loader, Python compiler or host source translation is involved.
The bounded filter reads stdin, calls the existing buffer ABI, and writes the
returned output prefix to stdout. It never opens an arbitrary filesystem path.
"""
from __future__ import annotations

import struct


def _bytes(hexadecimal):
    data = bytes.fromhex(hexadecimal)
    return "".join("    emit_bytes(o, w, " + str(int.from_bytes(data[i:i + 8], "little"))
                   + ", " + str(len(data[i:i + 8])) + ")\n" for i in range(0, len(data), 8))


def _header():
    identity = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = identity + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1,
        0x400000 + 176, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
    stack = struct.pack("<IIQQQQQQ", 0x6474e551, 6, 0, 0, 0, 0, 0, 16)
    assert len(header + load + stack) == 176
    return _bytes((header + load + stack).hex())


SOURCE = r'''
def cli_begin(o:mutbuf, w:mutbuf) -> u64:
''' + _header() + _bytes("48 83 3c 24 01") + r'''
    put(w, 512, owned_branch(o, w, 133))
''' + _bytes("31 ff be 00 00 30 00 ba 03 00 00 00 41 ba 22 00 00 00"
             " 49 c7 c0 ff ff ff ff 45 31 c9 b8 09 00 00 00 0f 05 48 3d 01 f0 ff ff") + r'''
    put(w, 520, owned_branch(o, w, 131))
''' + _bytes("49 89 c4 45 31 ed") + r'''
    reading = get(w, 56)
''' + _bytes("31 c0 31 ff 4b 8d 34 2c ba 01 00 10 00 4c 29 ea 0f 05 48 83 f8 fc") + r'''
    cli_to(o, w, 132, reading)
''' + _bytes("48 85 c0") + r'''
    put(w, 528, owned_branch(o, w, 136))
    put(w, 536, owned_branch(o, w, 132))
''' + _bytes("49 01 c5 49 81 fd 00 00 10 00") + r'''
    put(w, 544, owned_branch(o, w, 135))
    cli_to(o, w, 0, reading)
    owned_patch(o, w, get(w, 536))
''' + _bytes("4c 89 e7 4c 89 ee 49 8d 94 24 00 00 10 00 b9 00 00 10 00"
             " 4d 8d 84 24 00 00 20 00 41 b9 00 00 10 00 e8") + r'''
    put(w, 440, get(w, 56))
    emit4(o, w, 0)
''' + _bytes("83 f8 ff") + r'''
    put(w, 560, owned_branch(o, w, 132))
''' + _bytes("83 f8 fe") + r'''
    put(w, 568, owned_branch(o, w, 132))
''' + _bytes("3d 00 00 10 00") + r'''
    put(w, 576, owned_branch(o, w, 135))
''' + _bytes("41 89 c6 4d 8d bc 24 00 00 10 00") + r'''
    writing = get(w, 56)
''' + _bytes("4d 85 f6") + r'''
    put(w, 584, owned_branch(o, w, 132))
''' + _bytes("b8 01 00 00 00 bf 01 00 00 00 4c 89 fe 4c 89 f2 0f 05 48 83 f8 fc") + r'''
    cli_to(o, w, 132, writing)
''' + _bytes("48 85 c0") + r'''
    put(w, 592, owned_branch(o, w, 142))
''' + _bytes("49 01 c7 49 29 c6") + r'''
    cli_to(o, w, 0, writing)
    owned_patch(o, w, get(w, 584))
''' + _bytes("31 ff") + r'''
    put(w, 600, owned_branch(o, w, 0))
    owned_patch(o, w, get(w, 560))
''' + _bytes("bf 02 00 00 00") + r'''
    put(w, 608, owned_branch(o, w, 0))
    owned_patch(o, w, get(w, 544))
    owned_patch(o, w, get(w, 568))
    owned_patch(o, w, get(w, 576))
''' + _bytes("bf 03 00 00 00") + r'''
    put(w, 616, owned_branch(o, w, 0))
    owned_patch(o, w, get(w, 520))
    owned_patch(o, w, get(w, 528))
    owned_patch(o, w, get(w, 592))
''' + _bytes("bf 04 00 00 00") + r'''
    put(w, 624, owned_branch(o, w, 0))
    owned_patch(o, w, get(w, 512))
''' + _bytes("bf 40 00 00 00") + r'''
    owned_patch(o, w, get(w, 600))
    owned_patch(o, w, get(w, 608))
    owned_patch(o, w, get(w, 616))
    owned_patch(o, w, get(w, 624))
''' + _bytes("b8 3c 00 00 00 0f 05 0f 0b") + r'''
    put(w, 448, get(w, 56))
    return 0

def cli_to(o:mutbuf, w:mutbuf, condition:u64, destination:u64) -> u64:
    at = owned_branch(o, w, condition)
    if get(w, 48) == 2:
        write4(o, at, destination - at - 4)
    return 0

def cli_finish(o:mutbuf, w:mutbuf) -> u64:
    if get(w, 48) == 2:
        at = get(w, 440)
        write4(o, at, get(w, 448) - at - 4)
        put(o, 96, get(w, 56))
        put(o, 104, get(w, 56))
    return 0
'''
