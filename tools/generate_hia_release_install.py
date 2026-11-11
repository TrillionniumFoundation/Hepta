"""Author the HIA release-package policy and its syscall-only ELF packer.

The installer publishes one operator-authorized, content-addressed directory.
It does not switch a worker, own request journals or qualify the installed code.
"""
from __future__ import annotations

import struct
import subprocess
import tempfile
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
MAGIC = int.from_bytes(b'HIAINS01', 'little')
BUNDLE_MAGIC = int.from_bytes(b'HIAREL01', 'little')
WIRE_LIMIT = 64 << 20
WORK_BYTES = 65536

POLICY_SOURCE = '''def policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 65536:
        return 16
    phase = get(w, 0)
    if phase == 0:
        return arguments(s, o, w)
    if phase == 1:
        if length(s) != 32:
            return 16
        i = 0
        while i < 32:
            v = unhex(byte(w, 768 + i * 2)) * 16 + unhex(byte(w, 769 + i * 2))
            if byte(s, i) != v:
                return 11
            i = i + 1
        return 0
    if phase == 2:
        return package(s, w)
    if phase == 4:
        return select(s, w)
    if phase == 5:
        if directory(w, 416) == 0:
            return 10
        if get(w, 440) & 18 != 0:
            return 10
        return 0
    if phase == 6:
        if directory(w, 416) == 0:
            return 10
        mode = 16704
        if get(w, 8) == 1:
            mode = 16832
        actual = get(w, 440) & 4294967295
        if actual != mode:
            if get(w, 8) != 1 or actual != 17856:
                return 10
        copy(w, 416, 272, 144)
        return 0
    if phase == 7:
        if directory(w, 560) == 0:
            return 10
        if get(w, 560) != get(w, 272) or get(w, 568) != get(w, 280):
            return 12
        if get(w, 584) & 4294967295 != 16704:
            return 10
        return 0
    if phase == 8 or phase == 9:
        return file_stat(w, phase)
    if phase == 10:
        offset = get(w, 72)
        count = get(w, 80)
        total = get(w, 48)
        start = get(w, 40)
        if offset > total or count > total - offset or count > length(o):
            return 11
        if start > length(s) or total > length(s) - start:
            return 16
        i = 0
        while i < count:
            if byte(s, start + offset + i) != byte(o, i):
                return 11
            i = i + 1
        return 0
    if phase == 11:
        return entries(s, o, w)
    if phase == 12:
        if get(w, 112) != get(w, 24):
            return 11
        return 0
    if phase == 13:
        write(w, 848, 7022071303105570862, 8)
        write(w, 856, 2975591, 3)
        i = 0
        while i < 16:
            v = byte(w, 912 + i)
            store(w, 859 + i * 2, hex(v >> 4))
            store(w, 860 + i * 2, hex(v & 15))
            i = i + 1
        store(w, 891, 0)
        return 0
    if phase == 14:
        return receipt(o, w)
    if phase == 15:
        put(w, 112, 0)
        i = 0
        while i < get(w, 24):
            at = 4096 + i * 96 + 88
            put(w, at, get(w, at) & 1)
            i = i + 1
        return 0
    if phase == 17:
        if directory(w, 416) == 0 or get(w, 440) & 4294967295 != 16704:
            return 10
        if get(w, 416) != get(w, 272) or get(w, 424) != get(w, 280):
            return 12
        return 0
    return 16

def arguments(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 24 or length(o) < 8192:
        return 16
    a = uint(s, 0, 8)
    b = uint(s, 8, 8)
    c = uint(s, 16, 8)
    if a > 7 or b == 0 or b > 4095 or c != 64 or length(s) != 24 + a + b + c:
        return 16
    op = 0
    if a == 7 and uint(s, 24, 7) == 30526565255720553:
        op = 1
    if a == 6 and uint(s, 24, 6) == 133476589827702:
        op = 2
    if op == 0:
        return 16
    root = 24 + a
    if byte(s, root) != 47:
        return 16
    store(o, 0, 0)
    i = 1
    begin = 1
    while i < b:
        v = byte(s, root + i)
        if v == 0:
            return 16
        if v == 47:
            if component(s, root + begin, i - begin) == 0:
                return 16
            store(o, i, 0)
            begin = i + 1
        else:
            store(o, i, v)
        i = i + 1
    if b > 1:
        if component(s, root + begin, b - begin) == 0:
            return 16
    store(o, b, 0)
    i = 0
    while i < 64:
        v = byte(s, root + b + i)
        if unhex(v) > 15:
            return 16
        store(w, 768 + i, v)
        i = i + 1
    store(w, 832, 0)
    put(w, 8, op)
    put(w, 88, b)
    return op

def component(s:readbuf, at:u64, size:u64) -> u64:
    if size == 0 or size > 255:
        return 0
    if size == 1 and byte(s, at) == 46:
        return 0
    if size == 2 and byte(s, at) == 46 and byte(s, at + 1) == 46:
        return 0
    return 1

def package(s:readbuf, w:mutbuf) -> u32:
    if length(s) < 24 or length(s) > 67108864:
        return 16
    if uint(s, 0, 8) != 3544407730921556296 or uint(s, 16, 8) != 0:
        return 16
    count = uint(s, 8, 8)
    if count == 0 or count > 256:
        return 16
    at = 24
    i = 0
    while i < count:
        if at > length(s) or length(s) - at < 24:
            return 16
        name = uint(s, at, 8)
        mode = uint(s, at + 8, 8)
        size = uint(s, at + 16, 8)
        if name == 0 or name > 127 or mode != 256 and mode != 320:
            return 16
        at = at + 24
        if name > length(s) - at:
            return 16
        j = 0
        while j < name:
            v = byte(s, at + j)
            if alnum(v) == 0:
                if j == 0 or v != 46 and v != 45 and v != 95:
                    return 16
            j = j + 1
        j = 0
        while j < i:
            row = 4096 + j * 96
            if get(w, row + 8) == name:
                k = 0
                same = 1
                while k < name:
                    if byte(s, at + k) != byte(s, get(w, row) + k):
                        same = 0
                    k = k + 1
                if same == 1:
                    return 16
            j = j + 1
        row = 4096 + i * 96
        put(w, row, at)
        put(w, row + 8, name)
        at = at + name
        if size > length(s) - at:
            return 16
        put(w, row + 16, at)
        put(w, row + 24, size)
        put(w, row + 32, mode)
        put(w, row + 88, 0)
        at = at + size
        i = i + 1
    if at != length(s):
        return 16
    put(w, 16, length(s))
    put(w, 24, count)
    return 0

def select(s:readbuf, w:mutbuf) -> u32:
    index = get(w, 32)
    if index >= get(w, 24) or index >= 256:
        return 16
    row = 4096 + index * 96
    name = get(w, row)
    size = get(w, row + 8)
    if size == 0 or size > 127 or name > length(s) or size > length(s) - name:
        return 16
    i = 0
    while i < size:
        store(w, 960 + i, byte(s, name + i))
        i = i + 1
    store(w, 960 + size, 0)
    put(w, 40, get(w, row + 16))
    put(w, 48, get(w, row + 24))
    put(w, 56, get(w, row + 32))
    return 0

def directory(w:mutbuf, at:u64) -> u64:
    if get(w, at + 24) & 61440 != 16384:
        return 0
    if get(w, at + 28) & 4294967295 != get(w, 64):
        return 0
    return 1

def file_stat(w:mutbuf, phase:u64) -> u32:
    index = get(w, 32)
    if index >= get(w, 24) or index >= 256:
        return 16
    row = 4096 + index * 96
    if get(w, 440) & 4294967295 != 32768 + get(w, row + 32):
        return 10
    if get(w, 444) & 4294967295 != get(w, 64) or get(w, 432) != 1:
        return 10
    if get(w, 464) != get(w, row + 24):
        return 11
    if get(w, row + 88) & 1 == 1:
        if get(w, 416) != get(w, row + 40) or get(w, 424) != get(w, row + 48):
            return 12
        if get(w, 504) != get(w, row + 56) or get(w, 512) != get(w, row + 64):
            return 12
        if get(w, 520) != get(w, row + 72) or get(w, 528) != get(w, row + 80):
            return 12
        return 0
    if phase == 9:
        return 16
    put(w, row + 40, get(w, 416))
    put(w, row + 48, get(w, 424))
    put(w, row + 56, get(w, 504))
    put(w, row + 64, get(w, 512))
    put(w, row + 72, get(w, 520))
    put(w, row + 80, get(w, 528))
    put(w, row + 88, 1)
    return 0

def entries(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = get(w, 80)
    if size > length(o):
        return 16
    at = 0
    while at < size:
        if size - at < 20:
            return 16
        extent = byte(o, at + 16) | byte(o, at + 17) << 8
        if extent < 20 or extent > size - at:
            return 16
        n = 0
        while n < extent - 19 and byte(o, at + 19 + n) != 0:
            n = n + 1
        if n == extent - 19 or n == 0:
            return 16
        special = 0
        if n == 1 and byte(o, at + 19) == 46:
            special = 1
        if n == 2 and byte(o, at + 19) == 46 and byte(o, at + 20) == 46:
            special = 1
        if special == 0:
            found = 0
            i = 0
            while i < get(w, 24):
                row = 4096 + i * 96
                if get(w, row + 8) == n:
                    same = 1
                    j = 0
                    while j < n:
                        if byte(o, at + 19 + j) != byte(s, get(w, row) + j):
                            same = 0
                        j = j + 1
                    if same == 1:
                        if get(w, row + 88) != 1 or get(w, row + 48) != get(o, at):
                            return 12
                        if byte(o, at + 18) != 0 and byte(o, at + 18) != 8:
                            return 10
                        put(w, row + 88, 3)
                        put(w, 112, get(w, 112) + 1)
                        found = 1
                i = i + 1
            if found == 0:
                return 11
        at = at + extent
    return 0

def receipt(o:mutbuf, w:mutbuf) -> u32:
    if length(o) < 512:
        return 16
    RECEIPT_PREFIX
    at = RECEIPT_PREFIX_SIZE
    i = 0
    while i < 64:
        store(o, at + i, byte(w, 768 + i))
        i = i + 1
    at = at + 64
    at = append(o, at, 4189033144851666980, 8)
    at = append(o, at, 14882, 2)
    at = decimal(o, at, get(w, 24))
    at = append(o, at, 8315161642760679980, 8)
    at = append(o, at, 14882, 2)
    at = decimal(o, at, get(w, 16))
    at = append(o, at, 7810778314095127084, 8)
    at = append(o, at, 24590976124585574, 7)
    if get(w, 8) == 1:
        at = append(o, at, 1702195828, 4)
    else:
        at = append(o, at, 435728179558, 5)
    at = append(o, at, 2685, 2)
    return at

def decimal(o:mutbuf, at:u64, v:u64) -> u64:
    divisor = 10000000000000000000
    started = 0
    while divisor > 0:
        digit = 0
        while v >= divisor:
            digit = digit + 1
            v = v - divisor
        if digit != 0 or started != 0 or divisor == 1:
            store(o, at, digit + 48)
            at = at + 1
            started = 1
        divisor = divide10(divisor)
    return at

def divide10(v:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit > 0:
        bit = bit - 1
        remainder = remainder * 2 + ((v >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def append(o:mutbuf, at:u64, value:u64, size:u64) -> u64:
    write(o, at, value, size)
    return at + size

def hex(v:u64) -> u64:
    if v < 10:
        return v + 48
    return v + 87

def unhex(v:u64) -> u64:
    if v >= 48 and v <= 57:
        return v - 48
    if v >= 97 and v <= 102:
        return v - 87
    return 16

def alnum(v:u64) -> u64:
    if v >= 48 and v <= 57 or v >= 65 and v <= 90 or v >= 97 and v <= 122:
        return 1
    return 0

def copy(w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(w, source + i))
        i = i + 1
    return 0

def uint(s:readbuf, at:u64, size:u64) -> u64:
    v = 0
    i = 0
    while i < size:
        v = v | byte(s, at + i) << (i * 8)
        i = i + 1
    return v

def get(w:mutbuf, at:u64) -> u64:
    v = 0
    i = 0
    while i < 8:
        v = v | byte(w, at + i) << (i * 8)
        i = i + 1
    return v

def put(w:mutbuf, at:u64, v:u64) -> u64:
    return write(w, at, v, 8)

def write(o:mutbuf, at:u64, v:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, v >> (i * 8) & 255)
        i = i + 1
    return 0
'''


def policy_source():
    source = POLICY_SOURCE.replace('30526565255720553', str(int.from_bytes(b'install', 'little')))
    source = source.replace('133476589827702', str(int.from_bytes(b'verify', 'little')))
    source = source.replace('3544407730921556296', str(BUNDLE_MAGIC))
    source = source.replace('7022071303105570862', str(int.from_bytes(b'.hia-sta', 'little')))
    source = source.replace('2975591', str(int.from_bytes(b'ge-', 'little')))
    prefix = b'{"schema":"hepta.hia.release-install.v1","sha256":"'
    writes = []
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at+8]
        writes.append(f'write(o, {at}, {int.from_bytes(chunk, "little")}, {len(chunk)})')
    source = source.replace('RECEIPT_PREFIX_SIZE', str(len(prefix)))
    source = source.replace('RECEIPT_PREFIX', '\n    '.join(writes))
    for old, raw in [('4189033144851666980', b'","files'), ('14882', b'":'),
                     ('8315161642760679980', b',"bytes"'),
                     ('7810778314095127084', b',"publis'), ('24590976124585574', b'hed":')]:
        source = source.replace(old, str(int.from_bytes(raw, 'little')))
    source = source.replace('14882, 2)\n    at = decimal(o, at, get(w, 16))',
                            str(int.from_bytes(b':', 'little'))+', 1)\n    at = decimal(o, at, get(w, 16))')
    # The second fragment has only five bytes; its explicit count is part of
    # the HIA receipt writer, not implicit C-string formatting.
    source = source.replace(str(int.from_bytes(b'hed":', 'little'))+', 7)',
                            str(int.from_bytes(b'hed":', 'little'))+', 5)')
    return source


def template():
    with tempfile.TemporaryDirectory(prefix='hia-release-template-') as folder:
        obj, raw = Path(folder)/'adapter.o', Path(folder)/'adapter.bin'
        subprocess.run(['as', '--64', str(ROOT/'tools/hia_release_install_syscalls.S'), '-o', str(obj)],
                       check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)],
                       check=True, capture_output=True)
        symbols = {}
        for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines():
            address, _, name = line.split()
            symbols[name] = int(address, 16)
        if 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('unresolved release adapter relocation')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01'+bytes(9)
              +struct.pack('<HHIQQQIHHHHHH', 2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
              +struct.pack('<IIQQQQQQ', 1,5,0,0x400000,0x400000,0,0,4096)
              +struct.pack('<IIQQQQQQ', 0x6474e551,6,0,0,0,0,0,16))
    return header+code, {name:176+symbols[name] for name in
                        ('policy_initial_hole','policy_hole','sha_hole')}


def packer_source():
    from tools.generate_hia_native_filter import LINK_SOURCE
    prefix, holes = template()
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 26 or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != {MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    sha = uint(s, 16, 8)
    if policy == 0 or sha == 0 or policy > 1048576 or sha > 1048576:
        return 4294967295
    if length(s) != 24 + policy + sha:
        return 4294967295
    size = {len(prefix)} + policy + sha
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at+8]
        source += f'    write(o, {at}, {int.from_bytes(chunk,"little")}, {len(chunk)})\n'
    source += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name, offset in holes.items():
        target = str(len(prefix)) + (' + policy' if name == 'sha_hole' else '')
        source += f'    write(o, {offset}, {target} - {offset + 4}, 4)\n'
    source += f'    copy_bytes(s, o, 24, {len(prefix)}, policy + sha)\n    return size\n'
    return source + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]


def main():
    for name, source in [('release_install_policy', policy_source()), ('release_install_packer', packer_source())]:
        path = ROOT/'examples/hia_bootstrap'/f'{name}.hiaasm'
        path.write_text(render_assembly(document(source, name)))
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
