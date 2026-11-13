"""Author the HIA source-bundle driver and self-contained ELF packer.

The generator and GNU assembler are bootstrap authoring tools. Produced ELFs
execute only the checked HIA policy/compiler/packer and fixed syscall transport.
"""
from __future__ import annotations

from pathlib import Path
import struct
import subprocess
import tempfile

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
BUNDLE_MAGIC = int.from_bytes(b'HIAREL01', 'little')
PACK_MAGIC = int.from_bytes(b'HIASBL01', 'little')
WIRE_LIMIT = 64 << 20
IMAGE_LIMIT = 1 << 20
# Same source/result/workspace bounds as qualify_hia_selfhost.compile_stage.
# This component does not extend the compiler's supported language or limits.
COMPILER_WORK_BYTES = 1 << 20
IMAGE_AT = 65536
POLICY_WORK_BYTES = IMAGE_AT + IMAGE_LIMIT
ROLE_NAMES = ('source_build_policy.hepta', 'selfhost.hepta', 'source_build_packer.hepta')
LAYOUT = {'ARGS': 0, 'WORK': 4096}
LAYOUT['COMPWORK'] = LAYOUT['WORK'] + POLICY_WORK_BYTES
LAYOUT['FRAME'] = LAYOUT['COMPWORK'] + COMPILER_WORK_BYTES
LAYOUT['FRAME_CAP'] = 3 * IMAGE_LIMIT + 4096
LAYOUT['OUT'] = LAYOUT['FRAME'] + LAYOUT['FRAME_CAP']
LAYOUT['WIRE'] = LAYOUT['OUT'] + WIRE_LIMIT
LAYOUT['WIRE_CAP'] = WIRE_LIMIT + 4096
LAYOUT['MAPSIZE'] = LAYOUT['WIRE'] + LAYOUT['WIRE_CAP']

POLICY = '''def policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < POLICY_WORK_BYTES:
        return 16
    if get(w, 16) == 255:
        return 16
    phase = get(w, 0)
    if phase == 0:
        if get(w, 16) != 0:
            return bad(w, 16)
        return arguments(s, w)
    if phase == 1:
        if get(w, 16) != 1:
            return bad(w, 16)
        return admit(s, o, w)
    if length(s) != get(w, 40):
        return bad(w, 16)
    if phase == 2:
        return select(s, w)
    if phase == 3:
        return consume(s, o, w)
    if phase == 4:
        return frame(s, o, w)
    if phase == 5:
        if get(w, 16) != 8:
            return bad(w, 16)
        expected = TEMPLATE_SIZE + get(w, 312) + get(w, 328) + get(w, 344)
        if get(w, 72) != expected or expected > length(o) or expected > 67108864:
            return bad(w, 18)
        put(w, 88, expected)
        put(w, 16, 7)
        return 0
    return bad(w, 16)

def arguments(s:readbuf, w:mutbuf) -> u32:
    if length(s) < 16 or uint(s, 0, 8) != 1:
        return bad(w, 16)
    n = uint(s, 8, 8)
    if n > 16 or length(s) != 16 + n:
        return bad(w, 16)
    op = 0
    if n == 5 and uint(s, 16, 5) == BUILD_WORD:
        op = 1
    if n == 4 and uint(s, 16, 4) == PACK_WORD:
        op = 2
    if op == 0:
        return bad(w, 16)
    put(w, 8, op)
    put(w, 16, 1)
    return 0

def admit(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 24 or length(s) > 67108864:
        return bad(w, 16)
    if uint(s, 0, 8) != BUNDLE_MAGIC or uint(s, 16, 8) != 0:
        return bad(w, 16)
    count = uint(s, 8, 8)
    op = get(w, 8)
    if count == 0 or count > 128:
        return bad(w, 16)
    if op == 2 and count != 3 and count != 6:
        return bad(w, 16)
    at = 24
    i = 0
    bits = 0
    while i < count:
        if at > length(s) or length(s) - at < 24:
            return bad(w, 16)
        n = uint(s, at, 8)
        mode = uint(s, at + 8, 8)
        size = uint(s, at + 16, 8)
        if n == 0 or n > 127 or mode != 256 or size == 0 or size > 1048576:
            return bad(w, 16)
        at = at + 24
        if n > length(s) - at:
            return bad(w, 16)
        j = 0
        while j < n:
            v = byte(s, at + j)
            if alnum(v) == 0:
                if j == 0 or v != 46 and v != 45 and v != 95:
                    return bad(w, 16)
            j = j + 1
        if op == 1:
            if n < 7 or n > 123:
                return bad(w, 16)
            suffix = 0
            if uint(s, at + n - 6, 6) == SUFFIX_WORD:
                suffix = 1
            if n >= 8 and uint(s, at + n - 7, 7) == ASM_SUFFIX_WORD:
                suffix = 1
            if suffix == 0:
                return bad(w, 16)
        j = 0
        while j < i:
            row = 4096 + j * 40
            if get(w, row + 8) == n:
                k = 0
                same = 1
                while k < n:
                    if byte(s, at + k) != byte(s, get(w, row) + k):
                        same = 0
                    k = k + 1
                if same == 1:
                    return bad(w, 16)
            j = j + 1
        row = 4096 + i * 40
        put(w, row, at)
        put(w, row + 8, n)
        if op == 2:
            which = role(s, at, n)
            if which == 0:
                return bad(w, 16)
            which = which - 1
            bits = bits | (1 << which)
            put(w, 256 + which * 16, at + n)
            put(w, 264 + which * 16, size)
        at = at + n
        if size > length(s) - at:
            return bad(w, 16)
        put(w, row + 16, at)
        put(w, row + 24, size)
        at = at + size
        i = i + 1
    if at != length(s):
        return bad(w, 16)
    if op == 2:
        if count == 3 and bits != 56 or count == 6 and bits != 63:
            return bad(w, 16)
        put(w, 16, 5)
    else:
        if length(o) < 24:
            return bad(w, 17)
        write(o, 0, BUNDLE_MAGIC, 8)
        write(o, 8, count * 2, 8)
        write(o, 16, 0, 8)
        put(w, 16, 2)
    put(w, 24, count)
    put(w, 32, 0)
    put(w, 40, length(s))
    put(w, 48, 24)
    return 0

def select(s:readbuf, w:mutbuf) -> u32:
    op = get(w, 8)
    index = get(w, 32)
    if op == 1:
        if get(w, 16) != 2 or index > get(w, 24):
            return bad(w, 16)
        if index == get(w, 24):
            put(w, 88, get(w, 48))
            put(w, 16, 7)
            return 3
        row = 4096 + index * 40
        put(w, 56, get(w, row + 16))
        put(w, 64, get(w, row + 24))
    else:
        if get(w, 16) != 5 or index > 3:
            return bad(w, 16)
        if get(w, 24) == 3 or index == 3:
            put(w, 16, 6)
            return 2
        put(w, 56, get(w, 256 + index * 16))
        put(w, 64, get(w, 264 + index * 16))
    if get(w, 56) > length(s) or get(w, 64) > length(s) - get(w, 56):
        return bad(w, 16)
    put(w, 16, 3)
    return 1

def consume(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 16) != 3:
        return bad(w, 16)
    size = get(w, 72)
    if size == 0 or size > 1048576:
        return bad(w, 18)
    index = get(w, 32)
    if get(w, 8) == 2:
        if index >= 3 or get(w, 264 + (index + 3) * 16) != size:
            return bad(w, 19)
        source = get(w, 256 + (index + 3) * 16)
        if source > length(s) or size > length(s) - source:
            return bad(w, 16)
        i = 0
        while i < size:
            if byte(s, source + i) != byte(w, 65536 + i):
                return bad(w, 19)
            i = i + 1
        put(w, 16, 5)
    else:
        if index >= get(w, 24) or index >= 128:
            return bad(w, 16)
        row = 4096 + index * 40
        n = get(w, row + 8)
        source = get(w, row + 16)
        source_size = get(w, row + 24)
        at = get(w, 48)
        need = 52 + n * 2 + source_size + size
        if at > length(o) or need > length(o) - at or at > 67108864 or need > 67108864 - at:
            return bad(w, 17)
        write(o, at, n, 8)
        write(o, at + 8, 256, 8)
        write(o, at + 16, source_size, 8)
        copy_bytes(s, o, get(w, row), at + 24, n)
        at = at + 24 + n
        copy_bytes(s, o, source, at, source_size)
        at = at + source_size
        write(o, at, n + 4, 8)
        write(o, at + 8, 256, 8)
        write(o, at + 16, size, 8)
        copy_bytes(s, o, get(w, row), at + 24, n)
        write(o, at + 24 + n, IMAGE_SUFFIX_WORD, 4)
        at = at + 28 + n
        i = 0
        while i < size:
            store(o, at + i, byte(w, 65536 + i))
            i = i + 1
        put(w, 48, at + size)
        put(w, 16, 2)
    put(w, 32, index + 1)
    return 0

def frame(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 16) != 6:
        return bad(w, 16)
    size = 32 + get(w, 312) + get(w, 328) + get(w, 344)
    if size > length(o):
        return bad(w, 17)
    write(o, 0, PACK_MAGIC, 8)
    at = 32
    i = 0
    while i < 3:
        source = get(w, 304 + i * 16)
        n = get(w, 312 + i * 16)
        if n == 0 or n > 1048576 or source > length(s) or n > length(s) - source:
            return bad(w, 16)
        write(o, 8 + i * 8, n, 8)
        copy_bytes(s, o, source, at, n)
        at = at + n
        i = i + 1
    put(w, 80, at)
    put(w, 16, 8)
    return 0

def bad(w:mutbuf, code:u32) -> u32:
    put(w, 16, 255)
    return code

ROLE_FUNCTION

def alnum(v:u64) -> u64:
    if v >= 48 and v <= 57 or v >= 65 and v <= 90 or v >= 97 and v <= 122:
        return 1
    return 0

def copy_bytes(s:readbuf, o:mutbuf, source:u64, target:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, target + i, byte(s, source + i))
        i = i + 1
    return 0

def uint(s:readbuf, at:u64, n:u64) -> u64:
    v = 0
    i = 0
    while i < n:
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

def write(o:mutbuf, at:u64, v:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, at + i, v >> (i * 8) & 255)
        i = i + 1
    return 0
'''


def template():
    source = (ROOT / 'tools/hia_source_build_syscalls.S').read_text()
    constants = {**LAYOUT, 'LIMIT': WIRE_LIMIT, 'IMAGE_LIMIT': IMAGE_LIMIT,
                 'WORK_BYTES': POLICY_WORK_BYTES, 'COMPILER_WORK_BYTES': COMPILER_WORK_BYTES,
                 'IMAGE_AT': IMAGE_AT}
    source = '\n'.join(f'.equ {k},{v}' for k, v in constants.items()) + '\n' + source
    with tempfile.TemporaryDirectory(prefix='hia-source-build-template-') as directory:
        folder = Path(directory)
        asm, obj, raw = folder/'adapter.S', folder/'adapter.o', folder/'adapter.bin'
        asm.write_text(source)
        subprocess.run(['as', '--64', str(asm), '-o', str(obj)], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)], check=True, capture_output=True)
        symbols = {name: int(address, 16) for address, _, name in
                   (line.split() for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
        if 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('unresolved source-build syscall relocation')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + code, {key: 176 + symbols[key] for key in
                           ('policy_initial_hole', 'policy_hole', 'compiler_hole', 'packer_hole')}


def policy_source():
    roles = ['def role(s:readbuf, at:u64, n:u64) -> u64:']
    for index, name in enumerate((*ROLE_NAMES, *(n + '.bin' for n in ROLE_NAMES)), 1):
        # Wire roles accept both actual source suffixes. The closed three-role
        # inventory/count/bitset still rejects duplicate aliases of one role.
        for spelling in (name, name.replace('.hepta', '.hiaasm')):
            raw = spelling.encode('ascii')
            terms = [f'n == {len(raw)}']
            terms += [f'uint(s, at + {at}, {len(raw[at:at+8])}) == {int.from_bytes(raw[at:at+8], "little")}'
                      for at in range(0, len(raw), 8)]
            roles += ['    if ' + ' and '.join(terms) + ':', f'        return {index}']
    roles += ['    return 0']
    source = POLICY.replace('ROLE_FUNCTION', '\n'.join(roles))
    values = {'POLICY_WORK_BYTES': POLICY_WORK_BYTES, 'TEMPLATE_SIZE': len(template()[0]),
              'BUNDLE_MAGIC': BUNDLE_MAGIC, 'PACK_MAGIC': PACK_MAGIC,
              'BUILD_WORD': int.from_bytes(b'build', 'little'), 'PACK_WORD': int.from_bytes(b'pack', 'little'),
              'SUFFIX_WORD': int.from_bytes(b'.hepta', 'little'),
              'ASM_SUFFIX_WORD': int.from_bytes(b'.hiaasm', 'little'),
              'IMAGE_SUFFIX_WORD': int.from_bytes(b'.bin', 'little')}
    # Replace longer tokens first because IMAGE_SUFFIX_WORD contains SUFFIX_WORD.
    for key in sorted(values, key=len, reverse=True):
        source = source.replace(key, str(values[key]))
    return source


def packer_source():
    prefix, holes = template()
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 35 or length(s) > {32 + 3 * IMAGE_LIMIT}:
        return 4294967295
    if uint(s, 0, 8) != {PACK_MAGIC}:
        return 4294967295
    policy = uint(s, 8, 8)
    compiler = uint(s, 16, 8)
    packer = uint(s, 24, 8)
    if policy == 0 or compiler == 0 or packer == 0 or policy > 1048576 or compiler > 1048576 or packer > 1048576:
        return 4294967295
    if length(s) != 32 + policy + compiler + packer:
        return 4294967295
    size = {len(prefix)} + policy + compiler + packer
    if length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        chunk = prefix[at:at+8]
        source += f'    write(o, {at}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
    source += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name, at in holes.items():
        target = str(len(prefix))
        if name in ('compiler_hole', 'packer_hole'):
            target += ' + policy'
        if name == 'packer_hole':
            target += ' + compiler'
        source += f'    write(o, {at}, {target} - {at + 4}, 4)\n'
    source += f'    copy_bytes(s, o, 32, {len(prefix)}, policy + compiler + packer)\n    return size\n'
    helpers = POLICY[POLICY.index('\ndef copy_bytes('):]
    return source + helpers


def main():
    for name, source in (('source_build_policy', policy_source()), ('source_build_packer', packer_source())):
        path = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
        path.write_text(render_assembly(document(source, name)))
        print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
