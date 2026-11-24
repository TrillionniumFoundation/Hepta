"""Author the HIA source-capture owner and its fixed Linux transport packer."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_native_filter import LINK_SOURCE

MAGIC = int.from_bytes(b'HIACAP01', 'little')
MAGIC2 = int.from_bytes(b'HIACAP02', 'little')
PACK = int.from_bytes(b'HIACAPK1', 'little')
TAGS = tuple(int.from_bytes(s, 'little') for s in
             (b'HIANAM01', b'HIASRC01', b'HIAIMG01', b'HIAMUL01', b'HIAKIT01', b'HIAKOBJ1', b'HIARAW01'))

POLICY = r'''
def capture(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 2097152 or length(o) != 67108864:
        return 0
    phase = mw(w, 0, 8)
    result = mw(w, 8, 8)
    if phase == 0:
        if mw(w, 136, 8) != 1 or length(s) < 32 or length(s) > 1048576:
            return fail(w, 16)
        protocol = uint(s, 0, 8)
        if protocol != MAGIC and protocol != MAGIC2:
            return fail(w, 16)
        root = uint(s, 8, 8)
        tag = uint(s, 16, 8)
        count = uint(s, 24, 8)
        if root < 3 or root > 2147483647 or count == 0 or count > 128:
            return fail(w, 16)
        if tag != NAMED and tag != SINGLE and tag != IMAGE and tag != MULTI and tag != KIT and tag != KOBJ and tag != RAW:
            return fail(w, 16)
        if (tag == SINGLE or tag == IMAGE or tag == RAW) and count != 1:
            return fail(w, 16)
        if tag == MULTI and (count < 2 or count > 4):
            return fail(w, 16)
        if (tag == KIT or tag == KOBJ) and count != 3:
            return fail(w, 16)
        at = 32
        index = 0
        total = 16
        if tag == RAW:
            total = 0
        while index < count:
            if at > length(s) or length(s) - at < 56:
                return fail(w, 16)
            pn = uint(s, at, 8)
            an = uint(s, at + 8, 8)
            size = uint(s, at + 16, 8)
            if pn == 0 or pn > 4095 or an == 0 or an > 127 or size > 1048576:
                return fail(w, 16)
            if size == 0 and protocol == MAGIC:
                return fail(w, 16)
            if pn + an > length(s) - at - 56:
                return fail(w, 16)
            path = at + 56
            alias = path + pn
            if valid_path(s, path, pn) == 0 or valid_name(s, alias, an) == 0:
                return fail(w, 16)
            if tag != RAW and valid_alias(s, alias, an) == 0:
                return fail(w, 16)
            prior = 0
            while prior < index:
                slot = 16384 + 32 * prior
                if mw(w, slot + 16, 8) == an:
                    if equal_source(s, alias, mw(w, slot + 8, 8), an) == 1:
                        return fail(w, 16)
                prior = prior + 1
            if total > length(o) - 16 - an - size:
                return fail(w, 17)
            slot = 16384 + 32 * index
            write(w, slot, at, 8)
            write(w, slot + 8, alias, 8)
            write(w, slot + 16, an, 8)
            write(w, slot + 24, size, 8)
            if tag == RAW:
                total = size
            else:
                total = total + 16 + an + size
            at = alias + an
            index = index + 1
        if at != length(s):
            return fail(w, 16)
        if tag != RAW:
            write(o, 0, tag, 8)
            write(o, 8, count, 8)
        write(w, 32, count, 8)
        write(w, 40, 0, 8)
        if tag == RAW:
            write(w, 48, 0, 8)
        else:
            write(w, 48, 16, 8)
        write(w, 56, root, 8)
        write(w, 112, total, 8)
        write(w, 120, tag, 8)
        return issue(w, 1, 1)
    if phase == 1:
        if result != 0:
            return fail(w, 15)
        if (mw(w, 4632, 4) & 61440) != 16384:
            return fail(w, 16)
        return next_source(s, w)
    if phase == 2:
        if result > 2147483647:
            return fail(w, 15)
        write(w, 64, result, 8)
        return issue(w, 3, 3)
    if phase == 3:
        if result != 0:
            return fail(w, 15)
        if (mw(w, 4632, 4) & 61440) != 32768 or mw(w, 4624, 8) != 1:
            return fail(w, 16)
        actual = mw(w, 4656, 8)
        if mw(w, 72, 8) == 0:
            if actual == 0 or actual > 1048576:
                return fail(w, 16)
            if mw(w, 112, 8) > length(o) - actual:
                return fail(w, 17)
            write(w, 72, actual, 8)
            write(w, 112, mw(w, 112, 8) + actual, 8)
        if actual != mw(w, 72, 8):
            return fail(w, 19)
        write(w, 80, 0, 8)
        write(w, 144, mw(w, 72, 8) + 1, 8)
        return issue(w, 4, 4)
    if phase == 4:
        if result == 18446744073709551612:
            return issue(w, 4, 4)
        if result > mw(w, 144, 8):
            return fail(w, 15)
        used = mw(w, 80, 8)
        size = mw(w, 72, 8)
        if result == 0:
            if used != size:
                return fail(w, 19)
            return issue(w, 5, 5)
        if result > size - used:
            return fail(w, 19)
        used = used + result
        write(w, 80, used, 8)
        write(w, 144, size - used + 1, 8)
        return issue(w, 4, 4)
    if phase == 5:
        if result != 0:
            return fail(w, 15)
        if (mw(w, 4776, 4) & 61440) != 32768 or mw(w, 4768, 8) != 1:
            return fail(w, 19)
        if mw(w, 4608, 8) != mw(w, 4752, 8) or mw(w, 4616, 8) != mw(w, 4760, 8):
            return fail(w, 19)
        if mw(w, 4656, 8) != mw(w, 4800, 8):
            return fail(w, 19)
        if mw(w, 4696, 8) != mw(w, 4840, 8) or mw(w, 4704, 8) != mw(w, 4848, 8):
            return fail(w, 19)
        if mw(w, 4712, 8) != mw(w, 4856, 8) or mw(w, 4720, 8) != mw(w, 4864, 8):
            return fail(w, 19)
        return issue(w, 6, 6)
    if phase == 6:
        if result != 0:
            return fail(w, 15)
        write(w, 64, 0, 8)
        return issue(w, 7, 7)
    if phase == 7:
        if result != 0:
            return fail(w, 18)
        return issue(w, 8, 8)
    if phase == 8:
        if result != 0:
            return fail(w, 18)
        return issue(w, 9, 9)
    if phase == 9:
        if result != 32:
            return fail(w, 18)
        pin = mw(w, 88, 8) + 24
        at = 0
        while at < 32:
            if byte(s, pin + at) != byte(w, 4896 + at):
                return fail(w, 19)
            at = at + 1
        target = mw(w, 48, 8)
        alias = mw(w, 96, 8)
        an = mw(w, 104, 8)
        size = mw(w, 72, 8)
        if mw(w, 120, 8) == RAW:
            copy_mut(w, o, 65537, 0, size)
            write(w, 48, size, 8)
        else:
            write(o, target, an, 8)
            write(o, target + 8, size, 8)
            copy_bytes(s, o, alias, target + 16, an)
            copy_mut(w, o, 65537, target + 16 + an, size)
            write(w, 48, target + 16 + an + size, 8)
        write(w, 40, mw(w, 40, 8) + 1, 8)
        return next_source(s, w)
    return fail(w, 16)

def next_source(s:readbuf, w:mutbuf) -> u32:
    index = mw(w, 40, 8)
    if index == mw(w, 32, 8):
        if mw(w, 48, 8) != mw(w, 112, 8):
            return fail(w, 16)
        write(w, 128, 0, 8)
        return issue(w, 10, 10)
    if index > mw(w, 32, 8):
        return fail(w, 16)
    slot = 16384 + 32 * index
    row = mw(w, slot, 8)
    size = mw(w, slot + 24, 8)
    path = row + 56
    pn = uint(s, row, 8)
    copy_bytes(s, w, path, 512, pn)
    store(w, 512 + pn, 0)
    write(w, 72, size, 8)
    write(w, 88, row, 8)
    write(w, 96, mw(w, slot + 8, 8), 8)
    write(w, 104, mw(w, slot + 16, 8), 8)
    return issue(w, 2, 2)

def issue(w:mutbuf, phase:u64, action:u64) -> u32:
    write(w, 0, phase, 8)
    write(w, 16, action, 8)
    write(w, 24, mw(w, 24, 8) + 1, 8)
    return action

def fail(w:mutbuf, code:u64) -> u32:
    write(w, 128, code, 8)
    write(w, 48, 0, 8)
    return issue(w, 11, 10)

def valid_path(s:readbuf, at:u64, n:u64) -> u64:
    if byte(s, at) == 47 or byte(s, at + n - 1) == 47:
        return 0
    i = 0
    part = 0
    while i <= n:
        if i == n or byte(s, at + i) == 47:
            size = i - part
            if size == 0 or (size == 1 and byte(s, at + part) == 46):
                return 0
            if size == 2 and byte(s, at + part) == 46 and byte(s, at + part + 1) == 46:
                return 0
            part = i + 1
        else:
            c = byte(s, at + i)
            if plain(c) == 0:
                return 0
        i = i + 1
    return 1

def valid_alias(s:readbuf, at:u64, n:u64) -> u64:
    if n < 7 or uint(s, at + n - 6, 6) != SUFFIX:
        return 0
    return valid_name(s, at, n)

def valid_name(s:readbuf, at:u64, n:u64) -> u64:
    i = 0
    while i < n:
        c = byte(s, at + i)
        if plain(c) == 0:
            return 0
        if i == 0 and (c == 46 or c == 45):
            return 0
        i = i + 1
    return 1

def plain(c:u64) -> u64:
    if (c >= 65 and c <= 90) or (c >= 97 and c <= 122) or (c >= 48 and c <= 57):
        return 1
    if c == 45 or c == 46 or c == 95:
        return 1
    return 0

def equal_source(s:readbuf, first:u64, second:u64, n:u64) -> u64:
    i = 0
    while i < n:
        if byte(s, first + i) != byte(s, second + i):
            return 0
        i = i + 1
    return 1

def mw(w:mutbuf, at:u64, n:u64) -> u64:
    value = 0
    i = 0
    while i < n:
        value = value | (byte(w, at + i) << (8 * i))
        i = i + 1
    return value

def copy_mut(s:mutbuf, o:mutbuf, first:u64, target:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, target + i, byte(s, first + i))
        i = i + 1
    return 0
'''

def policy_source():
    values = {'MAGIC2': MAGIC2, 'MAGIC': MAGIC, 'NAMED': TAGS[0], 'SINGLE': TAGS[1], 'IMAGE': TAGS[2], 'MULTI': TAGS[3],
              'KOBJ': TAGS[5], 'KIT': TAGS[4], 'RAW': TAGS[6],
              'SUFFIX': int.from_bytes(b'.hepta', 'little')}
    value = POLICY
    for key, number in values.items():
        value = value.replace(key, str(number))
    return value + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]

def template():
    with tempfile.TemporaryDirectory(prefix='hia-source-capture-author-') as tmp:
        obj, raw = Path(tmp) / 'adapter.o', Path(tmp) / 'adapter.bin'
        subprocess.run(['as', '--64', str(ROOT / 'tools/hia_source_capture_syscalls.S'), '-o', str(obj)], check=True, capture_output=True)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)], check=True, capture_output=True)
        symbols = {name: int(address, 16) for address, _, name in
                   (line.split() for line in subprocess.check_output(['nm', '-n', str(obj)], text=True).splitlines())}
        if symbols['_start'] != 0 or 'R_X86_64' in subprocess.check_output(['objdump', '-r', str(obj)], text=True):
            raise ValueError('source-capture transport has unresolved relocations')
        code = raw.read_bytes()
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + code, {name: 176 + symbols[name] for name in ('policy_hole', 'sha_hole')}

def packer_source():
    prefix, holes = template()
    code = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 26 or uint(s, 0, 8) != {PACK}:
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
        code += f'    write(o, {at}, {int.from_bytes(chunk, "little")}, {len(chunk)})\n'
    code += '    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n'
    for name, at in holes.items():
        target = str(len(prefix)) + (' + policy' if name == 'sha_hole' else '')
        code += f'    write(o, {at}, {target} - {at+4}, 4)\n'
    code += f'    copy_bytes(s, o, 24, {len(prefix)}, policy + sha)\n    return size\n'
    return code + LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]

def main():
    for name, source in (('source_capture', policy_source()), ('source_capture_packer', packer_source())):
        path = ROOT / 'examples/hia_bootstrap' / (name + '.hepta')
        path.write_text(render_assembly(document(source, name)))
        print(path.name, path.stat().st_size)

if __name__ == '__main__':
    main()
