"""Author the HIA verifier and relocatable-object transform for embedded build code."""

from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cli_discovery_json import document
from tools.generate_hia_worker_publication_observation import sha256_range


SOURCE = '''
def core_packed_assets(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1114112 or length(o) < 64:
        return 16
    phase = word_load(w, 0)
    state = word_load(w, 16)
    if phase == 0 and state == 0:
        if length(s) != 21 or word_load(s, 0) != 1 or word_load(s, 8) != 5 or small(s, 16, 5) != 431315580258:
            return 16
        word_store(w, 16, 1)
        return 0
    if phase == 2 and state == 7:
        return 3
    if phase != 1 or state != 1 or length(s) < 64 or word_load(s, 0) != PACK_MAGIC:
        return 16
    size = word_load(s, 8)
    if size < 38 or size > length(s) - 16 or word_load(s, 16) != LINK_MAGIC:
        return 16
    count = word_load(s, 24)
    if count < 21 or count > 128 or word_load(s, 32) != 6 or word_load(s, 40) != 0 or small(s, 48, 6) != START_NAME:
        return 16
    # Each additional input is the exact 48-byte runtime descriptor plus raw DEFLATE.
    cursor = 16 + size
    i = 0
    while i < 4:
        if length(s) - cursor < 48:
            return 16
        encoded = word_load(s, cursor + 8)
        raw = word_load(s, cursor)
        if raw == 0 or raw > 1048576 or encoded == 0 or encoded > 1048528 or encoded > length(s) - cursor - 48:
            return 16
        word_store(w, 512 + i * 8, cursor)
        cursor = cursor + 48 + encoded
        i = i + 1
    if cursor != length(s):
        return 16
    # Verify all four physical .rodata images before publishing the first object.
    cursor = 54
    seen = 0
    index = 0
    while index < count:
        if 16 + size - cursor < 8:
            return 16
        extent = word_load(s, cursor)
        origin = cursor + 8
        if extent < 64 or extent > 16 + size - origin:
            return 16
        if index >= 17 and index <= 20:
            slot = index - 17
            meta = word_load(w, 512 + slot * 8)
            if check_object(s, o, w, origin, extent, slot, meta) == 0:
                return 19
            seen = seen + 1
        cursor = origin + extent
        index = index + 1
    if cursor != 16 + size or seen != 4:
        return 16
    at = copy(s, o, 16, 0, 38)
    cursor = 54
    index = 0
    while index < count:
        extent = word_load(s, cursor)
        if index >= 17 and index <= 20:
            slot = index - 17
            meta = word_load(w, 512 + slot * 8)
            at = rewrite(s, o, cursor + 8, extent, at, meta)
            if at == 0:
                return 19
        else:
            if extent + 8 > length(o) - at:
                return 17
            at = copy(s, o, cursor, at, extent + 8)
        cursor = cursor + 8 + extent
        index = index + 1
    word_store(w, 88, at)
    word_store(w, 16, 7)
    return 0

def check_object(s:readbuf, o:mutbuf, w:mutbuf, origin:u64, extent:u64, slot:u64, meta:u64) -> u64:
    if extent < 64 + 72 + 576 or word_load(s, origin) != ELF_ID or word_load(s, origin + 16) != ELF_TYPE:
        return 0
    sh = word_load(s, origin + 40)
    if sh != extent - 576 or (sh & 7) != 0:
        return 0
    table = origin + sh
    size = word_load(s, meta)
    if size > extent - 64 or word_load(s, table + 4 * 64 + 24) != 64 or word_load(s, table + 4 * 64 + 32) != size:
        return 0
    sym = (64 + size + 7) & 18446744073709551608
    strings = sym + 72
    name = label_size(slot)
    names = strings + 2 * name + 13
    if sh != ((names + SECTION_TABLE_ROUND) & 18446744073709551608) or word_load(s, table + 5 * 64 + 24) != 64 + size:
        return 0
    if word_load(s, table + 6 * 64 + 24) != sym or word_load(s, table + 7 * 64 + 24) != strings or word_load(s, table + 8 * 64 + 24) != names:
        return 0
    if word_load(s, origin + sym + 56) != size or name_ok(s, origin + strings + 1, slot) == 0:
        return 0
    if small(s, origin + strings + name + 1, 7) != START_SUFFIX or name_ok(s, origin + strings + name + 8, slot) == 0 or small(s, origin + strings + 2 * name + 8, 5) != END_SUFFIX:
        return 0
    if sha256_range(s, origin + 64, size, o, w) != 32:
        return 0
    i = 0
    while i < 32:
        if byte(s, meta + 16 + i) != byte(o, i):
            return 0
        i = i + 1
    return validates(s, w, origin + 64, size, meta + 48, word_load(s, meta + 8))

def rewrite(s:readbuf, o:mutbuf, origin:u64, extent:u64, dest:u64, meta:u64) -> u64:
    n = 48 + word_load(s, meta + 8)
    raw = word_load(s, meta)
    sym = (64 + raw + 7) & 18446744073709551608
    new = (64 + n + 7) & 18446744073709551608
    size = new + extent - sym
    if dest > length(o) or size + 8 > length(o) - dest:
        return 0
    word_store(o, dest, size)
    base = dest + 8
    copy(s, o, origin, base, 64)
    copy(s, o, meta, base + 64, n)
    i = 64 + n
    while i < new:
        store(o, base + i, 0)
        i = i + 1
    copy(s, o, origin + sym, base + new, extent - sym)
    sh = size - 576
    table = base + sh
    word_store(o, base + 40, sh)
    word_store(o, base + new + 56, n)
    word_store(o, table + 4 * 64 + 32, n)
    word_store(o, table + 5 * 64 + 24, 64 + n)
    index = 6
    while index <= 8:
        row = table + index * 64 + 24
        word_store(o, row, word_load(o, row) - sym + new)
        index = index + 1
    return base + size

def copy(s:readbuf, o:mutbuf, origin:u64, dest:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(o, dest + i, byte(s, origin + i))
        i = i + 1
    return dest + size

def small(s:readbuf, at:u64, width:u64) -> u64:
    v = 0
    i = 0
    while i < width:
        v = v | (byte(s, at + i) << (8 * i))
        i = i + 1
    return v

# Compare literals and each overlapping back-reference against the newly
# compiled image. The verified prefix is the DEFLATE dictionary at that point.
def validates(s:readbuf, w:mutbuf, raw:u64, size:u64, stream:u64, extent:u64) -> u64:
    word_store(w, 600, stream * 8)
    word_store(w, 608, (stream + extent) * 8)
    cursor = 0
    last = 0
    while last == 0:
        header = bits(s, w, 3, 0)
        if header >= 4:
            return 0
        last = header & 1
        if header < 2:
            off = (word_load(w, 600) + 7) >> 3
            if off > stream + extent or stream + extent - off < 4:
                return 0
            count = small(s, off, 2)
            if (count ^ small(s, off + 2, 2)) != 65535 or count > size - cursor or count > stream + extent - off - 4:
                return 0
            i = 0
            while i < count:
                if byte(s, raw + cursor + i) != byte(s, off + 4 + i):
                    return 0
                i = i + 1
            word_store(w, 600, (off + 4 + count) * 8)
            cursor = cursor + count
        else:
            cursor = literals(s, w, raw, size, cursor)
            if cursor > size:
                return 0
    return choose(cursor == size and ((word_load(w, 600) + 7) >> 3) == stream + extent, 1, 0)

def bits(s:readbuf, w:mutbuf, width:u64, reverse:u64) -> u64:
    at = word_load(w, 600)
    if width > word_load(w, 608) - at:
        return 1048577
    value = 0
    i = 0
    while i < width:
        bit = (byte(s, (at + i) >> 3) >> ((at + i) & 7)) & 1
        if reverse == 1:
            value = (value << 1) | bit
        else:
            value = value | (bit << i)
        i = i + 1
    word_store(w, 600, at + width)
    return value

def symbol(s:readbuf, w:mutbuf) -> u64:
    code = bits(s, w, 7, 1)
    if code > 127:
        return 1048577
    if code < 24:
        return 256 + code
    extra = bits(s, w, 1, 0)
    if extra > 1:
        return 1048577
    code = 2 * code + extra
    if code < 192:
        return code - 48
    if code < 200:
        return code + 88
    extra = bits(s, w, 1, 0)
    return 2 * code + extra - 256

def literals(s:readbuf, w:mutbuf, raw:u64, size:u64, pos:u64) -> u64:
    while True:
        code = symbol(s, w)
        if code == 256:
            return pos
        if code > 285:
            return 1048577
        if code < 256:
            if pos == size or byte(s, raw + pos) != code:
                return 1048577
            pos = pos + 1
        else:
            count = code - 254
            if code == 285:
                count = 258
            elif code > 264:
                width = (code - 261) >> 2
                count = (4 << width) + 3 + (((code - 265) & 3) << width) + bits(s, w, width, 0)
            dist = bits(s, w, 5, 1)
            if count > size - pos or dist > 29:
                return 1048577
            if dist < 4:
                distance = dist + 1
            else:
                width = (dist >> 1) - 1
                distance = (2 << width) + 1 + ((dist & 1) << width) + bits(s, w, width, 0)
            if distance > pos:
                return 1048577
            i = 0
            while i < count:
                if byte(s, raw + pos + i) != byte(s, raw + pos + i - distance):
                    return 1048577
                i = i + 1
            pos = pos + count
    return 1048577

def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, 8192 + at)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    word_store(w, 8192 + at, value)
    return 0
'''


def render():
    from tools.build_hia_core_edit import PACKED_BUILD_IMAGES
    from tools.generate_hia_elf_embed import SECTIONS

    constants = {'PACK_MAGIC': b'HIACPA01', 'LINK_MAGIC': b'HIALNK01', 'START_NAME': b'_start',
                 'ELF_ID': b'\x7fELF\x02\x01\x01\0', 'ELF_TYPE': b'\x01\0\x3e\0\x01\0\0\0',
                 'START_SUFFIX': b'_start\0', 'END_SUFFIX': b'_end\0'}
    src = SOURCE.replace('SECTION_TABLE_ROUND', str(len(SECTIONS) + 7))
    for name, value in constants.items():
        src = src.replace(name, str(int.from_bytes(value, 'little')))
    names = list(PACKED_BUILD_IMAGES.values())
    src += '\ndef label_size(slot:u64) -> u64:\n'
    for i, name in enumerate(names):
        src += f'    if slot == {i}:\n        return {len(name)}\n'
    src += '    return 0\n\ndef name_ok(s:readbuf, at:u64, slot:u64) -> u64:\n'
    for i, name in enumerate(names):
        comparisons = []
        for off in range(0, len(name), 8):
            chunk = name[off:off+8].encode()
            comparisons.append(f'small(s, at + {off}, {len(chunk)}) == {int.from_bytes(chunk,"little")}')
        src += f'    if slot == {i}:\n        return choose({" and ".join(comparisons)}, 1, 0)\n'
    src += '    return 0\n'
    sha = sha256_range().split('def get(')[0].replace('o:mutbuf, w:mutbuf) -> u32:', 'o:mutbuf, w:mutbuf) -> u64:', 1)
    return render_assembly(document(src + '\n' + sha, module='source_core_packed_assets', word_memory=True))


if __name__ == '__main__':
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/source_core_packed_assets.hepta'
    path.write_text(render())
