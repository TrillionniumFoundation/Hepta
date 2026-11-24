"""Author a lossless, bounded HIA archive chunk codec with an independent decoder."""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_document import document

ROOT = Path(__file__).resolve().parents[1]
MAGIC = int.from_bytes(b'HIAQAZ01', 'little')

CODEC = r'''def pack_chunk(w:mutbuf, size:u64) -> u64:
    if size == 0 or size > 65504:
        return 0
    pos = 0
    literal = 0
    output = 800032
    while pos + 24 <= size:
        value = get(w, 700000 + pos)
        if value == get(w, 700008 + pos) and value == get(w, 700016 + pos):
            if pos != literal:
                put(w, output, (pos - literal) * 2)
                copyw(w, output + 8, 700000 + literal, pos - literal)
                output = output + 8 + pos - literal
            count = 3
            while pos + count * 8 + 8 <= size and get(w, 700000 + pos + count * 8) == value:
                count = count + 1
            put(w, output, count * 2 + 1)
            put(w, output + 8, value)
            output = output + 16
            pos = pos + count * 8
            literal = pos
        else:
            pos = pos + 8
    if literal < size:
        put(w, output, (size - literal) * 2)
        copyw(w, output + 8, 700000 + literal, size - literal)
        output = output + 8 + size - literal
    compressed = output - 800032
    mode = 1
    if compressed >= size:
        compressed = size
        mode = 0
        copyw(w, 800032, 700000, size)
    put(w, 800000, CHUNK_MAGIC)
    put(w, 800008, size)
    put(w, 800016, compressed)
    put(w, 800024, mode)
    return 32 + compressed

def unpack_chunk(w:mutbuf, encoded:u64) -> u64:
    if encoded < 33 or encoded > 65536 or get(w, 800000) != CHUNK_MAGIC:
        return 0
    size = get(w, 800008)
    payload = get(w, 800016)
    mode = get(w, 800024)
    if size == 0 or size > 65504 or payload != encoded - 32 or mode > 1:
        return 0
    if mode == 0:
        if payload != size:
            return 0
        copyw(w, 940000, 800032, size)
        return size
    pos = 800032
    end = 800000 + encoded
    out = 0
    while pos < end:
        if end - pos < 8:
            return 0
        token = get(w, pos)
        amount = token >> 1
        pos = pos + 8
        if amount == 0:
            return 0
        if token & 1 == 0:
            if amount > end - pos or amount > size - out:
                return 0
            copyw(w, 940000 + out, pos, amount)
            pos = pos + amount
            out = out + amount
        else:
            if end - pos < 8 or amount > (size - out) >> 3:
                return 0
            value = get(w, pos)
            pos = pos + 8
            byte_value = value & 255
            if value == byte_value * 72340172838076673:
                fill_range(w, 940000 + out, amount * 8, byte_value)
                out = out + amount * 8
            else:
                i = 0
                while i < amount:
                    put(w, 940000 + out, value)
                    out = out + 8
                    i = i + 1
    if pos != end or out != size:
        return 0
    return size

def chunk_equal(w:mutbuf, size:u64) -> u64:
    i = 0
    while i + 8 <= size:
        if get(w, 700000 + i) != get(w, 940000 + i):
            return 0
        i = i + 8
    while i < size:
        if byte(w, 700000 + i) != byte(w, 940000 + i):
            return 0
        i = i + 1
    return 1
'''.replace('CHUNK_MAGIC', str(MAGIC))

ENTRY = r'''def codec(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 17 or word_load(s, 0) != ENTRY_MAGIC or length(w) < 1005504:
        return 4294967295
    mode = word_load(s, 8)
    size = length(s) - 16
    if size > 65536 or mode > 1:
        return 4294967295
    at = choose(mode == 0, 700000, 800000)
    i = 0
    while i < size:
        store(w, at + i, byte(s, 16 + i))
        i = i + 1
    result = 0
    if mode == 0:
        result = pack_chunk(w, size)
        if result == 0 or unpack_chunk(w, result) != size or chunk_equal(w, size) == 0:
            return 4294967295
        at = 800000
    else:
        result = unpack_chunk(w, size)
        if result == 0:
            return 4294967295
        at = 940000
    if length(o) < result:
        return 4294967294
    i = 0
    while i < result:
        store(o, i, byte(w, at + i))
        i = i + 1
    return result
'''.replace('ENTRY_MAGIC', str(int.from_bytes(b'HIAQCP01', 'little')))

HELPERS = r'''def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (8 * i)) & 255)
        i = i + 1
    return 0

def copyw(w:mutbuf, to:u64, source:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, to + i, byte(w, source + i))
        i = i + 1
    return 0
'''


if __name__ == '__main__':
    path = ROOT / 'examples/hia_bootstrap/cold_qualification_codec.hepta'
    path.write_text(render_assembly(document(ENTRY + '\n' + CODEC + '\n' + HELPERS,
                                             'cold_qualification_codec')))
    print(path.name, path.stat().st_size)
