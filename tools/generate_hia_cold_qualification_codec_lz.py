"""Separate lossless HIAQAZ02 journal codec; legacy chunks remain decodable.

The new mode is bounded LZ with an encoder-only 8192-slot u16 dictionary.
The decoder uses only the encoded bytes and its forward output, never that
dictionary or the original raw chunk. Existing chunk and driver limits remain.
"""
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_document import document
from tools.generate_hia_cold_qualification_codec import CODEC as ORIGINAL_CODEC, MAGIC as LEGACY_MAGIC

ROOT = Path(__file__).resolve().parents[1]
MAGIC = int.from_bytes(b'HIAQAZ02', 'little')
WORKSPACE_BYTES = 3293184

LEGACY = ORIGINAL_CODEC.replace('def pack_chunk(', 'def pack_chunk_rle(').replace(
    'def unpack_chunk(', 'def unpack_chunk_rle(')
LEGACY = LEGACY.replace(
    'get(w, 800000) != ' + str(LEGACY_MAGIC),
    '(get(w, 800000) != ' + str(LEGACY_MAGIC) + ' and get(w, 800000) != ' + str(MAGIC) + ')')

LZ = r'''def pack_lz(w:mutbuf, size:u64, best:u64) -> u64:
    fill_range(w, 3276800, 16384, 0)
    pos = 0
    literal = 0
    output = 0
    while pos + 8 <= size:
        value = word_load(w, 700000 + pos)
        slot = (value ^ (value >> 13) ^ (value >> 26) ^ (value >> 39) ^ (value >> 52)) & 8191
        at = 3276800 + slot * 2
        previous = byte(w, at) | (byte(w, at + 1) << 8)
        store(w, at, (pos + 1) & 255)
        store(w, at + 1, (pos + 1) >> 8)
        matched = 0
        if previous != 0:
            candidate = previous - 1
            if candidate < pos and word_load(w, 700000 + candidate) == value:
                matched = 8
                while pos + matched + 8 <= size and word_load(w, 700000 + pos + matched) == word_load(w, 700000 + candidate + matched):
                    matched = matched + 8
                while pos + matched < size and byte(w, 700000 + pos + matched) == byte(w, 700000 + candidate + matched):
                    matched = matched + 1
        if matched >= 8:
            count = pos - literal
            needed = 5
            if count != 0:
                needed = needed + 3 + count
            if output + needed >= best:
                return 0
            if count != 0:
                store(w, 880000 + output, 0)
                store(w, 880001 + output, count & 255)
                store(w, 880002 + output, count >> 8)
                copyw(w, 880003 + output, 700000 + literal, count)
                output = output + 3 + count
            distance = pos - (previous - 1)
            store(w, 880000 + output, 1)
            store(w, 880001 + output, matched & 255)
            store(w, 880002 + output, matched >> 8)
            store(w, 880003 + output, distance & 255)
            store(w, 880004 + output, distance >> 8)
            output = output + 5
            pos = pos + matched
            literal = pos
        else:
            pos = pos + 1
    if literal != size:
        count = size - literal
        if output + 3 + count >= best:
            return 0
        store(w, 880000 + output, 0)
        store(w, 880001 + output, count & 255)
        store(w, 880002 + output, count >> 8)
        copyw(w, 880003 + output, 700000 + literal, count)
        output = output + 3 + count
    if output == 0 or output >= best:
        return 0
    return output

def pack_chunk(w:mutbuf, size:u64) -> u64:
    result = pack_chunk_rle(w, size)
    if result == 0:
        return 0
    put(w, 800000, NEW_MAGIC)
    best = result - 32
    if best < 64:
        return result
    compressed = pack_lz(w, size, best)
    if compressed == 0:
        return result
    copyw(w, 800032, 880000, compressed)
    put(w, 800016, compressed)
    put(w, 800024, 2)
    return 32 + compressed

def unpack_chunk(w:mutbuf, encoded:u64) -> u64:
    if encoded < 33 or encoded > 65536:
        return 0
    magic = word_load(w, 800000)
    if magic != OLD_MAGIC and magic != NEW_MAGIC:
        return 0
    size = word_load(w, 800008)
    payload = word_load(w, 800016)
    mode = word_load(w, 800024)
    if size == 0 or size > 65504 or payload != encoded - 32 or mode > 2:
        return 0
    if mode < 2:
        return unpack_chunk_rle(w, encoded)
    if magic != NEW_MAGIC:
        return 0
    pos = 800032
    end = 800000 + encoded
    out = 0
    while pos < end:
        if end - pos < 3:
            return 0
        token = byte(w, pos)
        amount = byte(w, pos + 1) | (byte(w, pos + 2) << 8)
        pos = pos + 3
        if amount == 0:
            return 0
        if token == 0:
            if amount > end - pos or amount > size - out:
                return 0
            copyw(w, 940000 + out, pos, amount)
            pos = pos + amount
            out = out + amount
        else:
            if token != 1 or amount < 8 or end - pos < 2:
                return 0
            distance = byte(w, pos) | (byte(w, pos + 1) << 8)
            pos = pos + 2
            if distance == 0 or distance > out or amount > size - out:
                return 0
            copy_forward(w, 940000 + out, 940000 + out - distance, amount, distance)
            out = out + amount
    if pos != end or out != size:
        return 0
    return size

def copy_forward(w:mutbuf, to:u64, source:u64, size:u64, distance:u64) -> u64:
    if distance != 0 and to >= source and to-source == distance and to <= length(w) and size <= length(w)-to:
        first = choose(distance < size,distance,size)
        copyw(w,to,source,first)
        written = first
        while written < size:
            amount = choose(written < size-written,written,size-written)
            copyw(w,to+written,to,amount)
            written = written+amount
        return 0
    i = 0
    if distance >= 8:
        while i + 8 <= size:
            value = word_load(w, source + i)
            store(w, to + i, value & 255)
            store(w, to + i + 1, (value >> 8) & 255)
            store(w, to + i + 2, (value >> 16) & 255)
            store(w, to + i + 3, (value >> 24) & 255)
            store(w, to + i + 4, (value >> 32) & 255)
            store(w, to + i + 5, (value >> 40) & 255)
            store(w, to + i + 6, (value >> 48) & 255)
            store(w, to + i + 7, (value >> 56) & 255)
            i = i + 8
    while i < size:
        store(w, to + i, byte(w, source + i))
        i = i + 1
    return 0
'''.replace('NEW_MAGIC', str(MAGIC)).replace('OLD_MAGIC', str(LEGACY_MAGIC))

CODEC = LEGACY + '\n' + LZ

ENTRY = r'''def codec(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 17 or word_load(s, 0) != ENTRY_MAGIC or length(w) < 3293184:
        return 4294967295
    mode = word_load(s, 8)
    size = length(s) - 16
    if size > 65536 or mode > 1:
        return 4294967295
    at = choose(mode == 0, 700000, 800000)
    i = 0
    while i + 8 <= size:
        value = word_load(s, 16 + i)
        put(w, at + i, value)
        i = i + 8
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
    while i + 8 <= result:
        value = word_load(w, at + i)
        store(o, i, value & 255)
        store(o, i + 1, (value >> 8) & 255)
        store(o, i + 2, (value >> 16) & 255)
        store(o, i + 3, (value >> 24) & 255)
        store(o, i + 4, (value >> 32) & 255)
        store(o, i + 5, (value >> 40) & 255)
        store(o, i + 6, (value >> 48) & 255)
        store(o, i + 7, (value >> 56) & 255)
        i = i + 8
    while i < result:
        store(o, i, byte(w, at + i))
        i = i + 1
    return result
'''.replace('ENTRY_MAGIC', str(int.from_bytes(b'HIAQCP01', 'little')))

HELPERS = r'''def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at, value & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    store(w, at + 4, (value >> 32) & 255)
    store(w, at + 5, (value >> 40) & 255)
    store(w, at + 6, (value >> 48) & 255)
    store(w, at + 7, (value >> 56) & 255)
    return 0

def copyw(w:mutbuf, to:u64, source:u64, size:u64) -> u64:
    i = 0
    while i + 8 <= size:
        value = word_load(w, source + i)
        store(w, to + i, value & 255)
        store(w, to + i + 1, (value >> 8) & 255)
        store(w, to + i + 2, (value >> 16) & 255)
        store(w, to + i + 3, (value >> 24) & 255)
        store(w, to + i + 4, (value >> 32) & 255)
        store(w, to + i + 5, (value >> 40) & 255)
        store(w, to + i + 6, (value >> 48) & 255)
        store(w, to + i + 7, (value >> 56) & 255)
        i = i + 8
    while i < size:
        store(w, to + i, byte(w, source + i))
        i = i + 1
    return 0
'''


def main():
    doc = document(ENTRY + '\n' + CODEC + '\n' + HELPERS, 'cold_qualification_codec_lz')
    path = ROOT / 'examples/hia_bootstrap/cold_qualification_codec_lz.hepta'
    path.write_text(render_assembly(doc))
    print(path.name, path.stat().st_size, len(doc['functions']),
          sum(len(f['blocks']) for f in doc['functions']),
          sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))


if __name__ == '__main__':
    main()
