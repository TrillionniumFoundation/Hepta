"""Author the bounded, deterministic raw DEFLATE encoder for HIA releases."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_elf_linker import SOURCE as LINK_SOURCE

ENCODER = r'''
# Bounded RFC 1951 fixed-Huffman, raw DEFLATE. Positions are stored plus one.
# A 32 KiB rolling history and a 16-bit hash table share the caller's workspace.
# Incompressible data may instead use byte-aligned stored blocks.
def deflate(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = length(s)
    if size > 1048576 or length(o) > 1048576 or length(w) != 393216:
        return 4294967295
    clear = 0
    while clear < length(w):
        write(w, clear, 0, 8)
        clear = clear + 8
    cursor = append_bits(o, 0, 3, 3)
    start = 0
    while start < size and cursor != 4294967295:
        limit = size - start
        if limit > 258:
            limit = 258
        count = 2
        distance = 0
        if limit >= 3:
            recent = word(w, 4 * hash_triple(s, start))
            probes = 0
            while recent != 0 and start + 1 - recent <= 32768 and probes < 48 and count < limit:
                match = recent - 1
                if byte(s, match + count) == byte(s, start + count):
                    run = 0
                    while run < limit and byte(s, match + run) == byte(s, start + run):
                        run = run + 1
                    if run > count:
                        count = run
                        distance = start - match
                recent = word(w, 262144 + 4 * (match & 32767))
                probes = probes + 1
        if count > 2:
            cursor = emit_match(o, cursor, count, distance)
        else:
            count = 1
            cursor = emit_symbol(o, cursor, byte(s, start))
        stop = start + count
        while start < stop:
            if size - start >= 3:
                bucket = 4 * hash_triple(s, start)
                prior = word(w, bucket)
                write(w, 262144 + 4 * (start & 32767), prior, 4)
                write(w, bucket, start + 1, 4)
            start = start + 1
    cursor = emit_symbol(o, cursor, 256)
    packed = (cursor + 7) >> 3
    stored_size = size
    block = 0
    while block < size:
        stored_size = stored_size + 5
        block = block + 65535
    if size != 0 and stored_size < packed and stored_size <= length(o):
        return stored(s, o, size)
    if cursor == 4294967295:
        return cursor
    return packed

def stored(s:readbuf, o:mutbuf, size:u64) -> u64:
    start = 0
    target = 0
    while start < size:
        count = size - start
        if count > 65535:
            count = 65535
        final = 0
        if start + count == size:
            final = 1
        store(o, target, final)
        write(o, target + 1, count, 2)
        write(o, target + 3, count ^ 65535, 2)
        copy_bytes(s, o, start, target + 5, count)
        start = start + count
        target = target + count + 5
    tail = target
    while tail < length(o):
        store(o, tail, 0)
        tail = tail + 1
    return target

def hash_triple(s:readbuf, start:u64) -> u64:
    # Multiplication gives competing byte prefixes distinct hash bits.
    return ((uint(s, start, 3) * 506832829) >> 16) & 65535

def word(w:mutbuf, at:u64) -> u64:
    return byte(w, at) | (byte(w, at + 1) << 8) | (byte(w, at + 2) << 16) | (byte(w, at + 3) << 24)

def reverse_bits(value:u64, width:u64) -> u64:
    first = ((value & 21845) << 1) | ((value >> 1) & 21845)
    second = ((first & 13107) << 2) | ((first >> 2) & 13107)
    third = ((second & 3855) << 4) | ((second >> 4) & 3855)
    return (((third & 255) << 8) | (third >> 8)) >> (16 - width)

def append_bits(o:mutbuf, at:u64, value:u64, width:u64) -> u64:
    if at == 4294967295 or width > length(o) * 8 - at:
        return 4294967295
    end = at + width
    while at < end:
        offset = at & 7
        position = at >> 3
        take = 8 - offset
        if take > end - at:
            take = end - at
        prefix = 0
        if offset != 0:
            prefix = byte(o, position)
        shift = (value & ((1 << take) - 1)) << offset
        store(o, position, prefix | shift)
        at = at + take
        value = value >> take
    return end

def emit_symbol(o:mutbuf, at:u64, symbol:u64) -> u64:
    if symbol < 144:
        return append_bits(o, at, reverse_bits(symbol + 48, 8), 8)
    if symbol < 256:
        return append_bits(o, at, reverse_bits(symbol + 256, 9), 9)
    if symbol < 280:
        return append_bits(o, at, reverse_bits(symbol - 256, 7), 7)
    return append_bits(o, at, reverse_bits(symbol - 88, 8), 8)

def emit_match(o:mutbuf, at:u64, count:u64, distance:u64) -> u64:
    if count == 258:
        at = emit_symbol(o, at, 285)
    elif count <= 10:
        at = emit_symbol(o, at, 254 + count)
    else:
        width = 1
        while count - 3 >= (8 << width):
            width = width + 1
        base = (4 << width) + 3
        index = (count - base) >> width
        at = emit_symbol(o, at, 261 + width * 4 + index)
        at = append_bits(o, at, count - base - (index << width), width)
    if distance <= 4:
        return append_bits(o, at, reverse_bits(distance - 1, 5), 5)
    extra = 1
    while distance - 1 >= (4 << extra):
        extra = extra + 1
    minimum = (2 << extra) + 1
    part = (distance - minimum) >> extra
    code = (extra + 1) * 2 + part
    at = append_bits(o, at, reverse_bits(code, 5), 5)
    return append_bits(o, at, distance - minimum - (part << extra), extra)
'''


def render():
    helpers = LINK_SOURCE[LINK_SOURCE.index('\ndef uint('):]
    return render_assembly(document(ENCODER + helpers, 'release_deflate'))


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    (root / 'examples/hia_bootstrap/core_cli/release_deflate.hepta').write_text(render())
