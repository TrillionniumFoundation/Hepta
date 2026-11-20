"""Author the native bounded-page policy for existing Agent artifacts."""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_elf_linker import LinkerBuilder, SOURCE as LINKER_SOURCE
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_worker_request import hash_program, replace_once


SOURCE = r'''
def page(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    size = length(s)
    if size >= 8 and uint(s, 0) == LOOKUP_INPUT_TAG:
        return lookup_cursor(s, o, size)
    if size < 24:
        return 4294967295
    mode = uint(s, 0)
    begin = 24
    reference = 0
    reference_at = 32
    output_base = 0
    offset = uint(s, 8)
    limit = uint(s, 16)
    if mode == BOUND_INPUT_TAG:
        if size < 1024 or length(o) < 40 or length(w) < 16:
            return 4294967295
        reference = uint(s, 24)
        reference_at = 1024
        window = bound_window(s, w)
        if window == 1:
            put(o, 0, UNBOUND_OUTPUT_TAG)
            put(o, 8, 0)
            put(o, 16, 0)
            put(o, 24, 0)
            put(o, 32, 0)
            return 40
        if window != 0:
            return 4294967295
        offset = byte_word(w, 0)
        limit = byte_word(w, 8)
        output_base = 32
    elif mode == CURSOR_INPUT_TAG:
        if size < 32:
            return 4294967295
        reference = uint(s, 24)
    elif mode != INPUT_TAG:
        return 4294967295
    if mode != INPUT_TAG:
        # The bound covers the full public reference including JSON escapes.
        if reference == 0 or reference > 512 or reference > size - reference_at:
            return 4294967295
        if length(w) < 4128 + reference:
            return 4294967295
        begin = reference_at + reference
    total = size - begin
    if total > 67108864:
        return 4294967295
    if limit == 0 or limit > 65536:
        return 4294967295
    start = begin + offset
    wanted = 0
    if offset < total:
        wanted = total - offset
        if wanted > limit:
            wanted = limit
    else:
        start = size
    kind = 0
    if is_utf8(s, begin, size) == 0:
        kind = 1
    if kind == 0:
        result = text_extent(s, start, wanted)
        count = result >> 32
        cost = result & 4294967295
        while cost > 230000:
            result = text_extent(s, start, count // 2)
            count = result >> 32
            cost = result & 4294967295
    else:
        count = wanted
    next = 18446744073709551615
    if offset < total and count < total - offset:
        next = offset + count
    return finish_page(s, o, w, start, kind, count, next, offset, limit, output_base)

def lookup_cursor(s:readbuf, o:mutbuf, size:u64) -> u64:
    # The admitted JSON string is at most 512 scalars, or 2048 UTF-8 bytes.
    count = size - 8
    if count > 2048 or is_utf8(s, 8, size) == 0:
        return 4294967295
    end = 56 + count
    if length(o) < end:
        return 4294967294
    # HIAQPA01 v1, one inline text predicate for the fixed cursor query.
    put(o, 0, LOOKUP_PARAMETER_TAG)
    put(o, 8, 1)
    put(o, 16, 1)
    put(o, 24, end)
    retain_cell(o, 32, 3, 56, count)
    copy_bytes(s, o, 8, 56, count)
    return end

def finish_page(s:readbuf, o:mutbuf, w:mutbuf, start:u64, kind:u64, count:u64,
                next:u64, offset:u64, limit:u64, output_base:u64) -> u64:
    mode = uint(s, 0)
    content = choose(kind == 0, count, 4 * ((count + 2) // 3))
    header = output_base + 40
    output_tag = OUTPUT_TAG
    cursor = mode != INPUT_TAG and next != 18446744073709551615
    if mode != INPUT_TAG:
        output_tag = CURSOR_OUTPUT_TAG
    if cursor:
        header = header + 69
    retain_size = 0
    if output_base != 0 and cursor:
        retain_size = 277 + uint(s, 32)
    if length(o) < header + content + retain_size:
        return 4294967294
    if cursor:
        reference_at = choose(output_base == 0, 32, 1024)
        if cursor_digest(s, w, reference_at, uint(s, 24), next) == 0:
            return 4294967295
        emit_cursor(o, w, output_base + 40)
    if output_base != 0:
        put(o, 0, BOUND_OUTPUT_TAG)
        put(o, 8, offset)
        put(o, 16, limit)
        put(o, 24, retain_size)
    put(o, output_base, output_tag)
    put(o, output_base + 8, kind)
    put(o, output_base + 16, count)
    put(o, output_base + 24, next)
    put(o, output_base + 32, content)
    if kind == 0:
        copy_bytes(s, o, start, header, count)
    else:
        encode_binary(s, o, start, count, header)
    if retain_size != 0:
        retain_cursor(s, o, header + content, output_base + 40, next, uint(s, 32))
    return header + content + retain_size

def retain_cursor(s:readbuf, o:mutbuf, at:u64, cursor:u64,
                  offset:u64, identity_size:u64) -> u64:
    # HIAINS01 v1, fixed INSERT OR IGNORE cursor plan (10), four cells.
    put(o, at, CURSOR_RETAIN_TAG)
    put(o, at + 8, 1)
    put(o, at + 16, 10)
    put(o, at + 24, 0)
    put(o, at + 32, 4)
    retain_cell(o, at + 40, 3, 136, 69)
    retain_cell(o, at + 64, 3, 205, identity_size)
    retain_cell(o, at + 88, 3, 205 + identity_size, 64)
    retain_cell(o, at + 112, 1, 269 + identity_size, 8)
    index = 0
    while index < 69:
        store(o, at + 136 + index, byte(o, cursor + index))
        index = index + 1
    copy_bytes(s, o, 120, at + 205, identity_size)
    copy_bytes(s, o, 56, at + 205 + identity_size, 64)
    return put(o, at + 269 + identity_size, offset)

def retain_cell(o:mutbuf, dir:u64, kind:u64, start:u64, size:u64) -> u64:
    put(o, dir, kind)
    put(o, dir + 8, start)
    return put(o, dir + 16, size)

def bound_window(s:readbuf, w:mutbuf) -> u64:
    flags = uint(s, 8)
    limit = uint(s, 16)
    identity_size = uint(s, 32)
    cursor_size = uint(s, 40)
    row_size = uint(s, 48)
    if flags > 3 or identity_size == 0 or identity_size > 256 or cursor_size > 128 or row_size > 512:
        return 2
    if flags & 1 == 0 and limit != 0:
        return 2
    if flags & 2 == 0 and (cursor_size != 0 or row_size != 0):
        return 2
    cursor_at = 120 + identity_size
    row = cursor_at + cursor_size
    if row + row_size > 1024:
        return 2
    offset = 0
    if flags & 2 != 0:
        if row_size == 0:
            return 1
        offset = bound_cursor(s, row, row_size, identity_size, cursor_at, cursor_size)
        if offset == 18446744073709551615:
            return 1
    if offset >= 9223372036854775808 or (flags & 1 != 0 and (limit == 0 or limit > 65536)):
        return 2
    if flags & 1 == 0:
        limit = 65536
    put(w, 0, offset)
    put(w, 8, limit)
    return 0

def bound_cursor(s:readbuf, row:u64, size:u64, identity_size:u64,
                 cursor_at:u64, cursor_size:u64) -> u64:
    invalid = 18446744073709551614
    mismatch = 18446744073709551615
    # HIAROW01 v1, cursor table (6), four cells: key, artifact ID, SHA, offset.
    if size < 128 or uint(s, row) != CURSOR_ROW_TAG or uint(s, row + 8) != 1:
        return invalid
    if uint(s, row + 16) != 6 or uint(s, row + 24) != 4:
        return invalid
    at = 128
    field = 0
    matches = 1
    while field < 4:
        descriptor = row + 32 + field * 24
        kind = uint(s, descriptor)
        start = uint(s, descriptor + 8)
        count = uint(s, descriptor + 16)
        if start != at or count > size - at:
            return invalid
        if field < 3:
            if kind != 3:
                return invalid
            want_at = choose(field == 0, cursor_at, choose(field == 1, 120, 56))
            want_size = choose(field == 0, cursor_size, choose(field == 1, identity_size, 64))
            if count != want_size or same(s, row + at, want_at, count) == 0:
                matches = 0
        else:
            if kind != 1 or count != 8 or at + 8 != size:
                return invalid
            if matches == 0:
                return mismatch
            position = uint(s, row + at)
            if position >= 9223372036854775808:
                return invalid
            return position
        at = at + count
        field = field + 1
    return invalid

def same(s:readbuf, l:u64, r:u64, count:u64) -> u64:
    step = 0
    while step < count:
        if byte(s, l + step) != byte(s, r + step):
            return 0
        step = step + 1
    return 1

def byte_word(s:mutbuf, at:u64) -> u64:
    word = 0
    index = 0
    while index < 8:
        word = word | (byte(s, at + index) << (8 * index))
        index = index + 1
    return word

def cursor_digest(s:readbuf, w:mutbuf, ref_at:u64, reference:u64, next:u64) -> u64:
    put(w, 0, CURSOR_ARTIFACT_FIRST)
    put(w, 8, CURSOR_ARTIFACT_LAST)
    copy_bytes(s, w, ref_at, 12, reference)
    end = 12 + reference
    put(w, end, CURSOR_OFFSET_FIRST)
    put(w, end + 8, CURSOR_OFFSET_LAST)
    end = end + 10
    remaining = next
    divisor = 1
    while remaining >= 10:
        remaining = remaining // 10
        divisor = divisor * 10
    while divisor != 0:
        store(w, end, 48 + next // divisor)
        next = next % divisor
        divisor = divisor // 10
        end = end + 1
    store(w, end, 125)
    return choose(hash_sha256(w, end + 1) == 32, 1, 0)

def emit_cursor(o:mutbuf, w:mutbuf, at:u64) -> u64:
    put(o, at, CURSOR_PREFIX)
    digest = length(w) - 4096 + 1088
    i = 0
    while i < 32:
        value = byte(w, digest + i)
        store(o, at + 5 + i * 2, hex_digit(value >> 4))
        store(o, at + 6 + i * 2, hex_digit(value & 15))
        i = i + 1
    return 0

def hex_digit(value:u64) -> u64:
    return choose(value < 10, value + 48, value + 87)

def is_utf8(s:readbuf, begin:u64, size:u64) -> u64:
    at = begin
    while at < size:
        first = byte(s, at)
        at = at + 1
        if first >= 128:
            at = multibyte_end(s, at, size, first)
            if at == 0:
                return 0
    return 1

def multibyte_end(s:readbuf, at:u64, size:u64, first:u64) -> u64:
    needed = 0
    low = 128
    high = 191
    if first >= 194 and first <= 223:
        needed = 1
    elif first >= 224 and first <= 239:
        needed = 2
        if first == 224:
            low = 160
        if first == 237:
            high = 159
    elif first >= 240 and first <= 244:
        needed = 3
        if first == 240:
            low = 144
        if first == 244:
            high = 143
    if needed == 0 or needed > size - at:
        return 0
    second = byte(s, at)
    if second < low or second > high:
        return 0
    i = 1
    while i < needed:
        tail = byte(s, at + i)
        if tail < 128 or tail > 191:
            return 0
        i = i + 1
    return at + needed

def text_extent(s:readbuf, start:u64, wanted:u64) -> u64:
    # JSON string quotes cost 2 bytes in the first form and 6 in the
    # twice-escaped MCP text form. Non-ASCII UTF-8 units stay verbatim.
    at = start
    end = start + wanted
    cost = 8
    while at < end:
        first = byte(s, at)
        width = 1
        if first >= 128:
            after = multibyte_end(s, at + 1, end, first)
            if after == 0:
                return ((at - start) << 32) | cost
            width = after - at
        if first == 34 or first == 92:
            cost = cost + 6
        elif first < 32:
            if first == 8 or first == 9 or first == 10 or first == 12 or first == 13:
                cost = cost + 5
            else:
                cost = cost + 13
        else:
            cost = cost + width * 2
        at = at + width
    return ((at - start) << 32) | cost

def encode_binary(s:readbuf, o:mutbuf, start:u64, size:u64, header:u64) -> u64:
    at = 0
    out = header
    while at < size:
        first = byte(s, start + at)
        second = 0
        third = 0
        tail1 = 61
        tail2 = 61
        if size - at >= 2:
            second = byte(s, start + at + 1)
        if size - at >= 3:
            third = byte(s, start + at + 2)
            tail2 = alphabet(third & 63)
        if size - at >= 2:
            tail1 = alphabet(((second & 15) << 2) | (third >> 6))
        store(o, out, alphabet(first >> 2))
        store(o, out + 1, alphabet(((first & 3) << 4) | (second >> 4)))
        store(o, out + 2, tail1)
        store(o, out + 3, tail2)
        at = at + 3
        out = out + 4
    return 0

def alphabet(value:u64) -> u64:
    if value < 26:
        return 65 + value
    if value < 52:
        return 97 + value - 26
    if value < 62:
        return 48 + value - 52
    if value == 62:
        return 43
    return 47

def uint(s:readbuf, index:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, index + i) << (i * 8))
        i = i + 1
    return value

def put(o:mutbuf, index:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, index + i, value >> (i * 8))
        i = i + 1
    return 0
'''


def document():
    source = SOURCE
    for symbol, raw in (
        ('UNBOUND_OUTPUT_TAG', b'HIAARU03'), ('BOUND_INPUT_TAG', b'HIAARB01'),
        ('BOUND_OUTPUT_TAG', b'HIAARO04'), ('CURSOR_ROW_TAG', b'HIAROW01'),
        ('CURSOR_RETAIN_TAG', b'HIAINS01'),
        ('LOOKUP_INPUT_TAG', b'HIAARQ01'), ('LOOKUP_PARAMETER_TAG', b'HIAQPA01'),
        ('CURSOR_INPUT_TAG', b'HIAARC01'), ('CURSOR_OUTPUT_TAG', b'HIAARO02'),
        ('INPUT_TAG', b'HIAARP01'), ('OUTPUT_TAG', b'HIAARO01'),
        ('CURSOR_ARTIFACT_FIRST', b'{"artifa'), ('CURSOR_ARTIFACT_LAST', b'ct":'),
        ('CURSOR_OFFSET_FIRST', b',"offset'), ('CURSOR_OFFSET_LAST', b'":'),
        ('CURSOR_PREFIX', b'page-'),
    ):
        source = source.replace(symbol, str(int.from_bytes(raw, 'little')))
    source += LINKER_SOURCE[LINKER_SOURCE.index('\ndef copy_bytes('):]
    # Hash the small prefix in the same workspace, below the private SHA arena.
    digest = hash_program()
    digest = replace_once(digest, 'hash_sha256(s: mutbuf, w: mutbuf, n: u64) -> u32:',
                          'hash_sha256(w: mutbuf, n: u64) -> u64:')
    digest = replace_once(digest, 'hash_padded_byte(s,', 'hash_padded_byte(w,')
    digest = replace_once(digest, 'hash_padded_byte(s:', 'hash_padded_byte(w:')
    digest = replace_once(digest, 'return byte(s, index)', 'return byte(w, index)')
    source += digest
    nodes = ast.parse(source).body
    names = {node.name: 'f' + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = LinkerBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(p) for p in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_read_page',
                                  'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/agent_read_page.hepta'
    path.write_text(render_assembly(document()))


if __name__ == '__main__':
    main()
