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
    if size < 24:
        return 4294967295
    mode = uint(s, 0)
    begin = 24
    reference = 0
    if mode == CURSOR_INPUT_TAG:
        if size < 32:
            return 4294967295
        reference = uint(s, 24)
        # The limit covers the full public ASCII reference format and LF escapes.
        if reference == 0 or reference > 512 or reference > size - 32:
            return 4294967295
        if length(w) < 4128 + reference:
            return 4294967295
        begin = 32 + reference
    elif mode != INPUT_TAG:
        return 4294967295
    total = size - begin
    if total > 67108864:
        return 4294967295
    offset = uint(s, 8)
    limit = uint(s, 16)
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
        content = count
    else:
        count = wanted
        content = 4 * ((count + 2) // 3)
    next = 18446744073709551615
    if offset < total and count < total - offset:
        next = offset + count
    header = 40
    output_tag = OUTPUT_TAG
    if mode == CURSOR_INPUT_TAG:
        output_tag = CURSOR_OUTPUT_TAG
        if next != 18446744073709551615:
            header = 109
    if length(o) < header + content:
        return 4294967294
    if header == 109:
        if cursor_digest(s, w, reference, next) == 0:
            return 4294967295
        emit_cursor(o, w)
    put(o, 0, output_tag)
    put(o, 8, kind)
    put(o, 16, count)
    put(o, 24, next)
    put(o, 32, content)
    if kind == 0:
        copy_bytes(s, o, start, header, count)
    else:
        encode_binary(s, o, start, count, header)
    return header + content

def cursor_digest(s:readbuf, w:mutbuf, reference:u64, next:u64) -> u64:
    put(w, 0, CURSOR_ARTIFACT_FIRST)
    put(w, 8, CURSOR_ARTIFACT_LAST)
    copy_bytes(s, w, 32, 12, reference)
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

def emit_cursor(o:mutbuf, w:mutbuf) -> u64:
    put(o, 40, CURSOR_PREFIX)
    digest = length(w) - 4096 + 1088
    i = 0
    while i < 32:
        value = byte(w, digest + i)
        store(o, 45 + i * 2, hex_digit(value >> 4))
        store(o, 46 + i * 2, hex_digit(value & 15))
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
