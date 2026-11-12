"""Author the complete ordinary artifact page decision in HIA.

The host still owns issued-artifact retrieval, SQLite and the worker envelope.
This image owns cursor row comparison, whole-artifact UTF-8 classification,
precise page trimming, base64, both JSON wire budgets and the original cursor
digest. Its three buffers are request metadata, immutable artifact bytes and
private output/workspace; it never executes a host hash or encoder.
"""
from __future__ import annotations
import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_sha256 import BODY as SHA_BODY, INITIAL, ROUND

REQUEST_MAGIC = int.from_bytes(b'HIAARDQ1', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAARDR1', 'little')

SOURCE = r'''

def agent_read(s:readbuf, d:readbuf, o:mutbuf) -> u32:
    if length(s) < 168 or length(o) < 128:
        return 4294967293
    if length(s) > 2635249153387064187:
        return 4294967293
    if length(o) < length(s) * 7 + 102304:
        return 4294967294
    if read_word(s, 0) != @REQUEST_MAGIC@ or read_word(s, 8) != 1:
        return refused(o, 2)
    if valid_packet(s) == 0 or length(d) > 67108864:
        return refused(o, 2)
    flags = read_word(s, 16)
    limit = read_word(s, 24)
    offset = read_word(s, 32)
    if flags != 0:
        if (flags & 2) == 0 or (flags & 4) == 0 or (flags & 8) == 0:
            return refused(o, 1)
        if fields_equal(s, 0, 3) == 0 or fields_equal(s, 1, 4) == 0:
            return refused(o, 1)
        if (flags & 16) == 0:
            return refused(o, 2)
    i = 0
    while i < 3:
        if valid_utf8(s, field_start(s, i), field_size(s, i)) == 0:
            return refused(o, 2)
        i = i + 1
    start = slice_start(offset, length(d))
    stop = slice_stop(offset, limit, length(d))
    count = 0
    if stop >= start:
        count = stop - start
    encoding = 1
    if valid_utf8(d, 0, length(d)) == 0:
        encoding = 2
    if encoding == 1:
        count = utf8_prefix(d, start, count)
    cost = page_cost(d, start, count, encoding)
    while cost > 230000:
        count = count >> 1
        if count == 0:
            count = 1
        if encoding == 1:
            count = utf8_prefix(d, start, count)
        cost = page_cost(d, start, count, encoding)
    following = offset + count
    more = 0
    if following >= 9223372036854775808 or following < length(d):
        more = 1
    work = length(s) + 100000
    if more == 1:
        extent = cursor_document(s, o, work + 2048, following)
        cursor_sha(o, work + 2048, extent, work, work + 1088)
    return publish(s, d, o, offset, start, count, following, encoding, more, cost, work)

def valid_packet(s:readbuf) -> u64:
    if read_word(s, 40) != 5:
        return 0
    i = 6
    while i < 16:
        if read_word(s, i * 8) != 0:
            return 0
        i = i + 1
    flags = read_word(s, 16)
    if flags > 31:
        return 0
    if flags != 0 and (flags & 1) == 0:
        return 0
    limit = read_word(s, 24)
    if limit < 512 or limit > 65536:
        return 0
    remaining = length(s) - 168
    i = 0
    while i < 5:
        amount = read_word(s, 128 + i * 8)
        if amount > remaining:
            return 0
        remaining = remaining - amount
        i = i + 1
    if remaining != 0:
        return 0
    if flags == 0:
        if read_word(s, 32) != 0 or field_size(s, 3) != 0 or field_size(s, 4) != 0:
            return 0
    if (flags & 2) == 0:
        if (flags & 28) != 0 or read_word(s, 32) != 0 or field_size(s, 3) != 0 or field_size(s, 4) != 0:
            return 0
    if (flags & 4) == 0 and field_size(s, 3) != 0:
        return 0
    if (flags & 8) == 0 and field_size(s, 4) != 0:
        return 0
    if (flags & 16) == 0 and read_word(s, 32) != 0:
        return 0
    return 1

def field_size(s:readbuf, index:u64) -> u64:
    return read_word(s, 128 + index * 8)

def field_start(s:readbuf, index:u64) -> u64:
    at = 168
    i = 0
    while i < index:
        at = at + field_size(s, i)
        i = i + 1
    return at

def fields_equal(s:readbuf, left:u64, right:u64) -> u64:
    size = field_size(s, left)
    if size != field_size(s, right):
        return 0
    a = field_start(s, left)
    b = field_start(s, right)
    i = 0
    while i < size:
        if byte(s, a + i) != byte(s, b + i):
            return 0
        i = i + 1
    return 1

def slice_start(offset:u64, size:u64) -> u64:
    if offset < 9223372036854775808:
        if offset > size:
            return size
        return offset
    magnitude = 18446744073709551615 - offset + 1
    if magnitude >= size:
        return 0
    return size - magnitude

def slice_stop(offset:u64, limit:u64, size:u64) -> u64:
    if offset < 9223372036854775808:
        end = offset + limit
        if end > size:
            return size
        return end
    magnitude = 18446744073709551615 - offset + 1
    if magnitude <= limit:
        end = limit - magnitude
        if end > size:
            return size
        return end
    magnitude = magnitude - limit
    if magnitude >= size:
        return 0
    return size - magnitude

def utf8_width(s:readbuf, at:u64, end:u64) -> u64:
    if at >= end:
        return 0
    first = byte(s, at)
    if first < 128:
        return 1
    remaining = end - at
    if first < 194 or first > 244:
        return 0
    if remaining < 2:
        return 0
    second = byte(s, at + 1)
    if second < 128 or second > 191:
        return 0
    if first < 224:
        return 2
    if remaining < 3:
        return 0
    third = byte(s, at + 2)
    if third < 128 or third > 191:
        return 0
    if first == 224 and second < 160:
        return 0
    if first == 237 and second > 159:
        return 0
    if first < 240:
        return 3
    if remaining < 4:
        return 0
    fourth = byte(s, at + 3)
    if fourth < 128 or fourth > 191:
        return 0
    if first == 240 and second < 144:
        return 0
    if first == 244 and second > 143:
        return 0
    return 4

def valid_utf8(s:readbuf, start:u64, size:u64) -> u64:
    if start > length(s) or size > length(s) - start:
        return 0
    at = start
    end = start + size
    while at < end:
        width = 1
        if byte(s, at) >= 128:
            width = utf8_width(s, at, end)
            if width == 0:
                return 0
        at = at + width
    return 1

def utf8_prefix(s:readbuf, start:u64, size:u64) -> u64:
    at = start
    end = start + size
    while at < end:
        width = 1
        if byte(s, at) >= 128:
            width = utf8_width(s, at, end)
            if width == 0:
                return at - start
        at = at + width
    return size

def base64_size(size:u64) -> u64:
    return (((size + 2) * 2863311531) >> 33) * 4

def page_cost(d:readbuf, start:u64, size:u64, encoding:u64) -> u64:
    if encoding == 2:
        return 8 + 2 * base64_size(size)
    total = 8
    i = 0
    while i < size:
        value = byte(d, start + i)
        contribution = 2
        if value == 34 or value == 92:
            contribution = 6
        if value < 32:
            contribution = 13
            if value == 8 or value == 9 or value == 10 or value == 12 or value == 13:
                contribution = 5
        total = total + contribution
        i = i + 1
    return total

def cursor_document(s:readbuf, w:mutbuf, start:u64, following:u64) -> u64:
    at = literal(w, start, 0)
    at = quoted(s, field_start(s, 0), field_size(s, 0), w, at)
    at = literal(w, at, 1)
    at = quoted(s, field_start(s, 1), field_size(s, 1), w, at)
    at = literal(w, at, 2)
    at = quoted(s, field_start(s, 2), field_size(s, 2), w, at)
    at = literal(w, at, 3)
    value = following
    if following >= 9223372036854775808:
        store(w, at, 45)
        at = at + 1
        value = 18446744073709551615 - following + 1
    at = at + write_decimal(w, at, value)
    store(w, at, 125)
    return at + 1 - start

def quoted(s:readbuf, start:u64, size:u64, w:mutbuf, at:u64) -> u64:
    store(w, at, 34)
    at = at + 1
    i = 0
    while i < size:
        value = byte(s, start + i)
        if value == 34 or value == 92:
            store(w, at, 92)
            store(w, at + 1, value)
            at = at + 2
        else:
            if value < 32:
                escaped = 0
                if value == 8:
                    escaped = 98
                if value == 9:
                    escaped = 116
                if value == 10:
                    escaped = 110
                if value == 12:
                    escaped = 102
                if value == 13:
                    escaped = 114
                if escaped != 0:
                    store(w, at, 92)
                    store(w, at + 1, escaped)
                    at = at + 2
                else:
                    store(w, at, 92)
                    store(w, at + 1, 117)
                    store(w, at + 2, 48)
                    store(w, at + 3, 48)
                    store(w, at + 4, hexadecimal(value >> 4))
                    store(w, at + 5, hexadecimal(value & 15))
                    at = at + 6
            else:
                store(w, at, value)
                at = at + 1
        i = i + 1
    store(w, at, 34)
    return at + 1

def hexadecimal(value:u64) -> u64:
    if value < 10:
        return 48 + value
    return 87 + value

def decimal_size(value:u64) -> u64:
    i = 0
    while i < 19:
        if value >= decimal_power(i):
            return 20 - i
        i = i + 1
    return 1

def write_decimal(w:mutbuf, at:u64, value:u64) -> u64:
    size = decimal_size(value)
    i = 20 - size
    while i < 20:
        power = decimal_power(i)
        digit = 0
        while value >= power:
            value = value - power
            digit = digit + 1
        store(w, at, 48 + digit)
        at = at + 1
        i = i + 1
    return size

def refused(o:mutbuf, status:u64) -> u32:
    i = 0
    while i < 16:
        write_word(o, i * 8, 0)
        i = i + 1
    write_word(o, 0, @RESULT_MAGIC@)
    write_word(o, 8, 1)
    write_word(o, 16, status)
    return 128

def publish(s:readbuf, d:readbuf, o:mutbuf, offset:u64, start:u64, size:u64, following:u64, encoding:u64, more:u64, cost:u64, work:u64) -> u32:
    content_size = size
    if encoding == 2:
        content_size = base64_size(size)
    cursor_size = 0
    if more == 1:
        cursor_size = 69
    payload = field_size(s, 0) + field_size(s, 1) + field_size(s, 2) + cursor_size + content_size
    if payload > 4294967127:
        return refused(o, 2)
    i = 0
    while i < 16:
        write_word(o, i * 8, 0)
        i = i + 1
    write_word(o, 0, @RESULT_MAGIC@)
    write_word(o, 8, 1)
    write_word(o, 24, encoding)
    write_word(o, 32, 5)
    write_word(o, 40, offset)
    write_word(o, 48, size)
    write_word(o, 56, following)
    write_word(o, 64, length(d))
    write_word(o, 72, cost)
    write_word(o, 80, more)
    write_word(o, 88, payload)
    write_word(o, 128, field_size(s, 0))
    write_word(o, 136, field_size(s, 1))
    write_word(o, 144, field_size(s, 2))
    write_word(o, 152, cursor_size)
    write_word(o, 160, content_size)
    at = 168
    i = 0
    while i < 3:
        at = copy_source(s, field_start(s, i), field_size(s, i), o, at)
        i = i + 1
    if more == 1:
        at = literal(o, at, 4)
        i = 0
        while i < 32:
            value = byte(o, work + 1088 + i)
            store(o, at, hexadecimal(value >> 4))
            store(o, at + 1, hexadecimal(value & 15))
            at = at + 2
            i = i + 1
    if encoding == 1:
        at = copy_source(d, start, size, o, at)
    else:
        at = base64_copy(d, start, size, o, at)
    return at

def copy_source(s:readbuf, start:u64, size:u64, o:mutbuf, at:u64) -> u64:
    i = 0
    while i < size:
        store(o, at + i, byte(s, start + i))
        i = i + 1
    return at + size

def base64_copy(d:readbuf, start:u64, size:u64, o:mutbuf, at:u64) -> u64:
    i = 0
    while i < size:
        first = byte(d, start + i)
        second = 0
        third = 0
        if size - i > 1:
            second = byte(d, start + i + 1)
        if size - i > 2:
            third = byte(d, start + i + 2)
        store(o, at, base64_character(first >> 2))
        store(o, at + 1, base64_character(((first & 3) << 4) | (second >> 4)))
        third_character = 61
        fourth_character = 61
        if size - i > 1:
            third_character = base64_character(((second & 15) << 2) | (third >> 6))
        if size - i > 2:
            fourth_character = base64_character(third & 63)
        store(o, at + 2, third_character)
        store(o, at + 3, fourth_character)
        at = at + 4
        i = i + 3
    return at

def base64_character(value:u64) -> u64:
    if value < 26:
        return 65 + value
    if value < 52:
        return 97 + value - 26
    if value < 62:
        return 48 + value - 52
    if value == 62:
        return 43
    return 47

def read_word(s:readbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def read_word_mut(s:mutbuf, at:u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def write_word(o:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, value >> (i * 8))
        i = i + 1
    return value

def rotate(value:u64, shift:u64) -> u64:
    return (value >> shift) | ((value << (32 - shift)) & 4294967295)

def cursor_padded_byte(w:mutbuf, start:u64, extent:u64, index:u64, total:u64) -> u64:
    if index < extent:
        return byte(w, start + index)
    if index == extent:
        return 128
    if index < total - 8:
        return 0
    return ((extent << 3) >> ((total - 1 - index) * 8)) & 255
'''

def source_program():
    source = SOURCE.replace('@REQUEST_MAGIC@', str(REQUEST_MAGIC)).replace('@RESULT_MAGIC@', str(RESULT_MAGIC))
    literal = ['def literal(w:mutbuf, at:u64, which:u64) -> u64:']
    for index, raw in enumerate((b'{"artifact":{"id":', b',"sha256":', b',"uri":', b'},"offset":', b'page-')):
        literal.append('    if which == ' + str(index) + ':')
        literal.extend('        store(w, at + ' + str(i) + ', ' + str(value) + ')' for i, value in enumerate(raw))
        literal.append('        return at + ' + str(len(raw)))
    literal.append('    return at')
    powers = ['def decimal_power(index:u64) -> u64:']
    for i in range(19):
        powers.extend(('    if index == ' + str(i) + ':', '        return ' + str(10 ** (19 - i))))
    powers.append('    return 1')
    # Reuse the existing HIA SHA compression authoring without a host hash.
    # Its input and scratch occupy disjoint regions of this one private buffer.
    sha = 'def cursor_sha(w:mutbuf, start:u64, extent:u64, scratch:u64, destination:u64) -> u64:\n'
    for i, value in enumerate(ROUND):
        sha += '    write_word(w, scratch + ' + str(i * 8) + ', ' + str(value) + ')\n'
    for i, value in enumerate(INITIAL):
        sha += '    write_word(w, scratch + ' + str(1024 + i * 8) + ', ' + str(value) + ')\n'
    body = SHA_BODY.replace('length(s)', 'extent')
    body = body.replace('padded_byte(s, ', 'cursor_padded_byte(w, start, extent, ')
    body = body.replace('get(w, ', 'read_word_mut(w, scratch + ')
    body = body.replace('put(w, ', 'write_word(w, scratch + ')
    sha += body
    for i, name in enumerate('abcdefgh'):
        at = str(1024 + i * 8)
        sha += '        write_word(w, scratch + ' + at + ', (read_word_mut(w, scratch + ' + at + ') + ' + name + ') & 4294967295)\n'
    sha += '''        block = block + 64
    i = 0
    while i < 8:
        value = read_word_mut(w, scratch + 1024 + i * 8)
        j = 0
        while j < 4:
            store(w, destination + i * 4 + j, (value >> ((3 - j) * 8)) & 255)
            j = j + 1
        i = i + 1
    return 32
'''
    return source + '\n' + '\n'.join(literal) + '\n\n' + '\n'.join(powers) + '\n\n' + sha

def document():
    nodes = ast.parse(source_program()).body
    # The retained flat ABI is exactly (readbuf, mutbuf, mutbuf) -> u32.
    # Give the private artifact buffer a read-only loan inside this wrapper;
    # every existing algorithm function retains its original readbuf types.
    names = {node.name: 'f' + str(i + 1) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
    params = [{'name': 'v0', 'type': 'readbuf'}, {'name': 'v1', 'type': 'mutbuf'},
              {'name': 'v2', 'type': 'mutbuf'}]
    wrapper = {'name': 'f0', 'params': params, 'returns': ['u32'],
        'effects': ['read', 'write', 'trap'], 'entry': 'b0',
        'blocks': [{'id': 'b0', 'params': [dict(item) for item in params], 'ops': [
            {'op': 'borrow.read', 'args': ['v1'],
             'out': [{'name': 'v3', 'type': 'readbuf'}], 'attrs': {}},
            {'op': 'call', 'args': ['v0', 'v3', 'v2'],
             'out': [{'name': 'v4', 'type': 'u32'}], 'attrs': {'function': names['agent_read']}},
            {'op': 'loan.end', 'args': ['v3'], 'out': [], 'attrs': {}}],
            'term': {'op': 'ret', 'values': ['v4']}}]}
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_read',
                                  'functions': [wrapper, *functions]})

def main():
    path = ROOT / 'examples/hia_bootstrap/agent_read.hepta'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)

if __name__ == '__main__':
    main()
