"""Author bounded HIA byte transport for the standalone CLI argument owners."""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document


PAYLOAD = r'''
def transport(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) >= 4096 and byte(w, 0) == 0:
        return inflate(s, o, w)
    if length(w) == 1 and byte(w, 0) == 1:
        return argv_frame(s, o)
    if length(w) == 1 and byte(w, 0) == 2:
        return utf8_output(s, o, False)
    if length(w) == 1 and byte(w, 0) == 3:
        return utf8_output(s, o, True)
    if length(w) >= 65536 and read_workspace(w, 0, 8) == RESULT_MAGIC:
        return command_frame(s, o, w)
    return 4294967293

# Raw DEFLATE is compiled from the same admitted control and renderer.
# Counts and sorted symbols describe a canonical Huffman tree; no tree
# can be addressed outside its allocated arena, even on malformed input.
def bits(s:readbuf, w:mutbuf, width:u64) -> u64:
    cursor = read_workspace(w, 8, 8)
    if cursor > length(s) * 8 or width > length(s) * 8 - cursor:
        return BAD
    value = 0
    offset = 0
    while offset < width:
        at = cursor + offset
        value = value | (((byte(s, at >> 3) >> (at & 7)) & 1) << offset)
        offset = offset + 1
    write_word(w, 8, 8, cursor + width)
    return value

def tree(w:mutbuf, lengths:u64, size:u64, table:u64) -> u64:
    i = 0
    while i < 16:
        write_word(w, table + 2 * i, 2, 0)
        i = i + 1
    i = 0
    while i < size:
        width = byte(w, lengths + i)
        if width > 15:
            return BAD
        at = table + 2 * width
        write_word(w, at, 2, read_workspace(w, at, 2) + 1)
        i = i + 1
    i = 1
    free = 1
    offset = 0
    while i <= 15:
        count = read_workspace(w, table + 2 * i, 2)
        free = free * 2
        if count > free:
            return BAD
        free = free - count
        write_word(w, table + 32 + 2 * i, 2, offset)
        offset = offset + count
        i = i + 1
    i = 0
    while i < size:
        width = byte(w, lengths + i)
        if width != 0:
            at = table + 32 + 2 * width
            offset = read_workspace(w, at, 2)
            write_word(w, table + 64 + offset * 2, 2, i)
            write_word(w, at, 2, offset + 1)
        i = i + 1
    return 0

def symbol(s:readbuf, w:mutbuf, table:u64) -> u64:
    code = 0
    first = 0
    index = 0
    width = 1
    while width <= 15:
        next_bit = bits(s, w, 1)
        if next_bit == BAD:
            return BAD
        code = code | next_bit
        count = read_workspace(w, table + 2 * width, 2)
        if code >= first and code - first < count:
            return read_workspace(w, table + 64 + 2 * (index + code - first), 2)
        index = index + count
        first = (first + count) * 2
        code = code * 2
        width = width + 1
    return BAD

def fixed(w:mutbuf) -> u64:
    i = 0
    while i < 288:
        width = 8
        if i >= 144 and i < 256:
            width = 9
        if i >= 256 and i < 280:
            width = 7
        store(w, 32 + i, width)
        i = i + 1
    stop = i + 32
    while i < stop:
        store(w, 32 + i, 5)
        i = i + 1
    tree(w, 32, 288, 512)
    tree(w, 320, 32, 1536)
    return 0

def code_order(index:u64) -> u64:
    if index < 16:
        return (ORDER_FIRST >> (index * 4)) & 15
    return (ORDER_LAST >> ((index - 16) * 4)) & 15

def dynamic(s:readbuf, w:mutbuf) -> u64:
    literal_count = bits(s, w, 5) + 257
    distance_count = bits(s, w, 5) + 1
    length_count = bits(s, w, 4) + 4
    if literal_count > 286 or distance_count > 32 or length_count > 19:
        return BAD
    i = 0
    while i < 19:
        store(w, 32 + i, 0)
        i = i + 1
    i = 0
    while i < length_count:
        width = bits(s, w, 3)
        if width == BAD:
            return BAD
        destination = code_order(i)
        if i < 3:
            destination = 16 + i
        store(w, 32 + destination, width)
        i = i + 1
    if tree(w, 32, 19, 1792) == BAD:
        return BAD
    stop = literal_count + distance_count
    i = 0
    previous = 0
    while i < stop:
        width = symbol(s, w, 1792)
        run = 1
        if width == BAD:
            return BAD
        if width == 16:
            if i == 0:
                return BAD
            width = previous
            run = bits(s, w, 2) + 3
        elif width == 17:
            width = 0
            run = bits(s, w, 3) + 3
        elif width == 18:
            width = 0
            run = bits(s, w, 7) + 11
        if run > stop - i:
            return BAD
        end = i + run
        while i < end:
            store(w, 32 + i, width)
            i = i + 1
        previous = width
    if byte(w, 288) == 0 or tree(w, 32, literal_count, 512) == BAD:
        return BAD
    return tree(w, 32 + literal_count, distance_count, 1536)

def stored(s:readbuf, o:mutbuf, w:mutbuf, cursor:u64) -> u64:
    start = (read_workspace(w, 8, 8) + 7) >> 3
    if start > length(s) or length(s) - start < 4:
        return BAD
    count = read_word(s, start, 2)
    if count ^ read_word(s, start + 2, 2) != 65535:
        return BAD
    start = start + 4
    if count > length(s) - start or count > length(o) - cursor:
        return BAD
    i = 0
    while i < count:
        store(o, cursor + i, byte(s, start + i))
        i = i + 1
    write_word(w, 8, 8, (start + count) * 8)
    return cursor + count

def match_length(s:readbuf, w:mutbuf, code:u64) -> u64:
    if code <= 264:
        return code - 254
    if code == 285:
        return 258
    width = (code - 261) >> 2
    extra = bits(s, w, width)
    if extra == BAD:
        return BAD
    return (4 << width) + 3 + (((code - 265) & 3) << width) + extra

def match_distance(s:readbuf, w:mutbuf, code:u64) -> u64:
    if code <= 3:
        return code + 1
    width = (code >> 1) - 1
    extra = bits(s, w, width)
    if extra == BAD:
        return BAD
    return (2 << width) + 1 + ((code & 1) << width) + extra

def huffman(s:readbuf, o:mutbuf, w:mutbuf, cursor:u64) -> u64:
    while True:
        code = symbol(s, w, 512)
        if code == 256:
            return cursor
        if code > 285:
            return BAD
        if code < 256:
            if cursor == length(o):
                return BAD
            store(o, cursor, code)
            cursor = cursor + 1
        else:
            count = match_length(s, w, code)
            if count > length(o) - cursor:
                return BAD
            distance_code = symbol(s, w, 1536)
            if distance_code > 29:
                return BAD
            distance = match_distance(s, w, distance_code)
            if distance > cursor:
                return BAD
            i = 0
            while i < count:
                store(o, cursor + i, byte(o, cursor - distance + i))
                i = i + 1
            cursor = cursor + count
    return BAD

def inflate(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if length(s) == 0 or length(s) > 1048576 or length(o) == 0 or length(o) > 1048576:
        return BAD
    write_word(w, 8, 8, 0)
    cursor = 0
    last = 0
    while last == 0:
        header = bits(s, w, 3)
        if header == BAD or header >= 6:
            return BAD
        last = header & 1
        kind = header >> 1
        if kind == 0:
            cursor = stored(s, o, w, cursor)
        else:
            if kind == 1:
                fixed(w)
            elif dynamic(s, w) == BAD:
                return BAD
            cursor = huffman(s, o, w, cursor)
        if cursor == BAD:
            return BAD
    if cursor != length(o) or ((read_workspace(w, 8, 8) + 7) >> 3) != length(s):
        return BAD
    return cursor

def read_word(s:readbuf, at:u64, width:u64) -> u64:
    value = 0
    i = 0
    while i < width:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def read_workspace(s:mutbuf, at:u64, width:u64) -> u64:
    value = 0
    i = 0
    while i < width:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def write_word(o:mutbuf, at:u64, width:u64, value:u64) -> u64:
    i = 0
    while i < width:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def utf8_point(s:readbuf, index:u64, stop:u64) -> u64:
    first = byte(s, index)
    if first < 128:
        return (first << 3) | 1
    bad = ((56320 + first) << 3) | 1
    width = 0
    if first >= 194 and first <= 223:
        width = 2
    if first >= 224 and first <= 239:
        width = 3
    if first >= 240 and first <= 244:
        width = 4
    if width == 0 or width > stop - index:
        return bad
    second = byte(s, index + 1)
    if second < 128 or second > 191:
        return bad
    if (first == 224 and second < 160) or (first == 237 and second > 159):
        return bad
    if (first == 240 and second < 144) or (first == 244 and second > 143):
        return bad
    value = first & (127 >> width)
    i = 1
    while i < width:
        continuation = byte(s, index + i)
        if continuation < 128 or continuation > 191:
            return bad
        value = (value << 6) | (continuation & 63)
        i = i + 1
    return (value << 3) | width

def append_span(s:readbuf, o:mutbuf, begin:u64, stop:u64, entry:u64, target:u64) -> u64:
    write_word(o, entry, 8, target)
    cursor = target
    while begin < stop:
        if length(o) - cursor < 4:
            return 4294967293
        point = utf8_point(s, begin, stop)
        write_word(o, cursor, 4, point >> 3)
        cursor = cursor + 4
        begin = begin + (point & 7)
    write_word(o, entry + 8, 8, (cursor - target) >> 2)
    return cursor

# HCLILNX4: magic, argc, envc, stdout columns/tty, default digit limit,
# followed by consecutive (byte offset, size) spans for argv and envp.
def name_size(field:u64) -> u64:
    if field == 1:
        return 14
    if field == 2:
        return 9
    if field == 3:
        return 12
    if field == 4:
        return 5
    if field == 5:
        return 8
    return 22

def name_first(field:u64) -> u64:
    if field == 1:
        return NAME_1_FIRST
    if field == 2:
        return NAME_2_FIRST
    if field == 3:
        return NAME_3_FIRST
    if field == 4:
        return NAME_4_FIRST
    if field == 5:
        return NAME_5_FIRST
    return NAME_6_FIRST

def name_last(field:u64) -> u64:
    if field == 1:
        return NAME_1_LAST
    if field == 2:
        return NAME_2_LAST
    if field == 3:
        return NAME_3_LAST
    return NAME_6_LAST

def environment_offset(s:readbuf, argc:u64, count:u64, field:u64) -> u64:
    prefix = name_size(field)
    first = prefix
    if first > 8:
        first = 8
    second = prefix - first
    if second > 8:
        second = 8
    index = argc
    while index < count:
        offset = 48 + index * 16
        size = read_word(s, offset + 8, 8)
        if size >= prefix:
            begin = read_word(s, offset, 8)
            if read_word(s, begin, first) == name_first(field):
                if second == 0 or read_word(s, begin + first, second) == name_last(field):
                    if prefix <= 16 or read_word(s, begin + 16, prefix - 16) == NAME_6_END:
                        return offset
        index = index + 1
    return 0

def environment_span(s:readbuf, o:mutbuf, entry:u64, target:u64, argc:u64, count:u64, field:u64) -> u64:
    offset = environment_offset(s, argc, count, field)
    if offset != 0:
        begin = read_word(s, offset, 8)
        size = read_word(s, offset + 8, 8)
        write_word(o, 72, 8, byte(o, 72) | (1 << field))
        return append_span(s, o, begin + name_size(field), begin + size, entry, target)
    write_word(o, entry, 8, target)
    write_word(o, entry + 8, 8, 0)
    return target

def digit_limit(s:readbuf, argc:u64, count:u64, fallback:u64) -> u64:
    offset = environment_offset(s, argc, count, 6)
    if offset == 0:
        return fallback
    begin = read_word(s, offset, 8)
    stop = begin + read_word(s, offset + 8, 8)
    index = begin + name_size(6)
    while index < stop and (byte(s, index) == 32 or (byte(s, index) >= 9 and byte(s, index) <= 13)):
        index = index + 1
    negative = False
    if index < stop and (byte(s, index) == 43 or byte(s, index) == 45):
        negative = byte(s, index) == 45
        index = index + 1
    if index == stop:
        return fallback
    result = 0
    while index < stop:
        digit = byte(s, index)
        if digit < 48 or digit > 57 or result > 214748364:
            return fallback
        result = result * 10 + digit - 48
        index = index + 1
    if result == 0:
        return 0
    if negative or result < 640 or result > 2147483647:
        return fallback
    return result

def argv_frame(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 48 or length(s) > 8388608:
        return 4294967293
    if read_word(s, 0, 8) != RAW_MAGIC:
        return 4294967293
    argc = read_word(s, 8, 8)
    envc = read_word(s, 16, 8)
    columns = read_word(s, 24, 8)
    terminal = read_word(s, 32, 8)
    digits = read_word(s, 40, 8)
    bound = (length(s) - 48) >> 4
    if argc > bound or envc > bound - argc or columns > 65535 or terminal > 1:
        return 4294967293
    count = argc + envc
    end = 48 + count * 16
    cursor = end
    offset = 48
    while offset < end:
        start = read_word(s, offset, 8)
        size = read_word(s, offset + 8, 8)
        if start != cursor or size > length(s) - cursor:
            return 4294967293
        cursor = cursor + size
        offset = offset + 16
    if cursor != length(s):
        return 4294967293
    target = 192 + argc * 16
    if target > length(o) or VERSION_LENGTH * 4 > length(o) - target:
        return 4294967293
    write_word(o, 0, 8, ARGV_MAGIC)
    write_word(o, 8, 8, 4)
    write_word(o, 16, 8, argc)
    write_word(o, 24, 8, 314)
    write_word(o, 32, 8, columns)
    write_word(o, 40, 8, 0)
    write_word(o, 48, 8, terminal)
    write_word(o, 56, 8, digit_limit(s, argc, count, digits))
    write_word(o, 64, 8, 0)
    write_word(o, 72, 8, 1)
    write_word(o, 80, 8, 0)
    write_word(o, 88, 8, 0)
    write_word(o, 96, 8, target)
    write_word(o, 104, 8, VERSION_LENGTH)
    VERSION_WRITES
    target = target + VERSION_LENGTH * 4
    field = 1
    while field < 6:
        target = environment_span(s, o, 96 + field * 16, target, argc, count, field)
        if target == 4294967293:
            return target
        field = field + 1
    index = 0
    while index < argc:
        offset = 48 + index * 16
        begin = read_word(s, offset, 8)
        target = append_span(s, o, begin, begin + read_word(s, offset + 8, 8), 192 + index * 16, target)
        if target == 4294967293:
            return target
        index = index + 1
    return target

def hexadecimal(point:u64) -> u64:
    if point < 10:
        return 48 + point
    return 87 + point

def utf8_output(s:readbuf, o:mutbuf, stderr:bool) -> u64:
    if length(s) & 3 != 0:
        return 4294967293
    return utf8_span(s, o, 0, length(s), 0, stderr)

def utf8_span(s:readbuf, o:mutbuf, index:u64, stop:u64, target:u64, stderr:bool) -> u64:
    while index < stop:
        point = read_word(s, index, 4)
        index = index + 4
        remaining = length(o) - target
        if point < 128:
            if remaining < 1:
                return 4294967293
            store(o, target, point)
            target = target + 1
        elif point >= 55296 and point <= 57343:
            if stderr == False and point >= 56448 and point <= 56575:
                if remaining < 1:
                    return 4294967293
                store(o, target, point - 56320)
                target = target + 1
            else:
                if stderr == False or remaining < 6:
                    return 4294967293
                store(o, target, 92)
                store(o, target + 1, 117)
                i = 0
                while i < 4:
                    store(o, target + 2 + i, hexadecimal((point >> (12 - i * 4)) & 15))
                    i = i + 1
                target = target + 6
        elif point < 2048:
            if remaining < 2:
                return 4294967293
            store(o, target, 192 | (point >> 6))
            store(o, target + 1, 128 | (point & 63))
            target = target + 2
        elif point < 65536:
            if remaining < 3:
                return 4294967293
            store(o, target, 224 | (point >> 12))
            store(o, target + 1, 128 | ((point >> 6) & 63))
            store(o, target + 2, 128 | (point & 63))
            target = target + 3
        else:
            if point > 1114111 or remaining < 4:
                return 4294967293
            store(o, target, 240 | (point >> 18))
            store(o, target + 1, 128 | ((point >> 12) & 63))
            store(o, target + 2, 128 | ((point >> 6) & 63))
            store(o, target + 3, 128 | (point & 63))
            target = target + 4
    return target

def command_word(s:readbuf, o:mutbuf, w:mutbuf, field:u64, entry:u64, target:u64) -> u64:
    at = 256 + field * 32
    begin = read_workspace(w, at + 8, 8)
    size = read_workspace(w, at + 16, 8)
    if read_workspace(w, at, 8) != 2 or begin > length(s) or size > (length(s) - begin) >> 2:
        return BAD
    cursor = utf8_span(s, o, begin, begin + size * 4, target, False)
    if cursor == BAD or cursor - target > 131071:
        return BAD
    write_word(o, entry, 8, target)
    write_word(o, entry + 8, 8, cursor - target)
    return cursor

def command_frame(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if read_workspace(w, 8, 8) != 0 or read_workspace(w, 104, 8) != length(s):
        return BAD
    scope = read_workspace(w, 16, 8)
    if scope == 0 or scope > 15:
        return BAD
    count = 1
    if scope > 2:
        count = count + 2
    field = 2
    while field < 19:
        if field != 15 and field != 16 and read_workspace(w, 256 + field * 32, 8) == 2:
            count = count + 2
        field = field + 1
    target = 32 + count * 16
    if target > length(o):
        return BAD
    write_word(o, 0, 8, COMMAND_MAGIC)
    write_word(o, 8, 8, 1)
    write_word(o, 16, 8, count)
    write_word(o, 24, 8, target)
    target = command_word(s, o, w, 16, 32, target)
    if target == BAD:
        return BAD
    entry = 48
    field = 2
    while field < 19:
        if field != 15 and field != 16 and read_workspace(w, 256 + field * 32, 8) == 2:
            size = option_size(field)
            if size == 0 or size > length(o) - target:
                return BAD
            write_word(o, entry, 8, target)
            write_word(o, entry + 8, 8, size)
            first = size
            if first > 8:
                first = 8
            write_word(o, target, first, option_first(field))
            if size > 8:
                second = size - 8
                if second > 8:
                    second = 8
                write_word(o, target + 8, second, option_second(field))
                if size > 16:
                    third = size - 16
                    if third > 8:
                        third = 8
                    write_word(o, target + 16, third, option_third(field))
                    if size > 24:
                        write_word(o, target + 24, size - 24, option_fourth(field))
            target = command_word(s, o, w, field, entry + 16, target + size)
            if target == BAD:
                return BAD
            entry = entry + 32
        field = field + 1
    if scope > 2:
        if length(o) - target < 2:
            return BAD
        write_word(o, entry, 8, target)
        write_word(o, entry + 8, 8, 2)
        write_word(o, target, 2, 11565)
        return command_word(s, o, w, 15, entry + 16, target + 2)
    return target
'''


SOURCE = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/core_cli/argument_payload.hepta'


def source_program():
    from hepta import __version__
    from tools.generate_hia_cli_control import TOKENS, _lookup

    version = 'hia ' + __version__
    source = PAYLOAD.replace('VERSION_LENGTH', str(len(version))).replace(
        'VERSION_WRITES', '\n    '.join(
            f'write_word(o, target + {offset * 4}, 4, {ord(char)})'
            for offset, char in enumerate(version)
        )
    )
    constants = {
        'BAD': 4294967293,
        'ORDER_FIRST': sum(value << (i * 4) for i, value in enumerate(
            (0, 0, 0, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2))),
        'ORDER_LAST': 14 | (1 << 4) | (15 << 8),
        'RAW_MAGIC': int.from_bytes(b'HCLILNX4', 'little'),
        'ARGV_MAGIC': int.from_bytes(b'HCLIARG4', 'little'),
        'RESULT_MAGIC': int.from_bytes(b'HCLIRES4', 'little'),
        'COMMAND_MAGIC': 3555107374463273288,
    }
    names = (b'PYTHON_COLORS=', b'NO_COLOR=', b'FORCE_COLOR=', b'TERM=', b'COLUMNS=',
             b'PYTHONINTMAXSTRDIGITS=')
    if len(names[-1]) != 22:
        raise ValueError('standalone CLI digit option does not fit its HIA literal layout')
    for index, name in enumerate(names, 1):
        constants[f'NAME_{index}_FIRST'] = int.from_bytes(name[:8], 'little')
        constants[f'NAME_{index}_LAST'] = int.from_bytes(name[8:16], 'little')
    constants['NAME_6_END'] = int.from_bytes(names[-1][16:], 'little')
    for name, value in constants.items():
        source = source.replace(name, str(value))
    options = {field: spelling.encode('ascii') for spelling, field in TOKENS
               if spelling.startswith('--') and field > 1}
    source += '\n' + _lookup('option_size', 'field', ((field, len(name)) for field, name in options.items()))
    if any(len(name) > 32 for name in options.values()):
        raise ValueError('standalone CLI option does not fit its HIA literal layout')
    for index, part in enumerate(('first', 'second', 'third', 'fourth')):
        source += '\n' + _lookup('option_' + part, 'field', (
            (field, int.from_bytes(name[index * 8:(index + 1) * 8], 'little'))
            for field, name in options.items() if len(name) > index * 8
        ))
    return source


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(source_program(), 'cli_argument_payload')))
