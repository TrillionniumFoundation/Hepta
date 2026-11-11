def format_cli(s: readbuf, o: mutbuf, w: mutbuf) -> u32:
    if length(s) < 8 or length(w) < 131072 or length(o) < 4:
        return 199
    put(w, 1024, 0)
    put(w, 1032, 0)
    put(w, 1072, 0)
    format_constants(w)
    if read64(s, 0) == 3767070053674795848 and get(w, 0) == 3770430221338821448:
        return observation_request(s, w)
    if read64(s, 0) == 3770166295598482248:
        return driver_error(s, o, w)
    if read64(s, 0) != 3767070053674795848 or length(s) < 192 or read64(s, 8) != 4:
        return 199
    argc = read64(s, 16)
    if argc > length(s) - 192 >> 4 or length(w) < 131072 + argc * 24:
        return 199
    if get(w, 0) != 3770433532758606664 or get(w, 88) != argc or get(w, 104) != length(s):
        return 199
    if read64(s, 24) != get(w, 128) or (get(w, 128) != 312 and get(w, 128) != 314):
        return 199
    if get(w, 24) > 15 or get(w, 8) < 1 or get(w, 8) > 3 or (get(w, 80) > argc):
        return 199
    cursor = 192 + argc * 16
    record = 96
    while record < 192 + argc * 16:
        size = read64(s, record + 8)
        if read64(s, record) != cursor or size > length(s) - cursor >> 2:
            return 199
        end = cursor + size * 4
        while cursor < end:
            if read32(s, cursor) > 1114111:
                return 199
            cursor = cursor + 4
        record = record + 16
    if cursor != length(s):
        return 199
    if get(w, 8) == 3:
        if get(w, 32) < 1 or get(w, 32) > 7 or get(w, 40) > 16:
            return 199
        if get(w, 48) > length(s) or get(w, 56) > length(s) - get(w, 48) >> 2:
            return 199
    index = 0
    while index < get(w, 80):
        at = 131072 + index * 24
        if get(w, at) > length(s) or get(w, at + 8) > length(s) - get(w, at) >> 2 or get(w, at + 16) > 1:
            return 199
        index = index + 1
    settings(s, w)
    expand_printable(w)
    row = choose(get(w, 128) == 312, 0, 16) + get(w, 24)
    put(w, 1096, 40960 + row * 8)
    put(w, 1104, 43008 + row * 8)
    kind = get(w, 8)
    if kind == 2:
        width = text_width(w, 0)
        wrap_text(s, o, w, 1, read64(s, 96), read64(s, 104), width, 0)
        point(o, w, 10)
    else:
        usage(o, w)
        point(o, w, 10)
        if kind == 1:
            point(o, w, 10)
            help_sections(s, o, w)
        else:
            put(w, 1032, get(w, 1024))
            error_message(s, o, w)
            point(o, w, 10)
    if get(w, 1072) != 0:
        return 199
    return 0

def word16(w: mutbuf, at: u64) -> u64:
    return byte(w, at) | byte(w, at + 1) << 8

def point(o: mutbuf, w: mutbuf, value: u64) -> u64:
    cursor = get(w, 1024)
    if cursor >= length(o) >> 2:
        put(w, 1072, 1)
        return 0
    put32(o, cursor * 4, value)
    put(w, 1024, cursor + 1)
    return 0

def spaces(o: mutbuf, w: mutbuf, count: u64) -> u64:
    index = 0
    while index < count:
        point(o, w, 32)
        index = index + 1
    return 0

def literal_size(w: mutbuf, literal: u64) -> u64:
    return word16(w, 8192 + literal * 4 + 2)

def literal_at(w: mutbuf, literal: u64) -> u64:
    return word16(w, 8192 + literal * 4)

def literal(o: mutbuf, w: mutbuf, literal_id: u64) -> u64:
    at = literal_at(w, literal_id)
    size = literal_size(w, literal_id)
    index = 0
    while index < size:
        point(o, w, byte(w, at + index))
        index = index + 1
    return 0

def style(o: mutbuf, w: mutbuf, literal_id: u64) -> u64:
    if get(w, 1064) != 0:
        literal(o, w, literal_id)
    return 0

def raw_text(s: readbuf, o: mutbuf, w: mutbuf, begin: u64, size: u64) -> u64:
    index = 0
    while index < size:
        point(o, w, read32(s, begin + index * 4))
        index = index + 1
    return 0

def source_equal(s: readbuf, w: mutbuf, begin: u64, size: u64, literal_id: u64) -> bool:
    if size != literal_size(w, literal_id):
        return False
    index = 0
    while index < size:
        if read32(s, begin + index * 4) != byte(w, literal_at(w, literal_id) + index):
            return False
        index = index + 1
    return True

def env_equal(s: readbuf, w: mutbuf, index: u64, literal_id: u64) -> bool:
    return source_equal(s, w, read64(s, 96 + index * 16), read64(s, 104 + index * 16), literal_id)

def int_space(point_value: u64) -> bool:
    return point_value >= 9 and point_value <= 13 or point_value == 32 or point_value == 133 or (point_value == 160) or (point_value == 5760) or (point_value >= 8192 and point_value <= 8202) or (point_value == 8232) or (point_value == 8233) or (point_value == 8239) or (point_value == 8287) or (point_value == 12288)

def decimal_digit(point_value: u64, profile: u64) -> u64:
    if decimal(point_value, profile) == 0:
        return 10
    digit = 0
    cursor = point_value
    while cursor > 0 and decimal(cursor - 1, profile) != 0:
        cursor = cursor - 1
        digit = digit + 1
        if digit == 10:
            digit = 0
    return digit

def columns(s: readbuf, w: mutbuf) -> u64:
    fallback = read64(s, 32)
    if fallback == 0:
        fallback = 80
    begin = read64(s, 176)
    size = read64(s, 184)
    index = 0
    while index < size and int_space(read32(s, begin + index * 4)):
        index = index + 1
    negative = False
    if index < size and (read32(s, begin + index * 4) == 43 or read32(s, begin + index * 4) == 45):
        negative = read32(s, begin + index * 4) == 45
        index = index + 1
    value = 0
    digits = 0
    previous_digit = False
    done = False
    while index < size and done == False:
        character = read32(s, begin + index * 4)
        if int_space(character):
            done = True
        else:
            if character == 95:
                if previous_digit == False:
                    return fallback
                previous_digit = False
            else:
                digit = decimal_digit(character, get(w, 128))
                if digit == 10:
                    return fallback
                digits = digits + 1
                previous_digit = True
                if value >= 115292150460684697:
                    value = 1152921504606846976
                else:
                    value = value * 10 + digit
            index = index + 1
    if previous_digit == False or digits == 0:
        return fallback
    while index < size:
        if int_space(read32(s, begin + index * 4)) == False:
            return fallback
        index = index + 1
    if read64(s, 56) != 0 and digits > read64(s, 56):
        return fallback
    if negative or value == 0:
        return fallback
    return value

def color_choice(s: readbuf, w: mutbuf) -> u64:
    if get(w, 128) != 314:
        return 0
    if read64(s, 40) == 0 and env_equal(s, w, 1, 1):
        return 0
    if read64(s, 40) == 0 and env_equal(s, w, 1, 2):
        return 1
    if read64(s, 136) != 0:
        return 0
    if read64(s, 152) != 0:
        return 1
    if env_equal(s, w, 4, 3):
        return 0
    return 2

def observation_request(s: readbuf, w: mutbuf) -> u32:
    if length(s) < 192 or read64(s, 8) != 4:
        return 199
    profile = read64(s, 24)
    if profile != 312 and profile != 314:
        return 199
    if read64(s, 40) > 1 or read64(s, 48) > 1 or read64(s, 72) > 63:
        return 199
    if read64(s, 64) != 0 or read64(s, 80) != 0 or read64(s, 88) != 0:
        return 199
    argc = read64(s, 16)
    if argc > length(s) - 192 >> 4:
        return 199
    cursor = 192 + argc * 16
    record = 96
    while record < 192 + argc * 16:
        begin = read64(s, record)
        size = read64(s, record + 8)
        if begin != cursor or size > length(s) - cursor >> 2:
            return 199
        end = cursor + size * 4
        while cursor < end:
            if read32(s, cursor) > 1114111:
                return 199
            cursor = cursor + 4
        record = record + 16
    if cursor != length(s):
        return 199
    put(w, 128, profile)
    put(w, 1064, choose(color_choice(s, w) == 2, 1, 0))
    return 3

def settings(s: readbuf, w: mutbuf) -> u64:
    size = columns(s, w)
    put(w, 1040, size)
    put(w, 1048, size - 2)
    put(w, 1056, choose(size < 2, 1, 0))
    color = color_choice(s, w)
    if color == 2:
        color = read64(s, 48)
    put(w, 1064, color)
    return 0

def beyond_width(w: mutbuf, size: u64) -> bool:
    return get(w, 1056) != 0 or size > get(w, 1048)

def text_width(w: mutbuf, indent: u64) -> u64:
    if get(w, 1056) != 0 or get(w, 1048) < indent + 11:
        return 11
    return get(w, 1048) - indent

def usage_part_at(w: mutbuf, index: u64) -> u64:
    return 41216 + (word16(w, get(w, 1096)) + index) * 4

def usage_part_size(w: mutbuf, index: u64) -> u64:
    return literal_size(w, word16(w, usage_part_at(w, index)))

def part(o: mutbuf, w: mutbuf, index: u64) -> u64:
    at = usage_part_at(w, index)
    plain = word16(w, at)
    field = byte(w, at + 2)
    optional = byte(w, at + 3)
    if get(w, 1064) == 0:
        return literal(o, w, plain)
    if field >= 15:
        style(o, w, 24)
        literal(o, w, plain)
        return style(o, w, 23)
    if optional != 0:
        point(o, w, 91)
    style(o, w, choose(field == 0, 24, 25))
    literal(o, w, primary_literal(field))
    if field >= 2:
        point(o, w, 32)
        style(o, w, 26)
        literal(o, w, metavar_literal(field))
    style(o, w, 23)
    if optional != 0:
        point(o, w, 93)
    return 0

def colored_program(o: mutbuf, w: mutbuf) -> u64:
    style(o, w, 28)
    literal(o, w, word16(w, get(w, 1096) + 4))
    return style(o, w, 23)

def group_line_count(w: mutbuf, start: u64, count: u64, indent: u64) -> u64:
    lines = 0
    width = indent
    words = 0
    index = 0
    while index < count:
        size = usage_part_size(w, start + index)
        if words != 0 and beyond_width(w, width + 1 + size):
            lines = lines + 1
            words = 0
            width = indent
        if words != 0:
            width = width + 1
        width = width + size
        words = words + 1
        index = index + 1
    return lines + choose(words != 0, 1, 0)

def usage_group(o: mutbuf, w: mutbuf, start: u64, count: u64, indent: u64, existing: u64) -> u64:
    words = existing
    width = get(w, 1112)
    index = 0
    while index < count:
        size = usage_part_size(w, start + index)
        if words != 0 and beyond_width(w, width + 1 + size):
            point(o, w, 10)
            spaces(o, w, indent)
            width = indent
            words = 0
        if words != 0:
            point(o, w, 32)
            width = width + 1
        part(o, w, start + index)
        width = width + size
        words = words + 1
        index = index + 1
    put(w, 1112, width)
    return 0

def usage(o: mutbuf, w: mutbuf) -> u64:
    row = get(w, 1096)
    count = byte(w, row + 2)
    optionals = byte(w, row + 3)
    program_size = literal_size(w, word16(w, row + 4))
    whole = program_size
    index = 0
    while index < count:
        whole = whole + 1 + usage_part_size(w, index)
        index = index + 1
    style(o, w, 27)
    literal(o, w, 4)
    style(o, w, 23)
    colored_program(o, w)
    if beyond_width(w, whole + 7) == False:
        index = 0
        while index < count:
            point(o, w, 32)
            part(o, w, index)
            index = index + 1
        return 0
    if get(w, 1056) == 0 and (7 + program_size) * 4 <= get(w, 1048) * 3:
        indent = 8 + program_size
        put(w, 1112, 7 + program_size)
        usage_group(o, w, 0, optionals, indent, 1)
        if count > optionals:
            point(o, w, 10)
            spaces(o, w, indent)
            put(w, 1112, indent)
            usage_group(o, w, optionals, count - optionals, indent, 0)
        return 0
    point(o, w, 10)
    spaces(o, w, 7)
    put(w, 1112, 7)
    lines = group_line_count(w, 0, count, 7)
    if lines > 1 and count > optionals:
        usage_group(o, w, 0, optionals, 7, 0)
        point(o, w, 10)
        spaces(o, w, 7)
        put(w, 1112, 7)
        return usage_group(o, w, optionals, count - optionals, 7, 0)
    return usage_group(o, w, 0, count, 7, 0)

def text_point(s: readbuf, w: mutbuf, kind: u64, begin: u64, index: u64) -> u64:
    if kind == 0:
        return byte(w, begin + index)
    return read32(s, begin + index * 4)

def wrap_text(s: readbuf, o: mutbuf, w: mutbuf, kind: u64, begin: u64, size: u64, width: u64, indent: u64) -> u64:
    index = 0
    used = 0
    while index < size:
        while index < size and (text_point(s, w, kind, begin, index) == 32 or (text_point(s, w, kind, begin, index) >= 9 and text_point(s, w, kind, begin, index) <= 13)):
            index = index + 1
        if index == size:
            return 0
        end = index
        while end < size and text_point(s, w, kind, begin, end) != 32 and (text_point(s, w, kind, begin, end) < 9 or text_point(s, w, kind, begin, end) > 13):
            end = end + 1
        word_size = end - index
        if used != 0 and used + 1 + word_size > width:
            point(o, w, 10)
            spaces(o, w, indent)
            used = 0
        if used != 0:
            point(o, w, 32)
            used = used + 1
        while index < end:
            if used == width:
                point(o, w, 10)
                spaces(o, w, indent)
                used = 0
            point(o, w, text_point(s, w, kind, begin, index))
            used = used + 1
            index = index + 1
    return 0

def help_header(o: mutbuf, w: mutbuf, field: u64, plain: u64) -> u64:
    if get(w, 1064) == 0:
        return literal(o, w, plain)
    if field >= 15:
        style(o, w, 30)
        literal(o, w, plain)
        return style(o, w, 23)
    if field == 0:
        style(o, w, 30)
        literal(o, w, 8)
        style(o, w, 23)
        literal(o, w, 11)
        style(o, w, 29)
        literal(o, w, 9)
        return style(o, w, 23)
    style(o, w, 29)
    literal(o, w, primary_literal(field))
    style(o, w, 23)
    if field == 3:
        literal(o, w, 11)
        style(o, w, 30)
        literal(o, w, 10)
        style(o, w, 23)
    if field >= 2:
        point(o, w, 32)
        style(o, w, 31)
        literal(o, w, metavar_literal(field))
        style(o, w, 23)
    return 0

def help_row(s: readbuf, o: mutbuf, w: mutbuf, index: u64) -> u64:
    row = get(w, 1104)
    at = 43264 + (word16(w, row) + index) * 8
    label = word16(w, at)
    field = byte(w, at + 2)
    help_text = word16(w, at + 4)
    spaces(o, w, 2)
    help_header(o, w, field, label)
    if help_text == 0:
        point(o, w, 10)
        return 0
    position = get(w, 1080)
    label_size = literal_size(w, label)
    if position >= 4 and label_size <= position - 4:
        spaces(o, w, position - 2 - label_size)
    else:
        point(o, w, 10)
        spaces(o, w, position)
    wrap_text(s, o, w, 0, literal_at(w, help_text), literal_size(w, help_text), text_width(w, position), position)
    point(o, w, 10)
    return 0

def heading(o: mutbuf, w: mutbuf, text: u64) -> u64:
    style(o, w, 27)
    literal(o, w, text)
    style(o, w, 23)
    point(o, w, 10)
    return 0

def help_sections(s: readbuf, o: mutbuf, w: mutbuf) -> u64:
    row = get(w, 1104)
    count = byte(w, row + 2)
    positionals = byte(w, row + 3)
    maximum = 0
    index = 0
    while index < count:
        at = 43264 + (word16(w, row) + index) * 8
        size = literal_size(w, word16(w, at)) + 2
        if size > maximum:
            maximum = size
        index = index + 1
    cap = 4
    if get(w, 1040) > 26:
        cap = choose(get(w, 1040) - 22 < 24, get(w, 1040) - 22, 24)
    position = choose(maximum + 2 < cap, maximum + 2, cap)
    put(w, 1080, position)
    if get(w, 24) == 0:
        wrap_text(s, o, w, 0, literal_at(w, 5), literal_size(w, 5), text_width(w, 0), 0)
        point(o, w, 10)
        point(o, w, 10)
    if positionals != 0:
        heading(o, w, 6)
        help_row(s, o, w, 0)
        point(o, w, 10)
    heading(o, w, 7)
    index = positionals
    while index < count:
        help_row(s, o, w, index)
        index = index + 1
    return 0

def varint(w: mutbuf) -> u64:
    cursor = get(w, 1128)
    value = 0
    shift = 0
    done = False
    while done == False:
        piece = byte(w, cursor)
        value = value | (piece & 127) << shift
        cursor = cursor + 1
        shift = shift + 7
        done = piece < 128
    put(w, 1128, cursor)
    return value

def expand_printable(w: mutbuf) -> u64:
    put(w, 1128, 49152)
    previous = 0
    count = 0
    while get(w, 1128) < 49152 + 2371:
        lower = previous + varint(w)
        upper = lower + varint(w)
        flags = varint(w)
        put(w, 65536 + count * 8, lower | upper << 21 | flags << 42)
        previous = upper + 1
        count = count + 1
    put(w, 1088, count)
    return 0

def printable(w: mutbuf, character: u64) -> bool:
    low = 0
    high = get(w, 1088)
    while low < high:
        middle = low + high >> 1
        value = get(w, 65536 + middle * 8)
        lower = value & 2097151
        upper = value >> 21 & 2097151
        if character < lower:
            high = middle
        elif character > upper:
            low = middle + 1
        else:
            mask = choose(get(w, 128) == 312, 1, 2)
            return value >> 42 & mask != 0
    return False

def hex_digits(o: mutbuf, w: mutbuf, value: u64, count: u64) -> u64:
    index = count
    while index > 0:
        index = index - 1
        digit = value >> index * 4 & 15
        point(o, w, choose(digit < 10, 48 + digit, 87 + digit))
    return 0

def quoted(s: readbuf, o: mutbuf, w: mutbuf, begin: u64, size: u64) -> u64:
    single = False
    double = False
    index = 0
    while index < size:
        character = read32(s, begin + index * 4)
        if character == 39:
            single = True
        if character == 34:
            double = True
        index = index + 1
    quote = choose(single and double == False, 34, 39)
    point(o, w, quote)
    index = 0
    while index < size:
        character = read32(s, begin + index * 4)
        if character == quote or character == 92:
            point(o, w, 92)
            point(o, w, character)
        elif character == 9 or character == 10 or character == 13:
            point(o, w, 92)
            point(o, w, choose(character == 9, 116, choose(character == 10, 110, 114)))
        elif printable(w, character):
            point(o, w, character)
        else:
            point(o, w, 92)
            if character < 256:
                point(o, w, 120)
                hex_digits(o, w, character, 2)
            elif character < 65536:
                point(o, w, 117)
                hex_digits(o, w, character, 4)
            else:
                point(o, w, 85)
                hex_digits(o, w, character, 8)
        index = index + 1
    point(o, w, quote)
    return 0

def required_error(o: mutbuf, w: mutbuf) -> u64:
    literal(o, w, 13)
    mask = get(w, 72)
    wrote = False
    if mask & 32768 != 0:
        literal(o, w, error_label(15))
        wrote = True
    field = 0
    while field < 17:
        if field != 15 and mask & 1 << field != 0:
            if wrote:
                literal(o, w, 11)
            literal(o, w, error_label(field))
            wrote = True
        field = field + 1
    return 0

def error_message(s: readbuf, o: mutbuf, w: mutbuf) -> u64:
    literal(o, w, word16(w, get(w, 1096) + 4))
    literal(o, w, 12)
    reason = get(w, 32)
    field = get(w, 40)
    if reason == 1:
        return required_error(o, w)
    if reason == 7:
        literal(o, w, 14)
        index = 0
        while index < get(w, 80):
            at = 131072 + index * 24
            if index != 0:
                point(o, w, 32)
            if get(w, at + 16) != 0:
                point(o, w, 45)
            raw_text(s, o, w, get(w, at), get(w, at + 8))
            index = index + 1
        return 0
    if reason == 3:
        literal(o, w, 15)
        raw_text(s, o, w, get(w, 48), get(w, 56))
        literal(o, w, 16)
        token = 0
        wrote = False
        while token < 17:
            if get(w, 64) & 1 << token != 0:
                if wrote:
                    literal(o, w, 11)
                literal(o, w, token_text(token))
                wrote = True
            token = token + 1
        return 0
    literal(o, w, 17)
    literal(o, w, error_label(field))
    literal(o, w, 18)
    if reason == 4:
        return literal(o, w, 19)
    if reason == 5:
        literal(o, w, 20)
        return quoted(s, o, w, get(w, 48), get(w, 56))
    if reason == 2 or reason == 6:
        literal(o, w, 21)
        quoted(s, o, w, get(w, 48), get(w, 56))
        literal(o, w, 22)
        index = 0
        count = choice_count(field)
        while index < count:
            if index != 0:
                literal(o, w, 11)
            literal(o, w, choice_literal(field, index))
            index = index + 1
        point(o, w, 41)
        return 0
    return 199

def driver_error(s: readbuf, o: mutbuf, w: mutbuf) -> u32:
    if length(s) < 32 or read64(s, 8) != 4 or read64(s, 24) != 0:
        return 199
    size = read64(s, 16)
    if size != length(s) - 32 >> 2 or length(s) != 32 + size * 4:
        return 199
    literal(o, w, 33)
    index = 0
    while index < size:
        character = read32(s, 32 + index * 4)
        if character > 1114111:
            return 199
        if character == 34 or character == 92:
            point(o, w, 92)
            point(o, w, character)
        elif character == 8 or character == 9 or character == 10 or (character == 12) or (character == 13):
            point(o, w, 92)
            escape = choose(character == 8, 98, choose(character == 9, 116, choose(character == 10, 110, choose(character == 12, 102, 114))))
            point(o, w, escape)
        elif character < 32:
            literal(o, w, 32)
            hex_digits(o, w, character, 2)
        else:
            point(o, w, character)
        index = index + 1
    literal(o, w, 34)
    if get(w, 1072) != 0:
        return 199
    return 0

def read64(s: readbuf, at: u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | byte(s, at + index) << index * 8
        index = index + 1
    return value

def read32(s: readbuf, at: u64) -> u64:
    value = 0
    index = 0
    while index < 4:
        value = value | byte(s, at + index) << index * 8
        index = index + 1
    return value

def get(w: mutbuf, at: u64) -> u64:
    value = 0
    index = 0
    while index < 8:
        value = value | byte(w, at + index) << index * 8
        index = index + 1
    return value

def get32(w: mutbuf, at: u64) -> u64:
    value = 0
    index = 0
    while index < 4:
        value = value | byte(w, at + index) << index * 8
        index = index + 1
    return value

def put(w: mutbuf, at: u64, value: u64) -> u64:
    index = 0
    while index < 8:
        store(w, at + index, value >> index * 8)
        index = index + 1
    return 0

def put32(w: mutbuf, at: u64, value: u64) -> u64:
    index = 0
    while index < 4:
        store(w, at + index, value >> index * 8)
        index = index + 1
    return 0

def primary_literal(field: u64) -> u64:
    if field == 0:
        return 8
    if field == 1:
        return 42
    if field == 2:
        return 100
    if field == 3:
        return 58
    if field == 4:
        return 101
    if field == 5:
        return 102
    if field == 6:
        return 103
    if field == 7:
        return 67
    if field == 8:
        return 72
    if field == 9:
        return 74
    if field == 10:
        return 76
    if field == 11:
        return 78
    if field == 12:
        return 92
    if field == 13:
        return 85
    if field == 14:
        return 87
    return 0

def metavar_literal(field: u64) -> u64:
    if field == 2:
        return 104
    if field == 3:
        return 59
    if field == 4:
        return 105
    if field == 5:
        return 106
    if field == 6:
        return 107
    if field == 7:
        return 68
    if field == 8:
        return 73
    if field == 9:
        return 75
    if field == 10:
        return 77
    if field == 11:
        return 79
    if field == 12:
        return 93
    if field == 13:
        return 86
    if field == 14:
        return 88
    if field == 15:
        return 49
    if field == 16:
        return 37
    return 0

def error_label(field: u64) -> u64:
    if field == 0:
        return 108
    if field == 1:
        return 42
    if field == 2:
        return 100
    if field == 3:
        return 109
    if field == 4:
        return 101
    if field == 5:
        return 102
    if field == 6:
        return 103
    if field == 7:
        return 67
    if field == 8:
        return 72
    if field == 9:
        return 74
    if field == 10:
        return 76
    if field == 11:
        return 78
    if field == 12:
        return 92
    if field == 13:
        return 85
    if field == 14:
        return 87
    if field == 15:
        return 49
    if field == 16:
        return 110
    return 0

def token_text(token: u64) -> u64:
    if token == 0:
        return 8
    if token == 1:
        return 9
    if token == 2:
        return 42
    if token == 3:
        return 100
    if token == 4:
        return 58
    if token == 5:
        return 10
    if token == 6:
        return 101
    if token == 7:
        return 102
    if token == 8:
        return 103
    if token == 9:
        return 67
    if token == 10:
        return 72
    if token == 11:
        return 74
    if token == 12:
        return 76
    if token == 13:
        return 78
    if token == 14:
        return 92
    if token == 15:
        return 85
    if token == 16:
        return 87
    return 0

def choice_count(field: u64) -> u64:
    if field == 2:
        return 8
    if field == 4:
        return 1
    if field == 5:
        return 1
    if field == 6:
        return 1
    if field == 16:
        return 15
    return 0

def choice_literal(field: u64, index: u64) -> u64:
    if field == 2:
        if index == 0:
            return 111
        if index == 1:
            return 112
        if index == 2:
            return 113
        if index == 3:
            return 114
        if index == 4:
            return 115
        if index == 5:
            return 116
        if index == 6:
            return 117
        if index == 7:
            return 118
        return 0
    if field == 4:
        if index == 0:
            return 119
        return 0
    if field == 5:
        if index == 0:
            return 120
        return 0
    if field == 6:
        if index == 0:
            return 121
        return 0
    if field == 16:
        if index == 0:
            return 122
        if index == 1:
            return 123
        if index == 2:
            return 124
        if index == 3:
            return 125
        if index == 4:
            return 126
        if index == 5:
            return 127
        if index == 6:
            return 128
        if index == 7:
            return 129
        if index == 8:
            return 130
        if index == 9:
            return 131
        if index == 10:
            return 132
        if index == 11:
            return 133
        if index == 12:
            return 134
        if index == 13:
            return 135
        if index == 14:
            return 136
        return 0
    return 0

def format_constants(w: mutbuf) -> u64:
    format_constants_0(w)
    format_constants_1(w)
    format_constants_2(w)
    format_constants_3(w)
    format_constants_4(w)
    format_constants_5(w)
    format_constants_6(w)
    format_constants_7(w)
    return 0

def format_constants_0(w: mutbuf) -> u64:
    put(w, 8192, 334251534856192)
    put(w, 8200, 1178685054988289)
    put(w, 8208, 6808231834234886)
    put(w, 8216, 2304825481310245)
    put(w, 8224, 1741918476316738)
    put(w, 8232, 616052929212490)
    put(w, 8240, 10749199335895118)
    put(w, 8248, 5119966090637437)
    put(w, 8256, 2586824443506855)
    put(w, 8264, 5964571407954109)
    put(w, 8272, 4557398389436628)
    put(w, 8280, 1179827517141246)
    put(w, 8288, 1461341147967760)
    put(w, 8296, 2024334051062042)
    put(w, 8304, 2024394180735270)
    put(w, 8312, 2024454310277428)
    put(w, 8320, 20038900064203074)
    put(w, 8328, 1180699399434637)
    put(w, 8336, 47624134977073627)
    put(w, 8344, 900027576955535)
    put(w, 8352, 8781382759887509)
    put(w, 8360, 10751879395488446)
    put(w, 8368, 50721558017094381)
    put(w, 8376, 50159428402099121)
    put(w, 8384, 1465094950171758)
    put(w, 8392, 12724197097944196)
    put(w, 8400, 5406152646603972)
    put(w, 8408, 2873036769473777)
    put(w, 8416, 3717551893460237)
    put(w, 8424, 1747317250602277)
    put(w, 8432, 4843653664355635)
    put(w, 8440, 2592085780018520)
    put(w, 8448, 4281051603154310)
    put(w, 8456, 2592416492369319)
    put(w, 8464, 2592485210011091)
    put(w, 8472, 2874071856526819)
    put(w, 8480, 2311207801992702)
    put(w, 8488, 1466847296173584)
    put(w, 8496, 1466898835781148)
    put(w, 8504, 1748429647132200)
    put(w, 8512, 5407690244109878)
    put(w, 8520, 3718977822733911)
    put(w, 8528, 2030248221685361)
    put(w, 8536, 2874724690769543)
    put(w, 8544, 4000701907220118)
    put(w, 8552, 5408192755218092)
    put(w, 8560, 2875051108742860)
    put(w, 8568, 6534354655524578)
    put(w, 8576, 48755785845716749)
    put(w, 8584, 4283564159088590)
    put(w, 8592, 2594813082351600)
    put(w, 8600, 2313402530019329)
    put(w, 8608, 2314162749913103)
    put(w, 8616, 7380781039630528)
    put(w, 8624, 3158806712891618)
    put(w, 8632, 5692171697666294)
    put(w, 8640, 5692343497013524)
    put(w, 8648, 5692515295705404)
    put(w, 8656, 5692687094397284)
    put(w, 8664, 1752209219139980)
    put(w, 8672, 6818810338621862)
    put(w, 8680, 2033890353756612)
    put(w, 8688, 4285784656918999)
    put(w, 8696, 1752634420509173)
    put(w, 8704, 2597115184757257)
    put(w, 8712, 1471275407325721)
    put(w, 8720, 2878697535584803)
    put(w, 8728, 4567633295456819)
    put(w, 8736, 1063501)
    put(w, 12288, 8319664108897317168)
    put(w, 12296, 4704370589021071201)
    put(w, 12304, 7440263679476450080)
    put(w, 12312, 7310589492924280421)
    put(w, 12320, 8317990617537930866)
    put(w, 12328, 2336349433641923689)
    put(w, 12336, 8389754676633367137)
    put(w, 12344, 7957695015410416243)
    put(w, 12352, 7307140068453202547)
    put(w, 12360, 2322203933078810732)
    put(w, 12368, 8367752370824835685)
    put(w, 12376, 8028911461405320552)
    put(w, 12384, 7454127125053729143)
    put(w, 12392, 6998720764839292277)
    put(w, 12400, 7599104626777941362)
    put(w, 12408, 8245656749041018226)
    put(w, 12416, 7312272867892093797)
    put(w, 12424, 7308626857453232228)
    put(w, 12432, 7092431779225891950)
    put(w, 12440, 8007527085683074921)
    put(w, 12448, 2314914454458430576)
    put(w, 12456, 7020303009828925283)
    put(w, 12464, 8459856186519872372)
    put(w, 12472, 7286888108152218989)
    put(w, 12480, 2334102057442963576)
    put(w, 12488, 8459856186519678575)
    put(w, 12496, 8029468888270792045)
    put(w, 12504, 7813877729218291058)
    put(w, 12512, 7454127125271503721)
    put(w, 12520, 7955925901167127925)
    put(w, 12528, 7521891418276389238)
    put(w, 12536, 2891346395953064303)
    put(w, 12544, 7358993337588607075)
    put(w, 12552, 7867888721082543986)
    put(w, 12560, 3700581674622606107)
    put(w, 12568, 1976292107150388534)
    put(w, 12576, 6564960952787874139)
    put(w, 12584, 3556466486597073713)
    put(w, 12592, 4265290495451083579)
    put(w, 12600, 3691598586932179507)
    put(w, 12608, 755250347200245043)
    put(w, 12616, 7955434372052688928)
    put(w, 12624, 4189037474216178543)
    put(w, 12632, 8872126588268469024)
    put(w, 12640, 2459000718894309386)
    put(w, 12648, 2459029315948670819)
    put(w, 12656, 5928239357415939909)
    put(w, 12664, 2314885530817014818)
    put(w, 12672, 7449362198107595296)
    put(w, 12680, 732998369319461477)
    put(w, 12688, 8080056003806109728)
    put(w, 12696, 2459029315949650280)
    put(w, 12704, 730271869691327076)
    put(w, 12712, 2314861740994600992)
    put(w, 12720, 7741443805845007453)
    put(w, 12728, 7310305785733462562)
    put(w, 12736, 7022364309382498860)
    put(w, 12744, 7287422581097067892)
    put(w, 12752, 6592436572605346418)
    return 0

def format_constants_1(w: mutbuf) -> u64:
    put(w, 12760, 7311080717912205357)
    put(w, 12768, 7168425960787243890)
    put(w, 12776, 8388354980832178273)
    put(w, 12784, 7022344797552862569)
    put(w, 12792, 8030038434085564268)
    put(w, 12800, 7882833662170723442)
    put(w, 12808, 7236833192277797986)
    put(w, 12816, 7882833662170722917)
    put(w, 12824, 7162245557559848034)
    put(w, 12832, 7092436534709792107)
    put(w, 12840, 7379555244523157868)
    put(w, 12848, 7162254423478578297)
    put(w, 12856, 7809643567100341364)
    put(w, 12864, 7811904093162928745)
    put(w, 12872, 3199916886748834916)
    put(w, 12880, 7290329866991332713)
    put(w, 12888, 8243123821925919076)
    put(w, 12896, 7002380991635729529)
    put(w, 12904, 7594306113343615088)
    put(w, 12912, 3271974480785845620)
    put(w, 12920, 7234237276562486641)
    put(w, 12928, 7521983764246656105)
    put(w, 12936, 3349967204483359021)
    put(w, 12944, 3199857431650250286)
    put(w, 12952, 8318267694548593952)
    put(w, 12960, 8316293034886524776)
    put(w, 12968, 7308533437519194144)
    put(w, 12976, 7953674036811232115)
    put(w, 12984, 3255386101999018084)
    put(w, 12992, 8317708060499010934)
    put(w, 13000, 7453301734228062056)
    put(w, 13008, 7311066724037386610)
    put(w, 13016, 8461736408563413874)
    put(w, 13024, 7236828443217060461)
    put(w, 13032, 7019256343428621600)
    put(w, 13040, 7811883199287616288)
    put(w, 13048, 3255358656839513193)
    put(w, 13056, 8872198388400546675)
    put(w, 13064, 7595371767660569960)
    put(w, 13072, 7021788497383009889)
    put(w, 13080, 8098994043913383533)
    put(w, 13088, 8083505486523949428)
    put(w, 13096, 8515864210702823282)
    put(w, 13104, 3342080424572103730)
    put(w, 13112, 7453301734461499752)
    put(w, 13120, 7506431261597852018)
    put(w, 13128, 7019256042646433893)
    put(w, 13136, 7881706611452047406)
    put(w, 13144, 8390317603883873838)
    put(w, 13152, 8246141913630518881)
    put(w, 13160, 3852317578583238511)
    put(w, 13168, 7507044781602990124)
    put(w, 13176, 8243680180224024937)
    put(w, 13184, 7307139007831240033)
    put(w, 13192, 3342068294661272688)
    put(w, 13200, 3345437242195669616)
    put(w, 13208, 7022361299819181942)
    put(w, 13216, 8030604430060120110)
    put(w, 13224, 9023091795212464743)
    put(w, 13232, 8386092971864975453)
    put(w, 13240, 7166121105108724833)
    put(w, 13248, 7307225774412359016)
    put(w, 13256, 3342068294661272688)
    put(w, 13264, 3345437242195669616)
    put(w, 13272, 7022361299819180406)
    put(w, 13280, 8030604430060120110)
    put(w, 13288, 3184737828280037991)
    put(w, 13296, 7595371767660569960)
    put(w, 13304, 7021788497383009889)
    put(w, 13312, 8098994043946937965)
    put(w, 13320, 8083505486523949428)
    put(w, 13328, 8515864210702823282)
    put(w, 13336, 3342080424572103732)
    put(w, 13344, 7453301734461499752)
    put(w, 13352, 7506433460621107570)
    put(w, 13360, 7019256042646433893)
    put(w, 13368, 7881706611452047406)
    put(w, 13376, 8390317603884004910)
    put(w, 13384, 8246141913630518881)
    put(w, 13392, 3996432766659094383)
    put(w, 13400, 7507044781602990124)
    put(w, 13408, 8243680180224024937)
    put(w, 13416, 3268343636041821537)
    put(w, 13424, 2338623232362770221)
    put(w, 13432, 7592317272213181775)
    put(w, 13440, 2333261979305996398)
    put(w, 13448, 7002381030475722089)
    put(w, 13456, 5006151630796977011)
    put(w, 13464, 2338609982203523192)
    put(w, 13472, 7310313481142618440)
    put(w, 13480, 2338053341825491565)
    put(w, 13488, 8028899319671256179)
    put(w, 13496, 2334397804054603118)
    put(w, 13504, 8462031897463051082)
    put(w, 13512, 6076850273017753716)
    put(w, 13520, 2337136347834504528)
    put(w, 13528, 7595413496956998991)
    put(w, 13536, 8243105118282719329)
    put(w, 13544, 7809924986309927213)
    put(w, 13552, 7307199386133031033)
    put(w, 13560, 7882833662170721123)
    put(w, 13568, 8511910401082485858)
    put(w, 13576, 7019256364852146789)
    put(w, 13584, 8386658464741353760)
    put(w, 13592, 7886488416259500392)
    put(w, 13600, 8011109226030656609)
    put(w, 13608, 6076850633811457141)
    put(w, 13616, 7017220842225685840)
    put(w, 13624, 7960992382028442467)
    put(w, 13632, 6583556105017324641)
    put(w, 13640, 8872201691297688877)
    put(w, 13648, 6736668587868185199)
    put(w, 13656, 7306934683318431067)
    put(w, 13664, 3917909817003024500)
    put(w, 13672, 8606218820622036276)
    put(w, 13680, 3276497845987585390)
    put(w, 13688, 7019256244979723879)
    put(w, 13696, 3255368522447282720)
    put(w, 13704, 2334111888757186914)
    put(w, 13712, 9035758422684954235)
    put(w, 13720, 8872201691297688877)
    put(w, 13728, 3277904074047644271)
    put(w, 13736, 2338605601487156269)
    put(w, 13744, 3257288213055174779)
    put(w, 13752, 3273685299622538869)
    put(w, 13760, 7955377262162766188)
    put(w, 13768, 8462656715864505717)
    put(w, 13776, 4995988719815390053)
    return 0

def format_constants_2(w: mutbuf) -> u64:
    put(w, 13784, 7021147421822964819)
    put(w, 13792, 8171062637294543732)
    put(w, 13800, 5856177189811348853)
    put(w, 13808, 2333261978766886229)
    put(w, 13816, 3255386075844078953)
    put(w, 13824, 7957695015192261990)
    put(w, 13832, 5642809484373808454)
    put(w, 13840, 4786028359222177069)
    put(w, 13848, 7022850341490347852)
    put(w, 13856, 4995983205143508332)
    put(w, 13864, 8314889994848578861)
    put(w, 13872, 7595412324362832198)
    put(w, 13880, 8155302496242573409)
    put(w, 13888, 8459498623396373877)
    put(w, 13896, 5053160206699357038)
    put(w, 13904, 3264633956255092309)
    put(w, 13912, 4764926480573293101)
    put(w, 13920, 7022850341490347852)
    put(w, 13928, 6146359429620397420)
    put(w, 13936, 7236270204637752645)
    put(w, 13944, 6000004464030130291)
    put(w, 13952, 5870849369341766957)
    put(w, 13960, 7309954817971078485)
    put(w, 13968, 4995166483155742835)
    put(w, 13976, 7595396995658764371)
    put(w, 13984, 7002380991635726433)
    put(w, 13992, 8462594848139800688)
    put(w, 14000, 5928238291428668005)
    put(w, 14008, 8030045015146048857)
    put(w, 14016, 5788046165134373742)
    put(w, 14024, 7310236292612312655)
    put(w, 14032, 8317708060514805100)
    put(w, 14040, 5713190250198353235)
    put(w, 14048, 7234223979192931150)
    put(w, 14056, 7521983764246656105)
    put(w, 14064, 3255391637894164781)
    put(w, 14072, 8028075781016806771)
    put(w, 14080, 4847364434565297006)
    put(w, 14088, 7019256201239021908)
    put(w, 14096, 7017221147404297504)
    put(w, 14104, 7813868916163765108)
    put(w, 14112, 7593739056998218617)
    put(w, 14120, 7146213588128262508)
    put(w, 14128, 7578546001215059041)
    put(w, 14136, 8313976365262008429)
    put(w, 14144, 8227084125713818995)
    put(w, 14152, 8313976356453248613)
    put(w, 14160, 7146220215144899955)
    put(w, 14168, 8319099784386536808)
    put(w, 14176, 7311079945103633765)
    put(w, 14184, 8317701201536117106)
    put(w, 14192, 8245930579948954992)
    put(w, 14200, 7074140691121332589)
    put(w, 14208, 8386107317106272629)
    put(w, 14216, 7161128497714063459)
    put(w, 14224, 8155302496242576500)
    put(w, 14232, 7594306113344005493)
    put(w, 14240, 3204711840028372340)
    put(w, 14248, 8386091928506688613)
    put(w, 14256, 8751168581018675299)
    put(w, 14264, 7017221147404297516)
    put(w, 14272, 7813868916163765108)
    put(w, 14280, 3255308881535991161)
    put(w, 14288, 2318355955935638895)
    put(w, 14296, 6147506216737206061)
    put(w, 14304, 8462391747554389332)
    put(w, 14312, 6076851595345076340)
    put(w, 14320, 7020378893159968045)
    put(w, 14328, 7954882391399607597)
    put(w, 14336, 3270860628426567012)
    put(w, 14344, 8895846658938598445)
    put(w, 14352, 7595371767660569960)
    put(w, 14360, 7021788497383009889)
    put(w, 14368, 8098994043913383533)
    put(w, 14376, 8083505486523949428)
    put(w, 14384, 8515864210702823282)
    put(w, 14392, 3342080424572103730)
    put(w, 14400, 7453301734461499752)
    put(w, 14408, 7506431261597852018)
    put(w, 14416, 7019256042646433893)
    put(w, 14424, 7881706611452047406)
    put(w, 14432, 8390317603883873838)
    put(w, 14440, 8246141913630518881)
    put(w, 14448, 3852317578583238511)
    put(w, 14456, 7507044781602990124)
    put(w, 14464, 8243680180224024937)
    put(w, 14472, 7307139007831240033)
    put(w, 14480, 3342068294661272688)
    put(w, 14488, 3345437242195669616)
    put(w, 14496, 7022361299819181942)
    put(w, 14504, 8030604430060120110)
    put(w, 14512, 9023091795212464743)
    put(w, 14520, 9035758422684954235)
    put(w, 14528, 9039959639267110779)
    put(w, 14536, 3257288213055174779)
    put(w, 14544, 3273685299622538869)
    put(w, 14552, 7955377262162766188)
    put(w, 14560, 7506705835531009397)
    put(w, 14568, 8391735720501341285)
    put(w, 14576, 7595443011420714352)
    put(w, 14584, 7957695015191404385)
    put(w, 14592, 7595371767660569960)
    put(w, 14600, 7021788497383009889)
    put(w, 14608, 8390317603972066925)
    put(w, 14616, 8246141913630518881)
    put(w, 14624, 3636144796469454703)
    put(w, 14632, 7595371767660569960)
    put(w, 14640, 7021788497383009889)
    put(w, 14648, 8390317604005621357)
    put(w, 14656, 8246141913630518881)
    put(w, 14664, 3780259984545310575)
    put(w, 14672, 7595371767660569960)
    put(w, 14680, 7021788497383009889)
    put(w, 14688, 8390317604039175789)
    put(w, 14696, 8246141913630518881)
    put(w, 14704, 3924375172621166447)
    put(w, 14712, 7595371767660569960)
    put(w, 14720, 7021788497383009889)
    put(w, 14728, 8390317604072730221)
    put(w, 14736, 8246141913630518881)
    put(w, 14744, 4068490360697022319)
    put(w, 14752, 7092999497381601646)
    put(w, 14760, 6860733172345431402)
    put(w, 14768, 8029473307804644406)
    put(w, 14776, 8679965255892037239)
    put(w, 14784, 7021218898870429485)
    put(w, 14792, 8315168235715324258)
    put(w, 14800, 7595161807865799011)
    return 0

def format_constants_3(w: mutbuf) -> u64:
    put(w, 14808, 8313976365262008429)
    put(w, 14816, 7310038651590501747)
    put(w, 14824, 8319099784504108142)
    put(w, 14832, 7307199768569212261)
    put(w, 14840, 7882833662170721123)
    put(w, 14848, 7379555244528200802)
    put(w, 14856, 8386658464741353849)
    put(w, 14864, 8820700510885670766)
    put(w, 14872, 7021222235859149413)
    put(w, 14880, 7161128497717994356)
    put(w, 14888, 8462595152813516148)
    put(w, 14896, 3275358708925297253)
    put(w, 14904, 7594306443838255201)
    put(w, 14912, 3271974480785845620)
    put(w, 14920, 7594306443938198897)
    put(w, 14928, 3271974480785845620)
    put(w, 14936, 521510350945)
    put(w, 40960, 167537541120)
    put(w, 40968, 188995403780)
    put(w, 40976, 197602181125)
    put(w, 40984, 214782115847)
    put(w, 40992, 227667017738)
    put(w, 41000, 231945142285)
    put(w, 41008, 236240109583)
    put(w, 41016, 240535076881)
    put(w, 41024, 244846886931)
    put(w, 41032, 270684061718)
    put(w, 41040, 296420179997)
    put(w, 41048, 304993271842)
    put(w, 41056, 343765876774)
    put(w, 41064, 382353211441)
    put(w, 41072, 403794362424)
    put(w, 41080, 412417982525)
    put(w, 41088, 167537475652)
    put(w, 41096, 188995403847)
    put(w, 41104, 197602181192)
    put(w, 41112, 214782115914)
    put(w, 41120, 227667017805)
    put(w, 41128, 231945142352)
    put(w, 41136, 236240109650)
    put(w, 41144, 240535076948)
    put(w, 41152, 244846886998)
    put(w, 41160, 270667219033)
    put(w, 41168, 296403337311)
    put(w, 41176, 304976429155)
    put(w, 41184, 343698505830)
    put(w, 41192, 382319525997)
    put(w, 41200, 403777519730)
    put(w, 41208, 412384297078)
    put(w, 41216, 72339223650238499)
    put(w, 41224, 4503762837176357)
    put(w, 41232, 72057744378560547)
    put(w, 41240, 72057744378691629)
    put(w, 41248, 4222335121031216)
    put(w, 41256, 72902225143267363)
    put(w, 41264, 72057744362766385)
    put(w, 41272, 72057744362766385)
    put(w, 41280, 72057744362766385)
    put(w, 41288, 72057744362766385)
    put(w, 41296, 4222335121031216)
    put(w, 41304, 844674055012387)
    put(w, 41312, 73183751643004987)
    put(w, 41320, 73746710203269181)
    put(w, 41328, 72057744362766385)
    put(w, 41336, 1970612616757296)
    put(w, 41344, 4222335104516164)
    put(w, 41352, 1970612616560675)
    put(w, 41360, 4222335104516164)
    put(w, 41368, 72902225143267363)
    put(w, 41376, 2252113346822216)
    put(w, 41384, 2533596913533002)
    put(w, 41392, 2815080480243788)
    put(w, 41400, 3096564046954574)
    put(w, 41408, 72057744362766385)
    put(w, 41416, 3659539786432560)
    put(w, 41424, 3941023336955990)
    put(w, 41432, 4222335104974936)
    put(w, 41440, 72902225143267363)
    put(w, 41448, 3378099153272924)
    put(w, 41456, 72057744362766385)
    put(w, 41464, 3659539786432560)
    put(w, 41472, 3941023336955990)
    put(w, 41480, 4222335104974936)
    put(w, 41488, 72339223650238499)
    put(w, 41496, 72057744362831969)
    put(w, 41504, 72620737281654819)
    put(w, 41512, 72902225143267363)
    put(w, 41520, 72057744362766385)
    put(w, 41528, 4222335121031216)
    put(w, 41536, 4222335120834595)
    put(w, 41544, 4222335120834595)
    put(w, 41552, 4222335120834595)
    put(w, 41560, 72902225143267363)
    put(w, 41568, 72057744362766385)
    put(w, 41576, 73183751643005027)
    put(w, 41584, 73746710203269181)
    put(w, 41592, 72057744362766385)
    put(w, 41600, 1970625501659184)
    put(w, 41608, 72057744362766385)
    put(w, 41616, 4222335104516166)
    put(w, 41624, 72902225143267363)
    put(w, 41632, 2533626978238545)
    put(w, 41640, 3096585521725523)
    put(w, 41648, 72057744362766385)
    put(w, 41656, 3659561261269040)
    put(w, 41664, 4222335104974939)
    put(w, 41672, 72902225143267363)
    put(w, 41680, 4222335104843871)
    put(w, 41688, 72902225143267363)
    put(w, 41696, 3941040516825178)
    put(w, 41704, 983089)
    put(w, 43008, 16973824)
    put(w, 43016, 65539)
    put(w, 43024, 131076)
    put(w, 43032, 16973830)
    put(w, 43040, 16973833)
    put(w, 43048, 16908300)
    put(w, 43056, 16908302)
    put(w, 43064, 16908304)
    put(w, 43072, 16973842)
    put(w, 43080, 17170453)
    put(w, 43088, 17039387)
    put(w, 43096, 16973855)
    put(w, 43104, 17236002)
    put(w, 43112, 17104937)
    put(w, 43120, 17039406)
    put(w, 43128, 17104946)
    put(w, 43136, 16973879)
    return 0

def format_constants_4(w: mutbuf) -> u64:
    put(w, 43144, 65594)
    put(w, 43152, 131131)
    put(w, 43160, 16973885)
    put(w, 43168, 16973888)
    put(w, 43176, 16908355)
    put(w, 43184, 16908357)
    put(w, 43192, 16908359)
    put(w, 43200, 16973897)
    put(w, 43208, 17170508)
    put(w, 43216, 17039442)
    put(w, 43224, 16973910)
    put(w, 43232, 17236057)
    put(w, 43240, 17104992)
    put(w, 43248, 17039461)
    put(w, 43256, 17105001)
    put(w, 43264, 1048613)
    put(w, 43272, 176093659176)
    put(w, 43280, 184683659306)
    put(w, 43288, 176093659176)
    put(w, 43296, 176093659176)
    put(w, 43304, 131119)
    put(w, 43312, 219044315185)
    put(w, 43320, 176093659176)
    put(w, 43328, 196660)
    put(w, 43336, 219044315185)
    put(w, 43344, 176093659176)
    put(w, 43352, 196660)
    put(w, 43360, 219044315185)
    put(w, 43368, 176093659176)
    put(w, 43376, 219044315185)
    put(w, 43384, 176093659176)
    put(w, 43392, 219044315185)
    put(w, 43400, 176093659176)
    put(w, 43408, 219044315185)
    put(w, 43416, 176093659176)
    put(w, 43424, 196660)
    put(w, 43432, 219044315185)
    put(w, 43440, 176093659176)
    put(w, 43448, 196660)
    put(w, 43456, 262208)
    put(w, 43464, 327745)
    put(w, 43472, 393282)
    put(w, 43480, 219044315185)
    put(w, 43488, 176093659176)
    put(w, 43496, 196660)
    put(w, 43504, 458822)
    put(w, 43512, 219044315185)
    put(w, 43520, 176093659176)
    put(w, 43528, 458822)
    put(w, 43536, 219044315185)
    put(w, 43544, 176093659176)
    put(w, 43552, 196660)
    put(w, 43560, 524369)
    put(w, 43568, 589906)
    put(w, 43576, 655443)
    put(w, 43584, 720980)
    put(w, 43592, 219044315185)
    put(w, 43600, 176093659176)
    put(w, 43608, 196660)
    put(w, 43616, 852058)
    put(w, 43624, 917595)
    put(w, 43632, 219044315185)
    put(w, 43640, 176093659176)
    put(w, 43648, 196660)
    put(w, 43656, 786527)
    put(w, 43664, 219044315185)
    put(w, 43672, 176093659176)
    put(w, 43680, 196660)
    put(w, 43688, 852058)
    put(w, 43696, 917595)
    put(w, 43704, 1048613)
    put(w, 43712, 176093659176)
    put(w, 43720, 184683659306)
    put(w, 43728, 176093659176)
    put(w, 43736, 176093659176)
    put(w, 43744, 131119)
    put(w, 43752, 219044315185)
    put(w, 43760, 176093659176)
    put(w, 43768, 196706)
    put(w, 43776, 219044315185)
    put(w, 43784, 176093659176)
    put(w, 43792, 196706)
    put(w, 43800, 219044315185)
    put(w, 43808, 176093659176)
    put(w, 43816, 219044315185)
    put(w, 43824, 176093659176)
    put(w, 43832, 219044315185)
    put(w, 43840, 176093659176)
    put(w, 43848, 219044315185)
    put(w, 43856, 176093659176)
    put(w, 43864, 196706)
    put(w, 43872, 219044315185)
    put(w, 43880, 176093659176)
    put(w, 43888, 196706)
    put(w, 43896, 262208)
    put(w, 43904, 327745)
    put(w, 43912, 393282)
    put(w, 43920, 219044315185)
    put(w, 43928, 176093659176)
    put(w, 43936, 196706)
    put(w, 43944, 458822)
    put(w, 43952, 219044315185)
    put(w, 43960, 176093659176)
    put(w, 43968, 458822)
    put(w, 43976, 219044315185)
    put(w, 43984, 176093659176)
    put(w, 43992, 196706)
    put(w, 44000, 524369)
    put(w, 44008, 589906)
    put(w, 44016, 655443)
    put(w, 44024, 720980)
    put(w, 44032, 219044315185)
    put(w, 44040, 176093659176)
    put(w, 44048, 196706)
    put(w, 44056, 852058)
    put(w, 44064, 917595)
    put(w, 44072, 219044315185)
    put(w, 44080, 176093659176)
    put(w, 44088, 196706)
    put(w, 44096, 786527)
    put(w, 44104, 219044315185)
    put(w, 44112, 176093659176)
    put(w, 44120, 196706)
    put(w, 44128, 852058)
    put(w, 44136, 917595)
    put(w, 49152, 14483861222950395424)
    put(w, 49160, 217866042989478661)
    put(w, 49168, 10088348020442857473)
    return 0

def format_constants_5(w: mutbuf) -> u64:
    put(w, 49176, 229967268501586691)
    put(w, 49184, 1875752775279903234)
    put(w, 49192, 72925181777347587)
    put(w, 49200, 4179906904568562111)
    put(w, 49208, 145023444866826755)
    put(w, 49216, 223773719116514096)
    put(w, 49224, 2163138537522921474)
    put(w, 49232, 72982283350444035)
    put(w, 49240, 72623872607977888)
    put(w, 49248, 72908620384502275)
    put(w, 49256, 218426793886155520)
    put(w, 49264, 2255111267221762)
    put(w, 49272, 144964015397864451)
    put(w, 49280, 217581269427553048)
    put(w, 49288, 432630427967226116)
    put(w, 49296, 72903122825052419)
    put(w, 49304, 217299794417287937)
    put(w, 49312, 847732088701188)
    put(w, 49320, 505247587541124867)
    put(w, 49328, 218425694358209296)
    put(w, 49336, 432630427950449153)
    put(w, 49344, 144964015397863683)
    put(w, 49352, 216736844497355529)
    put(w, 49360, 793199796042268674)
    put(w, 49368, 72904222337009411)
    put(w, 49376, 222085968549774087)
    put(w, 49384, 288515153975248385)
    put(w, 49392, 144960721158406659)
    put(w, 49400, 216458668055921410)
    put(w, 49408, 74875715388113921)
    put(w, 49416, 72904230926876931)
    put(w, 49424, 216173894527288067)
    put(w, 49432, 144962915886366977)
    put(w, 49440, 217021622321349379)
    put(w, 49448, 216174994072339202)
    put(w, 49456, 866101888007995398)
    put(w, 49464, 72926212569301251)
    put(w, 49472, 216736844598084367)
    put(w, 49480, 144399966000055041)
    put(w, 49488, 144962920181137923)
    put(w, 49496, 216736844816515849)
    put(w, 49504, 288515188334990849)
    put(w, 49512, 72904222337139203)
    put(w, 49520, 216460867062399747)
    put(w, 49528, 144400000275907329)
    put(w, 49536, 72904222337403907)
    put(w, 49544, 217581269427487538)
    put(w, 49552, 144400068995387140)
    put(w, 49560, 72927320671846659)
    put(w, 49568, 217863843882271496)
    put(w, 49576, 284795053735939)
    put(w, 49584, 144969534431232259)
    put(w, 49592, 224058493350183682)
    put(w, 49600, 288515149680279845)
    put(w, 49608, 72902023314866435)
    put(w, 49616, 216173894577554198)
    put(w, 49624, 216739069273769473)
    put(w, 49632, 289113288338776067)
    put(w, 49640, 220114544771531558)
    put(w, 49648, 72903965209201665)
    put(w, 49656, 213923194208584448)
    put(w, 49664, 72908624678289667)
    put(w, 49672, 227433993140765440)
    put(w, 49680, 216457693098083073)
    put(w, 49688, 72902023313752579)
    put(w, 49696, 231936493441123075)
    put(w, 49704, 2234351947165664001)
    put(w, 49712, 145053097316123395)
    put(w, 49720, 1945839833993839365)
    put(w, 49728, 649385891136537347)
    put(w, 49736, 219563689178104599)
    put(w, 49744, 6704737248094650881)
    put(w, 49752, 433199910583075331)
    put(w, 49760, 240949190186828557)
    put(w, 49768, 2164546165876664839)
    put(w, 49776, 289086912940671235)
    put(w, 49784, 217300894616847104)
    put(w, 49792, 722268196215925515)
    put(w, 49800, 72972396356502275)
    put(w, 49808, 218712667026752284)
    put(w, 49816, 5490172848159001862)
    put(w, 49824, 895002498629891)
    put(w, 49832, 232788616647016960)
    put(w, 49840, 72061146026413571)
    put(w, 49848, 577316180992853250)
    put(w, 49856, 360854238357947178)
    put(w, 49864, 144965119206818307)
    put(w, 49872, 216173894510379783)
    put(w, 49880, 3747561267326550017)
    put(w, 49888, 144973911003365635)
    put(w, 49896, 216737944277418757)
    put(w, 49904, 3316904523162912769)
    put(w, 49912, 72930614910718211)
    put(w, 49920, 225196487464911628)
    put(w, 49928, 217745100971805455)
    put(w, 49936, 10598380639940116992)
    put(w, 49944, 206040795868955406)
    put(w, 49952, 361132399467955459)
    put(w, 49960, 216461967479669504)
    put(w, 49968, 432630363660162830)
    put(w, 49976, 72908620383518979)
    put(w, 49984, 217862744471307014)
    put(w, 49992, 1811013835579131393)
    put(w, 50000, 216688504662917379)
    put(w, 50008, 4467854517236599578)
    put(w, 50016, 361244553951641859)
    put(w, 50024, 239536319137645354)
    put(w, 50032, 3314651524919066880)
    put(w, 50040, 3891957809648763139)
    put(w, 50048, 123589517941344515)
    put(w, 50056, 144678150944196611)
    put(w, 50064, 288515149680279810)
    put(w, 50072, 217081068946325507)
    put(w, 50080, 235603365407884041)
    put(w, 50088, 2092770244400712456)
    put(w, 50096, 289085800548467459)
    put(w, 50104, 219841866206610208)
    put(w, 50112, 1952314175120410882)
    put(w, 50120, 144965119204723203)
    put(w, 50128, 217862744471831301)
    put(w, 50136, 649085131767888641)
    put(w, 50144, 222378440096155139)
    put(w, 50152, 216996602005630980)
    put(w, 50160, 291611400814684418)
    put(w, 50168, 72906421361509635)
    put(w, 50176, 216455369503867648)
    put(w, 50184, 144963719263386625)
    put(w, 50192, 227748453416370997)
    return 0

def format_constants_6(w: mutbuf) -> u64:
    put(w, 50200, 216457632951775750)
    put(w, 50208, 216601595994178563)
    put(w, 50216, 144965123499474180)
    put(w, 50224, 216737944059380485)
    put(w, 50232, 75720093056828931)
    put(w, 50240, 72929511104774659)
    put(w, 50248, 220114544201106194)
    put(w, 50256, 145526386050927874)
    put(w, 50264, 72997689417794563)
    put(w, 50272, 228890845997368076)
    put(w, 50280, 1081761124994253186)
    put(w, 50288, 224345465515410203)
    put(w, 50296, 2594358283515144709)
    put(w, 50304, 216627060855866371)
    put(w, 50312, 2523145140193921282)
    put(w, 50320, 793534068852982787)
    put(w, 50328, 217862744605524747)
    put(w, 50336, 1009091133009232129)
    put(w, 50344, 217018310901235971)
    put(w, 50352, 1515746059765940787)
    put(w, 50360, 72907619656206851)
    put(w, 50368, 217656036318839593)
    put(w, 50376, 72342552250089474)
    put(w, 50384, 72926216864137987)
    put(w, 50392, 221292121272353607)
    put(w, 50400, 1874345305974178049)
    put(w, 50408, 289135549149611267)
    put(w, 50416, 216455370309239571)
    put(w, 50424, 2017897415180486405)
    put(w, 50432, 505257496030609923)
    put(w, 50440, 226904029543203592)
    put(w, 50448, 2018460584311458564)
    put(w, 50456, 505275092513194499)
    put(w, 50464, 236526954353525507)
    put(w, 50472, 3244565570045293111)
    put(w, 50480, 216776439818160131)
    put(w, 50488, 2162238003140362780)
    put(w, 50496, 144961816377229571)
    put(w, 50504, 144175669839921921)
    put(w, 50512, 1807635775198800384)
    put(w, 50520, 649387046478751235)
    put(w, 50528, 233352664770151245)
    put(w, 50536, 650492073010725889)
    put(w, 50544, 577323873279936003)
    put(w, 50552, 221521920662242086)
    put(w, 50560, 449800508903985419)
    put(w, 50568, 72905321848242435)
    put(w, 50576, 232504940885508878)
    put(w, 50584, 504687944762853637)
    put(w, 50592, 72925117352575491)
    put(w, 50600, 217299794433999622)
    put(w, 50608, 144681440892881153)
    put(w, 50616, 361132420939907587)
    put(w, 50624, 217301993541206790)
    put(w, 50632, 565148993587467)
    put(w, 50640, 72630443926946050)
    put(w, 50648, 144960721107681792)
    put(w, 50656, 74311597186746625)
    put(w, 50664, 2162576648465751298)
    put(w, 50672, 3819516490953524039)
    put(w, 50680, 793552872219673091)
    put(w, 50688, 232237759593841417)
    put(w, 50696, 1881381025062521094)
    put(w, 50704, 13331523528433730051)
    put(w, 50712, 507784510386158337)
    put(w, 50720, 72909724189721091)
    put(w, 50728, 216455369973629697)
    put(w, 50736, 524109743976024834)
    put(w, 50744, 1946410467713679875)
    put(w, 50752, 236453288349270855)
    put(w, 50760, 1009405557716748551)
    put(w, 50768, 228558793620193801)
    put(w, 50776, 2234633259067837697)
    put(w, 50784, 5261063087696708099)
    put(w, 50792, 228277318525715206)
    put(w, 50800, 576745530126958595)
    put(w, 50808, 72907542346926083)
    put(w, 50816, 216455370091070209)
    put(w, 50824, 195346971144422657)
    put(w, 50832, 227432893847634712)
    put(w, 50840, 23927572043864835)
    put(w, 50848, 218312487629557507)
    put(w, 50856, 14054330377871519334)
    put(w, 50864, 12613741851125220097)
    put(w, 50872, 2277143569943757576)
    put(w, 50880, 4122404456543683842)
    put(w, 50888, 2163701464777475586)
    put(w, 50896, 72989997129072899)
    put(w, 50904, 217582369392427785)
    put(w, 50912, 432630376561853706)
    put(w, 50920, 12683000788341227779)
    put(w, 50928, 7278760386424355075)
    put(w, 50936, 220684092147237706)
    put(w, 50944, 17802169680056747072)
    put(w, 50952, 11543814808797999)
    put(w, 50960, 217094065534533634)
    put(w, 50968, 11673615011967862273)
    put(w, 50976, 216767630790296322)
    put(w, 50984, 10018260682740531202)
    put(w, 50992, 866102257450746627)
    put(w, 51000, 144969538726265603)
    put(w, 51008, 432910683657470723)
    put(w, 51016, 1585833511871447987)
    put(w, 51024, 216723895195207939)
    put(w, 51032, 8000648350124942858)
    put(w, 51040, 865556968147064067)
    put(w, 51048, 222938091488019219)
    put(w, 51056, 72978989132808583)
    put(w, 51064, 216456468998783745)
    put(w, 51072, 284820773208834)
    put(w, 51080, 72972392057929987)
    put(w, 51088, 217862744488149763)
    put(w, 51096, 288515162565188353)
    put(w, 51104, 72908628973060355)
    put(w, 51112, 144962512142664403)
    put(w, 51120, 1009091107474310589)
    put(w, 51128, 217586767455899651)
    put(w, 51136, 144977209537724885)
    put(w, 51144, 217299794433999622)
    put(w, 51152, 3202062634149166341)
    put(w, 51160, 289084705327612675)
    put(w, 51168, 4112071362196013825)
    put(w, 51176, 227717448097334531)
    put(w, 51184, 16141464031665455574)
    put(w, 51192, 72342380451399171)
    put(w, 51200, 216669765715755267)
    put(w, 51208, 649647867593690882)
    put(w, 51216, 235038825443820547)
    return 0

def format_constants_7(w: mutbuf) -> u64:
    put(w, 51224, 72905325052902476)
    put(w, 51232, 216173894527157018)
    put(w, 51240, 216457594297057282)
    put(w, 51248, 433189993502998787)
    put(w, 51256, 216173894510576384)
    put(w, 51264, 72342376156430337)
    put(w, 51272, 72902027608326403)
    put(w, 51280, 216173894510379776)
    put(w, 51288, 284777823535105)
    put(w, 51296, 72908620383322627)
    put(w, 51304, 216173894560711427)
    put(w, 51312, 145525930230745345)
    put(w, 51320, 3747856911433990403)
    put(w, 51328, 7134831192923046657)
    put(w, 51336, 72917420772035587)
    put(w, 51344, 120763773614097166)
    put(w, 51352, 289122135968593923)
    put(w, 51360, 217595563062264584)
    put(w, 51368, 220680792804098458)
    put(w, 51376, 6774543544863624195)
    put(w, 51384, 1081708352729974275)
    put(w, 51392, 218714866805113611)
    put(w, 51400, 72623967214708486)
    put(w, 51408, 4468134897030594563)
    put(w, 51416, 865257432979538643)
    put(w, 51424, 360850920193917699)
    put(w, 51432, 144115201715732992)
    put(w, 51440, 938721246353491456)
    put(w, 51448, 562958576910339)
    put(w, 51456, 218431187587171080)
    put(w, 51464, 903802903433735)
    put(w, 51472, 16071242617865634340)
    put(w, 51480, 433225968635806413)
    put(w, 51488, 1009700773568905693)
    put(w, 51496, 11673898600303377072)
    put(w, 51504, 2795059584077962515)
    put(w, 51512, 3151059601154049283)
    put(w, 51520, 197103)
    return 0

def decimal(point: u64, profile: u64) -> u64:
    if profile == 312:
        return decimal_312(point)
    return decimal_314(point)

def decimal_312(point: u64) -> u64:
    if point >= 48 and point <= 57:
        return 1
    if point >= 1632 and point <= 1641:
        return 1
    if point >= 1776 and point <= 1785:
        return 1
    if point >= 1984 and point <= 1993:
        return 1
    if point >= 2406 and point <= 2415:
        return 1
    if point >= 2534 and point <= 2543:
        return 1
    if point >= 2662 and point <= 2671:
        return 1
    if point >= 2790 and point <= 2799:
        return 1
    if point >= 2918 and point <= 2927:
        return 1
    if point >= 3046 and point <= 3055:
        return 1
    if point >= 3174 and point <= 3183:
        return 1
    if point >= 3302 and point <= 3311:
        return 1
    if point >= 3430 and point <= 3439:
        return 1
    if point >= 3558 and point <= 3567:
        return 1
    if point >= 3664 and point <= 3673:
        return 1
    if point >= 3792 and point <= 3801:
        return 1
    if point >= 3872 and point <= 3881:
        return 1
    if point >= 4160 and point <= 4169:
        return 1
    if point >= 4240 and point <= 4249:
        return 1
    if point >= 6112 and point <= 6121:
        return 1
    if point >= 6160 and point <= 6169:
        return 1
    if point >= 6470 and point <= 6479:
        return 1
    if point >= 6608 and point <= 6617:
        return 1
    if point >= 6784 and point <= 6793:
        return 1
    if point >= 6800 and point <= 6809:
        return 1
    if point >= 6992 and point <= 7001:
        return 1
    if point >= 7088 and point <= 7097:
        return 1
    if point >= 7232 and point <= 7241:
        return 1
    if point >= 7248 and point <= 7257:
        return 1
    if point >= 42528 and point <= 42537:
        return 1
    if point >= 43216 and point <= 43225:
        return 1
    if point >= 43264 and point <= 43273:
        return 1
    if point >= 43472 and point <= 43481:
        return 1
    if point >= 43504 and point <= 43513:
        return 1
    if point >= 43600 and point <= 43609:
        return 1
    if point >= 44016 and point <= 44025:
        return 1
    if point >= 65296 and point <= 65305:
        return 1
    if point >= 66720 and point <= 66729:
        return 1
    if point >= 68912 and point <= 68921:
        return 1
    if point >= 69734 and point <= 69743:
        return 1
    if point >= 69872 and point <= 69881:
        return 1
    if point >= 69942 and point <= 69951:
        return 1
    if point >= 70096 and point <= 70105:
        return 1
    if point >= 70384 and point <= 70393:
        return 1
    if point >= 70736 and point <= 70745:
        return 1
    if point >= 70864 and point <= 70873:
        return 1
    if point >= 71248 and point <= 71257:
        return 1
    if point >= 71360 and point <= 71369:
        return 1
    if point >= 71472 and point <= 71481:
        return 1
    if point >= 71904 and point <= 71913:
        return 1
    if point >= 72016 and point <= 72025:
        return 1
    if point >= 72784 and point <= 72793:
        return 1
    if point >= 73040 and point <= 73049:
        return 1
    if point >= 73120 and point <= 73129:
        return 1
    if point >= 73552 and point <= 73561:
        return 1
    if point >= 92768 and point <= 92777:
        return 1
    if point >= 92864 and point <= 92873:
        return 1
    if point >= 93008 and point <= 93017:
        return 1
    if point >= 120782 and point <= 120831:
        return 1
    if point >= 123200 and point <= 123209:
        return 1
    if point >= 123632 and point <= 123641:
        return 1
    if point >= 124144 and point <= 124153:
        return 1
    if point >= 125264 and point <= 125273:
        return 1
    if point >= 130032 and point <= 130041:
        return 1
    return 0

def decimal_314(point: u64) -> u64:
    if point >= 48 and point <= 57:
        return 1
    if point >= 1632 and point <= 1641:
        return 1
    if point >= 1776 and point <= 1785:
        return 1
    if point >= 1984 and point <= 1993:
        return 1
    if point >= 2406 and point <= 2415:
        return 1
    if point >= 2534 and point <= 2543:
        return 1
    if point >= 2662 and point <= 2671:
        return 1
    if point >= 2790 and point <= 2799:
        return 1
    if point >= 2918 and point <= 2927:
        return 1
    if point >= 3046 and point <= 3055:
        return 1
    if point >= 3174 and point <= 3183:
        return 1
    if point >= 3302 and point <= 3311:
        return 1
    if point >= 3430 and point <= 3439:
        return 1
    if point >= 3558 and point <= 3567:
        return 1
    if point >= 3664 and point <= 3673:
        return 1
    if point >= 3792 and point <= 3801:
        return 1
    if point >= 3872 and point <= 3881:
        return 1
    if point >= 4160 and point <= 4169:
        return 1
    if point >= 4240 and point <= 4249:
        return 1
    if point >= 6112 and point <= 6121:
        return 1
    if point >= 6160 and point <= 6169:
        return 1
    if point >= 6470 and point <= 6479:
        return 1
    if point >= 6608 and point <= 6617:
        return 1
    if point >= 6784 and point <= 6793:
        return 1
    if point >= 6800 and point <= 6809:
        return 1
    if point >= 6992 and point <= 7001:
        return 1
    if point >= 7088 and point <= 7097:
        return 1
    if point >= 7232 and point <= 7241:
        return 1
    if point >= 7248 and point <= 7257:
        return 1
    if point >= 42528 and point <= 42537:
        return 1
    if point >= 43216 and point <= 43225:
        return 1
    if point >= 43264 and point <= 43273:
        return 1
    if point >= 43472 and point <= 43481:
        return 1
    if point >= 43504 and point <= 43513:
        return 1
    if point >= 43600 and point <= 43609:
        return 1
    if point >= 44016 and point <= 44025:
        return 1
    if point >= 65296 and point <= 65305:
        return 1
    if point >= 66720 and point <= 66729:
        return 1
    if point >= 68912 and point <= 68921:
        return 1
    if point >= 68928 and point <= 68937:
        return 1
    if point >= 69734 and point <= 69743:
        return 1
    if point >= 69872 and point <= 69881:
        return 1
    if point >= 69942 and point <= 69951:
        return 1
    if point >= 70096 and point <= 70105:
        return 1
    if point >= 70384 and point <= 70393:
        return 1
    if point >= 70736 and point <= 70745:
        return 1
    if point >= 70864 and point <= 70873:
        return 1
    if point >= 71248 and point <= 71257:
        return 1
    if point >= 71360 and point <= 71369:
        return 1
    if point >= 71376 and point <= 71395:
        return 1
    if point >= 71472 and point <= 71481:
        return 1
    if point >= 71904 and point <= 71913:
        return 1
    if point >= 72016 and point <= 72025:
        return 1
    if point >= 72688 and point <= 72697:
        return 1
    if point >= 72784 and point <= 72793:
        return 1
    if point >= 73040 and point <= 73049:
        return 1
    if point >= 73120 and point <= 73129:
        return 1
    if point >= 73552 and point <= 73561:
        return 1
    if point >= 90416 and point <= 90425:
        return 1
    if point >= 92768 and point <= 92777:
        return 1
    if point >= 92864 and point <= 92873:
        return 1
    if point >= 93008 and point <= 93017:
        return 1
    if point >= 93552 and point <= 93561:
        return 1
    if point >= 118000 and point <= 118009:
        return 1
    if point >= 120782 and point <= 120831:
        return 1
    if point >= 123200 and point <= 123209:
        return 1
    if point >= 123632 and point <= 123641:
        return 1
    if point >= 124144 and point <= 124153:
        return 1
    if point >= 124401 and point <= 124410:
        return 1
    if point >= 125264 and point <= 125273:
        return 1
    if point >= 130032 and point <= 130041:
        return 1
    return 0
