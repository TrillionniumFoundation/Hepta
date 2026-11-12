"""Author CLI help, errors, version and E_DRIVER JSON presentation in HIA.

Grammar-derived pieces are constants. HIA owns line wrapping, repr escaping,
Unicode classes, color/column decisions and complete output construction.
The reference presentation profiles are CPython 3.12.14, 3.14.4 and 3.14.10
with English messages and the default 3.14 theme. The 3.14.10 choice-list
quoting difference is explicit; private formatter/theme overrides are not
installation policy.
"""
from __future__ import annotations
import ast
import json
from pathlib import Path
import struct
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools import generate_hia_cli_control as grammar

SOURCE_PATH = "examples/hia_bootstrap/cli_format.hiaasm"
SYMBOLS = {
    "ARGV_MAGIC": grammar.SYMBOLS["ARGV_MAGIC"],
    "RESULT_MAGIC": grammar.SYMBOLS["RESULT_MAGIC"],
    "OBSERVE_MAGIC": int.from_bytes(b"HCLIOBS4", "little"),
    "ERROR_MAGIC": int.from_bytes(b"HCLIERR4", "little"),
    "F_CURSOR": 1024, "F_SPLIT": 1032, "F_COLUMNS": 1040,
    "F_WIDTH": 1048, "F_NEGATIVE": 1056, "F_COLOR": 1064,
    "F_OVERFLOW": 1072, "F_HELP_POSITION": 1080, "F_UNICODE_COUNT": 1088,
    "F_USAGE_ROW": 1096, "F_HELP_ROW": 1104, "F_LINE": 1112,
    "F_WORDS": 1120, "F_VAR_CURSOR": 1128,
    "F_LITERAL_TABLE": 8192, "F_LITERAL_DATA": 12288,
    "F_USAGE_ROWS": 40960, "F_USAGE_PARTS": 41216,
    "F_HELP_ROWS": 43008, "F_HELP_LABELS": 43264,
    "F_UNICODE_COMPRESSED": 49152, "F_UNICODE_TABLE": 65536,
    "F_EXTRAS": 131072,
    "FIELD_COUNT": len(grammar.FIELDS), "TOKEN_COUNT": len(grammar.TOKENS),
}

SOURCE = r'''
def format_cli(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 8 or length(w) < F_EXTRAS or length(o) < 4:
        return 199
    put(w, F_CURSOR, 0)
    put(w, F_SPLIT, 0)
    put(w, F_OVERFLOW, 0)
    format_constants(w)
    if read64(s, 0) == ARGV_MAGIC and get(w, 0) == OBSERVE_MAGIC:
        return observation_request(s, w)
    if read64(s, 0) == ERROR_MAGIC:
        return driver_error(s, o, w)
    if read64(s, 0) != ARGV_MAGIC or length(s) < 192 or read64(s, 8) != 4:
        return 199
    argc = read64(s, 16)
    if argc > (length(s) - 192) >> 4 or length(w) < F_EXTRAS + argc * 24:
        return 199
    if get(w, 0) != RESULT_MAGIC or get(w, 88) != argc or get(w, 104) != length(s):
        return 199
    if read64(s, 24) != get(w, 128) or (get(w, 128) != 312 and get(w, 128) != 314 and get(w, 128) != 31410):
        return 199
    if get(w, 24) > 15 or get(w, 8) < 1 or get(w, 8) > 3 or get(w, 80) > argc:
        return 199
    cursor = 192 + argc * 16
    record = 96
    while record < 192 + argc * 16:
        size = read64(s, record + 8)
        if read64(s, record) != cursor or size > (length(s) - cursor) >> 2:
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
        if get(w, 32) < 1 or get(w, 32) > 9 or get(w, 40) >= FIELD_COUNT:
            return 199
        if get(w, 48) > length(s) or get(w, 56) > (length(s) - get(w, 48)) >> 2:
            return 199
    index = 0
    while index < get(w, 80):
        at = F_EXTRAS + index * 24
        if get(w, at) > length(s) or get(w, at + 8) > (length(s) - get(w, at)) >> 2 or get(w, at + 16) > 1:
            return 199
        index = index + 1
    settings(s, w)
    expand_printable(w)
    row = choose(get(w, 128) == 312, 0, 16) + get(w, 24)
    put(w, F_USAGE_ROW, F_USAGE_ROWS + row * 8)
    put(w, F_HELP_ROW, F_HELP_ROWS + row * 8)
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
            put(w, F_SPLIT, get(w, F_CURSOR))
            error_message(s, o, w)
            point(o, w, 10)
    if get(w, F_OVERFLOW) != 0:
        return 199
    return 0

def word16(w:mutbuf, at:u64) -> u64:
    return byte(w, at) | (byte(w, at + 1) << 8)

def point(o:mutbuf, w:mutbuf, value:u64) -> u64:
    cursor = get(w, F_CURSOR)
    if cursor >= length(o) >> 2:
        put(w, F_OVERFLOW, 1)
        return 0
    put32(o, cursor * 4, value)
    put(w, F_CURSOR, cursor + 1)
    return 0

def spaces(o:mutbuf, w:mutbuf, count:u64) -> u64:
    index = 0
    while index < count:
        point(o, w, 32)
        index = index + 1
    return 0

def literal_size(w:mutbuf, literal:u64) -> u64:
    return word16(w, F_LITERAL_TABLE + literal * 4 + 2)

def literal_at(w:mutbuf, literal:u64) -> u64:
    return word16(w, F_LITERAL_TABLE + literal * 4)

def literal(o:mutbuf, w:mutbuf, literal_id:u64) -> u64:
    at = literal_at(w, literal_id)
    size = literal_size(w, literal_id)
    index = 0
    while index < size:
        point(o, w, byte(w, at + index))
        index = index + 1
    return 0

def style(o:mutbuf, w:mutbuf, literal_id:u64) -> u64:
    if get(w, F_COLOR) != 0:
        literal(o, w, literal_id)
    return 0

def raw_text(s:readbuf, o:mutbuf, w:mutbuf, begin:u64, size:u64) -> u64:
    index = 0
    while index < size:
        point(o, w, read32(s, begin + index * 4))
        index = index + 1
    return 0

def source_equal(s:readbuf, w:mutbuf, begin:u64, size:u64, literal_id:u64) -> bool:
    if size != literal_size(w, literal_id):
        return False
    index = 0
    while index < size:
        if read32(s, begin + index * 4) != byte(w, literal_at(w, literal_id) + index):
            return False
        index = index + 1
    return True

def env_equal(s:readbuf, w:mutbuf, index:u64, literal_id:u64) -> bool:
    return source_equal(s, w, read64(s, 96 + index * 16), read64(s, 104 + index * 16), literal_id)

def int_space(point_value:u64) -> bool:
    return (point_value >= 9 and point_value <= 13) or point_value == 32 or point_value == 133 or point_value == 160 or point_value == 5760 or (point_value >= 8192 and point_value <= 8202) or point_value == 8232 or point_value == 8233 or point_value == 8239 or point_value == 8287 or point_value == 12288

def decimal_digit(point_value:u64, profile:u64) -> u64:
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

def columns(s:readbuf, w:mutbuf) -> u64:
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

def color_choice(s:readbuf, w:mutbuf) -> u64:
    if get(w, 128) == 312:
        return 0
    if read64(s, 40) == 0 and env_equal(s, w, 1, L_ZERO):
        return 0
    if read64(s, 40) == 0 and env_equal(s, w, 1, L_ONE):
        return 1
    if read64(s, 136) != 0:
        return 0
    if read64(s, 152) != 0:
        return 1
    if env_equal(s, w, 4, L_DUMB):
        return 0
    return 2

def observation_request(s:readbuf, w:mutbuf) -> u32:
    if length(s) < 192 or read64(s, 8) != 4:
        return 199
    profile = read64(s, 24)
    if profile != 312 and profile != 314 and profile != 31410:
        return 199
    if read64(s, 40) > 1 or read64(s, 48) > 1 or read64(s, 72) > 63:
        return 199
    if read64(s, 64) != 0 or read64(s, 80) != 0 or read64(s, 88) != 0:
        return 199
    argc = read64(s, 16)
    if argc > (length(s) - 192) >> 4:
        return 199
    cursor = 192 + argc * 16
    record = 96
    while record < 192 + argc * 16:
        begin = read64(s, record)
        size = read64(s, record + 8)
        if begin != cursor or size > (length(s) - cursor) >> 2:
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
    put(w, F_COLOR, choose(color_choice(s, w) == 2, 1, 0))
    return 3

def settings(s:readbuf, w:mutbuf) -> u64:
    size = columns(s, w)
    put(w, F_COLUMNS, size)
    put(w, F_WIDTH, size - 2)
    put(w, F_NEGATIVE, choose(size < 2, 1, 0))
    color = color_choice(s, w)
    if color == 2:
        color = read64(s, 48)
    put(w, F_COLOR, color)
    return 0

def beyond_width(w:mutbuf, size:u64) -> bool:
    return get(w, F_NEGATIVE) != 0 or size > get(w, F_WIDTH)

def text_width(w:mutbuf, indent:u64) -> u64:
    if get(w, F_NEGATIVE) != 0 or get(w, F_WIDTH) < indent + 11:
        return 11
    return get(w, F_WIDTH) - indent

def usage_part_at(w:mutbuf, index:u64) -> u64:
    return F_USAGE_PARTS + (word16(w, get(w, F_USAGE_ROW)) + index) * 4

def usage_part_size(w:mutbuf, index:u64) -> u64:
    return literal_size(w, word16(w, usage_part_at(w, index)))

def part(o:mutbuf, w:mutbuf, index:u64) -> u64:
    at = usage_part_at(w, index)
    plain = word16(w, at)
    field = byte(w, at + 2)
    optional = byte(w, at + 3)
    if get(w, F_COLOR) == 0:
        return literal(o, w, plain)
    if field == 15 or field == 16:
        style(o, w, L_GREEN)
        literal(o, w, plain)
        return style(o, w, L_RESET)
    if optional != 0:
        point(o, w, 91)
    style(o, w, choose(field == 0, L_GREEN, L_CYAN))
    literal(o, w, primary_literal(field))
    if field >= 2:
        point(o, w, 32)
        style(o, w, L_YELLOW)
        literal(o, w, metavar_literal(field))
    style(o, w, L_RESET)
    if optional != 0:
        point(o, w, 93)
    return 0

def colored_program(o:mutbuf, w:mutbuf) -> u64:
    style(o, w, L_BOLD_MAGENTA)
    literal(o, w, word16(w, get(w, F_USAGE_ROW) + 4))
    return style(o, w, L_RESET)

def group_line_count(w:mutbuf, start:u64, count:u64, indent:u64) -> u64:
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

def usage_group(o:mutbuf, w:mutbuf, start:u64, count:u64, indent:u64, existing:u64) -> u64:
    words = existing
    width = get(w, F_LINE)
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
    put(w, F_LINE, width)
    return 0

def usage(o:mutbuf, w:mutbuf) -> u64:
    row = get(w, F_USAGE_ROW)
    count = byte(w, row + 2)
    optionals = byte(w, row + 3)
    program_size = literal_size(w, word16(w, row + 4))
    whole = program_size
    index = 0
    while index < count:
        whole = whole + 1 + usage_part_size(w, index)
        index = index + 1
    style(o, w, L_BOLD_BLUE)
    literal(o, w, L_USAGE)
    style(o, w, L_RESET)
    colored_program(o, w)
    if beyond_width(w, whole + 7) == False:
        index = 0
        while index < count:
            point(o, w, 32)
            part(o, w, index)
            index = index + 1
        return 0
    if get(w, F_NEGATIVE) == 0 and (7 + program_size) * 4 <= get(w, F_WIDTH) * 3:
        indent = 8 + program_size
        put(w, F_LINE, 7 + program_size)
        usage_group(o, w, 0, optionals, indent, 1)
        if count > optionals:
            point(o, w, 10)
            spaces(o, w, indent)
            put(w, F_LINE, indent)
            usage_group(o, w, optionals, count - optionals, indent, 0)
        return 0
    point(o, w, 10)
    spaces(o, w, 7)
    put(w, F_LINE, 7)
    lines = group_line_count(w, 0, count, 7)
    if lines > 1 and count > optionals:
        usage_group(o, w, 0, optionals, 7, 0)
        point(o, w, 10)
        spaces(o, w, 7)
        put(w, F_LINE, 7)
        return usage_group(o, w, optionals, count - optionals, 7, 0)
    return usage_group(o, w, 0, count, 7, 0)

def text_point(s:readbuf, w:mutbuf, kind:u64, begin:u64, index:u64) -> u64:
    if kind == 0:
        return byte(w, begin + index)
    return read32(s, begin + index * 4)

def help_letter(point_value:u64) -> bool:
    return (point_value >= 65 and point_value <= 90) or (point_value >= 97 and point_value <= 122)

def wrap_text(s:readbuf, o:mutbuf, w:mutbuf, kind:u64, begin:u64, size:u64, width:u64, indent:u64) -> u64:
    index = 0
    used = 0
    while index < size:
        separated = False
        while index < size and (text_point(s, w, kind, begin, index) == 32 or (text_point(s, w, kind, begin, index) >= 9 and text_point(s, w, kind, begin, index) <= 13)):
            separated = True
            index = index + 1
        if index == size:
            return 0
        end = index
        stopped = False
        while end < size and stopped == False and text_point(s, w, kind, begin, end) != 32 and (text_point(s, w, kind, begin, end) < 9 or text_point(s, w, kind, begin, end) > 13):
            # The fixed English help vocabulary contains compound words.
            # Match textwrap's ordinary two-letter / hyphen / two-letter
            # boundary without inserting a space between the two chunks.
            if text_point(s, w, kind, begin, end) == 45 and end >= index + 2 and end + 2 < size:
                if help_letter(text_point(s, w, kind, begin, end - 2)) and help_letter(text_point(s, w, kind, begin, end - 1)) and help_letter(text_point(s, w, kind, begin, end + 1)) and help_letter(text_point(s, w, kind, begin, end + 2)):
                    stopped = True
            end = end + 1
        word_size = end - index
        gap = choose(used != 0 and separated, 1, 0)
        if used != 0 and used + gap + word_size > width:
            point(o, w, 10)
            spaces(o, w, indent)
            used = 0
            gap = 0
        if gap != 0:
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

def help_header(o:mutbuf, w:mutbuf, field:u64, plain:u64) -> u64:
    if get(w, F_COLOR) == 0:
        return literal(o, w, plain)
    if field == 15 or field == 16:
        style(o, w, L_BOLD_GREEN)
        literal(o, w, plain)
        return style(o, w, L_RESET)
    if field == 0:
        style(o, w, L_BOLD_GREEN)
        literal(o, w, L_SHORT_HELP)
        style(o, w, L_RESET)
        literal(o, w, L_COMMA_SPACE)
        style(o, w, L_BOLD_CYAN)
        literal(o, w, L_LONG_HELP)
        return style(o, w, L_RESET)
    style(o, w, L_BOLD_CYAN)
    literal(o, w, primary_literal(field))
    style(o, w, L_RESET)
    if field == 3:
        literal(o, w, L_COMMA_SPACE)
        style(o, w, L_BOLD_GREEN)
        literal(o, w, L_SHORT_OUTPUT)
        style(o, w, L_RESET)
    if field >= 2:
        point(o, w, 32)
        style(o, w, L_BOLD_YELLOW)
        literal(o, w, metavar_literal(field))
        style(o, w, L_RESET)
    return 0

def help_row(s:readbuf, o:mutbuf, w:mutbuf, index:u64) -> u64:
    row = get(w, F_HELP_ROW)
    at = F_HELP_LABELS + (word16(w, row) + index) * 8
    label = word16(w, at)
    field = byte(w, at + 2)
    help_text = word16(w, at + 4)
    spaces(o, w, 2)
    help_header(o, w, field, label)
    if help_text == 0:
        point(o, w, 10)
        return 0
    position = get(w, F_HELP_POSITION)
    label_size = literal_size(w, label)
    if position >= 4 and label_size <= position - 4:
        spaces(o, w, position - 2 - label_size)
    else:
        point(o, w, 10)
        spaces(o, w, position)
    wrap_text(s, o, w, 0, literal_at(w, help_text), literal_size(w, help_text), text_width(w, position), position)
    point(o, w, 10)
    return 0

def heading(o:mutbuf, w:mutbuf, text:u64) -> u64:
    style(o, w, L_BOLD_BLUE)
    literal(o, w, text)
    style(o, w, L_RESET)
    point(o, w, 10)
    return 0

def help_sections(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    row = get(w, F_HELP_ROW)
    count = byte(w, row + 2)
    positionals = byte(w, row + 3)
    maximum = 0
    index = 0
    while index < count:
        at = F_HELP_LABELS + (word16(w, row) + index) * 8
        size = literal_size(w, word16(w, at)) + 2
        if size > maximum:
            maximum = size
        index = index + 1
    cap = 4
    if get(w, F_COLUMNS) > 26:
        cap = choose(get(w, F_COLUMNS) - 22 < 24, get(w, F_COLUMNS) - 22, 24)
    position = choose(maximum + 2 < cap, maximum + 2, cap)
    put(w, F_HELP_POSITION, position)
    if get(w, 24) == 0:
        wrap_text(s, o, w, 0, literal_at(w, L_DESCRIPTION), literal_size(w, L_DESCRIPTION), text_width(w, 0), 0)
        point(o, w, 10)
        point(o, w, 10)
    if positionals != 0:
        heading(o, w, L_POSITIONALS)
        help_row(s, o, w, 0)
        point(o, w, 10)
    heading(o, w, L_OPTIONS)
    index = positionals
    while index < count:
        help_row(s, o, w, index)
        index = index + 1
    return 0

def varint(w:mutbuf) -> u64:
    cursor = get(w, F_VAR_CURSOR)
    value = 0
    shift = 0
    done = False
    while done == False:
        piece = byte(w, cursor)
        value = value | ((piece & 127) << shift)
        cursor = cursor + 1
        shift = shift + 7
        done = piece < 128
    put(w, F_VAR_CURSOR, cursor)
    return value

def expand_printable(w:mutbuf) -> u64:
    put(w, F_VAR_CURSOR, F_UNICODE_COMPRESSED)
    previous = 0
    count = 0
    while get(w, F_VAR_CURSOR) < F_UNICODE_COMPRESSED + UNICODE_COMPRESSED_SIZE:
        lower = previous + varint(w)
        upper = lower + varint(w)
        flags = varint(w)
        put(w, F_UNICODE_TABLE + count * 8, lower | (upper << 21) | (flags << 42))
        previous = upper + 1
        count = count + 1
    put(w, F_UNICODE_COUNT, count)
    return 0

def printable(w:mutbuf, character:u64) -> bool:
    low = 0
    high = get(w, F_UNICODE_COUNT)
    while low < high:
        middle = (low + high) >> 1
        value = get(w, F_UNICODE_TABLE + middle * 8)
        lower = value & 2097151
        upper = (value >> 21) & 2097151
        if character < lower:
            high = middle
        else:
            if character > upper:
                low = middle + 1
            else:
                mask = choose(get(w, 128) == 312, 1, 2)
                return ((value >> 42) & mask) != 0
    return False

def hex_digits(o:mutbuf, w:mutbuf, value:u64, count:u64) -> u64:
    index = count
    while index > 0:
        index = index - 1
        digit = (value >> (index * 4)) & 15
        point(o, w, choose(digit < 10, 48 + digit, 87 + digit))
    return 0

def quoted(s:readbuf, o:mutbuf, w:mutbuf, begin:u64, size:u64) -> u64:
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
        else:
            if character == 9 or character == 10 or character == 13:
                point(o, w, 92)
                point(o, w, choose(character == 9, 116, choose(character == 10, 110, 114)))
            else:
                if printable(w, character):
                    point(o, w, character)
                else:
                    point(o, w, 92)
                    if character < 256:
                        point(o, w, 120)
                        hex_digits(o, w, character, 2)
                    else:
                        if character < 65536:
                            point(o, w, 117)
                            hex_digits(o, w, character, 4)
                        else:
                            point(o, w, 85)
                            hex_digits(o, w, character, 8)
        index = index + 1
    point(o, w, quote)
    return 0

def required_error(o:mutbuf, w:mutbuf) -> u64:
    literal(o, w, L_REQUIRED)
    mask = get(w, 72)
    wrote = False
    if (mask & 32768) != 0:
        literal(o, w, error_label(15))
        wrote = True
    field = 0
    while field < FIELD_COUNT:
        if field != 15 and (mask & (1 << field)) != 0:
            if wrote:
                literal(o, w, L_COMMA_SPACE)
            literal(o, w, error_label(field))
            wrote = True
        field = field + 1
    return 0

def error_message(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    literal(o, w, word16(w, get(w, F_USAGE_ROW) + 4))
    literal(o, w, L_ERROR)
    reason = get(w, 32)
    field = get(w, 40)
    if reason == 1:
        return required_error(o, w)
    if reason == 8:
        return literal(o, w, L_SELFHOST_REQUIRED)
    if reason == 9:
        return literal(o, w, L_SELFHOST_ONLY)
    if reason == 7:
        literal(o, w, L_UNRECOGNIZED)
        index = 0
        while index < get(w, 80):
            at = F_EXTRAS + index * 24
            if index != 0:
                point(o, w, 32)
            if get(w, at + 16) != 0:
                point(o, w, 45)
            raw_text(s, o, w, get(w, at), get(w, at + 8))
            index = index + 1
        return 0
    if reason == 3:
        literal(o, w, L_AMBIGUOUS)
        raw_text(s, o, w, get(w, 48), get(w, 56))
        literal(o, w, L_COULD_MATCH)
        token = 0
        wrote = False
        while token < TOKEN_COUNT:
            if (get(w, 64) & (1 << token)) != 0:
                if wrote:
                    literal(o, w, L_COMMA_SPACE)
                literal(o, w, token_text(token))
                wrote = True
            token = token + 1
        return 0
    literal(o, w, L_ARGUMENT)
    literal(o, w, error_label(field))
    literal(o, w, L_COLON_SPACE)
    if reason == 4:
        return literal(o, w, L_EXPECTED)
    if reason == 5:
        literal(o, w, L_IGNORED)
        return quoted(s, o, w, get(w, 48), get(w, 56))
    if reason == 2 or reason == 6:
        literal(o, w, L_INVALID)
        quoted(s, o, w, get(w, 48), get(w, 56))
        literal(o, w, L_CHOOSE)
        index = 0
        count = choice_count(field)
        while index < count:
            if index != 0:
                literal(o, w, L_COMMA_SPACE)
            if get(w, 128) == 31410:
                point(o, w, 39)
            literal(o, w, choice_literal(field, index))
            if get(w, 128) == 31410:
                point(o, w, 39)
            index = index + 1
        point(o, w, 41)
        return 0
    return 199

def driver_error(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 32 or read64(s, 8) != 4 or read64(s, 24) != 0:
        return 199
    size = read64(s, 16)
    if size != (length(s) - 32) >> 2 or length(s) != 32 + size * 4:
        return 199
    literal(o, w, L_DRIVER_PREFIX)
    index = 0
    while index < size:
        character = read32(s, 32 + index * 4)
        if character > 1114111:
            return 199
        if character == 34 or character == 92:
            point(o, w, 92)
            point(o, w, character)
        else:
            if character == 8 or character == 9 or character == 10 or character == 12 or character == 13:
                point(o, w, 92)
                escape = choose(character == 8, 98, choose(character == 9, 116, choose(character == 10, 110, choose(character == 12, 102, 114))))
                point(o, w, escape)
            else:
                if character < 32:
                    literal(o, w, L_U00)
                    hex_digits(o, w, character, 2)
                else:
                    point(o, w, character)
        index = index + 1
    literal(o, w, L_DRIVER_SUFFIX)
    if get(w, F_OVERFLOW) != 0:
        return 199
    return 0
'''

def _metadata():
    pool = [""]
    ids = {"": 0}
    def intern(text):
        if text not in ids:
            ids[text] = len(pool)
            pool.append(text)
        return ids[text]
    fixed = {
        "L_ZERO": "0", "L_ONE": "1", "L_DUMB": "dumb",
        "L_USAGE": "usage: ", "L_DESCRIPTION": "HIA Core Agent interface",
        "L_POSITIONALS": "positional arguments:", "L_OPTIONS": "options:",
        "L_SHORT_HELP": "-h", "L_LONG_HELP": "--help", "L_SHORT_OUTPUT": "-o",
        "L_COMMA_SPACE": ", ", "L_ERROR": ": error: ",
        "L_REQUIRED": "the following arguments are required: ",
        "L_UNRECOGNIZED": "unrecognized arguments: ",
        "L_AMBIGUOUS": "ambiguous option: ", "L_COULD_MATCH": " could match ",
        "L_ARGUMENT": "argument ", "L_COLON_SPACE": ": ",
        "L_EXPECTED": "expected one argument", "L_IGNORED": "ignored explicit argument ",
        "L_INVALID": "invalid choice: ", "L_CHOOSE": " (choose from ",
        "L_RESET": "\x1b[0m", "L_GREEN": "\x1b[32m", "L_CYAN": "\x1b[36m",
        "L_YELLOW": "\x1b[33m", "L_BOLD_BLUE": "\x1b[1;34m",
        "L_BOLD_MAGENTA": "\x1b[1;35m", "L_BOLD_CYAN": "\x1b[1;36m",
        "L_BOLD_GREEN": "\x1b[1;32m", "L_BOLD_YELLOW": "\x1b[1;33m",
        "L_U00": "\\u00",
        "L_SELFHOST_REQUIRED": "--backend selfhost requires --selfhost-manifest and --selfhost-manifest-sha256",
        "L_SELFHOST_ONLY": "selfhost compiler options require --backend selfhost",
        "L_DRIVER_PREFIX": '{\n  "diagnostics": [\n    {\n      "code": "E_DRIVER",\n      "message": "',
        "L_DRIVER_SUFFIX": '",\n      "phase": "driver"\n    }\n  ],\n  "ok": false,\n  "status": "error"\n}',
    }
    symbols = {name: intern(text) for name, text in fixed.items()}
    option_strings = {field: [text for text, number in grammar.TOKENS if number == field]
                      for field in range(len(grammar.FIELDS)) if field not in (15, 16)}
    choice_values = {2: grammar.SCHEMAS, 4: ("native", "selfhost"), 5: ("object",),
                     6: ("x86_64-unknown-linux-gnu",), 16: grammar.ACTIONS}
    def metavar(field):
        if field in choice_values:
            return "{" + ",".join(choice_values[field]) + "}"
        return grammar.FIELDS[field] if field in (15, 16) else grammar.FIELDS[field].upper()
    usage_rows = bytearray()
    usage_parts = bytearray()
    help_rows = bytearray()
    help_labels = bytearray()
    for profile in (312, 314):
        for scope in range(16):
            options = grammar.allowed_fields(scope)
            required = set(grammar.required_fields(scope))
            parts = []
            for field in options:
                text = option_strings[field][0]
                if field >= 2:
                    text += " " + metavar(field)
                optional = field not in required
                if optional:
                    text = "[" + text + "]"
                components = text.split(" ") if profile == 312 and not optional else [text]
                parts += [(intern(part), field, int(optional)) for part in components]
            optional_count = len(parts)
            if scope == 0:
                text = metavar(16) + " ..."
                components = text.split(" ") if profile == 312 else [text]
                parts += [(intern(part), 16, 0) for part in components]
            elif scope > 2:
                parts.append((intern("input"), 15, 0))
            program = "hia" + ((" " + grammar.ACTIONS[scope - 1]) if scope else "")
            usage_rows += struct.pack("<HBBHH", len(usage_parts) // 4, len(parts), optional_count, intern(program), 0)
            for text, field, optional in parts:
                usage_parts += struct.pack("<HBB", text, field, optional)
            fields = ([16] if scope == 0 else [15] if scope > 2 else []) + list(options)
            help_rows += struct.pack("<HBBI", len(help_labels) // 8, len(fields),
                                     int(scope == 0 or scope > 2), 0)
            for field in fields:
                help_text = ""
                if field == 0:
                    help_text = "show this help message and exit"
                elif field == 1:
                    help_text = "show program's version number and exit"
                elif field == 15:
                    help_text = "Explicit HIA assembly or standalone Core JSON"
                elif field == 17:
                    help_text = "Operator-selected native compiler manifest"
                elif field == 18:
                    help_text = "Exact operator pin for that manifest"
                if field == 15 or field == 16:
                    label = metavar(field)
                elif field < 2:
                    label = ", ".join(option_strings[field])
                elif profile == 312:
                    label = ", ".join(text + " " + metavar(field) for text in option_strings[field])
                else:
                    label = ", ".join(option_strings[field]) + " " + metavar(field)
                help_labels += struct.pack("<HBBHH", intern(label), field, 0, intern(help_text), 0)
    lookup = []
    lookup.append(grammar._lookup("primary_literal", "field",
                                  ((field, intern(strings[0])) for field, strings in option_strings.items())))
    lookup.append(grammar._lookup("metavar_literal", "field",
                                  ((field, intern(metavar(field))) for field in range(2, len(grammar.FIELDS)))))
    lookup.append(grammar._lookup("error_label", "field",
                                  ((field, intern(grammar.FIELDS[field] if field in (15, 16)
                                                  else "/".join(option_strings[field]))) for field in range(len(grammar.FIELDS)))))
    lookup.append(grammar._lookup("token_text", "token",
                                  ((index, intern(text)) for index, (text, _) in enumerate(grammar.TOKENS))))
    lookup.append(grammar._lookup("choice_count", "field",
                                  ((field, len(values)) for field, values in choice_values.items())))
    lines = ["def choice_literal(field:u64, index:u64) -> u64:"]
    for field, values in choice_values.items():
        lines.append(f"    if field == {field}:")
        for index, value in enumerate(values):
            lines += [f"        if index == {index}:", f"            return {intern(value)}"]
        lines.append("        return 0")
    lookup.append("\n".join(lines + ["    return 0", ""]))
    table = bytearray()
    data = bytearray()
    for text in pool:
        raw = text.encode("ascii")
        table += struct.pack("<HH", SYMBOLS["F_LITERAL_DATA"] + len(data), len(raw))
        data += raw
    if len(table) > 4096 or len(data) > 20480 or len(usage_parts) > 1792 or len(help_labels) > 5888:
        raise ValueError("formatter metadata exceeded private regions")
    unicode = json.loads(Path(__file__).with_name("hia_cli_unicode_tables.json").read_text())
    events = {}
    for bit, profile in ((1, "312"), (2, "314")):
        for lo, hi in unicode["profiles"][profile]["printable_ranges"]:
            events[lo] = events.get(lo, 0) ^ bit
            events[hi + 1] = events.get(hi + 1, 0) ^ bit
    ranges = []
    previous = 0
    flags = 0
    for at in sorted(events):
        if flags and at > previous:
            if ranges and ranges[-1][1] + 1 == previous and ranges[-1][2] == flags:
                ranges[-1][1] = at - 1
            else:
                ranges.append([previous, at - 1, flags])
        flags ^= events[at]
        previous = at
    compressed = bytearray()
    def varint(value):
        while value >= 128:
            compressed.append((value & 127) | 128)
            value >>= 7
        compressed.append(value)
    previous = 0
    for lo, hi, flags in ranges:
        for value in (lo - previous, hi - lo, flags):
            varint(value)
        previous = hi + 1
    if len(compressed) > 8192 or len(ranges) * 8 > 65536:
        raise ValueError("formatter Unicode table exceeded private regions")
    symbols["UNICODE_COMPRESSED_SIZE"] = len(compressed)
    regions = ((SYMBOLS["F_LITERAL_TABLE"], table), (SYMBOLS["F_LITERAL_DATA"], data),
               (SYMBOLS["F_USAGE_ROWS"], usage_rows), (SYMBOLS["F_USAGE_PARTS"], usage_parts),
               (SYMBOLS["F_HELP_ROWS"], help_rows), (SYMBOLS["F_HELP_LABELS"], help_labels),
               (SYMBOLS["F_UNICODE_COMPRESSED"], compressed))
    writes = [(base + offset, int.from_bytes(raw[offset:offset + 8].ljust(8, b"\0"), "little"))
              for base, raw in regions for offset in range(0, len(raw), 8)]
    chunks = [writes[index:index + 128] for index in range(0, len(writes), 128)]
    initializers = ["\n".join(["def format_constants(w:mutbuf) -> u64:"] +
                             [f"    format_constants_{i}(w)" for i in range(len(chunks))] +
                             ["    return 0", ""])]
    for index, chunk in enumerate(chunks):
        initializers.append("\n".join([f"def format_constants_{index}(w:mutbuf) -> u64:"] +
                                     [f"    put(w, {at}, {value})" for at, value in chunk] +
                                     ["    return 0", ""]))
    return symbols, "\n".join(lookup + initializers), {
        "literal_count": len(pool), "literal_bytes": len(data),
        "unicode_regions": len(ranges), "unicode_compressed_bytes": len(compressed),
        "constant_writes": len(writes),
    }

def source_program():
    additions, metadata, _ = _metadata()
    values = dict(SYMBOLS)
    values.update(additions)
    common = {"read64", "read32", "get", "get32", "put", "put32"}
    helpers = "\n".join(ast.unparse(node) for node in ast.parse(grammar.SOURCE).body if node.name in common)
    class Replace(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(values[node.id]), node) if node.id in values else node
    tree = Replace().visit(ast.parse(SOURCE + "\n" + helpers + "\n" + metadata + "\n" + grammar._decimal()))
    return ast.unparse(ast.fix_missing_locations(tree)) + "\n"

def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({"name": names[node.name], "params": [builder.param(v) for v in builder.params],
                          "returns": [builder.returns], "effects": ["read", "write", "trap"],
                          "entry": "b0", "blocks": builder.blocks})
    return compact_authoring_cfg({"schema": "hepta.hia.program.v8", "module": "cli_format",
                                  "functions": functions})

if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / SOURCE_PATH
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)
