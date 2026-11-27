"""Author the bounded original rmcp/serde parameter diagnostics in HIA.

The Unicode 17 ranges were observed from Rust 1.96.1 string Debug over every
valid scalar. They are development input only: the native dispatch contains
the bounded HIA lookup table and never reads this table at execution time.
"""
from hashlib import sha256
import json
from pathlib import Path

RANGES = Path(__file__).with_name('hia_request_history_debug_ranges.json')
RANGES_SHA256 = 'f44fa079024a38570608fd2701793896a19040ca575b7c2df4f9584313142588'
MAX_DIAGNOSTIC_STRING_BYTES = 1 << 20
TEXT = {
    'history_param_prefix': 'failed to deserialize parameters: ',
    'history_param_type': 'invalid type: ',
    'history_param_value': 'invalid value: ',
    'history_param_integer': 'integer `',
    'history_param_float': 'floating point `',
    'history_param_boolean': 'boolean `',
    'history_param_string': 'string ',
    'history_param_sequence': 'sequence',
    'history_param_map': 'map',
    'history_param_unit': 'unit value',
    'history_param_tick': '`',
    'history_param_u16': ', expected u16',
    'history_param_text': ', expected a string',
    'history_param_unknown': 'unknown field `',
    'history_param_fields': '`, expected `after_id` or `limit`',
    'history_param_error': '{"code":-32602,"message":',
}
SOURCE = r'''
def history_finish_parameter_error(w:mutbuf, end:u64) -> u64:
    at = text_history_param_error(w, PURE_OUTPUT)
    at = quoted(w, at, PURE_INPUT, end - PURE_INPUT)
    at = text_close(w, at)
    bind(w, S_RESPONSE, PURE_OUTPUT, at - PURE_OUTPUT)
    put(w, 280, 3)
    return 1

def history_parameter_fallback(w:mutbuf) -> u64:
    end = text_invalid_params(w, PURE_OUTPUT)
    bind(w, S_RESPONSE, PURE_OUTPUT, end - PURE_OUTPUT)
    put(w, 280, 3)
    return 1

def history_unknown_parameter(w:mutbuf, row:u64) -> u64:
    size = get(w, row + 48)
    if size > 1048576:
        return history_parameter_fallback(w)
    at = text_history_param_prefix(w, PURE_INPUT)
    at = text_history_param_unknown(w, at)
    at = copy_state(w, ARENA + get(w, row + 40), at, size)
    at = text_history_param_fields(w, at)
    return history_finish_parameter_error(w, at)

def history_type_error(w:mutbuf, row:u64, expected:u64) -> u64:
    kind = get(w, row)
    if kind == 4 and get(w, row + 32) > 1048576:
        return history_parameter_fallback(w)
    is_float = False
    start = 0
    size = 0
    if kind == 3:
        start = get(w, 72) + get(w, row + 24)
        size = get(w, row + 32)
        index = 0
        while index < size:
            ch = byte(w, start + index)
            if ch == 46 or ch == 101 or ch == 69:
                is_float = True
            index = index + 1
    at = text_history_param_prefix(w, PURE_INPUT)
    if kind == 3 and is_float == False and expected == 1:
        at = text_history_param_value(w, at)
    else:
        at = text_history_param_type(w, at)
    if kind == 3:
        if is_float:
            at = text_history_param_float(w, at)
        else:
            at = text_history_param_integer(w, at)
        at = copy_state(w, start, at, size)
        at = text_history_param_tick(w, at)
    elif kind == 1 or kind == 2:
        at = text_history_param_boolean(w, at)
        if kind == 1:
            at = text_false(w, at)
        else:
            at = text_true(w, at)
        at = text_history_param_tick(w, at)
    elif kind == 4:
        at = text_history_param_string(w, at)
        at = history_debug_string(w, at, ARENA + get(w, row + 24), get(w, row + 32))
    elif kind == 5:
        at = text_history_param_sequence(w, at)
    elif kind == 6:
        at = text_history_param_map(w, at)
    else:
        at = text_history_param_unit(w, at)
    if expected == 1:
        at = text_history_param_u16(w, at)
    else:
        at = text_history_param_text(w, at)
    return history_finish_parameter_error(w, at)

def history_debug_string(w:mutbuf, at:u64, source:u64, size:u64) -> u64:
    store(w, at, 34)
    at = at + 1
    history_debug_init(w)
    index = 0
    while index < size:
        first = byte(w, source + index)
        count = 1
        point = first
        if first >= 192:
            count = choose(first < 224, 2, choose(first < 240, 3, 4))
            point = first & choose(count == 2, 31, choose(count == 3, 15, 7))
            next = 1
            while next < count:
                point = (point << 6) | (byte(w, source + index + next) & 63)
                next = next + 1
        if point == 0 or point == 9 or point == 10 or point == 13:
            store(w, at, 92)
            store(w, at + 1, choose(point == 0, 48, choose(point == 9, 116, choose(point == 10, 110, 114))))
            at = at + 2
        elif point == 34 or point == 92:
            store(w, at, 92)
            store(w, at + 1, point)
            at = at + 2
        elif history_debug_escape(w, point):
            store(w, at, 92)
            store(w, at + 1, 117)
            store(w, at + 2, 123)
            at = at + 3
            shift = 20
            while shift > 0 and ((point >> shift) & 15) == 0:
                shift = shift - 4
            emitting = True
            while emitting:
                store(w, at, hex_digit((point >> shift) & 15))
                at = at + 1
                if shift == 0:
                    emitting = False
                else:
                    shift = shift - 4
            store(w, at, 125)
            at = at + 1
        else:
            at = copy_state(w, source + index, at, count)
        index = index + count
    store(w, at, 34)
    return at + 1
'''


def source_program():
    raw = RANGES.read_bytes()
    if sha256(raw).hexdigest() != RANGES_SHA256:
        raise ValueError('original Rust diagnostic Unicode table identity changed')
    table = json.loads(raw)
    if (table['scalar_count'] != 1112064 or table['context_differences'] != 0
            or table['unicode_version'] != [17, 0, 0]):
        raise ValueError('original Rust diagnostic Unicode scope changed')
    ranges = table['ranges']
    if len(ranges) != 909 or any(not 0 <= a <= b <= 0x10ffff for a,b in ranges):
        raise ValueError('invalid diagnostic Unicode ranges')
    if any(left[1] >= right[0] for left,right in zip(ranges,ranges[1:])):
        raise ValueError('unordered diagnostic Unicode ranges')
    # Each independent seed frame retains at most 2048 scalar slots. Keep the
    # constant initialization in small functions without changing that budget.
    banks=[ranges[index:index+64] for index in range(0,len(ranges),64)]
    value = SOURCE + '\ndef history_debug_init(w:mutbuf) -> u64:\n'
    for bank in range(len(banks)):
        value += f'    history_debug_bank_{bank}(w)\n'
    value += '    return 0\n'
    for bank,rows in enumerate(banks):
        value += f'\ndef history_debug_bank_{bank}(w:mutbuf) -> u64:\n'
        for item,(low,high) in enumerate(rows):
            index=bank*64+item
            value += f'    put(w,SCRATCH+{index*8},{low | (high << 21)})\n'
        value += '    return 0\n'
    return value + '''
def history_debug_escape(w:mutbuf, point:u64) -> bool:
    low = 0
    high = 909
    while low < high:
        middle = (low+high)>>1
        row = get(w,SCRATCH+middle*8)
        if point < (row & 2097151):
            high = middle
        elif point <= row >> 21:
            return True
        else:
            low = middle+1
    return False
'''
