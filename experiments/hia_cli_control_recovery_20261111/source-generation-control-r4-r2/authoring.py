def cli(s: readbuf, o: mutbuf, w: mutbuf) -> u32:
    if length(w) < 65536:
        if length(w) >= 2080 + 8:
            put(w, 2048, 3768479636171539272)
            put(w, 2080, 1)
            put(w, 2072, 0)
        return 199
    if length(s) < 8 or length(o) < 128:
        return control_refuse(w)
    if read64(s, 0) == 3769605604797858632:
        return control_step(s, o, w)
    if get(w, 2048) == 3768479636171539272:
        return control_refuse(w)
    if read64(s, 0) != 3767070053674795848 or length(s) < 192:
        return control_refuse(w)
    if read64(s, 8) != 4:
        return control_refuse(w)
    argc = read64(s, 16)
    profile = read64(s, 24)
    if profile != 312 and profile != 314:
        return control_refuse(w)
    if argc > length(s) - 192 >> 4:
        return control_refuse(w)
    if length(w) < 65536 + argc * 80 + length(s):
        return control_refuse(w)
    if read64(s, 40) > 1 or read64(s, 48) > 1 or read64(s, 72) > 63:
        return control_refuse(w)
    if read64(s, 64) != 0 or read64(s, 80) != 0 or read64(s, 88) != 0:
        return control_refuse(w)
    cursor = 192 + argc * 16
    record = 96
    while record < 192 + argc * 16:
        begin = read64(s, record)
        size = read64(s, record + 8)
        if begin != cursor or size > length(s) - cursor >> 2:
            return control_refuse(w)
        end = begin + size * 4
        while cursor < end:
            if read32(s, cursor) > 1114111:
                return control_refuse(w)
            cursor = cursor + 4
        record = record + 16
    if cursor != length(s):
        return control_refuse(w)
    index = 0
    while index < 4096:
        store(w, index, 0)
        index = index + 1
    constants(w)
    put(w, 0, 3770433532758606664)
    put(w, 88, argc)
    put(w, 104, length(s))
    put(w, 128, profile)
    put(w, 120, 1)
    field = 0
    while field < 17:
        put(w, 256 + field * 32 + 24, field_literal(field))
        field = field + 1
    copy_at = 65536 + argc * 80
    index = 0
    while index < length(s):
        store(w, copy_at + index, byte(s, index))
        index = index + 1
    put(w, 152, copy_at)
    parse_root(s, w)
    if get(w, 8) == 0:
        control_seed(w, get(w, 16), field_truth(w, 3))
    index = 0
    while index < 128:
        store(o, index, byte(w, index))
        index = index + 1
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

def literal_equal(s: readbuf, w: mutbuf, begin: u64, size: u64, literal: u64) -> bool:
    at = 8192 + literal * 16
    if size != get(w, at + 8):
        return False
    index = 0
    while index < size:
        if read32(s, begin + index * 4) != byte(w, get(w, at) + index):
            return False
        index = index + 1
    return True

def literal_prefix(s: readbuf, w: mutbuf, begin: u64, size: u64, literal: u64) -> bool:
    at = 8192 + literal * 16
    if size > get(w, at + 8):
        return False
    index = 0
    while index < size:
        if read32(s, begin + index * 4) != byte(w, get(w, at) + index):
            return False
        index = index + 1
    return True

def token_find(s: readbuf, w: mutbuf, scope: u64, begin: u64, size: u64, prefix: bool) -> u64:
    allowed = token_mask(scope)
    matches = 0
    token = 0
    while token < 17:
        if allowed & 1 << token != 0:
            same = literal_equal(s, w, begin, size, token_literal(token))
            if prefix:
                same = literal_prefix(s, w, begin, size, token_literal(token))
            if same:
                matches = matches | 1 << token
        token = token + 1
    return matches

def negative_number(s: readbuf, w: mutbuf, begin: u64, size: u64) -> bool:
    if size < 2:
        return False
    end = size
    if read32(s, begin + (end - 1) * 4) == 10:
        end = end - 1
    index = 1
    while index < end:
        if decimal(read32(s, begin + index * 4), get(w, 128)) == 0:
            if read32(s, begin + index * 4) != 46:
                return False
            index = index + 1
            if index == end:
                return False
            while index < end:
                if decimal(read32(s, begin + index * 4), get(w, 128)) == 0:
                    return False
                index = index + 1
            return True
        index = index + 1
    return end > 1

def classify_one(s: readbuf, w: mutbuf, scope: u64, index: u64) -> u64:
    record = 32768 + index * 48
    begin = read64(s, 192 + index * 16)
    size = read64(s, 200 + index * 16)
    put(w, record, 1)
    put(w, record + 8, 0)
    put(w, record + 16, 0)
    put(w, record + 24, 0)
    put(w, record + 32, 0)
    if size == 0 or read32(s, begin) != 45:
        return 0
    if size == 1:
        return 0
    if size == 2 and read32(s, begin + 4) == 45:
        put(w, record, 3)
        return 0
    matches = token_find(s, w, scope, begin, size, False)
    if matches != 0:
        put(w, record, 2)
        put(w, record + 8, matches)
        return 0
    equal = 0
    scan = 0
    while scan < size:
        if read32(s, begin + scan * 4) == 61 and equal == 0:
            equal = scan
        scan = scan + 1
    prefix_size = choose(equal == 0, size, equal)
    if equal != 0:
        matches = token_find(s, w, scope, begin, prefix_size, False)
        if matches != 0:
            put(w, record, 2)
            put(w, record + 8, matches)
            put(w, record + 16, begin + (equal + 1) * 4)
            put(w, record + 24, size - equal - 1)
            put(w, record + 32, 1)
            return 0
    if read32(s, begin + 4) == 45:
        matches = token_find(s, w, scope, begin, prefix_size, True)
        if matches != 0 and equal != 0:
            put(w, record + 16, begin + (equal + 1) * 4)
            put(w, record + 24, size - equal - 1)
            put(w, record + 32, 1)
    else:
        matches = token_find(s, w, scope, begin, 2, False)
        if matches != 0:
            put(w, record + 16, begin + 8)
            put(w, record + 24, size - 2)
    if matches != 0:
        put(w, record, 2)
        put(w, record + 8, matches)
        return 0
    if negative_number(s, w, begin, size):
        return 0
    scan = 0
    while scan < size:
        if read32(s, begin + scan * 4) == 32:
            return 0
        scan = scan + 1
    put(w, record, 2)
    return 0

def classify_scope(s: readbuf, w: mutbuf, scope: u64, start: u64) -> u64:
    after_dash = False
    index = start
    while index < get(w, 88):
        if after_dash:
            put(w, 32768 + index * 48, 1)
        else:
            classify_one(s, w, scope, index)
            if get(w, 32768 + index * 48) == 3:
                after_dash = True
        index = index + 1
    return 0

def set_field(w: mutbuf, field: u64, kind: u64, begin: u64, size: u64, seen: bool) -> u64:
    at = 256 + field * 32
    put(w, at, kind)
    put(w, at + 8, begin)
    put(w, at + 16, size)
    put(w, 96, get(w, 96) | 1 << field)
    if seen:
        put(w, 144, get(w, 144) | 1 << field)
    return 0

def field_truth(w: mutbuf, field: u64) -> u64:
    at = 256 + field * 32
    return choose(get(w, at) > 1 and get(w, at + 16) > 0, 1, 0)

def add_extra(w: mutbuf, begin: u64, size: u64, hyphen: u64) -> u64:
    at = 32768 + get(w, 88) * 48 + get(w, 80) * 24
    put(w, at, begin)
    put(w, at + 8, size)
    put(w, at + 16, hyphen)
    put(w, 80, get(w, 80) + 1)
    return 0

def refusal(w: mutbuf, reason: u64, option: u64, begin: u64, size: u64, mask: u64) -> u64:
    put(w, 8, 3)
    put(w, 32, reason)
    put(w, 40, option)
    put(w, 48, begin)
    put(w, 56, size)
    put(w, 64, mask)
    put(w, 112, 2)
    put(w, 120, 2)
    return 0

def consume_option(s: readbuf, w: mutbuf, scope: u64, index: u64) -> u64:
    record = 32768 + index * 48
    matches = get(w, record + 8)
    begin = read64(s, 192 + index * 16)
    size = read64(s, 200 + index * 16)
    if matches == 0:
        add_extra(w, begin, size, 0)
        return index + 1
    if matches & matches - 1 != 0:
        refusal(w, 3, 0, begin, size, matches)
        return get(w, 88)
    token = 0
    while matches & 1 << token == 0:
        token = token + 1
    explicit = get(w, record + 16)
    explicit_size = get(w, record + 24)
    separator = get(w, record + 32)
    stop = index + 1
    queued_help = False
    queued_version = False
    final_field = 0
    value_begin = 0
    value_size = 0
    done = False
    while done == False:
        field = token_field(token)
        if field < 2:
            if explicit != 0:
                if token == 0 and explicit_size > 0:
                    if separator != 0 or read32(s, explicit) == 45:
                        refusal(w, 5, field, explicit, explicit_size, 0)
                        return get(w, 88)
                    queued_help = True
                    char = read32(s, explicit)
                    explicit = explicit + 4
                    explicit_size = explicit_size - 1
                    if char == 104:
                        token = 0
                    elif char == 111 and token_mask(scope) & 32 != 0:
                        token = 5
                    else:
                        add_extra(w, explicit - 4, explicit_size + 1, 1)
                        done = True
                    if explicit_size == 0:
                        explicit = 0
                        separator = 0
                    elif read32(s, explicit) == 61:
                        explicit = explicit + 4
                        explicit_size = explicit_size - 1
                        separator = 1
                    else:
                        separator = 0
                else:
                    refusal(w, 5, field, explicit, explicit_size, 0)
                    return get(w, 88)
            else:
                if field == 0:
                    queued_help = True
                else:
                    queued_version = True
                done = True
        else:
            if explicit == 0:
                if stop >= get(w, 88) or get(w, 32768 + stop * 48) != 1:
                    refusal(w, 4, field, 0, 0, 0)
                    return get(w, 88)
                explicit = read64(s, 192 + stop * 16)
                explicit_size = read64(s, 200 + stop * 16)
                stop = stop + 1
            final_field = field
            value_begin = explicit
            value_size = explicit_size
            done = True
    if queued_help:
        put(w, 8, 1)
        return get(w, 88)
    if queued_version:
        put(w, 8, 2)
        return get(w, 88)
    if choice_ok(s, w, final_field, value_begin, value_size) == 0:
        refusal(w, 6, final_field, value_begin, value_size, 0)
        return get(w, 88)
    set_field(w, final_field, 2, value_begin, value_size, True)
    return stop

def parse_child(s: readbuf, w: mutbuf, scope: u64, start: u64) -> u64:
    put(w, 24, scope)
    namespace_defaults(w, scope)
    classify_scope(s, w, scope, start)
    index = start
    input_seen = False
    while index < get(w, 88):
        kind = get(w, 32768 + index * 48)
        if kind == 2:
            index = consume_option(s, w, scope, index)
            if get(w, 8) != 0:
                return 0
        else:
            selected = index
            if kind == 3:
                selected = selected + 1
            if scope > 2 and input_seen == False and (selected < get(w, 88)) and (get(w, 32768 + selected * 48) == 1):
                set_field(w, 15, 2, read64(s, 192 + selected * 16), read64(s, 200 + selected * 16), True)
                input_seen = True
                index = selected + 1
                if index < get(w, 88) and get(w, 32768 + index * 48) == 3:
                    index = index + 1
            else:
                add_extra(w, read64(s, 192 + index * 16), read64(s, 200 + index * 16), 0)
                index = index + 1
    required = required_mask(scope)
    missing = required ^ required & get(w, 144)
    if missing != 0:
        put(w, 72, missing)
        refusal(w, 1, 0, 0, 0, 0)
    return 0

def parse_root(s: readbuf, w: mutbuf) -> u64:
    classify_scope(s, w, 0, 0)
    index = 0
    while index < get(w, 88):
        kind = get(w, 32768 + index * 48)
        if kind == 2:
            index = consume_option(s, w, 0, index)
            if get(w, 8) != 0:
                return 0
        else:
            selected = index
            if kind == 3:
                selected = selected + 1
            if selected < get(w, 88) and get(w, 32768 + selected * 48) == 1:
                begin = read64(s, 192 + selected * 16)
                size = read64(s, 200 + selected * 16)
                action = action_value(s, w, begin, size)
                if action == 0:
                    refusal(w, 2, 16, begin, size, 0)
                    return 0
                put(w, 16, action)
                set_field(w, 16, 2, begin, size, True)
                parse_child(s, w, action, selected + 1)
                if get(w, 8) == 0 and get(w, 80) != 0:
                    put(w, 24, 0)
                    refusal(w, 7, 0, 0, 0, 0)
                return 0
            add_extra(w, read64(s, 192 + index * 16), read64(s, 200 + index * 16), 0)
            index = index + 1
    put(w, 72, 65536)
    refusal(w, 1, 0, 0, 0, 0)
    return 0

def token_literal(token: u64) -> u64:
    if token == 0:
        return 0
    if token == 1:
        return 1
    if token == 2:
        return 2
    if token == 3:
        return 3
    if token == 4:
        return 4
    if token == 5:
        return 5
    if token == 6:
        return 6
    if token == 7:
        return 7
    if token == 8:
        return 8
    if token == 9:
        return 9
    if token == 10:
        return 10
    if token == 11:
        return 11
    if token == 12:
        return 12
    if token == 13:
        return 13
    if token == 14:
        return 14
    if token == 15:
        return 15
    if token == 16:
        return 16
    return 0

def token_field(token: u64) -> u64:
    if token == 0:
        return 0
    if token == 1:
        return 0
    if token == 2:
        return 1
    if token == 3:
        return 2
    if token == 4:
        return 3
    if token == 5:
        return 3
    if token == 6:
        return 4
    if token == 7:
        return 5
    if token == 8:
        return 6
    if token == 9:
        return 7
    if token == 10:
        return 8
    if token == 11:
        return 9
    if token == 12:
        return 10
    if token == 13:
        return 11
    if token == 14:
        return 12
    if token == 15:
        return 13
    if token == 16:
        return 14
    return 0

def field_literal(field: u64) -> u64:
    if field == 0:
        return 32
    if field == 1:
        return 33
    if field == 2:
        return 34
    if field == 3:
        return 35
    if field == 4:
        return 36
    if field == 5:
        return 37
    if field == 6:
        return 38
    if field == 7:
        return 39
    if field == 8:
        return 40
    if field == 9:
        return 41
    if field == 10:
        return 42
    if field == 11:
        return 43
    if field == 12:
        return 44
    if field == 13:
        return 45
    if field == 14:
        return 46
    if field == 15:
        return 47
    if field == 16:
        return 48
    return 0

def token_mask(scope: u64) -> u64:
    if scope == 0:
        return 7
    if scope == 1:
        return 3
    if scope == 2:
        return 11
    if scope == 3:
        return 51
    if scope == 4:
        return 51
    if scope == 5:
        return 3
    if scope == 6:
        return 3
    if scope == 7:
        return 3
    if scope == 8:
        return 51
    if scope == 9:
        return 499
    if scope == 10:
        return 563
    if scope == 11:
        return 515
    if scope == 12:
        return 15411
    if scope == 13:
        return 98355
    if scope == 14:
        return 16435
    if scope == 15:
        return 98355
    return 0

def required_mask(scope: u64) -> u64:
    if scope == 1:
        return 0
    if scope == 2:
        return 0
    if scope == 3:
        return 32768
    if scope == 4:
        return 32768
    if scope == 5:
        return 32768
    if scope == 6:
        return 32768
    if scope == 7:
        return 32768
    if scope == 8:
        return 32768
    if scope == 9:
        return 32776
    if scope == 10:
        return 32896
    if scope == 11:
        return 32896
    if scope == 12:
        return 36608
    if scope == 13:
        return 57344
    if scope == 14:
        return 36864
    if scope == 15:
        return 57344
    return 0

def action_value(s: readbuf, w: mutbuf, begin: u64, size: u64) -> u64:
    if literal_equal(s, w, begin, size, 17):
        return 1
    if literal_equal(s, w, begin, size, 18):
        return 2
    if literal_equal(s, w, begin, size, 19):
        return 3
    if literal_equal(s, w, begin, size, 20):
        return 4
    if literal_equal(s, w, begin, size, 21):
        return 5
    if literal_equal(s, w, begin, size, 22):
        return 6
    if literal_equal(s, w, begin, size, 23):
        return 7
    if literal_equal(s, w, begin, size, 24):
        return 8
    if literal_equal(s, w, begin, size, 25):
        return 9
    if literal_equal(s, w, begin, size, 26):
        return 10
    if literal_equal(s, w, begin, size, 27):
        return 11
    if literal_equal(s, w, begin, size, 28):
        return 12
    if literal_equal(s, w, begin, size, 29):
        return 13
    if literal_equal(s, w, begin, size, 30):
        return 14
    if literal_equal(s, w, begin, size, 31):
        return 15
    return 0

def choice_ok(s: readbuf, w: mutbuf, field: u64, begin: u64, size: u64) -> u64:
    if field == 2:
        if literal_equal(s, w, begin, size, 49):
            return 1
        if literal_equal(s, w, begin, size, 50):
            return 1
        if literal_equal(s, w, begin, size, 51):
            return 1
        if literal_equal(s, w, begin, size, 52):
            return 1
        if literal_equal(s, w, begin, size, 53):
            return 1
        if literal_equal(s, w, begin, size, 54):
            return 1
        if literal_equal(s, w, begin, size, 55):
            return 1
        if literal_equal(s, w, begin, size, 56):
            return 1
        return 0
    if field == 4:
        if literal_equal(s, w, begin, size, 57):
            return 1
        return 0
    if field == 5:
        if literal_equal(s, w, begin, size, 58):
            return 1
        return 0
    if field == 6:
        if literal_equal(s, w, begin, size, 59):
            return 1
        return 0
    return 1

def namespace_defaults(w: mutbuf, scope: u64) -> u64:
    if scope == 1:
        return 0
    if scope == 2:
        set_field(w, 2, 3, get(w, 8192 + 56 * 16), 20, False)
        return 0
    if scope == 3:
        set_field(w, 3, 1, 0, 0, False)
        return 0
    if scope == 4:
        set_field(w, 3, 1, 0, 0, False)
        return 0
    if scope == 5:
        return 0
    if scope == 6:
        return 0
    if scope == 7:
        return 0
    if scope == 8:
        set_field(w, 3, 1, 0, 0, False)
        return 0
    if scope == 9:
        set_field(w, 3, 1, 0, 0, False)
        set_field(w, 4, 3, get(w, 8192 + 57 * 16), 6, False)
        set_field(w, 5, 3, get(w, 8192 + 58 * 16), 6, False)
        set_field(w, 6, 3, get(w, 8192 + 59 * 16), 24, False)
        return 0
    if scope == 10:
        set_field(w, 3, 1, 0, 0, False)
        set_field(w, 7, 1, 0, 0, False)
        return 0
    if scope == 11:
        set_field(w, 7, 1, 0, 0, False)
        return 0
    if scope == 12:
        set_field(w, 3, 1, 0, 0, False)
        set_field(w, 8, 1, 0, 0, False)
        set_field(w, 9, 1, 0, 0, False)
        set_field(w, 10, 1, 0, 0, False)
        set_field(w, 11, 1, 0, 0, False)
        return 0
    if scope == 13:
        set_field(w, 3, 1, 0, 0, False)
        set_field(w, 13, 1, 0, 0, False)
        set_field(w, 14, 1, 0, 0, False)
        return 0
    if scope == 14:
        set_field(w, 3, 1, 0, 0, False)
        set_field(w, 12, 1, 0, 0, False)
        return 0
    if scope == 15:
        set_field(w, 3, 1, 0, 0, False)
        set_field(w, 13, 1, 0, 0, False)
        set_field(w, 14, 1, 0, 0, False)
        return 0
    return 0

def constants(w: mutbuf) -> u64:
    constants_0(w)
    constants_1(w)
    return 0

def constants_0(w: mutbuf) -> u64:
    put(w, 8192, 16384)
    put(w, 8200, 2)
    put(w, 16384, 26669)
    put(w, 8208, 16392)
    put(w, 8216, 6)
    put(w, 16392, 123610860105005)
    put(w, 8224, 16400)
    put(w, 8232, 9)
    put(w, 16400, 8028074745930329389)
    put(w, 16408, 110)
    put(w, 8240, 16416)
    put(w, 8248, 8)
    put(w, 16416, 7020378893159968045)
    put(w, 8256, 16424)
    put(w, 8264, 8)
    put(w, 16424, 8391737126163524909)
    put(w, 8272, 16432)
    put(w, 8280, 2)
    put(w, 16432, 28461)
    put(w, 8288, 16440)
    put(w, 8296, 9)
    put(w, 16440, 7954882391399607597)
    put(w, 16448, 100)
    put(w, 8304, 16456)
    put(w, 8312, 6)
    put(w, 16456, 110425377811757)
    put(w, 8320, 16464)
    put(w, 8328, 8)
    put(w, 16464, 8387223622006353197)
    put(w, 8336, 16472)
    put(w, 8344, 9)
    put(w, 16472, 8315181416903224621)
    put(w, 16480, 116)
    put(w, 8352, 16488)
    put(w, 8360, 10)
    put(w, 16488, 7598807797348052269)
    put(w, 16496, 28271)
    put(w, 8368, 16504)
    put(w, 8376, 7)
    put(w, 16504, 30227152718933293)
    put(w, 8384, 16512)
    put(w, 8392, 7)
    put(w, 16512, 28558080999828781)
    put(w, 8400, 16520)
    put(w, 8408, 8)
    put(w, 16520, 8314889994848578861)
    put(w, 8416, 16528)
    put(w, 8424, 12)
    put(w, 16528, 8386658447326915885)
    put(w, 16536, 1936617321)
    put(w, 8432, 16544)
    put(w, 8440, 7)
    put(w, 16544, 34184252269604141)
    put(w, 8448, 16552)
    put(w, 8456, 10)
    put(w, 16552, 7957702707512487213)
    put(w, 16560, 25971)
    put(w, 8464, 16568)
    put(w, 8472, 12)
    put(w, 16568, 7596562542729650531)
    put(w, 16576, 1936025972)
    put(w, 8480, 16584)
    put(w, 8488, 7)
    put(w, 16584, 29114433883365731)
    put(w, 8496, 16592)
    put(w, 8504, 15)
    put(w, 16592, 7002381030475722089)
    put(w, 16600, 34177642179949427)
    put(w, 8512, 16608)
    put(w, 8520, 15)
    put(w, 16608, 7002378775433209202)
    put(w, 16616, 34177642179949427)
    put(w, 8528, 16624)
    put(w, 8536, 14)
    put(w, 16624, 8313976326354987107)
    put(w, 16632, 133506414765427)
    put(w, 8544, 16640)
    put(w, 8552, 6)
    put(w, 16640, 133480762729846)
    put(w, 8560, 16648)
    put(w, 8568, 7)
    put(w, 16648, 32760384627895913)
    put(w, 8576, 16656)
    put(w, 8584, 9)
    put(w, 16656, 8820700510885670766)
    put(w, 16664, 101)
    put(w, 8592, 16672)
    put(w, 8600, 5)
    put(w, 16672, 431315580258)
    put(w, 8608, 16680)
    put(w, 8616, 5)
    put(w, 16680, 448345170288)
    put(w, 8624, 16688)
    put(w, 8632, 6)
    put(w, 16688, 127970185342313)
    put(w, 8640, 16696)
    put(w, 8648, 10)
    put(w, 16696, 7310874010146399333)
    put(w, 16704, 31090)
    put(w, 8656, 16712)
    put(w, 8664, 10)
    put(w, 16712, 8102082577494008933)
    put(w, 16720, 31084)
    put(w, 8672, 16728)
    put(w, 8680, 16)
    put(w, 16728, 8386091928506688613)
    put(w, 16736, 8751168581018675299)
    put(w, 8688, 16744)
    put(w, 8696, 16)
    put(w, 16744, 8386091928506688613)
    put(w, 16752, 8749491804043044963)
    put(w, 8704, 16760)
    put(w, 8712, 4)
    put(w, 16760, 1886152040)
    put(w, 8720, 16768)
    put(w, 8728, 7)
    put(w, 16768, 31084746137298294)
    put(w, 8736, 16776)
    put(w, 8744, 6)
    put(w, 16776, 107122480669555)
    put(w, 8752, 16784)
    put(w, 8760, 6)
    put(w, 16784, 128047746676079)
    put(w, 8768, 16792)
    put(w, 8776, 7)
    put(w, 16792, 28268879543492962)
    put(w, 8784, 16800)
    put(w, 8792, 4)
    return 0

def constants_1(w: mutbuf) -> u64:
    put(w, 16800, 1684957547)
    put(w, 8800, 16808)
    put(w, 8808, 6)
    put(w, 16808, 127978876068212)
    put(w, 8816, 16816)
    put(w, 8824, 7)
    put(w, 16816, 32777976897693042)
    put(w, 8832, 16824)
    put(w, 8840, 8)
    put(w, 16824, 7957695015192261990)
    put(w, 8848, 16832)
    put(w, 8856, 5)
    put(w, 16832, 461229747298)
    put(w, 8864, 16840)
    put(w, 8872, 5)
    put(w, 16840, 435761734006)
    put(w, 8880, 16848)
    put(w, 8888, 6)
    put(w, 16848, 126875152509286)
    put(w, 8896, 16856)
    put(w, 8904, 10)
    put(w, 16856, 8028075781016806771)
    put(w, 16864, 29550)
    put(w, 8912, 16872)
    put(w, 8920, 5)
    put(w, 16872, 521610294641)
    put(w, 8928, 16880)
    put(w, 8936, 8)
    put(w, 16880, 7310308045059482994)
    put(w, 8944, 16888)
    put(w, 8952, 5)
    put(w, 16888, 500186508905)
    put(w, 8960, 16896)
    put(w, 8968, 10)
    put(w, 16896, 7598807741144066408)
    put(w, 16904, 28271)
    put(w, 8976, 16912)
    put(w, 8984, 20)
    put(w, 16912, 7595371767660569960)
    put(w, 16920, 7021788497383009889)
    put(w, 16928, 829828717)
    put(w, 8992, 16936)
    put(w, 9000, 20)
    put(w, 16936, 7595371767660569960)
    put(w, 16944, 7021788497383009889)
    put(w, 16952, 846605933)
    put(w, 9008, 16960)
    put(w, 9016, 20)
    put(w, 16960, 7595371767660569960)
    put(w, 16968, 7021788497383009889)
    put(w, 16976, 863383149)
    put(w, 9024, 16984)
    put(w, 9032, 20)
    put(w, 16984, 7595371767660569960)
    put(w, 16992, 7021788497383009889)
    put(w, 17000, 880160365)
    put(w, 9040, 17008)
    put(w, 9048, 20)
    put(w, 17008, 7595371767660569960)
    put(w, 17016, 7021788497383009889)
    put(w, 17024, 896937581)
    put(w, 9056, 17032)
    put(w, 9064, 20)
    put(w, 17032, 7595371767660569960)
    put(w, 17040, 7021788497383009889)
    put(w, 17048, 913714797)
    put(w, 9072, 17056)
    put(w, 9080, 20)
    put(w, 17056, 7595371767660569960)
    put(w, 17064, 7021788497383009889)
    put(w, 17072, 930492013)
    put(w, 9088, 17080)
    put(w, 9096, 20)
    put(w, 17080, 7595371767660569960)
    put(w, 17088, 7021788497383009889)
    put(w, 17096, 947269229)
    put(w, 9104, 17104)
    put(w, 9112, 6)
    put(w, 17104, 111559249781102)
    put(w, 9120, 17112)
    put(w, 9128, 6)
    put(w, 17112, 127970252055151)
    put(w, 9136, 17120)
    put(w, 9144, 24)
    put(w, 17120, 8443462284519815288)
    put(w, 17128, 7795007989297867630)
    put(w, 17136, 8461814194867891817)
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

def control_seed(w: mutbuf, action: u64, output: u64) -> u64:
    index = 2048
    while index < 2304 + 128:
        store(w, index, 0)
        index = index + 1
    put(w, 2048, 3768479636171539272)
    put(w, 2088, action)
    put(w, 2152, output)
    control_constants(w)
    return 0

def control_refuse(w: mutbuf) -> u32:
    put(w, 2048, 3768479636171539272)
    put(w, 2080, 1)
    put(w, 2072, 0)
    return 199

def control_ask(w: mutbuf, operation: u64, next_phase: u64, a: u64, b: u64, c: u64, d: u64) -> u64:
    sequence = get(w, 2064) + 1
    put(w, 2064, sequence)
    put(w, 2072, operation)
    put(w, 2056, next_phase)
    catching = choose(get(w, 2216) == 0, 1, 0)
    put(w, 2224, catching)
    index = 2304
    while index < 2304 + 128:
        store(w, index, 0)
        index = index + 1
    put(w, 2304, 3766220139776459592)
    put(w, 2304 + 8, operation)
    put(w, 2304 + 16, sequence)
    put(w, 2304 + 24, catching)
    put(w, 2304 + 32, a)
    put(w, 2304 + 40, b)
    put(w, 2304 + 48, c)
    put(w, 2304 + 56, d)
    return 1

def control_done(w: mutbuf, code: u64) -> u64:
    put(w, 2080, 1)
    put(w, 2072, 0)
    index = 2304
    while index < 2304 + 128:
        store(w, index, 0)
        index = index + 1
    put(w, 2304, 3766220139776459592)
    put(w, 2304 + 16, get(w, 2064))
    put(w, 2304 + 32, code)
    return 2

def control_step(s: readbuf, o: mutbuf, w: mutbuf) -> u32:
    if length(s) != 96 or length(o) < 128 or length(w) < 65536:
        return control_refuse(w)
    if get(w, 2048) != 3768479636171539272 or get(w, 2080) != 0:
        return control_refuse(w)
    if read64(s, 8) != 4 or read64(s, 16) != get(w, 2064) or read64(s, 24) != get(w, 2072):
        return control_refuse(w)
    if read64(s, 32) > 1 or read64(s, 64) != 0 or read64(s, 72) != 0 or (read64(s, 80) != 0) or (read64(s, 88) != 0):
        return control_refuse(w)
    if get(w, 2064) >= 9223372036854775807:
        return control_refuse(w)
    if get(w, 2072) == 0 and get(w, 2056) != 0:
        return control_refuse(w)
    if control_reply_valid(s, w) == 0:
        return control_refuse(w)
    if read64(s, 32) == 1:
        if get(w, 2224) != 1 or read64(s, 40) == 0:
            return control_refuse(w)
        put(w, 2216, 1)
        put(w, 2232, read64(s, 40))
        put(w, 2056, 900)
    put(w, 2072, 0)
    put(w, 2192, read64(s, 40))
    put(w, 2200, read64(s, 48))
    put(w, 2208, read64(s, 56))
    result = 0
    while result == 0:
        phase = get(w, 2056)
        if phase < 40:
            result = control_initial(w)
        elif phase < 80:
            result = control_edits(w)
        elif phase < 200:
            result = control_reports(w)
        else:
            result = control_terminal(w)
    if result == 199:
        return control_refuse(w)
    index = 0
    while index < 128:
        store(o, index, byte(w, 2304 + index))
        index = index + 1
    return result

def control_reply_valid(s: readbuf, w: mutbuf) -> u64:
    a = read64(s, 40)
    b = read64(s, 48)
    c = read64(s, 56)
    operation = get(w, 2072)
    if read64(s, 32) == 1:
        return choose(a > 0 and a < 9223372036854775808 and (b == 0) and (c == 0), 1, 0)
    if operation == 22 or operation == 23 or operation == 25 or (operation == 28) or (operation == 34) or (operation >= 35 and operation <= 41):
        return choose(a == 0 and b == 0 and (c == 0), 1, 0)
    if operation == 30 or operation == 31:
        return choose(a <= 1 and b == 0 and (c == 0), 1, 0)
    if a == 0 or a >= 9223372036854775808:
        return 0
    if operation == 13 or operation == 16 or operation == 18:
        return choose(b > 0 and b < 9223372036854775808 and (c == 0), 1, 0)
    if operation == 14:
        return choose(b > 0 and b < 9223372036854775808 and (c > 0) and (c < 9223372036854775808), 1, 0)
    return choose(b == 0 and c == 0, 1, 0)

def control_initial(w: mutbuf) -> u64:
    phase = get(w, 2056)
    action = get(w, 2088)
    value = get(w, 2192)
    if phase == 0:
        if value == 0 or action < 1 or action > 15:
            return 199
        put(w, 2096, value)
        if action == 1:
            return control_ask(w, 1, 200, 0, 0, 0, 0)
        return control_ask(w, 35, 1, 0, 0, 0, 0)
    if phase == 1:
        if action == 2:
            return control_ask(w, 2, 200, get(w, 2096), 2, 0, 0)
        if action == 3 or action == 4 or action == 5:
            return control_ask(w, 36, 2, 0, 0, 0, 0)
        return control_ask(w, 3, 10, get(w, 2096), 15, 8388608, 0)
    if phase == 2:
        return control_ask(w, 3, 10, get(w, 2096), 15, 8388608, 0)
    if phase == 10:
        if action == 3:
            return control_ask(w, 5, 11, value, 0, 0, 0)
        if action == 5:
            return control_ask(w, 6, 14, value, 0, 0, 0)
        return control_ask(w, 4, 20, value, 0, 0, 0)
    if phase == 11:
        put(w, 2104, value)
        put(w, 2056, 80)
        return 0
    if phase == 12:
        return control_ask(w, 7, 13, get(w, 2104), 0, 0, 0)
    if phase == 13:
        if get(w, 2152) != 0:
            return control_ask(w, 21, 200, get(w, 2104), value, get(w, 2096), 3)
        return control_ask(w, 23, 201, value, 0, 0, 0)
    if phase == 14:
        put(w, 2128, value)
        return control_ask(w, 22, 15, value, 0, 0, 0)
    if phase == 15:
        return control_ask(w, 30, 16, get(w, 2128), 0, 0, 0)
    if phase == 16:
        if value > 1:
            return 199
        return control_done(w, 1 - value)
    if phase == 20:
        put(w, 2104, value)
        if action == 4:
            put(w, 2056, 12)
            return 0
        if action == 6:
            return control_ask(w, 9, 21, value, 0, 0, 0)
        if action == 7:
            return control_ask(w, 10, 200, value, 0, 0, 0)
        if action == 8:
            put(w, 2056, 80)
            return 0
        if action == 9:
            return control_ask(w, 11, 24, value, get(w, 2096), 3, 0)
        if action == 10:
            return control_ask(w, 3, 30, get(w, 2096), 7, 8388608, 0)
        if action == 11:
            return control_ask(w, 41, 27, 0, 0, 0, 0)
        if action == 12:
            return control_ask(w, 37, 27, 0, 0, 0, 0)
        if action == 13:
            return control_ask(w, 38, 27, 0, 0, 0, 0)
        if action == 14:
            return control_ask(w, 39, 27, 0, 0, 0, 0)
        if action == 15:
            return control_ask(w, 40, 27, 0, 0, 0, 0)
        return 199
    if phase == 21:
        return control_ask(w, 24, 22, value, 0, 0, 0)
    if phase == 22:
        put(w, 2128, value)
        return control_ask(w, 25, 23, value, 9223372036854775812, 9223372036854775819, 0)
    if phase == 23:
        return control_ask(w, 25, 202, get(w, 2128), 9223372036854775813, 9223372036854775808, 0)
    if phase == 24:
        put(w, 2128, value)
        return control_ask(w, 22, 25, value, 0, 0, 0)
    if phase == 25:
        return control_ask(w, 31, 26, get(w, 2128), 0, 0, 0)
    if phase == 26:
        if value > 1:
            return 199
        return control_done(w, 1 - value)
    if phase == 27:
        if action == 11:
            return control_ask(w, 3, 30, get(w, 2096), 7, 8388608, 0)
        if action == 12:
            return control_ask(w, 27, 50, 0, 0, 0, 0)
        if action == 13:
            return control_ask(w, 3, 60, get(w, 2096), 13, 8388608, 0)
        if action == 14:
            return control_ask(w, 3, 65, get(w, 2096), 12, 8388608, 0)
        if action == 15:
            return control_ask(w, 3, 67, get(w, 2096), 13, 1048576, 0)
        return 199
    if phase == 30:
        if action == 10:
            return control_ask(w, 13, 70, get(w, 2104), value, 0, 0)
        return control_ask(w, 14, 90, get(w, 2104), value, 0, 0)
    return 199

def control_edits(w: mutbuf) -> u64:
    phase = get(w, 2056)
    value = get(w, 2192)
    if phase == 50:
        put(w, 2160, value)
        put(w, 2168, 0)
        put(w, 2184, 0)
        put(w, 2056, 53)
        return 0
    if phase == 51:
        return control_ask(w, 28, 52, get(w, 2160), value, 0, 0)
    if phase == 52:
        put(w, 2168, get(w, 2176) + 1)
        put(w, 2056, 53)
        return 0
    if phase == 53:
        if get(w, 2184) != 0:
            return control_ask(w, 15, 55, get(w, 2104), get(w, 2096), get(w, 2160), 0)
        field = 256 + 11 * 32
        if get(w, field) != 2:
            return 199
        start = get(w, 2168)
        end = start
        size = get(w, field + 16)
        at = get(w, 152) + get(w, field + 8)
        while end < size and get32(w, at + end * 4) != 44:
            end = end + 1
        put(w, 2176, end)
        if end == size:
            put(w, 2184, 1)
        return control_ask(w, 29, 51, get(w, 2096), 11, start, end - start)
    if phase == 55:
        if get(w, 2152) != 0:
            return control_ask(w, 20, 200, value, get(w, 2096), 3, 0)
        put(w, 2128, value)
        put(w, 2056, 202)
        return 0
    if phase == 60:
        return control_ask(w, 12, 61, value, 0, 0, 0)
    if phase == 61:
        put(w, 2136, value)
        return control_ask(w, 3, 62, get(w, 2096), 14, 16384, 0)
    if phase == 62:
        return control_ask(w, 16, 70, get(w, 2104), get(w, 2136), value, 0)
    if phase == 65:
        return control_ask(w, 12, 66, value, 0, 0, 0)
    if phase == 66:
        return control_ask(w, 17, 55, get(w, 2104), value, 0, 0)
    if phase == 67:
        put(w, 2136, value)
        return control_ask(w, 3, 68, get(w, 2096), 14, 65536, 0)
    if phase == 68:
        return control_ask(w, 18, 70, get(w, 2104), get(w, 2136), value, 0)
    if phase == 70:
        put(w, 2112, value)
        put(w, 2120, get(w, 2200))
        if get(w, 2152) != 0:
            return control_ask(w, 19, 71, value, get(w, 2096), 3, 0)
        return control_ask(w, 8, 73, value, 0, 0, 0)
    if phase == 71:
        return control_ask(w, 25, 72, get(w, 2120), 9223372036854775814, value, 0)
    if phase == 72:
        return control_ask(w, 25, 74, get(w, 2120), 9223372036854775812, 9223372036854775818, 0)
    if phase == 73:
        return control_ask(w, 25, 74, get(w, 2120), 9223372036854775815, value, 0)
    if phase == 74:
        put(w, 2128, get(w, 2120))
        put(w, 2056, 202)
        return 0
    return 199

def control_reports(w: mutbuf) -> u64:
    phase = get(w, 2056)
    value = get(w, 2192)
    if phase == 80:
        if get(w, 2152) != 0:
            return control_ask(w, 19, 200, get(w, 2104), get(w, 2096), 3, 0)
        return control_ask(w, 8, 200, get(w, 2104), 0, 0, 0)
    if phase == 90:
        put(w, 2120, get(w, 2200))
        put(w, 2144, get(w, 2208))
        return control_ask(w, 26, 91, 0, 0, 0, 0)
    if phase == 91:
        put(w, 2128, value)
        return control_ask(w, 25, 92, value, 9223372036854775810, 9223372036854775820, 0)
    if phase == 92:
        return control_ask(w, 25, 93, get(w, 2128), 9223372036854775811, 9223372036854775809, 0)
    if phase == 93:
        return control_ask(w, 25, 94, get(w, 2128), 9223372036854775812, 9223372036854775821, 0)
    if phase == 94:
        return control_ask(w, 25, 95, get(w, 2128), 9223372036854775816, get(w, 2120), 0)
    if phase == 95:
        return control_ask(w, 25, 202, get(w, 2128), 9223372036854775817, get(w, 2144), 0)
    return 199

def control_terminal(w: mutbuf) -> u64:
    phase = get(w, 2056)
    value = get(w, 2192)
    if phase == 200:
        put(w, 2128, value)
        put(w, 2056, 202)
        return 0
    if phase == 201:
        return control_done(w, 0)
    if phase == 202:
        return control_ask(w, 22, 201, get(w, 2128), 0, 0, 0)
    if phase == 900:
        return control_ask(w, 32, 901, get(w, 2232), 0, 0, 0)
    if phase == 901:
        return control_ask(w, 33, 902, value, 0, 0, 0)
    if phase == 902:
        return control_ask(w, 34, 903, value, 0, 0, 0)
    if phase == 903:
        return control_done(w, 2)
    return 199

def control_constants(w: mutbuf) -> u64:
    put(w, 4096, 1)
    put(w, 4104, 0)
    put(w, 4112, 0)
    put(w, 4128, 1)
    put(w, 4136, 1)
    put(w, 4144, 0)
    put(w, 4160, 2)
    put(w, 4168, 6144)
    put(w, 4176, 6)
    put(w, 6144, 107122480669555)
    put(w, 4192, 2)
    put(w, 4200, 6152)
    put(w, 4208, 2)
    put(w, 6152, 27503)
    put(w, 4224, 2)
    put(w, 4232, 6160)
    put(w, 4240, 6)
    put(w, 6160, 126948300911731)
    put(w, 4256, 2)
    put(w, 4264, 6168)
    put(w, 4272, 15)
    put(w, 6168, 7304668679868014958)
    put(w, 6176, 28259048531125624)
    put(w, 4288, 2)
    put(w, 4296, 6184)
    put(w, 4304, 11)
    put(w, 6184, 8386093285581682032)
    put(w, 6192, 7237481)
    put(w, 4320, 2)
    put(w, 4328, 6200)
    put(w, 4336, 7)
    put(w, 6200, 30787916450984560)
    put(w, 4352, 2)
    put(w, 4360, 6208)
    put(w, 4368, 5)
    put(w, 6208, 448345170288)
    put(w, 4384, 2)
    put(w, 4392, 6216)
    put(w, 4400, 6)
    put(w, 6216, 127970185342313)
    put(w, 4416, 2)
    put(w, 4424, 6224)
    put(w, 4432, 31)
    put(w, 6224, 7234304265017255286)
    put(w, 6232, 7020675722979405407)
    put(w, 6240, 8462368653519123312)
    put(w, 6248, 28258996958358626)
    put(w, 4448, 2)
    put(w, 4456, 6256)
    put(w, 4464, 23)
    put(w, 6256, 8028899319671256179)
    put(w, 6264, 6874026228985062766)
    put(w, 6272, 28259009574561891)
    put(w, 4480, 2)
    put(w, 4488, 6280)
    put(w, 4496, 25)
    put(w, 6280, 7595371767660569960)
    put(w, 6288, 8386654066593836641)
    put(w, 6296, 8515877477639614765)
    put(w, 6304, 49)
    put(w, 4512, 2)
    put(w, 4520, 6312)
    put(w, 4528, 20)
    put(w, 6312, 7234304265017255286)
    put(w, 6320, 7596554928004167007)
    put(w, 6328, 1684367475)
    return 0
