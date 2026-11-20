"""Generate the bounded kernel-mapping parser and authorization policy in HIA.

The native program scans the original immutable maps snapshot. Integer tokens
retain their source spans, so valid arbitrary-size hex values can be ordered
without u64 truncation or an extra token-size limit. Kernel effects and Python
object admission remain the caller's explicit foreign boundary.
"""
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document

ROOT = Path(__file__).resolve().parents[1]
REQUEST_MAGIC = int.from_bytes(b'HIAMAP01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAMPR01', 'little')
STATE_BYTES = 8192
MAX_MAPS_BYTES = 16 << 20

POLICY = '''def mapping(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) != 8192:
        return 8
    count = get(w, 8)
    if get(w, 0) != REQUEST_MAGIC or count == 0 or count > 128 or get(w, 40) == 0 or get(w, 56) != 0:
        return 8
    if length(s) > 16777216 or length(o) != 16 + 8 * count:
        return 8
    i = 0
    while i < count:
        if get(w, 64 + i * 8) == 0:
            return 8
        put(w, 1088 + i * 8, 0)
        put(w, 2112 + i * 8, 0)
        i = i + 1
    at = 0
    while at < length(s):
        begin = at
        while at < length(s) and byte(s, at) != 10 and byte(s, at) != 13:
            at = at + 1
        status = line(s, w, begin, at)
        if status != 0:
            return status
        if at < length(s):
            ending = byte(s, at)
            at = at + 1
            if ending == 13 and at < length(s) and byte(s, at) == 10:
                at = at + 1
    i = 0
    while i < count:
        if get(w, 1088 + i * 8) != 1:
            return 7
        i = i + 1
    put(o, 0, RESULT_MAGIC)
    put(o, 8, count)
    i = 0
    while i < count:
        put(o, 16 + i * 8, get(w, 2112 + i * 8))
        i = i + 1
    return 0

def line(s:readbuf, w:mutbuf, begin:u64, end:u64) -> u64:
    at = begin
    field = 0
    while field < 5:
        while at < end and whitespace(byte(s, at)) != 0:
            at = at + 1
        if at == end:
            return 1
        first = at
        while at < end and whitespace(byte(s, at)) == 0:
            at = at + 1
        put(w, 4096 + field * 16, first)
        put(w, 4104 + field * 16, at)
        field = field + 1
    bounds = separator(s, get(w, 4096), get(w, 4104), 45)
    device = separator(s, get(w, 4144), get(w, 4152), 58)
    if bounds == 18446744073709551615 or device == 18446744073709551615:
        return 2
    if integer(s, w, get(w, 4096), bounds, 16, 3136) != 0:
        return 9
    if integer(s, w, bounds + 1, get(w, 4104), 16, 3200) != 0:
        return 9
    if integer(s, w, get(w, 4128), get(w, 4136), 16, 3264) != 0:
        return 9
    if integer(s, w, get(w, 4144), device, 16, 3328) != 0:
        return 9
    if integer(s, w, device + 1, get(w, 4152), 16, 3392) != 0:
        return 9
    if integer(s, w, get(w, 4160), get(w, 4168), 10, 3456) != 0:
        return 9
    permission = get(w, 4112)
    permission_end = get(w, 4120)
    at = permission
    while at < permission_end:
        if byte(s, at) > 127:
            put(w, 4200, 1)
            put(w, 4208, permission)
            put(w, 4216, permission_end)
            return 9
        at = at + 1
    i = 0
    while i < 6:
        if get(w, 3152 + i * 64) != 0:
            return 3
        i = i + 1
    if less(s, w, 3136, 3200) == 0:
        return 3
    i = 0
    while i < get(w, 8):
        address = get(w, 64 + i * 8)
        if get(w, 3144) == 0 and get(w, 3136) <= address and (get(w, 3208) != 0 or address < get(w, 3200)):
            if permission_end - permission != 4:
                return 4
            if byte(s, permission) != 114 or byte(s, permission + 1) != 45 or byte(s, permission + 2) != 120 or byte(s, permission + 3) != 112:
                return 4
            if get(w, 3336) != 0 or get(w, 3400) != 0 or get(w, 3464) != 0:
                return 5
            if get(w, 3328) != get(w, 16) or get(w, 3392) != get(w, 24) or get(w, 3456) != get(w, 32):
                return 5
            delta = address - get(w, 3136)
            offset = get(w, 3264)
            if get(w, 3272) != 0 or offset > 18446744073709551615 - delta:
                return 6
            offset = offset + delta
            if offset >= get(w, 40):
                return 6
            put(w, 1088 + i * 8, get(w, 1088 + i * 8) + 1)
            put(w, 2112 + i * 8, offset)
        i = i + 1
    return 0

def whitespace(value:u64) -> u64:
    if value == 32 or (value >= 9 and value <= 13):
        return 1
    return 0

def separator(s:readbuf, begin:u64, end:u64, value:u64) -> u64:
    result = 18446744073709551615
    at = begin
    while at < end:
        if byte(s, at) == value:
            if result != 18446744073709551615:
                return 18446744073709551615
            result = at
        at = at + 1
    return result

def digit(value:u64) -> u64:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 65 and value <= 70:
        return value - 55
    if value >= 97 and value <= 102:
        return value - 87
    return 16

def integer(s:readbuf, w:mutbuf, begin:u64, end:u64, base:u64, slot:u64) -> u64:
    put(w, 4200, base)
    put(w, 4208, begin)
    put(w, 4216, end)
    at = begin
    negative = 0
    if at < end and (byte(s, at) == 43 or byte(s, at) == 45):
        if byte(s, at) == 45:
            negative = 1
        at = at + 1
    if base == 16 and at + 1 < end and byte(s, at) == 48 and (byte(s, at + 1) == 88 or byte(s, at + 1) == 120):
        at = at + 2
        if at < end and byte(s, at) == 95:
            at = at + 1
    value = 0
    overflow = 0
    first = end
    digits = 0
    total = 0
    required = 1
    maximum = 1844674407370955161
    last = 5
    if base == 16:
        maximum = 1152921504606846975
        last = 15
    while at < end:
        char = byte(s, at)
        if char == 95:
            if required != 0:
                return 1
            required = 1
        else:
            number = digit(char)
            if number >= base:
                return 1
            total = total + 1
            required = 0
            if number != 0 or digits != 0:
                if digits == 0:
                    first = at
                digits = digits + 1
            if overflow == 0:
                if value > maximum or (value == maximum and number > last):
                    overflow = 1
                else:
                    value = value * base + number
        at = at + 1
    if required != 0:
        return 1
    if base == 10 and get(w, 48) != 0 and total > get(w, 48):
        return 1
    if digits == 0:
        negative = 0
    put(w, slot, value)
    put(w, slot + 8, overflow)
    put(w, slot + 16, negative)
    put(w, slot + 24, digits)
    put(w, slot + 32, first)
    put(w, slot + 40, end)
    return 0

def less(s:readbuf, w:mutbuf, left:u64, right:u64) -> u64:
    a = get(w, left + 24)
    b = get(w, right + 24)
    if a < b:
        return 1
    if a > b:
        return 0
    x = get(w, left + 32)
    y = get(w, right + 32)
    i = 0
    while i < a:
        while byte(s, x) == 95:
            x = x + 1
        while byte(s, y) == 95:
            y = y + 1
        first = digit(byte(s, x))
        second = digit(byte(s, y))
        if first < second:
            return 1
        if first > second:
            return 0
        x = x + 1
        y = y + 1
        i = i + 1
    return 0

def get(w:mutbuf, at:u64) -> u64:
    result = 0
    i = 0
    while i < 8:
        result = result | (byte(w, at + i) << (i * 8))
        i = i + 1
    return result

def put(w:mutbuf, at:u64, value:u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''


def source():
    return POLICY.replace('REQUEST_MAGIC', str(REQUEST_MAGIC)).replace('RESULT_MAGIC', str(RESULT_MAGIC))


def main():
    path = ROOT / 'examples/hia_bootstrap/native_mapping.hepta'
    path.write_text(render_assembly(document(source(), 'native_mapping')))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
