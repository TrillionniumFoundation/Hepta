"""HIA exact signed arithmetic for the current context/deadline policies.

The wire carries exact-int tags and two's-complement bytes. Extents derive
from the actual operands; there is no integer-width or decimal-digit quota.
Other numeric objects are an explicit foreign protocol, never a narrowed int.
"""
from __future__ import annotations

REQUEST_MAGIC = int.from_bytes(b'HCTXINT1', 'little')
RESULT_MAGIC = int.from_bytes(b'HCTXNUM1', 'little')

POLICY = r'''
def context_math(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 64 or length(o) < 32:
        return 4294967293
    if read_word(s, 0) != @MATH_REQUEST@ or read_word(s, 48) != 0 or read_word(s, 56) != 0:
        return 4294967293
    operation = read_word(s, 8)
    left_tag = read_word(s, 16)
    right_tag = read_word(s, 24)
    left_size = read_word(s, 32)
    right_size = read_word(s, 40)
    if operation < 1 or operation > 8 or left_tag > 1 or right_tag > 1:
        return 4294967293
    if left_size > length(s) - 64 or right_size != length(s) - 64 - left_size:
        return 4294967293
    if (left_tag == 0 and left_size != 0) or (right_tag == 0 and right_size != 0):
        return 4294967293
    if (left_tag == 1 and left_size == 0) or (right_tag == 1 and right_size == 0):
        return 4294967293
    if left_tag == 0 or right_tag == 0:
        math_header(o, 1, 0, operation)
        return 32
    width = left_size
    if right_size > width:
        width = right_size
    if width > 18446744073709551607:
        return 4294967293
    width = width + 8
    if width > length(w) // 3 or width > length(o) - 32:
        return 4294967293
    left_sign = byte(s, 63 + left_size) >> 7
    right_sign = byte(s, 63 + left_size + right_size) >> 7
    i = 0
    while i < width:
        a = left_sign * 255
        b = right_sign * 255
        if i < left_size:
            a = byte(s, 64 + i)
        if i < right_size:
            b = byte(s, 64 + left_size + i)
        store(w, i, a)
        store(w, width + i, b)
        store(w, width * 2 + i, 0)
        i = i + 1
    if operation >= 5 and operation <= 7:
        relation = math_compare(w, width, left_sign, right_sign)
        value = 0
        if operation == 5 and relation == 2:
            value = 1
        if operation == 6 and relation != 2:
            value = 1
        if operation == 7 and relation != 1:
            value = 1
        math_header(o, 2, 1, operation)
        store(o, 32, value)
        return 32
    if operation == 1 or operation == 2:
        math_add(w, width, operation - 1)
    elif operation == 3:
        if math_million(w, width) == 0:
            return 4294967293
        carry = 0
        i = 0
        while i < width:
            product = byte(w, i) * 1000000 + carry
            store(w, width * 2 + i, product & 255)
            carry = product >> 8
            i = i + 1
    elif operation == 4:
        if math_million(w, width) == 0:
            return 4294967293
        math_floor(w, width, left_sign)
    elif operation == 8:
        i = 0
        while i < width:
            value = 0
            if left_sign == 0:
                value = byte(w, i)
            store(w, width * 2 + i, value)
            i = i + 1
    else:
        return 4294967293
    math_header(o, 0, width, operation)
    i = 0
    while i < width:
        store(o, 32 + i, byte(w, width * 2 + i))
        i = i + 1
    return 32

def math_compare(w:mutbuf, width:u64, left_sign:u64, right_sign:u64) -> u64:
    if left_sign != right_sign:
        if left_sign == 1:
            return 0
        return 2
    i = width
    while i > 0:
        i = i - 1
        a = byte(w, i)
        b = byte(w, width + i)
        if a < b:
            return 0
        if a > b:
            return 2
    return 1

def math_add(w:mutbuf, width:u64, subtract:u64) -> u64:
    carry = subtract
    i = 0
    while i < width:
        b = byte(w, width + i)
        if subtract == 1:
            b = 255 - b
        value = byte(w, i) + b + carry
        store(w, width * 2 + i, value & 255)
        carry = value >> 8
        i = i + 1
    return 0

def math_million(w:mutbuf, width:u64) -> u64:
    expected = 1000000
    i = 0
    while i < width:
        if byte(w, width + i) != (expected & 255):
            return 0
        expected = expected >> 8
        i = i + 1
    return 1

def math_floor(w:mutbuf, width:u64, negative:u64) -> u64:
    if negative == 1:
        math_negate(w, 0, width)
    remainder = 0
    i = width
    while i > 0:
        i = i - 1
        value = (remainder << 8) | byte(w, i)
        store(w, width * 2 + i, value // 1000000)
        remainder = value % 1000000
    if negative == 1:
        math_negate(w, width * 2, width)
        if remainder != 0:
            borrow = 1
            i = 0
            while i < width and borrow == 1:
                value = byte(w, width * 2 + i)
                if value == 0:
                    store(w, width * 2 + i, 255)
                else:
                    store(w, width * 2 + i, value - 1)
                    borrow = 0
                i = i + 1
    return 0

def math_negate(w:mutbuf, at:u64, width:u64) -> u64:
    carry = 1
    i = 0
    while i < width:
        value = 255 - byte(w, at + i) + carry
        store(w, at + i, value & 255)
        carry = value >> 8
        i = i + 1
    return 0

def math_header(o:mutbuf, kind:u64, size:u64, operation:u64) -> u64:
    put_word(o, 0, @MATH_RESULT@)
    put_word(o, 8, kind)
    put_word(o, 16, size)
    put_word(o, 24, operation)
    return 0
'''


def source():
    return POLICY.replace('@MATH_REQUEST@', str(REQUEST_MAGIC)).replace('@MATH_RESULT@', str(RESULT_MAGIC))
