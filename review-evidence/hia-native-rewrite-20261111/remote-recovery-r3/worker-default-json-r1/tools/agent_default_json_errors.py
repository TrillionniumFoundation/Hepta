"""Native complete Unicode, preflight, JSON syntax and integer-limit text.

All offsets are original-byte positions for UnicodeDecodeError, original
code-point positions for UnicodeEncodeError / JSONDecodeError. No message
rendering is delegated to a Python exception or numeric formatter.
"""
LITERALS={
 1:'JSON data must be UTF-8 bytes or text',
 2:'JSON data exceeds 8 MiB',
 3:'HIA JSON exceeds node/depth budget before decoding',
 4:'HIA JSON preflight: duplicate decoded object key',
 5:'nonfinite JSON number',
 10:"'utf-8' codec can't decode byte",
 11:' 0x',12:' in position ',13:': ',14:'s in position ',
 15:"'utf-8' codec can't encode character",
 16:" '\\u",17:"' in position ",18:': surrogates not allowed',
 21:'invalid start byte',22:'invalid continuation byte',23:'unexpected end of data',
 30:'Exceeds the limit (',
 31:' digits) for integer string conversion: value has ',
 32:' digits; use sys.set_int_max_str_digits() to increase the limit',
 40:'Extra data',41:'Expecting value',42:"Expecting ',' delimiter",
 43:'Expecting property name enclosed in double quotes',44:"Expecting ':' delimiter",
 45:': line ',46:' column ',47:' (char ',
}
PREFLIGHT_REASONS={
 1:'expected JSON string',
 2:'unescaped control or isolated Unicode surrogate',
 3:'unterminated JSON escape',
 4:'invalid JSON escape',
 5:'invalid Unicode escape',
 6:'unpaired high Unicode surrogate',
 7:'unpaired low Unicode surrogate',
 8:'unterminated JSON string',
 9:'missing JSON value',
 10:'expected JSON integer or literal',
 11:'unexpected value completion',
 12:'extra JSON data',
 13:'incomplete JSON value',
 14:'expected array separator/end',
 15:'invalid array preflight state',
 16:'expected object field name',
 17:'expected object colon',
 18:'expected object separator/end',
 19:'invalid object preflight state',
 20:'invalid JSON syntax or Unicode',
}
LITERALS.update({100+key:'HIA JSON preflight: '+value for key,value in PREFLIGHT_REASONS.items()})
ERRORS=r'''
def gc_text(w:mutbuf, identifier:u64) -> u64:
    used = gc_get(w, G_TEXT_SIZE)
    size = gc_literal_size(identifier)
    if used > GC_TEXT_CAP or size > GC_TEXT_CAP - used:
        return gc_bad(w, 20)
    offset = 0
    while offset < size:
        word = gc_literal_word(identifier, offset >> 3)
        if size - offset >= 8:
            gc_put(w, GC_TEXT + used + offset, word)
            offset = offset + 8
        else:
            part = 0
            while part < size - offset:
                store(w, GC_TEXT + used + offset + part, (word >> (part * 8)) & 255)
                part = part + 1
            offset = size
    gc_put(w, G_TEXT_SIZE, used + size)
    return 0

def gc_text_byte(w:mutbuf, value:u64) -> u64:
    used = gc_get(w, G_TEXT_SIZE)
    if used >= GC_TEXT_CAP:
        return gc_bad(w, 21)
    store(w, GC_TEXT + used, value)
    gc_put(w, G_TEXT_SIZE, used + 1)
    return 0

def gc_divide_ten(value:u64) -> u64:
    quotient = 0
    remainder = 0
    bit = 64
    while bit != 0:
        bit = bit - 1
        remainder = (remainder << 1) | ((value >> bit) & 1)
        if remainder >= 10:
            remainder = remainder - 10
            quotient = quotient | (1 << bit)
    return quotient

def gc_decimal(w:mutbuf, value:u64) -> u64:
    count = 0
    while value >= 10:
        divided = gc_divide_ten(value)
        store(w, GC_DECIMAL + count, 48 + value - divided * 10)
        value = divided
        count = count + 1
    store(w, GC_DECIMAL + count, 48 + value)
    count = count + 1
    while count != 0:
        count = count - 1
        gc_text_byte(w, byte(w, GC_DECIMAL + count))
    return 0

def gc_hex(w:mutbuf, value:u64, width:u64) -> u64:
    shift = width * 4
    while shift != 0:
        shift = shift - 4
        digit = (value >> shift) & 15
        gc_text_byte(w, choose(digit < 10, 48 + digit, 87 + digit))
    return 0

def gc_decode_error(w:mutbuf, reason:u64) -> u64:
    if reason == 0 or reason > 3:
        return gc_bad(w, 22)
    gc_put(w, G_TEXT_SIZE, 0)
    gc_text(w, 10)
    start = gc_get(w, G_ERROR_START)
    end = gc_get(w, G_ERROR_END)
    if end <= start:
        return gc_bad(w, 23)
    if end == start + 1:
        gc_text(w, 11)
        gc_hex(w, gc_get(w, G_ERROR_AUX), 2)
        gc_text(w, 12)
        gc_decimal(w, start)
    else:
        gc_text(w, 14)
        gc_decimal(w, start)
        gc_text_byte(w, 45)
        gc_decimal(w, end - 1)
    gc_text(w, 13)
    gc_text(w, 20 + reason)
    return gc_error(w, 4, reason)

def gc_encode_error(w:mutbuf) -> u64:
    gc_put(w, G_TEXT_SIZE, 0)
    gc_text(w, 15)
    start = gc_get(w, G_ERROR_START)
    end = gc_get(w, G_ERROR_END)
    if end <= start:
        return gc_bad(w, 24)
    if end == start + 1:
        gc_text(w, 16)
        gc_hex(w, gc_get(w, G_ERROR_AUX), 4)
        gc_text(w, 17)
        gc_decimal(w, start)
    else:
        gc_text(w, 14)
        gc_decimal(w, start)
        gc_text_byte(w, 45)
        gc_decimal(w, end - 1)
    gc_text(w, 18)
    return gc_error(w, 5, 1)

def gc_digit_error(w:mutbuf, maximum:u64, actual:u64) -> u64:
    gc_put(w, G_TEXT_SIZE, 0)
    gc_text(w, 30)
    gc_decimal(w, maximum)
    gc_text(w, 31)
    gc_decimal(w, actual)
    gc_text(w, 32)
    gc_put(w, G_ERROR_AUX, actual)
    return gc_error(w, 2, 1)

def gc_location(s:readbuf, w:mutbuf, target:u64) -> u64:
    if target > length(s):
        return 0
    index = 0
    position = 0
    line = 1
    column = 1
    while index < target:
        if gc_point(s, w, index, length(s), 0) == 0:
            return 0
        if gc_get(w, G_UTF8_NEXT) > target:
            return 0
        if byte(s, index) == 10:
            line = line + 1
            column = 1
        else:
            column = column + 1
        position = position + 1
        index = gc_get(w, G_UTF8_NEXT)
    gc_put(w, G_ERROR_START, position)
    gc_put(w, G_ERROR_END, position)
    gc_put(w, G_ERROR_LINE, line)
    gc_put(w, G_ERROR_COLUMN, column)
    return 1

def gc_json_error(s:readbuf, w:mutbuf, reason:u64, byte_position:u64) -> u64:
    if reason < 40 or reason > 44:
        return gc_bad(w, 25)
    if gc_location(s, w, byte_position) == 0:
        return gc_bad(w, 26)
    gc_put(w, G_TEXT_SIZE, 0)
    gc_text(w, reason)
    gc_text(w, 45)
    gc_decimal(w, gc_get(w, G_ERROR_LINE))
    gc_text(w, 46)
    gc_decimal(w, gc_get(w, G_ERROR_COLUMN))
    gc_text(w, 47)
    gc_decimal(w, gc_get(w, G_ERROR_START))
    gc_text_byte(w, 41)
    return gc_error(w, 6, reason - 39)
'''
