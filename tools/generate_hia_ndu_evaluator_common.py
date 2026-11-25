"""HIA NDU evaluator shared memory and SHA authoring. Development only."""
from tools.generate_hia_sha256 import INITIAL, ROUND, BODY
COMMON=r'''
def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    word_store(w, at, value)
    return value

def cp(w:mutbuf, target:u64, start:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(w, start + i))
        i = i + 1
    return target + size

def input_copy(s:readbuf, w:mutbuf, target:u64, start:u64, size:u64) -> u64:
    i = 0
    while i < size:
        store(w, target + i, byte(s, start + i))
        i = i + 1
    return target + size

def eq(w:mutbuf, a:u64, an:u64, b:u64, bn:u64) -> u64:
    if an != bn:
        return 0
    i = 0
    while i < an:
        if byte(w, a + i) != byte(w, b + i):
            return 0
        i = i + 1
    return 1

def before(w:mutbuf, a:u64, an:u64, b:u64, bn:u64) -> u64:
    n = choose(an < bn, an, bn)
    i = 0
    while i < n:
        av = byte(w, a + i)
        bv = byte(w, b + i)
        if av != bv:
            return choose(av < bv, 1, 0)
        i = i + 1
    return choose(an < bn, 1, 0)

def error(w:mutbuf, code:u64, position:u64, a:u64, b:u64) -> u64:
    if get(w, 0) == 0:
        put(w, 0, code)
        put(w, 8, position)
        put(w, 16, a)
        put(w, 24, b)
    return 0

def text_byte(w:mutbuf, value:u64) -> u64:
    at = get(w, 64)
    store(w, at, value)
    put(w, 64, at + 1)
    return at + 1

def text_copy(w:mutbuf, at:u64, size:u64) -> u64:
    end = cp(w, get(w, 64), at, size)
    put(w, 64, end)
    return end

def text(w:mutbuf, which:u64) -> u64:
    end = literal(w, get(w, 64), which)
    put(w, 64, end)
    return end

def be32(w:mutbuf, value:u64) -> u64:
    i = 0
    while i < 4:
        text_byte(w, value >> ((3 - i) * 8))
        i = i + 1
    return get(w, 64)

def be64(w:mutbuf, value:u64) -> u64:
    i = 0
    while i < 8:
        text_byte(w, value >> ((7 - i) * 8))
        i = i + 1
    return get(w, 64)

def identifier(w:mutbuf, at:u64, size:u64) -> u64:
    be32(w, size)
    return text_copy(w, at, size)

def fixed_id(w:mutbuf, which:u64) -> u64:
    end = literal(w, 45056, which)
    return identifier(w, 45056, end - 45056)

def decimal(w:mutbuf, value:u64) -> u64:
    n = value
    count = 0
    while n >= 10:
        store(w, 43008 + count, 48 + n % 10)
        count = count + 1
        n = n // 10
    text_byte(w, 48 + n)
    while count > 0:
        count = count - 1
        text_byte(w, byte(w, 43008 + count))
    return get(w, 64)

def quote(w:mutbuf, at:u64, size:u64) -> u64:
    text_byte(w, 34)
    i = 0
    while i < size:
        ch = byte(w, at + i)
        if ch == 34 or ch == 92:
            text_byte(w, 92)
            text_byte(w, ch)
        else:
            if ch == 8:
                text_byte(w, 92)
                text_byte(w, 98)
            else:
                if ch == 9:
                    text_byte(w, 92)
                    text_byte(w, 116)
                else:
                    if ch == 10:
                        text_byte(w, 92)
                        text_byte(w, 110)
                    else:
                        if ch == 12:
                            text_byte(w, 92)
                            text_byte(w, 102)
                        else:
                            if ch == 13:
                                text_byte(w, 92)
                                text_byte(w, 114)
                            else:
                                if ch < 32:
                                    text_byte(w, 92)
                                    text_byte(w, 117)
                                    text_byte(w, 48)
                                    text_byte(w, 48)
                                    text_byte(w, hex_digit(ch >> 4))
                                    text_byte(w, hex_digit(ch & 15))
                                else:
                                    text_byte(w, ch)
        i = i + 1
    return text_byte(w, 34)

def hex_digit(value:u64) -> u64:
    return choose(value < 10, 48 + value, 87 + value)

def hex_output(w:mutbuf, at:u64) -> u64:
    text_byte(w, 34)
    i = 0
    while i < 32:
        ch = byte(w, at + i)
        text_byte(w, hex_digit(ch >> 4))
        text_byte(w, hex_digit(ch & 15))
        i = i + 1
    return text_byte(w, 34)

def hex_parse(w:mutbuf, at:u64, size:u64, output:u64) -> u64:
    if size != 64:
        return error(w, 1012, 0, size, 0)
    i = 0
    accum = 0
    while i < 64:
        ch = byte(w, at + i)
        digit = 16
        if ch >= 48 and ch <= 57:
            digit = ch - 48
        if ch >= 97 and ch <= 102:
            digit = ch - 87
        if digit == 16:
            return error(w, 1013, 0, i, 0)
        accum = (accum << 4) | digit
        if i & 1 == 1:
            store(w, output + (i >> 1), accum)
            accum = 0
        i = i + 1
    return 1

def nonzero(w:mutbuf, at:u64) -> u64:
    i = 0
    result = 0
    while i < 32:
        result = result | byte(w, at + i)
        i = i + 1
    return choose(result != 0, 1, 0)

def emit_utf8(w:mutbuf, at:u64, cp:u64) -> u64:
    if cp < 128:
        store(w, at, cp)
        return at + 1
    if cp < 2048:
        store(w, at, 192 | (cp >> 6))
        store(w, at + 1, 128 | (cp & 63))
        return at + 2
    if cp < 65536:
        store(w, at, 224 | (cp >> 12))
        store(w, at + 1, 128 | ((cp >> 6) & 63))
        store(w, at + 2, 128 | (cp & 63))
        return at + 3
    store(w, at, 240 | (cp >> 18))
    store(w, at + 1, 128 | ((cp >> 12) & 63))
    store(w, at + 2, 128 | ((cp >> 6) & 63))
    store(w, at + 3, 128 | (cp & 63))
    return at + 4
'''
def hash_source():
    prefix='def hash_segment(w:mutbuf, start:u64, size:u64, out:u64) -> u64:\n'
    for i,x in enumerate(ROUND):prefix+=f'    put(w, {6291456+i*8}, {x})\n'
    for i,x in enumerate(INITIAL):prefix+=f'    put(w, {6292480+i*8}, {x})\n'
    import ast
    class Rewrite(ast.NodeTransformer):
        def visit_Call(self,n):
            n=self.generic_visit(n)
            if isinstance(n.func,ast.Name):
                if n.func.id=='length':return ast.Name(id='size',ctx=ast.Load())
                if n.func.id in ('get','put'):
                    n.args[1]=ast.BinOp(left=n.args[1],op=ast.Add(),right=ast.Constant(6291456))
                if n.func.id=='padded_byte':
                    n.func.id='hash_padded';n.args=[ast.Name(id='w',ctx=ast.Load()),ast.Name(id='start',ctx=ast.Load()),ast.Name(id='size',ctx=ast.Load()),*n.args[1:]]
            return n
    body=BODY
    for i,name in enumerate('abcdefgh'):body+=f'        put(w, {1024+i*8}, (get(w, {1024+i*8}) + {name}) & 4294967295)\n'
    body+='        block = block + 64\n'
    node=ast.parse('def x():\n'+body).body[0]
    prefix+='\n'.join('    '+line for n in node.body for line in ast.unparse(ast.fix_missing_locations(Rewrite().visit(n))).splitlines())+'\n'
    prefix+='''    i = 0
    while i < 8:
        value = get(w, 6292480 + i * 8)
        j = 0
        while j < 4:
            store(w, out + i * 4 + j, value >> ((3 - j) * 8))
            j = j + 1
        i = i + 1
    return 0

def hash_padded(w:mutbuf, start:u64, size:u64, at:u64, total:u64) -> u64:
    if at < size:
        return byte(w, start + at)
    if at == size:
        return 128
    if at < total - 8:
        return 0
    return ((size << 3) >> ((total - 1 - at) * 8)) & 255

def rotate(value:u64, shift:u64) -> u64:
    return (value >> shift) | ((value << (32 - shift)) & 4294967295)
'''
    return prefix
