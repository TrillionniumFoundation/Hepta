"""Author the Hepta source lexical recognizer as ordinary executable HIA.

This is not the assembly compiler scanner. Native code recognizes source
tokens, nested comments, UTF-8 code points, spans and numeric token grammar.
The host token bridge still constructs Python values (notably arbitrary-size
integers and finite binary64 values). Full parsing/type checking remain open.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from hepta.lexer import KEYWORDS
from tools.generate_hia_selfhost import Builder,compact_authoring_cfg,total_scalar_functions

KEYWORD_ORDER=tuple(sorted(KEYWORDS))
PAIR_ORDER=('->','..','==','!=','<=','>=','&&','||','<<','>>','::','=>')

SOURCE=r'''
def lexer(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 128 or length(s) > 8388608:
        return 4294967293
    initialize(w, 0)
    scan(s, o, w)
    if get(w, 48) != 0:
        return 4294967295
    size = get(w, 40) * 56
    if length(o) < size:
        return 4294967294
    initialize(w, 1)
    scan(s, o, w)
    return size

def initialize(w:mutbuf, phase:u64) -> u64:
    put(w, 0, 0)
    put(w, 8, 0)
    put(w, 16, 1)
    put(w, 24, 1)
    put(w, 32, 0)
    put(w, 40, 0)
    put(w, 48, 0)
    put(w, 104, phase)
    return 0

def scan(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    while get(w, 0) < length(s) and get(w, 48) == 0:
        ch = peek(s, get(w, 0))
        if ch == 32 or ch == 9 or ch == 10 or ch == 13:
            advance(s, w)
        else:
            mark(w)
            following = peek(s, get(w, 0) + 1)
            if ch == 47 and (following == 47 or following == 42):
                advance(s, w)
                advance(s, w)
                if following == 47:
                    while get(w, 0) < length(s) and get(w, 48) == 0 and peek(s, get(w, 0)) != 10 and peek(s, get(w, 0)) != 13:
                        advance(s, w)
                else:
                    depth = 1
                    while get(w, 0) < length(s) and get(w, 48) == 0 and depth > 0:
                        a = peek(s, get(w, 0))
                        b = peek(s, get(w, 0) + 1)
                        if a == 47 and b == 42:
                            advance(s, w)
                            advance(s, w)
                            depth = depth + 1
                        else:
                            if a == 42 and b == 47:
                                advance(s, w)
                                advance(s, w)
                                depth = depth - 1
                            else:
                                advance(s, w)
                    if depth != 0 and get(w, 48) == 0:
                        lex_fail(w, 1, 0)
            else:
                if identifier_start(ch) == 1:
                    advance(s, w)
                    while identifier_continue(peek(s, get(w, 0))) == 1:
                        advance(s, w)
                    token(o, w, keyword(s, get(w, 56), get(w, 0)), get(w, 56), get(w, 0))
                else:
                    if ch == 39:
                        advance(s, w)
                        if identifier_start(peek(s, get(w, 0))) != 1:
                            lex_fail(w, 9, 0)
                        else:
                            begin = get(w, 0)
                            while identifier_continue(peek(s, get(w, 0))) == 1:
                                advance(s, w)
                            token(o, w, 2, begin, get(w, 0))
                    else:
                        if ch >= 48 and ch <= 57:
                            number(s, o, w)
                        else:
                            if ch == 34:
                                string(s, o, w)
                            else:
                                kind = punctuation(ch, following)
                                if kind == 0:
                                    advance(s, w)
                                    if get(w, 48) == 0:
                                        lex_fail(w, 10, 0)
                                else:
                                    advance(s, w)
                                    if kind >= 512:
                                        advance(s, w)
                                    token(o, w, kind, get(w, 56), get(w, 0))
    if get(w, 48) == 0:
        mark(w)
        token(o, w, 0, get(w, 0), get(w, 0))
    return 0

def number(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    floating = False
    ch = peek(s, get(w, 0))
    marker = peek(s, get(w, 0) + 1)
    if ch == 48 and (marker == 120 or marker == 88 or marker == 98 or marker == 66 or marker == 111 or marker == 79):
        advance(s, w)
        advance(s, w)
        base = 16
        if marker == 98 or marker == 66:
            base = 2
        if marker == 111 or marker == 79:
            base = 8
        digits(s, w, base)
    else:
        digits(s, w, 10)
        if peek(s, get(w, 0)) == 46 and peek(s, get(w, 0) + 1) >= 48 and peek(s, get(w, 0) + 1) <= 57:
            floating = True
            advance(s, w)
            digits(s, w, 10)
        if peek(s, get(w, 0)) == 101 or peek(s, get(w, 0)) == 69:
            floating = True
            advance(s, w)
            if peek(s, get(w, 0)) == 43 or peek(s, get(w, 0)) == 45:
                advance(s, w)
            digits(s, w, 10)
    if get(w, 48) != 0:
        return 0
    if identifier_continue(peek(s, get(w, 0))) == 1:
        while identifier_continue(peek(s, get(w, 0))) == 1:
            advance(s, w)
        return lex_fail(w, 4, 0)
    i = get(w, 56)
    count = 0
    while i < get(w, 0):
        if peek(s, i) != 95:
            count = count + 1
        i = i + 1
    if count > 4096:
        return lex_fail(w, 5, 0)
    token(o, w, choose(floating, 4, 3), get(w, 56), get(w, 0))
    return 0

def digits(s:readbuf, w:mutbuf, base:u64) -> u64:
    if get(w, 48) != 0:
        return 0
    start = get(w, 0)
    separator = False
    ch = peek(s, get(w, 0))
    while ch == 95 or digit(ch) < base:
        advance(s, w)
        if ch == 95:
            if get(w, 0) == start + 1 or separator:
                return lex_fail(w, 2, 0)
            separator = True
        else:
            separator = False
        ch = peek(s, get(w, 0))
    if get(w, 0) == start or separator:
        return lex_fail(w, 3, 0)
    return 0

def string(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    advance(s, w)
    begin = get(w, 0)
    while get(w, 0) < length(s) and peek(s, get(w, 0)) != 34 and get(w, 48) == 0:
        ch = peek(s, get(w, 0))
        if ch == 92:
            mark(w)
            return lex_fail(w, 6, 1)
        if ch < 32:
            return lex_fail(w, 7, 1)
        advance(s, w)
    if get(w, 48) != 0:
        return 0
    if get(w, 0) == length(s):
        return lex_fail(w, 8, 0)
    end = get(w, 0)
    advance(s, w)
    token(o, w, 5, begin, end)
    return 0

def advance(s:readbuf, w:mutbuf) -> u64:
    at = get(w, 0)
    a = peek(s, at)
    count = 1
    if a >= 128:
        if a >= 194 and a <= 223:
            count = 2
        else:
            if a >= 224 and a <= 239:
                count = 3
            else:
                if a >= 240 and a <= 244:
                    count = 4
                else:
                    return lex_fail(w, 11, 0)
        b = peek(s, at + 1)
        if b < 128 or b > 191:
            return lex_fail(w, 11, 0)
        if count == 3 and ((a == 224 and b < 160) or (a == 237 and b >= 160)):
            return lex_fail(w, 11, 0)
        if count == 4 and ((a == 240 and b < 144) or (a == 244 and b >= 144)):
            return lex_fail(w, 11, 0)
        i = 2
        while i < count:
            b = peek(s, at + i)
            if b < 128 or b > 191:
                return lex_fail(w, 11, 0)
            i = i + 1
    put(w, 0, at + count)
    put(w, 8, get(w, 8) + 1)
    if a == 13:
        put(w, 16, get(w, 16) + 1)
        put(w, 24, 1)
        put(w, 32, 1)
    else:
        if a == 10:
            if get(w, 32) == 0:
                put(w, 16, get(w, 16) + 1)
            put(w, 24, 1)
        else:
            put(w, 24, get(w, 24) + 1)
        put(w, 32, 0)
    return 0

def mark(w:mutbuf) -> u64:
    put(w, 56, get(w, 0))
    put(w, 64, get(w, 8))
    put(w, 72, get(w, 16))
    put(w, 80, get(w, 24))
    return 0

def lex_fail(w:mutbuf, code:u64, extra:u64) -> u64:
    put(w, 48, code)
    put(w, 112, get(w, 8) + extra)
    return 0

def token(o:mutbuf, w:mutbuf, kind:u64, begin:u64, end:u64) -> u64:
    count = get(w, 40)
    if count >= 1048576:
        return lex_fail(w, 12, 0)
    if get(w, 104) == 1:
        at = count * 56
        put(o, at, kind)
        put(o, at + 8, get(w, 64))
        put(o, at + 16, get(w, 8))
        put(o, at + 24, get(w, 72))
        put(o, at + 32, get(w, 80))
        put(o, at + 40, begin)
        put(o, at + 48, end)
    put(w, 40, count + 1)
    return 0

def peek(s:readbuf, at:u64) -> u64:
    if at >= length(s):
        return 256
    return byte(s, at)

def identifier_start(ch:u64) -> u64:
    return choose((ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122) or ch == 95, 1, 0)

def identifier_continue(ch:u64) -> u64:
    return choose(identifier_start(ch) == 1 or (ch >= 48 and ch <= 57), 1, 0)

def digit(ch:u64) -> u64:
    if ch >= 48 and ch <= 57:
        return ch - 48
    if ch >= 65 and ch <= 70:
        return ch - 55
    if ch >= 97 and ch <= 102:
        return ch - 87
    return 256

def matches(s:readbuf, begin:u64, end:u64, expected:u64, second:u64, size:u64) -> u64:
    if end - begin != size:
        return 0
    i = 0
    while i < size:
        word = expected
        shift = i
        if i >= 8:
            word = second
            shift = i - 8
        if peek(s, begin + i) != ((word >> (shift * 8)) & 255):
            return 0
        i = i + 1
    return 1

def get(w:mutbuf, at:u64) -> u64:
    value = 0
    value = value | (byte(w, at + 0) << 0)
    value = value | (byte(w, at + 1) << 8)
    value = value | (byte(w, at + 2) << 16)
    value = value | (byte(w, at + 3) << 24)
    value = value | (byte(w, at + 4) << 32)
    value = value | (byte(w, at + 5) << 40)
    value = value | (byte(w, at + 6) << 48)
    value = value | (byte(w, at + 7) << 56)
    return value

def put(w:mutbuf, at:u64, value:u64) -> u64:
    store(w, at + 0, (value >> 0) & 255)
    store(w, at + 1, (value >> 8) & 255)
    store(w, at + 2, (value >> 16) & 255)
    store(w, at + 3, (value >> 24) & 255)
    store(w, at + 4, (value >> 32) & 255)
    store(w, at + 5, (value >> 40) & 255)
    store(w, at + 6, (value >> 48) & 255)
    store(w, at + 7, (value >> 56) & 255)
    return 0
'''


def source_program():
    text=SOURCE+'\ndef keyword(s:readbuf, begin:u64, end:u64) -> u64:\n'
    for i,word in enumerate(KEYWORD_ORDER):
        assert len(word)<=16
        raw=word.encode()
        text+=f'    if matches(s, begin, end, {int.from_bytes(raw[:8],"little")}, {int.from_bytes(raw[8:],"little")}, {len(word)}) == 1:\n        return {128+i}\n'
    text+='    return 1\n\ndef punctuation(a:u64, b:u64) -> u64:\n'
    for i,pair in enumerate(PAIR_ORDER):
        text+=f'    if a == {ord(pair[0])} and b == {ord(pair[1])}:\n        return {512+i}\n'
    for ch in '{}()[],:;=+-*/%!<>.&|^':
        text+=f'    if a == {ord(ch)}:\n        return {256+ord(ch)}\n'
    return text+'    return 0\n'


def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'source_lexer','functions':functions})


def main():
    p=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/source_lexer.hiaasm'
    p.write_text(render_assembly(document()));print(p.name,p.stat().st_size)


if __name__=='__main__':main()
