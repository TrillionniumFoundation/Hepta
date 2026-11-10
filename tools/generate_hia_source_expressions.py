"""Author the existing source expression grammar in bounded executable HIA.

The type/scanner helpers are composed from their actual HIA authoring source.
This is an opt-in application, not a rewrite of declarations or semantic passes.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_source_types import source_program as type_program
from tools.generate_hia_source_lexer import KEYWORD_ORDER, PAIR_ORDER

MAGIC = int.from_bytes(b'HIAEXP01', 'little')
SOURCE = r'''
def expression_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 25024 + ((length(s) + 7) >> 3) or length(s) > 8388608:
        return 4294967293
    limit = get(w, 8520)
    minimum = get(w, 8544)
    allow = get(w, 8552)
    mode = get(w, 8616)
    if limit < 1 or limit > 128 or minimum > 128 or allow > 1 or mode > 1:
        return 4294967293
    i = 25024
    while i < length(w):
        store(w, i, 0)
        i = i + 1
    expr_reset(w, 0, 0)
    expr_first(s, o, w)
    root = expr_parse(s, o, w, minimum, allow)
    if mode == 0 and (get(w, 48) != 0 or get(w, 216) != 0):
        return 4294967295
    count = get(w, 200)
    names = get(w, 208)
    base = 64 + count * 128
    used = base + names
    if used > length(o):
        return 4294967294
    expr_reset(w, 1, base)
    expr_first(s, o, w)
    root = expr_parse(s, o, w, minimum, allow)
    put(o, 0, @MAGIC@ ^ mode)
    put(o, 8, count)
    put(o, 16, base)
    put(o, 24, used)
    put(o, 32, get(w, 184))
    put(o, 40, get(w, 192))
    put(o, 48, 1 + mode)
    put(o, 56, choose(mode == 0, root, get(w, 216)))
    return used

def expr_reset(w:mutbuf, phase:u64, base:u64) -> u64:
    type_reset(w, phase, base)
    put(w, 8512, 0)
    put(w, 8528, 0)
    put(w, 8536, 0)
    put(w, 8560, 0)
    return 0

def expr_first(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    type_next(s, o, w)
    seed = get(w, 8600)
    if seed != 0 and seed != get(w, 128) and get(w, 48) == 0:
        if get(w, 136) != 0 or get(w, 144) != 2 or (seed != 317 and seed != 318) or seed != 256 + byte(s, 0):
            return type_error(w, 112)
        put(w, 0, get(w, 0) - 1)
        put(w, 8, get(w, 8) - 1)
        put(w, 24, get(w, 24) - 1)
        put(w, 144, get(w, 144) - 1)
        put(w, 160, get(w, 160) - 1)
        put(w, 128, seed)
    return 0

def expr_frame(w:mutbuf) -> u64:
    return 8640 + (get(w, 8512) - 1) * 128

def expr_push(w:mutbuf, minimum:u64, allow:u64) -> u64:
    level = get(w, 8512)
    if level >= get(w, 8520):
        return type_error(w, 1)
    at = 8640 + level * 128
    field = 0
    while field < 128:
        put(w, at + field, 0)
        field = field + 8
    put(w, at + 24, minimum)
    put(w, at + 32, allow)
    put(w, 8512, level + 1)
    return 0

def expr_attach(o:mutbuf, w:mutbuf, parent:u64, child:u64) -> u64:
    type_set(o, w, child, 8, parent)
    return type_link(o, w, parent, child)

def expr_span(o:mutbuf, w:mutbuf, node:u64, at:u64, end:u64) -> u64:
    type_set(o, w, node, 80, get(w, at + 40))
    type_set(o, w, node, 88, end)
    type_set(o, w, node, 96, get(w, at + 48))
    type_set(o, w, node, 104, get(w, at + 56))
    return 0

def expr_mark(o:mutbuf, w:mutbuf, node:u64) -> u64:
    type_set(o, w, node, 80, get(w, 152))
    type_set(o, w, node, 88, get(w, 160))
    type_set(o, w, node, 96, get(w, 168))
    type_set(o, w, node, 104, get(w, 176))
    return 0

def expr_text(s:readbuf, o:mutbuf, w:mutbuf, node:u64) -> u64:
    begin = get(w, 136)
    end = get(w, 144)
    offset = type_text(s, o, w, begin, end)
    type_set(o, w, node, 40, offset)
    type_set(o, w, node, 48, end - begin)
    return expr_mark(o, w, node)

def expr_error_at(w:mutbuf, code:u64, start:u64, end:u64, line:u64, column:u64) -> u64:
    if get(w, 48) == 0 and get(w, 216) == 0:
        put(w, 8560, 1)
        put(w, 8568, start)
        put(w, 8576, end)
        put(w, 8584, line)
        put(w, 8592, column)
        type_error(w, code)
    return 0

def expr_type(s:readbuf, o:mutbuf, w:mutbuf, parent:u64) -> u64:
    put(w, 224, get(w, 8520) - get(w, 8512))
    return type_parse(s, o, w, parent, 1)

def expr_field(w:mutbuf) -> u64:
    if get(w, 128) != 1 and get(w, 128) != @MATCH@:
        return type_error(w, 102)
    return 0

def expr_finish(o:mutbuf, w:mutbuf) -> u64:
    at = expr_frame(w)
    put(w, 8528, get(w, at + 8))
    put(w, 8536, get(w, at + 16))
    put(w, 8512, get(w, 8512) - 1)
    return 0

def expr_parse(s:readbuf, o:mutbuf, w:mutbuf, minimum:u64, allow:u64) -> u64:
    expr_push(w, minimum, allow)
    while get(w, 8512) != 0 and get(w, 216) == 0 and get(w, 48) == 0:
        at = expr_frame(w)
        state = get(w, at)
        if state == 0:
            kind = get(w, 128)
            put(w, at + 40, get(w, 152))
            put(w, at + 48, get(w, 168))
            put(w, at + 56, get(w, 176))
            if kind == 3 or kind == 4 or kind == @TRUE@ or kind == @FALSE@:
                tag = choose(kind == 3, 16, choose(kind == 4, 17, 18))
                node = type_node(o, w, tag, 18446744073709551615)
                put(w, at + 8, node)
                put(w, at + 16, tag)
                expr_mark(o, w, node)
                type_set(o, w, node, 56, get(w, 136))
                type_set(o, w, node, 64, get(w, 144) - get(w, 136))
                type_set(o, w, node, 72, kind)
                type_consume(s, o, w)
                put(w, at, 1)
            elif kind == 301 or kind == 289 or kind == @READ@ or kind == @MUT@ or kind == @MOVE@:
                node = type_node(o, w, 19, 18446744073709551615)
                put(w, at + 8, node)
                put(w, at + 16, 19)
                type_set(o, w, node, 72, kind)
                type_consume(s, o, w)
                put(w, at, 2)
                expr_push(w, 12, get(w, at + 32))
            elif kind == 1:
                node = type_node(o, w, 20, 18446744073709551615)
                put(w, at + 8, node)
                put(w, at + 16, 20)
                part = type_node(o, w, 28, node)
                expr_text(s, o, w, part)
                type_link(o, w, node, part)
                put(w, at + 112, 1)
                type_consume(s, o, w)
                put(w, at, 10)
            elif kind == 296:
                type_consume(s, o, w)
                put(w, at, 3)
                expr_push(w, 0, 1)
            elif kind == 347:
                node = type_node(o, w, 27, 18446744073709551615)
                put(w, at + 8, node)
                put(w, at + 16, 27)
                put(w, at + 72, 349)
                type_consume(s, o, w)
                put(w, at, 7)
            else:
                start = get(w, 152)
                end = get(w, 160)
                line = get(w, 168)
                column = get(w, 176)
                type_consume(s, o, w)
                expr_error_at(w, choose(kind == 5, 107, 108), start, end, line, column)
        elif state == 1:
            kind = get(w, 128)
            left = get(w, at + 8)
            if kind == 296:
                if get(w, at + 16) != 20:
                    type_error(w, 101)
                else:
                    type_set(o, w, left, 0, 21)
                    put(w, at + 16, 21)
                    put(w, at + 72, 297)
                    type_consume(s, o, w)
                    put(w, at, 7)
            elif kind == 347:
                node = type_node(o, w, 22, 18446744073709551615)
                expr_attach(o, w, node, left)
                put(w, at + 8, node)
                put(w, at + 16, 22)
                type_consume(s, o, w)
                put(w, at, 5)
                expr_push(w, 0, 1)
            elif kind == 302:
                type_consume(s, o, w)
                expr_field(w)
                if get(w, 216) == 0:
                    node = type_node(o, w, 23, 18446744073709551615)
                    expr_attach(o, w, node, left)
                    expr_text(s, o, w, node)
                    put(w, at + 8, node)
                    put(w, at + 16, 23)
                    type_consume(s, o, w)
                    expr_span(o, w, node, at, get(w, 184))
            elif kind == @AS@ and get(w, at + 24) <= 11:
                node = type_node(o, w, 24, 18446744073709551615)
                expr_attach(o, w, node, left)
                put(w, at + 8, node)
                put(w, at + 16, 24)
                type_consume(s, o, w)
                expr_type(s, o, w, node)
                expr_span(o, w, node, at, get(w, 184))
            else:
                precedence = expr_precedence(kind)
                if precedence == 18446744073709551615 or precedence < get(w, at + 24):
                    expr_finish(o, w)
                else:
                    node = type_node(o, w, 25, 18446744073709551615)
                    expr_attach(o, w, node, left)
                    type_set(o, w, node, 72, kind)
                    put(w, at + 8, node)
                    put(w, at + 16, 25)
                    type_consume(s, o, w)
                    put(w, at, 4)
                    expr_push(w, precedence + 1, get(w, at + 32))
        elif state == 2 or state == 4:
            node = get(w, at + 8)
            expr_attach(o, w, node, get(w, 8528))
            expr_span(o, w, node, at, get(w, 184))
            put(w, at, 1)
        elif state == 3:
            type_expect(s, o, w, 297, 104)
            node = get(w, 8528)
            put(w, at + 8, node)
            put(w, at + 16, get(w, 8536))
            expr_span(o, w, node, at, get(w, 184))
            put(w, at, 1)
        elif state == 5:
            node = get(w, at + 8)
            expr_attach(o, w, node, get(w, 8528))
            type_expect(s, o, w, 349, 105)
            expr_span(o, w, node, at, get(w, 184))
            put(w, at, 1)
        elif state == 7:
            if get(w, 128) == get(w, at + 72):
                type_consume(s, o, w)
                expr_span(o, w, get(w, at + 8), at, get(w, 184))
                put(w, at, 1)
            else:
                put(w, at, 8)
                expr_push(w, 0, 1)
        elif state == 8:
            expr_attach(o, w, get(w, at + 8), get(w, 8528))
            if get(w, 128) == 300:
                type_consume(s, o, w)
                put(w, at, 7)
            else:
                close = get(w, at + 72)
                type_expect(s, o, w, close, choose(close == 297, 104, 105))
                expr_span(o, w, get(w, at + 8), at, get(w, 184))
                put(w, at, 1)
        elif state == 9:
            if get(w, 128) == 381:
                type_consume(s, o, w)
                expr_span(o, w, get(w, at + 8), at, get(w, 184))
                put(w, at, 1)
            else:
                expr_field(w)
                if get(w, 216) == 0:
                    node = get(w, at + 8)
                    field = type_node(o, w, 29, node)
                    expr_text(s, o, w, field)
                    type_link(o, w, node, field)
                    type_consume(s, o, w)
                    type_expect(s, o, w, 314, 103)
                    put(w, at, 13)
                    if get(w, 216) == 0:
                        expr_push(w, 0, 1)
        elif state == 10:
            node = get(w, at + 8)
            if get(w, 128) == 522:
                type_consume(s, o, w)
                if get(w, 128) == 316:
                    if get(w, at + 104) != 0:
                        type_error(w, 109)
                    else:
                        type_consume(s, o, w)
                        put(w, at, 11)
                elif get(w, 128) != 1:
                    type_error(w, 110)
                else:
                    part = type_node(o, w, 28, node)
                    expr_text(s, o, w, part)
                    type_link(o, w, node, part)
                    put(w, at + 112, get(w, at + 112) + 1)
                    type_consume(s, o, w)
            else:
                type_set(o, w, node, 112, get(w, 184))
                type_set(o, w, node, 120, get(w, at + 112))
                expr_span(o, w, node, at, get(w, 184))
                if get(w, at + 32) != 0 and get(w, 128) == 379:
                    type_set(o, w, node, 0, 26)
                    put(w, at + 16, 26)
                    type_consume(s, o, w)
                    put(w, at, 9)
                else:
                    put(w, at, 1)
        elif state == 11:
            expr_type(s, o, w, get(w, at + 8))
            put(w, at + 104, 1)
            put(w, at, 12)
        elif state == 12:
            if get(w, 128) == 300:
                type_consume(s, o, w)
                put(w, at, 11)
            else:
                type_close(s, o, w)
                put(w, at, 10)
        elif state == 13:
            expr_attach(o, w, get(w, at + 8), get(w, 8528))
            if get(w, 128) == 300:
                type_consume(s, o, w)
                put(w, at, 9)
            else:
                type_expect(s, o, w, 381, 106)
                expr_span(o, w, get(w, at + 8), at, get(w, 184))
                put(w, at, 1)
        else:
            type_error(w, 111)
    return get(w, 8528)
'''


def token_kind(value):
    if value in KEYWORD_ORDER: return 128 + KEYWORD_ORDER.index(value)
    if value in PAIR_ORDER: return 512 + PAIR_ORDER.index(value)
    return 256 + ord(value)


def source_program():
    source = SOURCE.replace('@MAGIC@', str(MAGIC))
    for word in ('true', 'false', 'read', 'mut', 'move', 'as', 'match'):
        source = source.replace('@' + word.upper() + '@', str(token_kind(word)))
    source += '\ndef expr_precedence(kind:u64) -> u64:\n'
    from hepta.parser import _BINARY
    for operator, precedence in _BINARY.items():
        source += f'    if kind == {token_kind(operator)}:\n        return {precedence}\n'
    source += '    return 18446744073709551615\n'
    original = type_program()
    for node in ast.parse(original).body:
        if node.name == 'type_main': continue
        text = ast.get_source_segment(original, node)
        if node.name in ('type_set', 'type_node', 'type_link'):
            text = text.replace('* 80', '* 128').replace('field < 80', 'field < 128')
        if node.name == 'type_consume':
            # String token value ranges exclude the quotes; the scanner cursor
            # still reports the complete consumed token for diagnostic replay.
            text = text.replace('put(w, 192, get(w, 144))', 'put(w, 192, get(w, 0))')
        if node.name == 'type_parse':
            text = text.replace('    put(w, 304, 0)', '    root = get(w, 200)\n    put(w, 304, 0)', 1)
            text = text.rsplit('    return 0', 1)[0] + '    return root'
        if node.name == 'type_close':
            # Sideband records prevent the foreign cursor bridge from
            # splitting an actual binary >> or >= expression operator.
            text = text.replace('    if kind == 521 or kind == 517:\n',
                '    if kind == 521 or kind == 517:\n'
                '        bit_at = 25024 + (get(w, 136) >> 3)\n'
                '        store(w, bit_at, byte(w, bit_at) | (1 << (get(w, 136) & 7)))\n'
                '        node = type_node(o, w, 30, 18446744073709551615)\n'
                '        type_set(o, w, node, 56, get(w, 136))\n'
                '        type_set(o, w, node, 64, 2)\n'
                '        type_set(o, w, node, 72, kind)\n')
        source += '\n' + text + '\n'
    return source


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    assert len(names) == len(nodes)
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'source_expressions', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/source_expressions.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__': main()
