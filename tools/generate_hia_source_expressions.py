"""Author the full existing Hepta expression grammar as an explicit HIA stack.

The native parser emits a postfix construction arena. Python materialization is
an object bridge, never a Pratt parser. Cast/turbofish types are recognized by
the composed actual HIA type grammar and retain their exact byte ranges.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_source_types import source_program as types_program
from tools.generate_hia_source_lexer import KEYWORD_ORDER, PAIR_ORDER

MAGIC = 0x3152505845414948  # HIAEXPR1, little endian
WORKSPACE = 29184
SOURCE = r'''
def expression_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 29184 or length(s) > 8388608:
        return 4294967293
    if get(w, 8528) < 1 or get(w, 8528) > 128 or get(w, 8640) > 12 or get(w, 8648) > 1:
        return 4294967293
    expression_reset(s, o, w, 0)
    expression_parse(s, o, w)
    if get(w, 48) != 0 or get(w, 216) != 0 or get(w, 8592) != 0:
        return 4294967295
    count = get(w, 8536)
    size = 64 + count * 96
    if size > length(o):
        return 4294967294
    expression_reset(s, o, w, 1)
    expression_parse(s, o, w)
    put(o, 0, @MAGIC@)
    put(o, 8, count)
    put(o, 16, size)
    put(o, 24, get(w, 184))
    put(o, 32, get(w, 192))
    put(o, 40, 1)
    put(o, 48, get(w, 8552))
    put(o, 56, 0)
    return size

def expression_reset(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u64:
    type_reset(w, 0, 0)
    put(w, 8520, 0)
    put(w, 8536, 0)
    put(w, 8544, phase)
    put(w, 8552, 0)
    put(w, 8592, 0)
    type_next(s, o, w)
    expression_push(w, get(w, 8640), get(w, 8648))
    return 0

def expression_error(w:mutbuf, code:u64) -> u64:
    if get(w, 8592) == 0 and get(w, 216) == 0 and get(w, 48) == 0:
        put(w, 8592, code)
        put(w, 8600, get(w, 152))
        put(w, 8608, get(w, 160))
        put(w, 8616, get(w, 168))
        put(w, 8624, get(w, 176))
        put(w, 8632, get(w, 128))
    return 0

def expression_ok(w:mutbuf) -> bool:
    return get(w, 8592) == 0 and get(w, 216) == 0 and get(w, 48) == 0

def expression_expect(s:readbuf, o:mutbuf, w:mutbuf, kind:u64, code:u64) -> u64:
    if expression_ok(w) == False:
        return 0
    if get(w, 128) != kind:
        return expression_error(w, code)
    return type_consume(s, o, w)

def expression_frame(w:mutbuf) -> u64:
    return 8704 + (get(w, 8520) - 1) * 160

def expression_push(w:mutbuf, minimum:u64, allow:u64) -> u64:
    depth = get(w, 8520)
    if depth >= get(w, 8528):
        return expression_error(w, 1)
    at = 8704 + depth * 160
    i = 0
    while i < 160:
        put(w, at + i, 0)
        i = i + 8
    put(w, at + 8, minimum)
    put(w, at + 16, allow)
    put(w, at + 32, get(w, 152))
    put(w, at + 40, get(w, 168))
    put(w, at + 48, get(w, 176))
    put(w, 8520, depth + 1)
    return 0

def expression_emit(o:mutbuf, w:mutbuf, kind:u64, arity:u64, start:u64, end:u64, line:u64, column:u64, begin:u64, finish:u64, aux:u64) -> u64:
    count = get(w, 8536)
    if count >= 2097152:
        return expression_error(w, 13)
    if get(w, 8544) == 1:
        at = 64 + count * 96
        put(o, at, kind)
        put(o, at + 8, arity)
        put(o, at + 16, start)
        put(o, at + 24, end)
        put(o, at + 32, line)
        put(o, at + 40, column)
        put(o, at + 48, begin)
        put(o, at + 56, finish)
        put(o, at + 64, aux)
        put(o, at + 72, 0)
        put(o, at + 80, 0)
        put(o, at + 88, 0)
    put(w, 8536, count + 1)
    return 0

def expression_current(o:mutbuf, w:mutbuf, kind:u64, arity:u64, aux:u64) -> u64:
    return expression_emit(o, w, kind, arity, get(w, 152), get(w, 160), get(w, 168), get(w, 176), get(w, 136), get(w, 144), aux)

def expression_complete(o:mutbuf, w:mutbuf, kind:u64, arity:u64, begin:u64, finish:u64, aux:u64) -> u64:
    at = expression_frame(w)
    expression_emit(o, w, kind, arity, get(w, at + 32), get(w, 184), get(w, at + 40), get(w, at + 48), begin, finish, aux)
    put(w, at + 24, kind)
    put(w, at, 1)
    return 0

def expression_precedence(kind:u64) -> u64:
    if kind == 519:
        return 1
    if kind == 518:
        return 2
    if kind == 380:
        return 3
    if kind == 350:
        return 4
    if kind == 294:
        return 5
    if kind == 514 or kind == 515:
        return 6
    if kind == 316 or kind == 516 or kind == 318 or kind == 517:
        return 7
    if kind == 520 or kind == 521:
        return 8
    if kind == 299 or kind == 301:
        return 9
    if kind == 298 or kind == 303 or kind == 293:
        return 10
    return 18446744073709551615

def expression_type(s:readbuf, o:mutbuf, w:mutbuf, event:u64) -> u64:
    begin = get(w, 136)
    start = get(w, 152)
    line = get(w, 168)
    column = get(w, 176)
    remaining = get(w, 8528) - get(w, 8520)
    put(w, 224, remaining)
    put(w, 200, 0)
    put(w, 208, 0)
    put(w, 232, 0)
    type_parse(s, o, w, 18446744073709551615, 1)
    if expression_ok(w):
        if event == 7:
            expression_emit(o, w, 7, 0, start, get(w, 184), line, column, begin, get(w, 192), remaining)
        else:
            expression_complete(o, w, 12, 1, begin, get(w, 192), remaining)
    return 0

def expression_name(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = expression_frame(w)
    expression_current(o, w, 6, 0, 0)
    type_consume(s, o, w)
    put(w, at + 72, 1)
    put(w, at + 80, 0)
    while get(w, 128) == 522 and expression_ok(w):
        type_consume(s, o, w)
        if get(w, 128) == 316:
            if get(w, at + 80) != 0:
                expression_error(w, 12)
            else:
                type_consume(s, o, w)
                expression_type(s, o, w, 7)
                put(w, at + 80, get(w, at + 80) + 1)
                while get(w, 128) == 300 and expression_ok(w):
                    type_consume(s, o, w)
                    expression_type(s, o, w, 7)
                    put(w, at + 80, get(w, at + 80) + 1)
                type_close(s, o, w)
        else:
            if get(w, 128) != 1:
                expression_error(w, 11)
            else:
                expression_current(o, w, 17, 0, 0)
                type_consume(s, o, w)
                put(w, at + 72, get(w, at + 72) + 1)
    if expression_ok(w):
        expression_complete(o, w, 8, get(w, at + 80), 0, 0, get(w, at + 72))
        put(w, at + 24, 6)
        if get(w, at + 16) == 1 and get(w, 128) == 379:
            type_consume(s, o, w)
            put(w, at + 64, 0)
            if get(w, 128) == 381:
                type_consume(s, o, w)
                expression_complete(o, w, 16, 0, 0, 0, 0)
            else:
                expression_struct_field(s, o, w)
    return 0

def expression_struct_field(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = expression_frame(w)
    if get(w, 128) != 1 and get(w, 128) != @MATCH@:
        return expression_error(w, 8)
    put(w, at + 88, get(w, 136))
    put(w, at + 96, get(w, 144))
    put(w, at + 104, get(w, 152))
    put(w, at + 112, get(w, 160))
    put(w, at + 120, get(w, 168))
    put(w, at + 128, get(w, 176))
    type_consume(s, o, w)
    expression_expect(s, o, w, 314, 9)
    if expression_ok(w):
        put(w, at, 8)
        expression_push(w, 0, 1)
    return 0

def expression_prefix(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = expression_frame(w)
    kind = get(w, 128)
    if kind == 3 or kind == 4 or kind == @TRUE@ or kind == @FALSE@:
        event = choose(kind == 3, 1, choose(kind == 4, 2, 3))
        expression_current(o, w, event, 0, kind)
        type_consume(s, o, w)
        put(w, at + 24, event)
        put(w, at, 1)
    elif kind == 301 or kind == 289 or kind == @READ@ or kind == @MUT@ or kind == @MOVE@:
        put(w, at + 56, kind)
        type_consume(s, o, w)
        put(w, at, 2)
        expression_push(w, 12, get(w, at + 16))
    elif kind == 1:
        expression_name(s, o, w)
    elif kind == 296:
        type_consume(s, o, w)
        put(w, at, 3)
        expression_push(w, 0, 1)
    elif kind == 347:
        type_consume(s, o, w)
        put(w, at + 64, 0)
        if get(w, 128) == 349:
            type_consume(s, o, w)
            expression_complete(o, w, 14, 0, 0, 0, 0)
        else:
            put(w, at, 4)
            expression_push(w, 0, 1)
    else:
        expression_error(w, choose(kind == 5, 2, 3))
        if kind != 0:
            type_consume(s, o, w)
    return 0

def expression_postfix(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = expression_frame(w)
    kind = get(w, 128)
    if kind == 296:
        if get(w, at + 24) != 6:
            return expression_error(w, 4)
        type_consume(s, o, w)
        put(w, at + 64, 0)
        if get(w, 128) == 297:
            type_consume(s, o, w)
            expression_complete(o, w, 9, 0, 0, 0, 0)
        else:
            put(w, at, 5)
            expression_push(w, 0, 1)
    elif kind == 347:
        type_consume(s, o, w)
        put(w, at, 6)
        expression_push(w, 0, 1)
    elif kind == 302:
        type_consume(s, o, w)
        if get(w, 128) != 1 and get(w, 128) != @MATCH@:
            return expression_error(w, 8)
        begin = get(w, 136)
        finish = get(w, 144)
        type_consume(s, o, w)
        expression_complete(o, w, 11, 1, begin, finish, 0)
    elif kind == @AS@ and get(w, at + 8) <= 11:
        type_consume(s, o, w)
        expression_type(s, o, w, 12)
    else:
        precedence = expression_precedence(kind)
        if precedence == 18446744073709551615 or precedence < get(w, at + 8):
            put(w, 8552, get(w, at + 24))
            put(w, 8520, get(w, 8520) - 1)
        else:
            put(w, at + 56, kind)
            type_consume(s, o, w)
            put(w, at, 7)
            expression_push(w, precedence + 1, get(w, at + 16))
    return 0

def expression_list_finish(s:readbuf, o:mutbuf, w:mutbuf, call:u64) -> u64:
    at = expression_frame(w)
    count = get(w, at + 64) + 1
    put(w, at + 64, count)
    closer = choose(call == 1, 297, 349)
    again = 0
    if get(w, 128) == 300:
        type_consume(s, o, w)
        if get(w, 128) != closer:
            again = 1
    if again == 1:
        expression_push(w, 0, 1)
    else:
        expression_expect(s, o, w, closer, choose(call == 1, 6, 7))
        if expression_ok(w):
            expression_complete(o, w, choose(call == 1, 9, 14), count, 0, 0, 0)
    return 0

def expression_struct_finish(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = expression_frame(w)
    expression_emit(o, w, 15, 1, get(w, at + 104), get(w, at + 112), get(w, at + 120), get(w, at + 128), get(w, at + 88), get(w, at + 96), 0)
    put(w, at + 64, get(w, at + 64) + 1)
    again = 0
    if get(w, 128) == 300:
        type_consume(s, o, w)
        if get(w, 128) != 381:
            again = 1
    if again == 1:
        expression_struct_field(s, o, w)
    else:
        expression_expect(s, o, w, 381, 10)
        if expression_ok(w):
            expression_complete(o, w, 16, get(w, at + 64), 0, 0, 0)
    return 0

def expression_parse(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    while get(w, 8520) != 0 and expression_ok(w):
        at = expression_frame(w)
        state = get(w, at)
        if state == 0:
            expression_prefix(s, o, w)
        elif state == 1:
            expression_postfix(s, o, w)
        elif state == 2:
            expression_complete(o, w, 4, 1, 0, 0, get(w, at + 56))
        elif state == 3:
            expression_expect(s, o, w, 297, 6)
            if expression_ok(w):
                expression_complete(o, w, 13, 1, 0, 0, 0)
                put(w, at + 24, get(w, 8552))
        elif state == 4:
            expression_list_finish(s, o, w, 0)
        elif state == 5:
            expression_list_finish(s, o, w, 1)
        elif state == 6:
            expression_expect(s, o, w, 349, 7)
            if expression_ok(w):
                expression_complete(o, w, 10, 2, 0, 0, 0)
        elif state == 7:
            expression_complete(o, w, 5, 2, 0, 0, get(w, at + 56))
        else:
            expression_struct_finish(s, o, w)
    return 0
'''


def source_program():
    source = SOURCE.replace('@MAGIC@', str(MAGIC))
    for word in ('match', 'true', 'false', 'read', 'mut', 'move', 'as'):
        source = source.replace('@' + word.upper() + '@', str(128 + KEYWORD_ORDER.index(word)))
    types = types_program().replace(
        'if kind == 521 or kind == 517:\n',
        'if kind == 521 or kind == 517:\n        expression_current(o, w, 18, 0, kind)\n', 1)
    combined = ast.parse(source + '\n' + types)
    definitions = {node.name: node for node in combined.body}
    # Only grammar/scanning dependencies: magnitude/float conversion has its own
    # pinned HIA library and must not consume parser compiler capacity here.
    needed = {'expression_main'}
    pending = list(needed)
    while pending:
        current = definitions[pending.pop()]
        for node in ast.walk(current):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                name = node.func.id
                if name in definitions and name not in needed:
                    needed.add(name); pending.append(name)
    return '\n\n'.join(ast.unparse(node) for node in combined.body if node.name in needed)


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
    data = document()
    path.write_text(render_assembly(data))
    print({'bytes': path.stat().st_size, 'functions': len(data['functions']),
           'blocks': sum(len(f['blocks']) for f in data['functions']),
           'instructions': sum(len(b['ops']) for f in data['functions'] for b in f['blocks'])})


if __name__ == '__main__': main()
