"""Author the complete existing source type grammar as executable HIA.

This application parses a type prefix, not declarations or expressions. Its
scanner is composed from the actual source lexer's HIA authoring definitions.
The foreign bridge may construct Type objects but must not recognize grammar.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_source_lexer import source_program as lexer_program, KEYWORD_ORDER

MAGIC = 5208780291693556273
SOURCE = r'''
def type_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 8512 or length(s) > 8388608:
        return 4294967293
    limit = get(w, 224)
    if limit < 1 or limit > 128:
        return 4294967293
    type_reset(w, 0, 0)
    type_next(s, o, w)
    root = type_parse(s, o, w, 18446744073709551615, 1)
    if get(w, 48) != 0 or get(w, 216) != 0:
        return 4294967295
    count = get(w, 200)
    names = get(w, 208)
    base = 64 + count * 80
    used = base + names
    if used > length(o):
        return 4294967294
    type_reset(w, 1, base)
    type_next(s, o, w)
    root = type_parse(s, o, w, 18446744073709551615, 1)
    put(o, 0, @MAGIC@)
    put(o, 8, count)
    put(o, 16, base)
    put(o, 24, used)
    put(o, 32, get(w, 184))
    put(o, 40, get(w, 192))
    put(o, 48, 1)
    put(o, 56, root)
    return used

def type_reset(w:mutbuf, phase:u64, base:u64) -> u64:
    initialize(w, 0)
    put(w, 184, 0)
    put(w, 192, 0)
    put(w, 200, 0)
    put(w, 208, 0)
    put(w, 216, 0)
    put(w, 232, phase)
    put(w, 248, base)
    return 0

def type_next(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    put(w, 40, 0)
    scan_next(s, o, w)
    return 0

def type_consume(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    put(w, 184, get(w, 160))
    put(w, 192, get(w, 144))
    type_next(s, o, w)
    return 0

def type_error(w:mutbuf, code:u64) -> u64:
    if get(w, 216) == 0 and get(w, 48) == 0:
        put(w, 216, code)
    return 0

def type_expect(s:readbuf, o:mutbuf, w:mutbuf, kind:u64, code:u64) -> u64:
    if get(w, 48) != 0 or get(w, 216) != 0:
        return 0
    if get(w, 128) != kind:
        return type_error(w, code)
    return type_consume(s, o, w)

def type_close(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, 48) != 0 or get(w, 216) != 0:
        return 0
    kind = get(w, 128)
    if kind == 521 or kind == 517:
        put(w, 184, get(w, 152) + 1)
        put(w, 192, get(w, 136) + 1)
        put(w, 128, choose(kind == 521, 318, 317))
        put(w, 136, get(w, 136) + 1)
        put(w, 152, get(w, 152) + 1)
        put(w, 176, get(w, 176) + 1)
        return 0
    return type_expect(s, o, w, 318, 8)

def type_set(o:mutbuf, w:mutbuf, node:u64, field:u64, value:u64) -> u64:
    if get(w, 232) == 1:
        put(o, 64 + node * 80 + field, value)
    return 0

def type_node(o:mutbuf, w:mutbuf, kind:u64, parent:u64) -> u64:
    node = get(w, 200)
    if node >= 1048576:
        type_error(w, 10)
        return 0
    put(w, 200, node + 1)
    if get(w, 232) == 1:
        at = 64 + node * 80
        field = 0
        while field < 80:
            put(o, at + field, 0)
            field = field + 8
        put(o, at, kind)
        put(o, at + 8, parent)
        put(o, at + 16, 18446744073709551615)
        put(o, at + 24, 18446744073709551615)
        put(o, at + 32, 18446744073709551615)
    return node

def type_link(o:mutbuf, w:mutbuf, parent:u64, child:u64) -> u64:
    if get(w, 232) == 1:
        at = 64 + parent * 80
        if get(o, at + 16) == 18446744073709551615:
            put(o, at + 16, child)
        else:
            previous = get(o, at + 24)
            put(o, 64 + previous * 80 + 32, child)
        put(o, at + 24, child)
    return 0

def type_text(s:readbuf, o:mutbuf, w:mutbuf, begin:u64, end:u64) -> u64:
    offset = get(w, 208)
    if get(w, 232) == 1:
        i = begin
        while i < end:
            store(o, get(w, 248) + offset + i - begin, byte(s, i))
            i = i + 1
    put(w, 208, offset + end - begin)
    return offset

def type_colons(o:mutbuf, w:mutbuf) -> u64:
    offset = get(w, 208)
    if get(w, 232) == 1:
        store(o, get(w, 248) + offset, 58)
        store(o, get(w, 248) + offset + 1, 58)
    put(w, 208, offset + 2)
    return 0

def type_lifetime(s:readbuf, o:mutbuf, w:mutbuf, parent:u64, code:u64) -> u64:
    if get(w, 128) != 2:
        return type_error(w, code)
    node = type_node(o, w, 8, parent)
    begin = get(w, 136)
    end = get(w, 144)
    offset = type_text(s, o, w, begin, end)
    type_set(o, w, node, 40, offset)
    type_set(o, w, node, 48, end - begin)
    type_link(o, w, parent, node)
    return type_consume(s, o, w)

def type_frame(w:mutbuf) -> u64:
    return 320 + (get(w, 304) - 1) * 64

def type_push(w:mutbuf, parent:u64) -> u64:
    level = get(w, 304)
    if level >= get(w, 224):
        return type_error(w, 1)
    at = 320 + level * 64
    field = 0
    while field < 64:
        put(w, at + field, 0)
        field = field + 8
    put(w, at + 16, parent)
    put(w, 304, level + 1)
    return 0

def type_done(o:mutbuf, w:mutbuf) -> u64:
    at = type_frame(w)
    node = get(w, at + 8)
    parent = get(w, at + 16)
    if parent != 18446744073709551615:
        type_link(o, w, parent, node)
    put(w, 304, get(w, 304) - 1)
    return 0

def type_arity(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    at = type_frame(w)
    if get(w, at + 48) == 0 and get(w, at + 24) != 1 and get(w, 216) == 0 and get(w, 48) == 0:
        begin = get(w, at + 32)
        end = get(w, at + 40)
        builtin = matches(s, begin, end, @BUFFER@, 0, 6)
        builtin = builtin | matches(s, begin, end, @TASK@, 0, 4)
        builtin = builtin | matches(s, begin, end, @SENDER@, 0, 6)
        if builtin != 0:
            type_error(w, 9)
            put(w, 280, begin)
            put(w, 288, end)
    return type_done(o, w)

def type_parse(s:readbuf, o:mutbuf, w:mutbuf, parent:u64, depth:u64) -> u64:
    put(w, 304, 0)
    type_push(w, parent)
    while get(w, 304) != 0 and get(w, 216) == 0 and get(w, 48) == 0:
        at = type_frame(w)
        state = get(w, at)
        if state == 0:
            kind = get(w, 128)
            parent = get(w, at + 16)
            if kind == @READ@ or kind == @MUT@:
                node = type_node(o, w, choose(kind == @READ@, 4, 5), parent)
                put(w, at + 8, node)
                type_consume(s, o, w)
                type_lifetime(s, o, w, node, 2)
                put(w, at, 1)
                if get(w, 216) == 0 and get(w, 48) == 0:
                    type_push(w, node)
            elif kind == 347:
                node = type_node(o, w, 2, parent)
                put(w, at + 8, node)
                type_consume(s, o, w)
                put(w, at, 2)
                type_push(w, node)
            elif kind == @RAW@:
                type_consume(s, o, w)
                mode = get(w, 128)
                if mode != @CONST@ and mode != @MUT@:
                    type_error(w, 5)
                else:
                    node = type_node(o, w, choose(mode == @CONST@, 6, 7), parent)
                    put(w, at + 8, node)
                    type_consume(s, o, w)
                    put(w, at, 1)
                    type_push(w, node)
            elif kind == 1:
                node = type_node(o, w, 1, parent)
                put(w, at + 8, node)
                begin = get(w, 136)
                end = get(w, 144)
                put(w, at + 32, begin)
                put(w, at + 40, end)
                offset = type_text(s, o, w, begin, end)
                put(w, at + 56, offset)
                type_consume(s, o, w)
                while get(w, 128) == 522 and get(w, 216) == 0 and get(w, 48) == 0:
                    put(w, at + 48, 1)
                    type_consume(s, o, w)
                    if get(w, 128) != 1:
                        type_error(w, 7)
                    else:
                        type_colons(o, w)
                        type_text(s, o, w, get(w, 136), get(w, 144))
                        type_consume(s, o, w)
                type_set(o, w, node, 40, offset)
                type_set(o, w, node, 48, get(w, 208) - offset)
                put(w, at, 3)
            else:
                type_error(w, 6)
        elif state == 1:
            type_done(o, w)
        elif state == 2:
            node = get(w, at + 8)
            if get(w, 128) == 315:
                type_set(o, w, node, 0, 3)
                type_consume(s, o, w)
                if get(w, 128) != 3:
                    type_error(w, 3)
                else:
                    type_set(o, w, node, 56, get(w, 136))
                    type_set(o, w, node, 64, get(w, 144) - get(w, 136))
                    type_consume(s, o, w)
            type_expect(s, o, w, 349, 4)
            type_done(o, w)
        elif state == 3:
            if get(w, 128) == 316:
                type_consume(s, o, w)
                put(w, at, 4)
            else:
                type_arity(s, o, w)
        elif state == 4:
            node = get(w, at + 8)
            put(w, at, 5)
            if get(w, 128) == 2:
                type_lifetime(s, o, w, node, 2)
            else:
                put(w, at + 24, get(w, at + 24) + 1)
                type_push(w, node)
        else:
            if get(w, 128) == 300:
                type_consume(s, o, w)
                put(w, at, 4)
            else:
                type_close(s, o, w)
                type_arity(s, o, w)
    return 0

def token(o:mutbuf, w:mutbuf, kind:u64, begin:u64, end:u64) -> u64:
    put(w, 128, kind)
    put(w, 136, begin)
    put(w, 144, end)
    put(w, 152, get(w, 64))
    put(w, 160, get(w, 8))
    put(w, 168, get(w, 72))
    put(w, 176, get(w, 80))
    put(w, 40, 1)
    return 0
'''


def source_program():
    source = SOURCE.replace('@MAGIC@', str(MAGIC))
    for word in ('read', 'mut', 'raw', 'const'):
        source = source.replace('@' + word.upper() + '@', str(128 + KEYWORD_ORDER.index(word)))
    for word in ('Buffer', 'Task', 'Sender'):
        source = source.replace('@' + word.upper() + '@', str(int.from_bytes(word.encode(), 'little')))
    original = lexer_program()
    definitions = ast.parse(original).body
    by_name = {node.name: node for node in definitions}
    # Only scanner dependencies belong in this grammar application. The actual
    # v3 numeric lexer is separately bundled; unused decimal limbs have a larger
    # workspace ABI and are not part of this scanner's entry call graph.
    reachable = set()
    pending = ['scan', *(call.func.id for call in ast.walk(ast.parse(source))
                         if isinstance(call, ast.Call) and isinstance(call.func, ast.Name))]
    while pending:
        name = pending.pop()
        if name in reachable or name not in by_name or name == 'token':
            continue
        reachable.add(name)
        pending.extend(call.func.id for call in ast.walk(by_name[name])
                       if isinstance(call, ast.Call) and isinstance(call.func, ast.Name))
    for node in definitions:
        if node.name not in reachable:
            continue
        text = ast.get_source_segment(original, node)
        if node.name == 'scan':
            text = text.replace('def scan(', 'def scan_next(', 1)
            text = text.replace('while get(w, 0) < length(s) and get(w, 48) == 0:',
                                'while get(w, 0) < length(s) and get(w, 48) == 0 and get(w, 40) == 0:', 1)
            text = text.replace('if get(w, 48) == 0:\n        mark(w)\n        token(o, w, 0,',
                                'if get(w, 48) == 0 and get(w, 40) == 0:\n        mark(w)\n        token(o, w, 0,', 1)
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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'source_types', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/source_types.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
