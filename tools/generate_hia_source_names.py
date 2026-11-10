"""Author qualified names and both declaration parameter grammars in HIA.

The runtime recognizer consumes source bytes and emits a bounded value arena.
Python authoring and object construction remain explicit bootstrap dependencies.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_source_types import source_program as type_program

MAGIC = 5208780291693556274
SOURCE = r'''
def names_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 320 or length(s) > 8388608:
        return 4294967293
    mode = get(w, 224)
    if mode < 1 or mode > 3:
        return 4294967293
    type_reset(w, 0, 0)
    type_next(s, o, w)
    names_parse(s, o, w)
    if get(w, 48) != 0 or get(w, 216) != 0:
        return 4294967295
    count = get(w, 200)
    used = 64 + count * 64
    if used > length(o):
        return 4294967294
    type_reset(w, 1, 0)
    type_next(s, o, w)
    names_parse(s, o, w)
    put(o, 0, @MAGIC@)
    put(o, 8, count)
    put(o, 16, used)
    put(o, 24, get(w, 184))
    put(o, 32, get(w, 192))
    put(o, 40, mode)
    put(o, 48, 1)
    put(o, 56, 0)
    return used

def names_record(o:mutbuf, w:mutbuf, role:u64, begin:u64, end:u64, bound_begin:u64, bound_end:u64) -> u64:
    count = get(w, 200)
    if count >= 1048576:
        return type_error(w, 7)
    if get(w, 232) == 1:
        at = 64 + count * 64
        put(o, at, role)
        put(o, at + 8, begin)
        put(o, at + 16, end)
        put(o, at + 24, bound_begin)
        put(o, at + 32, bound_end)
        put(o, at + 40, 0)
        put(o, at + 48, 0)
        put(o, at + 56, 0)
    put(w, 200, count + 1)
    return 0

def names_item(s:readbuf, o:mutbuf, w:mutbuf, role:u64, error:u64) -> u64:
    if get(w, 128) != 1:
        return type_error(w, error)
    names_record(o, w, role, get(w, 136), get(w, 144), 0, 0)
    return type_consume(s, o, w)

def names_close(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    kind = get(w, 128)
    if kind == 521 or kind == 517:
        put(w, 184, get(w, 152) + 1)
        put(w, 192, get(w, 136) + 1)
        put(w, 128, choose(kind == 521, 318, 317))
        put(w, 136, get(w, 136) + 1)
        put(w, 152, get(w, 152) + 1)
        put(w, 176, get(w, 176) + 1)
        return 0
    return type_expect(s, o, w, 318, 6)

def names_parse(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    mode = get(w, 224)
    if mode == 1:
        names_item(s, o, w, 1, 1)
        while get(w, 128) == 522 and get(w, 216) == 0 and get(w, 48) == 0:
            type_consume(s, o, w)
            names_item(s, o, w, 1, 2)
        return 0
    if get(w, 128) != 316:
        return 0
    type_consume(s, o, w)
    more = 1
    while more != 0 and get(w, 216) == 0 and get(w, 48) == 0:
        if mode == 2:
            names_item(s, o, w, 2, 3)
        elif get(w, 128) == 2:
            names_record(o, w, 3, get(w, 136), get(w, 144), 0, 0)
            type_consume(s, o, w)
        elif get(w, 128) != 1:
            type_error(w, 4)
        else:
            begin = get(w, 136)
            end = get(w, 144)
            bound_begin = 0
            bound_end = 0
            type_consume(s, o, w)
            if get(w, 128) == 314:
                type_consume(s, o, w)
                if get(w, 128) != 1:
                    type_error(w, 5)
                else:
                    bound_begin = get(w, 136)
                    bound_end = get(w, 144)
                    type_consume(s, o, w)
            names_record(o, w, 2, begin, end, bound_begin, bound_end)
        if get(w, 128) == 300 and get(w, 216) == 0 and get(w, 48) == 0:
            type_consume(s, o, w)
        else:
            more = 0
    if get(w, 216) == 0 and get(w, 48) == 0:
        names_close(s, o, w)
    return 0
'''


def source_program():
    text = SOURCE.replace('@MAGIC@', str(MAGIC)) + '\n' + type_program()
    nodes = ast.parse(text).body
    definitions = {node.name: node for node in nodes}
    required, pending = set(), ['names_main']
    while pending:
        name = pending.pop()
        if name in required:
            continue
        required.add(name)
        for node in ast.walk(definitions[name]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in definitions:
                    pending.append(node.func.id)
    return '\n\n'.join(ast.get_source_segment(text, node) for node in nodes if node.name in required) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'source_names', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/source_names.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
